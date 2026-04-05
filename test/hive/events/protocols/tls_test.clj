(ns hive.events.protocols.tls-test
  "Tests for RFC 8446 TLS 1.3 Handshake FSM.

   Covers:
   - TLS record helpers (make-handshake-record, make-alert-record, predicates)
   - ClientHello builder (build-client-hello)
   - Individual handler functions for each state
   - Dispatch predicates
   - IProtocolFSM contract
   - Happy path (full certificate-based handshake)
   - PSK path (skipping certificate states)
   - Error paths (alerts, bad cert, verify failure, recv errors)"
  (:require [clojure.test :refer [deftest is testing]]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.tls :as tls]))

;; =============================================================================
;; Mock transport — records sends, plays back scripted receives
;; =============================================================================

(defn mock-transport
  "Create a mock ITransport that records sends and returns scripted responses.

   recv-queue — atom of vector; each recv! pops the first entry.
   sent-log   — atom of vector; each send! conjs the data."
  [recv-queue sent-log]
  (let [open (atom true)]
    (reify proto/ITransport
      (transport-id [_] :mock)
      (send! [_ data opts]
        (swap! sent-log conj data)
        {:sent? true :bytes-written 0})
      (recv! [_ opts]
        (if-let [item (first @recv-queue)]
          (do (swap! recv-queue #(vec (rest %)))
              {:data item :bytes-read 0})
          {:error :no-data}))
      (close! [_] (reset! open false))
      (open? [_] @open))))

(defn mock-timer
  "Create a mock ITimer that captures schedule calls."
  []
  (let [scheduled (atom [])]
    (reify proto/ITimer
      (schedule! [_ delay-ms callback]
        (swap! scheduled conj {:delay-ms delay-ms :callback callback})
        (fn cancel [] nil))
      (cancel-all! [_]
        (reset! scheduled [])))))

;; =============================================================================
;; Mock crypto resource
;; =============================================================================

(def mock-crypto
  "Mock crypto resource for testing. All operations succeed with deterministic values."
  {:generate-key-share    (fn [group]
                            {:group       group
                             :public-key  (str "client-pub-" (name group))
                             :private-key (str "client-priv-" (name group))})
   :derive-shared-secret  (fn [priv pub]
                            (str "shared-" priv "-" pub))
   :derive-handshake-keys (fn [secret _hash _suite]
                            {:client-handshake-key (str "chk-" secret)
                             :server-handshake-key (str "shk-" secret)
                             :client-finished-key  (str "cfk-" secret)
                             :server-finished-key  (str "sfk-" secret)})
   :derive-app-keys       (fn [hs-keys _hash _suite]
                            {:client-app-key (str "cak-" (:client-handshake-key hs-keys))
                             :server-app-key (str "sak-" (:server-handshake-key hs-keys))})
   :verify-signature      (fn [_cert _hash _sig _scheme] true)
   :verify-finished       (fn [_keys _hash _data] true)
   :compute-finished      (fn [_keys _hash] "client-finished-data")
   :hash-transcript       (fn [msgs] (str "hash-" (count msgs)))})

;; =============================================================================
;; Test helpers — build mock TLS handshake records
;; =============================================================================

(defn make-resources
  "Build standard test resources."
  ([recv-q sent]
   {:transport (mock-transport recv-q sent)})
  ([recv-q sent timer]
   {:transport (mock-transport recv-q sent)
    :timer     timer})
  ([recv-q sent timer crypto]
   {:transport (mock-transport recv-q sent)
    :timer     timer
    :crypto    crypto}))

(defn server-hello-record
  "Build a mock ServerHello record."
  [cipher-suite & {:keys [key-share-group key-share-pub psk?]
                   :or   {key-share-group :x25519
                          key-share-pub   "server-pub-x25519"
                          psk?            false}}]
  {:record-type :handshake
   :msg-type    tls/msg-server-hello
   :payload     {:server-random (vec (repeat 32 0x42))
                 :cipher-suite  cipher-suite
                 :extensions    (cond-> {:key-share {:group      key-share-group
                                                     :public-key key-share-pub}}
                                  psk? (assoc :pre-shared-key true))}})

(defn encrypted-extensions-record
  "Build a mock EncryptedExtensions record."
  [& {:keys [alpn]}]
  {:record-type :handshake
   :msg-type    tls/msg-encrypted-extensions
   :payload     {:extensions (cond-> {}
                               alpn (assoc :alpn alpn))}})

(defn certificate-record
  "Build a mock Certificate record."
  [cert-chain]
  {:record-type :handshake
   :msg-type    tls/msg-certificate
   :payload     {:certificate-chain cert-chain}})

(defn cert-verify-record
  "Build a mock CertificateVerify record."
  [signature & {:keys [scheme] :or {scheme :rsa-pss-rsae-sha256}}]
  {:record-type :handshake
   :msg-type    tls/msg-certificate-verify
   :payload     {:signature        signature
                 :signature-scheme scheme}})

(defn finished-record
  "Build a mock Finished record."
  [verify-data]
  {:record-type :handshake
   :msg-type    tls/msg-finished
   :payload     {:verify-data verify-data}})

(defn alert-record
  "Build a mock alert record for transport scripting."
  [level description]
  {:record-type :alert
   :level       level
   :description description})

;; =============================================================================
;; TLS record helpers
;; =============================================================================

(deftest make-handshake-record-test
  (testing "builds valid handshake record"
    (let [rec (tls/make-handshake-record tls/msg-client-hello {:cipher-suites [:AES]})]
      (is (= :handshake (:record-type rec)))
      (is (= tls/tls-version-1-3 (:version rec)))
      (is (= tls/msg-client-hello (:msg-type rec)))
      (is (= {:cipher-suites [:AES]} (:payload rec))))))

(deftest make-alert-record-test
  (testing "builds valid alert record"
    (let [rec (tls/make-alert-record tls/alert-fatal tls/alert-handshake-failure)]
      (is (= :alert (:record-type rec)))
      (is (= tls/alert-fatal (:level rec)))
      (is (= tls/alert-handshake-failure (:description rec))))))

(deftest handshake-msg-predicate-test
  (testing "matches correct message type"
    (is (tls/handshake-msg?
         {:record-type :handshake :msg-type tls/msg-server-hello}
         tls/msg-server-hello)))
  (testing "rejects wrong message type"
    (is (not (tls/handshake-msg?
              {:record-type :handshake :msg-type tls/msg-finished}
              tls/msg-server-hello))))
  (testing "rejects non-handshake records"
    (is (not (tls/handshake-msg?
              {:record-type :alert :msg-type tls/msg-server-hello}
              tls/msg-server-hello)))))

(deftest alert-record-predicate-test
  (testing "detects alert records"
    (is (tls/alert-record? {:record-type :alert}))
    (is (not (tls/alert-record? {:record-type :handshake})))))

;; =============================================================================
;; ClientHello builder
;; =============================================================================

(deftest build-client-hello-with-crypto-test
  (testing "builds with crypto key share"
    (let [hello (tls/build-client-hello mock-crypto
                                        {:cipher-suites    [:TLS_AES_128_GCM_SHA256]
                                         :server-name      "example.com"
                                         :supported-groups [:x25519]})]
      (is (= tls/msg-client-hello (:msg-type hello)))
      (is (= tls/tls-version-1-3 (:version hello)))
      (is (= [:TLS_AES_128_GCM_SHA256] (:cipher-suites hello)))
      (is (= "example.com" (get-in hello [:extensions :server-name])))
      (is (= :x25519 (get-in hello [:extensions :key-share :group])))
      (is (= "client-pub-x25519" (get-in hello [:extensions :key-share :public-key])))
      (is (= "client-priv-x25519" (:key-share-private hello)))
      (is (= 32 (count (:client-random hello)))))))

(deftest build-client-hello-without-crypto-test
  (testing "builds without crypto (testing mode)"
    (let [hello (tls/build-client-hello {} {:cipher-suites [:TLS_AES_128_GCM_SHA256]})]
      (is (nil? (get-in hello [:extensions :key-share])))
      (is (nil? (:key-share-private hello)))
      (is (= [:TLS_AES_128_GCM_SHA256] (:cipher-suites hello))))))

(deftest build-client-hello-alpn-test
  (testing "includes ALPN when specified"
    (let [hello (tls/build-client-hello {} {:alpn-protocols ["h2" "http/1.1"]})]
      (is (= ["h2" "http/1.1"] (get-in hello [:extensions :alpn]))))))

(deftest build-client-hello-extensions-test
  (testing "always includes supported-versions and signature-algorithms"
    (let [hello (tls/build-client-hello {} {})]
      (is (= [tls/tls-version-1-3]
             (get-in hello [:extensions :supported-versions])))
      (is (seq (get-in hello [:extensions :signature-algorithms]))))))

;; =============================================================================
;; ::start state handler
;; =============================================================================

(deftest on-send-client-hello-test
  (testing "sends ClientHello, records in data"
    (let [sent   (atom [])
          recv-q (atom [])
          timer  (mock-timer)
          res    (make-resources recv-q sent timer mock-crypto)
          data   {:cipher-suites    [:TLS_AES_128_GCM_SHA256]
                  :supported-groups [:x25519]
                  :server-name      "example.com"
                  :recv-timeout-ms  1000}
          result (tls/on-send-client-hello res data)]
      ;; ClientHello sent
      (is (= 1 (count @sent)))
      (is (= :handshake (:record-type (first @sent))))
      (is (= tls/msg-client-hello (:msg-type (first @sent))))
      ;; Data updated
      (is (:client-hello-sent? result))
      (is (map? (:client-hello result)))
      (is (vector? (:client-random result)))
      (is (= "client-priv-x25519" (:client-key-share result)))
      ;; Transcript started
      (is (= 1 (count (:transcript result))))
      ;; Private key NOT in sent record or client-hello data
      (is (nil? (:key-share-private (:client-hello result))))
      (is (nil? (:key-share-private (:payload (first @sent))))))))

(deftest on-send-client-hello-no-timer-test
  (testing "works without timer"
    (let [sent   (atom [])
          recv-q (atom [])
          res    (make-resources recv-q sent)
          data   {:cipher-suites [:TLS_AES_128_GCM_SHA256]}
          result (tls/on-send-client-hello res data)]
      (is (:client-hello-sent? result))
      (is (= 1 (count @sent))))))

(deftest on-start-handle-test
  (testing "no-op — passes data through"
    (let [data   {:client-hello-sent? true :extra :value}
          result (tls/on-start-handle nil data)]
      (is (= data result)))))

;; =============================================================================
;; ::wait-server-hello handler
;; =============================================================================

(deftest on-recv-server-hello-test
  (testing "processes valid ServerHello with key derivation"
    (let [sh-rec (server-hello-record :TLS_AES_128_GCM_SHA256)
          recv-q (atom [sh-rec])
          sent   (atom [])
          res    (make-resources recv-q sent nil mock-crypto)
          data   {:client-key-share "client-priv-x25519"
                  :transcript       [{:msg-type 1}]
                  :recv-timeout-ms  1000}
          result (tls/on-recv-server-hello res data)]
      (is (:server-hello-received? result))
      (is (= :TLS_AES_128_GCM_SHA256 (:cipher-suite result)))
      (is (some? (:server-random result)))
      (is (some? (:server-key-share result)))
      (is (some? (:shared-secret result)))
      (is (some? (:handshake-keys result)))
      (is (= 2 (count (:transcript result))))
      (is (string? (:transcript-hash result)))
      (is (false? (:psk-mode? result))))))

(deftest on-recv-server-hello-no-crypto-test
  (testing "processes ServerHello without crypto (nil keys)"
    (let [sh-rec (server-hello-record :TLS_AES_128_GCM_SHA256)
          recv-q (atom [sh-rec])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000}
          result (tls/on-recv-server-hello res data)]
      (is (:server-hello-received? result))
      (is (= :TLS_AES_128_GCM_SHA256 (:cipher-suite result)))
      (is (nil? (:shared-secret result)))
      (is (nil? (:handshake-keys result))))))

(deftest on-recv-server-hello-psk-test
  (testing "PSK ServerHello sets psk-mode?"
    (let [sh-rec (server-hello-record :TLS_AES_128_GCM_SHA256 :psk? true)
          recv-q (atom [sh-rec])
          sent   (atom [])
          res    (make-resources recv-q sent nil mock-crypto)
          data   {:client-key-share "k" :transcript [{}] :recv-timeout-ms 1000}
          result (tls/on-recv-server-hello res data)]
      (is (:server-hello-received? result))
      (is (:psk-mode? result)))))

(deftest on-recv-server-hello-alert-test
  (testing "alert from server sets error"
    (let [recv-q (atom [(alert-record tls/alert-fatal tls/alert-handshake-failure)])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000}
          result (tls/on-recv-server-hello res data)]
      (is (= :server-alert (:error result)))
      (is (= :server-hello (:error-phase result)))
      (is (some? (:alert result))))))

(deftest on-recv-server-hello-unexpected-test
  (testing "unexpected message type sets error"
    (let [bad-rec {:record-type :handshake :msg-type tls/msg-finished :payload {}}
          recv-q  (atom [bad-rec])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:transcript [{}] :recv-timeout-ms 1000}
          result  (tls/on-recv-server-hello res data)]
      (is (= :unexpected-message (:error result)))
      (is (= :server-hello (:error-phase result))))))

(deftest on-recv-server-hello-recv-error-test
  (testing "recv error propagated"
    (let [recv-q (atom [])  ;; empty → :no-data error
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 100}
          result (tls/on-recv-server-hello res data)]
      (is (= :no-data (:error result)))
      (is (= :server-hello (:error-phase result))))))

;; =============================================================================
;; ::wait-encrypted-extensions handler
;; =============================================================================

(deftest on-recv-encrypted-extensions-cert-mode-test
  (testing "cert mode: processes valid EncryptedExtensions"
    (let [ee-rec (encrypted-extensions-record :alpn "h2")
          recv-q (atom [ee-rec])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000 :psk-mode? false}
          result (tls/on-recv-encrypted-extensions res data)]
      (is (:encrypted-extensions-received? result))
      (is (:cert-expected? result))
      (is (= "h2" (:selected-alpn result)))
      (is (= 2 (count (:transcript result)))))))

(deftest on-recv-encrypted-extensions-psk-test
  (testing "PSK mode sets cert-expected? false"
    (let [ee-rec (encrypted-extensions-record)
          recv-q (atom [ee-rec])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000 :psk-mode? true}
          result (tls/on-recv-encrypted-extensions res data)]
      (is (:encrypted-extensions-received? result))
      (is (not (:cert-expected? result))))))

(deftest on-recv-encrypted-extensions-alert-test
  (testing "alert sets error"
    (let [recv-q (atom [(alert-record tls/alert-fatal tls/alert-decode-error)])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000}
          result (tls/on-recv-encrypted-extensions res data)]
      (is (= :server-alert (:error result)))
      (is (= :encrypted-extensions (:error-phase result))))))

(deftest on-recv-encrypted-extensions-recv-error-test
  (testing "recv error propagated"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 100}
          result (tls/on-recv-encrypted-extensions res data)]
      (is (= :no-data (:error result)))
      (is (= :encrypted-extensions (:error-phase result))))))

;; =============================================================================
;; ::wait-cert handler
;; =============================================================================

(deftest on-recv-certificate-test
  (testing "processes valid Certificate (no validator)"
    (let [certs  [{:subject "CN=example.com"} {:subject "CN=Root CA"}]
          cert-r (certificate-record certs)
          recv-q (atom [cert-r])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000}
          result (tls/on-recv-certificate res data)]
      (is (:certificate-received? result))
      (is (= certs (:certificates result)))
      (is (= 2 (count (:transcript result))))
      (is (nil? (:cert-validation result))))))

(deftest on-recv-certificate-with-validator-pass-test
  (testing "valid certificate passes validation"
    (let [certs    [{:subject "CN=example.com"}]
          cert-r   (certificate-record certs)
          recv-q   (atom [cert-r])
          sent     (atom [])
          res      (make-resources recv-q sent)
          data     {:transcript       [{}]
                    :recv-timeout-ms  1000
                    :cert-validator-fn (fn [_chain _name] {:valid? true})}
          result   (tls/on-recv-certificate res data)]
      (is (:certificate-received? result))
      (is (= {:valid? true} (:cert-validation result))))))

(deftest on-recv-certificate-invalid-test
  (testing "invalid certificate sets error"
    (let [certs    [{:subject "CN=evil.com"}]
          cert-r   (certificate-record certs)
          recv-q   (atom [cert-r])
          sent     (atom [])
          res      (make-resources recv-q sent)
          data     {:transcript       [{}]
                    :recv-timeout-ms  1000
                    :server-name      "example.com"
                    :cert-validator-fn (fn [_chain _name]
                                        {:valid? false :error :name-mismatch})}
          result   (tls/on-recv-certificate res data)]
      (is (= :bad-certificate (:error result)))
      (is (= :certificate (:error-phase result)))
      (is (= :name-mismatch (:cert-error result))))))

(deftest on-recv-certificate-unexpected-msg-test
  (testing "unexpected message type sets error"
    (let [bad-rec {:record-type :handshake :msg-type tls/msg-finished :payload {}}
          recv-q  (atom [bad-rec])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:transcript [{}] :recv-timeout-ms 1000}
          result  (tls/on-recv-certificate res data)]
      (is (= :unexpected-message (:error result)))
      (is (= :certificate (:error-phase result))))))

(deftest on-recv-certificate-recv-error-test
  (testing "recv error propagated"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 100}
          result (tls/on-recv-certificate res data)]
      (is (= :no-data (:error result))))))

;; =============================================================================
;; ::wait-cert-verify handler
;; =============================================================================

(deftest on-recv-cert-verify-success-test
  (testing "valid CertificateVerify sets cert-verified?"
    (let [cv-rec (cert-verify-record "valid-sig")
          recv-q (atom [cv-rec])
          sent   (atom [])
          res    (make-resources recv-q sent nil mock-crypto)
          data   {:transcript      [{}]
                  :transcript-hash "hash-1"
                  :certificates    [{:subject "CN=example.com"}]
                  :recv-timeout-ms 1000}
          result (tls/on-recv-cert-verify res data)]
      (is (:cert-verified? result))
      (is (= "valid-sig" (:signature (:cert-verify result))))
      (is (some? (:transcript-hash result))))))

(deftest on-recv-cert-verify-failure-test
  (testing "signature verification failure sets error"
    (let [cv-rec  (cert-verify-record "bad-sig")
          recv-q  (atom [cv-rec])
          sent    (atom [])
          crypto  (assoc mock-crypto :verify-signature (fn [& _] false))
          res     (make-resources recv-q sent nil crypto)
          data    {:transcript      [{}]
                   :transcript-hash "hash-1"
                   :certificates    [{:subject "CN=example.com"}]
                   :recv-timeout-ms 1000}
          result  (tls/on-recv-cert-verify res data)]
      (is (= :verify-failed (:error result)))
      (is (= :cert-verify (:error-phase result))))))

(deftest on-recv-cert-verify-no-crypto-test
  (testing "no crypto resource → trust mode (verified)"
    (let [cv-rec (cert-verify-record "any-sig")
          recv-q (atom [cv-rec])
          sent   (atom [])
          res    (make-resources recv-q sent)  ;; no crypto
          data   {:transcript      [{}]
                  :transcript-hash nil
                  :certificates    [{:subject "CN=example.com"}]
                  :recv-timeout-ms 1000}
          result (tls/on-recv-cert-verify res data)]
      (is (:cert-verified? result)))))

(deftest on-recv-cert-verify-recv-error-test
  (testing "recv error propagated"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 100}
          result (tls/on-recv-cert-verify res data)]
      (is (= :no-data (:error result)))
      (is (= :cert-verify (:error-phase result))))))

;; =============================================================================
;; ::wait-finished handler
;; =============================================================================

(deftest on-recv-finished-success-test
  (testing "valid Finished completes handshake, sends client Finished"
    (let [fin-rec (finished-record "server-verify-data")
          recv-q  (atom [fin-rec])
          sent    (atom [])
          res     (make-resources recv-q sent nil mock-crypto)
          data    {:transcript      [{}]
                   :transcript-hash "hash-1"
                   :handshake-keys  {:client-finished-key "cfk"}
                   :recv-timeout-ms 1000}
          result  (tls/on-recv-finished res data)]
      (is (:handshake-complete? result))
      (is (:client-finished-sent? result))
      ;; Client Finished sent
      (is (= 1 (count @sent)))
      (is (= tls/msg-finished (:msg-type (first @sent))))
      (is (= "client-finished-data" (get-in (first @sent) [:payload :verify-data]))))))

(deftest on-recv-finished-verify-failure-test
  (testing "Finished MAC verification failure sets error"
    (let [fin-rec (finished-record "bad-data")
          recv-q  (atom [fin-rec])
          sent    (atom [])
          crypto  (assoc mock-crypto :verify-finished (fn [& _] false))
          res     (make-resources recv-q sent nil crypto)
          data    {:transcript      [{}]
                   :transcript-hash "hash-1"
                   :handshake-keys  {}
                   :recv-timeout-ms 1000}
          result  (tls/on-recv-finished res data)]
      (is (= :finished-verify-failed (:error result)))
      (is (= :finished (:error-phase result)))
      ;; No client Finished sent
      (is (= 0 (count @sent))))))

(deftest on-recv-finished-no-crypto-test
  (testing "no crypto → trust mode, sends Finished with :computed"
    (let [fin-rec (finished-record "any")
          recv-q  (atom [fin-rec])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:transcript      [{}]
                   :transcript-hash nil
                   :handshake-keys  nil
                   :recv-timeout-ms 1000}
          result  (tls/on-recv-finished res data)]
      (is (:handshake-complete? result))
      (is (= :computed (get-in (first @sent) [:payload :verify-data]))))))

(deftest on-recv-finished-alert-test
  (testing "alert during finished sets error"
    (let [recv-q (atom [(alert-record tls/alert-fatal tls/alert-decrypt-error)])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 1000}
          result (tls/on-recv-finished res data)]
      (is (= :server-alert (:error result)))
      (is (= :finished (:error-phase result))))))

(deftest on-recv-finished-recv-error-test
  (testing "recv error propagated"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:transcript [{}] :recv-timeout-ms 100}
          result (tls/on-recv-finished res data)]
      (is (= :no-data (:error result)))
      (is (= :finished (:error-phase result))))))

;; =============================================================================
;; ::connected handler
;; =============================================================================

(deftest on-handshake-complete-with-crypto-test
  (testing "derives application keys"
    (let [res    {:crypto mock-crypto}
          data   {:transcript     [{} {} {}]
                  :cipher-suite   :TLS_AES_128_GCM_SHA256
                  :handshake-keys {:client-handshake-key "chk"
                                   :server-handshake-key "shk"}}
          result (tls/on-handshake-complete res data)]
      (is (:connected? result))
      (is (some? (:session-keys result)))
      (is (string? (:client-app-key (:session-keys result))))
      (is (string? (:server-app-key (:session-keys result)))))))

(deftest on-handshake-complete-no-crypto-test
  (testing "no crypto → connected but nil keys"
    (let [res    {}
          data   {:transcript   [{}]
                  :cipher-suite :TLS_AES_128_GCM_SHA256}
          result (tls/on-handshake-complete res data)]
      (is (:connected? result))
      (is (nil? (:session-keys result))))))

;; =============================================================================
;; ::error handler
;; =============================================================================

(deftest on-tls-error-bad-cert-test
  (testing "bad-certificate sends correct alert and closes transport"
    (let [recv-q (atom [])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          timer  (mock-timer)
          res    {:transport tp :timer timer}
          data   {:error :bad-certificate :error-phase :certificate}
          result (tls/on-tls-error res data)]
      ;; Alert sent
      (is (= 1 (count @sent)))
      (is (= :alert (:record-type (first @sent))))
      (is (= tls/alert-fatal (:level (first @sent))))
      (is (= tls/alert-bad-certificate (:description (first @sent))))
      ;; Transport closed
      (is (:transport-closed? result))
      (is (not (proto/open? tp))))))

(deftest on-tls-error-verify-failed-test
  (testing "verify-failed sends decrypt-error alert"
    (let [recv-q (atom [])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:error :verify-failed}
          result (tls/on-tls-error res data)]
      (is (= tls/alert-decrypt-error (:description (first @sent))))
      (is (:transport-closed? result)))))

(deftest on-tls-error-unknown-test
  (testing "unknown error sends internal-error alert"
    (let [recv-q (atom [])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:error :some-unknown-error}
          result (tls/on-tls-error res data)]
      (is (= tls/alert-internal-error (:description (first @sent))))
      (is (:transport-closed? result)))))

(deftest on-tls-error-unexpected-msg-test
  (testing "unexpected-message sends correct alert"
    (let [recv-q (atom [])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:error :unexpected-message}
          result (tls/on-tls-error res data)]
      (is (= tls/alert-unexpected-message (:description (first @sent))))
      (is (:transport-closed? result)))))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(deftest dispatch-predicates-test
  (testing "server-hello-received?"
    (is (tls/server-hello-received? nil {:server-hello-received? true}))
    (is (not (tls/server-hello-received? nil {}))))

  (testing "encrypted-extensions-received?"
    (is (tls/encrypted-extensions-received? nil {:encrypted-extensions-received? true}))
    (is (not (tls/encrypted-extensions-received? nil {}))))

  (testing "cert-expected?"
    (is (tls/cert-expected? nil {:cert-expected? true}))
    (is (not (tls/cert-expected? nil {})))
    (is (not (tls/cert-expected? nil {:cert-expected? false}))))

  (testing "psk-mode? requires EE received AND cert not expected"
    (is (tls/psk-mode? nil {:encrypted-extensions-received? true :cert-expected? false}))
    (is (not (tls/psk-mode? nil {:encrypted-extensions-received? true :cert-expected? true})))
    (is (not (tls/psk-mode? nil {:cert-expected? false})))
    (is (not (tls/psk-mode? nil {}))))

  (testing "certificate-received?"
    (is (tls/certificate-received? nil {:certificate-received? true}))
    (is (not (tls/certificate-received? nil {}))))

  (testing "cert-verified?"
    (is (tls/cert-verified? nil {:cert-verified? true}))
    (is (not (tls/cert-verified? nil {}))))

  (testing "handshake-complete?"
    (is (tls/handshake-complete? nil {:handshake-complete? true}))
    (is (not (tls/handshake-complete? nil {}))))

  (testing "has-error?"
    (is (tls/has-error? nil {:error :something}))
    (is (not (tls/has-error? nil {}))))

  (testing "always"
    (is (tls/always nil {}))
    (is (tls/always nil {:anything true}))))

;; =============================================================================
;; IProtocolFSM contract
;; =============================================================================

(deftest make-tls-fsm-contract-test
  (testing "factory returns valid IProtocolFSM"
    (let [fsm (tls/make-tls-fsm {:server-name "example.com"})]
      (is (= :tls-1.3 (proto/protocol-id fsm)))
      (is (map? (proto/fsm-spec fsm)))
      (is (= #{::tls/connected ::tls/error} (proto/terminal-states fsm)))
      (is (contains? (proto/composable-states fsm) ::tls/connected))
      (is (= :application (get (proto/composable-states fsm) ::tls/connected))))))

(deftest make-tls-fsm-initial-data-test
  (testing "initial-data includes defaults and overrides"
    (let [fsm  (tls/make-tls-fsm {:server-name   "example.com"
                                   :cipher-suites [:TLS_AES_256_GCM_SHA384]})
          data (proto/initial-data fsm {:recv-timeout-ms 3000})]
      (is (= "example.com" (:server-name data)))
      (is (= [:TLS_AES_256_GCM_SHA384] (:cipher-suites data)))
      (is (= 3000 (:recv-timeout-ms data)))
      (is (= [] (:transcript data)))
      (is (nil? (:client-hello data)))
      (is (nil? (:cipher-suite data)))
      (is (nil? (:certificates data)))
      (is (nil? (:session-keys data)))
      (is (false? (:handshake-complete? data)))
      (is (false? (:connected? data))))))

(deftest fsm-spec-structure-test
  (testing "spec contains all 8 states"
    (let [spec (tls/tls-fsm-spec {})]
      (is (= :tls-1.3 (:id spec)))
      (is (= ::tls/start (:initial spec)))
      (is (= 8 (count (:states spec))))
      (is (every? #(contains? (:states spec) %)
                  [::tls/start ::tls/wait-server-hello
                   ::tls/wait-encrypted-extensions
                   ::tls/wait-cert ::tls/wait-cert-verify
                   ::tls/wait-finished
                   ::tls/connected ::tls/error])))))

;; =============================================================================
;; Integration: Full certificate-based handshake (happy path)
;; start → wait-server-hello → wait-encrypted-extensions → wait-cert
;;       → wait-cert-verify → wait-finished → connected
;; =============================================================================

(deftest happy-path-cert-handshake-test
  (testing "full certificate-based TLS 1.3 handshake via direct handler calls"
    (let [sent    (atom [])
          certs   [{:subject "CN=example.com"} {:subject "CN=Root CA"}]
          ;; Script: ServerHello, EncryptedExtensions, Certificate,
          ;;         CertificateVerify, Finished
          recv-q  (atom [(server-hello-record :TLS_AES_128_GCM_SHA256)
                         (encrypted-extensions-record :alpn "h2")
                         (certificate-record certs)
                         (cert-verify-record "sig-bytes")
                         (finished-record "server-verify")])
          tp      (mock-transport recv-q sent)
          timer   (mock-timer)
          res     {:transport tp :timer timer :crypto mock-crypto}

          ;; Initial data
          d0      {:cipher-suites       [:TLS_AES_128_GCM_SHA256]
                   :supported-groups    [:x25519]
                   :server-name         "example.com"
                   :recv-timeout-ms     5000
                   :handshake-timeout-ms 10000}

          ;; 1. ::start — enter (send ClientHello)
          d1      (tls/on-send-client-hello res d0)
          _       (is (:client-hello-sent? d1))
          _       (is (= 1 (count @sent)))
          _       (is (= tls/msg-client-hello (:msg-type (first @sent))))
          d1b     (tls/on-start-handle res d1)
          _       (is (tls/always nil d1b))

          ;; 2. ::wait-server-hello — handle (recv ServerHello)
          d2      (tls/on-recv-server-hello res d1b)
          _       (is (:server-hello-received? d2))
          _       (is (= :TLS_AES_128_GCM_SHA256 (:cipher-suite d2)))
          _       (is (some? (:handshake-keys d2)))
          _       (is (tls/server-hello-received? nil d2))

          ;; 3. ::wait-encrypted-extensions — handle
          d3      (tls/on-recv-encrypted-extensions res d2)
          _       (is (:encrypted-extensions-received? d3))
          _       (is (:cert-expected? d3))
          _       (is (= "h2" (:selected-alpn d3)))
          _       (is (tls/cert-expected? nil d3))
          _       (is (not (tls/psk-mode? nil d3)))

          ;; 4. ::wait-cert — handle (recv Certificate)
          d4      (tls/on-recv-certificate res d3)
          _       (is (:certificate-received? d4))
          _       (is (= certs (:certificates d4)))
          _       (is (tls/certificate-received? nil d4))

          ;; 5. ::wait-cert-verify — handle (recv CertificateVerify)
          d5      (tls/on-recv-cert-verify res d4)
          _       (is (:cert-verified? d5))
          _       (is (tls/cert-verified? nil d5))

          ;; 6. ::wait-finished — handle (recv Finished, send client Finished)
          d6      (tls/on-recv-finished res d5)
          _       (is (:handshake-complete? d6))
          _       (is (:client-finished-sent? d6))
          _       (is (tls/handshake-complete? nil d6))

          ;; 7. ::connected — enter (derive app keys)
          d7      (tls/on-handshake-complete res d6)]

      (is (:connected? d7))
      (is (some? (:session-keys d7)))
      (is (= :TLS_AES_128_GCM_SHA256 (:cipher-suite d7)))

      ;; Verify sent sequence: ClientHello, client Finished
      (is (= 2 (count @sent)))
      (is (= tls/msg-client-hello (:msg-type (first @sent))))
      (is (= tls/msg-finished (:msg-type (second @sent))))

      ;; Transcript has all messages
      (is (= 6 (count (:transcript d6)))))))

;; =============================================================================
;; Integration: PSK handshake (skipping certificate states)
;; start → wait-server-hello → wait-encrypted-extensions → wait-finished
;;       → connected
;; =============================================================================

(deftest psk-handshake-test
  (testing "PSK handshake skips certificate states"
    (let [sent   (atom [])
          ;; Script: ServerHello (with PSK), EncryptedExtensions, Finished
          recv-q (atom [(server-hello-record :TLS_AES_128_GCM_SHA256 :psk? true)
                        (encrypted-extensions-record)
                        (finished-record "psk-verify")])
          tp     (mock-transport recv-q sent)
          res    {:transport tp :crypto mock-crypto}

          d0     {:cipher-suites    [:TLS_AES_128_GCM_SHA256]
                  :supported-groups [:x25519]
                  :recv-timeout-ms  5000}

          ;; 1. ::start
          d1     (tls/on-send-client-hello res d0)
          _      (is (:client-hello-sent? d1))

          ;; 2. ::wait-server-hello
          d2     (tls/on-recv-server-hello res d1)
          _      (is (:server-hello-received? d2))
          _      (is (:psk-mode? d2))

          ;; 3. ::wait-encrypted-extensions
          d3     (tls/on-recv-encrypted-extensions res d2)
          _      (is (:encrypted-extensions-received? d3))
          _      (is (not (:cert-expected? d3)))
          ;; Verify PSK mode dispatch would fire
          _      (is (tls/psk-mode? nil d3))
          _      (is (not (tls/cert-expected? nil d3)))

          ;; 4. Skip cert states → ::wait-finished
          d4     (tls/on-recv-finished res d3)
          _      (is (:handshake-complete? d4))

          ;; 5. ::connected
          d5     (tls/on-handshake-complete res d4)]

      (is (:connected? d5))
      ;; Only ClientHello + client Finished sent
      (is (= 2 (count @sent)))
      ;; No certificates in data (skipped)
      (is (nil? (:certificates d5))))))

;; =============================================================================
;; Error path: Bad certificate
;; =============================================================================

(deftest bad-certificate-error-path-test
  (testing "invalid cert triggers error state with cleanup"
    (let [sent    (atom [])
          recv-q  (atom [(server-hello-record :TLS_AES_128_GCM_SHA256)
                         (encrypted-extensions-record)
                         (certificate-record [{:subject "CN=evil.com"}])])
          tp      (mock-transport recv-q sent)
          res     {:transport tp :crypto mock-crypto}

          d0      {:cipher-suites     [:TLS_AES_128_GCM_SHA256]
                   :supported-groups  [:x25519]
                   :server-name       "example.com"
                   :cert-validator-fn (fn [_chain _name]
                                       {:valid? false :error :name-mismatch})
                   :recv-timeout-ms   5000}

          d1      (tls/on-send-client-hello res d0)
          d2      (tls/on-recv-server-hello res d1)
          d3      (tls/on-recv-encrypted-extensions res d2)
          d4      (tls/on-recv-certificate res d3)]

      (is (= :bad-certificate (:error d4)))
      (is (= :certificate (:error-phase d4)))
      (is (= :name-mismatch (:cert-error d4)))
      (is (tls/has-error? nil d4))

      ;; Error state cleanup
      (let [d5 (tls/on-tls-error res d4)]
        (is (:transport-closed? d5))
        (is (= tls/alert-bad-certificate (:description (last @sent))))
        (is (not (proto/open? tp)))))))

;; =============================================================================
;; Error path: Server alert during handshake
;; =============================================================================

(deftest server-alert-error-path-test
  (testing "server sends fatal alert during handshake"
    (let [sent    (atom [])
          recv-q  (atom [(server-hello-record :TLS_AES_128_GCM_SHA256)
                         (alert-record tls/alert-fatal tls/alert-handshake-failure)])
          tp      (mock-transport recv-q sent)
          res     {:transport tp :crypto mock-crypto}

          d0      {:cipher-suites    [:TLS_AES_128_GCM_SHA256]
                   :supported-groups [:x25519]
                   :recv-timeout-ms  5000}

          d1      (tls/on-send-client-hello res d0)
          d2      (tls/on-recv-server-hello res d1)
          _       (is (:server-hello-received? d2))
          ;; Next recv returns alert instead of EncryptedExtensions
          d3      (tls/on-recv-encrypted-extensions res d2)]

      (is (= :server-alert (:error d3)))
      (is (= :encrypted-extensions (:error-phase d3)))
      (is (tls/has-error? nil d3)))))

;; =============================================================================
;; Error path: Signature verification failure
;; =============================================================================

(deftest signature-verify-error-path-test
  (testing "CertificateVerify signature failure → error → cleanup"
    (let [sent    (atom [])
          recv-q  (atom [(server-hello-record :TLS_AES_128_GCM_SHA256)
                         (encrypted-extensions-record)
                         (certificate-record [{:subject "CN=example.com"}])
                         (cert-verify-record "forged-sig")])
          tp      (mock-transport recv-q sent)
          crypto  (assoc mock-crypto :verify-signature (fn [& _] false))
          res     {:transport tp :crypto crypto}

          d0      {:cipher-suites    [:TLS_AES_128_GCM_SHA256]
                   :supported-groups [:x25519]
                   :recv-timeout-ms  5000}

          d1      (tls/on-send-client-hello res d0)
          d2      (tls/on-recv-server-hello res d1)
          d3      (tls/on-recv-encrypted-extensions res d2)
          d4      (tls/on-recv-certificate res d3)
          _       (is (:certificate-received? d4))
          d5      (tls/on-recv-cert-verify res d4)]

      (is (= :verify-failed (:error d5)))
      (is (tls/has-error? nil d5))

      ;; Error state sends decrypt-error alert
      (let [d6 (tls/on-tls-error res d5)]
        (is (:transport-closed? d6))
        (is (= tls/alert-decrypt-error (:description (last @sent))))))))

;; =============================================================================
;; Error path: Recv timeout (empty queue)
;; =============================================================================

(deftest recv-timeout-error-path-test
  (testing "empty recv queue triggers error at any stage"
    (let [sent   (atom [])
          ;; Only ServerHello — no more messages after that
          recv-q (atom [(server-hello-record :TLS_AES_128_GCM_SHA256)])
          tp     (mock-transport recv-q sent)
          res    {:transport tp :crypto mock-crypto}

          d0     {:cipher-suites    [:TLS_AES_128_GCM_SHA256]
                  :supported-groups [:x25519]
                  :recv-timeout-ms  100}

          d1     (tls/on-send-client-hello res d0)
          d2     (tls/on-recv-server-hello res d1)
          _      (is (:server-hello-received? d2))
          ;; No more messages in queue
          d3     (tls/on-recv-encrypted-extensions res d2)]

      (is (= :no-data (:error d3)))
      (is (= :encrypted-extensions (:error-phase d3))))))
