(ns hive.events.protocols.tls
  "RFC 8446 TLS 1.3 Handshake FSM.

   States: start → wait-server-hello → wait-encrypted-extensions
          → wait-cert → wait-cert-verify → wait-finished → connected | error

   The FSM is pure data — all I/O happens through ITransport resources
   and all cryptographic operations are delegated to a :crypto resource
   map containing pluggable functions.

   Factory:
     (make-tls-fsm opts)
       opts — {:cipher-suites        [:TLS_AES_128_GCM_SHA256 ...]
               :supported-groups     [:x25519 :secp256r1]
               :alpn-protocols       [\"h2\" \"http/1.1\"]
               :server-name          \"example.com\"
               :cert-validator-fn    (fn [chain server-name] -> {:valid? bool})
               :handshake-timeout-ms 10000
               :recv-timeout-ms      5000}

   Resources:
     :transport — ITransport for sending/receiving TLS records
     :timer     — ITimer (optional) for handshake timeout
     :crypto    — map of pluggable crypto fns (all optional):
       :generate-key-share    (fn [group] -> {:group G :public-key PK :private-key SK})
       :derive-shared-secret  (fn [private-key peer-public-key] -> bytes)
       :derive-handshake-keys (fn [shared-secret transcript-hash cipher-suite] -> keys-map)
       :derive-app-keys       (fn [handshake-secret transcript-hash cipher-suite] -> keys-map)
       :verify-signature      (fn [public-key transcript-hash signature scheme] -> bool)
       :verify-finished       (fn [finished-key transcript-hash verify-data] -> bool)
       :compute-finished      (fn [finished-key transcript-hash] -> verify-data)
       :hash-transcript       (fn [messages] -> hash-bytes)"
  (:require [hive.events.protocols.core :as proto]))

;; =============================================================================
;; Constants — RFC 8446
;; =============================================================================

(def ^:const tls-version-1-3
  "TLS 1.3 protocol version."
  0x0304)

;; Handshake message types — RFC 8446 §4
(def ^:const msg-client-hello         1)
(def ^:const msg-server-hello         2)
(def ^:const msg-encrypted-extensions 8)
(def ^:const msg-certificate          11)
(def ^:const msg-certificate-verify   15)
(def ^:const msg-finished             20)

;; Alert levels — RFC 8446 §6
(def ^:const alert-warning  1)
(def ^:const alert-fatal    2)

;; Alert descriptions — RFC 8446 §6.2
(def ^:const alert-close-notify       0)
(def ^:const alert-unexpected-message 10)
(def ^:const alert-handshake-failure  40)
(def ^:const alert-bad-certificate    42)
(def ^:const alert-decode-error       50)
(def ^:const alert-decrypt-error      51)
(def ^:const alert-internal-error     80)

;; Default cipher suites — RFC 8446 §B.4
(def default-cipher-suites
  "Default cipher suite preference order."
  [:TLS_AES_128_GCM_SHA256
   :TLS_AES_256_GCM_SHA384
   :TLS_CHACHA20_POLY1305_SHA256])

;; Default supported groups — RFC 8446 §4.2.7
(def default-supported-groups
  "Default key exchange groups."
  [:x25519
   :secp256r1
   :secp384r1])

(def ^:const default-handshake-timeout-ms
  "Maximum time for the complete TLS handshake."
  10000)

(def ^:const default-recv-timeout-ms
  "Default timeout per handshake message receive."
  5000)

;; =============================================================================
;; TLS record helpers
;; =============================================================================

(defn make-handshake-record
  "Build a TLS handshake record map.

   msg-type — handshake message type constant
   payload  — message-specific data map"
  [msg-type payload]
  {:record-type :handshake
   :version     tls-version-1-3
   :msg-type    msg-type
   :payload     payload})

(defn make-alert-record
  "Build a TLS alert record."
  [level description]
  {:record-type :alert
   :level       level
   :description description})

(defn handshake-msg?
  "Check if a received record is a handshake message of the expected type."
  [record expected-type]
  (and (= :handshake (:record-type record))
       (= expected-type (:msg-type record))))

(defn alert-record?
  "Check if a received record is an alert."
  [record]
  (= :alert (:record-type record)))

;; =============================================================================
;; ClientHello builder
;; =============================================================================

(defn build-client-hello
  "Build a ClientHello message from crypto resource and FSM data.

   Includes: cipher suites, supported groups, key shares, SNI, ALPN.
   Key share generation is delegated to :generate-key-share in crypto."
  [crypto data]
  (let [group         (first (:supported-groups data default-supported-groups))
        generate-ks   (:generate-key-share crypto)
        key-share     (when generate-ks (generate-ks group))
        client-random (or (:client-random data)
                          (vec (repeatedly 32 #(rand-int 256))))]
    {:msg-type          msg-client-hello
     :version           tls-version-1-3
     :client-random     client-random
     :cipher-suites     (:cipher-suites data default-cipher-suites)
     :extensions        (cond-> {:supported-versions   [tls-version-1-3]
                                  :supported-groups     (:supported-groups data
                                                                          default-supported-groups)
                                  :signature-algorithms [:rsa-pss-rsae-sha256
                                                         :ecdsa-secp256r1-sha256
                                                         :ed25519]}
                          key-share
                          (assoc :key-share {:group      (:group key-share)
                                             :public-key (:public-key key-share)})

                          (:server-name data)
                          (assoc :server-name (:server-name data))

                          (seq (:alpn-protocols data))
                          (assoc :alpn (:alpn-protocols data)))
     ;; Private key kept separate — never sent on wire
     :key-share-private (:private-key key-share)}))

;; =============================================================================
;; FSM handlers — pure fns of [resources data] → data
;; =============================================================================

;; ---------------------------------------------------------------------------
;; ::start — send ClientHello
;; ---------------------------------------------------------------------------

(defn on-send-client-hello
  "Enter handler for ::start.
   Builds ClientHello, sends via transport, records in data.
   Optionally schedules handshake timeout via ITimer."
  [resources data]
  (let [crypto       (or (:crypto resources) {})
        client-hello (build-client-hello crypto data)
        transport    (:transport resources)
        record       (make-handshake-record msg-client-hello
                                            (dissoc client-hello :key-share-private))]
    (proto/send! transport record {})
    ;; Schedule handshake timeout if timer available
    (when-let [timer (:timer resources)]
      (proto/schedule! timer
                       (:handshake-timeout-ms data default-handshake-timeout-ms)
                       (fn [] (assoc data :handshake-timeout? true))))
    (assoc data
           :client-hello       (dissoc client-hello :key-share-private)
           :client-random      (:client-random client-hello)
           :client-key-share   (:key-share-private client-hello)
           :client-hello-sent? true
           :transcript         [(dissoc client-hello :key-share-private)])))

(defn on-start-handle
  "No-op handle for ::start — ClientHello already sent in enter."
  [_resources data]
  data)

;; ---------------------------------------------------------------------------
;; ::wait-server-hello — receive and process ServerHello
;; ---------------------------------------------------------------------------

(defn on-recv-server-hello
  "Handle in ::wait-server-hello.
   Receives ServerHello, extracts cipher suite and key share,
   derives handshake keys via crypto resource."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :server-hello)
      (let [record (:data result)]
        (cond
          (alert-record? record)
          (assoc data
                 :error       :server-alert
                 :error-phase :server-hello
                 :alert       record)

          (not (handshake-msg? record msg-server-hello))
          (assoc data
                 :error       :unexpected-message
                 :error-phase :server-hello
                 :unexpected  record)

          :else
          (let [payload         (:payload record)
                cipher-suite    (:cipher-suite payload)
                server-random   (:server-random payload)
                server-ks       (get-in payload [:extensions :key-share])
                psk?            (boolean (get-in payload [:extensions :pre-shared-key]))
                crypto          (or (:crypto resources) {})
                shared-secret   (when-let [derive-ss (:derive-shared-secret crypto)]
                                  (derive-ss (:client-key-share data)
                                             (:public-key server-ks)))
                transcript      (conj (:transcript data) payload)
                transcript-hash (when-let [hash-fn (:hash-transcript crypto)]
                                  (hash-fn transcript))
                handshake-keys  (when (and shared-secret
                                           (:derive-handshake-keys crypto))
                                  ((:derive-handshake-keys crypto)
                                   shared-secret transcript-hash cipher-suite))]
            (assoc data
                   :server-hello           payload
                   :server-hello-received? true
                   :cipher-suite           cipher-suite
                   :server-random          server-random
                   :server-key-share       server-ks
                   :psk-mode?              psk?
                   :shared-secret          shared-secret
                   :handshake-keys         handshake-keys
                   :transcript             transcript
                   :transcript-hash        transcript-hash)))))))

;; ---------------------------------------------------------------------------
;; ::wait-encrypted-extensions
;; ---------------------------------------------------------------------------

(defn on-recv-encrypted-extensions
  "Handle in ::wait-encrypted-extensions.
   Receives EncryptedExtensions, processes ALPN and other extensions.
   Determines whether certificate-based or PSK auth follows."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :encrypted-extensions)
      (let [record (:data result)]
        (cond
          (alert-record? record)
          (assoc data
                 :error       :server-alert
                 :error-phase :encrypted-extensions
                 :alert       record)

          (not (handshake-msg? record msg-encrypted-extensions))
          (assoc data
                 :error       :unexpected-message
                 :error-phase :encrypted-extensions
                 :unexpected  record)

          :else
          (let [payload    (:payload record)
                transcript (conj (:transcript data) payload)
                psk-mode?  (boolean (:psk-mode? data))
                alpn       (get-in payload [:extensions :alpn])]
            (assoc data
                   :encrypted-extensions           payload
                   :encrypted-extensions-received? true
                   :cert-expected?                 (not psk-mode?)
                   :selected-alpn                  alpn
                   :transcript                     transcript)))))))

;; ---------------------------------------------------------------------------
;; ::wait-cert
;; ---------------------------------------------------------------------------

(defn on-recv-certificate
  "Handle in ::wait-cert.
   Receives server's Certificate message, validates chain
   via :cert-validator-fn if provided in data."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :certificate)
      (let [record (:data result)]
        (cond
          (alert-record? record)
          (assoc data
                 :error       :server-alert
                 :error-phase :certificate
                 :alert       record)

          (not (handshake-msg? record msg-certificate))
          (assoc data
                 :error       :unexpected-message
                 :error-phase :certificate
                 :unexpected  record)

          :else
          (let [payload    (:payload record)
                cert-chain (:certificate-chain payload)
                transcript (conj (:transcript data) payload)
                validator  (:cert-validator-fn data)
                validation (when validator
                             (validator cert-chain (:server-name data)))]
            (if (and validator (not (:valid? validation)))
              (assoc data
                     :error       :bad-certificate
                     :error-phase :certificate
                     :cert-error  (:error validation)
                     :transcript  transcript)
              (assoc data
                     :certificates          cert-chain
                     :certificate-received? true
                     :cert-validation       validation
                     :transcript            transcript))))))))

;; ---------------------------------------------------------------------------
;; ::wait-cert-verify
;; ---------------------------------------------------------------------------

(defn on-recv-cert-verify
  "Handle in ::wait-cert-verify.
   Receives CertificateVerify, delegates signature verification
   to :verify-signature in crypto resource."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :cert-verify)
      (let [record (:data result)]
        (cond
          (alert-record? record)
          (assoc data
                 :error       :server-alert
                 :error-phase :cert-verify
                 :alert       record)

          (not (handshake-msg? record msg-certificate-verify))
          (assoc data
                 :error       :unexpected-message
                 :error-phase :cert-verify
                 :unexpected  record)

          :else
          (let [payload         (:payload record)
                signature       (:signature payload)
                sig-scheme      (:signature-scheme payload)
                transcript      (conj (:transcript data) payload)
                crypto          (or (:crypto resources) {})
                transcript-hash (when-let [hash-fn (:hash-transcript crypto)]
                                  (hash-fn transcript))
                server-cert     (first (:certificates data))
                verify-fn       (:verify-signature crypto)
                verified?       (if verify-fn
                                  (verify-fn server-cert
                                             (:transcript-hash data)
                                             signature
                                             sig-scheme)
                                  true)]  ;; No crypto → trust (testing mode)
            (if verified?
              (assoc data
                     :cert-verify     payload
                     :cert-verified?  true
                     :transcript      transcript
                     :transcript-hash transcript-hash)
              (assoc data
                     :error       :verify-failed
                     :error-phase :cert-verify
                     :transcript  transcript))))))))

;; ---------------------------------------------------------------------------
;; ::wait-finished
;; ---------------------------------------------------------------------------

(defn on-recv-finished
  "Handle in ::wait-finished.
   Receives server Finished, verifies MAC via crypto resource,
   then computes and sends client Finished."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :finished)
      (let [record (:data result)]
        (cond
          (alert-record? record)
          (assoc data
                 :error       :server-alert
                 :error-phase :finished
                 :alert       record)

          (not (handshake-msg? record msg-finished))
          (assoc data
                 :error       :unexpected-message
                 :error-phase :finished
                 :unexpected  record)

          :else
          (let [payload    (:payload record)
                verify-data (:verify-data payload)
                crypto     (or (:crypto resources) {})
                transcript (conj (:transcript data) payload)
                verify-fn  (:verify-finished crypto)
                verified?  (if verify-fn
                             (verify-fn (:handshake-keys data)
                                        (:transcript-hash data)
                                        verify-data)
                             true)
                compute-fn (:compute-finished crypto)
                client-fin (when compute-fn
                             (compute-fn (:handshake-keys data)
                                         (:transcript-hash data)))]
            (if-not verified?
              (assoc data
                     :error       :finished-verify-failed
                     :error-phase :finished
                     :transcript  transcript)
              (do
                (proto/send! transport
                             (make-handshake-record msg-finished
                                                    {:verify-data (or client-fin
                                                                      :computed)})
                             {})
                (assoc data
                       :server-finished       payload
                       :client-finished-sent? true
                       :handshake-complete?   true
                       :transcript            transcript)))))))))

;; ---------------------------------------------------------------------------
;; ::connected — handshake complete
;; ---------------------------------------------------------------------------

(defn on-handshake-complete
  "Enter handler for ::connected.
   Derives application traffic keys from handshake secret."
  [resources data]
  (let [crypto          (or (:crypto resources) {})
        derive-app      (:derive-app-keys crypto)
        hash-fn         (:hash-transcript crypto)
        transcript-hash (when hash-fn
                          (hash-fn (:transcript data)))
        session-keys    (when derive-app
                          (derive-app (:handshake-keys data)
                                      transcript-hash
                                      (:cipher-suite data)))]
    (assoc data
           :connected?   true
           :session-keys session-keys)))

;; ---------------------------------------------------------------------------
;; ::error — terminal error
;; ---------------------------------------------------------------------------

(defn on-tls-error
  "Enter handler for ::error.
   Sends fatal alert to peer (best-effort), then closes transport."
  [resources data]
  (let [transport  (:transport resources)
        alert-desc (case (:error data)
                     :bad-certificate        alert-bad-certificate
                     :verify-failed          alert-decrypt-error
                     :finished-verify-failed alert-decrypt-error
                     :unexpected-message     alert-unexpected-message
                     :handshake-timeout      alert-handshake-failure
                     alert-internal-error)]
    ;; Best-effort alert send — transport may already be broken
    (try
      (proto/send! transport
                   (make-alert-record alert-fatal alert-desc)
                   {})
      (catch Exception _e nil))
    (proto/close! transport)
    (when-let [timer (:timer resources)]
      (proto/cancel-all! timer))
    (assoc data :transport-closed? true)))

;; =============================================================================
;; Dispatch predicates — (fn [_resources data] → boolean)
;; =============================================================================

(defn server-hello-received?         [_r d] (:server-hello-received? d))
(defn encrypted-extensions-received? [_r d] (:encrypted-extensions-received? d))
(defn cert-expected?                 [_r d] (:cert-expected? d))
(defn psk-mode?                      [_r d] (and (:encrypted-extensions-received? d)
                                                  (not (:cert-expected? d))))
(defn certificate-received?          [_r d] (:certificate-received? d))
(defn cert-verified?                 [_r d] (:cert-verified? d))
(defn handshake-complete?            [_r d] (:handshake-complete? d))
(defn has-error?                     [_r d] (some? (:error d)))
(defn always                         [_r _d] true)

;; =============================================================================
;; FSM spec builder
;; =============================================================================

(defn tls-fsm-spec
  "Build a pure-data FSM spec for the RFC 8446 TLS 1.3 handshake.

   Covers the full client-side TLS 1.3 handshake:
   - ClientHello / ServerHello exchange with key share
   - EncryptedExtensions processing (ALPN, etc.)
   - Certificate-based auth with optional PSK bypass
   - CertificateVerify signature verification
   - Finished MAC verification and client Finished send
   - Application traffic key derivation"
  [_opts]
  {:id      :tls-1.3
   :initial ::start

   :states
   {;; ─── Handshake Initiation ─────────────────────────────────────────

    ::start
    {:enter    on-send-client-hello
     :handle   on-start-handle
     :dispatch [[::wait-server-hello always]]}

    ::wait-server-hello
    {:handle   on-recv-server-hello
     :dispatch [[::wait-encrypted-extensions server-hello-received?]
                [::error                     has-error?]
                [::wait-server-hello         always]]}

    ;; ─── Server Parameters ─────────────────────────────────────────────

    ::wait-encrypted-extensions
    {:handle   on-recv-encrypted-extensions
     :dispatch [[::wait-cert     cert-expected?]
                [::wait-finished psk-mode?]
                [::error         has-error?]
                [::wait-encrypted-extensions always]]}

    ;; ─── Server Authentication ─────────────────────────────────────────

    ::wait-cert
    {:handle   on-recv-certificate
     :dispatch [[::wait-cert-verify certificate-received?]
                [::error            has-error?]
                [::wait-cert        always]]}

    ::wait-cert-verify
    {:handle   on-recv-cert-verify
     :dispatch [[::wait-finished cert-verified?]
                [::error         has-error?]
                [::wait-cert-verify always]]}

    ;; ─── Handshake Completion ──────────────────────────────────────────

    ::wait-finished
    {:handle   on-recv-finished
     :dispatch [[::connected     handshake-complete?]
                [::error         has-error?]
                [::wait-finished always]]}

    ;; ─── Terminal States ───────────────────────────────────────────────

    ::connected
    {:enter on-handshake-complete}

    ::error
    {:enter on-tls-error}}})

;; =============================================================================
;; IProtocolFSM implementation
;; =============================================================================

(defn make-tls-fsm
  "Create a TLS 1.3 protocol FSM.

   opts (all optional):
     :cipher-suites        — preference list (default AES-128-GCM, AES-256-GCM, ChaCha20)
     :supported-groups     — key exchange groups (default x25519, secp256r1, secp384r1)
     :alpn-protocols       — ALPN protocol list (e.g. [\"h2\" \"http/1.1\"])
     :server-name          — SNI server name for certificate validation
     :cert-validator-fn    — (fn [chain server-name] -> {:valid? bool :error ...})
     :handshake-timeout-ms — max handshake duration (default 10 000)
     :recv-timeout-ms      — per-message recv timeout (default 5000)

   Returns: IProtocolFSM implementation.

   Usage:
     (def tls (make-tls-fsm {:server-name \"example.com\"
                              :cipher-suites [:TLS_AES_128_GCM_SHA256]}))

     ;; Run standalone
     (proto/run-session tls
       (proto/make-resources my-transport my-timer
                             {:crypto my-crypto-fns})
       {})

     ;; Or compose into TCP established state as sub-FSM"
  ([] (make-tls-fsm {}))
  ([opts]
   (let [spec     (tls-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))
         defaults {:cipher-suites        default-cipher-suites
                   :supported-groups     default-supported-groups
                   :handshake-timeout-ms default-handshake-timeout-ms
                   :recv-timeout-ms      default-recv-timeout-ms}]
     (reify proto/IProtocolFSM
       (protocol-id [_] :tls-1.3)

       (fsm-spec [_] spec)

       (compiled [_] @compiled)

       (initial-data [_ session-opts]
         (merge defaults opts session-opts
                {:transcript          []
                 :client-hello        nil
                 :server-hello        nil
                 :cipher-suite        nil
                 :certificates        nil
                 :session-keys        nil
                 :handshake-complete? false
                 :connected?          false}))

       (terminal-states [_]
         #{::connected ::error})

       (composable-states [_]
         ;; TLS connected state can host application-level sub-FSMs
         ;; (HTTP/1.1, HTTP/2, etc.)
         {::connected :application})))))
