(ns hive.events.protocols.http3-test
  "Tests for RFC 9114 HTTP/3 + RFC 9000 QUIC connection FSMs.

   Coverage:
   - Constants present (RFC 9000 QUIC + RFC 9114 HTTP/3)
   - Frame helpers (make-quic-frame, make-h3-frame, predicates)
   - Stream-id parity discrimination (RFC 9000 §2.1)
   - QUIC connection FSM handler unit tests
   - HTTP/3 stream FSM handler unit tests
   - Dispatch predicates
   - IProtocolFSM contract
   - Reachability: every state appears as initial or dispatch target
   - Property: every dispatch target is a declared state"
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.http3 :as http3]))

;; =============================================================================
;; Mock transport
;; =============================================================================

(defn mock-transport
  [recv-queue sent-log]
  (let [open (atom true)]
    (reify proto/ITransport
      (transport-id [_] :mock)
      (send! [_ data _opts]
        (swap! sent-log conj data)
        {:sent? true :bytes-written 0})
      (recv! [_ _opts]
        (if-let [item (first @recv-queue)]
          (do (swap! recv-queue #(vec (rest %)))
              {:data item :bytes-read 0})
          {:error :no-data}))
      (close! [_] (reset! open false))
      (open? [_] @open))))

(defn mock-timer []
  (let [scheduled (atom [])]
    (reify proto/ITimer
      (schedule! [_ delay-ms callback]
        (swap! scheduled conj {:delay-ms delay-ms :callback callback})
        (fn cancel [] nil))
      (cancel-all! [_] (reset! scheduled [])))))

;; =============================================================================
;; Constants
;; =============================================================================

(deftest constants-test
  (testing "RFC 9000 §17 packet types"
    (is (= 0x0 http3/pkt-initial))
    (is (= 0x2 http3/pkt-handshake))
    (is (= 0x4 http3/pkt-1rtt)))
  (testing "RFC 9000 §19 frame types"
    (is (= 0x06 http3/frame-crypto))
    (is (= 0x08 http3/frame-stream))
    (is (= 0x1C http3/frame-connection-close))
    (is (= 0x1E http3/frame-handshake-done)))
  (testing "RFC 9114 §7.2 HTTP/3 frame types"
    (is (= 0x0 http3/h3-frame-data))
    (is (= 0x1 http3/h3-frame-headers))
    (is (= 0x4 http3/h3-frame-settings))
    (is (= 0x7 http3/h3-frame-goaway)))
  (testing "RFC 9114 §8.1 HTTP/3 application errors"
    (is (= 0x100 http3/h3-err-no-error))
    (is (= 0x10C http3/h3-err-request-cancelled))
    (is (= 0x110 http3/h3-err-version-fallback)))
  (testing "RFC 9114 §6.2 stream type prefixes"
    (is (= 0x00 http3/stream-type-control))
    (is (= 0x02 http3/stream-type-qpack-encoder))
    (is (= 0x03 http3/stream-type-qpack-decoder))))

;; =============================================================================
;; Frame helpers
;; =============================================================================

(deftest frame-helpers-test
  (testing "make-quic-frame builds frame map"
    (let [f (http3/make-quic-frame http3/frame-crypto {:offset 0 :data [1 2 3]})]
      (is (= http3/frame-crypto (:frame-type f)))
      (is (= [1 2 3] (get-in f [:payload :data])))))
  (testing "make-h3-frame builds h3 frame map"
    (let [f (http3/make-h3-frame http3/h3-frame-headers {:headers {":status" "200"}})]
      (is (= http3/h3-frame-headers (:h3-frame-type f)))))
  (testing "make-quic-packet builds packet"
    (let [p (http3/make-quic-packet http3/pkt-initial [1 2] 0 [])]
      (is (= http3/pkt-initial (:packet-type p)))
      (is (= [1 2] (:connection-id p)))
      (is (= 0 (:packet-number p))))))

(deftest stream-id-parity-test
  (testing "RFC 9000 §2.1 stream-id 4-class discrimination"
    ;; 0 = client bidi, 1 = server bidi, 2 = client uni, 3 = server uni
    (is (http3/h3-stream-id-bidi? 0))
    (is (http3/h3-stream-id-bidi? 4))
    (is (http3/h3-stream-id-bidi? 8))
    (is (http3/h3-stream-id-server-bidi? 1))
    (is (http3/h3-stream-id-server-bidi? 5))
    (is (http3/h3-stream-id-client-uni? 2))
    (is (http3/h3-stream-id-client-uni? 6))
    (is (http3/h3-stream-id-server-uni? 3))
    (is (http3/h3-stream-id-server-uni? 7)))
  (testing "categories are mutually exclusive"
    (doseq [sid (range 16)]
      (let [hits (count (filter true?
                                [(http3/h3-stream-id-bidi? sid)
                                 (http3/h3-stream-id-server-bidi? sid)
                                 (http3/h3-stream-id-client-uni? sid)
                                 (http3/h3-stream-id-server-uni? sid)]))]
        (is (= 1 hits)
            (str "stream-id " sid " matched " hits " categories"))))))

(defspec stream-id-classification-property 100
  (prop/for-all [sid gen/nat]
    (let [hits (count (filter true?
                              [(http3/h3-stream-id-bidi? sid)
                               (http3/h3-stream-id-server-bidi? sid)
                               (http3/h3-stream-id-client-uni? sid)
                               (http3/h3-stream-id-server-uni? sid)]))]
      (= 1 hits))))

;; =============================================================================
;; QUIC connection FSM handlers
;; =============================================================================

(deftest on-quic-send-initial-test
  (testing "sends Initial packet via transport"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)
                :timer     (mock-timer)
                :quic      {}}
          out  (http3/on-quic-send-initial rsrc {:scid [1 2 3] :dcid [4 5 6]})]
      (is (:initial-sent? out))
      (is (= [1 2 3] (:scid out)))
      (is (= [4 5 6] (:dcid out)))
      (is (= http3/pkt-initial (:packet-type (first @sent))))))
  (testing "uses :new-connection-id resource if no scid/dcid given"
    (let [sent (atom [])
          ids  (atom [])
          new-id-fn (fn []
                      (let [id [(count @ids)]]
                        (swap! ids conj id)
                        id))
          rsrc {:transport (mock-transport (atom []) sent)
                :quic      {:new-connection-id new-id-fn}}
          out  (http3/on-quic-send-initial rsrc {})]
      (is (some? (:scid out)))
      (is (some? (:dcid out))))))

(deftest on-quic-handshake-recv-test
  (testing "HANDSHAKE_DONE frame sets handshake-complete?"
    (let [packet {:frames [(http3/make-quic-frame http3/frame-handshake-done {})]}
          recv   (atom [packet])
          rsrc   {:transport (mock-transport recv (atom []))
                  :quic      {}}
          out    (http3/on-quic-handshake-recv rsrc {})]
      (is (:handshake-complete? out))
      (is (:tls-complete? out))))
  (testing "CRYPTO frames buffered into :tls-state"
    (let [packet {:frames [(http3/make-quic-frame http3/frame-crypto {:data [10 20 30]})]}
          recv   (atom [packet])
          rsrc   {:transport (mock-transport recv (atom []))
                  :quic      {}}
          out    (http3/on-quic-handshake-recv rsrc {})]
      (is (= [10 20 30] (get-in out [:tls-state :crypto-buffer]))))))

(deftest on-quic-established-enter-test
  (testing "initialises connection state"
    (let [out (http3/on-quic-established-enter nil {})]
      (is (:connected? out))
      (is (= {} (:streams out)))
      (is (= 0 (:next-stream-id-bidi out)))
      (is (= 2 (:next-stream-id-uni out))))))

(deftest on-quic-established-recv-test
  (testing "CONNECTION_CLOSE sets close-received?"
    (let [packet {:frames [(http3/make-quic-frame http3/frame-connection-close
                                                  {:error-code http3/err-no-error
                                                   :reason     "bye"})]}
          recv   (atom [packet])
          rsrc   {:transport (mock-transport recv (atom []))
                  :quic      {}}
          out    (http3/on-quic-established-recv rsrc {})]
      (is (:close-received? out))
      (is (= "bye" (:close-reason out)))))
  (testing "MAX_DATA increments conn-send-window"
    (let [packet {:frames [(http3/make-quic-frame http3/frame-max-data {:max-data 1000})]}
          recv   (atom [packet])
          rsrc   {:transport (mock-transport recv (atom []))
                  :quic      {}}
          out    (http3/on-quic-established-recv rsrc {:conn-send-window 100})]
      (is (= 1100 (:conn-send-window out))))))

(deftest on-quic-send-close-test
  (testing "sends CONNECTION_CLOSE packet"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)
                :quic      {}}
          out  (http3/on-quic-send-close rsrc {:dcid [1] :next-pn 5})]
      (is (:close-sent? out))
      (is (= http3/pkt-1rtt (:packet-type (first @sent))))
      (let [frame (first (:frames (first @sent)))]
        (is (http3/quic-frame-of-type? frame http3/frame-connection-close))))))

(deftest on-quic-closed-enter-test
  (testing "closes transport"
    (let [tport (mock-transport (atom []) (atom []))
          rsrc  {:transport tport :timer (mock-timer)}
          out   (http3/on-quic-closed-enter rsrc {})]
      (is (:transport-closed? out))
      (is (not (proto/open? tport))))))

;; =============================================================================
;; HTTP/3 stream FSM handlers
;; =============================================================================

(deftest on-h3-send-headers-test
  (testing "sends HEADERS frame on the stream"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)
                :qpack     {:encode identity}}
          out  (http3/on-h3-send-headers
                 rsrc
                 {:stream-id 0
                  :request-headers {":method" "GET" ":path" "/"}})]
      (is (:headers-sent? out))
      (is (= 0 (:stream-id (first @sent))))
      (is (http3/h3-frame-of-type? (:h3-frame (first @sent))
                                    http3/h3-frame-headers))))
  (testing "end-stream-on-headers? marks end-stream-sent?"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)
                :qpack     {:encode identity}}
          out  (http3/on-h3-send-headers
                 rsrc
                 {:stream-id 0
                  :request-headers {}
                  :end-stream-on-headers? true})]
      (is (:end-stream-sent? out))
      (is (:end? (first @sent))))))

(deftest on-h3-recv-frame-test
  (testing "HEADERS frame captures :response-headers"
    (let [out (http3/on-h3-recv-frame
                {:qpack {:decode identity}}
                {:current-frame (assoc (http3/make-h3-frame
                                         http3/h3-frame-headers
                                         {:headers {":status" "200"}})
                                       :end? true)})]
      (is (= {":status" "200"} (:response-headers out)))
      (is (:end-stream-received? out))))
  (testing "DATA frame appends to :response-data"
    (let [out (http3/on-h3-recv-frame
                {:qpack {:decode identity}}
                {:current-frame (http3/make-h3-frame http3/h3-frame-data
                                                     {:data "hi"})})]
      (is (= "hi" (:response-data out)))))
  (testing "GOAWAY captures stream id"
    (let [out (http3/on-h3-recv-frame
                {:qpack {:decode identity}}
                {:current-frame (http3/make-h3-frame http3/h3-frame-goaway
                                                     {:stream-id 5})})]
      (is (:goaway-received? out))
      (is (= 5 (:goaway-stream-id out))))))

(deftest on-h3-cancel-test
  (testing "sends cancel signal with default error code"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)}
          out  (http3/on-h3-cancel rsrc {:stream-id 0})]
      (is (:cancel-sent? out))
      (is (= http3/h3-err-request-cancelled (:stream-error-code out)))
      (is (:cancel? (first @sent))))))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(deftest dispatch-predicates-test
  (testing "QUIC connection predicates"
    (is (http3/initial-sent?       nil {:initial-sent? true}))
    (is (http3/handshake-complete? nil {:handshake-complete? true}))
    (is (http3/close-received?     nil {:close-received? true}))
    (is (http3/handshake-timeout?  nil {:handshake-timeout? true}))
    (is (http3/has-error?          nil {:error :foo})))
  (testing "HTTP/3 stream predicates"
    (is (http3/h3-has-request?         nil {:request-headers {}}))
    (is (http3/h3-end-stream-sent?     nil {:end-stream-sent? true}))
    (is (http3/h3-end-stream-received? nil {:end-stream-received? true}))
    (is (http3/h3-cancel-sent?         nil {:cancel-sent? true}))
    (is (http3/h3-fully-closed?        nil {:end-stream-sent? true
                                             :end-stream-received? true}))))

;; =============================================================================
;; IProtocolFSM contract
;; =============================================================================

(deftest iprotocol-fsm-contract-test
  (testing "make-http3-fsm returns IProtocolFSM"
    (let [fsm (http3/make-http3-fsm)]
      (is (= :http/v3 (proto/protocol-id fsm)))
      (is (map? (proto/fsm-spec fsm)))
      (is (set? (proto/terminal-states fsm)))
      (is (contains? (proto/composable-states fsm) ::http3/quic-handshake))
      (is (contains? (proto/composable-states fsm) ::http3/quic-established))))
  (testing "make-http3-stream-fsm returns IProtocolFSM"
    (let [s (http3/make-http3-stream-fsm)]
      (is (= :http/v3-stream (proto/protocol-id s)))
      (is (= #{::http3/h3-stream-closed} (proto/terminal-states s))))))

;; =============================================================================
;; Reachability
;; =============================================================================

(deftest connection-spec-shape-test
  (testing "every QUIC state declared as initial or transition target"
    (let [spec    (http3/quic-connection-fsm-spec {})
          states  (set (keys (:states spec)))
          targets (set (concat [(:initial spec)]
                               (mapcat (fn [[_ {:keys [dispatch]}]]
                                         (map first dispatch))
                                       (:states spec))))]
      (doseq [s states]
        (is (contains? targets s) (str "QUIC state " s " unreachable")))))
  (testing "every QUIC dispatch target is a declared state"
    (let [spec   (http3/quic-connection-fsm-spec {})
          states (set (keys (:states spec)))]
      (doseq [[from {:keys [dispatch]}] (:states spec)
              [target _] dispatch]
        (is (contains? states target)
            (str "QUIC state " from " dispatches to undeclared " target))))))

(deftest stream-spec-shape-test
  (testing "every HTTP/3 stream state declared as initial or transition target"
    (let [spec    (http3/http3-stream-fsm-spec {})
          states  (set (keys (:states spec)))
          targets (set (concat [(:initial spec)]
                               (mapcat (fn [[_ {:keys [dispatch]}]]
                                         (map first dispatch))
                                       (:states spec))))]
      (doseq [s states]
        (is (contains? targets s) (str "HTTP/3 stream state " s " unreachable")))))
  (testing "every HTTP/3 stream dispatch target is a declared state"
    (let [spec   (http3/http3-stream-fsm-spec {})
          states (set (keys (:states spec)))]
      (doseq [[from {:keys [dispatch]}] (:states spec)
              [target _] dispatch]
        (is (contains? states target)
            (str "HTTP/3 stream state " from " dispatches to undeclared " target))))))

;; =============================================================================
;; Property tests
;; =============================================================================

(defspec quic-state-set-stable 25
  (prop/for-all [_ gen/small-integer]
    (let [spec   (http3/quic-connection-fsm-spec {})
          states (set (keys (:states spec)))]
      (and (contains? states ::http3/quic-start)
           (contains? states ::http3/quic-handshake)
           (contains? states ::http3/quic-established)
           (contains? states ::http3/quic-draining)
           (contains? states ::http3/quic-closed)
           (contains? states ::http3/quic-error)))))

(defspec h3-stream-state-set-stable 25
  (prop/for-all [_ gen/small-integer]
    (let [spec   (http3/http3-stream-fsm-spec {})
          states (set (keys (:states spec)))]
      (and (contains? states ::http3/h3-stream-idle)
           (contains? states ::http3/h3-stream-open)
           (contains? states ::http3/h3-stream-closed)
           (contains? states ::http3/h3-stream-half-closed-local)
           (contains? states ::http3/h3-stream-half-closed-remote)))))

(defspec quic-frame-helpers-pure 50
  (prop/for-all [t (gen/elements [http3/frame-crypto
                                  http3/frame-stream
                                  http3/frame-ack
                                  http3/frame-connection-close])]
    (let [f (http3/make-quic-frame t {:any "payload"})]
      (= t (:frame-type f)))))
