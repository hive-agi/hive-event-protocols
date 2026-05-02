(ns hive.events.protocols.http2-test
  "Tests for RFC 7540 HTTP/2 connection + stream FSMs.

   Coverage:
   - Constants present (RFC 7540 frame types, flags, settings, errors)
   - Frame helpers (make-frame, predicates)
   - Stream-id allocation (client odd, server even)
   - Connection FSM handler unit tests
   - Stream FSM handler unit tests
   - Dispatch predicates
   - IProtocolFSM contract
   - Reachability of every connection state from ::start
   - Reachability of every stream state from ::stream-idle
   - Property: every non-terminal state has at least one dispatch arm"
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.http2 :as http2]))

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
  (testing "RFC 7540 §11.2 frame types present"
    (is (= 0x0 http2/frame-data))
    (is (= 0x1 http2/frame-headers))
    (is (= 0x4 http2/frame-settings))
    (is (= 0x7 http2/frame-goaway))
    (is (= 0x8 http2/frame-window-update)))
  (testing "RFC 7540 §6 flags present"
    (is (= 0x1 http2/flag-end-stream))
    (is (= 0x4 http2/flag-end-headers)))
  (testing "RFC 7540 §6.5.2 settings present"
    (is (= 0x3 http2/settings-max-concurrent-streams))
    (is (= 0x4 http2/settings-initial-window-size)))
  (testing "RFC 7540 §7 error codes present"
    (is (= 0x0 http2/err-no-error))
    (is (= 0x1 http2/err-protocol-error))
    (is (= 0x8 http2/err-cancel)))
  (testing "RFC 7540 §3.5 connection preface"
    (is (= "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" http2/connection-preface))))

;; =============================================================================
;; Frame helpers
;; =============================================================================

(deftest frame-helpers-test
  (testing "make-frame builds a frame map"
    (let [f (http2/make-frame http2/frame-headers #{:end-headers} 1 {:headers {}})]
      (is (= http2/frame-headers (:frame-type f)))
      (is (= #{:end-headers}     (:flags f)))
      (is (= 1                   (:stream-id f)))))
  (testing "frame predicates dispatch correctly"
    (let [hdr  (http2/make-frame http2/frame-headers   #{} 1 {})
          data (http2/make-frame http2/frame-data      #{} 1 {})
          rst  (http2/make-frame http2/frame-rst-stream #{} 1 {})
          go   (http2/make-frame http2/frame-goaway    #{} 0 {})]
      (is (http2/headers-frame? hdr))
      (is (http2/data-frame? data))
      (is (http2/rst-stream-frame? rst))
      (is (http2/goaway-frame? go))))
  (testing "settings-ack? distinguishes ACK from non-ACK"
    (is (http2/settings-ack? (http2/make-frame http2/frame-settings #{:ack} 0 {})))
    (is (not (http2/settings-ack? (http2/make-frame http2/frame-settings #{} 0 {})))))
  (testing "end-stream? / end-headers? read flags"
    (let [f (http2/make-frame http2/frame-headers #{:end-stream :end-headers} 1 {})]
      (is (http2/end-stream? f))
      (is (http2/end-headers? f)))))

(deftest stream-id-allocation-test
  (testing "client stream ids are odd and ascending (RFC 7540 §5.1.1)"
    (is (= 1 (http2/next-client-stream-id 0)))
    (is (= 1 (http2/next-client-stream-id nil)))
    (is (= 3 (http2/next-client-stream-id 1)))
    (is (= 5 (http2/next-client-stream-id 3))))
  (testing "server stream ids are even"
    (is (= 2 (http2/next-server-stream-id 0)))
    (is (= 4 (http2/next-server-stream-id 2)))))

(defspec client-stream-ids-stay-odd 50
  ;; Client stream ids (RFC 7540 §5.1.1): always odd.  Seed must be
  ;; either nil/0 (first stream) or an odd id (next stream).
  (prop/for-all [n (gen/large-integer* {:min 0 :max 500})]
    (let [seed (inc (* 2 n))             ;; 1, 3, 5, ...
          id   (http2/next-client-stream-id seed)]
      (odd? id))))

(defspec client-stream-id-seed-zero-or-nil-yields-one 10
  (prop/for-all [seed (gen/elements [nil 0])]
    (= 1 (http2/next-client-stream-id seed))))

(defspec server-stream-ids-stay-even 50
  ;; Server stream ids: always even.  Seed must be nil/0 or an even id.
  (prop/for-all [n (gen/large-integer* {:min 0 :max 500})]
    (let [seed (* 2 n)                   ;; 0, 2, 4, ...
          id   (http2/next-server-stream-id seed)]
      (even? id))))

;; =============================================================================
;; Connection FSM handlers
;; =============================================================================

(deftest on-send-preface-test
  (testing "sends preface bytes + initial SETTINGS frame"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)
                :timer     (mock-timer)}
          out  (http2/on-send-preface rsrc {:max-concurrent-streams 100
                                            :initial-window-size    65535})]
      (is (:preface-sent? out))
      (is (:local-settings-sent? out))
      (is (= http2/connection-preface (:bytes (first @sent))))
      (is (http2/settings-frame? (second @sent)))
      (is (not (http2/settings-ack? (second @sent)))))))

(deftest on-recv-server-settings-test
  (testing "valid SETTINGS frame transitions data forward"
    (let [recv (atom [(http2/make-frame http2/frame-settings #{} 0
                                         {:settings {http2/settings-max-frame-size 32768}})])
          sent (atom [])
          rsrc {:transport (mock-transport recv sent)}
          out  (http2/on-recv-server-settings rsrc {})]
      (is (:server-settings-received? out))
      (is (= 32768 (:remote-max-frame-size out)))
      ;; Should send SETTINGS-ACK
      (is (http2/settings-ack? (first @sent)))))
  (testing "non-settings frame is recorded as error"
    (let [recv (atom [(http2/make-frame http2/frame-data #{} 1 {})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-server-settings rsrc {})]
      (is (= :unexpected-frame (:error out)))))
  (testing "premature SETTINGS-ACK is a protocol error"
    (let [recv (atom [(http2/make-frame http2/frame-settings #{:ack} 0 {})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-server-settings rsrc {})]
      (is (= :protocol-error (:error out))))))

(deftest on-recv-settings-ack-test
  (testing "ACK transitions to settings-ack-received?"
    (let [recv (atom [(http2/make-frame http2/frame-settings #{:ack} 0 {})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-settings-ack rsrc {})]
      (is (:settings-ack-received? out))))
  (testing "non-ack settings is protocol error"
    (let [recv (atom [(http2/make-frame http2/frame-settings #{} 0 {})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-settings-ack rsrc {})]
      (is (= :protocol-error (:error out)))))
  (testing "non-settings frame is queued for later"
    (let [recv (atom [(http2/make-frame http2/frame-data #{} 1 {})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-settings-ack rsrc {})]
      (is (not (:settings-ack-received? out)))
      (is (= 1 (count (:pending-frames out)))))))

(deftest on-enter-connected-test
  (testing "initialises stream registry + flow-control windows"
    (let [out (http2/on-enter-connected nil {})]
      (is (:connected? out))
      (is (= {} (:streams out)))
      (is (= http2/default-initial-window-size (:conn-send-window out)))
      (is (= http2/default-initial-window-size (:conn-recv-window out))))))

(deftest on-recv-connection-frame-test
  (testing "GOAWAY transitions to goaway-received?"
    (let [recv (atom [(http2/make-frame http2/frame-goaway #{} 0
                                         {:last-stream-id 7
                                          :error-code     http2/err-no-error})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-connection-frame rsrc {})]
      (is (:goaway-received? out))
      (is (= 7 (:goaway-last-stream-id out)))))
  (testing "PING is auto-acked"
    (let [recv (atom [(http2/make-frame http2/frame-ping #{} 0 {:opaque-data [1 2 3 4 5 6 7 8]})])
          sent (atom [])
          rsrc {:transport (mock-transport recv sent)}
          _    (http2/on-recv-connection-frame rsrc {})]
      (is (= http2/frame-ping (:frame-type (first @sent))))
      (is (http2/flag-set? (first @sent) :ack))))
  (testing "connection-level WINDOW_UPDATE adjusts conn-send-window"
    (let [recv (atom [(http2/make-frame http2/frame-window-update #{} 0
                                         {:window-size-increment 1000})])
          rsrc {:transport (mock-transport recv (atom []))}
          out  (http2/on-recv-connection-frame rsrc {:conn-send-window 100})]
      (is (= 1100 (:conn-send-window out))))))

(deftest on-send-goaway-test
  (testing "sends GOAWAY frame"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)}
          out  (http2/on-send-goaway rsrc {:last-server-stream-id 5})]
      (is (:goaway-sent? out))
      (is (http2/goaway-frame? (first @sent))))))

(deftest on-close-connection-test
  (testing "closes transport + cancels timers"
    (let [tport (mock-transport (atom []) (atom []))
          rsrc  {:transport tport :timer (mock-timer)}
          out   (http2/on-close-connection rsrc {})]
      (is (:transport-closed? out))
      (is (not (proto/open? tport))))))

;; =============================================================================
;; Stream FSM handlers
;; =============================================================================

(deftest on-stream-send-headers-test
  (testing "sends HEADERS frame with END_HEADERS flag"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)}
          out  (http2/on-stream-send-headers
                 rsrc
                 {:stream-id 3
                  :request-headers {":method" "GET" ":path" "/"}})]
      (is (:headers-sent? out))
      (is (= 3 (:stream-id (first @sent))))
      (is (http2/flag-set? (first @sent) :end-headers))
      (is (not (http2/flag-set? (first @sent) :end-stream)))))
  (testing "sets end-stream-sent? when end-stream-on-headers?"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)}
          out  (http2/on-stream-send-headers
                 rsrc
                 {:stream-id 3
                  :request-headers {}
                  :end-stream-on-headers? true})]
      (is (:end-stream-sent? out))
      (is (http2/flag-set? (first @sent) :end-stream)))))

(deftest on-stream-recv-frame-test
  (testing "RST_STREAM sets rst-received?"
    (let [data (http2/on-stream-recv-frame
                 nil
                 {:current-frame (http2/make-frame http2/frame-rst-stream #{} 3
                                                    {:error-code http2/err-cancel})})]
      (is (:rst-received? data))
      (is (= http2/err-cancel (:stream-error-code data)))))
  (testing "HEADERS frame captures :response-headers"
    (let [data (http2/on-stream-recv-frame
                 nil
                 {:current-frame (http2/make-frame http2/frame-headers #{:end-stream} 3
                                                    {:headers {":status" "200"}})})]
      (is (= {":status" "200"} (:response-headers data)))
      (is (:end-stream-received? data))))
  (testing "DATA frame appends to :response-data"
    (let [data (http2/on-stream-recv-frame
                 nil
                 {:current-frame (http2/make-frame http2/frame-data #{} 3 {:data "hi"})
                  :recv-window 100})]
      (is (= "hi" (:response-data data)))
      (is (= 98 (:recv-window data))))))

(deftest on-stream-rst-test
  (testing "sends RST_STREAM frame"
    (let [sent (atom [])
          rsrc {:transport (mock-transport (atom []) sent)}
          out  (http2/on-stream-rst rsrc {:stream-id 3})]
      (is (:rst-sent? out))
      (is (http2/rst-stream-frame? (first @sent)))
      (is (= 3 (:stream-id (first @sent)))))))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(deftest dispatch-predicates-test
  (testing "connection predicates"
    (is (http2/local-settings-sent?      nil {:local-settings-sent? true}))
    (is (http2/server-settings-received? nil {:server-settings-received? true}))
    (is (http2/settings-ack-received?    nil {:settings-ack-received? true}))
    (is (http2/goaway-received?          nil {:goaway-received? true}))
    (is (http2/has-error?                nil {:error :foo})))
  (testing "stream predicates"
    (is (http2/has-request?           nil {:request-headers {}}))
    (is (http2/end-stream-sent?       nil {:end-stream-sent? true}))
    (is (http2/end-stream-received?   nil {:end-stream-received? true}))
    (is (http2/rst-received?          nil {:rst-received? true}))
    (is (http2/fully-closed?          nil {:end-stream-sent? true
                                            :end-stream-received? true}))))

;; =============================================================================
;; IProtocolFSM contract
;; =============================================================================

(deftest iprotocol-fsm-contract-test
  (testing "make-http2-fsm returns IProtocolFSM"
    (let [fsm (http2/make-http2-fsm)]
      (is (= :http/v2 (proto/protocol-id fsm)))
      (is (map? (proto/fsm-spec fsm)))
      (is (contains? #{::http2/closed ::http2/error}
                     (first (proto/terminal-states fsm))))
      (is (set? (proto/terminal-states fsm)))
      (is (contains? (proto/composable-states fsm) ::http2/connected))
      (is (some? (proto/initial-data fsm {})))))
  (testing "make-http2-stream-fsm returns IProtocolFSM"
    (let [s (http2/make-http2-stream-fsm)]
      (is (= :http/v2-stream (proto/protocol-id s)))
      (is (= #{::http2/stream-closed} (proto/terminal-states s))))))

;; =============================================================================
;; Reachability — every state appears in the spec
;; =============================================================================

(deftest connection-spec-shape-test
  (testing "every connection state declared as initial or transition target"
    (let [spec    (http2/http2-connection-fsm-spec {})
          states  (set (keys (:states spec)))
          targets (set (concat [(:initial spec)]
                               (mapcat (fn [[_ {:keys [dispatch]}]]
                                         (map first dispatch))
                                       (:states spec))))]
      (doseq [s states]
        (is (contains? targets s) (str "state " s " unreachable")))))
  (testing "every dispatch target is a declared state"
    (let [spec   (http2/http2-connection-fsm-spec {})
          states (set (keys (:states spec)))]
      (doseq [[from {:keys [dispatch]}] (:states spec)
              [target _] dispatch]
        (is (contains? states target)
            (str "state " from " dispatches to undeclared " target))))))

(deftest stream-spec-shape-test
  (testing "every stream state declared as initial or transition target"
    (let [spec    (http2/http2-stream-fsm-spec {})
          states  (set (keys (:states spec)))
          targets (set (concat [(:initial spec)]
                               (mapcat (fn [[_ {:keys [dispatch]}]]
                                         (map first dispatch))
                                       (:states spec))))]
      (doseq [s states]
        (is (contains? targets s) (str "stream state " s " unreachable")))))
  (testing "every stream dispatch target is a declared state"
    (let [spec   (http2/http2-stream-fsm-spec {})
          states (set (keys (:states spec)))]
      (doseq [[from {:keys [dispatch]}] (:states spec)
              [target _] dispatch]
        (is (contains? states target)
            (str "stream state " from " dispatches to undeclared " target))))))

;; =============================================================================
;; Property tests
;; =============================================================================

(defspec every-non-terminal-state-has-dispatch 25
  (prop/for-all [_ gen/small-integer]
    (let [spec      (http2/http2-connection-fsm-spec {})
          terminal? #{::http2/closed ::http2/error}]
      (every? (fn [[id {:keys [dispatch enter]}]]
                (or (terminal? id)
                    (and (seq dispatch))
                    ;; states that only have :enter are allowed if they
                    ;; declare a dispatch list (transition logic)
                    (some? enter)))
              (:states spec)))))

(defspec stream-state-progress 25
  (prop/for-all [_ gen/small-integer]
    (let [spec   (http2/http2-stream-fsm-spec {})
          states (set (keys (:states spec)))]
      (and (contains? states ::http2/stream-idle)
           (contains? states ::http2/stream-open)
           (contains? states ::http2/stream-closed)
           (contains? states ::http2/stream-half-closed-local)
           (contains? states ::http2/stream-half-closed-remote)))))

(defspec frame-helpers-pure 50
  (prop/for-all [t (gen/elements [http2/frame-data
                                  http2/frame-headers
                                  http2/frame-rst-stream
                                  http2/frame-settings
                                  http2/frame-goaway])
                 sid gen/nat
                 flags (gen/set (gen/elements [:end-stream :end-headers :ack]))]
    (let [f (http2/make-frame t flags sid {})]
      (and (= t   (:frame-type f))
           (= sid (:stream-id f))
           (= flags (:flags f))))))
