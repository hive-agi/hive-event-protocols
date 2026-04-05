(ns hive.events.protocols.websocket-test
  "Tests for RFC 6455 WebSocket lifecycle FSM."
  (:require [clojure.test :refer [deftest is testing]]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.websocket :as ws]))

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
;; Handshake helpers
;; =============================================================================

(defn make-valid-handshake-response
  "Build a mock 101 response with correct Sec-WebSocket-Accept for the given key."
  [ws-key]
  {:status  101
   :headers {"Sec-WebSocket-Accept" (ws/sec-websocket-accept ws-key)}})

;; =============================================================================
;; Unit tests — sec-websocket-accept
;; =============================================================================

(deftest sec-websocket-accept-test
  (testing "RFC 6455 §4.2.2 example"
    ;; The RFC specifies this exact test vector
    (is (= "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
           (ws/sec-websocket-accept "dGhlIHNhbXBsZSBub25jZQ==")))))

(deftest valid-accept-test
  (testing "valid accept header matches"
    (is (ws/valid-accept? "dGhlIHNhbXBsZSBub25jZQ=="
                          "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")))
  (testing "invalid accept header rejected"
    (is (not (ws/valid-accept? "dGhlIHNhbXBsZSBub25jZQ=="
                               "INVALID")))))

;; =============================================================================
;; Frame parsing
;; =============================================================================

(deftest parse-frame-test
  (testing "text frame"
    (is (= :text (:type (ws/parse-frame {:opcode 0x1 :fin? true :payload [72 105]})))))
  (testing "binary frame"
    (is (= :binary (:type (ws/parse-frame {:opcode 0x2 :fin? true :payload [0 1]})))))
  (testing "close frame"
    (is (= :close (:type (ws/parse-frame {:opcode 0x8 :fin? true :payload [3 -24]})))))
  (testing "ping frame"
    (is (= :ping (:type (ws/parse-frame {:opcode 0x9 :fin? true :payload nil})))))
  (testing "pong frame"
    (is (= :pong (:type (ws/parse-frame {:opcode 0xA :fin? true :payload nil})))))
  (testing "continuation frame"
    (is (= :continuation (:type (ws/parse-frame {:opcode 0x0 :fin? true :payload [1]})))))
  (testing "unknown opcode"
    (is (= :unknown (:type (ws/parse-frame {:opcode 0x3 :fin? true :payload nil}))))))

(deftest parse-close-payload-test
  (testing "code 1000 normal closure"
    (let [payload [(unchecked-byte 0x03) (unchecked-byte 0xE8)]]
      (is (= {:close-code 1000 :close-reason ""}
             (ws/parse-close-payload payload)))))
  (testing "code with reason string"
    (let [reason-bytes (seq (.getBytes "bye" "UTF-8"))
          payload (vec (concat [(unchecked-byte 0x03) (unchecked-byte 0xE8)]
                               reason-bytes))]
      (is (= 1000 (:close-code (ws/parse-close-payload payload))))
      (is (= "bye" (:close-reason (ws/parse-close-payload payload))))))
  (testing "nil payload defaults to 1000"
    (is (= 1000 (:close-code (ws/parse-close-payload nil))))))

;; =============================================================================
;; Handler tests — direct invocation (no FSM engine needed)
;; =============================================================================

(deftest on-initiate-handshake-test
  (testing "sends upgrade request with Sec-WebSocket-Key"
    (let [sent     (atom [])
          recv-q   (atom [])
          tp       (mock-transport recv-q sent)
          res      {:transport tp}
          data     {}
          result   (ws/on-initiate-handshake res data)]
      (is (string? (:ws-key result)))
      (is (= 1 (count @sent)))
      (is (= "websocket" (get-in (first @sent) [:headers "Upgrade"]))))))

(deftest on-handshake-response-valid-test
  (testing "valid 101 response completes handshake"
    (let [ws-key "test-key-123"
          resp   (make-valid-handshake-response ws-key)
          recv-q (atom [resp])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:ws-key ws-key}
          result (ws/on-handshake-response res data)]
      (is (:handshake-complete? result))
      (is (nil? (:error result))))))

(deftest on-handshake-response-invalid-status-test
  (testing "non-101 status triggers error"
    (let [recv-q (atom [{:status 400 :headers {}}])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:ws-key "k"}
          result (ws/on-handshake-response res data)]
      (is (= :invalid-status (:error result)))
      (is (= :handshake (:error-phase result))))))

(deftest on-handshake-response-invalid-accept-test
  (testing "wrong Sec-WebSocket-Accept triggers error"
    (let [recv-q (atom [{:status 101 :headers {"Sec-WebSocket-Accept" "WRONG"}}])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:ws-key "k"}
          result (ws/on-handshake-response res data)]
      (is (= :invalid-accept (:error result))))))

;; =============================================================================
;; Open-state frame handling
;; =============================================================================

(deftest on-receive-text-frame-test
  (testing "complete text frame appended to :frames"
    (let [frame  {:opcode 0x1 :fin? true :payload [72 105]}
          recv-q (atom [frame])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:frames [] :max-frame-size 65536 :recv-timeout-ms 5000}
          result (ws/on-receive-frame res data)]
      (is (= 1 (count (:frames result))))
      (is (= :text (:type (first (:frames result))))))))

(deftest on-receive-ping-responds-pong-test
  (testing "ping triggers automatic pong response"
    (let [payload [1 2 3]
          frame   {:opcode 0x9 :fin? true :payload payload}
          recv-q  (atom [frame])
          sent    (atom [])
          tp      (mock-transport recv-q sent)
          res     {:transport tp}
          data    {:frames [] :max-frame-size 65536 :recv-timeout-ms 5000}
          result  (ws/on-receive-frame res data)]
      ;; Should have sent a pong
      (is (= 1 (count @sent)))
      (is (= ws/opcode-pong (:opcode (first @sent))))
      (is (= payload (:payload (first @sent))))
      ;; Ping recorded in frames
      (is (= :ping (:type (first (:frames result))))))))

(deftest on-receive-pong-test
  (testing "pong frame recorded without sending"
    (let [frame  {:opcode 0xA :fin? true :payload [1 2 3]}
          recv-q (atom [frame])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:frames [] :max-frame-size 65536}
          result (ws/on-receive-frame res data)]
      (is (= 0 (count @sent)))
      (is (= :pong (:type (first (:frames result))))))))

(deftest on-receive-close-frame-test
  (testing "peer close frame sets :peer-close?"
    (let [payload [(unchecked-byte 0x03) (unchecked-byte 0xE8)]  ;; 1000
          frame   {:opcode 0x8 :fin? true :payload payload}
          recv-q  (atom [frame])
          sent    (atom [])
          tp      (mock-transport recv-q sent)
          res     {:transport tp}
          data    {:frames [] :max-frame-size 65536}
          result  (ws/on-receive-frame res data)]
      (is (:peer-close? result))
      (is (= 1000 (:close-code result))))))

;; =============================================================================
;; Fragment assembly
;; =============================================================================

(deftest fragment-assembly-test
  (testing "fragmented text message assembled across frames"
    (let [frag1  {:opcode 0x1 :fin? false :payload [72]}    ;; text, not final
          frag2  {:opcode 0x0 :fin? true  :payload [105]}   ;; continuation, final
          recv-q (atom [frag1])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:frames [] :max-frame-size 65536}
          ;; Process first fragment
          d1     (ws/on-receive-frame res data)]
      (is (= [72] (:fragment-buffer d1)))
      (is (= :text (:fragment-type d1)))
      (is (= 0 (count (:frames d1))))
      ;; Process second fragment
      (reset! recv-q [frag2])
      (let [d2 (ws/on-receive-frame res d1)]
        (is (nil? (:fragment-buffer d2)))
        (is (= 1 (count (:frames d2))))
        (is (= :text (:type (first (:frames d2)))))
        (is (= [72 105] (:payload (first (:frames d2)))))))))

;; =============================================================================
;; Close handshake
;; =============================================================================

(deftest on-initiate-close-test
  (testing "sends close frame with code and reason"
    (let [sent   (atom [])
          recv-q (atom [])
          tp     (mock-transport recv-q sent)
          timer  (mock-timer)
          res    {:transport tp :timer timer}
          data   {:close-code 1000 :close-reason "normal"}
          result (ws/on-initiate-close res data)]
      (is (:close-sent? result))
      (is (= 1 (count @sent)))
      (is (= ws/opcode-close (:opcode (first @sent)))))))

(deftest on-await-peer-close-test
  (testing "receives peer close frame → close-done"
    (let [payload [(unchecked-byte 0x03) (unchecked-byte 0xE8)]
          close-frame {:opcode 0x8 :fin? true :payload payload}
          recv-q  (atom [close-frame])
          sent    (atom [])
          tp      (mock-transport recv-q sent)
          res     {:transport tp}
          data    {:close-timeout-ms 5000}
          result  (ws/on-await-peer-close res data)]
      (is (:peer-close? result))
      (is (= 1000 (:close-code result))))))

(deftest on-await-peer-close-timeout-test
  (testing "recv error → close-timeout"
    (let [recv-q (atom [])   ;; empty → :no-data error
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          data   {:close-timeout-ms 100}
          result (ws/on-await-peer-close res data)]
      (is (:close-timeout? result)))))

;; =============================================================================
;; Transport teardown
;; =============================================================================

(deftest on-close-transport-test
  (testing "closes transport and cancels timers"
    (let [recv-q (atom [])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          timer  (mock-timer)
          res    {:transport tp :timer timer}
          data   {}
          result (ws/on-close-transport res data)]
      (is (:transport-closed? result))
      (is (not (proto/open? tp))))))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(deftest dispatch-predicates-test
  (testing "handshake-ok? when handshake-complete?"
    (is (ws/handshake-ok? nil {:handshake-complete? true}))
    (is (not (ws/handshake-ok? nil {}))))
  (testing "handshake-err? when error present"
    (is (ws/handshake-err? nil {:error :boom}))
    (is (not (ws/handshake-err? nil {}))))
  (testing "peer-close? when peer sent close"
    (is (ws/peer-close? nil {:peer-close? true}))
    (is (not (ws/peer-close? nil {}))))
  (testing "close-done? on peer-close or timeout"
    (is (ws/close-done? nil {:peer-close? true}))
    (is (ws/close-done? nil {:close-timeout? true}))
    (is (not (ws/close-done? nil {})))))

;; =============================================================================
;; IProtocolFSM reification
;; =============================================================================

(deftest make-websocket-fsm-test
  (testing "factory returns valid IProtocolFSM"
    (let [fsm (ws/make-websocket-fsm {:ping-interval-ms 15000})]
      (is (= :websocket (proto/protocol-id fsm)))
      (is (map? (proto/fsm-spec fsm)))
      (is (= #{::ws/closed ::ws/error} (proto/terminal-states fsm)))
      (is (contains? (proto/composable-states fsm) ::ws/open))))

  (testing "initial-data includes defaults and overrides"
    (let [fsm  (ws/make-websocket-fsm {:ping-interval-ms 10000})
          data (proto/initial-data fsm {:close-timeout-ms 3000})]
      (is (= 10000 (:ping-interval-ms data)))
      (is (= 3000 (:close-timeout-ms data)))
      (is (= [] (:frames data)))
      (is (nil? (:close-code data))))))

;; =============================================================================
;; Happy path integration — connecting → open → closing → closed
;; =============================================================================

(deftest happy-path-lifecycle-test
  (testing "full lifecycle via direct handler calls"
    (let [ws-key  "test-lifecycle-key"
          sent    (atom [])
          ;; Script: handshake response, text frame, peer close
          recv-q  (atom [(make-valid-handshake-response ws-key)
                         {:opcode 0x1 :fin? true :payload [72 105]}
                         {:opcode 0x8 :fin? true
                          :payload [(unchecked-byte 0x03) (unchecked-byte 0xE8)]}])
          tp      (mock-transport recv-q sent)
          timer   (mock-timer)
          res     {:transport tp :timer timer}

          ;; 1. connecting — initiate handshake
          d0      {:ws-key ws-key}
          d1      (ws/on-initiate-handshake res d0)
          _       (is (= ws-key (:ws-key d1)))

          ;; 2. connecting — validate response
          d2      (ws/on-handshake-response res d1)
          _       (is (:handshake-complete? d2))
          _       (is (ws/handshake-ok? res d2))

          ;; 3. open — enter
          d3      (ws/on-open res d2)
          _       (is (= [] (:frames d3)))

          ;; 4. open — receive text frame
          d4      (ws/on-receive-frame res d3)
          _       (is (= 1 (count (:frames d4))))
          _       (is (= :text (:type (first (:frames d4)))))

          ;; 5. open — receive peer close → transitions to closing
          d5      (ws/on-receive-frame res d4)
          _       (is (:peer-close? d5))
          _       (is (= 1000 (:close-code d5)))

          ;; 6. closing — send our close frame
          d6      (ws/on-initiate-close res d5)
          _       (is (:close-sent? d6))

          ;; 7. closed — tear down
          d7      (ws/on-close-transport res d6)]

      (is (:transport-closed? d7))
      (is (not (proto/open? tp)))

      ;; Verify sent frames: upgrade, pong (none here), close
      (let [sent-types (mapv #(or (:type %) (:opcode %)) @sent)]
        (is (= :http-upgrade (first sent-types)))
        (is (= ws/opcode-close (last sent-types)))))))

;; =============================================================================
;; Error path — invalid handshake
;; =============================================================================

(deftest error-on-invalid-handshake-test
  (testing "bad status code → error state"
    (let [recv-q (atom [{:status 403 :headers {}}])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          d0     {:ws-key "k"}
          d1     (ws/on-initiate-handshake res d0)
          d2     (ws/on-handshake-response res d1)]
      (is (ws/handshake-err? res d2))
      (is (= :invalid-status (:error d2)))
      ;; Cleanup
      (let [d3 (ws/on-close-transport res d2)]
        (is (:transport-closed? d3))))))
