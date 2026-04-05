(ns hive.events.protocols.tcp-test
  "Tests for RFC 793 TCP Connection Lifecycle FSM.

   Covers:
   - Segment helpers (make-segment, flag predicates)
   - Individual handler functions for each state
   - Dispatch predicates
   - IProtocolFSM contract
   - Active open happy path (closed → syn-sent → established → fin-wait-1 → fin-wait-2 → time-wait → closed)
   - Passive open happy path (closed → listen → syn-received → established → close-wait → last-ack → closed)
   - Simultaneous close path (established → fin-wait-1 → closing → time-wait → closed)
   - Error paths (RST during handshake, recv errors)"
  (:require [clojure.test :refer [deftest is testing]]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.tcp :as tcp]))

;; =============================================================================
;; Mock transport — records sends, plays back scripted receives
;; =============================================================================

(defn mock-transport
  "Create a mock ITransport that records sends and returns scripted responses.

   recv-queue — atom of vector; each recv! pops the first entry.
   sent-log   — atom of vector; each send! conjs the segment."
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
;; Test helpers
;; =============================================================================

(defn make-resources
  "Build standard test resources from recv queue and sent log."
  ([recv-q sent]
   {:transport (mock-transport recv-q sent)})
  ([recv-q sent timer]
   {:transport (mock-transport recv-q sent)
    :timer     timer}))

;; =============================================================================
;; Segment helpers
;; =============================================================================

(deftest make-segment-test
  (testing "basic SYN segment"
    (let [seg (tcp/make-segment #{:syn} 1000 0)]
      (is (= #{:syn} (:flags seg)))
      (is (= 1000 (:seq-num seg)))
      (is (= 0 (:ack-num seg)))
      (is (= 65535 (:window seg)))))

  (testing "segment with payload and custom window"
    (let [seg (tcp/make-segment #{:ack :psh} 5000 3000
                                :payload [1 2 3] :window 32768)]
      (is (= #{:ack :psh} (:flags seg)))
      (is (= [1 2 3] (:payload seg)))
      (is (= 32768 (:window seg)))))

  (testing "flags coerced to set"
    (let [seg (tcp/make-segment [:syn :ack] 100 200)]
      (is (set? (:flags seg)))
      (is (contains? (:flags seg) :syn))
      (is (contains? (:flags seg) :ack)))))

(deftest flag-predicates-test
  (testing "individual flag checks"
    (let [syn-seg     {:flags #{:syn}}
          ack-seg     {:flags #{:ack}}
          fin-seg     {:flags #{:fin}}
          rst-seg     {:flags #{:rst}}
          syn-ack-seg {:flags #{:syn :ack}}
          fin-ack-seg {:flags #{:fin :ack}}]
      (is (tcp/syn? syn-seg))
      (is (not (tcp/syn? ack-seg)))
      (is (tcp/ack? ack-seg))
      (is (tcp/fin? fin-seg))
      (is (tcp/rst? rst-seg))
      (is (tcp/syn-ack? syn-ack-seg))
      (is (not (tcp/syn-ack? syn-seg)))
      (is (tcp/fin-ack? fin-ack-seg))
      (is (not (tcp/fin-ack? fin-seg))))))

;; =============================================================================
;; ::closed state handlers
;; =============================================================================

(deftest on-close-cleanup-initial-test
  (testing "initial entry (open-mode present) is a no-op"
    (let [sent   (atom [])
          recv-q (atom [])
          res    (make-resources recv-q sent)
          data   {:open-mode :active}
          result (tcp/on-close-cleanup res data)]
      (is (= :active (:open-mode result)))
      (is (nil? (:connection-closed? result)))
      (is (proto/open? (:transport res))))))

(deftest on-close-cleanup-terminal-test
  (testing "terminal re-entry (open-mode consumed) closes transport and timers"
    (let [sent   (atom [])
          recv-q (atom [])
          timer  (mock-timer)
          res    (make-resources recv-q sent timer)
          data   {:connection-established? true}  ;; no :open-mode → terminal
          result (tcp/on-close-cleanup res data)]
      (is (:connection-closed? result))
      (is (:transport-closed? result))
      (is (not (proto/open? (:transport res)))))))

(deftest on-open-connection-test
  (testing "active open sets local-seq"
    (let [data   {:open-mode :active :initial-seq-num 42}
          result (tcp/on-open-connection nil data)]
      (is (= 42 (:local-seq result)))))

  (testing "active open generates random ISN if none provided"
    (let [data   {:open-mode :active}
          result (tcp/on-open-connection nil data)]
      (is (number? (:local-seq result)))))

  (testing "passive open is no-op"
    (let [data   {:open-mode :passive}
          result (tcp/on-open-connection nil data)]
      (is (= data result))))

  (testing "nil open-mode (terminal) is no-op"
    (let [data   {:connection-closed? true}
          result (tcp/on-open-connection nil data)]
      (is (= data result)))))

;; =============================================================================
;; ::listen state handlers
;; =============================================================================

(deftest on-enter-listen-test
  (testing "sets listening?, consumes open-mode"
    (let [data   {:open-mode :passive :extra :kept}
          result (tcp/on-enter-listen nil data)]
      (is (:listening? result))
      (is (nil? (:open-mode result)))
      (is (= :kept (:extra result))))))

(deftest on-listen-recv-syn-test
  (testing "SYN sets syn-received? with remote seq"
    (let [syn    (tcp/make-segment #{:syn} 5000 0 :window 32768)
          recv-q (atom [syn])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:recv-timeout-ms 1000}
          result (tcp/on-listen-recv res data)]
      (is (:syn-received? result))
      (is (= 5000 (:remote-seq result)))
      (is (= 32768 (:remote-window result)))
      (is (number? (:local-seq result))))))

(deftest on-listen-recv-rst-test
  (testing "RST is silently ignored per RFC 793"
    (let [rst    (tcp/make-segment #{:rst} 0 0)
          recv-q (atom [rst])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {}
          result (tcp/on-listen-recv res data)]
      (is (nil? (:error result)))
      (is (nil? (:syn-received? result))))))

(deftest on-listen-recv-ack-error-test
  (testing "unexpected ACK sets error"
    (let [ack-seg (tcp/make-segment #{:ack} 0 0)
          recv-q  (atom [ack-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {}
          result  (tcp/on-listen-recv res data)]
      (is (= :unexpected-ack (:error result)))
      (is (= :listen (:error-phase result))))))

(deftest on-listen-recv-error-test
  (testing "recv error propagated"
    (let [recv-q (atom [])  ;; empty → :no-data error
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {}
          result (tcp/on-listen-recv res data)]
      (is (= :no-data (:error result))))))

;; =============================================================================
;; ::syn-sent state handlers
;; =============================================================================

(deftest on-send-syn-test
  (testing "sends SYN, consumes open-mode"
    (let [recv-q (atom [])
          sent   (atom [])
          timer  (mock-timer)
          res    (make-resources recv-q sent timer)
          data   {:local-seq 1000 :open-mode :active}
          result (tcp/on-send-syn res data)]
      (is (:syn-sent? result))
      (is (nil? (:open-mode result)))
      (is (= 1 (count @sent)))
      (is (tcp/syn? (first @sent)))
      (is (= 1000 (:seq-num (first @sent)))))))

(deftest on-syn-sent-recv-syn-ack-test
  (testing "SYN+ACK completes three-way handshake"
    (let [syn-ack (tcp/make-segment #{:syn :ack} 3000 1001 :window 49152)
          recv-q  (atom [syn-ack])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:local-seq 1000 :connect-timeout-ms 1000}
          result  (tcp/on-syn-sent-recv res data)]
      ;; ACK sent back
      (is (= 1 (count @sent)))
      (is (tcp/ack? (first @sent)))
      (is (= 1001 (:seq-num (first @sent))))   ;; local-seq + 1
      (is (= 3001 (:ack-num (first @sent))))   ;; remote seq + 1
      ;; State updated
      (is (:syn-ack-received? result))
      (is (= 3001 (:remote-seq result)))
      (is (= 49152 (:remote-window result)))
      (is (= 1001 (:local-seq result))))))

(deftest on-syn-sent-recv-syn-test
  (testing "bare SYN triggers simultaneous open"
    (let [syn    (tcp/make-segment #{:syn} 7000 0 :window 16384)
          recv-q (atom [syn])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1000 :connect-timeout-ms 1000}
          result (tcp/on-syn-sent-recv res data)]
      (is (:syn-received? result))
      (is (= 7000 (:remote-seq result)))
      (is (= 16384 (:remote-window result)))
      (is (nil? (:syn-ack-received? result))))))

(deftest on-syn-sent-recv-rst-test
  (testing "RST sets error"
    (let [rst    (tcp/make-segment #{:rst} 0 0)
          recv-q (atom [rst])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1000 :connect-timeout-ms 1000}
          result (tcp/on-syn-sent-recv res data)]
      (is (:rst-received? result))
      (is (= :connection-reset (:error result))))))

;; =============================================================================
;; ::syn-received state handlers
;; =============================================================================

(deftest on-send-syn-ack-test
  (testing "sends SYN+ACK with correct seq/ack numbers"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1000 :remote-seq 5000}
          result (tcp/on-send-syn-ack res data)]
      (is (:syn-ack-sent? result))
      (is (= 5001 (:local-ack result)))
      (is (= 1 (count @sent)))
      (let [seg (first @sent)]
        (is (tcp/syn-ack? seg))
        (is (= 1000 (:seq-num seg)))
        (is (= 5001 (:ack-num seg)))))))

(deftest on-syn-received-recv-ack-test
  (testing "ACK completes handshake"
    (let [ack-seg (tcp/make-segment #{:ack} 5001 1001)
          recv-q  (atom [ack-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:connect-timeout-ms 1000}
          result  (tcp/on-syn-received-recv res data)]
      (is (:ack-received? result)))))

(deftest on-syn-received-recv-rst-test
  (testing "RST during syn-received sets error"
    (let [rst    (tcp/make-segment #{:rst} 0 0)
          recv-q (atom [rst])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:connect-timeout-ms 1000}
          result (tcp/on-syn-received-recv res data)]
      (is (:rst-received? result))
      (is (= :connection-reset (:error result))))))

;; =============================================================================
;; ::established state handlers
;; =============================================================================

(deftest on-enter-established-test
  (testing "marks connection established, inits receive buffer"
    (let [data   {:local-seq 1001}
          result (tcp/on-enter-established nil data)]
      (is (:connection-established? result))
      (is (= [] (:segments-received result))))))

(deftest on-established-recv-data-test
  (testing "data segment is ACKed and accumulated"
    (let [seg    (tcp/make-segment #{:ack} 3001 1001 :payload [72 101 108 108 111])
          recv-q (atom [seg])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1001 :segments-received [] :recv-timeout-ms 1000}
          result (tcp/on-established-recv res data)]
      ;; ACK sent for data
      (is (= 1 (count @sent)))
      (is (tcp/ack? (first @sent)))
      ;; Segment accumulated
      (is (= 1 (count (:segments-received result))))
      (is (= [72 101 108 108 111] (:payload (first (:segments-received result))))))))

(deftest on-established-recv-fin-test
  (testing "FIN from peer is ACKed and sets fin-received?"
    (let [fin    (tcp/make-segment #{:fin} 3006 1001)
          recv-q (atom [fin])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1001 :segments-received [] :recv-timeout-ms 1000}
          result (tcp/on-established-recv res data)]
      (is (:fin-received? result))
      (is (= 3007 (:remote-seq result)))
      ;; ACK for FIN sent
      (is (= 1 (count @sent)))
      (is (tcp/ack? (first @sent)))
      (is (= 3007 (:ack-num (first @sent)))))))

(deftest on-established-close-requested-test
  (testing "close-requested? causes immediate return for dispatch"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:close-requested? true :local-seq 1001}
          result (tcp/on-established-recv res data)]
      ;; No recv attempted, data passed through
      (is (:close-requested? result))
      (is (= 0 (count @sent))))))

(deftest on-established-recv-rst-test
  (testing "RST sets error"
    (let [rst    (tcp/make-segment #{:rst} 0 0)
          recv-q (atom [rst])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1001 :segments-received [] :recv-timeout-ms 1000}
          result (tcp/on-established-recv res data)]
      (is (= :connection-reset (:error result))))))

;; =============================================================================
;; ::fin-wait-1 state handlers
;; =============================================================================

(deftest on-send-fin-test
  (testing "sends FIN+ACK, increments local-seq"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1001 :remote-seq 3007}
          result (tcp/on-send-fin res data)]
      (is (:fin-sent? result))
      (is (= 1002 (:local-seq result)))
      (is (= 1 (count @sent)))
      (let [seg (first @sent)]
        (is (tcp/fin? seg))
        (is (tcp/ack? seg))
        (is (= 1001 (:seq-num seg)))
        (is (= 3007 (:ack-num seg)))))))

(deftest on-fin-wait-1-recv-ack-test
  (testing "ACK of our FIN transitions toward fin-wait-2"
    (let [ack-seg (tcp/make-segment #{:ack} 3007 1002)
          recv-q  (atom [ack-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:local-seq 1002 :recv-timeout-ms 1000}
          result  (tcp/on-fin-wait-1-recv res data)]
      (is (:ack-of-fin-received? result))
      (is (nil? (:fin-received? result))))))

(deftest on-fin-wait-1-recv-fin-test
  (testing "FIN from peer (simultaneous close) → sends ACK, sets fin-received?"
    (let [fin    (tcp/make-segment #{:fin} 3007 1002)
          recv-q (atom [fin])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1002 :recv-timeout-ms 1000}
          result (tcp/on-fin-wait-1-recv res data)]
      (is (:fin-received? result))
      (is (nil? (:ack-of-fin-received? result)))
      (is (= 3008 (:remote-seq result)))
      ;; ACK sent for peer FIN
      (is (= 1 (count @sent)))
      (is (tcp/ack? (first @sent)))
      (is (= 3008 (:ack-num (first @sent)))))))

(deftest on-fin-wait-1-recv-fin-ack-test
  (testing "FIN+ACK sets both flags → time-wait"
    (let [fin-ack (tcp/make-segment #{:fin :ack} 3007 1002)
          recv-q  (atom [fin-ack])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:local-seq 1002 :recv-timeout-ms 1000}
          result  (tcp/on-fin-wait-1-recv res data)]
      (is (:fin-received? result))
      (is (:ack-of-fin-received? result))
      (is (= 3008 (:remote-seq result)))
      ;; ACK sent
      (is (= 1 (count @sent))))))

;; =============================================================================
;; ::fin-wait-2 state handler
;; =============================================================================

(deftest on-fin-wait-2-recv-fin-test
  (testing "FIN received → ACK sent, fin-received? set"
    (let [fin    (tcp/make-segment #{:fin} 3007 1002)
          recv-q (atom [fin])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1002 :recv-timeout-ms 1000}
          result (tcp/on-fin-wait-2-recv res data)]
      (is (:fin-received? result))
      (is (= 3008 (:remote-seq result)))
      (is (= 1 (count @sent)))
      (is (tcp/ack? (first @sent))))))

(deftest on-fin-wait-2-recv-non-fin-test
  (testing "non-FIN segment is ignored"
    (let [ack-seg (tcp/make-segment #{:ack} 3007 1002)
          recv-q  (atom [ack-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:local-seq 1002 :recv-timeout-ms 1000}
          result  (tcp/on-fin-wait-2-recv res data)]
      (is (nil? (:fin-received? result))))))

;; =============================================================================
;; ::close-wait state handlers
;; =============================================================================

(deftest on-enter-close-wait-test
  (testing "sets peer-closed?"
    (let [data   {}
          result (tcp/on-enter-close-wait nil data)]
      (is (:peer-closed? result)))))

(deftest on-close-wait-handle-test
  (testing "no-op handle — passes data through"
    (let [data   {:peer-closed? true :extra :data}
          result (tcp/on-close-wait-handle nil data)]
      (is (= data result)))))

;; =============================================================================
;; ::closing state handler
;; =============================================================================

(deftest on-closing-recv-ack-test
  (testing "ACK of our FIN sets ack-of-fin-received?"
    (let [ack-seg (tcp/make-segment #{:ack} 3008 1002)
          recv-q  (atom [ack-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:recv-timeout-ms 1000}
          result  (tcp/on-closing-recv res data)]
      (is (:ack-of-fin-received? result)))))

(deftest on-closing-recv-non-ack-test
  (testing "non-ACK segment ignored"
    (let [syn-seg (tcp/make-segment #{:syn} 0 0)
          recv-q  (atom [syn-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:recv-timeout-ms 1000}
          result  (tcp/on-closing-recv res data)]
      (is (nil? (:ack-of-fin-received? result))))))

;; =============================================================================
;; ::last-ack state handlers
;; =============================================================================

(deftest on-send-fin-last-ack-test
  (testing "sends FIN+ACK, increments local-seq"
    (let [recv-q (atom [])
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 5000 :remote-seq 3008}
          result (tcp/on-send-fin-last-ack res data)]
      (is (:fin-sent? result))
      (is (= 5001 (:local-seq result)))
      (is (= 1 (count @sent)))
      (is (tcp/fin-ack? (first @sent))))))

(deftest on-last-ack-recv-ack-test
  (testing "ACK of our FIN sets ack-of-fin-received?"
    (let [ack-seg (tcp/make-segment #{:ack} 3008 5001)
          recv-q  (atom [ack-seg])
          sent    (atom [])
          res     (make-resources recv-q sent)
          data    {:recv-timeout-ms 1000}
          result  (tcp/on-last-ack-recv res data)]
      (is (:ack-of-fin-received? result)))))

;; =============================================================================
;; ::time-wait state handlers
;; =============================================================================

(deftest on-enter-time-wait-with-timer-test
  (testing "starts 2MSL timer"
    (let [timer  (mock-timer)
          res    {:timer timer}
          data   {:msl-ms 1000}
          result (tcp/on-enter-time-wait res data)]
      (is (= 2000 (:time-wait-ms result)))
      (is (fn? (:cancel-time-wait result)))
      (is (nil? (:time-wait-expired? result))))))

(deftest on-enter-time-wait-no-timer-test
  (testing "no timer → immediate expiration"
    (let [res    {}
          data   {:msl-ms 1000}
          result (tcp/on-enter-time-wait res data)]
      (is (:time-wait-expired? result)))))

(deftest on-time-wait-handle-test
  (testing "no-op — passes data through"
    (let [data   {:time-wait-expired? true}
          result (tcp/on-time-wait-handle nil data)]
      (is (= data result)))))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(deftest dispatch-predicates-test
  (testing "passive-open?"
    (is (tcp/passive-open? nil {:open-mode :passive}))
    (is (not (tcp/passive-open? nil {:open-mode :active})))
    (is (not (tcp/passive-open? nil {}))))

  (testing "active-open?"
    (is (tcp/active-open? nil {:open-mode :active}))
    (is (not (tcp/active-open? nil {:open-mode :passive}))))

  (testing "syn-received?"
    (is (tcp/syn-received? nil {:syn-received? true}))
    (is (not (tcp/syn-received? nil {}))))

  (testing "syn-ack-received?"
    (is (tcp/syn-ack-received? nil {:syn-ack-received? true}))
    (is (not (tcp/syn-ack-received? nil {}))))

  (testing "ack-received?"
    (is (tcp/ack-received? nil {:ack-received? true}))
    (is (not (tcp/ack-received? nil {}))))

  (testing "ack-of-fin?"
    (is (tcp/ack-of-fin? nil {:ack-of-fin-received? true}))
    (is (not (tcp/ack-of-fin? nil {}))))

  (testing "fin-received?"
    (is (tcp/fin-received? nil {:fin-received? true}))
    (is (not (tcp/fin-received? nil {}))))

  (testing "fin-ack-received? (requires both)"
    (is (tcp/fin-ack-received? nil {:fin-received? true :ack-of-fin-received? true}))
    (is (not (tcp/fin-ack-received? nil {:fin-received? true})))
    (is (not (tcp/fin-ack-received? nil {:ack-of-fin-received? true}))))

  (testing "close-requested?"
    (is (tcp/close-requested? nil {:close-requested? true}))
    (is (not (tcp/close-requested? nil {}))))

  (testing "time-wait-expired?"
    (is (tcp/time-wait-expired? nil {:time-wait-expired? true}))
    (is (not (tcp/time-wait-expired? nil {}))))

  (testing "has-error?"
    (is (tcp/has-error? nil {:error :something}))
    (is (not (tcp/has-error? nil {}))))

  (testing "always"
    (is (tcp/always nil {}))
    (is (tcp/always nil {:anything true}))))

;; =============================================================================
;; IProtocolFSM contract
;; =============================================================================

(deftest make-tcp-fsm-test
  (testing "factory returns valid IProtocolFSM"
    (let [fsm (tcp/make-tcp-fsm {:msl-ms 60000})]
      (is (= :tcp (proto/protocol-id fsm)))
      (is (map? (proto/fsm-spec fsm)))
      (is (= #{::tcp/closed} (proto/terminal-states fsm)))
      (is (contains? (proto/composable-states fsm) ::tcp/established))
      (is (= :application (get (proto/composable-states fsm) ::tcp/established)))))

  (testing "initial-data includes defaults and overrides"
    (let [fsm  (tcp/make-tcp-fsm {:msl-ms 60000})
          data (proto/initial-data fsm {:open-mode :active :recv-timeout-ms 5000})]
      (is (= :active (:open-mode data)))
      (is (= 60000 (:msl-ms data)))
      (is (= 5000 (:recv-timeout-ms data)))
      (is (= [] (:segments-received data)))
      (is (false? (:connection-established? data)))
      (is (false? (:connection-closed? data))))))

(deftest fsm-spec-structure-test
  (testing "spec contains all 11 states"
    (let [spec (tcp/tcp-fsm-spec {})]
      (is (= :tcp (:id spec)))
      (is (= ::tcp/closed (:initial spec)))
      (is (= 11 (count (:states spec))))
      (is (every? #(contains? (:states spec) %)
                  [::tcp/closed ::tcp/listen ::tcp/syn-sent ::tcp/syn-received
                   ::tcp/established ::tcp/fin-wait-1 ::tcp/fin-wait-2
                   ::tcp/close-wait ::tcp/closing ::tcp/last-ack ::tcp/time-wait])))))

;; =============================================================================
;; Integration: Active open happy path
;; closed → syn-sent → established → fin-wait-1 → fin-wait-2 → time-wait → closed
;; =============================================================================

(deftest active-open-happy-path-test
  (testing "full active open lifecycle via direct handler calls"
    (let [isn     1000
          peer-sn 3000
          sent    (atom [])
          ;; Script: SYN+ACK, data segment, ACK-of-FIN, peer FIN
          recv-q  (atom [(tcp/make-segment #{:syn :ack} peer-sn (inc isn))
                         (tcp/make-segment #{:ack :psh} (inc peer-sn) (inc isn)
                                           :payload [72 105])
                         (tcp/make-segment #{:ack} (inc peer-sn) (+ 2 isn))  ;; ACK of our FIN
                         (tcp/make-segment #{:fin} (+ 3 peer-sn) (+ 2 isn))])
          tp      (mock-transport recv-q sent)
          timer   (mock-timer)
          res     {:transport tp :timer timer}

          ;; 1. ::closed — enter (initial no-op) + handle (set ISN)
          d0      {:open-mode :active :initial-seq-num isn
                   :connect-timeout-ms 5000 :recv-timeout-ms 5000 :msl-ms 1000}
          d1      (tcp/on-close-cleanup res d0)
          _       (is (= :active (:open-mode d1)))  ;; still initial
          d2      (tcp/on-open-connection res d1)
          _       (is (= isn (:local-seq d2)))
          _       (is (tcp/active-open? nil d2))

          ;; 2. ::syn-sent — enter (send SYN) + handle (recv SYN+ACK)
          d3      (tcp/on-send-syn res d2)
          _       (is (:syn-sent? d3))
          _       (is (nil? (:open-mode d3)))
          _       (is (tcp/syn? (first @sent)))
          d4      (tcp/on-syn-sent-recv res d3)
          _       (is (:syn-ack-received? d4))
          _       (is (tcp/syn-ack-received? nil d4))

          ;; 3. ::established — enter + handle (recv data)
          d5      (tcp/on-enter-established res d4)
          _       (is (:connection-established? d5))
          d6      (tcp/on-established-recv res d5)
          _       (is (= 1 (count (:segments-received d6))))

          ;; 4. Application requests close
          d6c     (assoc d6 :close-requested? true)
          d6d     (tcp/on-established-recv res d6c)
          _       (is (tcp/close-requested? nil d6d))

          ;; 5. ::fin-wait-1 — enter (send FIN) + handle (recv ACK)
          d7      (tcp/on-send-fin res d6d)
          _       (is (:fin-sent? d7))
          d8      (tcp/on-fin-wait-1-recv res d7)
          _       (is (:ack-of-fin-received? d8))
          _       (is (tcp/ack-of-fin? nil d8))

          ;; 6. ::fin-wait-2 — handle (recv peer FIN)
          d9      (tcp/on-fin-wait-2-recv res d8)
          _       (is (:fin-received? d9))
          _       (is (tcp/fin-received? nil d9))

          ;; 7. ::time-wait — enter (no timer → immediate expire)
          d10     (tcp/on-enter-time-wait {:timer nil} d9)
          _       (is (:time-wait-expired? d10))

          ;; 8. ::closed — enter (terminal cleanup)
          d11     (tcp/on-close-cleanup res d10)]

      (is (:connection-closed? d11))
      (is (:transport-closed? d11))
      (is (not (proto/open? tp)))

      ;; Verify sent sequence: SYN, ACK(handshake), ACK(data), FIN+ACK, ACK(peer FIN)
      (let [sent-flags (mapv :flags @sent)]
        (is (= #{:syn} (nth sent-flags 0)))
        (is (= #{:ack} (nth sent-flags 1)))
        (is (= #{:ack} (nth sent-flags 2)))
        (is (= #{:fin :ack} (nth sent-flags 3)))
        (is (= #{:ack} (nth sent-flags 4)))))))

;; =============================================================================
;; Integration: Passive open happy path
;; closed → listen → syn-received → established → close-wait → last-ack → closed
;; =============================================================================

(deftest passive-open-happy-path-test
  (testing "full passive open lifecycle via direct handler calls"
    (let [peer-sn 5000
          sent    (atom [])
          ;; Script: SYN, ACK(handshake), data, FIN, ACK(our FIN)
          recv-q  (atom [(tcp/make-segment #{:syn} peer-sn 0)
                         (tcp/make-segment #{:ack} (inc peer-sn) 1001)
                         (tcp/make-segment #{:ack :psh} (inc peer-sn) 1001
                                           :payload [104 105])
                         (tcp/make-segment #{:fin} (+ 3 peer-sn) 1001)
                         (tcp/make-segment #{:ack} (+ 4 peer-sn) 1002)])
          tp      (mock-transport recv-q sent)
          res     {:transport tp}

          ;; 1. ::closed — enter (no-op) + handle
          d0      {:open-mode :passive :recv-timeout-ms 5000 :connect-timeout-ms 5000}
          d1      (tcp/on-close-cleanup res d0)
          d2      (tcp/on-open-connection res d1)
          _       (is (tcp/passive-open? nil d2))

          ;; 2. ::listen — enter + handle (recv SYN)
          d3      (tcp/on-enter-listen res d2)
          _       (is (:listening? d3))
          _       (is (nil? (:open-mode d3)))
          d4      (tcp/on-listen-recv res d3)
          _       (is (:syn-received? d4))
          _       (is (= peer-sn (:remote-seq d4)))

          ;; 3. ::syn-received — enter (send SYN+ACK) + handle (recv ACK)
          d5      (tcp/on-send-syn-ack res d4)
          _       (is (:syn-ack-sent? d5))
          _       (is (tcp/syn-ack? (last @sent)))
          d6      (tcp/on-syn-received-recv res d5)
          _       (is (:ack-received? d6))

          ;; 4. ::established — enter + handle (recv data)
          d7      (tcp/on-enter-established res d6)
          _       (is (:connection-established? d7))
          d8      (tcp/on-established-recv res d7)
          _       (is (= 1 (count (:segments-received d8))))

          ;; 5. ::established — handle (recv FIN from peer)
          d9      (tcp/on-established-recv res d8)
          _       (is (:fin-received? d9))
          _       (is (tcp/fin-received? nil d9))

          ;; 6. ::close-wait — enter
          d10     (tcp/on-enter-close-wait res d9)
          _       (is (:peer-closed? d10))

          ;; 7. Application decides to close
          d10c    (assoc d10 :close-requested? true)

          ;; 8. ::last-ack — enter (send FIN) + handle (recv ACK)
          d11     (tcp/on-send-fin-last-ack res d10c)
          _       (is (:fin-sent? d11))
          d12     (tcp/on-last-ack-recv res d11)
          _       (is (:ack-of-fin-received? d12))

          ;; 9. ::closed — enter (terminal cleanup)
          d13     (tcp/on-close-cleanup res d12)]

      (is (:connection-closed? d13))
      (is (not (proto/open? tp))))))

;; =============================================================================
;; Integration: Simultaneous close
;; established → fin-wait-1 → closing → time-wait → closed
;; =============================================================================

(deftest simultaneous-close-test
  (testing "both sides send FIN simultaneously"
    (let [sent    (atom [])
          ;; In fin-wait-1: receive bare FIN (no ACK of ours), then ACK of our FIN
          recv-q  (atom [(tcp/make-segment #{:fin} 3007 1002)
                         (tcp/make-segment #{:ack} 3008 1002)])
          tp      (mock-transport recv-q sent)
          res     {:transport tp}

          ;; Already in ::established, application closes
          base    {:local-seq 1001 :remote-seq 3007
                   :close-requested? true :connection-established? true
                   :recv-timeout-ms 1000}

          ;; ::fin-wait-1 — enter (send FIN)
          d1      (tcp/on-send-fin res base)
          _       (is (:fin-sent? d1))

          ;; ::fin-wait-1 — handle (recv peer FIN, no ACK of ours)
          d2      (tcp/on-fin-wait-1-recv res d1)
          _       (is (:fin-received? d2))
          _       (is (nil? (:ack-of-fin-received? d2)))
          ;; Dispatch → ::closing (fin-received? but not ack-of-fin?)
          _       (is (tcp/fin-received? nil d2))
          _       (is (not (tcp/ack-of-fin? nil d2)))

          ;; ::closing — handle (recv ACK of our FIN)
          d3      (tcp/on-closing-recv res d2)
          _       (is (:ack-of-fin-received? d3))
          ;; Dispatch → ::time-wait
          _       (is (tcp/ack-of-fin? nil d3))

          ;; ::time-wait — enter (no timer → immediate expire)
          d4      (tcp/on-enter-time-wait {} d3)
          _       (is (:time-wait-expired? d4))

          ;; ::closed — terminal cleanup
          d5      (tcp/on-close-cleanup res d4)]

      (is (:connection-closed? d5))
      (is (not (proto/open? tp))))))

;; =============================================================================
;; Error path: RST during three-way handshake
;; =============================================================================

(deftest rst-during-active-open-test
  (testing "RST received in syn-sent → error → closed"
    (let [sent    (atom [])
          recv-q  (atom [(tcp/make-segment #{:rst} 0 1001)])
          tp      (mock-transport recv-q sent)
          timer   (mock-timer)
          res     {:transport tp :timer timer}

          d0      {:open-mode :active :initial-seq-num 1000
                   :connect-timeout-ms 1000}
          d1      (tcp/on-close-cleanup res d0)
          d2      (tcp/on-open-connection res d1)
          d3      (tcp/on-send-syn res d2)
          d4      (tcp/on-syn-sent-recv res d3)]

      (is (= :connection-reset (:error d4)))
      (is (:rst-received? d4))
      (is (tcp/has-error? nil d4))

      ;; Dispatch would go to ::closed, cleanup
      (let [d5 (tcp/on-close-cleanup res d4)]
        (is (:connection-closed? d5))))))

(deftest recv-error-in-established-test
  (testing "recv error in established state"
    (let [recv-q (atom [])  ;; empty → :no-data error
          sent   (atom [])
          res    (make-resources recv-q sent)
          data   {:local-seq 1001 :segments-received [] :recv-timeout-ms 100}
          result (tcp/on-established-recv res data)]
      (is (= :no-data (:error result)))
      (is (= :established (:error-phase result)))
      (is (tcp/has-error? nil result)))))
