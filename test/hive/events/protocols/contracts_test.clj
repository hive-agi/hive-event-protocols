(ns hive.events.protocols.contracts-test
  "Contract coverage gate + hive-test trifectas over the pure helpers.

   The gate asserts every public fn under src/ carries an m/=> contract
   (there are no exemptions). The trifectas pin golden snapshots, check a
   property over generated inputs, and kill a mutant for each helper."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.generators :as gen]
            [hive-schemas.coverage :refer [deftest-contract-coverage]]
            [hive-test.trifecta :refer [deftrifecta]]
            [malli.core :as m]
            [malli.generator :as mg]
            [malli.instrument :as mi]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.http1 :as http1]
            [hive.events.protocols.retry :as retry]
            [hive.events.protocols.tcp :as tcp]
            [hive.events.protocols.tls :as tls]
            [hive.events.protocols.websocket :as ws]))

;; =============================================================================
;; Coverage gate
;; =============================================================================

(deftest-contract-coverage every-public-fn-has-a-contract
  {:paths ["src"]})

;; =============================================================================
;; Schemas validate real values and hold under generated inputs
;; =============================================================================

(deftest shared-schemas-are-sound
  (testing "FsmSpec accepts every protocol's spec"
    (doseq [f [(tcp/make-tcp-fsm) (http1/make-http1-fsm) (tls/make-tls-fsm) (ws/make-websocket-fsm)]]
      (is (m/validate proto/FsmSpec (proto/fsm-spec f)) (str (proto/protocol-id f)))))
  (testing "factories return IProtocolFSM"
    (is (m/validate proto/ProtocolFSM (retry/make-retry-fsm {:max-retries 1})))
    (is (not (m/validate proto/ProtocolFSM {})))))

(deftest backoff-contracts-hold-under-generated-inputs
  (testing "every backoff strategy satisfies BackoffFn over generated args"
    (doseq [f [#'retry/exponential-backoff-ms #'retry/linear-backoff-ms #'retry/constant-backoff-ms]]
      (is (nil? (m/explain retry/BackoffFn @f {::m/function-checker mg/function-checker}))
          (str f)))))

(deftest instrumented-retry-session-respects-contracts
  (let [filters [(mi/-filter-ns 'hive.events.protocols.retry 'hive.events.protocols.core)]]
    (mi/instrument! {:filters filters
                     :report  (fn [t d] (throw (ex-info (str t) (select-keys d [:fn-name :args]))))})
    (try
      (let [r (retry/run-retry (retry/make-retry-fsm {:max-retries 2})
                               (fn [_] {:status 200})
                               {:sleep-fn (fn [_] nil)})]
        (is (= {:status 200} (:response r))))
      (finally (mi/unstrument! {:filters filters})))))

;; =============================================================================
;; Trifectas — golden + property + mutation
;; =============================================================================

(deftrifecta tcp-make-segment-trifecta
  hive.events.protocols.tcp/make-segment
  {:apply?      true
   :golden-path "test/golden/tcp-make-segment.edn"
   :cases       {:syn     [#{:syn} 1000 0]
                 :syn-ack [[:syn :ack] 1 1001]
                 :payload [#{:ack :psh} 5000 3000 :payload [1 2 3] :window 32768]}
   :gen         (gen/tuple (gen/set (gen/elements [:syn :ack :fin :rst :psh :urg]))
                           gen/nat gen/nat)
   :pred        #(m/validate tcp/Segment %)
   :mutations   [["drops-flags" (fn [_ s a & _] {:flags #{} :seq-num s :ack-num a :window 65535})]
                 ["zero-window" (fn [f s a & _] {:flags (set f) :seq-num s :ack-num a :window 0})]]})

(deftrifecta http1-no-body-status-trifecta
  hive.events.protocols.http1/no-body-status?
  {:golden-path "test/golden/http1-no-body-status.edn"
   :cases       {:continue 100 :ok 200 :no-content 204 :not-modified 304 :not-found 404}
   :gen         (gen/choose 100 599)
   :pred        boolean?
   :mutations   [["always-false" (fn [_] false)]
                 ["forgets-304" (fn [s] (or (= 204 s) (and (>= s 100) (< s 200))))]]})

(deftrifecta http1-retryable-status-trifecta
  hive.events.protocols.http1/retryable-status?
  {:golden-path "test/golden/http1-retryable-status.edn"
   :cases       {:ok 200 :too-many 429 :ise 500 :bad-gw 502 :not-found 404 :unavail 503}
   :gen         (gen/choose 100 599)
   :pred        boolean?
   :mutations   [["all-5xx" (fn [s] (>= s 500))]
                 ["never" (fn [_] false)]]})

(deftrifecta ws-parse-close-payload-trifecta
  hive.events.protocols.websocket/parse-close-payload
  {:golden-path "test/golden/ws-parse-close-payload.edn"
   :cases       {:nil    nil
                 :code   [3 -24]
                 :reason [3 -24 104 105]
                 :short  [1]}
   :gen         (gen/vector (gen/choose -128 127) 0 8)
   :pred        #(and (int? (:close-code %)) (string? (:close-reason %)))
   :mutations   [["ignores-payload" (fn [_] {:close-code 1000 :close-reason ""})]]})

(deftrifecta ws-control-opcode-trifecta
  hive.events.protocols.websocket/control-opcode?
  {:golden-path "test/golden/ws-control-opcode.edn"
   :cases       {:text 0x1 :binary 0x2 :close 0x8 :ping 0x9 :pong 0xA}
   :gen         (gen/choose 0 15)
   :pred        boolean?
   :mutations   [["off-by-one" (fn [op] (>= op 0x9))]]})

(deftrifecta tls-alert-record-trifecta
  hive.events.protocols.tls/make-alert-record
  {:apply?      true
   :golden-path "test/golden/tls-alert-record.edn"
   :cases       {:fatal   [:fatal :handshake-failure]
                 :warning [:warning :close-notify]}
   :gen         (gen/tuple (gen/elements [:fatal :warning]) gen/keyword)
   :pred        tls/alert-record?
   :mutations   [["handshake-type" (fn [l d] {:record-type :handshake :level l :description d})]]})

(deftrifecta retry-constant-backoff-trifecta
  hive.events.protocols.retry/constant-backoff-ms
  {:apply?      true
   :golden-path "test/golden/retry-constant-backoff.edn"
   :cases       {:first [0 500] :later [7 500] :zero [3 0]}
   :gen         (gen/tuple gen/nat gen/nat)
   :pred        nat-int?
   :mutations   [["scales-with-attempt" (fn [a b] (* (inc a) b))]]})
