(ns hive.events.protocols.retry-test
  "Tests for the reusable retry sub-FSM.

   Verifies state transitions with mock request/sleep fns:
   - Success on first attempt
   - Retry then success
   - Retry exhaustion
   - Custom retryable? predicate
   - Backoff calculation helpers
   - parse-retry-after integration
   - IProtocolFSM contract"
  (:require [clojure.test :refer [deftest testing is]]
            [hive.events.fsm :as fsm]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.retry :as retry]))

;; =============================================================================
;; Helpers
;; =============================================================================

(defn- mock-request-fn
  "Create a request-fn that returns responses from a sequence.
   Each call returns the next response."
  [responses]
  (let [idx (atom 0)]
    (fn [_data]
      (let [i @idx
            resp (nth responses (min i (dec (count responses))))]
        (swap! idx inc)
        resp))))

(defn- noop-sleep [_ms] nil)

(def ^:private ok-response {:status 200 :body "ok"})
(def ^:private rate-limited {:status 429 :body "rate limited"})
(def ^:private server-error {:status 500 :body "server error"})
(def ^:private overloaded   {:status 529 :body "overloaded"})

(defn- http-retryable? [resp]
  (contains? #{429 529} (:status resp)))

(defn- make-test-fsm
  "Create a retry FSM configured for HTTP-like status code retries."
  ([] (make-test-fsm {}))
  ([extra-opts]
   (retry/make-retry-fsm
    (merge {:retryable? http-retryable?
            :max-retries 3}
           extra-opts))))

;; =============================================================================
;; Tests: Backoff Helpers
;; =============================================================================

(deftest test-exponential-backoff-ms
  (testing "Exponential backoff grows with attempt number"
    (let [b0 (retry/exponential-backoff-ms 0 1000)
          b1 (retry/exponential-backoff-ms 1 1000)
          b2 (retry/exponential-backoff-ms 2 1000)]
      ;; Each level should be roughly double the previous
      (is (> b1 b0))
      (is (> b2 b1))
      ;; Attempt 0: base=1000, jitter up to 250
      (is (<= 1000 b0 1250))
      ;; Attempt 1: base=2000, jitter up to 500
      (is (<= 2000 b1 2500))
      ;; Attempt 2: base=4000, jitter up to 1000
      (is (<= 4000 b2 5000)))))

(deftest test-linear-backoff-ms
  (testing "Linear backoff grows linearly with attempt number"
    (let [b0 (retry/linear-backoff-ms 0 1000)
          b1 (retry/linear-backoff-ms 1 1000)
          b2 (retry/linear-backoff-ms 2 1000)]
      ;; Attempt 0: 1000 + jitter
      (is (<= 1000 b0 1250))
      ;; Attempt 1: 2000 + jitter
      (is (<= 2000 b1 2250))
      ;; Attempt 2: 3000 + jitter
      (is (<= 3000 b2 3250)))))

(deftest test-constant-backoff-ms
  (testing "Constant backoff returns same value regardless of attempt"
    (is (= 500 (retry/constant-backoff-ms 0 500)))
    (is (= 500 (retry/constant-backoff-ms 5 500)))
    (is (= 500 (retry/constant-backoff-ms 99 500)))))

;; =============================================================================
;; Tests: FSM Integration — Success
;; =============================================================================

(deftest test-success-on-first-try
  (testing "Non-retryable response on first attempt -> immediate success"
    (let [retry-fsm (make-test-fsm)
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn [ok-response])
                                    {:sleep-fn noop-sleep})]
      (is (= 0 (:attempt result)))
      (is (= 200 (get-in result [:response :status])))
      (is (nil? (:exhausted? result))))))

;; =============================================================================
;; Tests: FSM Integration — Retry then Success
;; =============================================================================

(deftest test-retry-then-success
  (testing "429 -> retry -> 200 succeeds on second attempt"
    (let [sleep-log (atom [])
          retry-fsm (make-test-fsm)
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn [rate-limited ok-response])
                                    {:sleep-fn (fn [ms] (swap! sleep-log conj ms))})]
      (is (= 1 (:attempt result)))
      (is (= 200 (get-in result [:response :status])))
      (is (= 1 (count @sleep-log)))
      (is (nil? (:exhausted? result))))))

(deftest test-multiple-retries-then-success
  (testing "429 -> 529 -> 200 retries through different retryable responses"
    (let [retry-fsm (make-test-fsm)
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn [rate-limited overloaded ok-response])
                                    {:sleep-fn noop-sleep})]
      (is (= 2 (:attempt result)))
      (is (= 200 (get-in result [:response :status]))))))

;; =============================================================================
;; Tests: FSM Integration — Exhaustion
;; =============================================================================

(deftest test-retry-exhaustion
  (testing "All retries exhausted -> exhausted state with error info"
    (let [retry-fsm (make-test-fsm {:max-retries 2})
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn (repeat 10 rate-limited))
                                    {:sleep-fn noop-sleep})]
      (is (true? (:exhausted? result)))
      (is (= :retry/exhausted (get-in result [:error :type])))
      (is (= 2 (get-in result [:error :attempt])))
      (is (= 429 (get-in result [:error :response :status]))))))

;; =============================================================================
;; Tests: Custom retryable? Predicate
;; =============================================================================

(deftest test-custom-retryable-predicate
  (testing "Custom predicate determines what is retryable"
    ;; Only 500 is retryable in this config
    (let [retry-fsm (retry/make-retry-fsm
                     {:retryable?  #(= 500 (:status %))
                      :max-retries 3})
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn [server-error ok-response])
                                    {:sleep-fn noop-sleep})]
      (is (= 1 (:attempt result)))
      (is (= 200 (get-in result [:response :status])))))

  (testing "Non-retryable failure goes straight to success (no retry)"
    ;; 429 is NOT retryable in this config
    (let [retry-fsm (retry/make-retry-fsm
                     {:retryable?  #(= 500 (:status %))
                      :max-retries 3})
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn [rate-limited])
                                    {:sleep-fn noop-sleep})]
      ;; Goes to ::success because retryable? returns false
      (is (= 0 (:attempt result)))
      (is (= 429 (get-in result [:response :status])))
      (is (nil? (:exhausted? result))))))

;; =============================================================================
;; Tests: parse-retry-after Integration
;; =============================================================================

(deftest test-parse-retry-after
  (testing "Server-specified wait time is respected over backoff calculation"
    (let [sleep-log (atom [])
          retry-fsm (retry/make-retry-fsm
                     {:retryable?        http-retryable?
                      :max-retries       3
                      :parse-retry-after (fn [resp]
                                           (when-let [v (get-in resp [:headers "retry-after"])]
                                             (* (Long/parseLong (str v)) 1000)))})
          resp-with-header {:status 429
                            :headers {"retry-after" "3"}
                            :body "rate limited"}
          result (retry/run-retry retry-fsm
                                 (mock-request-fn [resp-with-header ok-response])
                                 {:sleep-fn (fn [ms] (swap! sleep-log conj ms))})]
      (is (= 200 (get-in result [:response :status])))
      ;; Should have slept for 3000ms (Retry-After: 3)
      (is (= [3000] @sleep-log)))))

;; =============================================================================
;; Tests: Custom Backoff Strategy
;; =============================================================================

(deftest test-custom-backoff-fn
  (testing "Constant backoff strategy produces uniform wait times"
    (let [sleep-log (atom [])
          retry-fsm (retry/make-retry-fsm
                     {:retryable?         http-retryable?
                      :max-retries        3
                      :initial-backoff-ms 500
                      :backoff-fn         retry/constant-backoff-ms})
          result    (retry/run-retry retry-fsm
                                    (mock-request-fn [rate-limited rate-limited ok-response])
                                    {:sleep-fn (fn [ms] (swap! sleep-log conj ms))})]
      (is (= 200 (get-in result [:response :status])))
      ;; Both waits should be exactly 500ms
      (is (= [500 500] @sleep-log)))))

;; =============================================================================
;; Tests: IProtocolFSM Contract
;; =============================================================================

(deftest test-protocol-fsm-contract
  (testing "make-retry-fsm returns valid IProtocolFSM"
    (let [retry-fsm (make-test-fsm)]
      (is (= :retry (proto/protocol-id retry-fsm)))
      (is (map? (proto/fsm-spec retry-fsm)))
      (is (some? (proto/compiled retry-fsm)))
      (is (map? (proto/initial-data retry-fsm {})))
      (is (= #{::retry/success ::retry/exhausted}
             (proto/terminal-states retry-fsm)))
      (is (= {} (proto/composable-states retry-fsm))))))

(deftest test-initial-data
  (testing "initial-data includes attempt counter"
    (let [retry-fsm (make-test-fsm)
          data      (proto/initial-data retry-fsm {})]
      (is (= 0 (:attempt data)))))
  (testing "initial-data merges request-data from session opts"
    (let [retry-fsm (make-test-fsm)
          data      (proto/initial-data retry-fsm {:request-data {:url "http://example.com"}})]
      (is (= {:url "http://example.com"} (:request-data data))))))
