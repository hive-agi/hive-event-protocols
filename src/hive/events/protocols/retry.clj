(ns hive.events.protocols.retry
  "Reusable retry sub-FSM — transport-agnostic retry with configurable backoff.

   Generalizes the HTTP-specific retry loop from hive-agent into a composable
   protocol FSM that works with any request/response pattern.

   States: ::attempt -> ::success | ::retryable -> ::backoff -> ::attempt | ::exhausted

   Resources (injected at run time):
     :request-fn — (fn [data] -> response), executes the operation
     :sleep-fn   — (fn [ms]), blocks for backoff duration

   Configuration via opts:
     :max-retries        — max retry count (default 5)
     :initial-backoff-ms — base backoff in ms (default 1000)
     :backoff-fn         — (fn [attempt initial-backoff-ms] -> ms), default exponential
     :retryable?         — (fn [response] -> bool), determines if response is retryable
     :parse-retry-after  — (fn [response] -> ms or nil), extract server-requested wait

   Implements IProtocolFSM from hive.events.protocols.core for registry integration."
  (:require [hive.events.fsm :as fsm]
            [hive.events.protocols.core :as proto]))

;; =============================================================================
;; Pure Backoff Helpers
;; =============================================================================

(defn exponential-backoff-ms
  "Exponential backoff with jitter. Pure function of attempt and base.

   Formula: base * 2^attempt + rand(0, base * 2^attempt / 4)

   Example: base=1000, attempt 0 -> [1000,1250], attempt 1 -> [2000,2500]"
  [attempt initial-backoff-ms]
  (let [base (* initial-backoff-ms (Math/pow 2 attempt))]
    (long (+ base (rand-int (max 1 (int (/ base 4))))))))

(defn linear-backoff-ms
  "Linear backoff with jitter.

   Formula: base * (attempt + 1) + rand(0, base / 4)

   Example: base=1000, attempt 0 -> [1000,1250], attempt 1 -> [2000,2250]"
  [attempt initial-backoff-ms]
  (let [base (* initial-backoff-ms (inc attempt))]
    (long (+ base (rand-int (max 1 (int (/ initial-backoff-ms 4))))))))

(defn constant-backoff-ms
  "Constant backoff — always waits the same duration.

   Returns initial-backoff-ms regardless of attempt."
  [_attempt initial-backoff-ms]
  initial-backoff-ms)

;; =============================================================================
;; Default Configuration
;; =============================================================================

(def ^:private default-opts
  {:max-retries        5
   :initial-backoff-ms 1000
   :backoff-fn         exponential-backoff-ms
   :retryable?         (constantly false)
   :parse-retry-after  (constantly nil)})

;; =============================================================================
;; FSM State Handlers (closed over opts)
;; =============================================================================

(defn- make-attempt-handler
  "Execute request via :request-fn resource. Stores response in data."
  [_opts]
  (fn [{:keys [request-fn]} data]
    (let [response (request-fn data)]
      (assoc data :response response))))

(defn- make-success-handler
  "Terminal success — pass through data with response."
  [_opts]
  (fn [_resources data]
    data))

(defn- make-retryable-handler
  "Calculate wait duration from server hint or backoff strategy."
  [{:keys [backoff-fn initial-backoff-ms parse-retry-after]}]
  (fn [_resources {:keys [response attempt] :as data}]
    (let [wait (or (when parse-retry-after
                     (parse-retry-after response))
                   (backoff-fn attempt initial-backoff-ms))]
      (assoc data :wait-ms wait))))

(defn- make-backoff-handler
  "Sleep for calculated wait, increment attempt counter."
  [_opts]
  (fn [{:keys [sleep-fn]} {:keys [wait-ms] :as data}]
    (when sleep-fn
      (sleep-fn wait-ms))
    (-> data
        (update :attempt inc)
        (dissoc :wait-ms))))

(defn- make-exhausted-handler
  "Terminal exhaustion — all retries spent."
  [_opts]
  (fn [_resources data]
    (assoc data :exhausted? true
                :error {:type    :retry/exhausted
                        :attempt (:attempt data)
                        :response (:response data)})))

;; =============================================================================
;; Dispatch Predicates (closed over opts)
;; =============================================================================

(defn- make-success-pred
  "Predicate: response is NOT retryable (i.e., success or non-retryable error)."
  [{:keys [retryable?]}]
  (fn [{:keys [response]}]
    (not (retryable? response))))

(defn- make-retryable-pred
  "Predicate: response is retryable AND attempts remain."
  [{:keys [retryable? max-retries]}]
  (fn [{:keys [response attempt]}]
    (and (retryable? response)
         (< attempt max-retries))))

(defn- make-exhausted-pred
  "Predicate: response is retryable BUT no attempts remain."
  [{:keys [retryable? max-retries]}]
  (fn [{:keys [response attempt]}]
    (and (retryable? response)
         (>= attempt max-retries))))

;; =============================================================================
;; FSM Spec Builder
;; =============================================================================

(defn- make-fsm-spec
  "Build FSM spec map from merged opts. Pure data + inline fns."
  [opts]
  {:fsm {::fsm/start
         {:handler    (make-attempt-handler opts)
          :dispatches [[::success   (make-success-pred opts)]
                       [::retryable (make-retryable-pred opts)]
                       [::exhausted (make-exhausted-pred opts)]]}

         ::success
         {:handler    (make-success-handler opts)
          :dispatches [[::fsm/end (constantly true)]]}

         ::retryable
         {:handler    (make-retryable-handler opts)
          :dispatches [[::backoff (constantly true)]]}

         ::backoff
         {:handler    (make-backoff-handler opts)
          :dispatches [[::fsm/start (constantly true)]]}

         ::exhausted
         {:handler    (make-exhausted-handler opts)
          :dispatches [[::fsm/end (constantly true)]]}}

   :opts {:max-trace 20}})

;; =============================================================================
;; IProtocolFSM Implementation
;; =============================================================================

(defn make-retry-fsm
  "Factory: create a reusable retry protocol FSM.

   opts — configuration map (all optional):
     :max-retries        — max retry count (default 5)
     :initial-backoff-ms — base backoff in ms (default 1000)
     :backoff-fn         — (fn [attempt initial-backoff-ms] -> ms)
     :retryable?         — (fn [response] -> bool)
     :parse-retry-after  — (fn [response] -> ms or nil)

   Returns: IProtocolFSM implementation.

   Usage:
     (def retry (make-retry-fsm {:max-retries 3
                                  :retryable? #(#{429 503} (:status %))}))

     ;; Run directly
     (fsm/run (proto/compiled retry)
              {:request-fn my-request :sleep-fn #(Thread/sleep %)}
              {:data {:attempt 0}})

     ;; Or compose as sub-FSM in a parent
     (fsm/make-sub-fsm-handler (proto/compiled retry) {...})"
  ([] (make-retry-fsm {}))
  ([opts]
   (let [merged   (merge default-opts opts)
         spec     (make-fsm-spec merged)
         compiled (fsm/compile spec)]
     (reify proto/IProtocolFSM
       (protocol-id [_] :retry)

       (fsm-spec [_] spec)

       (compiled [_] compiled)

       (initial-data [_ session-opts]
         (merge {:attempt 0}
                (select-keys session-opts [:request-data])))

       (terminal-states [_]
         #{::success ::exhausted})

       (composable-states [_] {})))))

;; =============================================================================
;; Convenience: run-retry
;; =============================================================================

(defn run-retry
  "Execute a retry FSM to completion. Convenience wrapper.

   Arguments:
     retry-fsm  — IProtocolFSM from make-retry-fsm
     request-fn — (fn [data] -> response)
     opts       — optional map:
       :sleep-fn     — (fn [ms]), default Thread/sleep
       :initial-data — extra data merged into FSM initial state

   Returns: final FSM data map
     On success:    {:attempt N :response response-value}
     On exhaustion: {:attempt N :response last-response :exhausted? true :error {...}}

   Example:
     (run-retry (make-retry-fsm {:max-retries 3
                                  :retryable? #(= 429 (:status %))})
                (fn [_data] (http/get url))
                {:sleep-fn (fn [ms] (Thread/sleep ms))})"
  ([retry-fsm request-fn]
   (run-retry retry-fsm request-fn {}))
  ([retry-fsm request-fn {:keys [sleep-fn initial-data]
                           :or   {sleep-fn #(Thread/sleep (long %))}}]
   (let [resources {:request-fn request-fn
                    :sleep-fn   sleep-fn}
         data      (merge {:attempt 0} initial-data)]
     (fsm/run (proto/compiled retry-fsm) resources {:data data}))))
