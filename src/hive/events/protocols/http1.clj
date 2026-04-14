(ns hive.events.protocols.http1
  "HTTP/1.1 request lifecycle FSM.

   States: idle → connecting → sending-headers → sending-body
          → awaiting-response → reading-headers → reading-body
          → complete | error

   The FSM is pure data — all I/O happens through ITransport/ITimer
   resources injected at run time.  Request formatting, response parsing,
   keep-alive recycling, and retry with configurable backoff are handled
   as state-machine transitions.

   Retry logic composes backoff strategies from hive.events.protocols.retry.

   Factory:
     (make-http1-fsm opts)
       opts — {:connect-timeout-ms  5000    ;; transport connect timeout
               :recv-timeout-ms     30000   ;; response read timeout
               :max-retries         3       ;; retry count for retryable errors
               :retryable-status?   fn      ;; (fn [status] -> bool)
               :backoff-fn          fn      ;; from retry.clj
               :initial-backoff-ms  1000    ;; base backoff
               :keep-alive?         true}   ;; Connection: keep-alive default"
  (:require [clojure.string :as str]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.retry :as retry]))

;; =============================================================================
;; Constants
;; =============================================================================

(def ^:const default-connect-timeout-ms
  "Timeout for transport connection verification."
  5000)

(def ^:const default-recv-timeout-ms
  "Default receive timeout per response phase."
  30000)

(def ^:const default-max-retries
  "Maximum automatic retries for retryable status codes."
  3)

(def ^:const default-initial-backoff-ms
  "Base backoff duration for retry calculation."
  1000)

(def ^:private default-retryable-statuses
  "Status codes eligible for automatic retry."
  #{429 500 502 503 504})

;; =============================================================================
;; HTTP helpers
;; =============================================================================

(defn retryable-status?
  "Default predicate: status codes eligible for automatic retry.
   429 Too Many Requests, 500 Internal Server Error, 502 Bad Gateway,
   503 Service Unavailable, 504 Gateway Timeout."
  [status]
  (contains? default-retryable-statuses status))

(defn parse-content-length
  "Extract Content-Length as long from response headers, or nil."
  [headers]
  (when-let [cl (or (get headers "Content-Length")
                    (get headers "content-length"))]
    (try (Long/parseLong (str cl))
         (catch Exception _ nil))))

(defn chunked-transfer?
  "True when Transfer-Encoding includes chunked."
  [headers]
  (let [te (or (get headers "Transfer-Encoding")
               (get headers "transfer-encoding") "")]
    (str/includes? (str/lower-case te) "chunked")))

(defn response-keep-alive?
  "Check if response indicates keep-alive.
   HTTP/1.1 defaults to keep-alive unless Connection: close.
   HTTP/1.0 requires explicit Connection: keep-alive."
  [headers http-version]
  (let [conn (str/lower-case
              (or (get headers "Connection")
                  (get headers "connection") ""))]
    (if (= http-version "HTTP/1.1")
      (not= conn "close")
      (= conn "keep-alive"))))

(defn parse-retry-after-header
  "Extract Retry-After value in milliseconds from response headers.
   Supports integer seconds format (delta-seconds per RFC 7231 §7.1.3)."
  [headers]
  (when-let [ra (or (get headers "Retry-After")
                    (get headers "retry-after"))]
    (try (* (Long/parseLong (str ra)) 1000)
         (catch Exception _ nil))))

(defn no-body-status?
  "True for status codes that MUST NOT have a message body (RFC 7230 §3.3).
   1xx informational, 204 No Content, 304 Not Modified."
  [status]
  (or (= 204 status)
      (= 304 status)
      (and (>= status 100) (< status 200))))

;; =============================================================================
;; FSM handlers — pure fns of [resources data] → data
;; =============================================================================

;; ---------------------------------------------------------------------------
;; ::idle
;; ---------------------------------------------------------------------------

(defn on-idle-enter
  "Enter ::idle — reset intermediate state for a new request cycle.
   Preserves :response (last completed), :retry-count, and config keys.
   On first entry, this is a no-op (no intermediate state to clear).
   On keep-alive re-entry, clears tracking fields from previous cycle."
  [_resources data]
  (dissoc data
          :status :reason :http-version
          :response-headers :response-body
          :expected-length :chunked?
          :body-complete? :headers-complete? :status-received?
          :connected? :headers-sent? :body-sent? :method-str
          :error :error-phase
          :retryable? :keep-alive-next?
          :last-wait-ms))

;; ---------------------------------------------------------------------------
;; ::connecting
;; ---------------------------------------------------------------------------

(defn on-connect
  "Enter ::connecting — verify transport is open.
   The transport is expected to be pre-connected (e.g., composed on
   top of TCP's ::established state via ITransport adapter)."
  [resources data]
  (let [transport (:transport resources)]
    (if (proto/open? transport)
      (assoc data :connected? true)
      (assoc data :error :transport-closed :error-phase :connecting))))

;; ---------------------------------------------------------------------------
;; ::sending-headers
;; ---------------------------------------------------------------------------

(defn on-send-headers
  "Enter ::sending-headers — send request line and headers via transport.
   Sends a structured map; the transport adapter handles wire format.
   Normalises :method to uppercase string."
  [resources data]
  (let [transport (:transport resources)
        request   (:request data)
        method    (str/upper-case (name (or (:method request) "GET")))
        url       (or (:url request) "/")
        headers   (or (:headers request) {})
        result    (proto/send! transport
                               {:type    :request-head
                                :method  method
                                :url     url
                                :version "HTTP/1.1"
                                :headers headers}
                               {})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :sending-headers)
      (assoc data :headers-sent? true :method-str method))))

;; ---------------------------------------------------------------------------
;; ::sending-body
;; ---------------------------------------------------------------------------

(defn on-send-body
  "Enter ::sending-body — send request body via transport."
  [resources data]
  (let [transport (:transport resources)
        body      (get-in data [:request :body])
        result    (proto/send! transport
                               {:type :request-body
                                :body body}
                               {})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :sending-body)
      (assoc data :body-sent? true))))

;; ---------------------------------------------------------------------------
;; ::awaiting-response
;; ---------------------------------------------------------------------------

(defn on-recv-status
  "Handle in ::awaiting-response — receive HTTP status line.
   Expects transport to return {:status N :reason \"...\" :version \"HTTP/1.1\"}."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :awaiting-response)
      (let [resp (:data result)]
        (assoc data
               :status           (:status resp)
               :reason           (:reason resp)
               :http-version     (or (:version resp) "HTTP/1.1")
               :status-received? true)))))

;; ---------------------------------------------------------------------------
;; ::reading-headers
;; ---------------------------------------------------------------------------

(defn on-recv-headers
  "Handle in ::reading-headers — receive response headers.
   Expects transport to return {:headers {\"Name\" \"Value\" ...}}."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :reading-headers)
      (let [headers (or (:headers (:data result)) (:data result))]
        (assoc data
               :response-headers  headers
               :headers-complete? true
               :expected-length   (parse-content-length headers)
               :chunked?          (chunked-transfer? headers))))))

;; ---------------------------------------------------------------------------
;; ::reading-body
;; ---------------------------------------------------------------------------

(defn on-recv-body
  "Handle in ::reading-body — receive response body.
   Handles no-body status codes (204, 304, 1xx) and HEAD requests.
   For normal responses, reads from transport and accumulates body."
  [resources data]
  (if (or (no-body-status? (:status data))
          (= "HEAD" (:method-str data)))
    ;; No body expected for this response
    (assoc data :response-body "" :body-complete? true)
    ;; Normal body read
    (let [result (proto/recv! (:transport resources)
                              {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)
                               :max-bytes  (:expected-length data)})]
      (if (:error result)
        (assoc data :error (:error result) :error-phase :reading-body)
        (let [body-data  (:data result)
              chunk      (or (:body body-data) body-data)
              complete?  (if (contains? body-data :complete?)
                           (:complete? body-data)
                           true)]
          (-> data
              (update :response-body (fnil str "") (str chunk))
              (assoc :body-complete? complete?)))))))

;; ---------------------------------------------------------------------------
;; ::complete
;; ---------------------------------------------------------------------------

(defn on-complete
  "Enter ::complete — assemble final response, evaluate retry and keep-alive.

   Retry: if the response status matches :retryable-status? and
   :retry-count < :max-retries, marks :retryable? true and preserves
   :request for the next retry cycle.

   Keep-alive: if not retrying and the response indicates keep-alive,
   marks :keep-alive-next? true to enable ::idle recycling.

   When not retrying, dissocs :request to prevent re-execution."
  [_resources data]
  (let [status       (:status data)
        headers      (:response-headers data {})
        body         (:response-body data)
        retryable-fn (:retryable-status? data retryable-status?)
        max-retries  (:max-retries data default-max-retries)
        retry-count  (or (:retry-count data) 0)
        is-retryable (and (retryable-fn status)
                          (< retry-count max-retries))
        http-version (:http-version data "HTTP/1.1")
        keep-alive   (and (:keep-alive? data true)
                          (response-keep-alive? headers http-version)
                          (not is-retryable))]
    (cond-> (assoc data
                   :response         {:status  status
                                      :headers headers
                                      :body    body}
                   :retryable?       is-retryable
                   :keep-alive-next? keep-alive)
      ;; Clear request when not retrying to prevent re-execution
      (not is-retryable) (dissoc :request))))

;; ---------------------------------------------------------------------------
;; ::retrying
;; ---------------------------------------------------------------------------

(defn on-retry
  "Enter ::retrying — compute backoff, sleep, increment retry counter.
   Respects Retry-After header when present; falls back to configured
   backoff strategy (default: exponential from retry.clj)."
  [resources data]
  (let [retry-count  (or (:retry-count data) 0)
        headers      (:response-headers data {})
        backoff-fn   (:backoff-fn data retry/exponential-backoff-ms)
        initial-ms   (:initial-backoff-ms data default-initial-backoff-ms)
        ;; Respect Retry-After header if present
        wait-ms      (or (parse-retry-after-header headers)
                         (backoff-fn retry-count initial-ms))
        sleep-fn     (:sleep-fn resources)]
    (when sleep-fn
      (sleep-fn wait-ms))
    (-> data
        (update :retry-count inc)
        (assoc :last-wait-ms wait-ms)
        (dissoc :retryable?))))

;; ---------------------------------------------------------------------------
;; ::error
;; ---------------------------------------------------------------------------

(defn on-error
  "Enter ::error — close transport, cancel timers, preserve error context.
   Assembles partial :response if any response data was received."
  [resources data]
  (proto/close! (:transport resources))
  (when-let [timer (:timer resources)]
    (proto/cancel-all! timer))
  (cond-> (assoc data :transport-closed? true)
    ;; Preserve partial response for diagnostics
    (:status data) (assoc :response {:status  (:status data)
                                     :headers (:response-headers data)
                                     :body    (:response-body data)})))

;; =============================================================================
;; Dispatch predicates — (fn [_resources data] → boolean)
;; =============================================================================

(defn has-request?      [_r d] (some? (:request d)))
(defn connected?        [_r d] (:connected? d))
(defn has-body?         [_r d] (some? (get-in d [:request :body])))
(defn status-received?  [_r d] (:status-received? d))
(defn headers-complete? [_r d] (:headers-complete? d))
(defn body-complete?    [_r d] (:body-complete? d))
(defn retryable?        [_r d] (:retryable? d))
(defn keep-alive-next?  [_r d] (:keep-alive-next? d))
(defn has-error?        [_r d] (some? (:error d)))
(defn always            [_r _d] true)

;; =============================================================================
;; FSM spec builder
;; =============================================================================

(defn http1-fsm-spec
  "Build a pure-data FSM spec for the HTTP/1.1 request lifecycle.

   The spec covers the full request–response cycle including connection
   verification, request sending (headers + optional body), response
   reading (status + headers + body), automatic retry with backoff for
   retryable status codes (429, 5xx), and keep-alive connection recycling."
  [_opts]
  {:id      :http/1.1
   :initial ::idle

   :states
   {;;  ─── Request Preparation ──────────────────────────────────────────

    ::idle
    {:enter    on-idle-enter
     :dispatch [[::connecting has-request?]]}

    ;;  ─── Connection ────────────────────────────────────────────────────

    ::connecting
    {:enter    on-connect
     :dispatch [[::sending-headers connected?]
                [::error           has-error?]]}

    ;;  ─── Request Sending ───────────────────────────────────────────────

    ::sending-headers
    {:enter    on-send-headers
     :dispatch [[::error             has-error?]
                [::sending-body      has-body?]
                [::awaiting-response always]]}

    ::sending-body
    {:enter    on-send-body
     :dispatch [[::error             has-error?]
                [::awaiting-response always]]}

    ;;  ─── Response Reading ──────────────────────────────────────────────

    ::awaiting-response
    {:handle   on-recv-status
     :dispatch [[::reading-headers status-received?]
                [::error           has-error?]
                [::awaiting-response always]]}

    ::reading-headers
    {:handle   on-recv-headers
     :dispatch [[::reading-body headers-complete?]
                [::error        has-error?]
                [::reading-headers always]]}

    ::reading-body
    {:handle   on-recv-body
     :dispatch [[::complete     body-complete?]
                [::error        has-error?]
                [::reading-body always]]}

    ;;  ─── Completion / Retry / Keep-Alive ───────────────────────────────

    ::complete
    {:enter    on-complete
     :dispatch [[::retrying       retryable?]
                [::idle           keep-alive-next?]]}

    ::retrying
    {:enter    on-retry
     :dispatch [[::connecting always]]}

    ;;  ─── Error ─────────────────────────────────────────────────────────

    ::error
    {:enter on-error}}})

;; =============================================================================
;; IProtocolFSM implementation
;; =============================================================================

(defn make-http1-fsm
  "Create an HTTP/1.1 protocol FSM.

   opts (all optional):
     :connect-timeout-ms  — transport connect timeout       (default 5 000)
     :recv-timeout-ms     — response read timeout           (default 30 000)
     :max-retries         — retries for retryable status    (default 3)
     :retryable-status?   — (fn [status] → bool)            (default 429/500/502/503/504)
     :backoff-fn          — (fn [attempt base-ms] → ms)     (default exponential)
     :initial-backoff-ms  — base backoff duration            (default 1 000)
     :keep-alive?         — enable keep-alive recycling      (default true)

   Returns: IProtocolFSM implementation.

   Usage:
     (def http (make-http1-fsm {:max-retries 5}))

     ;; Single request
     (proto/run-session http
       (proto/make-resources my-transport)
       {:request {:method :GET :url \"/api/data\"
                  :headers {\"Host\" \"example.com\"}}})"
  ([] (make-http1-fsm {}))
  ([opts]
   (let [spec     (http1-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))
         defaults {:connect-timeout-ms default-connect-timeout-ms
                   :recv-timeout-ms    default-recv-timeout-ms
                   :max-retries        default-max-retries
                   :initial-backoff-ms default-initial-backoff-ms
                   :keep-alive?        true
                   :retryable-status?  retryable-status?
                   :backoff-fn         retry/exponential-backoff-ms}]
     (reify proto/IProtocolFSM
       (protocol-id [_] :http/1.1)

       (fsm-spec [_] spec)

       (compiled [_] @compiled)

       (initial-data [_ session-opts]
         (merge defaults opts session-opts
                {:response         nil
                 :retry-count      0
                 :keep-alive-next? false}))

       (terminal-states [_]
         #{::complete ::error})

       (composable-states [_]
         ;; HTTP/1.1 doesn't host sub-FSMs
         {})))))
