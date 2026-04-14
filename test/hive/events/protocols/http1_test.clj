(ns hive.events.protocols.http1-test
  "Tests for HTTP/1.1 request lifecycle FSM.

   Verifies state transitions with mock transport:
   - HTTP helper functions
   - Handler unit tests (direct invocation, no FSM engine)
   - Dispatch predicates
   - IProtocolFSM contract
   - Integration: GET happy path
   - Integration: POST with body
   - Integration: retry then success (429 → backoff → 200)
   - Integration: retry exhaustion
   - Integration: keep-alive recycling
   - Integration: Retry-After header
   - Error paths: closed transport, recv timeout, send failure"
  (:require [clojure.test :refer [deftest is testing]]
            [hive.events.protocols.core :as proto]
            [hive.events.protocols.http1 :as http1]
            [hive.events.protocols.retry :as retry]))

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

(defn closed-transport
  "Create a mock transport that reports closed."
  []
  (reify proto/ITransport
    (transport-id [_] :mock-closed)
    (send! [_ _ _] {:error :closed})
    (recv! [_ _] {:error :closed})
    (close! [_] nil)
    (open? [_] false)))

(defn error-send-transport
  "Transport that is open but fails on every send!."
  []
  (let [open (atom true)]
    (reify proto/ITransport
      (transport-id [_] :mock-error-send)
      (send! [_ _ _] {:error :send-failed})
      (recv! [_ _] {:error :no-data})
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
;; Test data helpers
;; =============================================================================

(def ^:private get-request
  {:method :GET :url "/api/data" :headers {"Host" "example.com"}})

(def ^:private post-request
  {:method :POST :url "/api/data"
   :headers {"Host" "example.com" "Content-Type" "application/json"}
   :body "{\"key\":\"value\"}"})

(def ^:private head-request
  {:method :HEAD :url "/api/health" :headers {"Host" "example.com"}})

(defn- status-response
  "Build a mock status-line response."
  [status]
  {:status status :reason "OK" :version "HTTP/1.1"})

(defn- response-headers
  "Build a mock response headers message."
  ([content-length]
   {:headers {"Content-Type" "text/plain"
              "Content-Length" (str content-length)}})
  ([content-length extra-headers]
   {:headers (merge {"Content-Type" "text/plain"
                     "Content-Length" (str content-length)}
                    extra-headers)}))

(defn- response-body
  "Build a mock response body message."
  [body]
  {:body body :complete? true})

(defn- noop-sleep [_ms] nil)

;; =============================================================================
;; Unit tests — HTTP helpers
;; =============================================================================

(deftest retryable-status-test
  (testing "retryable status codes"
    (doseq [s [429 500 502 503 504]]
      (is (http1/retryable-status? s) (str s " should be retryable"))))
  (testing "non-retryable status codes"
    (doseq [s [200 201 301 302 400 401 403 404 405 408]]
      (is (not (http1/retryable-status? s)) (str s " should NOT be retryable")))))

(deftest parse-content-length-test
  (testing "parses standard header"
    (is (= 42 (http1/parse-content-length {"Content-Length" "42"}))))
  (testing "parses lowercase header"
    (is (= 100 (http1/parse-content-length {"content-length" "100"}))))
  (testing "returns nil for missing header"
    (is (nil? (http1/parse-content-length {}))))
  (testing "returns nil for unparseable value"
    (is (nil? (http1/parse-content-length {"Content-Length" "abc"})))))

(deftest chunked-transfer-test
  (testing "detects chunked encoding"
    (is (http1/chunked-transfer? {"Transfer-Encoding" "chunked"})))
  (testing "detects case-insensitive"
    (is (http1/chunked-transfer? {"transfer-encoding" "Chunked"})))
  (testing "false when not chunked"
    (is (not (http1/chunked-transfer? {"Transfer-Encoding" "gzip"}))))
  (testing "false when missing"
    (is (not (http1/chunked-transfer? {})))))

(deftest response-keep-alive-test
  (testing "HTTP/1.1 defaults to keep-alive"
    (is (http1/response-keep-alive? {} "HTTP/1.1")))
  (testing "HTTP/1.1 close header disables keep-alive"
    (is (not (http1/response-keep-alive? {"Connection" "close"} "HTTP/1.1"))))
  (testing "HTTP/1.0 defaults to no keep-alive"
    (is (not (http1/response-keep-alive? {} "HTTP/1.0"))))
  (testing "HTTP/1.0 explicit keep-alive"
    (is (http1/response-keep-alive? {"Connection" "keep-alive"} "HTTP/1.0")))
  (testing "case-insensitive Connection header"
    (is (not (http1/response-keep-alive? {"connection" "Close"} "HTTP/1.1")))))

(deftest parse-retry-after-header-test
  (testing "parses integer seconds"
    (is (= 3000 (http1/parse-retry-after-header {"Retry-After" "3"}))))
  (testing "parses lowercase header"
    (is (= 5000 (http1/parse-retry-after-header {"retry-after" "5"}))))
  (testing "returns nil for missing header"
    (is (nil? (http1/parse-retry-after-header {}))))
  (testing "returns nil for non-numeric value"
    (is (nil? (http1/parse-retry-after-header {"Retry-After" "Thu, 01 Dec 2025"})))))

(deftest no-body-status-test
  (testing "204 No Content"
    (is (http1/no-body-status? 204)))
  (testing "304 Not Modified"
    (is (http1/no-body-status? 304)))
  (testing "100 Continue"
    (is (http1/no-body-status? 100)))
  (testing "101 Switching Protocols"
    (is (http1/no-body-status? 101)))
  (testing "200 OK has body"
    (is (not (http1/no-body-status? 200))))
  (testing "404 has body"
    (is (not (http1/no-body-status? 404)))))

;; =============================================================================
;; Handler tests — direct invocation (no FSM engine needed)
;; =============================================================================

(deftest on-idle-enter-test
  (testing "clears intermediate state, preserves response and config"
    (let [data {:status 200 :reason "OK" :http-version "HTTP/1.1"
                :response-headers {"X" "1"} :response-body "hello"
                :status-received? true :headers-complete? true :body-complete? true
                :connected? true :headers-sent? true :body-sent? true
                :method-str "GET" :expected-length 5 :chunked? false
                :error :old-error :error-phase :old-phase
                :retryable? false :keep-alive-next? true :last-wait-ms 100
                ;; These should survive
                :response {:status 200 :headers {} :body "hello"}
                :retry-count 1 :keep-alive? true :max-retries 3
                :request get-request}
          result (http1/on-idle-enter nil data)]
      ;; Cleared
      (is (nil? (:status result)))
      (is (nil? (:reason result)))
      (is (nil? (:response-headers result)))
      (is (nil? (:response-body result)))
      (is (nil? (:status-received? result)))
      (is (nil? (:headers-complete? result)))
      (is (nil? (:body-complete? result)))
      (is (nil? (:connected? result)))
      (is (nil? (:headers-sent? result)))
      (is (nil? (:body-sent? result)))
      (is (nil? (:method-str result)))
      (is (nil? (:error result)))
      (is (nil? (:retryable? result)))
      (is (nil? (:keep-alive-next? result)))
      ;; Preserved
      (is (= {:status 200 :headers {} :body "hello"} (:response result)))
      (is (= 1 (:retry-count result)))
      (is (true? (:keep-alive? result)))
      (is (= get-request (:request result))))))

(deftest on-connect-test
  (testing "open transport sets connected?"
    (let [tp     (mock-transport (atom []) (atom []))
          result (http1/on-connect {:transport tp} {})]
      (is (:connected? result))
      (is (nil? (:error result)))))
  (testing "closed transport sets error"
    (let [tp     (closed-transport)
          result (http1/on-connect {:transport tp} {})]
      (is (= :transport-closed (:error result)))
      (is (= :connecting (:error-phase result))))))

(deftest on-send-headers-test
  (testing "sends GET request head via transport"
    (let [sent   (atom [])
          tp     (mock-transport (atom []) sent)
          data   {:request get-request}
          result (http1/on-send-headers {:transport tp} data)]
      (is (:headers-sent? result))
      (is (= "GET" (:method-str result)))
      (is (= 1 (count @sent)))
      (let [sent-data (first @sent)]
        (is (= :request-head (:type sent-data)))
        (is (= "GET" (:method sent-data)))
        (is (= "/api/data" (:url sent-data)))
        (is (= "HTTP/1.1" (:version sent-data)))
        (is (= "example.com" (get-in sent-data [:headers "Host"]))))))
  (testing "normalises method keyword to uppercase string"
    (let [sent   (atom [])
          tp     (mock-transport (atom []) sent)
          data   {:request {:method :post :url "/x"}}
          result (http1/on-send-headers {:transport tp} data)]
      (is (= "POST" (:method-str result)))
      (is (= "POST" (:method (first @sent))))))
  (testing "transport send error propagates"
    (let [tp     (error-send-transport)
          result (http1/on-send-headers {:transport tp} {:request get-request})]
      (is (= :send-failed (:error result)))
      (is (= :sending-headers (:error-phase result))))))

(deftest on-send-body-test
  (testing "sends request body via transport"
    (let [sent   (atom [])
          tp     (mock-transport (atom []) sent)
          data   {:request post-request}
          result (http1/on-send-body {:transport tp} data)]
      (is (:body-sent? result))
      (is (= 1 (count @sent)))
      (is (= :request-body (:type (first @sent))))
      (is (= "{\"key\":\"value\"}" (:body (first @sent))))))
  (testing "transport send error propagates"
    (let [tp     (error-send-transport)
          result (http1/on-send-body {:transport tp} {:request post-request})]
      (is (= :send-failed (:error result)))
      (is (= :sending-body (:error-phase result))))))

(deftest on-recv-status-test
  (testing "parses 200 status line"
    (let [recv-q (atom [(status-response 200)])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-status {:transport tp} {:recv-timeout-ms 5000})]
      (is (:status-received? result))
      (is (= 200 (:status result)))
      (is (= "OK" (:reason result)))
      (is (= "HTTP/1.1" (:http-version result)))))
  (testing "parses 404 status line"
    (let [recv-q (atom [{:status 404 :reason "Not Found" :version "HTTP/1.1"}])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-status {:transport tp} {})]
      (is (= 404 (:status result)))
      (is (= "Not Found" (:reason result)))))
  (testing "transport recv error propagates"
    (let [recv-q (atom [])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-status {:transport tp} {})]
      (is (= :no-data (:error result)))
      (is (= :awaiting-response (:error-phase result))))))

(deftest on-recv-headers-test
  (testing "parses response headers with Content-Length"
    (let [recv-q (atom [(response-headers 42)])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-headers {:transport tp} {})]
      (is (:headers-complete? result))
      (is (= 42 (:expected-length result)))
      (is (not (:chunked? result)))
      (is (= "text/plain" (get-in result [:response-headers "Content-Type"])))))
  (testing "parses chunked encoding"
    (let [recv-q (atom [(response-headers 0 {"Transfer-Encoding" "chunked"})])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-headers {:transport tp} {})]
      (is (:headers-complete? result))
      (is (:chunked? result))))
  (testing "transport recv error propagates"
    (let [recv-q (atom [])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-headers {:transport tp} {})]
      (is (= :no-data (:error result)))
      (is (= :reading-headers (:error-phase result))))))

(deftest on-recv-body-test
  (testing "reads complete body"
    (let [recv-q (atom [(response-body "Hello, World!")])
          tp     (mock-transport recv-q (atom []))
          data   {:status 200 :expected-length 13}
          result (http1/on-recv-body {:transport tp} data)]
      (is (:body-complete? result))
      (is (= "Hello, World!" (:response-body result)))))
  (testing "204 No Content skips body read"
    (let [recv-q (atom [])  ;; recv should NOT be called
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-body {:transport tp} {:status 204})]
      (is (:body-complete? result))
      (is (= "" (:response-body result)))))
  (testing "304 Not Modified skips body read"
    (let [recv-q (atom [])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-body {:transport tp} {:status 304})]
      (is (:body-complete? result))
      (is (= "" (:response-body result)))))
  (testing "HEAD request skips body read"
    (let [recv-q (atom [])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-body {:transport tp} {:status 200 :method-str "HEAD"})]
      (is (:body-complete? result))
      (is (= "" (:response-body result)))))
  (testing "transport recv error propagates"
    (let [recv-q (atom [])
          tp     (mock-transport recv-q (atom []))
          result (http1/on-recv-body {:transport tp} {:status 200})]
      (is (= :no-data (:error result)))
      (is (= :reading-body (:error-phase result))))))

(deftest on-complete-test
  (testing "assembles final response on success"
    (let [data   {:status 200
                  :response-headers {"Content-Type" "text/plain"}
                  :response-body "ok"
                  :http-version "HTTP/1.1"
                  :retry-count 0 :max-retries 3
                  :keep-alive? true
                  :retryable-status? http1/retryable-status?
                  :request get-request}
          result (http1/on-complete nil data)]
      (is (= {:status 200 :headers {"Content-Type" "text/plain"} :body "ok"}
             (:response result)))
      (is (not (:retryable? result)))
      (is (:keep-alive-next? result))
      ;; :request dissoc'd (not retryable)
      (is (nil? (:request result)))))
  (testing "429 with retries remaining → retryable"
    (let [data   {:status 429 :response-headers {} :response-body ""
                  :http-version "HTTP/1.1"
                  :retry-count 0 :max-retries 3
                  :retryable-status? http1/retryable-status?
                  :request get-request}
          result (http1/on-complete nil data)]
      (is (:retryable? result))
      (is (not (:keep-alive-next? result)))
      ;; :request preserved for retry
      (is (some? (:request result)))))
  (testing "retryable but exhausted → NOT retryable"
    (let [data   {:status 503 :response-headers {} :response-body ""
                  :http-version "HTTP/1.1"
                  :retry-count 3 :max-retries 3
                  :retryable-status? http1/retryable-status?
                  :request get-request}
          result (http1/on-complete nil data)]
      (is (not (:retryable? result)))
      (is (nil? (:request result)))))
  (testing "Connection: close disables keep-alive"
    (let [data   {:status 200 :response-headers {"Connection" "close"}
                  :response-body "ok" :http-version "HTTP/1.1"
                  :retry-count 0 :max-retries 3
                  :keep-alive? true
                  :retryable-status? http1/retryable-status?
                  :request get-request}
          result (http1/on-complete nil data)]
      (is (not (:keep-alive-next? result)))))
  (testing "custom retryable-status? predicate"
    (let [data   {:status 418 :response-headers {} :response-body ""
                  :http-version "HTTP/1.1"
                  :retry-count 0 :max-retries 3
                  :retryable-status? (fn [s] (= 418 s))
                  :request get-request}
          result (http1/on-complete nil data)]
      (is (:retryable? result)))))

(deftest on-retry-test
  (testing "computes backoff and increments retry-count"
    (let [sleep-log (atom [])
          data      {:retry-count 0 :response-headers {}
                     :backoff-fn retry/constant-backoff-ms
                     :initial-backoff-ms 500
                     :retryable? true}
          result    (http1/on-retry {:sleep-fn (fn [ms] (swap! sleep-log conj ms))}
                                    data)]
      (is (= 1 (:retry-count result)))
      (is (= 500 (:last-wait-ms result)))
      (is (= [500] @sleep-log))
      (is (nil? (:retryable? result)))))
  (testing "respects Retry-After header over backoff calculation"
    (let [sleep-log (atom [])
          data      {:retry-count 0
                     :response-headers {"Retry-After" "3"}
                     :backoff-fn retry/constant-backoff-ms
                     :initial-backoff-ms 500}
          result    (http1/on-retry {:sleep-fn (fn [ms] (swap! sleep-log conj ms))}
                                    data)]
      (is (= 3000 (:last-wait-ms result)))
      (is (= [3000] @sleep-log))))
  (testing "no sleep-fn does not crash"
    (let [data   {:retry-count 0 :response-headers {}
                  :backoff-fn retry/constant-backoff-ms
                  :initial-backoff-ms 100}
          result (http1/on-retry {} data)]
      (is (= 1 (:retry-count result))))))

(deftest on-error-test
  (testing "closes transport and marks transport-closed?"
    (let [recv-q (atom [])
          sent   (atom [])
          tp     (mock-transport recv-q sent)
          data   {:error :timeout :error-phase :reading-body}
          result (http1/on-error {:transport tp} data)]
      (is (:transport-closed? result))
      (is (not (proto/open? tp)))))
  (testing "preserves partial response when status was received"
    (let [tp     (mock-transport (atom []) (atom []))
          data   {:error :timeout :error-phase :reading-body
                  :status 200 :response-headers {"X" "1"} :response-body "partial"}
          result (http1/on-error {:transport tp} data)]
      (is (= 200 (get-in result [:response :status])))
      (is (= {"X" "1"} (get-in result [:response :headers])))
      (is (= "partial" (get-in result [:response :body])))))
  (testing "no partial response when status not received"
    (let [tp     (mock-transport (atom []) (atom []))
          data   {:error :timeout :error-phase :connecting}
          result (http1/on-error {:transport tp} data)]
      (is (:transport-closed? result))
      (is (nil? (:response result)))))
  (testing "cancels timers when timer resource present"
    (let [tp    (mock-transport (atom []) (atom []))
          timer (mock-timer)
          data  {:error :timeout}
          result (http1/on-error {:transport tp :timer timer} data)]
      (is (:transport-closed? result)))))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(deftest dispatch-predicates-test
  (testing "has-request?"
    (is (http1/has-request? nil {:request get-request}))
    (is (not (http1/has-request? nil {}))))
  (testing "connected?"
    (is (http1/connected? nil {:connected? true}))
    (is (not (http1/connected? nil {}))))
  (testing "has-body? — POST with body"
    (is (http1/has-body? nil {:request post-request})))
  (testing "has-body? — GET without body"
    (is (not (http1/has-body? nil {:request get-request}))))
  (testing "status-received?"
    (is (http1/status-received? nil {:status-received? true}))
    (is (not (http1/status-received? nil {}))))
  (testing "headers-complete?"
    (is (http1/headers-complete? nil {:headers-complete? true}))
    (is (not (http1/headers-complete? nil {}))))
  (testing "body-complete?"
    (is (http1/body-complete? nil {:body-complete? true}))
    (is (not (http1/body-complete? nil {}))))
  (testing "retryable?"
    (is (http1/retryable? nil {:retryable? true}))
    (is (not (http1/retryable? nil {})))
    (is (not (http1/retryable? nil {:retryable? false}))))
  (testing "keep-alive-next?"
    (is (http1/keep-alive-next? nil {:keep-alive-next? true}))
    (is (not (http1/keep-alive-next? nil {}))))
  (testing "has-error?"
    (is (http1/has-error? nil {:error :boom}))
    (is (not (http1/has-error? nil {}))))
  (testing "always"
    (is (http1/always nil {}))
    (is (http1/always nil nil))))

;; =============================================================================
;; FSM spec structure
;; =============================================================================

(deftest fsm-spec-structure-test
  (testing "spec has correct shape"
    (let [spec (http1/http1-fsm-spec {})]
      (is (= :http/1.1 (:id spec)))
      (is (= ::http1/idle (:initial spec)))
      (is (= #{::http1/idle ::http1/connecting ::http1/sending-headers
               ::http1/sending-body ::http1/awaiting-response
               ::http1/reading-headers ::http1/reading-body
               ::http1/complete ::http1/retrying ::http1/error}
             (set (keys (:states spec)))))))
  (testing "terminal states have no :dispatch"
    (let [spec (http1/http1-fsm-spec {})]
      (is (nil? (get-in spec [:states ::http1/error :dispatch])))))
  (testing "non-terminal states have :dispatch"
    (let [spec (http1/http1-fsm-spec {})]
      (doseq [state [::http1/idle ::http1/connecting ::http1/sending-headers
                     ::http1/sending-body ::http1/awaiting-response
                     ::http1/reading-headers ::http1/reading-body
                     ::http1/complete ::http1/retrying]]
        (is (some? (get-in spec [:states state :dispatch]))
            (str state " should have :dispatch"))))))

;; =============================================================================
;; IProtocolFSM contract
;; =============================================================================

(deftest make-http1-fsm-test
  (testing "factory returns valid IProtocolFSM"
    (let [fsm (http1/make-http1-fsm {:max-retries 5})]
      (is (= :http/1.1 (proto/protocol-id fsm)))
      (is (map? (proto/fsm-spec fsm)))
      (is (= #{::http1/complete ::http1/error} (proto/terminal-states fsm)))
      (is (= {} (proto/composable-states fsm)))))
  (testing "initial-data includes defaults and overrides"
    (let [fsm  (http1/make-http1-fsm {:recv-timeout-ms 10000})
          data (proto/initial-data fsm {:request get-request})]
      (is (= 10000 (:recv-timeout-ms data)))
      (is (= 5000 (:connect-timeout-ms data)))
      (is (= get-request (:request data)))
      (is (= 0 (:retry-count data)))
      (is (nil? (:response data)))
      (is (fn? (:retryable-status? data)))
      (is (fn? (:backoff-fn data)))
      (is (true? (:keep-alive? data)))))
  (testing "factory opts override defaults"
    (let [fsm  (http1/make-http1-fsm {:max-retries 7 :keep-alive? false})
          data (proto/initial-data fsm {})]
      (is (= 7 (:max-retries data)))
      (is (false? (:keep-alive? data))))))

;; =============================================================================
;; Integration: Happy path GET
;; idle → connecting → sending-headers → awaiting-response
;; → reading-headers → reading-body → complete
;; =============================================================================

(deftest happy-path-get-test
  (testing "full GET lifecycle via direct handler calls"
    (let [sent    (atom [])
          recv-q  (atom [(status-response 200)
                         (response-headers 5)
                         (response-body "hello")])
          tp      (mock-transport recv-q sent)
          res     {:transport tp}

          d0      {:request get-request
                   :keep-alive? false
                   :retryable-status? http1/retryable-status?
                   :max-retries 3 :retry-count 0}

          ;; 1. idle — enter (reset)
          d1      (http1/on-idle-enter res d0)
          _       (is (http1/has-request? nil d1))

          ;; 2. connecting — enter
          d2      (http1/on-connect res d1)
          _       (is (:connected? d2))

          ;; 3. sending-headers — enter
          d3      (http1/on-send-headers res d2)
          _       (is (:headers-sent? d3))
          _       (is (= 1 (count @sent)))

          ;; GET has no body → skip sending-body
          _       (is (not (http1/has-body? nil d3)))

          ;; 4. awaiting-response — handle
          d4      (http1/on-recv-status res d3)
          _       (is (= 200 (:status d4)))
          _       (is (:status-received? d4))

          ;; 5. reading-headers — handle
          d5      (http1/on-recv-headers res d4)
          _       (is (:headers-complete? d5))
          _       (is (= 5 (:expected-length d5)))

          ;; 6. reading-body — handle
          d6      (http1/on-recv-body res d5)
          _       (is (:body-complete? d6))
          _       (is (= "hello" (:response-body d6)))

          ;; 7. complete — enter
          d7      (http1/on-complete res d6)]

      ;; Final response
      (is (= 200 (get-in d7 [:response :status])))
      (is (= {"Content-Type" "text/plain" "Content-Length" "5"}
             (get-in d7 [:response :headers])))
      (is (= "hello" (get-in d7 [:response :body])))
      (is (not (:retryable? d7)))
      (is (not (:keep-alive-next? d7)))
      (is (nil? (:request d7)))

      ;; Verify sent data
      (is (= :request-head (:type (first @sent))))
      (is (= "GET" (:method (first @sent)))))))

;; =============================================================================
;; Integration: POST with body
;; =============================================================================

(deftest happy-path-post-test
  (testing "POST goes through sending-body state"
    (let [sent   (atom [])
          recv-q (atom [(status-response 201)
                        (response-headers 7)
                        (response-body "created")])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}

          d0     {:request post-request
                  :keep-alive? false
                  :retryable-status? http1/retryable-status?
                  :max-retries 3 :retry-count 0}

          d1  (http1/on-idle-enter res d0)
          d2  (http1/on-connect res d1)
          d3  (http1/on-send-headers res d2)

          ;; POST has body
          _   (is (http1/has-body? nil d3))

          ;; sending-body — enter
          d4  (http1/on-send-body res d3)
          _   (is (:body-sent? d4))
          _   (is (= 2 (count @sent)))
          _   (is (= :request-head (:type (first @sent))))
          _   (is (= :request-body (:type (second @sent))))
          _   (is (= "{\"key\":\"value\"}" (:body (second @sent))))

          d5  (http1/on-recv-status res d4)
          d6  (http1/on-recv-headers res d5)
          d7  (http1/on-recv-body res d6)
          d8  (http1/on-complete res d7)]

      (is (= 201 (get-in d8 [:response :status])))
      (is (= "created" (get-in d8 [:response :body]))))))

;; =============================================================================
;; Integration: Retry then success — 429 → backoff → 200
;; =============================================================================

(deftest retry-then-success-test
  (testing "429 triggers retry, second attempt succeeds"
    (let [sleep-log (atom [])
          sent      (atom [])
          recv-q    (atom [;; First round: 429
                           (status-response 429)
                           (response-headers 0)
                           (response-body "")
                           ;; Second round: 200
                           (status-response 200)
                           (response-headers 2)
                           (response-body "ok")])
          tp        (mock-transport recv-q sent)
          res       {:transport tp :sleep-fn (fn [ms] (swap! sleep-log conj ms))}

          d0        {:request get-request
                     :keep-alive? false
                     :retryable-status? http1/retryable-status?
                     :max-retries 3 :retry-count 0
                     :backoff-fn retry/constant-backoff-ms
                     :initial-backoff-ms 100}

          ;; First cycle
          d1  (http1/on-idle-enter res d0)
          d2  (http1/on-connect res d1)
          d3  (http1/on-send-headers res d2)
          d4  (http1/on-recv-status res d3)
          _   (is (= 429 (:status d4)))
          d5  (http1/on-recv-headers res d4)
          d6  (http1/on-recv-body res d5)
          d7  (http1/on-complete res d6)
          _   (is (:retryable? d7))
          _   (is (some? (:request d7)))

          ;; Retry backoff
          d8  (http1/on-retry res d7)
          _   (is (= 1 (:retry-count d8)))
          _   (is (= [100] @sleep-log))

          ;; Second cycle (skips ::idle, goes straight to ::connecting)
          d9   (http1/on-connect res d8)
          d10  (http1/on-send-headers res d9)
          d11  (http1/on-recv-status res d10)
          _    (is (= 200 (:status d11)))
          d12  (http1/on-recv-headers res d11)
          d13  (http1/on-recv-body res d12)
          d14  (http1/on-complete res d13)]

      (is (= 200 (get-in d14 [:response :status])))
      (is (= "ok" (get-in d14 [:response :body])))
      (is (not (:retryable? d14)))
      ;; Two request-head sends (original + retry)
      (is (= 2 (count (filter #(= :request-head (:type %)) @sent)))))))

;; =============================================================================
;; Integration: Retry exhaustion
;; =============================================================================

(deftest retry-exhaustion-test
  (testing "all retries exhausted → complete with error response"
    (let [sleep-log  (atom [])
          sent       (atom [])
          ;; 4 total attempts (1 initial + 3 retries), all 503
          recv-q     (atom (vec (mapcat (fn [_] [(status-response 503)
                                                 (response-headers 0)
                                                 (response-body "")])
                                        (range 4))))
          tp         (mock-transport recv-q sent)
          res        {:transport tp :sleep-fn (fn [ms] (swap! sleep-log conj ms))}

          run-cycle  (fn [data]
                       (->> data
                            (http1/on-connect res)
                            (http1/on-send-headers res)
                            (http1/on-recv-status res)
                            (http1/on-recv-headers res)
                            (http1/on-recv-body res)
                            (http1/on-complete res)))

          d0  {:request get-request
               :keep-alive? false
               :retryable-status? http1/retryable-status?
               :max-retries 3 :retry-count 0
               :backoff-fn retry/constant-backoff-ms
               :initial-backoff-ms 100}

          d1  (http1/on-idle-enter res d0)

          ;; Attempt 1 (retry-count=0)
          d2  (run-cycle d1)
          _   (is (:retryable? d2))
          d3  (http1/on-retry res d2)
          _   (is (= 1 (:retry-count d3)))

          ;; Attempt 2 (retry-count=1)
          d4  (run-cycle d3)
          _   (is (:retryable? d4))
          d5  (http1/on-retry res d4)
          _   (is (= 2 (:retry-count d5)))

          ;; Attempt 3 (retry-count=2)
          d6  (run-cycle d5)
          _   (is (:retryable? d6))
          d7  (http1/on-retry res d6)
          _   (is (= 3 (:retry-count d7)))

          ;; Attempt 4 (retry-count=3 = max-retries → exhausted)
          d8  (run-cycle d7)]

      (is (not (:retryable? d8)))
      (is (= 503 (get-in d8 [:response :status])))
      (is (= 3 (count @sleep-log)))
      (is (= [100 100 100] @sleep-log))
      ;; request dissoc'd (exhausted, not retrying)
      (is (nil? (:request d8))))))

;; =============================================================================
;; Integration: Keep-alive recycling — complete → idle
;; =============================================================================

(deftest keep-alive-recycling-test
  (testing "keep-alive response enables idle recycling, transport stays open"
    (let [sent   (atom [])
          recv-q (atom [(status-response 200)
                        (response-headers 5)
                        (response-body "hello")])
          tp     (mock-transport recv-q sent)
          res    {:transport tp}

          d0  {:request get-request
               :keep-alive? true
               :retryable-status? http1/retryable-status?
               :max-retries 3 :retry-count 0}

          d1  (http1/on-idle-enter res d0)
          d2  (http1/on-connect res d1)
          d3  (http1/on-send-headers res d2)
          d4  (http1/on-recv-status res d3)
          d5  (http1/on-recv-headers res d4)
          d6  (http1/on-recv-body res d5)
          d7  (http1/on-complete res d6)]

      ;; Complete with keep-alive
      (is (:keep-alive-next? d7))
      (is (not (:retryable? d7)))
      (is (nil? (:request d7)))

      ;; Simulate transition to idle
      (let [d8 (http1/on-idle-enter res d7)]
        ;; Response preserved from previous cycle
        (is (= 200 (get-in d8 [:response :status])))
        ;; No request → FSM would terminate at idle
        (is (not (http1/has-request? nil d8)))
        ;; Transport still open for reuse
        (is (proto/open? tp)))))

  (testing "Connection: close prevents keep-alive recycling"
    (let [recv-q (atom [(status-response 200)
                        (response-headers 2 {"Connection" "close"})
                        (response-body "ok")])
          tp     (mock-transport recv-q (atom []))
          res    {:transport tp}
          d0     {:request get-request
                  :keep-alive? true
                  :retryable-status? http1/retryable-status?
                  :max-retries 3 :retry-count 0}
          d1  (http1/on-idle-enter res d0)
          d2  (http1/on-connect res d1)
          d3  (http1/on-send-headers res d2)
          d4  (http1/on-recv-status res d3)
          d5  (http1/on-recv-headers res d4)
          d6  (http1/on-recv-body res d5)
          d7  (http1/on-complete res d6)]
      ;; Not keep-alive because of Connection: close
      (is (not (:keep-alive-next? d7))))))

;; =============================================================================
;; Integration: Retry-After header respected
;; =============================================================================

(deftest retry-with-retry-after-header-test
  (testing "Retry-After header overrides backoff calculation"
    (let [sleep-log (atom [])
          recv-q    (atom [(status-response 429)
                           (response-headers 0 {"Retry-After" "5"})
                           (response-body "")
                           ;; Second round
                           (status-response 200)
                           (response-headers 2)
                           (response-body "ok")])
          tp        (mock-transport recv-q (atom []))
          res       {:transport tp :sleep-fn (fn [ms] (swap! sleep-log conj ms))}

          d0  {:request get-request
               :keep-alive? false
               :retryable-status? http1/retryable-status?
               :max-retries 3 :retry-count 0
               :backoff-fn retry/constant-backoff-ms
               :initial-backoff-ms 100}

          d1  (http1/on-idle-enter res d0)
          d2  (http1/on-connect res d1)
          d3  (http1/on-send-headers res d2)
          d4  (http1/on-recv-status res d3)
          d5  (http1/on-recv-headers res d4)
          d6  (http1/on-recv-body res d5)
          d7  (http1/on-complete res d6)
          d8  (http1/on-retry res d7)]

      ;; Should sleep 5000ms (Retry-After: 5) instead of 100ms (constant backoff)
      (is (= [5000] @sleep-log))
      (is (= 5000 (:last-wait-ms d8))))))

;; =============================================================================
;; Error paths
;; =============================================================================

(deftest error-on-closed-transport-test
  (testing "closed transport → error at connecting"
    (let [tp     (closed-transport)
          res    {:transport tp}
          d0     {:request get-request :retry-count 0}
          d1     (http1/on-idle-enter res d0)
          d2     (http1/on-connect res d1)]
      (is (http1/has-error? nil d2))
      (is (= :transport-closed (:error d2)))
      (is (= :connecting (:error-phase d2)))
      ;; Error handler
      (let [d3 (http1/on-error res d2)]
        (is (:transport-closed? d3))))))

(deftest error-on-recv-timeout-test
  (testing "empty recv queue simulates timeout at awaiting-response"
    (let [sent   (atom [])
          recv-q (atom [])  ;; empty → :no-data on first recv
          tp     (mock-transport recv-q sent)
          res    {:transport tp}
          d0     {:request get-request :retry-count 0}
          d1     (http1/on-idle-enter res d0)
          d2     (http1/on-connect res d1)
          d3     (http1/on-send-headers res d2)
          d4     (http1/on-recv-status res d3)]
      (is (= :no-data (:error d4)))
      (is (= :awaiting-response (:error-phase d4))))))

(deftest error-on-send-failure-test
  (testing "send failure at sending-headers → error"
    (let [tp     (error-send-transport)
          res    {:transport tp}
          d0     {:request get-request :retry-count 0}
          d1     (http1/on-idle-enter res d0)
          d2     (http1/on-connect res d1)
          d3     (http1/on-send-headers res d2)]
      (is (= :send-failed (:error d3)))
      (is (= :sending-headers (:error-phase d3))))))

(deftest error-on-body-send-failure-test
  (testing "send failure at sending-body → error"
    (let [tp     (error-send-transport)
          res    {:transport tp}
          d0     {:request post-request :retry-count 0}
          d1     (http1/on-idle-enter res d0)
          d2     (http1/on-connect res d1)
          ;; send-headers will also fail, but let's test send-body directly
          d3     (http1/on-send-body res d2)]
      (is (= :send-failed (:error d3)))
      (is (= :sending-body (:error-phase d3))))))

;; =============================================================================
;; Edge cases
;; =============================================================================

(deftest head-request-no-body-test
  (testing "HEAD request lifecycle completes without reading body"
    (let [sent   (atom [])
          recv-q (atom [(status-response 200)
                        (response-headers 1000)])  ;; C-L is 1000 but HEAD has no body
          tp     (mock-transport recv-q sent)
          res    {:transport tp}

          d0  {:request head-request
               :keep-alive? false
               :retryable-status? http1/retryable-status?
               :max-retries 3 :retry-count 0}

          d1  (http1/on-idle-enter res d0)
          d2  (http1/on-connect res d1)
          d3  (http1/on-send-headers res d2)
          _   (is (= "HEAD" (:method-str d3)))
          d4  (http1/on-recv-status res d3)
          d5  (http1/on-recv-headers res d4)
          ;; reading-body should skip because HEAD
          d6  (http1/on-recv-body res d5)]

      (is (:body-complete? d6))
      (is (= "" (:response-body d6)))
      ;; recv-q should still have items (body was not read from transport)
      ;; Actually recv-q was depleted by status + headers, but no body read was done
      )))

(deftest default-method-test
  (testing "nil method defaults to GET"
    (let [sent   (atom [])
          tp     (mock-transport (atom []) sent)
          data   {:request {:url "/test"}}
          result (http1/on-send-headers {:transport tp} data)]
      (is (= "GET" (:method (first @sent)))))))

(deftest multiple-retries-with-exponential-backoff-test
  (testing "exponential backoff grows between retries"
    (let [sleep-log (atom [])
          recv-q    (atom (vec (mapcat (fn [_] [(status-response 500)
                                                (response-headers 0)
                                                (response-body "")])
                                       (range 3))))
          tp        (mock-transport recv-q (atom []))
          res       {:transport tp :sleep-fn (fn [ms] (swap! sleep-log conj ms))}

          run-and-retry (fn [data]
                          (->> data
                               (http1/on-connect res)
                               (http1/on-send-headers res)
                               (http1/on-recv-status res)
                               (http1/on-recv-headers res)
                               (http1/on-recv-body res)
                               (http1/on-complete res)
                               (http1/on-retry res)))

          d0  {:request get-request
               :keep-alive? false
               :retryable-status? http1/retryable-status?
               :max-retries 5 :retry-count 0
               :backoff-fn retry/exponential-backoff-ms
               :initial-backoff-ms 100}

          d1  (http1/on-idle-enter res d0)
          d2  (run-and-retry d1)
          d3  (run-and-retry d2)
          d4  (run-and-retry d3)]

      ;; Each successive backoff should be larger than the previous
      (is (= 3 (count @sleep-log)))
      (is (< (nth @sleep-log 0) (nth @sleep-log 1)))
      (is (< (nth @sleep-log 1) (nth @sleep-log 2))))))
