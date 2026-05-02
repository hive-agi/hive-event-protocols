(ns hive.events.protocols.http2
  "RFC 7540 HTTP/2 connection + stream FSMs.

   The HTTP/2 protocol is modelled as two cooperating finite state
   machines:

     1. **Connection FSM** — manages the wire connection lifecycle
        (preface, settings exchange, GOAWAY, etc.).
     2. **Stream FSM**     — manages one logical HTTP request/response
        as a sub-FSM of the connection's ::connected state.

   Both FSMs are pure data — all I/O happens through ITransport /
   ITimer resources injected at run time.  Frame parsing, framing,
   flow control accounting, and HPACK encoding/decoding are delegated
   to optional :hpack and :flow-control resources so the FSM can run
   against mock transports for testing.

   Factory:
     (make-http2-fsm opts)
       opts — {:max-concurrent-streams Long
               :initial-window-size    Long
               :max-frame-size         Long       ;; 2^14..2^24-1
               :max-header-list-size   Long
               :enable-push?           bool
               :preface-timeout-ms     Long
               :settings-timeout-ms    Long
               :recv-timeout-ms        Long}

   References:
     RFC 7540 §3 (Starting HTTP/2)
     RFC 7540 §5 (Streams and Multiplexing)
     RFC 7540 §6 (Frame Definitions)
     RFC 7540 §7 (Error Codes)"
  (:require [hive.events.protocols.core :as proto]))

;; =============================================================================
;; Constants — RFC 7540
;; =============================================================================

(def ^:const connection-preface
  "Mandatory HTTP/2 client connection preface (RFC 7540 §3.5)."
  "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

;; Frame types — RFC 7540 §11.2
(def ^:const frame-data          0x0)
(def ^:const frame-headers       0x1)
(def ^:const frame-priority      0x2)
(def ^:const frame-rst-stream    0x3)
(def ^:const frame-settings      0x4)
(def ^:const frame-push-promise  0x5)
(def ^:const frame-ping          0x6)
(def ^:const frame-goaway        0x7)
(def ^:const frame-window-update 0x8)
(def ^:const frame-continuation  0x9)

;; Frame flags — RFC 7540 §6
(def ^:const flag-end-stream  0x1)
(def ^:const flag-end-headers 0x4)
(def ^:const flag-padded      0x8)
(def ^:const flag-priority    0x20)
(def ^:const flag-ack         0x1)

;; Settings parameters — RFC 7540 §6.5.2
(def ^:const settings-header-table-size      0x1)
(def ^:const settings-enable-push            0x2)
(def ^:const settings-max-concurrent-streams 0x3)
(def ^:const settings-initial-window-size    0x4)
(def ^:const settings-max-frame-size         0x5)
(def ^:const settings-max-header-list-size   0x6)

;; Error codes — RFC 7540 §7
(def ^:const err-no-error            0x0)
(def ^:const err-protocol-error      0x1)
(def ^:const err-internal-error      0x2)
(def ^:const err-flow-control-error  0x3)
(def ^:const err-settings-timeout    0x4)
(def ^:const err-stream-closed       0x5)
(def ^:const err-frame-size-error    0x6)
(def ^:const err-refused-stream      0x7)
(def ^:const err-cancel              0x8)
(def ^:const err-compression-error   0x9)
(def ^:const err-connect-error       0xA)
(def ^:const err-enhance-your-calm   0xB)
(def ^:const err-inadequate-security 0xC)
(def ^:const err-http-1-1-required   0xD)

;; Defaults — RFC 7540 §6.5.2
(def ^:const default-max-concurrent-streams Long/MAX_VALUE)
(def ^:const default-initial-window-size    65535)
(def ^:const default-max-frame-size         16384)
(def ^:const default-max-header-list-size   Long/MAX_VALUE)
(def ^:const default-preface-timeout-ms     5000)
(def ^:const default-settings-timeout-ms    5000)
(def ^:const default-recv-timeout-ms        30000)

;; =============================================================================
;; Frame helpers
;; =============================================================================

(defn make-frame
  "Build a generic HTTP/2 frame map.

   type     — frame type byte
   flags    — set of flag keywords or numeric bitmap
   stream-id — 31-bit stream identifier (0 for connection-level frames)
   payload  — frame-specific payload map"
  [type flags stream-id payload]
  {:frame-type type
   :flags      (if (set? flags) flags (or flags #{}))
   :stream-id  stream-id
   :payload    payload})

(defn flag-set?
  "Check whether a frame carries a specific flag keyword."
  [frame flag]
  (contains? (:flags frame) flag))

(defn settings-frame?
  [frame]
  (= frame-settings (:frame-type frame)))

(defn settings-ack?
  [frame]
  (and (settings-frame? frame) (flag-set? frame :ack)))

(defn headers-frame?       [frame] (= frame-headers       (:frame-type frame)))
(defn data-frame?          [frame] (= frame-data          (:frame-type frame)))
(defn rst-stream-frame?    [frame] (= frame-rst-stream    (:frame-type frame)))
(defn goaway-frame?        [frame] (= frame-goaway        (:frame-type frame)))
(defn ping-frame?          [frame] (= frame-ping          (:frame-type frame)))
(defn window-update-frame? [frame] (= frame-window-update (:frame-type frame)))
(defn push-promise-frame?  [frame] (= frame-push-promise  (:frame-type frame)))
(defn continuation-frame?  [frame] (= frame-continuation  (:frame-type frame)))

(defn end-stream?
  "True if frame carries END_STREAM flag."
  [frame]
  (flag-set? frame :end-stream))

(defn end-headers?
  "True if frame carries END_HEADERS flag."
  [frame]
  (flag-set? frame :end-headers))

(defn next-client-stream-id
  "Compute the next client-initiated stream id (odd).

   RFC 7540 §5.1.1: client stream ids are odd, server stream ids even.
   First client stream is 1; subsequent open streams add 2."
  [last-stream-id]
  (if (or (nil? last-stream-id) (zero? last-stream-id))
    1
    (+ last-stream-id 2)))

(defn next-server-stream-id
  "Compute the next server-initiated stream id (even, used for PUSH_PROMISE)."
  [last-stream-id]
  (if (or (nil? last-stream-id) (zero? last-stream-id))
    2
    (+ last-stream-id 2)))

;; =============================================================================
;; Connection FSM handlers — pure fns of [resources data] → data
;; =============================================================================

;; ---------------------------------------------------------------------------
;; ::start — send connection preface + initial SETTINGS
;; ---------------------------------------------------------------------------

(defn on-send-preface
  "Enter ::start.
   Sends the mandatory client preface bytes followed by initial SETTINGS.
   Schedules preface timeout if ITimer available."
  [resources data]
  (let [transport (:transport resources)
        settings  (cond-> {}
                    (some? (:max-concurrent-streams data))
                    (assoc settings-max-concurrent-streams
                           (:max-concurrent-streams data))

                    (some? (:initial-window-size data))
                    (assoc settings-initial-window-size
                           (:initial-window-size data))

                    (some? (:max-frame-size data))
                    (assoc settings-max-frame-size
                           (:max-frame-size data))

                    (some? (:max-header-list-size data))
                    (assoc settings-max-header-list-size
                           (:max-header-list-size data))

                    (some? (:enable-push? data))
                    (assoc settings-enable-push
                           (if (:enable-push? data) 1 0)))]
    (proto/send! transport
                 {:type :preface :bytes connection-preface}
                 {})
    (proto/send! transport
                 (make-frame frame-settings #{} 0 {:settings settings})
                 {})
    (when-let [timer (:timer resources)]
      (proto/schedule! timer
                       (:preface-timeout-ms data default-preface-timeout-ms)
                       (fn [] (assoc data :preface-timeout? true))))
    (assoc data
           :preface-sent?         true
           :local-settings        settings
           :local-settings-sent?  true)))

;; ---------------------------------------------------------------------------
;; ::wait-server-settings — receive peer SETTINGS
;; ---------------------------------------------------------------------------

(defn on-recv-server-settings
  "Handle in ::wait-server-settings.
   Receive peer's SETTINGS frame, capture parameters, send SETTINGS-ACK."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:settings-timeout-ms data
                                                                  default-settings-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :server-settings)
      (let [frame (:data result)]
        (cond
          (not (settings-frame? frame))
          (assoc data
                 :error          :unexpected-frame
                 :error-phase    :server-settings
                 :unexpected     frame)

          (settings-ack? frame)
          ;; Premature SETTINGS-ACK — peer must send its own SETTINGS first
          (assoc data
                 :error       :protocol-error
                 :error-phase :server-settings)

          :else
          (let [settings (or (get-in frame [:payload :settings]) {})]
            ;; ACK their SETTINGS
            (proto/send! transport
                         (make-frame frame-settings #{:ack} 0 {})
                         {})
            (assoc data
                   :remote-settings              settings
                   :server-settings-received?    true
                   :remote-max-concurrent-streams
                   (get settings settings-max-concurrent-streams
                        default-max-concurrent-streams)
                   :remote-initial-window-size
                   (get settings settings-initial-window-size
                        default-initial-window-size)
                   :remote-max-frame-size
                   (get settings settings-max-frame-size
                        default-max-frame-size))))))))

;; ---------------------------------------------------------------------------
;; ::wait-settings-ack — receive ACK of our SETTINGS
;; ---------------------------------------------------------------------------

(defn on-recv-settings-ack
  "Handle in ::wait-settings-ack — wait for peer to ACK our SETTINGS."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:settings-timeout-ms data
                                                              default-settings-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :settings-ack)
      (let [frame (:data result)]
        (cond
          (not (settings-frame? frame))
          ;; Spec allows interleaved frames here; for the FSM we treat
          ;; non-SETTINGS frames as a queued event rather than an error.
          (-> data
              (update :pending-frames (fnil conj []) frame))

          (not (settings-ack? frame))
          (assoc data
                 :error       :protocol-error
                 :error-phase :settings-ack)

          :else
          (assoc data :settings-ack-received? true))))))

;; ---------------------------------------------------------------------------
;; ::connected — connection established, multiplex streams
;; ---------------------------------------------------------------------------

(defn on-enter-connected
  "Enter ::connected.
   Initialise stream registry and connection-level flow-control window."
  [_resources data]
  (assoc data
         :connected?            true
         :streams               {}
         :last-client-stream-id 0
         :last-server-stream-id 0
         :conn-send-window      default-initial-window-size
         :conn-recv-window      default-initial-window-size
         :pending-frames        (or (:pending-frames data) [])))

(defn on-recv-connection-frame
  "Handle in ::connected — receive a frame and dispatch by type.

   Frames are stored in :inbound-frames for the consumer (the
   composed stream FSM) to process.  Connection-level frames
   (SETTINGS, PING, GOAWAY, WINDOW_UPDATE on stream 0) are
   handled here directly."
  [resources data]
  ;; Drain any pending frames captured during settings-ack first
  (if-let [pending (seq (:pending-frames data))]
    (let [frame (first pending)]
      (-> data
          (assoc :pending-frames (vec (rest pending)))
          (update :inbound-frames (fnil conj []) frame)
          (cond-> (goaway-frame? frame)        (assoc :goaway-received? true
                                                       :goaway-frame frame))))
    (let [transport (:transport resources)
          result    (proto/recv! transport
                                 {:timeout-ms (:recv-timeout-ms data
                                                                default-recv-timeout-ms)})]
      (if (:error result)
        (assoc data :error (:error result) :error-phase :connected)
        (let [frame (:data result)]
          (cond
            (goaway-frame? frame)
            (assoc data
                   :goaway-received?       true
                   :goaway-frame           frame
                   :goaway-last-stream-id  (get-in frame [:payload :last-stream-id])
                   :goaway-error-code      (get-in frame [:payload :error-code]))

            (and (ping-frame? frame) (not (flag-set? frame :ack)))
            (do (proto/send! transport
                             (make-frame frame-ping #{:ack} 0 (:payload frame))
                             {})
                (update data :inbound-frames (fnil conj []) frame))

            (and (window-update-frame? frame) (zero? (:stream-id frame)))
            (update data :conn-send-window
                    + (get-in frame [:payload :window-size-increment] 0))

            :else
            (update data :inbound-frames (fnil conj []) frame)))))))

;; ---------------------------------------------------------------------------
;; ::sending-goaway — initiate connection shutdown
;; ---------------------------------------------------------------------------

(defn on-send-goaway
  "Enter ::sending-goaway — send GOAWAY frame announcing shutdown."
  [resources data]
  (let [last-stream (or (:last-server-stream-id data) 0)
        error-code  (or (:goaway-error-code data) err-no-error)
        debug-data  (:goaway-debug data)]
    (proto/send! (:transport resources)
                 (make-frame frame-goaway #{} 0
                             {:last-stream-id last-stream
                              :error-code     error-code
                              :debug-data     debug-data})
                 {})
    (assoc data :goaway-sent? true)))

;; ---------------------------------------------------------------------------
;; ::closed — terminal
;; ---------------------------------------------------------------------------

(defn on-close-connection
  "Enter ::closed — close transport, cancel timers."
  [resources data]
  (proto/close! (:transport resources))
  (when-let [timer (:timer resources)]
    (proto/cancel-all! timer))
  (assoc data :transport-closed? true))

;; =============================================================================
;; Connection dispatch predicates — (fn [_resources data] → boolean)
;; =============================================================================

(defn local-settings-sent?    [_r d] (:local-settings-sent? d))
(defn server-settings-received? [_r d] (:server-settings-received? d))
(defn settings-ack-received?  [_r d] (:settings-ack-received? d))
(defn goaway-received?        [_r d] (:goaway-received? d))
(defn goaway-sent?            [_r d] (:goaway-sent? d))
(defn close-requested?        [_r d] (:close-requested? d))
(defn has-error?              [_r d] (some? (:error d)))
(defn always                  [_r _d] true)

;; =============================================================================
;; Connection FSM spec
;; =============================================================================

(defn http2-connection-fsm-spec
  "Build a pure-data FSM spec for the HTTP/2 connection lifecycle (RFC 7540).

   States:
     ::start                   send preface + local SETTINGS
     ::wait-server-settings    recv peer SETTINGS, send SETTINGS-ACK
     ::wait-settings-ack       recv ACK of our SETTINGS
     ::connected               multiplex streams; handle PING, GOAWAY, WINDOW_UPDATE
     ::sending-goaway          announce shutdown
     ::closed                  terminal — transport closed
     ::error                   terminal — protocol error"
  [_opts]
  {:id      :http/v2-connection
   :initial ::start

   :states
   {;; ─── Connection Setup ───────────────────────────────────────────────

    ::start
    {:enter    on-send-preface
     :dispatch [[::wait-server-settings local-settings-sent?]
                [::error                has-error?]]}

    ::wait-server-settings
    {:handle   on-recv-server-settings
     :dispatch [[::wait-settings-ack    server-settings-received?]
                [::error                has-error?]
                [::wait-server-settings always]]}

    ::wait-settings-ack
    {:handle   on-recv-settings-ack
     :dispatch [[::connected           settings-ack-received?]
                [::error               has-error?]
                [::wait-settings-ack   always]]}

    ;; ─── Active Connection ──────────────────────────────────────────────

    ::connected
    {:enter    on-enter-connected
     :handle   on-recv-connection-frame
     :dispatch [[::sending-goaway close-requested?]
                [::closed         goaway-received?]
                [::error          has-error?]
                [::connected      always]]}

    ;; ─── Connection Teardown ────────────────────────────────────────────

    ::sending-goaway
    {:enter    on-send-goaway
     :dispatch [[::closed always]]}

    ;; ─── Terminal States ────────────────────────────────────────────────

    ::closed
    {:enter on-close-connection}

    ::error
    {:enter on-close-connection}}})

;; =============================================================================
;; Stream FSM — RFC 7540 §5.1
;; =============================================================================

;; A stream represents one HTTP request/response exchange.  It is a
;; sub-FSM composed into the connection's ::connected state.

(defn on-stream-idle-handle
  "Handle in ::stream-idle — wait for application to attach a request
   (client) or for peer to send HEADERS (server)."
  [_resources data]
  data)

(defn on-stream-send-headers
  "Enter ::stream-open after sending HEADERS for an outgoing request."
  [resources data]
  (let [stream-id (:stream-id data)
        end?      (boolean (:end-stream-on-headers? data))
        flags     (cond-> #{:end-headers}
                    end? (conj :end-stream))]
    (proto/send! (:transport resources)
                 (make-frame frame-headers flags stream-id
                             {:headers (:request-headers data)})
                 {})
    (assoc data
           :headers-sent?     true
           :end-stream-sent?  end?)))

(defn on-stream-send-data
  "Send a DATA frame for the stream."
  [resources data]
  (let [stream-id (:stream-id data)
        chunk     (:pending-data data)
        end?      (boolean (:end-stream-on-data? data))
        flags     (if end? #{:end-stream} #{})]
    (proto/send! (:transport resources)
                 (make-frame frame-data flags stream-id
                             {:data chunk})
                 {})
    (cond-> (assoc data :data-sent? true)
      end? (assoc :end-stream-sent? true))))

(defn on-stream-recv-frame
  "Handle inbound stream frame on an open / half-closed stream."
  [_resources data]
  (let [frame (:current-frame data)]
    (cond
      (rst-stream-frame? frame)
      (assoc data
             :rst-received?      true
             :stream-error-code  (get-in frame [:payload :error-code]))

      (headers-frame? frame)
      (cond-> (assoc data :response-headers (get-in frame [:payload :headers]))
        (end-stream? frame) (assoc :end-stream-received? true))

      (data-frame? frame)
      (cond-> (-> data
                  (update :response-data (fnil str "") (str (get-in frame [:payload :data])))
                  (update :recv-window - (count (str (get-in frame [:payload :data])))))
        (end-stream? frame) (assoc :end-stream-received? true))

      :else data)))

(defn on-stream-rst
  "Send RST_STREAM to abort the stream."
  [resources data]
  (let [stream-id  (:stream-id data)
        error-code (or (:abort-error-code data) err-cancel)]
    (proto/send! (:transport resources)
                 (make-frame frame-rst-stream #{} stream-id
                             {:error-code error-code})
                 {})
    (assoc data :rst-sent? true :stream-error-code error-code)))

(defn on-stream-closed
  "Enter ::stream-closed — terminal."
  [_resources data]
  (assoc data :stream-closed? true))

;; Stream dispatch predicates
(defn has-request?           [_r d] (some? (:request-headers d)))
(defn pushed?                [_r d] (some? (:push-promise d)))
(defn headers-sent?          [_r d] (:headers-sent? d))
(defn end-stream-sent?       [_r d] (:end-stream-sent? d))
(defn end-stream-received?   [_r d] (:end-stream-received? d))
(defn rst-received?          [_r d] (:rst-received? d))
(defn rst-sent?              [_r d] (:rst-sent? d))
(defn abort-requested?       [_r d] (:abort-requested? d))
(defn has-pending-data?      [_r d] (some? (:pending-data d)))
(defn fully-closed?          [_r d] (and (:end-stream-sent? d)
                                          (:end-stream-received? d)))

(defn http2-stream-fsm-spec
  "Build a pure-data FSM spec for an HTTP/2 stream (RFC 7540 §5.1).

   States:
     ::stream-idle              no frames exchanged
     ::stream-reserved-local    we sent PUSH_PROMISE
     ::stream-reserved-remote   peer sent PUSH_PROMISE
     ::stream-open              both sides may send DATA / HEADERS
     ::stream-half-closed-local we sent END_STREAM
     ::stream-half-closed-remote peer sent END_STREAM
     ::stream-closed            terminal"
  [_opts]
  {:id      :http/v2-stream
   :initial ::stream-idle

   :states
   {::stream-idle
    {:handle   on-stream-idle-handle
     :dispatch [[::stream-open           has-request?]
                [::stream-reserved-remote pushed?]
                [::stream-idle           always]]}

    ::stream-reserved-local
    {:dispatch [[::stream-half-closed-remote headers-sent?]
                [::stream-closed             rst-sent?]
                [::stream-reserved-local     always]]}

    ::stream-reserved-remote
    {:handle   on-stream-recv-frame
     :dispatch [[::stream-half-closed-local end-stream-received?]
                [::stream-closed            rst-received?]
                [::stream-reserved-remote   always]]}

    ::stream-open
    {:enter    on-stream-send-headers
     :handle   on-stream-recv-frame
     :dispatch [[::stream-closed             rst-received?]
                [::stream-closed             rst-sent?]
                [::stream-half-closed-local  end-stream-sent?]
                [::stream-half-closed-remote end-stream-received?]
                [::stream-open               always]]}

    ::stream-half-closed-local
    {:handle   on-stream-recv-frame
     :dispatch [[::stream-closed             end-stream-received?]
                [::stream-closed             rst-received?]
                [::stream-closed             rst-sent?]
                [::stream-half-closed-local  always]]}

    ::stream-half-closed-remote
    {:handle   on-stream-send-data
     :dispatch [[::stream-closed             end-stream-sent?]
                [::stream-closed             rst-received?]
                [::stream-closed             rst-sent?]
                [::stream-half-closed-remote always]]}

    ::stream-closed
    {:enter on-stream-closed}}})

;; =============================================================================
;; IProtocolFSM implementation
;; =============================================================================

(defn make-http2-stream-fsm
  "Create an HTTP/2 stream sub-FSM."
  ([] (make-http2-stream-fsm {}))
  ([opts]
   (let [spec     (http2-stream-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))]
     (reify proto/IProtocolFSM
       (protocol-id [_] :http/v2-stream)
       (fsm-spec [_] spec)
       (compiled [_] @compiled)
       (initial-data [_ session-opts]
         (merge {:stream-id            (or (:stream-id session-opts) 1)
                 :send-window          default-initial-window-size
                 :recv-window          default-initial-window-size
                 :end-stream-sent?     false
                 :end-stream-received? false
                 :stream-closed?       false}
                opts session-opts))
       (terminal-states [_]
         #{::stream-closed})
       (composable-states [_] {})))))

(defn make-http2-fsm
  "Create an HTTP/2 connection protocol FSM.

   opts (all optional):
     :max-concurrent-streams — local advertised limit
     :initial-window-size    — initial flow-control window         (default 65535)
     :max-frame-size         — max frame payload size               (default 16384)
     :max-header-list-size   — max header list size
     :enable-push?           — accept server push                   (default true)
     :preface-timeout-ms     — preface + initial settings deadline  (default 5000)
     :settings-timeout-ms    — settings-ack deadline                (default 5000)
     :recv-timeout-ms        — per-frame recv timeout               (default 30000)

   Returns: IProtocolFSM implementation.

   Stream FSMs are exposed via composable-states; orchestrator
   composes one stream FSM per concurrent request.

   Usage:
     (def http2 (make-http2-fsm {:enable-push? false}))

     (proto/run-session http2
       (proto/make-resources my-transport my-timer)
       {})"
  ([] (make-http2-fsm {}))
  ([opts]
   (let [spec     (http2-connection-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))
         defaults {:initial-window-size  default-initial-window-size
                   :max-frame-size       default-max-frame-size
                   :enable-push?         true
                   :preface-timeout-ms   default-preface-timeout-ms
                   :settings-timeout-ms  default-settings-timeout-ms
                   :recv-timeout-ms      default-recv-timeout-ms}]
     (reify proto/IProtocolFSM
       (protocol-id [_] :http/v2)

       (fsm-spec [_] spec)

       (compiled [_] @compiled)

       (initial-data [_ session-opts]
         (merge defaults opts session-opts
                {:streams                {}
                 :last-client-stream-id  0
                 :last-server-stream-id  0
                 :conn-send-window       default-initial-window-size
                 :conn-recv-window       default-initial-window-size
                 :inbound-frames         []
                 :pending-frames         []
                 :connected?             false
                 :goaway-sent?           false
                 :goaway-received?       false}))

       (terminal-states [_]
         #{::closed ::error})

       (composable-states [_]
         ;; ::connected hosts one or more stream sub-FSMs
         {::connected (make-http2-stream-fsm opts)})))))
