(ns hive.events.protocols.http3
  "RFC 9114 HTTP/3 + RFC 9000 QUIC connection FSMs.

   HTTP/3 is layered:

     QUIC      (RFC 9000)  — secure, multiplexed transport over UDP
     HTTP/3    (RFC 9114)  — request/response semantics over QUIC streams
     QPACK     (RFC 9204)  — header compression  (delegated to :qpack resource)

   This namespace models two cooperating finite state machines:

     1. **QUIC Connection FSM** — handshake → established → draining → closed
     2. **HTTP/3 Stream FSM**   — request streams over QUIC bidirectional streams,
                                   plus dedicated control / encoder / decoder streams.

   Status: BLOCKER — concrete QUIC frame primitives (CRYPTO, STREAM, ACK,
   PATH_CHALLENGE, NEW_CONNECTION_ID, etc.) are not yet implemented in
   the hive transport layer.  This FSM is therefore pure-data spec only;
   wire-level QUIC encoding/decoding is delegated to a :quic resource
   map containing pluggable functions that the orchestrator must
   provide.  The TLS 1.3 handshake (per RFC 9001) is delegated to the
   existing hive.events.protocols.tls FSM as a sub-FSM.

   Factory:
     (make-http3-fsm opts)
       opts — {:max-streams-bidi      Long
               :max-streams-uni       Long
               :initial-max-data      Long       ;; bytes
               :idle-timeout-ms       Long
               :handshake-timeout-ms  Long
               :recv-timeout-ms       Long
               :enable-0rtt?          bool}

   Resources expected at run time:
     :transport — ITransport for sending/receiving QUIC packets
     :timer     — ITimer (optional) for handshake/idle timeouts
     :tls       — TLS 1.3 sub-FSM (from hive.events.protocols.tls)
     :quic      — map of pluggable QUIC frame fns (all optional in tests):
       :encode-frame  (fn [frame-map] -> bytes)
       :decode-frame  (fn [bytes]     -> frame-map)
       :new-connection-id (fn [] -> connection-id-bytes)
       :pn-encode     (fn [pn] -> bytes)
       :pn-decode     (fn [bytes] -> pn)

   References:
     RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport
     RFC 9001 — Using TLS to Secure QUIC
     RFC 9114 — HTTP/3
     RFC 9204 — QPACK (Header Compression for HTTP/3)"
  (:require [hive.events.protocols.core :as proto]))

;; =============================================================================
;; Constants — RFC 9000 (QUIC) and RFC 9114 (HTTP/3)
;; =============================================================================

;; QUIC packet types — RFC 9000 §17
(def ^:const pkt-initial    0x0)
(def ^:const pkt-zero-rtt   0x1)
(def ^:const pkt-handshake  0x2)
(def ^:const pkt-retry      0x3)
(def ^:const pkt-version-neg 0xFF)
(def ^:const pkt-1rtt       0x4)  ;; short-header

;; QUIC frame types — RFC 9000 §19
(def ^:const frame-padding             0x00)
(def ^:const frame-ping                0x01)
(def ^:const frame-ack                 0x02)
(def ^:const frame-reset-stream        0x04)
(def ^:const frame-stop-sending        0x05)
(def ^:const frame-crypto              0x06)
(def ^:const frame-new-token           0x07)
(def ^:const frame-stream              0x08)  ;; 0x08..0x0F variants
(def ^:const frame-max-data            0x10)
(def ^:const frame-max-stream-data     0x11)
(def ^:const frame-max-streams-bidi    0x12)
(def ^:const frame-max-streams-uni     0x13)
(def ^:const frame-data-blocked        0x14)
(def ^:const frame-stream-data-blocked 0x15)
(def ^:const frame-streams-blocked-bidi 0x16)
(def ^:const frame-streams-blocked-uni  0x17)
(def ^:const frame-new-connection-id   0x18)
(def ^:const frame-retire-connection-id 0x19)
(def ^:const frame-path-challenge      0x1A)
(def ^:const frame-path-response       0x1B)
(def ^:const frame-connection-close    0x1C)  ;; 0x1C / 0x1D
(def ^:const frame-handshake-done      0x1E)

;; QUIC transport error codes — RFC 9000 §20
(def ^:const err-no-error              0x0)
(def ^:const err-internal-error        0x1)
(def ^:const err-connection-refused    0x2)
(def ^:const err-flow-control-error    0x3)
(def ^:const err-stream-limit-error    0x4)
(def ^:const err-stream-state-error    0x5)
(def ^:const err-final-size-error      0x6)
(def ^:const err-frame-encoding-error  0x7)
(def ^:const err-transport-parameter-error 0x8)
(def ^:const err-protocol-violation    0xA)
(def ^:const err-application-error     0xC)

;; HTTP/3 frame types — RFC 9114 §7.2
(def ^:const h3-frame-data           0x0)
(def ^:const h3-frame-headers        0x1)
(def ^:const h3-frame-cancel-push    0x3)
(def ^:const h3-frame-settings       0x4)
(def ^:const h3-frame-push-promise   0x5)
(def ^:const h3-frame-goaway         0x7)
(def ^:const h3-frame-max-push-id    0xD)

;; HTTP/3 settings — RFC 9114 §7.2.4.1
(def ^:const h3-settings-qpack-max-table-capacity 0x1)
(def ^:const h3-settings-max-field-section-size   0x6)
(def ^:const h3-settings-qpack-blocked-streams    0x7)

;; HTTP/3 application error codes — RFC 9114 §8.1
(def ^:const h3-err-no-error                0x100)
(def ^:const h3-err-general-protocol-error  0x101)
(def ^:const h3-err-internal-error          0x102)
(def ^:const h3-err-stream-creation-error   0x103)
(def ^:const h3-err-closed-critical-stream  0x104)
(def ^:const h3-err-frame-unexpected        0x105)
(def ^:const h3-err-frame-error             0x106)
(def ^:const h3-err-excessive-load          0x107)
(def ^:const h3-err-id-error                0x108)
(def ^:const h3-err-settings-error          0x109)
(def ^:const h3-err-missing-settings        0x10A)
(def ^:const h3-err-request-rejected        0x10B)
(def ^:const h3-err-request-cancelled       0x10C)
(def ^:const h3-err-request-incomplete      0x10D)
(def ^:const h3-err-message-error           0x10E)
(def ^:const h3-err-connect-error           0x10F)
(def ^:const h3-err-version-fallback        0x110)

;; Stream type prefixes — RFC 9114 §6.2
(def ^:const stream-type-control        0x00)
(def ^:const stream-type-push           0x01)
(def ^:const stream-type-qpack-encoder  0x02)
(def ^:const stream-type-qpack-decoder  0x03)

;; Defaults
(def ^:const default-handshake-timeout-ms 10000)
(def ^:const default-idle-timeout-ms      30000)
(def ^:const default-recv-timeout-ms      30000)
(def ^:const default-initial-max-data     1048576)
(def ^:const default-max-streams-bidi     100)
(def ^:const default-max-streams-uni      100)

;; =============================================================================
;; Frame helpers
;; =============================================================================

(defn make-quic-packet
  "Build a generic QUIC packet map.

   pkt-type   — numeric packet type
   conn-id    — destination connection id bytes
   pn         — packet number (long)
   frames     — vector of frame maps"
  [pkt-type conn-id pn frames]
  {:packet-type     pkt-type
   :connection-id   conn-id
   :packet-number   pn
   :frames          (vec frames)})

(defn make-quic-frame
  "Build a generic QUIC frame map."
  [type payload]
  {:frame-type type
   :payload    payload})

(defn make-h3-frame
  "Build an HTTP/3 frame map."
  [type payload]
  {:h3-frame-type type
   :payload       payload})

(defn quic-frame-of-type?
  "Check whether a QUIC frame is of the given type."
  [frame type]
  (= type (:frame-type frame)))

(defn h3-frame-of-type?
  [frame type]
  (= type (:h3-frame-type frame)))

(defn h3-stream-id-bidi?
  "True for client-initiated bidirectional QUIC stream id (lowest 2 bits = 00)."
  [stream-id]
  (zero? (bit-and stream-id 0x3)))

(defn h3-stream-id-server-bidi?
  "True for server-initiated bidirectional QUIC stream id (lowest 2 bits = 01)."
  [stream-id]
  (= 0x1 (bit-and stream-id 0x3)))

(defn h3-stream-id-client-uni?
  "True for client-initiated unidirectional stream id (lowest 2 bits = 10)."
  [stream-id]
  (= 0x2 (bit-and stream-id 0x3)))

(defn h3-stream-id-server-uni?
  "True for server-initiated unidirectional stream id (lowest 2 bits = 11)."
  [stream-id]
  (= 0x3 (bit-and stream-id 0x3)))

;; =============================================================================
;; QUIC connection FSM handlers
;; =============================================================================

;; ---------------------------------------------------------------------------
;; ::quic-start — emit Initial packet (TLS ClientHello in CRYPTO frame)
;; ---------------------------------------------------------------------------

(defn on-quic-send-initial
  "Enter ::quic-start.
   Build Initial packet carrying TLS 1.3 ClientHello in a CRYPTO frame.
   Schedules handshake timeout via ITimer if available."
  [resources data]
  (let [transport  (:transport resources)
        encode     (get-in resources [:quic :encode-frame])
        new-id     (get-in resources [:quic :new-connection-id])
        scid       (cond
                     (:scid data)        (:scid data)
                     new-id              (new-id)
                     :else               [0])
        dcid       (or (:dcid data)
                       (when new-id (new-id))
                       [1])
        ;; The TLS sub-FSM produces ClientHello bytes; we wrap in CRYPTO
        ch-bytes   (or (:client-hello-bytes data) [])
        crypto-frame (make-quic-frame frame-crypto
                                       {:offset 0 :data ch-bytes})
        packet     (make-quic-packet pkt-initial dcid 0 [crypto-frame])
        wire       (if encode (encode packet) packet)]
    (proto/send! transport wire {})
    (when-let [timer (:timer resources)]
      (proto/schedule! timer
                       (:handshake-timeout-ms data default-handshake-timeout-ms)
                       (fn [] (assoc data :handshake-timeout? true))))
    (assoc data
           :scid                   scid
           :dcid                   dcid
           :initial-sent?          true
           :next-pn                1
           :largest-acked-pn       -1
           :handshake-progress     :initial-sent)))

;; ---------------------------------------------------------------------------
;; ::quic-handshake — drive TLS 1.3 sub-FSM via CRYPTO frames
;; ---------------------------------------------------------------------------

(defn on-quic-handshake-recv
  "Handle in ::quic-handshake.
   Receive Initial / Handshake packets, feed CRYPTO bytes into TLS,
   and capture handshake completion via :tls-complete? flag."
  [resources data]
  (let [transport (:transport resources)
        decode    (get-in resources [:quic :decode-frame])
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data
                                                              default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :handshake)
      (let [packet (cond-> (:data result) decode decode)
            frames (or (:frames packet) [])
            crypto (filter #(quic-frame-of-type? % frame-crypto) frames)
            crypto-bytes (mapcat #(get-in % [:payload :data]) crypto)
            tls-state (:tls-state data)
            tls-progress (cond-> tls-state
                           (seq crypto-bytes)
                           (update :crypto-buffer (fnil into []) crypto-bytes))]
        ;; We don't actually drive the TLS FSM here — the orchestrator
        ;; does that via the composed sub-FSM.  We just track whether
        ;; the TLS sub-FSM has reported completion.
        (cond
          (:handshake-done? data)
          (assoc data :tls-complete? true :handshake-complete? true)

          (some #(quic-frame-of-type? % frame-handshake-done) frames)
          (assoc data
                 :handshake-done?      true
                 :tls-complete?        true
                 :handshake-complete?  true
                 :tls-state            tls-progress)

          :else
          (assoc data :tls-state tls-progress))))))

;; ---------------------------------------------------------------------------
;; ::quic-established — connection ready, host HTTP/3 streams
;; ---------------------------------------------------------------------------

(defn on-quic-established-enter
  "Enter ::quic-established.
   Initialise stream registry, flow-control windows, and open the
   mandatory HTTP/3 control / qpack-encoder / qpack-decoder streams."
  [_resources data]
  (assoc data
         :connected?             true
         :streams                {}
         :next-stream-id-bidi    0
         :next-stream-id-uni     2
         :conn-send-window       (:initial-max-data data default-initial-max-data)
         :conn-recv-window       (:initial-max-data data default-initial-max-data)
         :control-stream-id      nil
         :qpack-encoder-stream-id nil
         :qpack-decoder-stream-id nil))

(defn on-quic-established-recv
  "Handle in ::quic-established.
   Drain inbound packets; surface frames to composed HTTP/3 stream FSMs;
   handle connection-level frames (ACK, MAX_DATA, NEW_CONNECTION_ID, etc.)."
  [resources data]
  (let [transport (:transport resources)
        decode    (get-in resources [:quic :decode-frame])
        result    (proto/recv! transport
                               {:timeout-ms (:recv-timeout-ms data
                                                              default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :established)
      (let [packet (cond-> (:data result) decode decode)
            frames (or (:frames packet) [])
            close-frame (some #(when (quic-frame-of-type? % frame-connection-close) %)
                              frames)]
        (cond
          close-frame
          (assoc data
                 :close-received?   true
                 :close-error-code  (get-in close-frame [:payload :error-code])
                 :close-reason      (get-in close-frame [:payload :reason]))

          :else
          (-> data
              (update :inbound-frames (fnil into []) frames)
              ;; Update flow-control window from MAX_DATA
              (cond->
                  (some #(quic-frame-of-type? % frame-max-data) frames)
                (update :conn-send-window
                        +
                        (->> frames
                             (filter #(quic-frame-of-type? % frame-max-data))
                             (map #(get-in % [:payload :max-data]))
                             (apply +))))))))))

;; ---------------------------------------------------------------------------
;; ::quic-draining — graceful shutdown
;; ---------------------------------------------------------------------------

(defn on-quic-send-close
  "Enter ::quic-draining — send CONNECTION_CLOSE."
  [resources data]
  (let [transport  (:transport resources)
        encode     (get-in resources [:quic :encode-frame])
        error-code (or (:close-error-code data) err-no-error)
        reason     (or (:close-reason data) "")
        cc-frame   (make-quic-frame frame-connection-close
                                     {:error-code error-code
                                      :reason     reason})
        packet     (make-quic-packet pkt-1rtt
                                     (:dcid data)
                                     (or (:next-pn data) 0)
                                     [cc-frame])
        wire       (if encode (encode packet) packet)]
    (proto/send! transport wire {})
    (assoc data :close-sent? true)))

;; ---------------------------------------------------------------------------
;; ::quic-closed — terminal
;; ---------------------------------------------------------------------------

(defn on-quic-closed-enter
  "Enter ::quic-closed — close transport, cancel timers."
  [resources data]
  (proto/close! (:transport resources))
  (when-let [timer (:timer resources)]
    (proto/cancel-all! timer))
  (assoc data :transport-closed? true))

;; =============================================================================
;; QUIC connection dispatch predicates
;; =============================================================================

(defn initial-sent?         [_r d] (:initial-sent? d))
(defn handshake-complete?   [_r d] (:handshake-complete? d))
(defn close-received?       [_r d] (:close-received? d))
(defn close-sent?           [_r d] (:close-sent? d))
(defn close-requested?      [_r d] (:close-requested? d))
(defn handshake-timeout?    [_r d] (:handshake-timeout? d))
(defn has-error?            [_r d] (some? (:error d)))
(defn always                [_r _d] true)

;; =============================================================================
;; QUIC connection FSM spec
;; =============================================================================

(defn quic-connection-fsm-spec
  "Build a pure-data FSM spec for the QUIC connection lifecycle (RFC 9000).

   States:
     ::quic-start         emit Initial packet with TLS ClientHello
     ::quic-handshake     drive TLS 1.3 via CRYPTO frames
     ::quic-established   normal data exchange; host HTTP/3 streams
     ::quic-draining      sent CONNECTION_CLOSE, awaiting drain
     ::quic-closed        terminal
     ::quic-error         terminal (transport / handshake error)"
  [_opts]
  {:id      :quic-connection
   :initial ::quic-start

   :states
   {::quic-start
    {:enter    on-quic-send-initial
     :dispatch [[::quic-handshake initial-sent?]
                [::quic-error     has-error?]]}

    ::quic-handshake
    {:handle   on-quic-handshake-recv
     :dispatch [[::quic-established handshake-complete?]
                [::quic-error       handshake-timeout?]
                [::quic-error       has-error?]
                [::quic-handshake   always]]}

    ::quic-established
    {:enter    on-quic-established-enter
     :handle   on-quic-established-recv
     :dispatch [[::quic-draining   close-requested?]
                [::quic-closed     close-received?]
                [::quic-error      has-error?]
                [::quic-established always]]}

    ::quic-draining
    {:enter    on-quic-send-close
     :dispatch [[::quic-closed always]]}

    ::quic-closed
    {:enter on-quic-closed-enter}

    ::quic-error
    {:enter on-quic-closed-enter}}})

;; =============================================================================
;; HTTP/3 stream FSM — RFC 9114 §6
;; =============================================================================

;; ---------------------------------------------------------------------------
;; HTTP/3 stream handlers
;; ---------------------------------------------------------------------------

(defn on-h3-send-headers
  "Enter ::h3-stream-open after sending HEADERS frame on a request stream."
  [resources data]
  (let [encode    (get-in resources [:qpack :encode] identity)
        headers   (:request-headers data)
        encoded   (encode headers)
        end?      (boolean (:end-stream-on-headers? data))
        h3-frame  (make-h3-frame h3-frame-headers {:headers encoded})]
    (proto/send! (:transport resources)
                 {:stream-id (:stream-id data)
                  :h3-frame  h3-frame
                  :end?      end?}
                 {})
    (cond-> (assoc data :headers-sent? true)
      end? (assoc :end-stream-sent? true))))

(defn on-h3-send-data
  "Send an HTTP/3 DATA frame on the request stream."
  [resources data]
  (let [chunk    (:pending-data data)
        end?     (boolean (:end-stream-on-data? data))
        h3-frame (make-h3-frame h3-frame-data {:data chunk})]
    (proto/send! (:transport resources)
                 {:stream-id (:stream-id data)
                  :h3-frame  h3-frame
                  :end?      end?}
                 {})
    (cond-> (assoc data :data-sent? true)
      end? (assoc :end-stream-sent? true))))

(defn on-h3-recv-frame
  "Handle inbound HTTP/3 frame on the request stream."
  [resources data]
  (let [decode (get-in resources [:qpack :decode] identity)
        frame  (:current-frame data)
        end?   (boolean (:end? frame))]
    (cond
      (h3-frame-of-type? frame h3-frame-headers)
      (cond-> (assoc data :response-headers (decode (get-in frame [:payload :headers])))
        end? (assoc :end-stream-received? true))

      (h3-frame-of-type? frame h3-frame-data)
      (cond-> (update data :response-data
                      (fnil str "")
                      (str (get-in frame [:payload :data])))
        end? (assoc :end-stream-received? true))

      (h3-frame-of-type? frame h3-frame-goaway)
      (assoc data :goaway-received? true
                  :goaway-stream-id (get-in frame [:payload :stream-id]))

      :else
      data)))

(defn on-h3-cancel
  "Send STOP_SENDING + RESET_STREAM (modelled as :cancel event) to abort
   the stream."
  [resources data]
  (let [code (or (:abort-error-code data) h3-err-request-cancelled)]
    (proto/send! (:transport resources)
                 {:stream-id (:stream-id data)
                  :cancel?   true
                  :error-code code}
                 {})
    (assoc data :cancel-sent? true :stream-error-code code)))

(defn on-h3-stream-closed
  "Enter ::h3-stream-closed — terminal."
  [_resources data]
  (assoc data :stream-closed? true))

;; HTTP/3 stream dispatch predicates
(defn h3-has-request?         [_r d] (some? (:request-headers d)))
(defn h3-headers-sent?        [_r d] (:headers-sent? d))
(defn h3-end-stream-sent?     [_r d] (:end-stream-sent? d))
(defn h3-end-stream-received? [_r d] (:end-stream-received? d))
(defn h3-cancel-sent?         [_r d] (:cancel-sent? d))
(defn h3-cancel-received?     [_r d] (:cancel-received? d))
(defn h3-fully-closed?        [_r d] (and (:end-stream-sent? d)
                                           (:end-stream-received? d)))

(defn http3-stream-fsm-spec
  "Build a pure-data FSM spec for an HTTP/3 request stream (RFC 9114 §6).

   The HTTP/3 stream lifecycle is layered on QUIC bidirectional streams.
   States:
     ::h3-stream-idle           no frames exchanged
     ::h3-stream-open           HEADERS sent, normal data exchange
     ::h3-stream-half-closed-local  we sent END_STREAM
     ::h3-stream-half-closed-remote peer sent END_STREAM
     ::h3-stream-closed         terminal"
  [_opts]
  {:id      :http/v3-stream
   :initial ::h3-stream-idle

   :states
   {::h3-stream-idle
    {:dispatch [[::h3-stream-open  h3-has-request?]
                [::h3-stream-idle  always]]}

    ::h3-stream-open
    {:enter    on-h3-send-headers
     :handle   on-h3-recv-frame
     :dispatch [[::h3-stream-closed             h3-cancel-received?]
                [::h3-stream-closed             h3-cancel-sent?]
                [::h3-stream-half-closed-local  h3-end-stream-sent?]
                [::h3-stream-half-closed-remote h3-end-stream-received?]
                [::h3-stream-open               always]]}

    ::h3-stream-half-closed-local
    {:handle   on-h3-recv-frame
     :dispatch [[::h3-stream-closed             h3-end-stream-received?]
                [::h3-stream-closed             h3-cancel-received?]
                [::h3-stream-closed             h3-cancel-sent?]
                [::h3-stream-half-closed-local  always]]}

    ::h3-stream-half-closed-remote
    {:handle   on-h3-send-data
     :dispatch [[::h3-stream-closed             h3-end-stream-sent?]
                [::h3-stream-closed             h3-cancel-received?]
                [::h3-stream-closed             h3-cancel-sent?]
                [::h3-stream-half-closed-remote always]]}

    ::h3-stream-closed
    {:enter on-h3-stream-closed}}})

;; =============================================================================
;; IProtocolFSM implementations
;; =============================================================================

(defn make-http3-stream-fsm
  "Create an HTTP/3 stream sub-FSM."
  ([] (make-http3-stream-fsm {}))
  ([opts]
   (let [spec     (http3-stream-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))]
     (reify proto/IProtocolFSM
       (protocol-id [_] :http/v3-stream)
       (fsm-spec [_] spec)
       (compiled [_] @compiled)
       (initial-data [_ session-opts]
         (merge {:stream-id            (or (:stream-id session-opts) 0)
                 :end-stream-sent?     false
                 :end-stream-received? false
                 :stream-closed?       false}
                opts session-opts))
       (terminal-states [_]
         #{::h3-stream-closed})
       (composable-states [_] {})))))

(defn make-http3-fsm
  "Create an HTTP/3 / QUIC connection protocol FSM.

   opts (all optional):
     :max-streams-bidi      — local advertised limit               (default 100)
     :max-streams-uni       — local advertised limit               (default 100)
     :initial-max-data      — connection-level send window         (default 1 MiB)
     :idle-timeout-ms       — QUIC idle timeout                    (default 30 000)
     :handshake-timeout-ms  — QUIC handshake timeout               (default 10 000)
     :recv-timeout-ms       — per-packet recv timeout              (default 30 000)
     :enable-0rtt?          — accept 0-RTT data                    (default false)

   Returns: IProtocolFSM implementation.

   The TLS 1.3 handshake is delegated to the existing
   hive.events.protocols.tls FSM, which is composed into the
   ::quic-handshake state.

   BLOCKER: wire-level QUIC frame encoding/decoding must be supplied
   by the orchestrator via the :quic resource map.  Without it, the
   FSM works against pre-decoded frame maps (suitable for unit and
   property testing)."
  ([] (make-http3-fsm {}))
  ([opts]
   (let [spec     (quic-connection-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))
         defaults {:max-streams-bidi      default-max-streams-bidi
                   :max-streams-uni       default-max-streams-uni
                   :initial-max-data      default-initial-max-data
                   :idle-timeout-ms       default-idle-timeout-ms
                   :handshake-timeout-ms  default-handshake-timeout-ms
                   :recv-timeout-ms       default-recv-timeout-ms
                   :enable-0rtt?          false}]
     (reify proto/IProtocolFSM
       (protocol-id [_] :http/v3)

       (fsm-spec [_] spec)

       (compiled [_] @compiled)

       (initial-data [_ session-opts]
         (merge defaults opts session-opts
                {:scid                    nil
                 :dcid                    nil
                 :next-pn                 0
                 :largest-acked-pn        -1
                 :streams                 {}
                 :inbound-frames          []
                 :connected?              false
                 :handshake-complete?     false
                 :close-received?         false
                 :close-sent?             false}))

       (terminal-states [_]
         #{::quic-closed ::quic-error})

       (composable-states [_]
         ;; ::quic-handshake hosts the TLS 1.3 sub-FSM.
         ;; ::quic-established hosts one or more HTTP/3 stream sub-FSMs.
         {::quic-handshake   :tls-1.3
          ::quic-established (make-http3-stream-fsm opts)})))))
