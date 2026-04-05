(ns hive.events.protocols.tcp
  "RFC 793 TCP Connection Lifecycle FSM.

   States: closed → listen / syn-sent → syn-received → established
          → fin-wait-1 / close-wait → fin-wait-2 / last-ack / closing
          → time-wait → closed

   The FSM is pure data — all I/O happens through ITransport/ITimer
   resources injected at run time.  Segment flag handling, sequence
   number tracking, and the three-way / four-way handshakes are
   modelled as state-machine transitions.

   Factory:
     (make-tcp-fsm opts)
       opts — {:msl-ms              120000  ;; Maximum Segment Lifetime (RFC 793)
               :connect-timeout-ms  30000   ;; SYN timeout
               :recv-timeout-ms     30000   ;; general receive timeout
               :initial-window      65535}  ;; advertised window size"
  (:require [hive.events.protocols.core :as proto]))

;; =============================================================================
;; Constants — RFC 793 §3.1
;; =============================================================================

(def ^:const default-msl-ms
  "Maximum Segment Lifetime — default 2 minutes per RFC 793 §3.3."
  120000)

(def ^:const default-connect-timeout-ms
  "Timeout for connection establishment (SYN → SYN+ACK)."
  30000)

(def ^:const default-recv-timeout-ms
  "Default receive timeout per segment."
  30000)

(def ^:const default-window
  "Default advertised receive window."
  65535)

;; =============================================================================
;; Segment helpers
;; =============================================================================

(defn make-segment
  "Build a TCP segment map.

   flags   — set of keywords #{:syn :ack :fin :rst :psh :urg}
   seq-num — sender sequence number
   ack-num — acknowledgment number
   keyword opts:
     :payload — data bytes (vector or byte-array)
     :window  — advertised window (default 65535)"
  [flags seq-num ack-num & {:keys [payload window] :or {window default-window}}]
  (cond-> {:flags   (if (set? flags) flags (set flags))
           :seq-num seq-num
           :ack-num ack-num
           :window  window}
    payload (assoc :payload payload)))

(defn has-flag?
  "Check whether a segment carries a specific flag keyword."
  [segment flag]
  (contains? (:flags segment) flag))

(defn syn?     [seg] (has-flag? seg :syn))
(defn ack?     [seg] (has-flag? seg :ack))
(defn fin?     [seg] (has-flag? seg :fin))
(defn rst?     [seg] (has-flag? seg :rst))
(defn syn-ack? [seg] (and (syn? seg) (ack? seg)))
(defn fin-ack? [seg] (and (fin? seg) (ack? seg)))

;; =============================================================================
;; FSM handlers — pure fns of [resources data] → data
;; =============================================================================

;; ---------------------------------------------------------------------------
;; ::closed  (initial + terminal)
;; ---------------------------------------------------------------------------

(defn on-close-cleanup
  "Enter handler for ::closed.
   Initial entry: :open-mode is present → no-op.
   Terminal re-entry: :open-mode was consumed → close transport, cancel timers."
  [resources data]
  (if-not (:open-mode data)
    ;; Re-entry — cleanup
    (do
      (proto/close! (:transport resources))
      (when-let [timer (:timer resources)]
        (proto/cancel-all! timer))
      (assoc data :connection-closed? true :transport-closed? true))
    ;; Initial entry — nothing to clean up
    data))

(defn on-open-connection
  "Handle in ::closed — inspect :open-mode, prepare sequence numbers."
  [_resources data]
  (case (:open-mode data)
    :active  (assoc data :local-seq (or (:initial-seq-num data) (rand-int 100000)))
    :passive data
    ;; nil / terminal — no-op
    data))

;; ---------------------------------------------------------------------------
;; ::listen
;; ---------------------------------------------------------------------------

(defn on-enter-listen
  "Enter ::listen — consume :open-mode, mark listening."
  [_resources data]
  (-> data
      (assoc :listening? true)
      (dissoc :open-mode)))

(defn on-listen-recv
  "Handle in ::listen — wait for SYN from a remote peer.
   RST is silently ignored per RFC 793 §3.9.  Unexpected ACK → error."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :listen)
      (let [segment (:data result)]
        (cond
          (rst? segment) data                           ;; ignore RST in LISTEN

          (ack? segment)                                ;; unexpected ACK
          (assoc data :error :unexpected-ack :error-phase :listen)

          (syn? segment)                                ;; incoming connection
          (assoc data
                 :syn-received?  true
                 :remote-seq     (:seq-num segment)
                 :remote-window  (:window segment default-window)
                 :local-seq      (or (:local-seq data) (rand-int 100000)))

          :else data)))))

;; ---------------------------------------------------------------------------
;; ::syn-sent
;; ---------------------------------------------------------------------------

(defn on-send-syn
  "Enter ::syn-sent — send SYN, consume :open-mode, optionally schedule
   connect timeout via ITimer."
  [resources data]
  (let [transport (:transport resources)
        seq-num   (:local-seq data)]
    (proto/send! transport
                 (make-segment #{:syn} seq-num 0)
                 {})
    (when-let [timer (:timer resources)]
      (proto/schedule! timer
                       (:connect-timeout-ms data default-connect-timeout-ms)
                       (fn [] (assoc data :connect-timeout? true))))
    (-> data
        (assoc :syn-sent? true)
        (dissoc :open-mode))))

(defn on-syn-sent-recv
  "Handle in ::syn-sent — expect SYN+ACK (normal) or bare SYN (simultaneous open).
   RST → error."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport
                               {:timeout-ms (:connect-timeout-ms data default-connect-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :syn-sent)
      (let [segment (:data result)]
        (cond
          (rst? segment)
          (assoc data :rst-received? true :error :connection-reset :error-phase :syn-sent)

          (syn-ack? segment)
          (do ;; Complete three-way handshake — send ACK
            (proto/send! transport
                         (make-segment #{:ack}
                                       (inc (:local-seq data))
                                       (inc (:seq-num segment)))
                         {})
            (assoc data
                   :syn-ack-received? true
                   :remote-seq        (inc (:seq-num segment))
                   :remote-window     (:window segment default-window)
                   :local-seq         (inc (:local-seq data))))

          (syn? segment)
          ;; Simultaneous open — peer also sent SYN (no ACK)
          (assoc data
                 :syn-received? true
                 :remote-seq    (:seq-num segment)
                 :remote-window (:window segment default-window))

          :else data)))))

;; ---------------------------------------------------------------------------
;; ::syn-received
;; ---------------------------------------------------------------------------

(defn on-send-syn-ack
  "Enter ::syn-received — send SYN+ACK."
  [resources data]
  (let [transport (:transport resources)
        seq-num   (:local-seq data)
        ack-num   (inc (:remote-seq data))]
    (proto/send! transport
                 (make-segment #{:syn :ack} seq-num ack-num)
                 {})
    (assoc data :syn-ack-sent? true :local-ack ack-num)))

(defn on-syn-received-recv
  "Handle in ::syn-received — wait for ACK completing the handshake.
   RST → error."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:connect-timeout-ms data default-connect-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :syn-received)
      (let [segment (:data result)]
        (cond
          (rst? segment)
          (assoc data :rst-received? true :error :connection-reset :error-phase :syn-received)

          (ack? segment)
          (assoc data :ack-received? true)

          :else data)))))

;; ---------------------------------------------------------------------------
;; ::established
;; ---------------------------------------------------------------------------

(defn on-enter-established
  "Enter ::established — mark connection ready, initialise receive buffer."
  [_resources data]
  (assoc data
         :connection-established? true
         :segments-received       []))

(defn on-established-recv
  "Handle in ::established — process data segments, detect FIN / RST.
   If :close-requested? is already set the handler returns immediately
   so the dispatch can transition to ::fin-wait-1."
  [resources data]
  (if (:close-requested? data)
    data
    (let [transport (:transport resources)
          result    (proto/recv! transport
                                {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
      (if (:error result)
        (assoc data :error (:error result) :error-phase :established)
        (let [segment (:data result)]
          (cond
            (rst? segment)
            (assoc data :rst-received? true :error :connection-reset :error-phase :established)

            (fin? segment)
            (do ;; ACK the peer's FIN
              (proto/send! transport
                           (make-segment #{:ack}
                                         (:local-seq data)
                                         (inc (:seq-num segment)))
                           {})
              (assoc data
                     :fin-received? true
                     :remote-seq    (inc (:seq-num segment))))

            :else
            (let [payload-len (count (or (:payload segment) []))
                  new-ack     (+ (:seq-num segment) (max 1 payload-len))]
              ;; ACK data segments
              (when (pos? payload-len)
                (proto/send! transport
                             (make-segment #{:ack}
                                           (:local-seq data)
                                           new-ack)
                             {}))
              (-> data
                  (update :segments-received conj segment)
                  (assoc :remote-seq new-ack)))))))))

;; ---------------------------------------------------------------------------
;; ::fin-wait-1
;; ---------------------------------------------------------------------------

(defn on-send-fin
  "Enter ::fin-wait-1 — send FIN+ACK to initiate active close."
  [resources data]
  (proto/send! (:transport resources)
               (make-segment #{:fin :ack}
                             (:local-seq data)
                             (or (:remote-seq data) 0))
               {})
  (assoc data
         :fin-sent? true
         :local-seq (inc (:local-seq data))))

(defn on-fin-wait-1-recv
  "Handle in ::fin-wait-1 — wait for ACK of our FIN and/or peer's FIN.
   Three possible outcomes:
     FIN+ACK  → both :ack-of-fin-received? and :fin-received? (→ ::time-wait)
     ACK only → :ack-of-fin-received? (→ ::fin-wait-2)
     FIN only → :fin-received?, simultaneous close (→ ::closing)"
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :fin-wait-1)
      (let [segment (:data result)]
        (cond
          ;; FIN+ACK — simultaneous-style close with ACK of our FIN
          (fin-ack? segment)
          (do (proto/send! (:transport resources)
                           (make-segment #{:ack}
                                         (:local-seq data)
                                         (inc (:seq-num segment)))
                           {})
              (assoc data
                     :fin-received?        true
                     :ack-of-fin-received? true
                     :remote-seq           (inc (:seq-num segment))))

          ;; ACK of our FIN only
          (ack? segment)
          (assoc data :ack-of-fin-received? true)

          ;; FIN from peer (simultaneous close, no ACK of ours yet)
          (fin? segment)
          (do (proto/send! (:transport resources)
                           (make-segment #{:ack}
                                         (:local-seq data)
                                         (inc (:seq-num segment)))
                           {})
              (assoc data
                     :fin-received? true
                     :remote-seq    (inc (:seq-num segment))))

          :else data)))))

;; ---------------------------------------------------------------------------
;; ::fin-wait-2
;; ---------------------------------------------------------------------------

(defn on-fin-wait-2-recv
  "Handle in ::fin-wait-2 — wait for peer's FIN."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :fin-wait-2)
      (let [segment (:data result)]
        (if (fin? segment)
          (do (proto/send! (:transport resources)
                           (make-segment #{:ack}
                                         (:local-seq data)
                                         (inc (:seq-num segment)))
                           {})
              (assoc data
                     :fin-received? true
                     :remote-seq    (inc (:seq-num segment))))
          data)))))

;; ---------------------------------------------------------------------------
;; ::close-wait
;; ---------------------------------------------------------------------------

(defn on-enter-close-wait
  "Enter ::close-wait — peer has closed their side; we can still send."
  [_resources data]
  (assoc data :peer-closed? true))

(defn on-close-wait-handle
  "Handle in ::close-wait — wait for application to set :close-requested?."
  [_resources data]
  data)

;; ---------------------------------------------------------------------------
;; ::closing
;; ---------------------------------------------------------------------------

(defn on-closing-recv
  "Handle in ::closing — wait for ACK of our FIN (simultaneous close path)."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :closing)
      (let [segment (:data result)]
        (if (ack? segment)
          (assoc data :ack-of-fin-received? true)
          data)))))

;; ---------------------------------------------------------------------------
;; ::last-ack
;; ---------------------------------------------------------------------------

(defn on-send-fin-last-ack
  "Enter ::last-ack — send our FIN to begin passive-side teardown."
  [resources data]
  (proto/send! (:transport resources)
               (make-segment #{:fin :ack}
                             (:local-seq data)
                             (or (:remote-seq data) 0))
               {})
  (assoc data
         :fin-sent? true
         :local-seq (inc (:local-seq data))))

(defn on-last-ack-recv
  "Handle in ::last-ack — wait for ACK of our FIN."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:recv-timeout-ms data default-recv-timeout-ms)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :last-ack)
      (let [segment (:data result)]
        (if (ack? segment)
          (assoc data :ack-of-fin-received? true)
          data)))))

;; ---------------------------------------------------------------------------
;; ::time-wait
;; ---------------------------------------------------------------------------

(defn on-enter-time-wait
  "Enter ::time-wait — start 2×MSL timer.  If no ITimer is available,
   expire immediately (useful for testing / non-timed environments)."
  [resources data]
  (let [msl-ms  (:msl-ms data default-msl-ms)
        two-msl (* 2 msl-ms)]
    (if-let [timer (:timer resources)]
      (let [cancel-fn (proto/schedule! timer two-msl
                                       (fn [] (assoc data :time-wait-expired? true)))]
        (assoc data :cancel-time-wait cancel-fn :time-wait-ms two-msl))
      ;; No timer → expire immediately
      (assoc data :time-wait-expired? true))))

(defn on-time-wait-handle
  "Handle in ::time-wait — wait for 2MSL timer expiration."
  [_resources data]
  data)

;; =============================================================================
;; Dispatch predicates — (fn [_resources data] → boolean)
;; =============================================================================

(defn passive-open?      [_r d] (= :passive (:open-mode d)))
(defn active-open?       [_r d] (= :active  (:open-mode d)))
(defn syn-received?      [_r d] (:syn-received? d))
(defn syn-ack-received?  [_r d] (:syn-ack-received? d))
(defn ack-received?      [_r d] (:ack-received? d))
(defn ack-of-fin?        [_r d] (:ack-of-fin-received? d))
(defn fin-received?      [_r d] (:fin-received? d))
(defn fin-ack-received?  [_r d] (and (:fin-received? d) (:ack-of-fin-received? d)))
(defn close-requested?   [_r d] (:close-requested? d))
(defn time-wait-expired? [_r d] (:time-wait-expired? d))
(defn has-error?         [_r d] (some? (:error d)))
(defn always             [_r _d] true)

;; =============================================================================
;; FSM spec builder
;; =============================================================================

(defn tcp-fsm-spec
  "Build a pure-data FSM spec for the RFC 793 TCP connection lifecycle.

   The spec covers all 11 standard TCP states plus every major transition
   path: active open, passive open, simultaneous open, active close,
   passive close, simultaneous close, RST handling, and 2MSL TIME-WAIT."
  [_opts]
  {:id      :tcp
   :initial ::closed

   :states
   {;;  ─── Connection Establishment ────────────────────────────────────

    ::closed
    {:enter    on-close-cleanup
     :handle   on-open-connection
     :dispatch [[::listen   passive-open?]
                [::syn-sent active-open?]]}

    ::listen
    {:enter    on-enter-listen
     :handle   on-listen-recv
     :dispatch [[::syn-received syn-received?]
                [::closed       has-error?]
                [::listen       always]]}

    ::syn-sent
    {:enter    on-send-syn
     :handle   on-syn-sent-recv
     :dispatch [[::established  syn-ack-received?]
                [::syn-received syn-received?]
                [::closed       has-error?]
                [::syn-sent     always]]}

    ::syn-received
    {:enter    on-send-syn-ack
     :handle   on-syn-received-recv
     :dispatch [[::established  ack-received?]
                [::closed       has-error?]
                [::syn-received always]]}

    ;;  ─── Data Transfer ───────────────────────────────────────────────

    ::established
    {:enter    on-enter-established
     :handle   on-established-recv
     :dispatch [[::close-wait  fin-received?]
                [::fin-wait-1  close-requested?]
                [::established always]]}

    ;;  ─── Connection Teardown ─────────────────────────────────────────

    ::fin-wait-1
    {:enter    on-send-fin
     :handle   on-fin-wait-1-recv
     :dispatch [[::time-wait   fin-ack-received?]   ;; FIN+ACK
                [::fin-wait-2  ack-of-fin?]          ;; ACK only
                [::closing     fin-received?]         ;; FIN only (simult. close)
                [::closed      has-error?]
                [::fin-wait-1  always]]}

    ::fin-wait-2
    {:handle   on-fin-wait-2-recv
     :dispatch [[::time-wait  fin-received?]
                [::closed     has-error?]
                [::fin-wait-2 always]]}

    ::close-wait
    {:enter    on-enter-close-wait
     :handle   on-close-wait-handle
     :dispatch [[::last-ack   close-requested?]
                [::close-wait always]]}

    ::closing
    {:handle   on-closing-recv
     :dispatch [[::time-wait ack-of-fin?]
                [::closed    has-error?]
                [::closing   always]]}

    ::last-ack
    {:enter    on-send-fin-last-ack
     :handle   on-last-ack-recv
     :dispatch [[::closed   ack-of-fin?]
                [::closed   has-error?]
                [::last-ack always]]}

    ::time-wait
    {:enter    on-enter-time-wait
     :handle   on-time-wait-handle
     :dispatch [[::closed    time-wait-expired?]
                [::time-wait always]]}}})

;; =============================================================================
;; IProtocolFSM implementation
;; =============================================================================

(defn make-tcp-fsm
  "Create a TCP protocol FSM.

   opts (all optional):
     :msl-ms              — Maximum Segment Lifetime (default 120 000)
     :connect-timeout-ms  — SYN handshake timeout     (default 30 000)
     :recv-timeout-ms     — per-segment recv timeout   (default 30 000)
     :initial-window      — advertised window size     (default 65 535)

   Returns: IProtocolFSM implementation.

   Usage:
     (def tcp (make-tcp-fsm {:msl-ms 60000}))

     ;; Active open
     (proto/run-session tcp
       (proto/make-resources my-transport my-timer)
       {:open-mode :active})

     ;; Passive open
     (proto/run-session tcp
       (proto/make-resources my-transport my-timer)
       {:open-mode :passive})"
  ([] (make-tcp-fsm {}))
  ([opts]
   (let [spec     (tcp-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))
         defaults {:msl-ms             default-msl-ms
                   :connect-timeout-ms default-connect-timeout-ms
                   :recv-timeout-ms    default-recv-timeout-ms
                   :initial-window     default-window}]
     (reify proto/IProtocolFSM
       (protocol-id [_] :tcp)

       (fsm-spec [_] spec)

       (compiled [_] @compiled)

       (initial-data [_ session-opts]
         (merge defaults opts session-opts
                {:segments-received       []
                 :local-seq               nil
                 :remote-seq              nil
                 :connection-established? false
                 :connection-closed?      false}))

       (terminal-states [_]
         #{::closed})

       (composable-states [_]
         ;; TCP established state hosts application-level sub-FSMs
         ;; (TLS, HTTP/1.1, HTTP/2, etc.)
         {::established :application})))))
