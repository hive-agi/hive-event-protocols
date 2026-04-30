(ns hive.events.protocols.core
  "Protocol FSM abstractions and registry.

   Defines the extension points that concrete protocol implementations
   (TCP, HTTP/1, HTTP/2, TLS, WebSocket, etc.) must satisfy.

   Design principles:
   - FSM specs are pure data — no I/O imports, no concrete transport deps
   - Handlers take [resources data] — resources contain I/O fns
   - ITransport defines what I/O capabilities a protocol needs
   - Any library (Aleph, Netty, java.net.http, clj-http) can provide ITransport
   - FSMs compose via hive.events.fsm sub-FSM mechanism

   Architecture:
     IProtocolFSM (this ns)     — what the protocol state machine looks like
     ITransport (this ns)       — what I/O capabilities it needs
     concrete protocols          — tcp.clj, http1.clj, etc.
     transport adapters          — aleph.clj, netty.clj, etc. (separate lib or consumer)")

;; =============================================================================
;; Protocol FSM — what a protocol state machine provides
;; =============================================================================

(defprotocol IProtocolFSM
  (protocol-id [this]
    "Keyword identifying this protocol. E.g. :tcp, :http/v1.1, :http/v2, :tls/v1.3
     (numeric-start name segments are invalid Clojure keywords; prefix with `v`).")

  (fsm-spec [this]
    "Return the hive.events.fsm spec map for this protocol.
     Pure data — no I/O, fully serializable as EDN.")

  (compiled [this]
    "Return pre-compiled FSM (cached). Thread-safe for concurrent use.")

  (initial-data [this opts]
    "Build initial FSM data map for a new session.
     opts may include protocol-specific configuration.")

  (terminal-states [this]
    "Set of terminal state keywords (e.g. #{::closed ::error}).
     Used by orchestrators to know when a session is done.")

  (composable-states [this]
    "Map of state keyword -> sub-FSM slot.
     States where another protocol FSM can be composed in.
     E.g. TCP's ::established can host TLS or HTTP.
     Returns {} if not composable."))

;; =============================================================================
;; Transport — what I/O capabilities a protocol FSM needs
;; =============================================================================

(defprotocol ITransport
  (transport-id [this]
    "Keyword identifying this transport. E.g. :aleph, :netty, :jdk-http, :mock")

  (send! [this data opts]
    "Send bytes/data over the transport.
     Returns result map {:sent? bool :bytes-written N :error ...}")

  (recv! [this opts]
    "Receive bytes/data from the transport.
     opts: {:timeout-ms N, :max-bytes N}
     Returns result map {:data ... :bytes-read N :error ...}")

  (close! [this]
    "Close the transport. Idempotent.")

  (open? [this]
    "Is the transport connection open?"))

;; =============================================================================
;; Timer — protocols need timed transitions (retransmit, keepalive, etc.)
;; =============================================================================

(defprotocol ITimer
  (schedule! [this delay-ms callback]
    "Schedule a callback after delay-ms. Returns cancel fn.")

  (cancel-all! [this]
    "Cancel all pending timers."))

;; =============================================================================
;; Registry — discover and compose protocol FSMs
;; =============================================================================

(defonce ^:private registry (atom {}))

(defn register!
  "Register a protocol FSM in the global registry."
  [protocol-fsm]
  (swap! registry assoc (protocol-id protocol-fsm) protocol-fsm))

(defn lookup
  "Look up a registered protocol FSM by id."
  [protocol-id]
  (get @registry protocol-id))

(defn registered-protocols
  "List all registered protocol ids."
  []
  (keys @registry))

;; =============================================================================
;; Resource Builder — construct FSM resources from transport + timer
;; =============================================================================

(defn make-resources
  "Build a resources map for FSM execution from transport adapters.

   Arguments:
     transport — ITransport implementation (Aleph, Netty, mock, etc.)
     timer     — ITimer implementation (or nil for no timers)
     extra     — additional resources map (merged in)

   Returns: map suitable as first arg to fsm/run

   The protocol FSM handlers destructure from this map.
   This is the seam where concrete I/O meets abstract state machine."
  ([transport] (make-resources transport nil {}))
  ([transport timer] (make-resources transport timer {}))
  ([transport timer extra]
   (cond-> {:transport transport}
     timer (assoc :timer timer)
     (seq extra) (merge extra))))

;; =============================================================================
;; Session — run a protocol FSM session
;; =============================================================================

(defn run-session
  "Run a protocol FSM session to completion.

   Arguments:
     protocol  — IProtocolFSM implementation
     resources — from make-resources
     opts      — protocol-specific session options

   Returns: final FSM data map"
  [protocol resources opts]
  (let [fsm   (compiled protocol)
        data  (initial-data protocol opts)]
    ((requiring-resolve 'hive.events.fsm/run)
     fsm resources {:data data})))
