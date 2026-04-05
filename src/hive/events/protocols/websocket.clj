(ns hive.events.protocols.websocket
  "RFC 6455 WebSocket lifecycle FSM.

   States: connecting → open → closing → closed (+ error terminal).

   The FSM is pure data — all I/O happens through ITransport/ITimer
   resources injected at run time. Frame parsing, fragment assembly,
   and the close handshake are handled as state-machine transitions.

   Factory:
     (make-websocket-fsm opts)
       opts — {:ping-interval-ms  30000   ;; keepalive interval
               :close-timeout-ms  5000    ;; max wait for peer close
               :max-frame-size    65536   ;; bytes
               :extensions        []      ;; reserved
               :subprotocols      []}     ;; Sec-WebSocket-Protocol"
  (:require [hive.events.protocols.core :as proto])
  (:import  [java.security MessageDigest]
            [java.util Base64]))

;; =============================================================================
;; Constants — RFC 6455 §5.2, §7.4
;; =============================================================================

(def ^:const ws-magic-guid "258EAFA5-E914-47DA-95CA-5AB5FE44EE06")

;; Opcodes
(def ^:const opcode-continuation 0x0)
(def ^:const opcode-text         0x1)
(def ^:const opcode-binary       0x2)
(def ^:const opcode-close        0x8)
(def ^:const opcode-ping         0x9)
(def ^:const opcode-pong         0xA)

;; Close codes
(def ^:const close-normal        1000)
(def ^:const close-going-away    1001)
(def ^:const close-protocol-err  1002)
(def ^:const close-invalid-data  1003)

;; =============================================================================
;; Handshake helpers — RFC 6455 §4.2.2
;; =============================================================================

(defn sec-websocket-accept
  "Compute Sec-WebSocket-Accept from a client key per RFC 6455 §4.2.2."
  [client-key]
  (let [sha1 (MessageDigest/getInstance "SHA-1")
        hash (.digest sha1 (.getBytes (str client-key ws-magic-guid) "UTF-8"))]
    (.encodeToString (Base64/getEncoder) hash)))

(defn valid-accept?
  "Verify server's Sec-WebSocket-Accept against our key."
  [client-key accept-header]
  (= accept-header (sec-websocket-accept client-key)))

;; =============================================================================
;; Frame helpers
;; =============================================================================

(defn control-opcode?
  "Control frames: close, ping, pong (opcodes ≥ 0x8)."
  [opcode]
  (>= opcode 0x8))

(defn parse-frame
  "Parse a raw frame map {:opcode :fin? :payload :mask-key}.
   Returns normalised frame with :type keyword."
  [raw-frame]
  (let [opcode (:opcode raw-frame 0)]
    (assoc raw-frame
           :type (case opcode
                   0x0 :continuation
                   0x1 :text
                   0x2 :binary
                   0x8 :close
                   0x9 :ping
                   0xA :pong
                   :unknown))))

(defn parse-close-payload
  "Extract close code and reason from a close frame payload."
  [payload]
  (if (and payload (>= (count payload) 2))
    {:close-code   (bit-or (bit-shift-left (bit-and (nth payload 0) 0xFF) 8)
                           (bit-and (nth payload 1) 0xFF))
     :close-reason (when (> (count payload) 2)
                     (String. (byte-array (drop 2 payload)) "UTF-8"))}
    {:close-code close-normal :close-reason ""}))

(defn make-close-payload
  "Build close frame payload bytes from code and optional reason."
  [code reason]
  (let [code-bytes [(unchecked-byte (bit-shift-right code 8))
                    (unchecked-byte (bit-and code 0xFF))]
        reason-bytes (when (seq reason)
                       (seq (.getBytes ^String reason "UTF-8")))]
    (vec (concat code-bytes reason-bytes))))

;; =============================================================================
;; FSM handlers — pure fns of [resources data] → data
;; =============================================================================

(defn on-initiate-handshake
  "Send HTTP upgrade request. Transport sends the raw upgrade bytes."
  [resources data]
  (let [transport (:transport resources)
        ws-key    (:ws-key data (str (java.util.UUID/randomUUID)))]
    (proto/send! transport
                 {:type    :http-upgrade
                  :headers {"Upgrade"              "websocket"
                            "Connection"           "Upgrade"
                            "Sec-WebSocket-Key"    ws-key
                            "Sec-WebSocket-Version" "13"}}
                 {})
    (assoc data :ws-key ws-key)))

(defn on-handshake-response
  "Validate the HTTP 101 upgrade response."
  [resources data]
  (let [transport (:transport resources)
        resp      (proto/recv! transport {:timeout-ms 5000})]
    (cond
      (:error resp)
      (assoc data :error (:error resp) :error-phase :handshake)

      (not= 101 (get-in resp [:data :status]))
      (assoc data :error :invalid-status :error-phase :handshake)

      (not (valid-accept? (:ws-key data)
                          (get-in resp [:data :headers "Sec-WebSocket-Accept"])))
      (assoc data :error :invalid-accept :error-phase :handshake)

      :else
      (assoc data :handshake-complete? true))))

(defn on-open
  "Transition into open state — start ping timer if configured."
  [resources data]
  (let [timer          (:timer resources)
        ping-interval  (:ping-interval-ms data)]
    (when (and timer ping-interval (pos? ping-interval))
      (let [cancel-fn (proto/schedule! timer ping-interval
                                       (fn [] (assoc data :ping-due? true)))]
        (assoc data :cancel-ping cancel-fn)))
    (assoc data :frames [] :fragment-buffer nil)))

(defn on-receive-frame
  "Handle an inbound frame in the open state."
  [resources data]
  (let [transport (:transport resources)
        result    (proto/recv! transport {:timeout-ms (:recv-timeout-ms data 30000)
                                         :max-bytes  (:max-frame-size data 65536)})]
    (if (:error result)
      (assoc data :error (:error result) :error-phase :recv)
      (let [raw-frame (:data result)
            frame     (parse-frame raw-frame)
            opcode    (:opcode frame 0)
            fin?      (:fin? frame true)]
        (case (:type frame)
          ;; --- Control frames (always processed immediately) ---
          :ping
          (do (proto/send! (:transport resources)
                           {:opcode opcode-pong :fin? true :payload (:payload frame)}
                           {})
              (update data :frames conj {:type :ping :payload (:payload frame)}))

          :pong
          (update data :frames conj {:type :pong :payload (:payload frame)})

          :close
          (let [{:keys [close-code close-reason]} (parse-close-payload (:payload frame))]
            (assoc data
                   :peer-close?  true
                   :close-code   close-code
                   :close-reason close-reason))

          ;; --- Data frames — text / binary / continuation ---
          (:text :binary :continuation)
          (if fin?
            ;; Complete message — flush any fragment buffer
            (let [payload (if-let [buf (:fragment-buffer data)]
                            (into buf (:payload frame))
                            (:payload frame))]
              (-> data
                  (update :frames conj {:type (if (:fragment-buffer data)
                                                (:fragment-type data)
                                                (:type frame))
                                        :payload payload})
                  (dissoc :fragment-buffer :fragment-type)))
            ;; Fragment — accumulate
            (-> data
                (update :fragment-buffer (fnil into []) (:payload frame))
                (cond-> (not= :continuation (:type frame))
                  (assoc :fragment-type (:type frame)))))

          ;; Unknown opcode → error
          (assoc data :error :unknown-opcode :error-phase :recv))))))

(defn on-send-ping
  "Send a ping frame."
  [resources data]
  (proto/send! (:transport resources)
               {:opcode opcode-ping :fin? true :payload nil}
               {})
  (assoc data :ping-due? false :awaiting-pong? true))

(defn on-initiate-close
  "Send a close frame to begin the close handshake."
  [resources data]
  (let [code   (:close-code data close-normal)
        reason (:close-reason data "")]
    (proto/send! (:transport resources)
                 {:opcode  opcode-close
                  :fin?    true
                  :payload (make-close-payload code reason)}
                 {})
    ;; Start close timeout
    (if-let [timer (:timer resources)]
      (let [timeout (:close-timeout-ms data 5000)
            cancel  (proto/schedule! timer timeout
                                     (fn [] (assoc data :close-timeout? true)))]
        (assoc data :close-sent? true :cancel-close-timer cancel))
      (assoc data :close-sent? true))))

(defn on-await-peer-close
  "Wait for peer's close frame after we sent ours."
  [resources data]
  (let [result (proto/recv! (:transport resources)
                            {:timeout-ms (:close-timeout-ms data 5000)})]
    (if (:error result)
      (assoc data :close-timeout? true)
      (let [frame (parse-frame (:data result))]
        (if (= :close (:type frame))
          (let [{:keys [close-code close-reason]} (parse-close-payload (:payload frame))]
            (assoc data
                   :peer-close?  true
                   :close-code   (or (:close-code data) close-code)
                   :close-reason (or (:close-reason data) close-reason)))
          ;; Non-close frame while closing — discard, keep waiting
          data)))))

(defn on-close-transport
  "Tear down the transport."
  [resources data]
  (proto/close! (:transport resources))
  (when-let [cancel (:cancel-ping data)]
    (cancel))
  (when-let [cancel (:cancel-close-timer data)]
    (cancel))
  (when-let [timer (:timer resources)]
    (proto/cancel-all! timer))
  (assoc data :transport-closed? true))

;; =============================================================================
;; Dispatch predicates
;; =============================================================================

(defn handshake-ok?  [_resources data] (:handshake-complete? data))
(defn handshake-err? [_resources data] (some? (:error data)))
(defn peer-close?    [_resources data] (:peer-close? data))
(defn close-sent?    [_resources data] (:close-sent? data))
(defn close-done?    [_resources data] (or (:peer-close? data) (:close-timeout? data)))
(defn has-error?     [_resources data] (some? (:error data)))
(defn always         [_resources _data] true)

;; =============================================================================
;; FSM spec builder
;; =============================================================================

(defn websocket-fsm-spec
  "Build a pure-data FSM spec for RFC 6455 WebSocket lifecycle."
  [_opts]
  {:id     :websocket
   :initial ::connecting

   :states
   {::connecting
    {:enter on-initiate-handshake
     :handle on-handshake-response
     :dispatch [[::open  handshake-ok?]
                [::error handshake-err?]]}

    ::open
    {:enter on-open
     :handle on-receive-frame
     :dispatch [[::closing peer-close?]     ;; peer initiated close
                [::closing close-sent?]      ;; we initiated close
                [::error   has-error?]
                [::open    always]]}         ;; stay open, process next frame

    ::closing
    {:enter on-initiate-close
     :handle on-await-peer-close
     :dispatch [[::closed close-done?]
                [::error  has-error?]
                [::closing always]]}

    ::closed
    {:enter on-close-transport}

    ::error
    {:enter on-close-transport}}})

;; =============================================================================
;; IProtocolFSM implementation
;; =============================================================================

(defn make-websocket-fsm
  "Create a WebSocket protocol FSM.

   opts:
     :ping-interval-ms  — keepalive ping interval (default 30000, nil to disable)
     :close-timeout-ms  — max wait for peer close frame (default 5000)
     :max-frame-size    — max inbound frame bytes (default 65536)
     :recv-timeout-ms   — recv timeout per frame (default 30000)
     :extensions        — reserved for extensions
     :subprotocols      — Sec-WebSocket-Protocol list"
  ([] (make-websocket-fsm {}))
  ([opts]
   (let [spec     (websocket-fsm-spec opts)
         compiled (delay ((requiring-resolve 'hive.events.fsm/compile) spec))
         defaults {:ping-interval-ms 30000
                   :close-timeout-ms 5000
                   :max-frame-size   65536
                   :recv-timeout-ms  30000}]
     (reify proto/IProtocolFSM
       (protocol-id [_] :websocket)

       (fsm-spec [_] spec)

       (compiled [_] @compiled)

       (initial-data [_ session-opts]
         (merge defaults opts session-opts
                {:frames           []
                 :fragment-buffer  nil
                 :close-code       nil
                 :close-reason     nil
                 :handshake-complete? false}))

       (terminal-states [_]
         #{::closed ::error})

       (composable-states [_]
         ;; WebSocket open state can host application-level sub-FSMs
         {::open :application})))))
