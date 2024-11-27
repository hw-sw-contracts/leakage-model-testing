(import hyrule *)
(require hyrule * :readers *)

(import .tracing *)
(require .tracing *)

(import collections [defaultdict :as ddict
                     OrderedDict
                     deque])


(defpredictor V1 []
  (on [(jump addr : n)
       (when (&insn.group CS_GRP_JUMP)
         [(if n (+ &pc &insn.size) addr)])]))

(defpredictor StraightLine []
  (on [(jump addr : n)
       [(+ &pc &insn.size)]]))

(setv V4_MAX 20)
(defpredictor V4Sized [storebuf (deque :maxlen V4_MAX)]
  ;; a simplification of STL forwarding that doesn't forward
  ;; between mixed-sized or overlapping memory operations
  (on [(load [addr]_sz)
       (lfor [waddr wsz val] storebuf
             :if (= [addr sz] [waddr wsz])
             val)]
      [(store [addr]_sz := val)
       (.append storebuf [addr sz (&mem.read addr sz)])]))

(setv RSB_SIZE 16)
(defpredictor RSBDropOldest [stack (deque :maxlen RSB_SIZE)]
  ;; RSB that drops oldest entry on overflow
  ;; and halts on underflow
  (on [(jump addr : n)
       (cond
         (&insn.group CS_GRP_CALL) (.append stack (+ &pc &insn.size))
         (&insn.group CS_GRP_RET) (if stack [(.pop stack)] [HALT]))]))

(defpredictor RSBCircular [stack (* [0] RSB_SIZE)
                           idx 0]
  ;; RSB prediction using a naive circular buffer
  (on [(jump addr : n)
       (cond
         (&insn.group CS_GRP_CALL) (do (assoc stack idx (+ &pc &insn.size))
                                       (setv idx (% (+ idx 1) RSB_SIZE)))
         (&insn.group CS_GRP_RET) (do (setv idx (% (- idx 1) RSB_SIZE))
                                      [(get stack idx)]))]))