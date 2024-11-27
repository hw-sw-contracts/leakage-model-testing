(import hyrule *)
(require hyrule * :readers *)

(import .tracing *)
(require .tracing *)

(import collections [defaultdict :as ddict
                     deque
                     OrderedDict])

(import ctypes [CDLL])


;; Deliberately defining each leakage model variant
;; as an entirely separate model, for the sake of
;; presentation in the paper.

;; "global" vars:
;;   &mem  : supports (.read addr sz) -> uint
;;   &regs : dict of REGNAME -> uint
;;   &pc   : shorthand for (get &regs "rip")
;;   &tick : monotonic increasing in-order instruction-wise step tick


;; ss
(defleakage SilentStore []
  (on [(store [addr]_sz := val)
       (when (= val (&mem.read addr sz))
         #("ss" addr val))]))

;; ssi
(defleakage SilentStoreInitializedOnly [initialized (set)]
  (on-start [model input]
    (.update initialized (sfor addr input.mem-initialized (- model.STACK addr))))
  (on [(store [addr]_sz := val)
       (let [addrs (range addr (+ addr sz))
             was-init (.issuperset initialized addrs)]
         (.update initialized addrs)
         (when (and was-init
                    (= val (&mem.read addr sz)))
           #("ss" addr val)))]))

;; ssi0
(defleakage SilentStore0InitializedOnly [initialized (set)]
  (on-start [model input]
    (.update initialized (sfor addr input.mem-initialized (- model.STACK addr))))
  (on [(store [addr]_sz := val)
       (let [addrs (range addr (+ addr sz))
             was-init (.issuperset initialized addrs)]
         (.update initialized addrs)
         (when (and was-init
                    (= 0 val (&mem.read addr sz)))
           #("ss" addr val)))]))

;; rfc
(defleakage RegisterFileCompression []
  (on [(write reg := val)
       (when (and (in reg X86_64_GPRS)
               (exists reg_i X86_64_GPRS
                       :where (!= reg_i reg)
                 (= val (&regs.read reg_i))))
         #("rfc" reg val))]))

;; rfc0
(defleakage RegisterFileCompression0 []
  (on [(write reg := val)
       (when (and (in reg X86_64_GPRS)
               (= val 0)
               (exists reg_i X86_64_GPRS
                       :where (!= reg_i reg)
                 (= val (&regs.read reg_i))))
         #("rfc" reg val))]))

;; nrfc
(setv NARROW_RFC_LIMIT (<< 1 16))
(defleakage NarrowRegisterFileCompression []
  (on [(write reg := val)
       (when (and (in reg X86_64_GPRS)
                (< val NARROW_RFC_LIMIT)
                (exists reg_i X86_64_GPRS
                        :where (!= reg_i reg)
                  (< (&regs.read reg_i) NARROW_RFC_LIMIT)))
         #("rfc" reg))]))

;; tcs
(setv ALL1 (- (<< 1 64) 1))
(setv T-MUL #{"mul" "imul" "and"}
      T-OR  #{"or"}
      T-DIV #{"div" "idiv" "shl" "sal" "shr" "sar"})
(defleakage TrivialComputationSimplification []
  (on [(expr (op v1 v2))
       (when (is-any-of op T-MUL :if (or (= v1 0) (= v2 0))
                           T-OR  :if (or (= v1 ALL1) (= v2 ALL1))
                           T-DIV :if (= v1 0))
         #("cs" op v1 v2))]))

;; stcs
(setv ST-ADD #{"add" "shl" "sal" "shr" "sar"}
      ST-SUB #{"sub"}
      ST-MUL #{"mul" "imul"}
      ST-DIV #{"div" "idiv"}
      ST-AND #{"and" "or"}
      ST-XOR #{"xor"}
  )
(defleakage SemiTrivialComputationSimplification []
  (on [(expr (op v1 v2))
       (when (is-any-of op
               ST-ADD :if (or (= v1 0) (= v2 0))
               ST_SUB :if (or (= v2 0) (= v1 v2))
               ST-MUL :if (or (= v1 0) (= v2 0)
                              (= v1 1) (= v2 1))
               ST-DIV :if (or (= v1 0) (= v2 1) (= v1 v2))
               ST-AND :if (or (= v1 0) (= v2 0)
                              (= v1 ALL1) (= v2 ALL1)
                              (= v1 v2))
               ST-XOR :if (or (= v1 0) (= v2 0))  ; XXX should this also have (= v1 v2)?
               )
                   ;; XXX rotations?
         #("cs" op v1 v2))]))

;; ncs
(setv NARROW_CS_LIMIT (<< 1 32))
(defleakage NarrowComputationSimplification []
  (on [(expr (op v1 v2))
       (when (and (in op ST-MUL)
                  (< v1 NARROW_CS_LIMIT)
                  (< v2 NARROW_CS_LIMIT))
         #("cs" op))]))

;; op
(setv OP_CTX_SIZE 200)
(defleakage OperandPacking [ctx (deque)]
  (on [(expr (op v1 v2))
       (when (and (< v1 16) (< v2 16))
         (while (and ctx (>= (- &tick (. ctx [0][0])) OP_CTX_SIZE))
           (.popleft ctx))
         (for [[i [tick_i op_i]] (enumerate ctx)]
           (when (= op_i op)
             (del (. ctx [i]))
             (return #("op" op_i op)))
           (else
             (.append ctx #(&tick op)))))]))

;; cr
(setv CR_CTX_SIZE 1024)
(setv CR_ENTRY_SIZE 4)
(setv CACHEING_OPS (set (.split "add sub adc sbb
                                 mul imul div idiv
                                 inc dec neg
                                 and or xor not
                                 shr shl sar sal
                                 ror rol rcr rcl")))
;; XXX confirm this is keyed by pc and not just a lookup?
;; XXX confirm cr vs cra which ones use ops vs loads vs lea
(defn update [ctx &pc vs]
  (when (not-in &pc ctx)
    (assoc ctx &pc (deque :maxlen CR_ENTRY_SIZE)))
  (.append (get ctx &pc) vs)
  (while (>= (len ctx) CR_CTX_SIZE)
    (.popitem ctx)))
(defleakage ComputationReuse [ctx (OrderedDict)]
  (on [(expr (op #* vs))
       (when (in op CACHEING_OPS)
         (if (in vs (.get ctx &pc #()))
           #("cr" op #* vs)
           (update ctx &pc vs)))]))

;; cra
;; XXX confirm name
(defleakage ComputationReuseWithAddresses [ctx (OrderedDict)
                                           ctx-addrs (OrderedDict)
                                           ctx-loads (OrderedDict)]
  (on [(expr (op #* vs))
       (when (in op CACHEING_OPS)
         (if (in vs (.get ctx &pc #()))
           #("cr" op #* vs)
           (update ctx &pc vs)))]
      [(addr base + index * scale + off)
       (if (in #(base index scale off) (.get ctx-addrs &pc #()))
         #("cr-addr" base index scale off)
         (update ctx-addrs &pc [base index scale off]))]
      #_[(load [addr]_sz)  ; I think load was handled originally for the implicit address computation
       (if (in addr (.get ctx-loads &pc #()))
         #("cr-load" addr)
         (update ctx-loads &pc addr))]))

;; nlpf
;; XXX activate on store as well?
(setv POINTER_SIZE 8)  ;; 8*8 == 64 bit pointers
(setv CACHELINE_BITS 6)  ;; 2**6 == 64 bytes
(setv PAGE_BITS 12)  ;; 2**12 == 4096 bytes
(defleakage NextLinePrefetch []
  (on [(load [addr]_sz)
       (let [cache-index (>> addr CACHELINE_BITS)]
         #("pf" (+ cache-index 1)))]))

;; spf
;; XXX activate on store as well? save stores? iterate over stores?
(setv PF_HITS 3)
(defn diff [ns]
  (setv [ns1 ns2] (tee ns))
  (next ns2)
  (lfor [n m] (zip ns1 ns2) (- m n)))
(defn direction-of? [page-hits]
  (when (< (len page-hits) page-hits.maxlen)
    (return 0))
  (setv diffs (diff page-hits))
  (cond (forall n diffs (> n 0)) 1
        (forall n diffs (< n 0)) -1
        True 0))
(defleakage StreamPrefetch [all-page-hits (ddict #%(deque :maxlen (+ PF_HITS 1)))]
  (on [(load [addr]_sz)
       (let [cache-index (>> addr CACHELINE_BITS)
             page-index  (>> addr PAGE_BITS)
             page-hits (get all-page-hits page-index)
             _ (when (not-in cache-index page-hits) (.append page-hits cache-index))
             stream-dir (direction-of? page-hits)
             next-cache-index (+ stream-dir cache-index)]
         (when (and stream-dir
                    (= (>> next-cache-index (- PAGE_BITS CACHELINE_BITS)) page-index))
           #("pf" next-cache-index)))]))

;; m1pf
(setv M1PF_SIZE 20)
(setv M1PF_PREFETCH 5)  ; arbitrarily deciding to prefetch 5 elements
(defleakage M1Prefetch [initialized (set)
                        accesses (deque :maxlen M1PF_SIZE)
                        marks (deque :maxlen PF_HITS)]
  (on-start [model input]
      (.update initialized (sfor addr input.mem-initialized (- model.STACK addr))))
  (on [(store [addr]_sz := val)
       (.update initialized (range addr (+ addr sz)))]
      [(load [addr]_sz)
       (let [val (&mem.read addr sz)]

         (setv stride 0)
         (for [[addr_i val_i] (reversed accesses)]
           (when (= val_i addr)
             (.append marks addr_i)
             (let [diffs (set (diff marks))]
               (when (= (len diffs) 1)
                 (setv [stride] diffs)))
             (break)))

         (.append accesses #(addr val))

         (when stride
           (setv last-aop (. marks [-1])
                 fetches [])
           (for [i (range M1PF_PREFETCH)]
             (let [aop-el (+ last-aop (* i stride))]
               (when (in aop-el initialized)
                 (.extend fetches [aop-el (&mem.read aop-el POINTER_SIZE)]))))
           #("pf" #* fetches)))]))


;; cc-*
(setv cc-models (CDLL "./targets/cc_models.so"))
(defn fpc-size [buf]
  (cc-models.fpclen (bytes buf) (len buf)))
(defn bdi-size [buf]
  (cc-models.bdilen (bytes buf) (len buf)))

(setv CACHELINE_SIZE (<< 1 CACHELINE_BITS))
(defn write-into [buf offset sz val]
  (assoc buf
         (slice offset (+ offset sz))
         (.to-bytes val :length sz :byteorder "little")))

;; cc-fpc
(defleakage FPCCacheCompression []
  (on [(load [addr]_sz)
       (let [block-addr (<< (>> addr CACHELINE_BITS) CACHELINE_BITS)
             block-data (&mem.read-bytes block-addr CACHELINE_SIZE)]
         #("cc" (fpc-size block-data)))]
      [(store [addr]_sz := val)
       (let [block-addr (<< (>> addr CACHELINE_BITS) CACHELINE_BITS)
             block-data (&mem.read-bytes block-addr CACHELINE_SIZE)
             offset (% addr CACHELINE_SIZE)]
         (write-into block-data offset sz val)
         #("cc" (fpc-size block-data)))]))

;; cc-bdi
(defleakage BDICacheCompression []
  (on [(load [addr]_sz)
       (let [block-addr (<< (>> addr CACHELINE_BITS) CACHELINE_BITS)
             block-data (&mem.read-bytes block-addr CACHELINE_SIZE)]
         #("cc" (bdi-size block-data)))]
      [(store [addr]_sz := val)
       (let [block-addr (<< (>> addr CACHELINE_BITS) CACHELINE_BITS)
             block-data (&mem.read-bytes block-addr CACHELINE_SIZE)
             offset (% addr CACHELINE_SIZE)]
         (write-into block-data offset sz val)
         #("cc" (bdi-size block-data)))]))

;; ct
(defleakage ConstantTime []
  (on [(load [addr]_sz)
       #("ct-load" addr)]
      [(store [addr]_sz := val)
       #("ct-store" addr)]
      [(jump addr : n)
       #("ct-jump" (if n addr (+ &pc &insn.size)))]))