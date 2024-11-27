(import hyrule *)
(require hyrule * :readers *)

(import collections [defaultdict :as ddict]
        functools [cache :as memoize]
        itertools [tee])

(import capstone
        capstone [CS_GRP_JUMP CS_GRP_CALL CS_GRP_RET]
        capstone.x86 [X86_OP_IMM X86_OP_REG X86_OP_MEM
                      X86_REG_RAX X86_REG_RDX
                      X86_REG_RCX X86_REG_ECX X86_REG_CX 
                      X86_REG_EFLAGS X86_REG_RSP
                      X86_INS_JA    X86_INS_JCXZ  X86_INS_JGE   X86_INS_JNE   X86_INS_JO
                      X86_INS_JAE   X86_INS_JE    X86_INS_JL    X86_INS_JNO   X86_INS_JP
                      X86_INS_JB    X86_INS_JECXZ X86_INS_JLE   X86_INS_JNP   X86_INS_JRCXZ
                      X86_INS_JBE   X86_INS_JG    X86_INS_JMP   X86_INS_JNS   X86_INS_JS]
        unicorn [UC_MEM_READ UC_MEM_WRITE x86_const])

(import interfaces [Trace])

(defn by3s [flattened]
  (let [it (iter flattened)]
    (try
      (while True
        (yield [(next it) (next it) (next it)]))
      (except [StopIteration]))))

(defmacro ite [#* body] `(if ~@body))

(defmacro list-when [cond #* body]
  `(if ~cond ~body []))

(defmacro exists [#* args]
  `(cfor any ~@(lfor arg args (if (= arg ':where) ':if arg))))

(defmacro forall [#* args]
  `(cfor all ~@args))

(defmacro is-any-of [op #* cases]
  `(or ~@(gfor [els _if check] (by3s cases)
           (do (assert (= _if ':if))
               `(and (in ~op ~els) ~check)))))


;; https://wiki.osdev.org/CPU_Registers_x86-64
;; RAX  EAX   AX    AH   AL    Accumulator
;; RBX  EBX   BX    BH   BL    Base
;; RCX  ECX   CX    CH   CL    Counter
;; RDX  EDX   DX    DH   DL    Data (commonly extends the A register)
;; RSI  ESI   SI         SIL   Source index for string operations
;; RDI  EDI   DI         DIL   Destination index for string operations
;; RSP  ESP   SP         SPL   Stack Pointer
;; RBP  EBP   BP         BPL   Base Pointer (meant for stack frames)
;; R8   R8D   R8W        R8B   General purpose
;; R9   R9D   R9W        R9B   General purpose
;; R10  R10D  R10W       R10B  General purpose
;; R11  R11D  R11W       R11B  General purpose
;; R12  R12D  R12W       R12B  General purpose
;; R13  R13D  R13W       R13B  General purpose
;; R14  R14D  R14W       R14B  General purpose
;; R15  R15D  R15W       R15B  General purpose
(setv X86_64_GPRS (.split "rax rbx rcx rdx
                           rsi rdi rsp rbp
                           r8  r9  r10 r11
                           r12 r13 r14 r15")
      X86_32_GPRS (.split "eax ebx ecx edx
                           esi edi esp ebp
                           r8d r9d r10d r11d
                           r12d r13d r14d r15d")
      X86_32_64_GPR_IDS #{19 20 21 22 23 24 29 30 35 36 37 38 39
                          40 43 44 106 107 108 109 110 111 112 113
                          226 227 228 229 230 231 232 233}
      X86_64_GPR_IDS #{35 36 37 38 39 40 106 43 44 107 108 109 110 111 112 113}
      X86_GPR_MAP {19 35  3 35  1 35  2 35  21 37  8 37  4 37  5 37  22 38
                   12 38  9 38  10 38  24 40  18 40  13 40  16 40  29 43  45 43
                   46 43  23 39  14 39  15 39  30 44  47 44  48 44  20 36  6 36
                   7 36  226 106  234 106  218 106  227 107  235 107  219 107
                   228 108  236 108  220 108  229 109  237 109  221 109
                   230 110  238 110  222 110  231 111  239 111  223 111
                   232 112  240 112  224 112  233 113  241 113  225 113}
      CF 0x0001
      PF 0x0004
      ZF 0x0040
      SF 0x0080
      OF 0x0800
      ;; http://unixwiz.net/techtips/x86-jumps.html
      X86_JUMP_TEST {X86_INS_JA   #%(= (& %1 (| CF ZF)) 0)
                     X86_INS_JAE  #%(= (& %1 CF) 0)
                     X86_INS_JB   #%(!= (& %1 CF) 0)
                     X86_INS_JBE  #%(!= (& %1 (| CF ZF)) 0)
                     ;; X86_INS_JCXZ
                     X86_INS_JE   #%(!= (& %1 ZF) 0)
                     ;; X86_INS_JECXZ
                     X86_INS_JG   #%(in (& %1 (| ZF SF OF)) #(0 (| SF OF)))   ;; ZF = 0 and SF = OF
                     X86_INS_JGE  #%(in (& %1 (| SF OF)) #(0 (| SF OF)))
                     X86_INS_JL   #%(in (& %1 (| SF OF)) #(SF OF))
                     X86_INS_JLE  #%(or (& %1 ZF) (in (& %1 (| SF OF)) #(SF OF)))     ;; ZF = 1 or SF <> OF
                     X86_INS_JMP  (fn [_] True)
                     X86_INS_JNE  #%(= (& %1 ZF) 0)
                     X86_INS_JNO  #%(= (& %1 OF) 0)
                     X86_INS_JNP  #%(= (& %1 PF) 0)
                     X86_INS_JNS  #%(= (& %1 SF) 0)
                     X86_INS_JO   #%(!= (& %1 OF) 0)
                     X86_INS_JP   #%(!= (& %1 PF) 0)
                     ;; X86_INS_JRCXZ
                     X86_INS_JS   #%(!= (& %1 SF) 0)}
      HALT (object))


(defclass Memory []
  (defn __init__ [self emu]
    (setv self.emu emu))

  (defn read-bytes [self addr sz]
    (self.emu.mem-read addr sz))

  (defn read [self addr sz]
    (-> (self.emu.mem-read addr sz) (int.from-bytes "little"))))

(defclass RegFile []
  (defn __init__ [self emu gprs]
    (setv self.emu emu
          self.gprs gprs))

  (defn read [self reg]
    (get self.gprs reg)))

(defclass InstructionInfo []
  (defn __init__ [self insn]
    (setv self.insn insn)
    (setv self.id insn.id)
    (setv self.size insn.size)
    (setv self.operands insn.operands)
    (setv self.regs-read insn.regs-read)
  )
  (defn [memoize] regs-access [self]
    (.regs-access self.insn))
  (defn [memoize] insn-name [self]
    (.insn-name self.insn))
  (defn [memoize] group [self grp]
    (.group self.insn grp))
)

(defn [memoize] cs/reg-name [reg]
  (cs.reg-name reg))


(defclass BaseTracer []
  (defn __init__ [self]
    (.__init__ (super))
    (.reset-trace self))

  (defn reset-trace [self]
    (setv self.trace []
          self.prev-pc None))

  (defn start-tracing [self model input])

  (defn get-trace [self]
    (Trace :trace (tuple self.trace)))

  (defn [staticmethod] encode-value [value]
    (if (isinstance value int)
      (hex value)
      (str value)))

  (defn add-to-trace [self values]
    (self.trace.append (.join " " (map self.encode-value values))))

  ;; (defn mem-access-hook [self emu access addr sz val model])
  ;; (defn instruction-hook [self emu pc insn-sz model])
)


(defclass BasePredictor [BaseTracer]
  (defn add-to-trace [self values]
    (self.trace.extend values))
  (defn mem-access-hook [self emu access addr sz val model])
  (defn instruction-hook [self emu pc insn-sz model]))


(setv cs (capstone.Cs capstone.CS_ARCH_X86 capstone.CS_MODE_64)
      cs.detail True
      cs-cache {})

(eval-and-compile
(defn _defmodel [basecls suffix tracer-name init-args body]
  (setv class-inits (-> (by2s init-args) list)
        class-args (lfor [arg _] class-inits arg))
  (setv start-trace-body []
        store-body []
        load-body []
        write-body []
        expr-body []
        addr-body []
        jump-body []
        injected [])
  (for [form body]
    (unless (and (isinstance form hy.models.Expression)
                 (isinstance (. form [0]) hy.models.Symbol))
      (print f"# warning: unknown form in {tracer-name}: {(cut (hy.repr form) 1 None)}"))
    (case (. form [0])
      'on-start (do
                  (setv args (. form [1]))
                  (.append start-trace-body `(setv ~args [model_ input_]))
                  (.extend start-trace-body (cut form 2 None)))
      'on (do
            (setv cases (cut form 1 None))
            (for [[[uop #* names] #* body] cases]
              #_(when (= (. body [0]) ':if)
                (setv body [`(when ~(. body [1]) ~@(cut body 2 None))]))
              (case uop
                'store (do
                         (setv addr (. names [0][0])
                               sz (hy.models.Symbol (cut (. names [1]) 1 None))
                               val (. names [3]))
                         (.append store-body `(setv ~addr addr_
                                                    ~sz sz_
                                                    ~val val_))
                         (.extend store-body body))
                'load (do
                        (setv addr (. names [0][0])
                              sz (hy.models.Symbol (cut (. names [1]) 1 None)))
                        (.append load-body `(setv ~addr addr_
                                                  ~sz sz_))
                        (.extend load-body body))
                'write (do
                         (setv reg (. names [0])
                               val (. names [2]))
                         (.append write-body `(setv ~reg reg_
                                                    ~val val_))
                         (.extend write-body body))
                'expr (do
                        (setv op (. names [0][0])
                              args (cut (. names [0]) 1 None))
                        (.append expr-body `(try
                                              (setv [~@args] opvals_)
                                              (except [ValueError])
                                              (else
                                                (setv ~op (insn_.insn-name))
                                                ~@body))))
                'addr (do
                        (setv [base _ index _ scale _ disp] names)
                        (.append addr-body `(setv ~base base_
                                                  ~index index_
                                                  ~scale scale_
                                                  ~disp disp_))
                        (.extend addr-body body))
                'jump (do
                        (setv [addr _ n] names)
                        (.append jump-body `(setv ~addr target_
                                                  ~n jmp-cond_))
                        (.extend jump-body body))
                else (print f"# warning: unhandled uop in {tracer-name}: {(hy.repr uop)}"))))
      else (print f"# warning: unknown form in {tracer-name}: {(cut (hy.repr form) 1 None)}")))

  `(defclass ~(hy.models.Symbol (+ tracer-name suffix)) [~basecls]
     (defn reset-trace [self]
       (.reset-trace (super))
       ~@(gfor [arg init] class-inits
           `(setv (. self ~arg) ~init))
       ~@(list-when write-body
           `(setv self.regs (ddict int))))

     ~@(list-when start-trace-body
         `(defn start-tracing [self model_ input_]
            ~@(gfor arg class-args `(setv ~arg (. self ~arg)))
            ~@start-trace-body
            ~@(list-when write-body
                (.update self.regs (dfor reg X86_64_GPR_IDS
                                     (cs/reg-name reg) (emu_.reg-read reg))))))

     ~@(list-when (or store-body load-body)
         `(defn mem-access-hook [self emu_ access-type_ addr_ sz_ val_ model_]
            (setv &tick model_.instruction-count
                  &pc self.prev-pc
                  &mem (Memory emu_))
            ~@(gfor arg class-args `(setv ~arg (. self ~arg)))
            (let [observation (if (= access-type_ UC_MEM_WRITE)
                                (do ~@store-body)
                                (do ~@load-body))]
              (when (is-not observation None)
                (self.add-to-trace observation)))))

     ~@(list-when write-body
         `(defn _uop-write [self emu_ pc_ tick_ reg_ val_]
            (setv &tick tick_
                  &regs (RegFile emu_ self.regs))
            ~@(gfor arg class-args `(setv ~arg (. self ~arg)))
            ~@write-body))

     ~@(list-when write-body
         `(defn finish-prev-insn [self emu_ tick_]
            (unless self.prev-pc (return))
            (setv insn_ (get cs-cache self.prev-pc))
            (for [reg_ (. (insn_.regs-access) [1])]
              ;; for now, we only consider 32- and 64-bit general purpose registers
              (when (in reg_ X86_32_64_GPR_IDS)
                (let [reg-name0 (cs/reg-name reg_)
                      reg-name (if (in reg-name0 X86_32_GPRS)
                                 (->> reg-name0 (.index X86_32_GPRS) (get X86_64_GPRS))
                                 reg-name0)
                      reg-val (emu_.reg-read reg_)
                      observation (self._uop-write emu_ self.prev-pc tick_ reg-name reg-val)]
                  (when (is-not observation None)
                    (self.add-to-trace observation))))
              (when (is-not (setx reg-id-64 (.get X86_GPR_MAP reg_)) None)
                (assoc self.regs (cs/reg-name reg-id-64) (emu_.reg-read reg-id-64))))))

     ~@(list-when addr-body
         `(defn _uop-addr [self emu_ pc_ tick_ base_ index_ scale_ disp_]
            (setv &pc pc_
                  &tick tick_)
            ~@(gfor arg class-args `(setv ~arg (. self ~arg)))
            ~@addr-body))

     ~@(list-when (or expr-body addr-body jump-body)
         `(defn _opval [self emu_ pc_ tick_ oparg_ is-lea_]
            (case oparg_.type
              X86_OP_IMM oparg_.imm
              X86_OP_REG (emu_.reg-read oparg_.reg)
              X86_OP_MEM (do
                           (setv memarg_ oparg_.mem
                                 base_ (emu_.reg-read memarg_.base)
                                 index_ (emu_.reg-read memarg_.index)
                                 scale_ memarg_.scale
                                 disp_ memarg_.disp
                                 addr_ (+ base_ (* scale_ index_) disp_
                                          (case memarg_.segment
                                            0 0
                                            x86_const.UC_X86_REG_CS (emu_.reg-read x86_const.UC_X86_REG_CS)
                                            x86_const.UC_X86_REG_ES (emu_.reg-read x86_const.UC_X86_REG_ES)
                                            x86_const.UC_X86_REG_FS (emu_.reg-read x86_const.UC_X86_REG_FS_BASE)
                                            x86_const.UC_X86_REG_GS (emu_.reg-read x86_const.UC_X86_REG_GS_BASE)
                                            else (raise (ValueError f"segment {memarg_.segment}")))))
                           ~@(list-when addr-body
                               `(let [addr-obs (self._uop-addr emu_ pc_ tick_ base_ index_ scale_ disp_)]
                                  (when (is-not addr-obs None)
                                    (self.add-to-trace addr-obs))))
                           (if is-lea_ addr_ (int.from-bytes (emu_.mem-read addr_ oparg_.size) "little"))))))

     ~@(list-when expr-body
         `(defn _uop-expr [self emu_ pc_ tick_ insn_]
            (setv mnemonic_ (insn_.insn-name))
            ;; XXX just ignore these instructions for now
            (when (in mnemonic_ ["nop" "push" "pop" "call"])
              (return))
            (setv &tick tick_
                  &pc pc_)
            ~@(gfor arg class-args `(setv ~arg (. self ~arg)))
            (setv opvals_ [])
            (when (and (= (len insn_.operands) 1)
                       insn_.regs-read)
              ;; There is an implicit first operand in rax, rdx:rax, or any of its subparts
              (let [implicit-lo (. insn_.regs-read [0])]
                (when (= (.get X86_GPR_MAP implicit-lo) X86_REG_RAX)
                  (setv rax_ (emu_.reg-read implicit-lo))
                  (.append opvals_
                           (if (= (len insn_.regs-read) 2)
                             (let [implicit-hi (. insn_.regs-read [1])]
                               (assert (= (.get X86_GPR_MAP implicit-hi) X86_REG_RDX) mnemonic_)
                               (setv rdx_ (emu_.reg-read implicit-hi))
                               (| (<< rdx_ (* 8 (. insn_.operands [0] size))) rax_))
                             rax_)))))
            (.extend opvals_ (lfor oparg insn_.operands (self._opval emu_ pc_ tick_ oparg (= mnemonic_ "lea"))))
            ~@expr-body))

     ~@(list-when jump-body
         `(defn [staticmethod] _do-jump? [emu_ insn_]
            (case insn_.id
             X86_INS_JRCXZ (= (emu_.reg-read X86_REG_RCX) 0)
             X86_INS_JECXZ (= (emu_.reg-read X86_REG_ECX) 0)
             X86_INS_JCXZ  (= (emu_.reg-read X86_REG_CX) 0)  
             else ((get X86_JUMP_TEST insn_.id) (emu_.reg-read X86_REG_EFLAGS)))) 
         `(defn _uop-jump [self emu_ insn_ pc_ target_ jmp-cond_]
            (setv &insn insn_
                  &pc pc_)
            ~@(gfor arg class-args `(setv ~arg (. self ~arg)))
            ~@jump-body))

     ;; this hook gets called *before* the instruction executes
     ~@(list-when (or write-body expr-body jump-body)
         `(defn instruction-hook [self emu_ pc_ insn-sz_ model_]
            ~@(list-when write-body
              `(self.finish-prev-insn emu_ (- model_.instruction-count 1)))
            (when (not-in pc_ cs-cache)
              (assoc cs-cache pc_
                     (-> (emu_.mem-read pc_ insn-sz_) (cs.disasm pc_) next InstructionInfo)))
            (setv insn_ (get cs-cache pc_))
            ;; TODO _uop-read would go here
            ~@(list-when expr-body
                `(let [tick_ model_.instruction-count
                       observation (self._uop-expr emu_ pc_ tick_ insn_)]
                   (when (is-not observation None)
                     (self.add-to-trace observation))))
            ~@(list-when jump-body
                `(setv tick_ model_.instruction-count)
                `(let [[target do-jump] (cond
                                          (insn_.group CS_GRP_JUMP) [(self._opval emu_ pc_ tick_
                                                                                  (. insn_.operands [0]) False)
                                                                     (self._do-jump? emu_ insn_)]
                                          (insn_.group CS_GRP_CALL) [(self._opval emu_ pc_ tick_
                                                                                  (. insn_.operands [0]) False)
                                                                     True]
                                          (insn_.group CS_GRP_RET)  [(emu_.mem-read (emu_.reg-read X86_REG_RSP) 8) True]
                                          True #(None None))
                       observation (if (is-not None do-jump)
                                     (self._uop-jump emu_ insn_ pc_ target do-jump)
                                     None)]
                   (when (is-not observation None)
                     (self.add-to-trace observation))))
            (setv self.prev-pc pc_)))

     )))

(defmacro defleakage [name init-args #* body]
  (_defmodel 'BaseTracer "Tracer" name init-args body))

(defmacro defpredictor [name init-args #* body]
  (_defmodel 'BasePredictor "Predictor" name init-args body))