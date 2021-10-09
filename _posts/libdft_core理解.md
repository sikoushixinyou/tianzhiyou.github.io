## 主要内容

这个代码主要实现的是一个如下的接口函数

```c++
void ins_inspect(INS ins)
```

它的主要实现功能是根据传入的指令ins进行分情况的对该指令调用不同的代码进行对指令的插桩

虽然源代码对于传入的ins指令分类很多，但是大多数分类都是不进行任何操作，以下将会对进行调用操作的情况来截取进行理解

### ins分类情况理解

```c++
switch (ins_indx)      //根据不同的指令分情况查桩
```

主要是通过传入指令的opencode（即用变量ins_indx表示）来判断该指令属于哪一个类型

---

#### 有效情况XED_ICLASS_POR

```c++
case XED_ICLASS_POR:
    ins_binary_op(ins);   //根据指令的两个操作数情况（内存，寄存器）查桩
    break;
```

对于类型XED_ICLASS_POR的指令，调用ins_binary_op函数进行插桩，此函数具体实现如下：

```c++
void ins_binary_op(INS ins) {   //根据指令的两个操作数情况（内存，寄存器）进行调用查桩
  if (INS_OperandIsImmediate(ins, OP_1))  //如果第二个操作数是立即数
    return;
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {   //如果内存操作数数量为0
    reg_dst = INS_OperandReg(ins, OP_0);    //返回第一个操作数寄存器的名称
    reg_src = INS_OperandReg(ins, OP_1);    //返回第二个操作数寄存器的名称
    if (REG_is_gr64(reg_dst)) {      //通用64位寄存器
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {        //通用32位寄存器
      R2R_CALL(r2r_binary_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {        //通用16位寄存器
      R2R_CALL(r2r_binary_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {         //SSE寄存器
      R2R_CALL(r2r_binary_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {         //YMM寄存器
      R2R_CALL(r2r_binary_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {         //MMX位寄存器
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))  //两个寄存器都是低8位
        R2R_CALL(r2r_binary_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))  //两个寄存器都是高8位
        R2R_CALL(r2r_binary_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))             //第一个寄存器是低8位
        R2R_CALL(r2r_binary_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(r2r_binary_opb_ul, reg_dst, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {   //如果第二个操作数是内存引用
    reg_dst = INS_OperandReg(ins, OP_0);   //返回第一个操作数寄存器的名称
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_binary_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_binary_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_binary_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_binary_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_binary_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_binary_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);  //返回第二个操作数寄存器的名称
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_binary_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_binary_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_binary_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_binary_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_binary_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_binary_opb_l, reg_src);
    }
  }
}

```

ins_binary_op函数主要是实现根据传入的指令的第一与第二个操作数操作情况，都是寄存器（寄存器又再细分为通用64，32，16位寄存器，高低8位寄存器，SSE，YMM，MMX寄存器几种不同情况）或者寄存器与内存引用的不同组合情况来选择不同的插桩代码。

---

#### 有效情况XED_ICLASS_XORPD

```c++
case XED_ICLASS_XORPD:
    if (reg_eq(ins)) {    //判断是否第一二个操作数都是寄存器且是同一个寄存器
      ins_clear_op(ins);  //根据指令操作数不同情况来调用清除污点
    } else {
      ins_binary_op(ins);  //根据指令的两个操作数情况（内存，寄存器）查桩
    }
    break;
```

对于类型XED_ICLASS_XORPD的情况：

先判断是否指令的两个操作数都是寄存器且是同一个，如果是的话该指令执行的其实是置零操作，这种情况应该调用对应的插桩代码 ins_clear_op来清除污点。

不是这种情况就正常根据指令的两个操作数情况（内存，寄存器）调用ins_binary_op来进行插桩污点标记。

其中ins_clear_op实现如下：

```c++
void ins_clear_op(INS ins) {  //根据指令操作数不同情况来调用清除污点
  if (INS_OperandIsMemory(ins, OP_0)) {   //第一操作数为内存引用
    INT32 n = INS_OperandWidth(ins, OP_0) / 8;  //以字节为单位返回操作数宽度
    M_CLEAR_N(n);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);  //返回第一操作数为寄存器的名称
    if (REG_is_gr64(reg_dst)) {   //通用64位寄存器
      R_CALL(r_clrq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {  //通用32位寄存器
      R_CALL(r_clrl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {  //通用16位寄存器
      R_CALL(r_clrw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {  //SSE寄存器
      R_CALL(r_clrx, reg_dst);
    } else if (REG_is_mm(reg_dst)) {  //MMX位寄存器
      R_CALL(r_clrq, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {  //YMM寄存器
      R_CALL(r_clry, reg_dst);
    } else {
      if (REG_is_Upper8(reg_dst))  //高8位寄存器     R_CALL=INS_InsertCall
        R_CALL(r_clrb_u, reg_dst);
      else
        R_CALL(r_clrb_l, reg_dst);
    }
  }
}
```

其实现的主要逻辑是实现根据传入的指令的第一与第二个操作数操作情况，都是寄存器（寄存器又再细分为通用64，32，16位寄存器，高低8位寄存器，SSE，YMM，MMX寄存器几种不同情况）或者寄存器与内存引用的不同组合情况来选择不同的插桩代码来进行污点清除。

---

#### 有效情况XED_ICLASS_MUL

```c++
case XED_ICLASS_MUL:
    ins_unitary_op(ins);  //根据指令的第一个操作数情况（内存，寄存器）查桩
    break;
```

对于XED_ICLASS_MUL类型情况：

调用ins_unitary_op根据指令的第一个操作数情况（内存，寄存器）查桩进行污点标记。

ins_unitary_op的具体实现如下：

```c++
void ins_unitary_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0))   //第一个操作数是内存引用
    switch (INS_MemoryWriteSize(ins)) {  //返回以字节为单位的内存写入大小
    case BIT2BYTE(MEM_64BIT_LEN):      //将64位的长度进行右移3位
      M_CALL_R(m2r_unitary_opq);
      break;
    case BIT2BYTE(MEM_LONG_LEN):      //将32位的长度进行右移3位
      M_CALL_R(m2r_unitary_opl);
      break;
    case BIT2BYTE(MEM_WORD_LEN):       //将16位的长度进行右移3位
      M_CALL_R(m2r_unitary_opw);
      break;
    case BIT2BYTE(MEM_BYTE_LEN):      //将8位的长度进行右移3位
    default:
      M_CALL_R(m2r_unitary_opb);
      break;
    }
  else {
    REG reg_src = INS_OperandReg(ins, OP_0);    //返回第一个操作数寄存器名称
    if (REG_is_gr64(reg_src))
      R_CALL(r2r_unitary_opq, reg_src);
    else if (REG_is_gr32(reg_src))
      R_CALL(r2r_unitary_opl, reg_src);
    else if (REG_is_gr16(reg_src))
      R_CALL(r2r_unitary_opw, reg_src);
    else if (REG_is_Upper8(reg_src))
      R_CALL(r2r_unitary_opb_u, reg_src);
    else
      R_CALL(r2r_unitary_opb_l, reg_src);
  }
}
```

在调用ins_unitary_op函数时候，其本身逻辑也是判断指令的操作数情况是内存引用（细分到内存引用操作的写入大小分情况）还是寄存器操作（细分到通用64，32，16位寄存器以及高低8位寄存器情况）来进行相应类型的插桩污点标记

但是此函数的调用是默认其传入指令ins的第二个操作数一定是寄存器操作，由此只对第一个操作数的情况来进行判断分类这点的逻辑与ins_binary_op函数有着明显的差别。

---

#### 有效情况XED_ICLASS_DIVSD

```c++
case XED_ICLASS_DIVSD:
    ins_binary_op(ins);         //根据指令的两个操作数情况（内存，寄存器）查桩
```

对于XED_ICLASS_DIVSD类型的情况：

也是根据指令的两个操作数情况（内存，寄存器）调用ins_binary_op查桩进行污点标记

---

#### 有效情况XED_ICLASS_MOV

```c++
case XED_ICLASS_MOV:
    if (INS_OperandIsImmediate(ins, OP_1) || //如果第二个操作数是立即数或者
        (INS_OperandIsReg(ins, OP_1) &&      //第二个操作数是寄存器且是段寄存器
         REG_is_seg(INS_OperandReg(ins, OP_1)))) {
      ins_clear_op(ins);             //根据指令操作数不同情况来调用清除污点
    } else {
      ins_xfer_op(ins);           // //根据指令的两个操作数情况（内存，寄存器）插桩
    }
    break;
```

对于情况XED_ICLASS_MOV的分类情况：

首先判断如果指令的第二个操作数是立即数或者第二个操作数是寄存器且是段寄存器，这种情况就调用ins_clear_op根据指令操作数不同情况来调用清除污点进行污点清除

不是以上这两种情况的话就调用ins_xfer_op来根据指令的两个操作数情况（内存，寄存器）进行插桩污点标记

ins_xfer_op函数的具体实现如下：

```c++
void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {  //如果内存操作数数量为0，然后返回两个寄存器的名称
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {        //判断第一个寄存器的具体情况（64，32，16，SSE，YMM，MMX）
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_xfer_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_xfer_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {//判断两个寄存器组合情况（高低8位）
        R2R_CALL(r2r_xfer_opb_l, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_u, reg_dst, reg_src);
      } else if (REG_is_Lower8(reg_dst)) {
        R2R_CALL(r2r_xfer_opb_lu, reg_dst, reg_src);
      } else {
        R2R_CALL(r2r_xfer_opb_ul, reg_dst, reg_src);
      }
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {//如果第二个操作数是内存引用
    reg_dst = INS_OperandReg(ins, OP_0);//返回第一个操作寄存器名称后分类讨论调用情况
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_xfer_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_xfer_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_xfer_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opb_l, reg_dst);
    }
  } else {  //判断第二个寄存器的具体情况（64，32，16，SSE，YMM，MMX）
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_xfer_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_xfer_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_xfer_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opb_l, reg_src);
    }
  }
}

```

其主要的实现逻辑是：通过把传入指令ins的操作数大的分为（1）两个操作数都是寄存器；（2）第一个操作数是寄存器第二个操作数是内存引用；（3）第一个操作数是内存引用第二个操作数是寄存器；这三种分类之下再通过对寄存器的类型进行细化的分类来对应调用代码插桩进行污点标记。

---

#### 有效情况XED_ICLASS_CVTSD2SI

```c++
case XED_ICLASS_CVTSD2SI:
    ins_xfer_op(ins);         //根据指令的两个操作数情况（内存，寄存器）插桩
    break;
```

对于XED_ICLASS_CVTSD2SI情况：

根据指令的两个操作数情况（内存，寄存器）调用ins_xfer_op插桩进行污点标记

---

#### 有效情况XED_ICLASS_MOVLPS

```c++
case XED_ICLASS_MOVLPS:
    ins_movlp(ins);      //根据第一个操作数是内存引用还是寄存器来插桩
    break;
```

对于XED_ICLASS_MOVLPS情况：

根据第一个操作数是内存引用还是寄存器来调用ins_movlp插桩

具体的ins_movlp函数实现如下：

```c++
void ins_movlp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {   //如果第一个操作数是内存引用
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq, reg_src);
  } else {      //否则第一个操作数是寄存器
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq, reg_dst);
  }
}
```

其主要逻辑是：判断指令第一个操作数是内存引用还是寄存器，但是并不对内存引用或是寄存器再往下细分，然后进行相应的调用来污点标记

---

#### 有效情况XED_ICLASS_MOVHPS

```c++
case XED_ICLASS_MOVHPS:
    ins_movhp(ins);      //根据第一个操作数是内存引用还是寄存器来插桩
    break;
```

对于XED_ICLASS_MOVHPS情况采取的方式与XED_ICLASS_MOVLPS情况基本相似

其中ins_movhp与ins_movlp的区别在于ins_movhp所实现的所调用Pin工具接口是正常接口的_predicate模式，此模式下的接口实现的目的与原版接口相同，是增加了针对当指令存在谓词且谓词为假的时候的处理情况，其余基本相同

---

#### 有效情况XED_ICLASS_CMOVZ

```c++
case XED_ICLASS_CMOVZ:
    ins_xfer_op_predicated(ins); 
    //与ins_xfer_op相似，区别在于第一操作数必定为寄存器且只分类了通用64，32，16三种情况  
    break;
```

对于XED_ICLASS_CMOVZ情况：

这种情况是调用了ins_xfer_op_predicated函数进行插桩污点标记，与ins_xfer_op相似，区别在于第一操作数必定为寄存器且只分类了通用64，32，16位三种情况 ，底层pin工具接口调用的是加入了指令存在谓词且谓词为假的时候的处理情况。

---

#### 有效情况XED_ICLASS_STMXCSR

```c++
case XED_ICLASS_STMXCSR:
    ins_clear_op(ins);         //根据指令操作数不同情况来调用清除污点
    break;
```

#### 有效情况XED_ICLASS_LAR

```c++
 case XED_ICLASS_LAR:
    ins_clear_op(ins);       //根据指令操作数不同情况来调用清除污点
    break;
```

#### 有效情况XED_ICLASS_RDTSC

```c++
case XED_ICLASS_RDTSC:
    ins_clear_op_l2(ins);  //不对操作数分情况直接调用插入r_clrl2
    break;
```

XED_ICLASS_RDTSC情况下也是调用ins_clear_op_l2函数来清除污点，但是这个函数不同于ins_clear_op在于，它不对操作数分情况分类对应调用而是确定的直接调用插入代码

#### 有效情况XED_ICLASS_CPUID

```c++
case XED_ICLASS_CPUID:
    ins_clear_op_l4(ins);  //不对操作数分情况直接调用插入r_clrl4
    break;
```

---

#### 有效情况XED_ICLASS_LAHF

```c++
case XED_ICLASS_LAHF:
    ins_clear_op(ins);        //根据指令操作数不同情况来调用清除污点
    break;
```

---

#### 有效情况XED_ICLASS_CMPXCHG_LOCK

```c++
case XED_ICLASS_CMPXCHG_LOCK:
    ins_cmpxchg_op(ins);
    //根据操作数情况分类插入funptr调用，并根据funptr是否返回非零地址来执行then分析调用
    break;
```

对于XED_ICLASS_CMPXCHG_LOCK这种情况，所调用的ins_cmpxchg_op插桩函数就进行sink点的检测，整体有两部完成，根据操作数情况分类插入funptr调用，并根据funptr是否返回非零地址来执行then分析调用

ins_cmpxchg_op的具体实现如下：

```c++
void ins_cmpxchg_op(INS ins) {
//根据操作数情况分类插入funptr调用，并根据funptr是否返回非零地址来执行then分析调用
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {  //r2r情况
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {//第一寄存器为64
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opq_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opq_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr32(reg_dst)) {//第一寄存器为32
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opl_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opl_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr16(reg_dst)) {//第一寄存器为16
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opw_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_AX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opw_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else {
      xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
      LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) +
          ")\n");
    }
  } else {   //m2r情况
    reg_src = INS_OperandReg(ins, OP_1);  //第二寄存器情况分类（64，32，16）
    if (REG_is_gr64(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opq_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opq_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr32(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opl_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opl_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr16(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opw_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_AX, IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opw_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else {
      xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
      LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) +
          ")\n");
    }
  }
}

```

其整体逻辑为根据操作数大情况分为r2r，m2r的情况，再针对操作寄存器的具体类型不同细分后进行插入funptr调用与then调用来作为sink检测点，检测逻辑本身会先执行funptr调用并根据funptr是否返回非零地址来执行then分析调用。

r2r表示：数据操作是从寄存器到寄存器，即指令的第一和第二两个操作数都是寄存器

m2r表示：数据操作是从内存到寄存器，即指令的第一个操作数是内存第二个操作数是寄存器

---

#### 有效情况XED_ICLASS_XCHG

```c++
case XED_ICLASS_XCHG:
    ins_xchg_op(ins);      //根据操作数情况分类（r2r,m2r,r2m）插桩
    break;
```

---

#### 有效情况XED_ICLASS_XADD_LOCK

```c++
case XED_ICLASS_XADD_LOCK:
    ins_xadd_op(ins);       //根据操作数情况分类（r2r,r2m）插桩
    break;
```

---

#### 有效情况XED_ICLASS_XLAT，XED_ICLASS_LODSB，XED_ICLASS_LODSW，XED_ICLASS_LODSD，XED_ICLASS_LODSQ

```c++
case XED_ICLASS_XLAT: //以下几个不考虑操作数情况直接调用插桩，_P表示有谓词为假处理机制
    M2R_CALL(m2r_xfer_opb_l, REG_AL);   //M2R_CALL=INS_InsertCall
    break;
  case XED_ICLASS_LODSB:
    M2R_CALL_P(m2r_xfer_opb_l, REG_AL);   //M2R_CALL_P=INS_InsertPredicatedCall
    break;
  case XED_ICLASS_LODSW:
    M2R_CALL_P(m2r_xfer_opw, REG_AX);
    break;
  case XED_ICLASS_LODSD:
    M2R_CALL_P(m2r_xfer_opl, REG_EAX);
    break;
  case XED_ICLASS_LODSQ:
    M2R_CALL_P(m2r_xfer_opq, REG_RAX);
    break;
```

上述点几个情况都是不考虑操作数情况直接调用确定行的插桩，_P表示有谓词为假处理机制

其中M2R_CALL=INS_InsertCall，M2R_CALL_P=INS_InsertPredicatedCall

这是通过宏定义给pin工具的API接口换了一个名称，本质还是调用的pin工具的接口。

---

#### 有效情况

```c++
case XED_ICLASS_STOSB:
    ins_stosb(ins);    //根据指令是否有重复前缀REPNE (0xF2)来选择是否进行sink点检测
    break;

```

对于XED_ICLASS_STOSB的情况：

调用ins_stosb来执行插桩sink点检查，但是会多有一个判断，根据指令是否有重复前缀REPNE (0xF2)来选择是否进行sink点检测。

具体实现如下：

```c++
//根据指令是否有重复前缀REPNE (0xF2)来选择是否进行sink点检测
void ins_stosb(INS ins) {  
  if (INS_RepPrefix(ins)) {   //如果指令具有 REPNE (0xF2) 重复前缀，则为 true
  //插入funptr调用并根据返回地址情况调用then（具有谓词机制）sink点检测
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opbn);
  } else {  //否则采取一般插桩
    R2M_CALL(r2m_xfer_opb_l, REG_AL);
  }
}

//插入funptr调用并根据返回地址情况调用then（具有谓词机制）
void ins_stos_ins(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_END);
}
```

基本实现逻辑是通过先判断传入指令是否具有 REPNE (0xF2) 重复前缀，有的话调用ins_stos_ins进行插入funptr调用并根据返回地址情况调用then（具有谓词机制），若是没有 REPNE (0xF2) 重复前缀则调用R2M_CALL进行插桩污点标记