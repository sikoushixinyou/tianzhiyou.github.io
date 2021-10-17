# TagMap模块的记录

 		在这篇学习记录里将对libdft64的重要模块之一的tagmap模块进行理解记 录，将会从其负责的主要功能，阴影内存与阴影寄存器设计的寻址方式，模块提供的接口函数，以及相比最初的32位的libdft的区别和一些不同设计这几个方面来对libdft64对tagmap模块进行学习记录。

---



## 主要功能

​		Tagmap 模块为注入被分析二进制可执行文件中的污点分析桩提供污点存储和污点操作功能。主要实现对被监控软件在 Linux x64 平台下进程地址空间以及每个线程通用寄存器中的数据进行标记，将数据的污点标记存储在影子内存 Mem_tag 以及影子寄存器 Reg_tag 对应的位置；并为 Tracker 和 I/O Interface 提供设置污点标记、清除污点标记以及获取污点标记等污点标记操作功能。

![tagmap模块示意图](/Users/tianzhiyou/Documents/tianzhiyou.github.io/photo/tagmap.png)

​		如图所示，Tagmap 为应用程序的进程虚拟地址空间以及线程通用寄存器保存污点标记的信息，它主要包括内存污点标记结构以及寄存器污点标记结构两个部分。内存污点标记结构为应用程序的每个进程存储进程内存空间数据的污点标记。根据 x64 虚拟地址空间结构，内存污点标记结构设计为类两级页表结构：其中 top_dir结构长度为 8M，存储指向二级表结构 page_table 的指针值；page_table 长度为 4K，存储指向 tag_page 结构的指针值；tag_page 结构存储实际的数据标记，长度为 4K，为对应虚拟地址数据存储其污点标记；此外，cleared_value 表示常数 0，表示该虚拟地址的数据没有被污染或者应用程序没有使用该内存空间。

​		寄存器污点标记结构 vcpu 用来为 x64 应用程序的每个执行线程存储 16 个通用寄存器数据的污点标记。vcpu 结构被设计为 16*8 的二维数组，为对应通用寄存器数据存储污点标记。

---

## 寻址设计

### 1.阴影内存的寻址设计

针对阴影内存的寻址，设计了top_dir, page_table, tag_page 的三级结构来帮助寻址，具体代码实现如下：

```c++
typedef struct {
  tag_t tag[PAGE_SIZE];//4096=2^12=4k
} tag_page_t;

typedef struct {
  tag_page_t *page[PAGETABLE_SZ];//0X1000=2^12 =4k
} tag_table_t;

typedef struct {
  tag_table_t *table[TOP_DIR_SZ];//0x800000=2^23 =8m
} tag_dir_t;
```

其中TOP_DIR_SZ通过宏定义为0x800000使得top_dir的结构长度为8M，PAGETABLE_SZ通过宏定义为0x1000使得page_table的结构长度为4k，PAGE_SIZE通过宏定义为4096使得tag_page的结构长度为4k。

​		当传入一个内存地址addr时，将通过三步来寻址到该addr所对应的阴影内存，下面来详细说明这三步的过程与实现。

首先明确64位linux一般使用48位来表示虚拟地址空间，使用40位来表示物理地址空间。其中，0x0000000000000000到0x00007fffffffffff 表示用户空间，用户空间的第48位其实没有用，一直是0，用户空间可用的是有47位 ，剩下的从0xFFFF800000000000到0xFFFFFFFFFFFFFFFF 表示内核空间，

（1）第一步设计一个 VIRT2PAGETABLE(addr) 的函数对adrr进行右移24位操作，即取出48位地址的高24位，由于用户空间可用为47位，故实际能访问的位数是23位，则寻址范围是到2^23=8M。通过第一步就完成了对内存地址addr在第一级结构top_dir的寻址。

（2）第二步设计一个 VIRT2PAGE(addr) 的函数对addr取低24位后，再取这24位中的高12位作为二级寻址地址，寻则址范围是2^12=4k。通过第二步就完成了对内存地址addr在第二级结构page_table的寻址。

（3）第三步设计一个 VIRT2OFFSET(addr) 函数来执行addr与0x00000FFFU（32位U的意思是无符号整型）逐位做“与”运算，通过这种运算来取addr的低12位作为三级寻址地址，寻则址范围是2^12=4k。通过第三步之后就完成了对内存地址addr在第三级结构tag_page的寻址。

​		总的来说就是对于一个48位的内存地址addr，通过对其高24位（实际有用的是23位）寻址top_dir，再用低24位中的高12位寻址page_table，最后用其低12位寻址tag_page就可以获得该内存地址addr的所对应储存数据标签的阴影内存位置

---

### 2.阴影寄存器寻址设计

对于阴影寄存器vcpu的实现如下：

```c++
typedef struct {
  // general purpose registers (GPRs)通用寄存器
  tag_t gpr[GRP_NUM + 1][TAGS_PER_GPR];//[43+1][32]
} vcpu_ctx_t;
```

其中tag_t类型是32位的无符号整型，设计了一个叫做gpr的二维数组来储存来对应寄存器的数据标签，定义了GRP_NUM值为43，TAGS_PER_GPR值为32。实际43个值每个都对应来一个寄存器，具体定义如下：

```c++
#define DFT_REG_RDI 3
#define DFT_REG_RSI 4
#define DFT_REG_RBP 5
#define DFT_REG_RSP 6
#define DFT_REG_RBX 7
#define DFT_REG_RDX 8
#define DFT_REG_RCX 9
#define DFT_REG_RAX 10
#define DFT_REG_R8 11
#define DFT_REG_R9 12
#define DFT_REG_R10 13
#define DFT_REG_R11 14
#define DFT_REG_R12 15
#define DFT_REG_R13 16
#define DFT_REG_R14 17
#define DFT_REG_R15 18
#define DFT_REG_XMM0 19
#define DFT_REG_XMM1 20
#define DFT_REG_XMM2 21
#define DFT_REG_XMM3 22
#define DFT_REG_XMM4 23
#define DFT_REG_XMM5 24
#define DFT_REG_XMM6 25
#define DFT_REG_XMM7 26
#define DFT_REG_XMM8 27
#define DFT_REG_XMM9 28
#define DFT_REG_XMM10 29
#define DFT_REG_XMM11 30
#define DFT_REG_XMM12 31
#define DFT_REG_XMM13 32
#define DFT_REG_XMM14 33
#define DFT_REG_XMM15 34
#define DFT_REG_ST0 35
#define DFT_REG_ST1 36
#define DFT_REG_ST2 37
#define DFT_REG_ST3 38
#define DFT_REG_ST4 39
#define DFT_REG_ST5 40
#define DFT_REG_ST6 41
#define DFT_REG_ST7 42
#define DFT_REG_HELPER1 0
#define DFT_REG_HELPER2 1
#define DFT_REG_HELPER3 2
```

vcpu结构的设计使得libdft64可以适用于多线程的场景，由于一个进程下的多个线程是共享其内存空间，所以每个线程的阴影内存也是共享同一个的，但是对于阴影寄存器就需要每个线程有自己独立的阴影寄存器，为了要做到这个目的实现了下面的一个结构：

```c++
/* thread context definition */
typedef struct {
  vcpu_ctx_t vcpu;           /* VCPU context */
  syscall_ctx_t syscall_ctx; /* syscall context */
  UINT32 syscall_nr;
} thread_ctx_t;
```

对于每个线程根据其线程tid的不同都会有一个唯一的thread_ctx_t结构来标识该线程，thread_ctx_t结构中就包含有一个vcpu结构，这样就做到了针对每个线程都可以通过不同的线程tid来唯一的构建其对应的阴影寄存器vcpu。

---

## TagMap接口函数

tanmap模块提供了一些接口函数如下，下面将对每个接口函数做说明

```c++
void tagmap_setb(ADDRINT addr, tag_t const &tag);
void tagmap_setb_reg(THREADID tid, unsigned int reg_idx, unsigned int off,tag_t const &tag);

tag_t tagmap_getb(ADDRINT addr);
tag_t tagmap_getb_reg(THREADID tid, unsigned int reg_idx, unsigned int off);

tag_t tagmap_getn(ADDRINT addr, unsigned int n);
tag_t tagmap_getn_reg(THREADID tid, unsigned int reg_idx, unsigned int n);

void tagmap_clrb(ADDRINT addr);
void tagmap_clrn(ADDRINT, UINT32);
```



### tagmap_setb（）函数

​		该接口函数接受两个传入参数addr与tag，其内部实现逻辑是按照之前的寻址方法对传入参数addr寻址（若是寻找为空就新建并用0填充初始化）然后将传入参数tag作为新的标签值存放在对应的addr阴影内存中。

```c++
void tagmap_setb(ADDRINT addr, tag_t const &tag) {
  tag_dir_setb(tag_dir, addr, tag);
}

//根据传入的dir与addr与寻址dir-table-page-tag【addr】（寻找为空就新建并用0填充初始化）然后赋值为传入参数的tag
inline void tag_dir_setb(tag_dir_t &dir, ADDRINT addr, tag_t const &tag) {
  if (addr > 0x7fffffffffff) {
    return;
  }
  // LOG("Setting tag "+hexstr(addr)+"\n");
  //VIRT2PAGETABLE(addr)对adrr进行右移24位操作，保留高24位，寻址范围到2^23=8M
  //无符号数值右移n位：最右边n位被丢弃，最左边用0填补。
  //64位linux一般使用48位来表示虚拟地址空间，使用40位来表示物理地址空间
  //其中，0x0000000000000000~0x00007fffffffffff 表示用户空间，用户空间的第48位其实没有用，一直是0 
  //0xFFFF800000000000~ 0xFFFFFFFFFFFFFFFF 表示内核空间，
  if (dir.table[VIRT2PAGETABLE(addr)] == NULL) {
    //  LOG("No tag table for "+hexstr(addr)+" allocating new table\n");
    tag_table_t *new_table = new (std::nothrow) tag_table_t();
    if (new_table == NULL) {
      LOG("Failed to allocate tag table!\n");
      libdft_die();
    }
    dir.table[VIRT2PAGETABLE(addr)] = new_table;
  }

  tag_table_t *table = dir.table[VIRT2PAGETABLE(addr)];
  //VIRT2PAGE(addr)对addr取低24位后再取这24位中的高12位，寻址范围是2^12=4k
  if ((*table).page[VIRT2PAGE(addr)] == NULL) {//addr与0x00FFFFFFU逐位做与运算后再右移动12位
    //    LOG("No tag page for "+hexstr(addr)+" allocating new page\n");
    tag_page_t *new_page = new (std::nothrow) tag_page_t();
    if (new_page == NULL) {
      LOG("Failed to allocate tag page!\n");
      libdft_die();
    }
    std::fill(new_page->tag, new_page->tag + PAGE_SIZE,
              tag_traits<tag_t>::cleared_val);//用0填充
    (*table).page[VIRT2PAGE(addr)] = new_page;
  }

  tag_page_t *page = (*table).page[VIRT2PAGE(addr)];
  (*page).tag[VIRT2OFFSET(addr)] = tag;
  //addr与0x00000FFFU（32位U的意思是无符号整型）逐位做“与”运算取addr的低12位
  /*
  if (!tag_is_empty(tag)) {
    LOGD("[!]Writing tag for %p \n", (void *)addr);
  }
  */
}

```



### tagmap_setb_reg（）函数

​		该接口函数接受四个传入参数tid ，reg_idx， off， tag，按照如下方式

```c++
threads_ctx[tid].vcpu.gpr[reg_idx][off] = tag;

```

去访问到指定的线程的指定阴影寄存器的指定标签位置，然后将该位置的标签值赋值为传入参数tag。



### tagmap_getb（）函数

​		该接口函数接受一个传入参数addr，该函数寻址访问参数addr对应的阴影内存后返回该阴影内存储存的标签值。如果查找为空的话就返回cleared_val（该值为0）。

```c++
tag_t tagmap_getb(ADDRINT addr) { return *tag_dir_getb_as_ptr(tag_dir, addr); }

//根据传入参数dir与addr，去寻址并返回dir结构中addr地址对应的标签
inline tag_t const *tag_dir_getb_as_ptr(tag_dir_t const &dir, ADDRINT addr) {
  if (addr > 0x7fffffffffff) {
    return NULL;
  }
  if (dir.table[VIRT2PAGETABLE(addr)]) {
    tag_table_t *table = dir.table[VIRT2PAGETABLE(addr)];
    if ((*table).page[VIRT2PAGE(addr)]) {
      tag_page_t *page = (*table).page[VIRT2PAGE(addr)];
      if (page != NULL)
        return &(*page).tag[VIRT2OFFSET(addr)];
    }
  }
  return &tag_traits<tag_t>::cleared_val;
}

```



### tagmap_getb_reg（）函数

​		该接口函数接受三个传入参数tid ，reg_idx， off，去访问到指定的线程的指定阴影寄存器的指定标签位置，最后返回该标签位置的标签值。

```c++
//返回寄存器的标签值
tag_t tagmap_getb_reg(THREADID tid, unsigned int reg_idx, unsigned int off) {
  return threads_ctx[tid].vcpu.gpr[reg_idx][off];
}
```



### tagmap_getn()函数

​		该接口函数与tagmap_getb类似，区别在于根据传入参数addr寻找访问到对应阴影内存后，该函数返回的是从此阴影内存的位置的再往后的n个位置的标签值，其中n也是传入参数之一。

```c++
//返回dir结构中addr的位置再往后的n个位置的标签值
tag_t tagmap_getn(ADDRINT addr, unsigned int n) {
  tag_t ts = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < n; i++) {
    const tag_t t = tagmap_getb(addr + i);
    if (tag_is_empty(t))
      continue;
    // LOGD("[tagmap_getn] %lu, ts: %d, %s\n", i, ts, tag_sprint(t).c_str());
    ts = tag_combine(ts, t);//与0逐位做“或”运算还是其本身
    // LOGD("t: %d, ts:%d\n", t, ts);
  }
  return ts;
}
```



### tagmap_getn_reg（）函数

​		该接口函数与tagmap_getb_reg（）类似，区别在于访问到指定的线程的指定阴影寄存器的指定标签位置，最后返回该标签位置的再往后的n个标签值，其中n也是传入参数之一。

```c++
//返回对应线程的threads_ctx[tid].vcpu.gpr[reg_idx][传入参数n个]的n个标签值
tag_t tagmap_getn_reg(THREADID tid, unsigned int reg_idx, unsigned int n) {
  tag_t ts = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < n; i++) {
    const tag_t t = tagmap_getb_reg(tid, reg_idx, i);
    if (tag_is_empty(t))
      continue;
    // LOGD("[tagmap_getn] %lu, ts: %d, %s\n", i, ts, tag_sprint(t).c_str());
    ts = tag_combine(ts, t);
    // LOGD("t: %d, ts:%d\n", t, ts);
  }
  return ts;
}
```



### tagmap_clrb（）函数

​		该接口函数访问到addr对应的阴影内存位置后置零标签值。

```c++
//把dir结构中的addr位置标签值置0
void PIN_FAST_ANALYSIS_CALL tagmap_clrb(ADDRINT addr) {
  tagmap_setb(addr, tag_traits<tag_t>::cleared_val);
}
```



### tagmap_clrn（）函数

​		该接口函数访问到addr对应的阴影内存位置后面的n个标签值都置0。

```c++
//根据传入参数把dir结构中从addr位置起后面的n个标签值都置0
void PIN_FAST_ANALYSIS_CALL tagmap_clrn(ADDRINT addr, UINT32 n) {
  ADDRINT i;
  for (i = addr; i < addr + n; i++) {
    tagmap_clrb(i);
  }
}
```

---

## libdft64与32位的libdft的不同

​		如图所示，根据libdft: Practical Dynamic Data Flow Tracking for Commodity System这篇论文中所描述的32位的libdft中的vcpu结构储存的是每个标签采取一字节到大小，每个通用寄存器使用4个标签来标记，32位的系统中共有8个通用寄存器，所以整个32位下的vcpu结构实现应该需要32字节。

![32vcpu](/Users/tianzhiyou/Documents/tianzhiyou.github.io/photo/32vcpu.png)

具体的代码实现如下：

```c++
typedef struct {
	/*
	 * general purpose registers (GPRs)
	 *
	 * we assign one bit of tag information for
	 * for every byte of addressable memory; the 32-bit
	 * GPRs of the x86 architecture will be represented
	 * with 4 bits each (the lower 4 bits of a 32-bit
	 * unsigned integer)
	 *
	 * NOTE the mapping:
	 * 	0: EDI
	 * 	1: ESI
	 * 	2: EBP
	 * 	3: ESP
	 * 	4: EBX
	 * 	5: EDX
	 * 	6: ECX
	 * 	7: EAX
	 * 	8: scratch (not a real register; helper) 
	 */
	uint32_t gpr[GRP_NUM + 1];
} vcpu_ctx_t;
```

gpr数组设计为uint32_t，即32位无符号整型，占4个字节正好就是一个通用寄存器所需要的标签空间大小。

​		对与64位的系统，首先通用寄存器变化位有16个，同时每个寄存器不再是用4个一字节的标签来标记，应该变为使用8个标签来标记，如图所示。

![64vcpu](/Users/tianzhiyou/Documents/tianzhiyou.github.io/photo/64vcpu.png)

按照图上的设计，64位下的vcpu结构应该是一个16x8二维数据结构，但是在如下的实际代码实现中，gpr是一个43x32的二维结构，其中43是由于加入了除了16个通用寄存器外的其他的寄存器所对应的阴影寄存器。

```c++
typedef struct {
  // general purpose registers (GPRs)通用寄存器
  tag_t gpr[GRP_NUM + 1][TAGS_PER_GPR];//[43+1][32]
} vcpu_ctx_t;
```

