/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Georgios Portokalidis <porto@cs.columbia.edu> contributed to the
 * optimized implementation of tagmap_setn() and tagmap_clrn()
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "tagmap.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

tag_dir_t tag_dir;
extern thread_ctx_t *threads_ctx;

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

// PIN_FAST_ANALYSIS_CALL
//tagmap_setb = tag_dir_setb ？参数tag_dir怎么获取？
//根据传入参数设置dir中addr位置的标签值
void tagmap_setb(ADDRINT addr, tag_t const &tag) {
  //根据传入的dir与addr与寻址dir-table-page-tag【addr】（寻找为空就新建并用0填充初始化）然后赋值为传入参数的tag
  tag_dir_setb(tag_dir, addr, tag);
}

//tag_t类型其实是无符号整型
//根据传入参数设置对应位置的寄存器标签值
void tagmap_setb_reg(THREADID tid, unsigned int reg_idx, unsigned int off,
                     tag_t const &tag) {
  threads_ctx[tid].vcpu.gpr[reg_idx][off] = tag;
}

//返回在dir结构中addr对应的标签值
tag_t tagmap_getb(ADDRINT addr) { return *tag_dir_getb_as_ptr(tag_dir, addr); }

//返回寄存器的标签值
tag_t tagmap_getb_reg(THREADID tid, unsigned int reg_idx, unsigned int off) {
  return threads_ctx[tid].vcpu.gpr[reg_idx][off];
}

//把dir结构中的addr位置标签值置0
void PIN_FAST_ANALYSIS_CALL tagmap_clrb(ADDRINT addr) {
  tagmap_setb(addr, tag_traits<tag_t>::cleared_val);
}

//根据传入参数把dir结构中从addr位置起后面的n个标签值都置0
void PIN_FAST_ANALYSIS_CALL tagmap_clrn(ADDRINT addr, UINT32 n) {
  ADDRINT i;
  for (i = addr; i < addr + n; i++) {
    tagmap_clrb(i);
  }
}

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
