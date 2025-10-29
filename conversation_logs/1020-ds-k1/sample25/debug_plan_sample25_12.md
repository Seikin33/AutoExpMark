基于提供的全局内存信息和exp执行历史，我设计了一个调试计划来探索当前局部内存状态。重点包括：验证堆布局完整性、检查fastbin攻击链（特别是0x70 bin）、确认unsorted bin状态、查看关键数据结构（chunk和size数组）、以及检查伪造的chunk地址是否有效。以下是详细的pwndbg命令和执行理由：

### 调试计划
1. **查看完整堆布局**  
   - 命令: `RunPwndbgCommand("heap")`  
   - 理由: 获取所有chunk的详细信息，包括地址、大小和元数据，以验证堆布局是否与exp预期一致，并识别任何异常chunk。

2. **详细检查fastbins链**  
   - 命令: `RunPwndbgCommand("fastbins")`  
   - 理由: 确认fastbin 0x70的链表状态（当前指向0x626eff3031f0 → 0x707629ac8aed），确保链表完整且fd指针正确指向伪造的chunk地址，这是fastbin攻击的关键。

3. **检查unsorted bin状态**  
   - 命令: `RunPwndbgCommand("unsortedbin")`  
   - 理由: 验证unsorted bin是否仍指向main_arena+88（0x707629ac8b78），确保libc泄漏后堆状态稳定，无意外变化。

4. **查看chunk数组内容**  
   - 命令: `RunPwndbgCommand("telescope 0x626ed0a02260 20")`  
   - 理由: chunk数组（地址0x626ed0a02260）存储各chunk的数据指针，检查其值是否与堆布局一致，特别是索引2的chunk（已修改为指向fake_chunk）。

5. **查看size数组内容**  
   - 命令: `RunPwndbgCommand("telescope 0x626ed0a020c0 20")`  
   - 理由: size数组（地址0x626ed0a020c0）存储各chunk的大小，验证大小值是否与分配时一致，避免大小错误影响利用。

6. **检查chunk[2]的内存内容**  
   - 命令: `RunPwndbgCommand("hexdump 0x626eff303200")`  
   - 理由: chunk[2]的数据区域（0x626eff303200）被exp修改为fake_chunk地址，检查其内容是否正确写入p64(fake_chunk)。

7. **验证伪造chunk的内存布局**  
   - 命令: `RunPwndbgCommand("hexdump 0x707629ac8aed")`  
   - 理由: fake_chunk地址（0x707629ac8aed = __malloc_hook - 0x23）是fastbin攻击的目标，检查该处内存是否具有有效的fastbin大小字段（应为0x7f或其他合法值）。

8. **继续程序执行**  
   - 命令: `RunPwndbgCommand("continue")`  
   - 理由: 以上命令已覆盖关键内存状态检查，如果未发现异常，程序应继续执行以完成exp利用链。

### 命令执行顺序
我将按顺序执行上述命令，从堆整体布局到具体内存细节，确保逐步验证exp的利用状态。如果任何命令显示异常（如链表断裂或数据损坏），将停止并报告；否则，最终执行`continue`让exp继续运行。