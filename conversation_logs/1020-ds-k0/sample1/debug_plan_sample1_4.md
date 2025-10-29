根据提供的全局内存信息和exp代码执行情况，当前程序状态涉及堆溢出漏洞利用，重点在于检查堆布局、bin状态和全局数组是否被覆盖。以下调试计划旨在探索关键内存状态，使用pwndbg命令而不改变程序执行流。

### 调试计划
1. **检查bins详细信息**：确认unsortedbin状态，因为heap输出显示unsortedbin有一个块（0x21aaf110），且可能被溢出影响。
   - 命令：`RunPwndbgCommand("bins")`
   - 理由：验证unsortedbin的链表结构，检查是否有伪造或损坏的指针。

2. **查看unsortedbin块内容**：深入分析unsortedbin块（0x21aaf100）的内存内容，以识别可能被覆盖的元数据或用户数据。
   - 命令：`RunPwndbgCommand("telescope 0x21aaf100 40")`
   - 理由：`telescope`可显示指针链和内存值，帮助检测off-by-one溢出导致的元数据修改或伪造块。

3. **检查全局heap数组**：exp代码中`ptr=0x6021E0`可能对应全局`heap`数组地址，需确认指针是否被覆盖为GOT地址或其他值。
   - 命令：`RunPwndbgCommand("telescope 0x6021E0 40")`
   - 理由：全局数组存储分配的内存块指针，编辑操作可能通过溢出修改这些指针，实现任意内存读写。

4. **查看被free的块相邻区域**：索引1的块（可能位于0x21aaf200）被释放，检查其周边内存以验证off-by-one溢出的影响。
   - 命令：`RunPwndbgCommand("hexdump 0x21aaf200 32")`
   - 理由：`hexdump`可显示原始内存内容，确认prev_size和size字段是否被覆盖，以及是否导致堆合并或UAF。

5. **验证GOT表状态**：exp目标可能涉及GOT劫持，检查free的GOT条目是否被修改。
   - 命令：`RunPwndbgCommand("gotplt")`
   - 理由：确认free函数在GOT中的地址是否已被覆盖，以评估利用进度。

6. **检查堆布局完整性**：使用heap命令再次验证所有块的状态，确保没有不一致的元数据。
   - 命令：`RunPwndbgCommand("heap")`
   - 理由：全局堆视图可帮助识别其他可能被溢出的块，如索引0或31的块。

如果以上命令执行后关键内存信息（如bins、全局数组、GOT）已清晰，则执行`RunPwndbgCommand("continue")`让程序继续运行。否则，可根据输出调整命令进一步探索。