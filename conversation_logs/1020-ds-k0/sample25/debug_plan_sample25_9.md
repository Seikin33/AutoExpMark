根据提供的全局内存信息和exp执行历史，程序存在堆溢出漏洞（通过edit函数溢出）和可能的堆元数据篡改。exp代码试图通过堆布局、元数据伪造和bin操作来实现利用。当前内存状态显示fastbins和unsortedbin中有活动块，堆内存被部分覆盖。为了深入探索局部内存状态，我设计了以下调试计划，使用Pwndbg命令检查堆布局、bins状态、特定堆块内容和全局数组，以识别漏洞利用的关键点。

### 调试计划
1. **检查堆布局和块细节**：使用`heap chunks`命令列出所有堆块，查看大小、状态和元数据，识别被覆盖的块和伪造的块。
2. **详细分析bins状态**：使用`bins`命令确认fastbins、unsortedbin等链表的当前状态，特别是关注0x30 fastbin链和unsortedbin块。
3. **检查特定堆块内存**：使用`hexdump`或`telescope`查看被编辑的堆块（如ID 6、2、0）的内容，验证元数据篡改和溢出效果。
4. **检查全局数组状态**：使用`telescope`查看全局`chunk`和`size`数组，确认分配的指针和大小，检测数组溢出。
5. **验证堆利用结构**：使用`malloc_chunk`命令分析关键堆块的chunk头，确保元数据符合预期。

理由：
- `heap chunks`提供堆的整体视图，帮助识别被破坏的块和布局。
- `bins`揭示空闲块的管理情况，fastbins中的链可能用于攻击。
- 直接内存检查确认exp中的payload是否正确修改了堆元数据。
- 全局数组检查可发现索引溢出问题，这可能被利用。
- 这些命令不改变执行流，符合约束。

现在执行命令探索内存状态。

```bash
RunPwndbgCommand: heap chunks
```

```bash
RunPwndbgCommand: bins
```

```bash
RunPwndbgCommand: telescope &chunk 10
```

```bash
RunPwndbgCommand: telescope &size 10
```

```bash
RunPwndbgCommand: malloc_chunk 0x55cb79116000
```

```bash
RunPwndbgCommand: hexdump 0x55cb79116000 64
```

```bash
RunPwndbgCommand: telescope 0x55cb79116020 20
```

如果关键信息已检索完毕，执行`continue`让程序继续运行。否则，根据输出调整进一步检查。