根据提供的全局内存信息和exp代码执行情况，程序当前状态可能涉及堆溢出或UAF漏洞利用。从heap和bins信息看，smallbin中有一个0xc0大小的bin包含两个chunk（0x300e000和0x300e190），且exp代码通过change_message和change_name操作可能破坏了堆元数据或全局变量。为了探索局部内存状态，我需要检查关键地址的内容，包括数据段中的全局变量（如name、message、page_list）和堆chunk的详细信息。以下调试计划将使用pwndbg命令检索内存信息，而不改变程序执行流。

### 调试计划
1. **检查GOT表状态**：确认GOT条目是否被覆盖，这可能用于漏洞利用。
   - 命令：`RunPwndbgCommand command="gotplt"`
   - 理由：GOT表覆盖是常见利用技术，从exp代码中定义了free_got等，需检查是否被修改。

2. **检查数据段全局变量**：查看0x602000区域的内容，定位name、message、page_list等全局变量地址和值。
   - 命令：`RunPwndbgCommand command="telescope 0x602000 50"`
   - 理由：数据段存储全局变量，从exp中使用了0x6020A0等地址，需确认这些地址对应的变量状态和是否被覆盖。

3. **检查堆chunk详细信息**：深入查看smallbin中的chunk（0x300e000和0x300e190），确认其fd/bk指针和可能的内存损坏。
   - 命令：`RunPwndbgCommand command="telescope 0x300e000 20"`
   - 命令：`RunPwndbgCommand command="telescope 0x300e190 20"`
   - 理由：这些chunk在bins中，可能被exp代码覆盖了元数据，用于构造恶意链表。

4. **检查符号信息**：确认0x602090和0x6020A0地址对应的符号，以理解全局变量布局。
   - 命令：`RunPwndbgCommand command="info symbol 0x602090"`
   - 命令：`RunPwndbgCommand command="info symbol 0x6020A0"`
   - 理由：从heap信息中0x300e000的bk指向0x602090，exp中使用了0x6020A0，需识别这些地址对应的变量（如stdin、page_list等）。

5. **重新验证堆和bins状态**：确保当前堆布局和bins与提供信息一致。
   - 命令：`RunPwndbgCommand command="heap"`
   - 命令：`RunPwndbgCommand command="bins"`
   - 理由：确认内存状态未变，并观察是否有额外变化。

6. **检查name变量内容**：从exp中change_name被调用并覆盖了name，需确认其当前值。
   - 首先通过数据段telescope找到name地址（可能 near 0x6020A0），然后检查其内容。
   - 命令：`RunPwndbgCommand command="telescope 0x602090 20"` # 假设name在0x602090附近
   - 理由：name被exp覆盖为构造的payload，可能用于进一步利用。

7. **检查message指针**：确认message全局变量当前指向的