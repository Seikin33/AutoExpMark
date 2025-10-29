## 内存变化总结

### 初始状态 → 当前状态的内存演变

#### 1. **堆内存分配阶段**
**初始状态**：堆内存为空，所有bins为空

**分配4个笔记后**：
- **Chunk 0** (`0x2619c000`)：33字节，存储"aaaa"
- **Chunk 1** (`0x2619c020`)：273字节，存储"aaaa"  
- **Chunk 2** (`0x2619c130`)：273字节，存储"aaaa"
- **Chunk 3** (`0x2619c240`)：273字节，存储"aaaa"

**全局指针数组**：
- `0x6020c8` → `0x2619c010` (note0)
- `0x6020d0` → `0x2619c030` (note1)
- `0x6020d8` → `0x2619c140` (note2)
- `0x6020e0` → `0x2619c250` (note3)

#### 2. **堆溢出攻击阶段**
通过`edit(b'0', payload)`触发堆溢出：

**Payload结构**：
- 覆盖chunk1的size为0x121
- 伪造chunk2的prev_size=0, size=0x101
- 设置chunk2的fd=0x6020c0, bk=0x6020c8
- 修改chunk3的prev_size=0x100, size=0x110

**关键变化**：
- chunk2的fd/bk指向全局变量区域
- 为unlink攻击准备了伪造的链表结构

#### 3. **Unlink攻击触发阶段**
通过`delete(b'1')`触发unlink：

**内存关键变化**：
- **全局指针修改**：`0x6020d8`从`0x2619c140`变为`0x6020c0`
- **堆块合并**：chunk1和chunk2合并为545字节的大块
- **Bins状态**：合并后的块进入unsortedbin

**Unlink操作效果**：
- 成功实现了`*(0x6020d8) = 0x6020c0`的任意写
- 现在note2指针指向全局变量区域

#### 4. **任意写原语建立阶段**
通过`edit(b'2', payload)`修改全局指针：

**Payload结构**：
- `b'a' * 0x8`：填充
- `p64(free_got)`：将note0指针指向free@got.plt
- `p64(atoi_got)`：将note1指针指向atoi@got.plt
- `p64(atoi_got) * 2`：填充其他指针

**全局变量最终状态**：
- `0x6020c0` → `atoi@got.plt` (0x602070)
- `0x6020c8` (note0) → `free@got.plt` (0x602018)
- `0x6020d0` (note1) → `atoi@got.plt` (0x602070)
- `0x6020d8` (note2) → `0x6020c0` (指向全局变量起始)

#### 5. **当前内存状态**
**堆布局**：
- `0x2619c000`：chunk0 (33字节，正常)
- `0x2619c020`：合并后的chunk1+chunk2 (545字节，在unsortedbin中)
- `0x2619c240`：chunk3 (272字节，正常)
- `0x2619c350`：top chunk

**Bins状态**：
- unsortedbin：包含`0x2619c020`，fd/bk指向`0x7e8cfde01b78` (main_arena+88)
- 其他bins：全部为空

**GOT表状态**：
- `free@got.plt`：`0x7e8cfdac1540` (原始libc地址)
- `atoi@got.plt`：`0x7e8cfda73e90` (原始libc地址)
- GOT表尚未被覆盖

### 漏洞利用链完成度
1. ✅ **堆溢出成功**：payload正确覆盖堆元数据
2. ✅ **元数据伪造**：创建了伪造的bin链表
3. ✅ **Unlink触发**：成功修改全局指针
4. ✅ **任意写建立**：通过编辑note2修改全局指针数组
5. ⏳ **GOT覆盖准备**：note0指向free_got，note1指向atoi_got，为后续GOT覆盖做准备

### 后续利用可能性
- **GOT覆盖**：通过编辑note0可以覆盖free_got，编辑note1可以覆盖atoi_got
- **代码执行**：将GOT条目覆盖为system或one_gadget地址
- **libc泄漏**：unsortedbin中的main_arena地址可用于计算libc基址
- **ROP利用**：由于NX启用，可能需要ROP链或ret2libc

当前内存状态为典型的堆利用成功阶段，任意写原语已建立，为后续的代码执行奠定了基础。程序处于理想的利用准备状态，等待触发GOT覆盖操作。