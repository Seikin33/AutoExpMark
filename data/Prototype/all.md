# 漏洞利用原型摘要

## 1. fastbin_dup_consolidate
步骤：
1. 分配一个小堆块p1（fastbin范围），释放到fastbin
2. 分配一个大堆块p3（大于0x400），再释放，使得p1=p3=top chunk，p1为悬空指针
3. 分配一个大堆块p4（大于0x400），p4=p3=p1，造成堆块复用

特征：
- 涉及fastbin
- 分配的大堆块涉及malloc_consolidate
- 本质上是利用consolidate绕过检查，达成double free

## 2. house of force
步骤：
1. 覆写top chunk为很大的数字
2. 分配一个异常大的堆块，使得top chunk到达目标地址附近
3. 分配一个小堆块，实现对目标地址的控制

特征：
- 溢出对象：top chunk的size位
- 会分配异常大的堆块（甚至用负数表示）

## 3. fastbin_dup_into_stack
步骤：
1. 经典三连0x20小堆块a-b-a制造fastbin的double free
2. 分配两次小堆块，使得d=a，同时fastbin中只剩a
3. 在栈上找一个0x20的值（位于x），并且将d的内容修改为栈上0x20附近的值（x-8），此时fastbin中变成a->(x-8)
4. 再次分配两个小堆块。新分配的堆块可以控制栈上的值

特征：
- 经典fastbin的UAF利用技巧，a-b-a绕过检测
- 栈上必须有0x20或者与利用的fastbin链表大小相同的值
- 需要通过泄露栈上的地址，或者需要泄露栈基址

## 4. house_of_einherjar
步骤：
1. 分配堆块a和相邻的堆块b
2. 在栈上或其他已知地址伪造一个fake_chunk，其fd和bk指针指向自身以绕过unlink检查
3. 利用off-by-one-null-byte漏洞覆写b的size字段，清除其PREV_INUSE位，使系统认为a是空闲的
4. 修改b的prev_size字段，使其指向伪造的fake_chunk
5. 释放b，系统检查到PREV_INUSE位为0，会尝试与“前一个”堆块（即伪造的fake_chunk）合并，从而将fake_chunk链入bins
6. 再次申请一个大堆块，即可获得指向栈上fake_chunk的指针，实现任意地址分配

特征：
- 需要off-by-one null byte溢出漏洞
- 核心是欺骗free函数，使其与一个位于任意地址的伪造堆块进行合并
- 最终效果是让malloc返回一个指向任意地址（如栈）的指针

## 5. house_of_lore
步骤：
1. 分配一个victim堆块，释放到small bin中
2. 在栈上构造一个fake_chunk，并构造一个双向链表结构，使其fd指针指向victim堆块
3. 利用UAF或堆溢出漏洞，覆写victim堆块的bk指针，使其指向栈上的fake_chunk
4. 再次申请与victim同样大小的堆块，这将触发unlink操作。由于精心构造的指针，成功绕过`P->bk->fd == P`检查，并将fake_chunk链入small bin
5. 再次申请堆块，即可获得指向栈上fake_chunk的指针

特征：
- 攻击目标是small bin
- 核心是绕过glibc对small bin双向链表的unlink检查
- 需要UAF或堆溢出漏洞来修改已释放堆块的bk指针

## 6. house_of_spirit
步骤：
1. 在栈上（或其他已知地址）伪造一个堆块及其元数据
2. 关键在于伪造size字段，使其大小属于fastbin范围，并通过fastbin的检查
3. 同时，需要伪造下一个堆块的size字段，使其通过free函数对next_chunk的完整性检查
4. 调用free函数释放这个伪造的堆块，使其被链入fastbin
5. 再次申请同样大小的堆块，即可获得指向栈上伪造块的指针

特征：
- 不需要堆溢出或UAF漏洞，但要求能控制一个将被free的指针
- 核心是欺骗free函数，让它把一个非堆上的地址当作一个有效的fastbin chunk来管理
- 最终效果是让malloc返回一个指向任意地址（如栈）的指针

## 7. large_bin_attack
步骤：
1. 分配并释放至少两个large chunk（p1, p2），使其进入unsorted bin，再通过一次分配将p2整理进large bin
2. 利用漏洞修改p2的bk和bk_nextsize指针，使其分别指向目标地址（如栈变量）附近
3. 分配并释放第三个large chunk（p3），然后再次分配一个小堆块
4. 这会触发p3被链入large bin，在链入过程中，glibc会执行`victim->bk_nextsize->fd_nextsize = victim`和`bck->fd = victim`等不安全的指针操作，导致将堆地址写入到由bk和bk_nextsize指定的任意地址

特征：
- 攻击目标是large bin
- 利用large bin在处理双向链表时的不安全指针操作
- 可以实现向任意地址写入一个堆地址

## 8. overlapping_chunks
步骤：
1. 分配三个连续的堆块p1, p2, p3
2. 释放p2，使其进入unsorted bin
3. 利用堆溢出漏洞，修改p2的size字段，将其改大，但要保持PREV_INUSE位不变
4. 申请一个新的堆块p4，大小为修改后的p2大小。由于p2在unsorted bin中，分配器会从p2开始分配，但使用了被篡改的size，导致p4的范围覆盖了p3

特征：
- 需要堆溢出漏洞来修改已释放堆块的size
- 核心是造成两个本应独立的堆块在内存上发生重叠
- 最终效果是获得两个指向重叠内存区域的指针，可以互相修改对方的数据

## 9. poison_null_byte
步骤：
1. 分配三个连续堆块a, b, c
2. 释放b，使其进入unsorted bin
3. 利用off-by-one-null-byte漏洞覆写b的size字段，将其改小，并清除PREV_INUSE位
4. 这个修改会破坏堆的元数据一致性（特别是c的prev_size没有被正确更新）
5. 再次分配，部分占用b的空间，然后释放c，触发向后合并
6. 由于元数据不一致，合并会出错，导致后续分配的堆块与现有堆块发生重叠

特征：
- 需要off-by-one null byte溢出漏洞
- 核心是利用null byte修改size，造成堆元数据不一致，欺骗合并机制
- 最终效果是造成堆块重叠（overlapping chunks）

## 10. unsafe_unlink
步骤：
1. 在一个可控的堆块（chunk0）中伪造一个free chunk的元数据，包括size, fd, bk
2. 将伪造chunk的fd和bk指针指向一个全局指针变量`ptr`的附近，构造`P->fd->bk == P`和`P->bk->fd == P`的条件以绕过检查
3. 利用堆溢出，修改下一个堆块（chunk1）的元数据：将其prev_size指向伪造的chunk，并清除其PREV_INUSE位
4. 释放chunk1，触发向后合并，进而调用unlink宏操作伪造的chunk
5. unlink操作`FD->bk = BK`和`BK->fd = FD`会修改全局指针`ptr`自身，使其指向`ptr`地址附近
6. 通过被修改的`ptr`，实现任意地址写

特征：
- 经典堆利用技巧，利用了早期glibc版本中unlink宏的漏洞
- 需要一个已知地址的指针（如全局指针）作为攻击目标
- 需要堆溢出漏洞来伪造元数据
- 核心是劫持unlink过程中的指针写操作，实现任意地址写

## 11. house_of_storm
步骤：
1. 准备一个unsorted bin chunk和一个large bin chunk
2. 利用漏洞，修改unsorted bin chunk的bk指针，指向目标地址（fake_chunk）
3. 同时修改large bin chunk的bk_nextsize指针，指向fake_chunk附近的一个地址，该地址将被用来写入伪造的size
4. 触发一次分配，这会处理unsorted bin。首先，large bin的机制会被用来在`bk_nextsize`指向的位置写入一个堆地址（被当作size）。然后，unsorted bin attack的机制会检查到`bk`指针（fake_chunk）现在有了一个有效的size
5. 分配器认为fake_chunk是一个有效的free chunk，并返回它，实现任意地址分配

特征：
- 结合了unsorted bin attack和large bin attack
- 利用large bin的写能力为unsorted bin attack创造一个有效的size
- 最终效果是实现任意地址分配，可以返回任意地址的“堆块”

## 12. sysmalloc_int_free
步骤：
1. 利用堆溢出漏洞，修改top chunk的size字段，将其改小，但要保持页对齐
2. 申请一个比修改后的top chunk更大的堆块
3. 这会触发sysmalloc函数来扩展堆。在扩展过程中，sysmalloc发现旧的top chunk无法合并（因为太小），就会调用_int_free将其释放到unsorted bin中
4. 之后再申请堆块，就可以从unsorted bin中获得旧的top chunk的控制权

特征：
- 类似于House of Orange
- 核心是滥用sysmalloc在堆扩展失败时的回退机制，间接实现`free(top_chunk)`
- 需要堆溢出修改top chunk的size

## 13. house_of_roman
步骤：
1. **阶段一**：利用UAF和相对覆写，将fastbin链表指向__malloc_hook附近的一个伪造chunk
2. **阶段二**：利用unsorted bin attack（同样通过相对覆写bk指针），将一个main_arena的地址写入__malloc_hook
3. **阶段三**：利用第一阶段获得的写能力，对__malloc_hook中的main_arena地址进行相对覆写，将其修改为system函数或one_gadget的地址
4. 触发malloc，执行被修改的__malloc_hook，获得shell

特征：
- 无需泄露地址（Leakless），完全依赖相对覆写
- 需要暴力破解部分地址位（例如12位）
- 多阶段攻击，结合fastbin attack和unsorted bin attack，最终控制__malloc_hook

## 14. house_of_gods
步骤：
1. 泄露libc地址，并通过特定分配操作在main_arena的binmap字段中设置一个位，使其看起来像一个有效的size
2. 利用Write-After-Free修改一个unsorted chunk的bk指针，指向main_arena的binmap字段
3. 申请堆块，获得对main_arena部分字段的写权限
4. 利用写权限和另一次unsorted bin attack，覆写main_arena中的`narenas`变量为极大值
5. 设置`main_arena.next`指向一个由攻击者控制的fake_arena
6. 通过两次特殊的malloc调用触发`reused_arena()`，劫持`thread_arena`使其指向fake_arena
7. 利用被劫持的arena实现任意地址分配

特征：
- 极其复杂，需要深入理解glibc的arena管理机制
- 目标是劫持`thread_arena`
- 结合了binmap attack, unsorted bin attack, arena-level的覆写

## 15. house_of_mind
步骤：
1. 在已知地址创建一个fake_arena
2. 通过大量分配来扩展堆，直到堆顶接近一个`HEAP_MAX_SIZE`的边界，使得下一个`heap_info`结构体的地址变得可以预测
3. 在可预测的`heap_info`地址处，写入指向fake_arena的指针
4. 利用单字节溢出，在一个fastbin chunk的size字段上设置`non-main arena`位
5. 释放这个被修改的chunk，`free`函数会根据`non-main arena`位和chunk地址去寻找`heap_info`，从而找到我们伪造的`heap_info`和`fake_arena`
6. `free`操作会将该chunk链入`fake_arena`的fastbin中，实现任意地址写

特征：
- 目标是glibc的非主线程arena（non-main arena）管理机制
- 仅需单字节溢出
- 需要大量的堆风水（heap feng shui）操作来控制内存布局

## 16. fastbin_dup
步骤：
1. 分配三个小堆块a、b、c（fastbin范围）。
2. 依次释放a、释放b、再次释放a（a-b-a），绕过直接双释放检查，在fastbin中形成循环链表。
3. 连续三次malloc相同大小的堆块，依次得到原a、原b、再次得到原a地址，证明同一内存被重复分配。

特征：
- 涉及fastbin管理与double free，关键释放序列为a-b-a。
- 会在fastbin中制造循环链表，破坏堆一致性。
- 后续malloc可返回已分配地址，导致UAF/类型混淆等更高级利用的基础。
- 不依赖越界写，本质是释放次序缺陷的利用原型。

## 17. overlapping_chunks_2
步骤：
1. 分配5个等大小的堆块p1~p5（如约1000字节）。
2. 释放p4，使其进入unsorted bin。
3. 通过p1的堆溢出覆盖正在使用的p2的size字段，将其改为覆盖p2+p3（并保留`PREV_INUSE`位），使p2的“下一块”被误判为p4。
4. 释放p2，分配器被欺骗，错误地把p2与p4合并为一个大free chunk（实际错误包含了仍在用的p3）。
5. 申请一个能由该大free chunk满足的新堆块p6，得到与p3重叠的分配；通过对p6写入篡改p3数据以验证重叠。

特征：
- 属于“非相邻Free Chunk合并（Nonadjacent Free Chunk Consolidation）”范式。
- 需要堆溢出修改在用chunk的size，并保持`PREV_INUSE`位以通过一致性检查。
- 借助unsorted bin中预先释放的p4来触发错误的向后/向前合并逻辑。
- 最终获得两个指向重叠内存的指针，可相互覆盖数据，为更复杂任意写/信息泄露打基础。

## 18. unsorted_bin_attack
步骤：
1. 分配两个堆块：victim（如400字节）与另一个任意堆块，用于避免victim在free后与top合并。
2. 释放victim，使其进入unsorted bin。
3. 利用UAF/溢出覆盖victim的bk指针为目标地址减去适当偏移（x64中为目标地址-0x10，即`&target-2`）。
4. 再次malloc与victim相同大小，触发unlink：执行`bk->fd = fd`，将`fd`（通常为main_arena地址）写入目标地址。
5. 验证目标地址内容被改写为libc/main_arena指针值，获得“任意地址写”原语。

特征：
- 基于unsorted bin的任意地址写（写入值通常为main_arena/堆地址）。
- 需要能在free后修改chunk（UAF）以控制bk指针。
- 常用于覆写`global_max_fast`或可写指针，作为后续fastbin等攻击的前置步骤。
- 需准备“垫块”以避免与top chunk合并影响利用。

## 19. unsorted_bin_into_stack
步骤：
1. 分配victim（如0x100）及另一个堆块，避免top合并。
2. 释放victim到unsorted bin。
3. 在栈上构造fake chunk：设置size为后续请求大小+头部（如0x110），并构造可通过校验的链表字段。
4. 利用UAF覆盖victim->size为较小值（如0x20）使其不满足请求，并将victim->bk指向栈上fake chunk地址。
5. 调用malloc(0x100)，遍历unsorted bin时返回fake chunk，得到指向栈的指针。
6. 使用该返回指针覆写关键栈数据（如返回地址/函数指针）以实现控制流劫持。

特征：
- 将malloc重定向到任意地址（如栈），实现“任意地址分配”。
- 需要UAF修改已释放chunk的size与bk；size需通过glibc一致性检查（满足2*SIZE_SZ与system_mem范围约束）。
- 可绕过“栈不可分配”的假设，便于覆盖返回地址等敏感数据。
- 依赖glibc具体版本行为，不同版本的检查可能影响可行性。