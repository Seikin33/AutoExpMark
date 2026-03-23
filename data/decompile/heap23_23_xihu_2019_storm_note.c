int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init_proc(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      _isoc99_scanf("%d", &v3);
      if ( v3 != 3 )
        break;
      delete_note();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 666 )
        backdoor();
LABEL_15:
      puts("Invalid choice");
    }
    else if ( v3 == 1 )
    {
      alloc_note();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_15;
      edit_note();
    }
  }
}

ssize_t menu()
{
  puts("================");
  puts("== Storm Note ==");
  puts("== 1. alloc   ==");
  puts("== 2. edit    ==");
  puts("== 3. delete  ==");
  puts("== 4. exit    ==");
  puts("================");
  return write(1, "Choice: ", 8u);
}

ssize_t init_proc()
{
  ssize_t result; // rax
  int fd; // [rsp+Ch] [rbp-4h]

  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  if ( !mallopt(1, 0) )
    exit(-1);
  if ( mmap((void *)0xABCD0000LL, 0x1000u, 3, 34, -1, 0) != (void *)2882338816LL )
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  result = read(fd, (void *)0xABCD0100LL, 0x30u);
  if ( result != 48 )
    exit(-1);
  return result;
}

void __noreturn backdoor()
{
  _BYTE buf[56]; // [rsp+0h] [rbp-40h] BYREF
  unsigned __int64 v1; // [rsp+38h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("If you can open the lock, I will let you in");
  read(0, buf, 0x30u);
  if ( !memcmp(buf, (const void *)0xABCD0100LL, 0x30u) )
    system("/bin/sh");
  exit(0);
}

unsigned __int64 delete_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Index ?");
  _isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 < 0x10 && *((_QWORD *)&note + v1) )
  {
    free(*((void **)&note + v1));
    *((_QWORD *)&note + v1) = 0;
    note_size[v1] = 0;
  }
  else
  {
    puts("Invalid index");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 edit_note()
{
  signed int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Index ?");
  _isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 < 0x10 && *((_QWORD *)&note + v1) )
  {
    puts("Content: ");
    v2 = read(0, *((void **)&note + v1), note_size[v1]);
    *(_BYTE *)(*((_QWORD *)&note + v1) + v2) = 0;
    puts("Done");
  }
  else
  {
    puts("Invalid index");
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 alloc_note()
{
  int v1; // [rsp+0h] [rbp-10h] BYREF
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  for ( i = 0; i <= 15 && note[i]; ++i )
    ;
  if ( i == 16 )
  {
    puts("full!");
  }
  else
  {
    puts("size ?");
    _isoc99_scanf("%d", &v1);
    if ( v1 > 0 && v1 <= 0xFFFFF )
    {
      note[i] = calloc(v1, 1u);
      note_size[i] = v1;
      puts("Done");
    }
    else
    {
      puts("Invalid size");
    }
  }
  return __readfsqword(0x28u) ^ v3;
}

