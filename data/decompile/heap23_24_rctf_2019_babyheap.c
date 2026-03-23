int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  while ( 1 )
  {
    menu();
    switch ( (unsigned int)get_int() )
    {
      case 1u:
        add();
        break;
      case 2u:
        edit();
        break;
      case 3u:
        delete();
        break;
      case 4u:
        show();
        break;
      case 5u:
        puts("See you next time!");
        exit(0);
      default:
        puts("Invalid choice!");
        break;
    }
  }
}

unsigned __int64 menu()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("1. add     ");
  puts("2. edit    ");
  puts("3. delete  ");
  puts("4. show    ");
  puts("5. exit    ");
  puts("Choice: ");
  return __readfsqword(0x28u) ^ v1;
}

int get_int()
{
  char nptr[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v2; // [rsp+8h] [rbp-18h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  *(_QWORD *)nptr = 0;
  v2 = 0;
  read_n(nptr, 15);
  return atoi(nptr);
}

void __noreturn timeout_handler()
{
  puts("Timeout");
  exit(0);
}

unsigned __int64 init()
{
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
  {
    puts("open failed!");
    exit(-1);
  }
  read(fd, &ptrs, 8u);
  close(fd);
  ptrs = (void *)((unsigned int)ptrs & 0xFFFF0000);
  mallopt(1, 0);
  if ( mmap(ptrs, 0x1000u, 3, 34, -1, 0) != ptrs )
  {
    puts("mmap error!");
    exit(-1);
  }
  signal(14, (__sighandler_t)timeout_handler);
  alarm(0x3Cu);
  if ( prctl(38, 1, 0, 0, 0) )
  {
    puts("Could not start seccomp:");
    exit(-1);
  }
  if ( prctl(22, 2, &filterprog) == -1 )
  {
    puts("Could not start seccomp:");
    exit(-1);
  }
  return __readfsqword(0x28u) ^ v2;
}

__int64 __fastcall read_n(void *a1, unsigned int a2)
{
  int v3; // [rsp+14h] [rbp-Ch]

  v3 = read(0, a1, a2);
  if ( v3 < 0 )
  {
    puts("read() error");
    exit(0);
  }
  if ( v3 && *((_BYTE *)a1 + v3 - 1) == 10 )
    *((_BYTE *)a1 + v3 - 1) = 0;
  return (unsigned int)v3;
}

unsigned __int64 add()
{
  void **v0; // rbx
  int i; // [rsp+0h] [rbp-20h]
  int v3; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; *((_QWORD *)ptrs + 2 * i) && i <= 15; ++i )
    ;
  if ( i == 16 )
  {
    puts("You can't");
    exit(-1);
  }
  printf("Size: ");
  v3 = get_int();
  if ( v3 <= 0 || v3 > 4096 )
  {
    puts("Invalid size :(");
  }
  else
  {
    *((_DWORD *)ptrs + 4 * i + 2) = v3;
    v0 = (void **)((char *)ptrs + 16 * i);
    *v0 = calloc(v3, 1u);
    puts("Add success :)");
  }
  return __readfsqword(0x28u) ^ v4;
}

unsigned __int64 edit()
{
  unsigned int v1; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( v1 < 0x10 && *((_QWORD *)ptrs + 2 * (int)v1) )
  {
    printf("Content: ");
    *(_BYTE *)(*((_QWORD *)ptrs + 2 * (int)v1)
             + (int)read_n(*((void **)ptrs + 2 * (int)v1), *((_DWORD *)ptrs + 4 * (int)v1 + 2))) = 0;
    puts("Edit success :)");
  }
  else
  {
    puts("Invalid index :(");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 delete()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( v1 < 0x10 && *((_QWORD *)ptrs + 2 * (int)v1) )
  {
    free(*((void **)ptrs + 2 * (int)v1));
    *((_QWORD *)ptrs + 2 * (int)v1) = 0;
    *((_DWORD *)ptrs + 4 * (int)v1 + 2) = 0;
    puts("Delete success :)");
  }
  else
  {
    puts("Invalid index :(");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 show()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( v1 < 0x10 && *((_QWORD *)ptrs + 2 * (int)v1) )
    puts(*((const char **)ptrs + 2 * (int)v1));
  else
    puts("Invalid index :(");
  return __readfsqword(0x28u) ^ v2;
}