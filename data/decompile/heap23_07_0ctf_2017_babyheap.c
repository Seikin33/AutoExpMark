__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = sub_B70(a1, a2, a3);
  while ( 1 )
  {
    sub_CF4();
    switch ( sub_138C() )
    {
      case 1LL:
        sub_D48(v4);
        break;
      case 2LL:
        sub_E7F(v4);
        break;
      case 3LL:
        sub_F50(v4);
        break;
      case 4LL:
        sub_1051(v4);
        break;
      case 5LL:
        return 0;
      default:
        continue;
    }
  }
}

char *sub_B70()
{
  int fd; // [rsp+4h] [rbp-3Ch]
  char *addr; // [rsp+8h] [rbp-38h]
  unsigned __int64 v3; // [rsp+10h] [rbp-30h]
  _QWORD buf[4]; // [rsp+20h] [rbp-20h] BYREF

  buf[3] = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  alarm(0x3Cu);
  puts("===== Baby Heap in 2017 =====");
  fd = open("/dev/urandom", 0);
  if ( fd < 0 || read(fd, buf, 0x10u) != 16 )
    exit(-1);
  close(fd);
  addr = (char *)((buf[0] % 0x555555543000uLL + 0x10000) & 0xFFFFFFFFFFFFF000LL);
  v3 = (buf[1] % 0xE80uLL) & 0xFFFFFFFFFFFFFFF0LL;
  if ( mmap(addr, 0x1000u, 3, 34, -1, 0) != addr )
    exit(-1);
  return &addr[v3];
}

int sub_CF4()
{
  puts("1. Allocate");
  puts("2. Fill");
  puts("3. Free");
  puts("4. Dump");
  puts("5. Exit");
  return printf("Command: ");
}

__int64 sub_138C()
{
  char nptr[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  sub_123D(nptr, 8);
  return atol(nptr);
}

unsigned __int64 __fastcall sub_123D(__int64 a1, __int64 a2)
{
  unsigned __int64 v3; // rax
  char buf; // [rsp+17h] [rbp-19h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]
  ssize_t v6; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( !a2 )
    return 0;
  v5 = 0;
  while ( a2 - 1 > v5 )
  {
    v6 = read(0, &buf, 1u);
    if ( v6 > 0 )
    {
      if ( buf == 10 )
        break;
      v3 = v5++;
      *(_BYTE *)(v3 + a1) = buf;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      break;
    }
  }
  *(_BYTE *)(a1 + v5) = 0;
  return v5;
}

void __fastcall sub_D48(__int64 a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = sub_138C();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1u);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", i);
      }
      return;
    }
  }
}

__int64 __fastcall sub_E7F(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (unsigned int)result < 0x10 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = sub_138C();
      v3 = result;
      if ( (int)result > 0 )
      {
        printf("Content: ");
        return sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}

__int64 __fastcall sub_F50(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (unsigned int)result < 0x10 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      *(_DWORD *)(24LL * v2 + a1) = 0;
      *(_QWORD *)(24LL * v2 + a1 + 8) = 0;
      free(*(void **)(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(_QWORD *)(result + 16) = 0;
    }
  }
  return result;
}

int __fastcall sub_1051(__int64 a1)
{
  int result; // eax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (unsigned int)result < 0x10 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      sub_130F(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8));
      return puts(byte_14F1);
    }
  }
  return result;
}