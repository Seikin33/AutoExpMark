__int64 __fastcall sub_BB0(_QWORD *a1, __int64 a2)
{
  return *a1 ^ a2;
}

__int64 __fastcall sub_BCC(__int64 a1, __int64 a2)
{
  return a2 ^ *(_QWORD *)(a1 + 8);
}

__int64 sub_BE6()
{
  int i; // [rsp+8h] [rbp-18h]
  int fd; // [rsp+Ch] [rbp-14h]

  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  alarm(0x3Cu);
  puts(
    "    __ __ _____________   __   __    ___    ____\n"
    "   / //_// ____/ ____/ | / /  / /   /   |  / __ )\n"
    "  / ,<  / __/ / __/ /  |/ /  / /   / /| | / __  |\n"
    " / /| |/ /___/ /___/ /|  /  / /___/ ___ |/ /_/ /\n"
    "/_/ |_/_____/_____/_/ |_/  /_____/_/  |_/_____/\n");
  puts("===== HEAP STORM II =====");
  if ( !mallopt(1, 0) )
    exit(-1);
  if ( mmap((void *)0x13370000, 0x1000u, 3, 34, -1, 0) != (void *)322371584 )
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  if ( read(fd, (void *)0x13370800, 0x18u) != 24 )
    exit(-1);
  close(fd);
  MEMORY[0x13370818] = MEMORY[0x13370810];
  for ( i = 0; i <= 15; ++i )
  {
    *(_QWORD *)(16 * (i + 2LL) + 0x13370800) = sub_BB0(322373632, 0);
    *(_QWORD *)(16 * (i + 2LL) + 0x13370808) = sub_BCC(322373632, 0);
  }
  return 322373632;
}

int sub_D92()
{
  puts("1. Allocate");
  puts("2. Update");
  puts("3. Delete");
  puts("4. View");
  puts("5. Exit");
  return printf("Command: ");
}

void __fastcall sub_DE6(_QWORD *a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !sub_BCC((__int64)a1, a1[2 * i + 5]) )
    {
      printf("Size: ");
      v2 = sub_1551();
      if ( v2 > 12 && v2 <= 4096 )
      {
        v3 = calloc(v2, 1u);
        if ( !v3 )
          exit(-1);
        a1[2 * i + 5] = sub_BCC((__int64)a1, v2);
        a1[2 * i + 4] = sub_BB0(a1, (__int64)v3);
        printf("Chunk %d Allocated\n", i);
      }
      else
      {
        puts("Invalid Size");
      }
      return;
    }
  }
}

int __fastcall sub_F21(_QWORD *a1)
{
  signed int v2; // [rsp+10h] [rbp-20h]
  int v3; // [rsp+14h] [rbp-1Ch]
  __int64 v4; // [rsp+18h] [rbp-18h]

  printf("Index: ");
  v2 = sub_1551();
  if ( (unsigned int)v2 >= 0x10 || !sub_BCC((__int64)a1, a1[2 * v2 + 5]) )
    return puts("Invalid Index");
  printf("Size: ");
  v3 = sub_1551();
  if ( v3 <= 0 || v3 > (unsigned __int64)(sub_BCC((__int64)a1, a1[2 * v2 + 5]) - 12) )
    return puts("Invalid Size");
  printf("Content: ");
  v4 = sub_BB0(a1, a1[2 * v2 + 4]);
  sub_1377(v4, v3);
  strcpy((char *)(v3 + v4), "HEAPSTORM_II");
  return printf("Chunk %d Updated\n", v2);
}

int __fastcall sub_109B(_QWORD *a1)
{
  void *v2; // rax
  signed int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  v3 = sub_1551();
  if ( (unsigned int)v3 >= 0x10 || !sub_BCC((__int64)a1, a1[2 * v3 + 5]) )
    return puts("Invalid Index");
  v2 = (void *)sub_BB0(a1, a1[2 * v3 + 4]);
  free(v2);
  a1[2 * v3 + 4] = sub_BB0(a1, 0);
  a1[2 * v3 + 5] = sub_BCC((__int64)a1, 0);
  return printf("Chunk %d Deleted\n", v3);
}

int __fastcall sub_11B5(_QWORD *a1)
{
  unsigned __int64 v2; // rbx
  __int64 v3; // rax
  signed int v4; // [rsp+1Ch] [rbp-14h]

  if ( (a1[3] ^ a1[2]) != 322401073 )
    return puts("Permission denied");
  printf("Index: ");
  v4 = sub_1551();
  if ( (unsigned int)v4 >= 0x10 || !sub_BCC((__int64)a1, a1[2 * v4 + 5]) )
    return puts("Invalid Index");
  printf("Chunk[%d]: ", v4);
  v2 = sub_BCC((__int64)a1, a1[2 * v4 + 5]);
  v3 = sub_BB0(a1, a1[2 * v4 + 4]);
  sub_14D4(v3, v2);
  return puts(byte_180A);
}

__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = sub_BE6(a1, a2, a3);
  while ( 1 )
  {
    sub_D92();
    switch ( sub_1551() )
    {
      case 1LL:
        sub_DE6(v4);
        break;
      case 2LL:
        sub_F21(v4);
        break;
      case 3LL:
        sub_109B(v4);
        break;
      case 4LL:
        sub_11B5(v4);
        break;
      case 5LL:
        return 0;
      default:
        continue;
    }
  }
}

unsigned __int64 __fastcall sub_1377(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v3; // [rsp+10h] [rbp-10h]
  ssize_t v4; // [rsp+18h] [rbp-8h]

  if ( !a2 )
    return 0;
  v3 = 0;
  while ( v3 < a2 )
  {
    v4 = read(0, (void *)(v3 + a1), a2 - v3);
    if ( v4 > 0 )
    {
      v3 += v4;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return v3;
    }
  }
  return v3;
}

unsigned __int64 __fastcall sub_1402(__int64 a1, __int64 a2)
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

unsigned __int64 __fastcall sub_14D4(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v3; // [rsp+10h] [rbp-10h]
  ssize_t v4; // [rsp+18h] [rbp-8h]

  v3 = 0;
  while ( v3 < a2 )
  {
    v4 = write(1, (const void *)(v3 + a1), a2 - v3);
    if ( v4 > 0 )
    {
      v3 += v4;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return v3;
    }
  }
  return v3;
}

__int64 sub_1551()
{
  char nptr[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  sub_1402(nptr, 8);
  return atol(nptr);
}