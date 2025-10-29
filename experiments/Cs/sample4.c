__int64 __fastcall main(int a1, char **a2, char **a3)
{
  setvbuf(stdout, 0, 2, 0);
  sub_400D60();
  return 0;
}

__int64 sub_400D60()
{
  __int64 result; // rax

  qword_6020B8 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      sub_400D30();
      result = sub_400A40();
      if ( (_DWORD)result != 1 )
        break;
      sub_400AD0();
    }
    if ( (_DWORD)result != 2 )
      break;
    sub_400C00();
  }
  if ( (_DWORD)result != 3 )
    sub_400990("Invalid option");
  return result;
}

int sub_400D30()
{
  puts("1: Search with a word");
  puts("2: Index a sentence");
  return puts("3: Quit");
}

__int64 sub_400A40()
{
  __int64 result; // rax
  char *endptr; // [rsp+8h] [rbp-50h] BYREF
  char nptr[56]; // [rsp+10h] [rbp-48h] BYREF
  unsigned __int64 v3; // [rsp+48h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  sub_4009B0(nptr, 48, 1);
  result = strtol(nptr, &endptr, 0);
  if ( endptr == nptr )
  {
    __printf_chk(1, "%s is not a valid number\n", nptr);
    return sub_400A40();
  }
  return result;
}

void __fastcall sub_4009B0(__int64 a1, int a2, int a3)
{
  int v4; // ebx
  _BYTE *v5; // rbp
  int v6; // eax

  if ( a2 <= 0 )
  {
    v4 = 0;
  }
  else
  {
    v4 = 0;
    while ( 1 )
    {
      v5 = (_BYTE *)(a1 + v4);
      v6 = fread(v5, 1u, 1u, stdin);
      if ( v6 <= 0 )
        break;
      if ( *v5 == 10 && a3 )
      {
        if ( v4 )
        {
          *v5 = 0;
          return;
        }
        v4 = v6 - 1;
        if ( a2 <= v6 - 1 )
          break;
      }
      else
      {
        v4 += v6;
        if ( a2 <= v4 )
          break;
      }
    }
  }
  if ( v4 != a2 )
    sub_400990("Not enough data");
}

void sub_400AD0()
{
  int v0; // ebp
  void *v1; // r12
  __int64 i; // rbx
  _BYTE v3[56]; // [rsp+0h] [rbp-38h] BYREF

  puts("Enter the word size:");
  v0 = sub_400A40();
  if ( (unsigned int)(v0 - 1) > 0xFFFD )
    sub_400990("Invalid size");
  puts("Enter the word:");
  v1 = malloc(v0);
  sub_4009B0((__int64)v1, v0, 0);
  for ( i = qword_6020B8; i; i = *(_QWORD *)(i + 32) )
  {
    if ( **(_BYTE **)(i + 16) )
    {
      if ( *(_DWORD *)(i + 8) == v0 && !memcmp(*(const void **)i, v1, v0) )
      {
        __printf_chk(1, "Found %d: ", *(_DWORD *)(i + 24));
        fwrite(*(const void **)(i + 16), 1u, *(int *)(i + 24), stdout);
        putchar(10);
        puts("Delete this sentence (y/n)?");
        sub_4009B0((__int64)v3, 2, 1);
        if ( v3[0] == 121 )
        {
          memset(*(void **)(i + 16), 0, *(int *)(i + 24));
          free(*(void **)(i + 16));
          puts("Deleted!");
        }
      }
    }
  }
  free(v1);
}

void __fastcall __noreturn sub_400990(const char *a1)
{
  puts(a1);
  exit(1);
}

int sub_400C00()
{
  int v0; // eax
  __int64 v1; // rbp
  int v2; // r13d
  char *v3; // r12
  char *v4; // rbx
  __int64 v5; // rbp
  _DWORD *v6; // rax
  int v7; // edx
  __int64 v8; // rdx
  __int64 v10; // rdx

  puts("Enter the sentence size:");
  v0 = sub_400A40();
  v1 = (unsigned int)(v0 - 1);
  v2 = v0;
  if ( (unsigned int)v1 > 0xFFFD )
    sub_400990("Invalid size");
  puts("Enter the sentence:");
  v3 = (char *)malloc(v2);
  sub_4009B0((__int64)v3, v2, 0);
  v4 = v3 + 1;
  v5 = (__int64)&v3[v1 + 2];
  v6 = malloc(0x28u);
  v7 = 0;
  *(_QWORD *)v6 = v3;
  v6[2] = 0;
  *((_QWORD *)v6 + 2) = v3;
  v6[6] = v2;
  do
  {
    while ( *(v4 - 1) != 32 )
    {
      v6[2] = ++v7;
LABEL_4:
      if ( ++v4 == (char *)v5 )
        goto LABEL_8;
    }
    if ( v7 )
    {
      v10 = qword_6020B8;
      qword_6020B8 = (__int64)v6;
      *((_QWORD *)v6 + 4) = v10;
      v6 = malloc(0x28u);
      v7 = 0;
      *(_QWORD *)v6 = v4;
      v6[2] = 0;
      *((_QWORD *)v6 + 2) = v3;
      v6[6] = v2;
      goto LABEL_4;
    }
    *(_QWORD *)v6 = v4++;
  }
  while ( v4 != (char *)v5 );
LABEL_8:
  if ( v7 )
  {
    v8 = qword_6020B8;
    qword_6020B8 = (__int64)v6;
    *((_QWORD *)v6 + 4) = v8;
  }
  else
  {
    free(v6);
  }
  return puts("Added sentence");
}