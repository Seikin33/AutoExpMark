__int64 __fastcall sub_40085D(__int64 a1, int a2)
{
  int i; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+1Ch] [rbp-4h]

  if ( a2 <= 0 )
    return 0;
  for ( i = 0; i < a2; i += v4 )
  {
    v4 = read(0, (void *)(a1 + i), a2 - i);
    if ( v4 <= 0 )
      break;
  }
  return (unsigned int)i;
}

__int64 __fastcall sub_4008C9(__int64 a1, int a2)
{
  int i; // [rsp+18h] [rbp-8h]

  if ( a2 <= 0 )
    return 0;
  for ( i = 0; a2 - 1 > i && (int)read(0, (void *)(i + a1), 1u) > 0 && *(_BYTE *)(i + a1) != 10; ++i )
    ;
  *(_BYTE *)(i + a1) = 0;
  return (unsigned int)i;
}

__int64 __fastcall sub_4008C9(__int64 a1, int a2)
{
  unsigned int i; // [rsp+18h] [rbp-8h]

  if ( a2 <= 0 )
    return 0;
  for ( i = 0; a2 - 1 > (int)i && (int)read(0, (void *)((int)i + a1), 1u) > 0 && *(_BYTE *)((int)i + a1) != 10; ++i )
    ;
  *(_BYTE *)((int)i + a1) = 0;
  return i;
}

__int64 sub_400998()
{
  puts("== 0ops Free Note ==");
  puts("1. List Note");
  puts("2. New Note");
  puts("3. Edit Note");
  puts("4. Delete Note");
  puts("5. Exit");
  puts("====================");
  printf("Your choice: ");
  return sub_40094E();
}

unsigned int sub_4009FD()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  return alarm(0x3Cu);
}

_QWORD *sub_400A49()
{
  _QWORD *result; // rax
  int i; // [rsp+Ch] [rbp-4h]

  qword_6020A8 = (__int64)malloc(0x1810u);
  *(_QWORD *)qword_6020A8 = 256;
  result = (_QWORD *)qword_6020A8;
  *(_QWORD *)(qword_6020A8 + 8) = 0;
  for ( i = 0; i <= 255; ++i )
  {
    *(_QWORD *)(qword_6020A8 + 24LL * i + 16) = 0;
    *(_QWORD *)(qword_6020A8 + 24LL * i + 24) = 0;
    result = (_QWORD *)(qword_6020A8 + 24LL * i + 32);
    *result = 0;
  }
  return result;
}

int sub_400B14()
{
  __int64 v0; // rax
  int i; // [rsp+Ch] [rbp-4h]

  if ( *(__int64 *)(qword_6020A8 + 8) <= 0 )
  {
    LODWORD(v0) = puts("You need to create some new notes first.");
  }
  else
  {
    for ( i = 0; ; ++i )
    {
      v0 = *(_QWORD *)qword_6020A8;
      if ( i >= *(_QWORD *)qword_6020A8 )
        break;
      if ( *(_QWORD *)(qword_6020A8 + 24LL * i + 16) == 1 )
        printf("%d. %s\n", i, *(const char **)(qword_6020A8 + 24LL * i + 32));
    }
  }
  return v0;
}

int sub_400BC2()
{
  __int64 v0; // rax
  int i; // [rsp+Ch] [rbp-14h]
  int v3; // [rsp+10h] [rbp-10h]
  void *v4; // [rsp+18h] [rbp-8h]

  if ( *(_QWORD *)(qword_6020A8 + 8) < *(_QWORD *)qword_6020A8 )
  {
    for ( i = 0; ; ++i )
    {
      v0 = *(_QWORD *)qword_6020A8;
      if ( i >= *(_QWORD *)qword_6020A8 )
        break;
      if ( !*(_QWORD *)(qword_6020A8 + 24LL * i + 16) )
      {
        printf("Length of new note: ");
        v3 = sub_40094E();
        if ( v3 > 0 )
        {
          if ( v3 > 4096 )
            v3 = 4096;
          v4 = malloc((128 - v3 % 128) % 128 + v3);
          printf("Enter your note: ");
          sub_40085D((__int64)v4, v3);
          *(_QWORD *)(qword_6020A8 + 24LL * i + 16) = 1;
          *(_QWORD *)(qword_6020A8 + 24LL * i + 24) = v3;
          *(_QWORD *)(qword_6020A8 + 24LL * i + 32) = v4;
          ++*(_QWORD *)(qword_6020A8 + 8);
          LODWORD(v0) = puts("Done.");
        }
        else
        {
          LODWORD(v0) = puts("Invalid length!");
        }
        return v0;
      }
    }
  }
  else
  {
    LODWORD(v0) = puts("Unable to create new note.");
  }
  return v0;
}

int sub_400BC2()
{
  __int64 v0; // rax
  int i; // [rsp+Ch] [rbp-14h]
  int v3; // [rsp+10h] [rbp-10h]
  void *v4; // [rsp+18h] [rbp-8h]

  if ( *(_QWORD *)(qword_6020A8 + 8) < *(_QWORD *)qword_6020A8 )
  {
    for ( i = 0; ; ++i )
    {
      v0 = *(_QWORD *)qword_6020A8;
      if ( i >= *(_QWORD *)qword_6020A8 )
        break;
      if ( !*(_QWORD *)(qword_6020A8 + 24LL * i + 16) )
      {
        printf("Length of new note: ");
        v3 = sub_40094E();
        if ( v3 > 0 )
        {
          if ( v3 > 4096 )
            v3 = 4096;
          v4 = malloc((128 - v3 % 128) % 128 + v3);
          printf("Enter your note: ");
          sub_40085D((__int64)v4, v3);
          *(_QWORD *)(qword_6020A8 + 24LL * i + 16) = 1;
          *(_QWORD *)(qword_6020A8 + 24LL * i + 24) = v3;
          *(_QWORD *)(qword_6020A8 + 24LL * i + 32) = v4;
          ++*(_QWORD *)(qword_6020A8 + 8);
          LODWORD(v0) = puts("Done.");
        }
        else
        {
          LODWORD(v0) = puts("Invalid length!");
        }
        return v0;
      }
    }
  }
  else
  {
    LODWORD(v0) = puts("Unable to create new note.");
  }
  return v0;
}

int sub_400D87()
{
  __int64 v1; // rbx
  int v2; // [rsp+4h] [rbp-1Ch]
  int v3; // [rsp+8h] [rbp-18h]

  printf("Note number: ");
  v3 = sub_40094E();
  if ( v3 < 0 || v3 >= *(_QWORD *)qword_6020A8 || *(_QWORD *)(qword_6020A8 + 24LL * v3 + 16) != 1 )
    return puts("Invalid number!");
  printf("Length of note: ");
  v2 = sub_40094E();
  if ( v2 <= 0 )
    return puts("Invalid length!");
  if ( v2 > 4096 )
    v2 = 4096;
  if ( v2 != *(_QWORD *)(qword_6020A8 + 24LL * v3 + 24) )
  {
    v1 = qword_6020A8;
    *(_QWORD *)(v1 + 24LL * v3 + 32) = realloc(*(void **)(qword_6020A8 + 24LL * v3 + 32), (128 - v2 % 128) % 128 + v2);
    *(_QWORD *)(qword_6020A8 + 24LL * v3 + 24) = v2;
  }
  printf("Enter your note: ");
  sub_40085D(*(_QWORD *)(qword_6020A8 + 24LL * v3 + 32), v2);
  return puts("Done.");
}

int sub_400F7D()
{
  int v1; // [rsp+Ch] [rbp-4h]

  if ( *(__int64 *)(qword_6020A8 + 8) <= 0 )
    return puts("No notes yet.");
  printf("Note number: ");
  v1 = sub_40094E();
  if ( v1 < 0 || v1 >= *(_QWORD *)qword_6020A8 )
    return puts("Invalid number!");
  --*(_QWORD *)(qword_6020A8 + 8);
  *(_QWORD *)(qword_6020A8 + 24LL * v1 + 16) = 0;
  *(_QWORD *)(qword_6020A8 + 24LL * v1 + 24) = 0;
  free(*(void **)(qword_6020A8 + 24LL * v1 + 32));
  return puts("Done.");
}

__int64 __fastcall main(const char *a1, char **a2, char **a3)
{
  sub_4009FD();
  sub_400A49();
  while ( 1 )
  {
    switch ( (unsigned int)sub_400998(a1, a2) )
    {
      case 1u:
        sub_400B14();
        break;
      case 2u:
        sub_400BC2();
        break;
      case 3u:
        sub_400D87();
        break;
      case 4u:
        sub_400F7D();
        break;
      case 5u:
        puts("Bye");
        return 0;
      default:
        a1 = "Invalid!";
        puts("Invalid!");
        break;
    }
  }
}