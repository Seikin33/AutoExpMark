void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_400882(a1, a2, a3);
  puts("I thought this is really baby.What about u?");
  puts("Loading.....");
  sleep(5u);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        sub_4008E3();
        memset(s, 0, 0x10u);
        read(0, s, 0xFu);
        v3 = atoi(s);
        if ( v3 != 2 )
          break;
        sub_400A79();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      sub_4009A0();
    }
    if ( v3 == 3 )
    {
      sub_400C01();
    }
    else
    {
      if ( v3 != 4 )
LABEL_13:
        exit(0);
      sub_400B54();
    }
  }
}

int sub_4008E3()
{
  puts("1.alloc");
  puts("2.edit");
  puts("3.show");
  puts("4.free");
  puts("5.exit");
  return printf("Choice:");
}

unsigned __int64 sub_400A79()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(s, 0, 0x10u);
  read(0, s, 0xFu);
  v1 = atoi(s);
  if ( v1 <= 0x1F && (&ptr)[v1] && dword_6020B0 != 3 )
  {
    printf("Content:");
    sub_40092B((&ptr)[v1], 32);
    ++dword_6020B0;
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 __fastcall sub_40092B(__int64 a1, unsigned int a2)
{
  unsigned __int64 result; // rax
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    read(0, (void *)(i + a1), 1u);
    if ( *(_BYTE *)(i + a1) == 10 || i == a2 - 1 )
    {
      result = i + a1;
      *(_BYTE *)result = 0;
      return result;
    }
  }
  return result;
}

unsigned __int64 sub_4009A0()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(s, 0, 0x10u);
  read(0, s, 0xFu);
  v1 = atoi(s);
  if ( v1 <= 9 && !(&ptr)[v1] )
  {
    (&ptr)[v1] = (char *)malloc(0x20u);
    printf("Content:");
    sub_40092B((__int64)(&ptr)[v1], 0x20u);
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 sub_400C01()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(s, 0, 0x10u);
  read(0, s, 0xFu);
  v1 = atoi(s);
  if ( v1 <= 9 && (&ptr)[v1] )
  {
    puts((&ptr)[v1]);
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 sub_400B54()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(s, 0, 0x10u);
  read(0, s, 0xFu);
  v1 = atoi(s);
  if ( v1 <= 9 && (&ptr)[v1] )
  {
    free((&ptr)[v1]);
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}