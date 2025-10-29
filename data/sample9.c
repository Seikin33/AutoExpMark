void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  sub_40091C(a1, a2, a3);
  sub_4009A4();
  while ( 1 )
  {
    __isoc99_scanf("%d", &v3);
    getchar();
    switch ( v3 )
    {
      case 2:
        sub_400AB7();
        break;
      case 3:
        sub_400B2F();
        break;
      case 1:
        sub_4009DC();
        break;
    }
  }
}

unsigned __int64 sub_40091C()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  return __readfsqword(0x28u) ^ v1;
}

unsigned __int64 sub_4009A4()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  system("cat banner.txt");
  return __readfsqword(0x28u) ^ v1;
}

__int64 sub_400AB7()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __isoc99_scanf("%d", &v1);
  getchar();
  if ( v1 >= 0xA )
    return 0xFFFFFFFFLL;
  free((&s)[v1]);
  return 0;
}

__int64 sub_400B2F()
{
  unsigned int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  __isoc99_scanf("%d", &v1);
  getchar();
  if ( v1 >= 0xA )
    return 0xFFFFFFFFLL;
  v2 = strlen((&s)[v1]);
  sub_4008B6((&s)[v1], v2 + 1);
  sub_4008B6(&unk_602120, 48);
  return 0;
}

__int64 __fastcall sub_4008B6(void *a1, __int64 a2)
{
  __int64 result; // rax

  LODWORD(result) = read(0, a1, a2 - 1);
  *((_BYTE *)a1 + a2 - 1) = 0;
  return (unsigned int)result;
}

__int64 sub_4009DC()
{
  size_t size; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 i; // [rsp+8h] [rbp-18h]
  void *v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  __isoc99_scanf("%lu", &size);
  getchar();
  if ( size != 16 && size <= 0x7F )
    exit(0);
  v3 = malloc(size);
  sub_4008B6(v3, size);
  for ( i = 0; i <= 9 && (&s)[i]; ++i )
    ;
  if ( i == 10 )
    exit(0);
  (&s)[i] = (char *)v3;
  return 0;
}