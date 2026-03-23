__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax
  int v5; // [rsp+Ch] [rbp-74h]
  char nptr[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v7; // [rsp+78h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  alarm(0x78u);
  while ( fgets(nptr, 10, stdin) )
  {
    v3 = atoi(nptr);
    if ( v3 == 2 )
    {
      v5 = sub_4009E8();
      goto LABEL_14;
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        v5 = sub_400B07();
        goto LABEL_14;
      }
      if ( v3 == 4 )
      {
        v5 = sub_400BA9();
        goto LABEL_14;
      }
    }
    else if ( v3 == 1 )
    {
      v5 = sub_400936();
      goto LABEL_14;
    }
    v5 = -1;
LABEL_14:
    if ( v5 )
      puts("FAIL");
    else
      puts("OK");
    fflush(stdout);
  }
  return 0;
}

__int64 sub_4009E8()
{
  int i; // eax
  unsigned int v2; // [rsp+8h] [rbp-88h]
  __int64 n; // [rsp+10h] [rbp-80h]
  char *ptr; // [rsp+18h] [rbp-78h]
  char s[104]; // [rsp+20h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v2 = atol(s);
  if ( v2 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v2] )
    return 0xFFFFFFFFLL;
  fgets(s, 16, stdin);
  n = atoll(s);
  ptr = (&::s)[v2];
  for ( i = fread(ptr, 1u, n, stdin); i > 0; i = fread(ptr, 1u, n, stdin) )
  {
    ptr += i;
    n -= i;
  }
  if ( n )
    return 0xFFFFFFFFLL;
  else
    return 0;
}

__int64 sub_400B07()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v1 = atol(s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v1] )
    return 0xFFFFFFFFLL;
  free((&::s)[v1]);
  (&::s)[v1] = 0;
  return 0;
}

__int64 sub_400BA9()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v1 = atol(s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v1] )
    return 0xFFFFFFFFLL;
  if ( strlen((&::s)[v1]) <= 3 )
    puts("//TODO");
  else
    puts("...");
  return 0;
}

__int64 sub_400936()
{
  __int64 size; // [rsp+0h] [rbp-80h]
  char *v2; // [rsp+8h] [rbp-78h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  size = atoll(s);
  v2 = (char *)malloc(size);
  if ( !v2 )
    return 0xFFFFFFFFLL;
  (&::s)[++dword_602100] = v2;
  printf("%d\n", dword_602100);
  return 0;
}