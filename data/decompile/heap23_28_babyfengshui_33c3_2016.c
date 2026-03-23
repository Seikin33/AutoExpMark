void __noreturn main()
{
  char v0; // [esp+3h] [ebp-15h] BYREF
  int v1; // [esp+4h] [ebp-14h] BYREF
  size_t v2[4]; // [esp+8h] [ebp-10h] BYREF

  v2[1] = __readgsdword(0x14u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  alarm(0x14u);
  while ( 1 )
  {
    puts("0: Add a user");
    puts("1: Delete a user");
    puts("2: Display a user");
    puts("3: Update a user description");
    puts("4: Exit");
    printf("Action: ");
    if ( __isoc99_scanf("%d", &v1) == -1 )
      break;
    if ( !v1 )
    {
      printf("size of description: ");
      __isoc99_scanf("%u%c", v2, &v0);
      add(v2[0]);
    }
    if ( v1 == 1 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      delete(v2[0]);
    }
    if ( v1 == 2 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      display(v2[0]);
    }
    if ( v1 == 3 )
    {
      printf("index: ");
      __isoc99_scanf("%d", v2);
      update(v2[0]);
    }
    if ( v1 == 4 )
    {
      puts("Bye");
      exit(0);
    }
    if ( (unsigned __int8)byte_804B069 > 0x31u )
    {
      puts("maximum capacity exceeded, bye");
      exit(0);
    }
  }
  exit(1);
}

_DWORD *__cdecl add(size_t a1)
{
  void *s; // [esp+14h] [ebp-14h]
  _DWORD *v3; // [esp+18h] [ebp-10h]

  s = malloc(a1);
  memset(s, 0, a1);
  v3 = malloc(0x80u);
  memset(v3, 0, 0x80u);
  *v3 = s;
  *(&ptr + (unsigned __int8)byte_804B069) = v3;
  printf("name: ");
  sub_80486BB((char *)*(&ptr + (unsigned __int8)byte_804B069) + 4, 124);
  update(byte_804B069++);
  return v3;
}

unsigned int __cdecl sub_80486BB(char *a1, int a2)
{
  char *v3; // [esp+18h] [ebp-10h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  fgets(a1, a2, stdin);
  v3 = strchr(a1, 10);
  if ( v3 )
    *v3 = 0;
  return __readgsdword(0x14u) ^ v4;
}

unsigned int __cdecl delete(unsigned __int8 a1)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    free(*(void **)*(&ptr + a1));
    free(*(&ptr + a1));
    *(&ptr + a1) = 0;
  }
  return __readgsdword(0x14u) ^ v2;
}

unsigned int __cdecl display(unsigned __int8 a1)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    printf("name: %s\n", (const char *)*(&ptr + a1) + 4);
    printf("description: %s\n", *(const char **)*(&ptr + a1));
  }
  return __readgsdword(0x14u) ^ v2;
}

unsigned int __cdecl update(unsigned __int8 a1)
{
  char v2; // [esp+17h] [ebp-11h] BYREF
  int v3; // [esp+18h] [ebp-10h] BYREF
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if ( a1 < (unsigned __int8)byte_804B069 && *(&ptr + a1) )
  {
    v3 = 0;
    printf("text length: ");
    __isoc99_scanf("%u%c", &v3, &v2);
    if ( (char *)(v3 + *(_DWORD *)*(&ptr + a1)) >= (char *)*(&ptr + a1) - 4 )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
    printf("text: ");
    sub_80486BB(*(char **)*(&ptr + a1), v3 + 1);
  }
  return __readgsdword(0x14u) ^ v4;
}

