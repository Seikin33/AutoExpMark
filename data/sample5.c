int sub_8048640()
{
  int result; // eax

  result = &unk_804D06B - &unk_804D068;
  if ( (unsigned int)(&unk_804D06B - &unk_804D068) > 6 )
    return 0;
  return result;
}

int sub_80486B0()
{
  int result; // eax

  if ( !byte_804D088 )
  {
    result = sub_8048640();
    byte_804D088 = 1;
  }
  return result;
}

int sub_80486D0()
{
  return 0;
}

void __cdecl sub_80486FB(int *a1)
{
  int i; // [esp+Ch] [ebp-Ch]

  for ( i = sub_804890F(a1); i; i = sub_804890F(a1) )
    sub_80487B5(a1, i - 1);
  free((void *)*a1);
}

_DWORD *__cdecl sub_8048754(_DWORD *a1, int a2)
{
  _DWORD *result; // eax
  _DWORD *v3; // [esp+8h] [ebp-10h]
  _DWORD *v4; // [esp+Ch] [ebp-Ch]

  v3 = (_DWORD *)*a1;
  v4 = calloc(1u, 8u);
  *v4 = a2;
  v4[1] = 0;
  if ( v3 )
  {
    while ( v3[1] )
      v3 = (_DWORD *)v3[1];
    result = v3;
    v3[1] = v4;
  }
  else
  {
    result = a1;
    *a1 = v4;
  }
  return result;
}

void __cdecl sub_80487B5(int *a1, unsigned int a2)
{
  int v2; // [esp+0h] [ebp-18h]
  void **ptr; // [esp+4h] [ebp-14h]
  unsigned int v4; // [esp+8h] [ebp-10h]
  void **v5; // [esp+Ch] [ebp-Ch]

  v2 = 1;
  v4 = sub_804890F(a1);
  ptr = (void **)*a1;
  if ( v4 )
  {
    if ( a2 )
    {
      if ( v4 > a2 )
      {
        while ( v2 != a2 )
        {
          ptr = (void **)ptr[1];
          ++v2;
        }
        v5 = (void **)ptr[1];
        ptr[1] = v5[1];
        free(*v5);
        free(v5);
        if ( sub_804890F(a1) == v2 )
          ptr[1] = 0;
      }
    }
    else if ( v4 == 1 )
    {
      free(*ptr);
      free(ptr);
      *a1 = 0;
    }
    else
    {
      *a1 = (int)ptr[1];
      free(*ptr);
      free(ptr);
    }
  }
}

int __cdecl sub_80488C2(int *a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-10h]
  _DWORD *v4; // [esp+Ch] [ebp-Ch]

  if ( sub_804890F(a1) <= a2 )
    return 0;
  v3 = 0;
  v4 = (_DWORD *)*a1;
  while ( v3 != a2 )
  {
    v4 = (_DWORD *)v4[1];
    ++v3;
  }
  return *v4;
}

int __cdecl sub_804890F(int *a1)
{
  int v2; // [esp+8h] [ebp-8h]
  int v3; // [esp+Ch] [ebp-4h]

  v2 = 1;
  v3 = *a1;
  if ( !*a1 )
    return 0;
  while ( *(_DWORD *)(v3 + 4) )
  {
    v3 = *(_DWORD *)(v3 + 4);
    ++v2;
  }
  return v2;
}

unsigned int sub_804894D()
{
  char *s2; // [esp+Ch] [ebp-ACh]
  char v2[10]; // [esp+A2h] [ebp-16h] BYREF
  unsigned int v3; // [esp+ACh] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  while ( 1 )
  {
    puts("====================");
    puts("[l]ist ingredients");
    puts("[r]ecipe book");
    puts("[a]dd ingredient");
    puts("[c]reate recipe");
    puts("[e]xterminate ingredient");
    puts("[d]elete recipe");
    puts("[g]ive your cookbook a name!");
    puts("[R]emove cookbook name");
    puts("[q]uit");
    fgets(v2, 10, stdin);
    switch ( v2[0] )
    {
      case 'R':
        sub_8048B4E();
        break;
      case 'a':
        sub_8048C7B();
        break;
      case 'c':
        sub_8049092();
        break;
      case 'e':
        s2 = (char *)calloc(0x80u, 1u);
        printf("which ingredient to exterminate? ");
        fgets(s2, 128, stdin);
        s2[strcspn(s2, "\n")] = 0;
        sub_80497F9(s2);
        free(s2);
        break;
      case 'g':
        sub_8048B68();
        break;
      case 'l':
        sub_804A261();
        break;
      case 'q':
        puts("goodbye, thanks for cooking with us!");
        return __readgsdword(0x14u) ^ v3;
      case 'r':
        sub_80496FA();
        break;
      default:
        puts("UNKNOWN DIRECTIVE");
        break;
    }
  }
}

void sub_8048B4E()
{
  free(ptr);
}

unsigned int sub_8048B68()
{
  unsigned int size; // [esp+8h] [ebp-50h]
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  unsigned int v3; // [esp+4Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) : ");
  fgets(s, 64, stdin);
  size = strtoul(s, 0, 16);
  ptr = (char *)malloc(size);
  fgets(ptr, size, stdin);
  printf("the new name of the cookbook is %s\n", ptr);
  return __readgsdword(0x14u) ^ v3;
}

void sub_8048C0F()
{
  char *v0; // ebx

  puts("what's your name?");
  dword_804D0AC = (char *)calloc(0x40u, 1u);
  fgets(dword_804D0AC, 64, stdin);
  v0 = dword_804D0AC;
  v0[strcspn(dword_804D0AC, "\n")] = 0;
}

unsigned int sub_8048C7B()
{
  char *v1; // [esp+8h] [ebp-30h]
  char *nptr; // [esp+Ch] [ebp-2Ch]
  char *v3; // [esp+14h] [ebp-24h]
  char v4[10]; // [esp+22h] [ebp-16h] BYREF
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  while ( 1 )
  {
    puts("====================");
    puts("[l]ist current stats?");
    puts("[n]ew ingredient?");
    puts("[c]ontinue editing ingredient?");
    puts("[d]iscard current ingredient?");
    puts("[g]ive name to ingredient?");
    puts("[p]rice ingredient?");
    puts("[s]et calories?");
    puts("[q]uit (doesn't save)?");
    puts("[e]xport saving changes (doesn't quit)?");
    fgets(v4, 10, stdin);
    v4[strcspn(v4, "\n")] = 0;
    switch ( v4[0] )
    {
      case 'c':
        puts("still editing this guy");
        break;
      case 'd':
        free(dword_804D09C);
        dword_804D09C = 0;
        break;
      case 'e':
        if ( dword_804D09C )
        {
          if ( sub_8049C58((char *)dword_804D09C + 8) == -1 && *((_BYTE *)dword_804D09C + 8) )
          {
            sub_8048754(&dword_804D094, (int)dword_804D09C);
            dword_804D09C = 0;
            puts("saved!");
          }
          else
          {
            puts("can't save because this is bad.");
          }
        }
        else
        {
          puts("can't do it on a null guy");
        }
        break;
      case 'g':
        v1 = (char *)calloc(0x80u, 1u);
        if ( dword_804D09C )
        {
          fgets(v1, 128, stdin);
          v1[strcspn(v1, "\n")] = 0;
          memcpy((char *)dword_804D09C + 8, v1, 0x80u);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(v1);
        break;
      case 'l':
        if ( dword_804D09C )
          sub_804A214((int)dword_804D09C);
        else
          puts("can't print NULL!");
        break;
      case 'n':
        dword_804D09C = malloc(0x90u);
        *((_DWORD *)dword_804D09C + 35) = dword_804D09C;
        break;
      case 'p':
        nptr = (char *)calloc(0x80u, 1u);
        if ( dword_804D09C )
        {
          fgets(nptr, 128, stdin);
          nptr[strcspn(nptr, "\n")] = 0;
          *((_DWORD *)dword_804D09C + 1) = atoi(nptr);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(nptr);
        break;
      case 'q':
        return __readgsdword(0x14u) ^ v5;
      case 's':
        v3 = (char *)calloc(0x80u, 1u);
        if ( dword_804D09C )
        {
          fgets(v3, 128, stdin);
          v3[strcspn(v3, "\n")] = 0;
          *(_DWORD *)dword_804D09C = atoi(v3);
        }
        else
        {
          puts("can't do it on a null guy");
        }
        free(v3);
        break;
      default:
        puts("UNKNOWN DIRECTIVE");
        break;
    }
  }
}

unsigned int sub_8049092()
{
  int v1; // [esp+Ch] [ebp-CCh]
  _DWORD *v2; // [esp+10h] [ebp-C8h]
  int v3; // [esp+18h] [ebp-C0h]
  unsigned int v4; // [esp+1Ch] [ebp-BCh]
  int v5; // [esp+20h] [ebp-B8h]
  char s[10]; // [esp+32h] [ebp-A6h] BYREF
  char nptr[144]; // [esp+3Ch] [ebp-9Ch] BYREF
  unsigned int v8; // [esp+CCh] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  while ( 1 )
  {
LABEL_2:
    puts("[n]ew recipe");
    puts("[d]iscard recipe");
    puts("[a]dd ingredient");
    puts("[r]emove ingredient");
    puts("[g]ive recipe a name");
    puts("[i]nclude instructions");
    puts("[s]ave recipe");
    puts("[p]rint current recipe");
    puts("[q]uit");
    fgets(s, 10, stdin);
    s[strcspn(s, "\n")] = 0;
    switch ( s[0] )
    {
      case 'a':
        if ( !dword_804D0A0 )
          puts("can't do it on a null guy");
        printf("which ingredient to add? ");
        fgets(nptr, 144, stdin);
        nptr[strcspn(nptr, "\n")] = 0;
        v3 = sub_8049D44(nptr);
        if ( v3 )
        {
          printf("how many? (hex): ");
          fgets(nptr, 144, stdin);
          nptr[strcspn(nptr, "\n")] = 0;
          v4 = strtoul(nptr, 0, 16);
          sub_8048754(dword_804D0A0, v3);
          sub_8048754((_DWORD *)dword_804D0A0 + 1, v4);
          puts("nice");
        }
        else
        {
          printf("I dont know about, %s!, please add it to the ingredient list!\n", nptr);
        }
        continue;
      case 'd':
        free(dword_804D0A0);
        continue;
      case 'g':
        if ( !dword_804D0A0 )
          goto LABEL_23;
        fgets((char *)dword_804D0A0 + 140, 1036, stdin);
        continue;
      case 'i':
        if ( !dword_804D0A0 )
          goto LABEL_23;
        fgets((char *)dword_804D0A0 + 140, 1036, stdin);
        s[strcspn(s, "\n")] = 0;
        continue;
      case 'n':
        dword_804D0A0 = calloc(1u, 0x40Cu);
        continue;
      case 'p':
        if ( dword_804D0A0 )
          sub_80495D6(dword_804D0A0);
        continue;
      case 'q':
        return __readgsdword(0x14u) ^ v8;
      case 'r':
        if ( !dword_804D0A0 )
          goto LABEL_23;
        printf("which ingredient to remove? ");
        fgets(nptr, 144, stdin);
        v1 = 0;
        v2 = *(_DWORD **)dword_804D0A0;
        break;
      case 's':
        if ( dword_804D0A0 )
        {
          if ( sub_8049CB8((char *)dword_804D0A0 + 8) == -1 && *((_BYTE *)dword_804D0A0 + 8) )
          {
            *((_DWORD *)dword_804D0A0 + 31) = off_804D064;
            sub_8048754(&dword_804D08C, (int)dword_804D0A0);
            dword_804D0A0 = 0;
            puts("saved!");
          }
          else
          {
            puts("can't save because this is bad.");
          }
        }
        else
        {
LABEL_23:
          puts("can't do it on a null guy");
        }
        continue;
      default:
        puts("UNKNOWN DIRECTIVE");
        continue;
    }
    while ( v2 )
    {
      v5 = *v2;
      if ( !strcmp((const char *)(*v2 + 8), nptr) )
      {
        sub_80487B5(dword_804D0A0, v1);
        sub_80487B5((char *)dword_804D0A0 + 4, v1);
        printf("deleted %s from the recipe!\n", (const char *)(v5 + 8));
        goto LABEL_2;
      }
      ++v1;
      v2 = (_DWORD *)v2[1];
    }
  }
}

unsigned int __cdecl sub_80495D6(int a1)
{
  int v1; // eax
  int v2; // eax
  int v4; // [esp+14h] [ebp-24h] BYREF
  int v5; // [esp+18h] [ebp-20h] BYREF
  unsigned int i; // [esp+1Ch] [ebp-1Ch]
  unsigned int v7; // [esp+20h] [ebp-18h]
  int v8; // [esp+24h] [ebp-14h]
  int v9; // [esp+28h] [ebp-10h]
  unsigned int v10; // [esp+2Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  v4 = *(_DWORD *)a1;
  v5 = *(_DWORD *)(a1 + 4);
  v7 = sub_804890F(&v4);
  printf("[---%s---]\n", (const char *)(a1 + 8));
  printf("recipe type: %s\n", *(const char **)(a1 + 124));
  puts((const char *)(a1 + 140));
  for ( i = 0; i < v7; ++i )
  {
    v8 = sub_80488C2(&v5, i);
    v9 = sub_80488C2(&v4, i);
    printf("%zd - %s\n", v8, (const char *)(v9 + 8));
  }
  v1 = sub_8049AA6(a1);
  printf("total cost : $%zu\n", v1);
  v2 = sub_8049B4A(a1);
  printf("total cals : %zu\n", v2);
  return __readgsdword(0x14u) ^ v10;
}

unsigned int sub_80496FA()
{
  unsigned int result; // eax
  unsigned int i; // [esp+4h] [ebp-14h]
  unsigned int v2; // [esp+8h] [ebp-10h]
  int v3; // [esp+Ch] [ebp-Ch]

  v2 = sub_804890F(&dword_804D08C);
  printf("%s's cookbook", dword_804D0AC);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= v2 )
      break;
    v3 = sub_80488C2(&dword_804D08C, i);
    sub_80495D6(v3);
  }
  return result;
}

int __cdecl sub_8049762(int *a1, const char *a2)
{
  int v3; // [esp+1Ch] [ebp-1Ch] BYREF
  unsigned int i; // [esp+20h] [ebp-18h]
  unsigned int v5; // [esp+24h] [ebp-14h]
  int v6; // [esp+28h] [ebp-10h]
  unsigned int v7; // [esp+2Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v3 = *a1;
  v5 = sub_804890F(&v3);
  for ( i = 0; i < v5; ++i )
  {
    v6 = sub_80488C2(&v3, i);
    if ( !strcmp((const char *)(v6 + 8), a2) )
      return 1;
  }
  return 0;
}

void __cdecl sub_80497F9(char *s2)
{
  signed int i; // [esp+8h] [ebp-30h]
  signed int j; // [esp+Ch] [ebp-2Ch]
  signed int k; // [esp+10h] [ebp-28h]
  unsigned int v4; // [esp+14h] [ebp-24h]
  int v5; // [esp+1Ch] [ebp-1Ch]
  int v6; // [esp+24h] [ebp-14h]
  int v7; // [esp+2Ch] [ebp-Ch]

  v4 = sub_8049C58(s2);
  if ( v4 != -1 )
  {
    sub_80487B5(&dword_804D094, v4);
    for ( i = sub_804890F(&dword_804D098) - 1; i >= 0; --i )
    {
      v5 = sub_80488C2(&dword_804D098, i);
      if ( !strcmp((const char *)(v5 + 8), s2) )
        sub_80487B5(&dword_804D098, i);
    }
    for ( j = sub_804890F(&dword_804D08C) - 1; j >= 0; --j )
    {
      v6 = sub_80488C2(&dword_804D08C, j);
      if ( sub_8049762(v6, s2) )
        sub_80487B5(&dword_804D08C, j);
    }
    for ( k = sub_804890F(&dword_804D090) - 1; k >= 0; --k )
    {
      v7 = sub_80488C2(&dword_804D090, k);
      if ( sub_8049762(v7, s2) )
        sub_80487B5(&dword_804D090, k);
    }
  }
}

void __cdecl sub_804996E(char *s2)
{
  unsigned int i; // [esp+Ch] [ebp-1Ch]
  unsigned int j; // [esp+10h] [ebp-18h]
  unsigned int v3; // [esp+14h] [ebp-14h]
  unsigned int v4; // [esp+14h] [ebp-14h]
  int v5; // [esp+18h] [ebp-10h]
  int v6; // [esp+1Ch] [ebp-Ch]

  v3 = sub_804890F(&dword_804D08C);
  for ( i = 0; i < v3; ++i )
  {
    v5 = sub_80488C2(&dword_804D08C, i);
    if ( !strcmp((const char *)(v5 + 8), s2) )
    {
      sub_80487B5(&dword_804D08C, i);
      break;
    }
  }
  v4 = sub_804890F(&dword_804D090);
  for ( j = 0; j < v4; ++j )
  {
    v6 = sub_80488C2(&dword_804D090, j);
    if ( !strcmp((const char *)(v6 + 8), s2) )
    {
      sub_80487B5(&dword_804D090, j);
      return;
    }
  }
}

int sub_8049A50()
{
  unsigned int i; // [esp+0h] [ebp-18h]
  int v2; // [esp+4h] [ebp-14h]
  unsigned int v3; // [esp+8h] [ebp-10h]

  v3 = sub_804890F(&dword_804D098);
  v2 = 0;
  for ( i = 0; i < v3; ++i )
    v2 += *(_DWORD *)(sub_80488C2(&dword_804D098, i) + 4);
  return v2;
}

int __cdecl sub_8049AA6(int *a1)
{
  int v2; // [esp+10h] [ebp-28h] BYREF
  int v3; // [esp+14h] [ebp-24h] BYREF
  int v4; // [esp+18h] [ebp-20h]
  unsigned int i; // [esp+1Ch] [ebp-1Ch]
  unsigned int v6; // [esp+20h] [ebp-18h]
  int v7; // [esp+24h] [ebp-14h]
  int v8; // [esp+28h] [ebp-10h]
  unsigned int v9; // [esp+2Ch] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  v2 = *a1;
  v3 = a1[1];
  v4 = 0;
  v6 = sub_804890F(&v2);
  for ( i = 0; i < v6; ++i )
  {
    v7 = sub_80488C2(&v3, i);
    v8 = sub_80488C2(&v2, i);
    v4 += *(_DWORD *)(v8 + 4) * v7;
  }
  return v4;
}

int __cdecl sub_8049B4A(int *a1)
{
  int v2; // [esp+10h] [ebp-28h] BYREF
  int v3; // [esp+14h] [ebp-24h] BYREF
  int v4; // [esp+18h] [ebp-20h]
  unsigned int i; // [esp+1Ch] [ebp-1Ch]
  unsigned int v6; // [esp+20h] [ebp-18h]
  int v7; // [esp+24h] [ebp-14h]
  _DWORD *v8; // [esp+28h] [ebp-10h]
  unsigned int v9; // [esp+2Ch] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  v2 = *a1;
  v3 = a1[1];
  v4 = 0;
  v6 = sub_804890F(&v2);
  for ( i = 0; i < v6; ++i )
  {
    v7 = sub_80488C2(&v3, i);
    v8 = (_DWORD *)sub_80488C2(&v2, i);
    v4 += *v8 * v7;
  }
  return v4;
}

void sub_8049BED()
{
  free(dword_804D0AC);
  free(ptr);
  sub_80486FB(&dword_804D08C);
  sub_80486FB(&dword_804D090);
  sub_80486FB(&dword_804D094);
  sub_80486FB(&dword_804D098);
}

int __cdecl sub_8049C58(char *s2)
{
  int v2; // [esp+4h] [ebp-14h]
  _DWORD *i; // [esp+8h] [ebp-10h]

  v2 = 0;
  for ( i = (_DWORD *)dword_804D094; i && *i; i = (_DWORD *)i[1] )
  {
    if ( !strcmp((const char *)(*i + 8), s2) )
      return v2;
    ++v2;
  }
  return -1;
}

int __cdecl sub_8049CB8(char *s2)
{
  int v2; // [esp+4h] [ebp-14h]
  _DWORD *i; // [esp+8h] [ebp-10h]

  v2 = 0;
  for ( i = (_DWORD *)dword_804D08C; i && *i; i = (_DWORD *)i[1] )
  {
    if ( !strcmp((const char *)(*i + 8), s2) )
      return v2;
    ++v2;
  }
  return -1;
}

int __cdecl sub_8049D18(char *s2)
{
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = sub_8049CB8(s2);
  return sub_80488C2(&dword_804D08C, v2);
}

int __cdecl sub_8049D44(char *s2)
{
  int v2; // [esp+Ch] [ebp-Ch]

  v2 = sub_8049C58(s2);
  return sub_80488C2(&dword_804D094, v2);
}

_DWORD *__cdecl sub_8049D70(int a1, int a2, void *src, size_t n)
{
  _DWORD *v5; // [esp+Ch] [ebp-Ch]

  v5 = calloc(1u, 0x90u);
  *v5 = a1;
  v5[1] = a2;
  memcpy(v5 + 2, src, n);
  v5[35] = v5;
  return v5;
}

int sub_8049DC5()
{
  int v1; // [esp+0h] [ebp-28h]
  int v2; // [esp+4h] [ebp-24h]
  int v3; // [esp+8h] [ebp-20h]
  int v4; // [esp+Ch] [ebp-1Ch]
  int v5; // [esp+10h] [ebp-18h]
  int v6; // [esp+14h] [ebp-14h]
  int v7; // [esp+18h] [ebp-10h]
  int v8; // [esp+1Ch] [ebp-Ch]

  v1 = sub_8049D70(0, 6, (void *)"water", 5u);
  v2 = sub_8049D70(1, 5, (void *)"tomato", 6u);
  v3 = sub_8049D70(2, 4, (void *)"basil", 5u);
  v4 = sub_8049D70(3, 3, (void *)"garlic", 6u);
  v5 = sub_8049D70(4, 2, "onion", 5u);
  v6 = sub_8049D70(5, 1, "lemon", 5u);
  v7 = sub_8049D70(6, 10, (void *)"corn", 4u);
  v8 = sub_8049D70(2, 3, (void *)"olive oil", 9u);
  sub_8048754(&dword_804D094, v1);
  sub_8048754(&dword_804D094, v2);
  sub_8048754(&dword_804D094, v3);
  sub_8048754(&dword_804D094, v4);
  sub_8048754(&dword_804D094, v5);
  sub_8048754(&dword_804D094, v6);
  sub_8048754(&dword_804D094, v7);
  return sub_8048754(&dword_804D094, v8);
}

unsigned int sub_8049F16()
{
  int v1; // [esp+0h] [ebp-48h] BYREF
  int v2; // [esp+4h] [ebp-44h] BYREF
  int v3; // [esp+8h] [ebp-40h] BYREF
  int v4; // [esp+Ch] [ebp-3Ch] BYREF
  int v5; // [esp+10h] [ebp-38h] BYREF
  int v6; // [esp+14h] [ebp-34h] BYREF
  _DWORD *v7; // [esp+18h] [ebp-30h]
  int v8; // [esp+1Ch] [ebp-2Ch]
  _DWORD *v9; // [esp+20h] [ebp-28h]
  int v10; // [esp+24h] [ebp-24h]
  int v11; // [esp+28h] [ebp-20h]
  int v12; // [esp+2Ch] [ebp-1Ch]
  int v13; // [esp+30h] [ebp-18h]
  _DWORD *v14; // [esp+34h] [ebp-14h]
  int v15; // [esp+38h] [ebp-10h]
  unsigned int v16; // [esp+3Ch] [ebp-Ch]

  v16 = __readgsdword(0x14u);
  v7 = calloc(1u, 0x40Cu);
  v1 = 0;
  v8 = sub_8049D44("corn");
  sub_8048754(&v1, v8);
  *v7 = v1;
  v2 = 0;
  memcpy(v7 + 2, "grilled corn", 0xCu);
  memcpy(v7 + 35, "just grill it on a tiny .vn grill", 0x21u);
  sub_8048754(&v2, 4);
  v7[1] = v2;
  v7[31] = off_804D054;
  sub_8048754(&dword_804D08C, v7);
  v9 = calloc(1u, 0x40Cu);
  memcpy(v9 + 2, "roasted tomato with basil and garlic", 0x24u);
  memcpy(
    v9 + 35,
    "first quarter the tomatoes, then mix with garlic and olive oil, top with chopped basil, bake at 275f for 2 hours.",
    0x71u);
  v3 = 0;
  v10 = sub_8049D44("tomato");
  v11 = sub_8049D44("basil");
  v12 = sub_8049D44("garlic");
  v13 = sub_8049D44("olive oil");
  sub_8048754(&v3, v10);
  sub_8048754(&v3, v11);
  sub_8048754(&v3, v12);
  sub_8048754(&v3, v13);
  v4 = 0;
  sub_8048754(&v4, 16);
  sub_8048754(&v4, 5);
  sub_8048754(&v4, 8);
  sub_8048754(&v4, 2);
  *v9 = v3;
  v9[1] = v4;
  v9[31] = off_804D058;
  sub_8048754(&dword_804D08C, v9);
  v14 = calloc(1u, 0x40Cu);
  v5 = 0;
  v15 = sub_8049D44("water");
  sub_8048754(&v5, v15);
  *v14 = v5;
  v6 = 0;
  memcpy(v14 + 2, "water", 5u);
  memcpy(v14 + 35, "pour it in a glass", 0x12u);
  sub_8048754(&v6, 1);
  v14[1] = v6;
  v14[31] = off_804D05C;
  sub_8048754(&dword_804D08C, v14);
  return __readgsdword(0x14u) ^ v16;
}

int __cdecl sub_804A214(int a1)
{
  printf("name: %s\n", (const char *)(a1 + 8));
  printf("calories: %zd\n", *(_DWORD *)a1);
  return printf("price: %zd\n", *(_DWORD *)(a1 + 4));
}

int sub_804A261()
{
  int result; // eax
  _DWORD *v1; // [esp+8h] [ebp-10h]

  result = dword_804D094;
  v1 = (_DWORD *)dword_804D094;
  while ( v1 )
  {
    puts("------");
    sub_804A214(*v1);
    result = v1[1];
    v1 = (_DWORD *)result;
    if ( !result )
      result = puts("------");
  }
  return result;
}

int sub_804A2BF()
{
  sub_8049DC5();
  return sub_8049F16();
}

int sub_804A2D2()
{
  puts("+-----------------------------+");
  puts("|          .--,--.            |");
  puts("|          `.  ,.'            |");
  puts("|           |___|             |");
  puts("|           :o o:             |");
  puts("|          _`~^~'             |");
  puts("|        /'   ^   `\\          |");
  puts("| cooking manager pro v6.1... |");
  return puts("+-----------------------------+");
}

int sub_804A36B()
{
  puts("   emmmmmm~~~~~~~~~~oT");
  puts("          |          |");
  puts("          |          |");
  return puts("          `----------'");
}

int __cdecl main(int a1, char **a2)
{
  unsigned int v2; // eax

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  if ( a1 > 1 )
  {
    v2 = atoi(a2[1]);
    alarm(v2);
  }
  sub_8048C0F();
  sub_804A2D2(&a1);
  sub_804A2BF();
  sub_804894D();
  sub_8049BED();
  sub_804A36B();
  return 0;
}