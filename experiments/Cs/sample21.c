int sub_40079D()
{
  setvbuf(stdout, 0, 2, 0);
  return setvbuf(stdin, 0, 2, 0);
}

int sub_4007DF()
{
  char nptr[8]; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  v2 = 0;
  for ( i = 0; i <= 3; ++i )
  {
    read(0, &nptr[i], 1u);
    if ( nptr[i] == 10 )
    {
      nptr[i] = 0;
      break;
    }
    if ( nptr[i] > 57 || nptr[i] <= 47 )
    {
      printf("0x%x ", nptr[i]);
      return 0;
    }
  }
  v2 = atoi(nptr);
  if ( v2 >= 0 )
    return atoi(nptr);
  else
    return 0;
}

int sub_4008B7()
{
  int nbytes; // [rsp+Ch] [rbp-4h]

  if ( ptr )
    return puts("already check in");
  puts("how long?");
  nbytes = sub_4007DF();
  if ( nbytes <= 0 || nbytes > 128 )
    return puts("invalid length");
  ptr = malloc(nbytes);
  printf("give me more money : ");
  printf("\n%d\n", nbytes);
  read(0, ptr, (unsigned int)nbytes);
  return puts("in~");
}

void sub_40096D()
{
  if ( ptr )
  {
    puts("out~");
    free(ptr);
    ptr = 0;
  }
  else
  {
    puts("havn't check in");
  }
}

int sub_4009AF()
{
  return printf("\n=======EASY HOTEL========\n1. check in\n2. check out\n3. goodbye\nyour choice : ");
}

int sub_4009C4()
{
  int v0; // eax

  while ( 1 )
  {
    while ( 1 )
    {
      sub_4009AF();
      v0 = sub_4007DF();
      if ( v0 != 2 )
        break;
      sub_40096D();
    }
    if ( v0 == 3 )
      break;
    if ( v0 == 1 )
      sub_4008B7();
    else
      puts("invalid choice");
  }
  return puts("good bye~");
}

int sub_400A29()
{
  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
  char *dest; // [rsp+38h] [rbp-8h]

  dest = (char *)malloc(0x40u);
  puts("give me money~");
  read(0, buf, 0x40u);
  strcpy(dest, buf);
  ptr = dest;
  return sub_4009C4();
}

int sub_400A8E()
{
  __int64 i; // [rsp+10h] [rbp-40h]
  char v2[48]; // [rsp+20h] [rbp-30h] BYREF

  puts("who are u?");
  for ( i = 0; i <= 47; ++i )
  {
    read(0, &v2[i], 1u);
    if ( v2[i] == 10 )
    {
      v2[i] = 0;
      break;
    }
  }
  printf("%s, welcome to ISCC~ \n", v2);
  puts("give me your id ~~?");
  sub_4007DF();
  return sub_400A29();
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  sub_40079D();
  sub_400A8E();
  return 0;
}