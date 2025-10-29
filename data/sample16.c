unsigned __int64 __fastcall sub_4008DD(__int64 a1, __int64 a2, char a3)
{
  char buf; // [rsp+2Fh] [rbp-11h] BYREF
  unsigned __int64 i; // [rsp+30h] [rbp-10h]
  ssize_t v7; // [rsp+38h] [rbp-8h]

  for ( i = 0; a2 - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1u);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(a1 + i) = 0;
  return i;
}

int sub_40096A()
{
  char nptr[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  sub_4008DD((__int64)nptr, 16, 10);
  return atoi(nptr);
}

__int64 sub_4009B9()
{
  __int64 v1; // [rsp+8h] [rbp-38h]
  char nptr[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  sub_4008DD((__int64)nptr, 32, 10);
  v1 = atol(nptr);
  if ( v1 < 0 )
    return -v1;
  return v1;
}

int sub_400A1B()
{
  puts("1.New note\n2.Show note\n3.Edit note\n4.Delete note\n5.Quit\noption--->>");
  return sub_40096A();
}

int sub_400A30()
{
  int i; // [rsp+Ch] [rbp-14h]
  __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 6 && *(&ptr + i); ++i )
    ;
  if ( i == 7 )
    puts("Note is full, add fail");
  puts("Input the length of the note content:(less than 1024)");
  size = sub_4009B9();
  if ( size < 0 )
    return puts("Length error");
  if ( size > 1024 )
    return puts("Content is too long");
  v3 = malloc(size);
  puts("Input the note content:");
  sub_4008DD((__int64)v3, size, 10);
  *(&ptr + i) = v3;
  qword_6020C0[i + 8] = size;
  qword_6020C0[0] = (__int64)*(&ptr + i);
  return printf("note add success, the id is %d\n", i);
}

int sub_400B33()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7;
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      free(*(&ptr + v3));
      if ( (void *)qword_6020C0[0] == *(&ptr + v3) )
        qword_6020C0[0] = 0;
      *(&ptr + v3) = 0;
      LODWORD(v1) = puts("Delete success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}

int sub_400BFD()
{
  return puts("No show, No leak.");
}

int sub_400C0D()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7;
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      puts("Input the new content:");
      sub_4008DD((__int64)*(&ptr + v3), qword_6020C0[v3 + 8], 10);
      qword_6020C0[0] = (__int64)*(&ptr + v3);
      LODWORD(v1) = puts("Edit success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}

void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(0x3Cu);
  while ( 1 )
  {
    switch ( sub_400A1B() )
    {
      case 1:
        sub_400A30();
        break;
      case 2:
        sub_400BFD();
        break;
      case 3:
        sub_400C0D();
        break;
      case 4:
        sub_400B33();
        break;
      case 5:
        puts("Bye~");
        exit(0);
      case 6:
        exit(0);
      default:
        continue;
    }
  }
}