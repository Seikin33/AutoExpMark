int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  init();
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        v3 = read_int();
        if ( v3 != 2 )
          break;
        fr();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      ma();
    }
    if ( v3 == 3 )
    {
      ed();
    }
    else
    {
      if ( v3 != 4 )
LABEL_13:
        exit(1);
      sh();
    }
  }
}

unsigned __int64 menu()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("1.malloc");
  puts("2.free");
  puts("3.edit");
  puts("4.show");
  return __readfsqword(0x28u) ^ v1;
}

int read_int()
{
  char buf[8]; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  read(0, buf, 8u);
  return atoi(buf);
}

unsigned __int64 fr()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("index:");
  v1 = read_int();
  if ( (unsigned int)v1 > 0x20 || !*((_QWORD *)&heap + v1) )
    exit(0);
  free(*((void **)&heap + v1));
  *((_QWORD *)&heap + v1) = 0;
  len[v1] = 0;
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 ma()
{
  int v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index:");
  v1 = read_int();
  if ( (unsigned int)v1 > 0x20 || *((_QWORD *)&heap + v1) )
    exit(0);
  puts("size:");
  v2 = read_int();
  if ( v2 <= 127 || v2 > 256 )
    exit(0);
  *((_QWORD *)&heap + v1) = malloc(v2);
  len[v1] = v2;
  printf("gift: %llx\n", *((_QWORD *)&heap + v1));
  puts("content:");
  read(0, *((void **)&heap + v1), v2);
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 ed()
{
  int v1; // [rsp+Ch] [rbp-14h]
  _BYTE *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( key1 == 2 )
    exit(0);
  puts("index:");
  v1 = read_int();
  if ( (unsigned int)v1 > 0x20 || !heap[v1] )
    exit(0);
  puts("content:");
  v2 = (_BYTE *)heap[v1];
  v2[read(0, v2, (int)len[v1])] = 0;
  ++key1;
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 sh()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( key2 )
  {
    puts("index:");
    v1 = read_int();
    if ( v1 > 0x20 || !heap[v1] )
      exit(0);
    puts((const char *)heap[v1]);
  }
  else
  {
    puts("only admin can use");
  }
  return __readfsqword(0x28u) ^ v2;
}