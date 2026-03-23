void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int choice; // eax

  setbuf_init(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      choice = read_int();
      if ( choice != 2 )
        break;
      delete();
    }
    if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        show();
      }
      else
      {
        if ( choice == 4 )
          exit(1);
LABEL_13:
        puts("Wrong choice");
      }
    }
    else
    {
      if ( choice != 1 )
        goto LABEL_13;
      create();
    }
  }
}

int delete()
{
  void **v0; // rax
  int idx; // [rsp+Ch] [rbp-4h]

  puts("Index: ");
  LODWORD(v0) = read_int();
  idx = (int)v0;
  if ( (unsigned int)v0 <= 6 )
  {
    free(heap_ptr[(unsigned int)v0]);
    v0 = heap_ptr;
    heap_ptr[idx] = 0;
  }
  return (int)v0;
}

void create()
{
  int i; // [rsp+0h] [rbp-10h]
  int v1; // [rsp+4h] [rbp-Ch]
  void *ptr; // [rsp+8h] [rbp-8h]

  puts("Size: ");
  v1 = read_int();
  ptr = malloc(v1);
  if ( ptr )
  {
    for ( i = 0; i <= 6 && heap_ptr[i]; ++i )
      ;
    if ( i == 7 )
    {
      puts("List is Full!\n");
      free(ptr);
    }
    else
    {
      puts("Data: ");
      write((__int64)ptr, v1);
      heap_ptr[i] = ptr;
    }
  }
}

unsigned __int64 __fastcall write(__int64 addr, int len)
{
  char buf; // [rsp+13h] [rbp-Dh] BYREF
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < len; ++i )
  {
    if ( (int)read(0, &buf, 1u) < 0 )
      puts("Read error!\n");
    if ( buf == 10 )
      break;
    *(_BYTE *)(addr + i) = buf;
  }
  *(_BYTE *)(i + addr) = 0;
  return __readfsqword(0x28u) ^ v5;
}

int show()
{
  void *v0; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 6; ++i )
  {
    v0 = heap_ptr[i];
    if ( v0 )
      LODWORD(v0) = printf("%d : %s \n", i, (const char *)heap_ptr[i]);
  }
  return (int)v0;
}