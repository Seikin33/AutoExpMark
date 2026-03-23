int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+24h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf(&unk_10C8, &v3);
      if ( v3 != 1 )
        break;
      add();
    }
    switch ( v3 )
    {
      case 3:
        delete();
        break;
      case 2:
        show();
        break;
      case 4:
        edit();
        break;
      case 5:
        puts("See you tomorrow~");
        exit(0);
      default:
        puts("Invalid choice!");
        break;
    }
  }
}

void *init()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  memset(&size, 0, 0x50u);
  return memset(&chunk, 0, 0x50u);
}

int add()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-14h] BYREF
  int v2; // [rsp+10h] [rbp-10h] BYREF
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Give me a book ID: ");
  __isoc99_scanf(&unk_10C8, &v2);
  printf("how long: ");
  __isoc99_scanf(&unk_10C8, &v1);
  result = v2;
  if ( v2 >= 0 )
  {
    result = v2;
    if ( v2 <= 49 )
    {
      if ( v1 < 0 )
      {
        return puts("too large!");
      }
      else
      {
        v3 = v2;
        chunk[v3] = malloc(v1);
        size[v3] = v1;
        return puts("Done!\n");
      }
    }
  }
  return result;
}

__int64 delete()
{
  unsigned int v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0;
  puts("Which one to throw?");
  __isoc99_scanf(&unk_10C8, &v1);
  if ( v1 <= 0x32 )
  {
    free((void *)chunk[v1]);
    chunk[v1] = 0;
    return (unsigned int)puts("Done!\n");
  }
  else
  {
    return (unsigned int)puts("Wrong!\n");
  }
}

unsigned __int64 show()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Which book do you want to show?");
  __isoc99_scanf(&unk_10C8, &v1);
  printf("Content: %s", (const char *)chunk[v1]);
  return __readfsqword(0x28u) ^ v2;
}

int edit()
{
  int v1; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2 = size[v1];
  printf("Which book to write?");
  __isoc99_scanf(&unk_10C8, &v1);
  if ( chunk[v1] )
  {
    printf("Content: ");
    read(0, (void *)chunk[v1], (unsigned int)(v2 + 1));
    return puts("Done!\n");
  }
  else
  {
    printf("wrong!");
    return 0;
  }
}

int menu()
{
  puts("\n***********************");
  puts("Welcome to the magic book world!");
  puts("***********************");
  puts("1.create a book");
  puts("2.show the content");
  puts("3.throw a book");
  puts("4.write something on the book");
  puts("5.exit the world");
  return printf("Your choice: ");
}