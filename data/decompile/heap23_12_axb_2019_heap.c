unsigned __int64 banner()
{
  char format[12]; // [rsp+Ch] [rbp-14h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Welcome to note management system!");
  printf("Enter your name: ");
  __isoc99_scanf("%s", format);
  printf("Hello, ");
  printf(format);
  puts("\n-------------------------------------");
  return __readfsqword(0x28u) ^ v2;
}

int menu()
{
  puts("1. add note");
  puts("2. dele note");
  puts("3. show note's content");
  puts("4. edit note");
  puts("Enter a option: ");
  return printf(">> ");
}

int get_int()
{
  char buf[10]; // [rsp+Eh] [rbp-12h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  read(0, buf, 0xAu);
  return atoi(buf);
}

size_t __fastcall get_input(__int64 a1, int a2)
{
  size_t result; // rax
  signed int v3; // [rsp+10h] [rbp-10h]
  _BYTE *v4; // [rsp+18h] [rbp-8h]

  v3 = 0;
  while ( 1 )
  {
    v4 = (_BYTE *)(v3 + a1);
    result = fread(v4, 1u, 1u, stdin);
    if ( (int)result <= 0 )
      break;
    if ( *v4 == 10 )
    {
      if ( v3 )
      {
        result = v3 + a1;
        *v4 = 0;
        return result;
      }
    }
    else
    {
      result = (unsigned int)++v3;
      if ( a2 + 1 <= (unsigned int)v3 )
        return result;
    }
  }
  return result;
}

_BOOL8 __fastcall check_pass(_QWORD *a1)
{
  return *a1 - (_QWORD)a1 > 4096LL;
}

unsigned __int64 add_note()
{
  unsigned int v0; // ebx
  unsigned int v1; // ebx
  unsigned int size; // [rsp+0h] [rbp-20h] BYREF
  unsigned int size_4; // [rsp+4h] [rbp-1Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  printf("Enter the index you want to create (0-10):");
  __isoc99_scanf("%d", &size_4);
  if ( size_4 <= 0xA )
  {
    if ( counts > 0xAu )
    {
      puts("full!");
      exit(0);
    }
    puts("Enter a size:");
    __isoc99_scanf("%d", &size);
    if ( key == 43 )
    {
      puts("Enter the content: ");
      v0 = size_4;
      *((_QWORD *)&note + 2 * (int)v0) = malloc(size);
      *((_DWORD *)&note + 4 * (int)size_4 + 2) = size;
      if ( !*((_QWORD *)&note + 2 * (int)size_4) )
      {
        fwrite("error", 1u, 5u, stderr);
        exit(0);
      }
    }
    else
    {
      if ( size <= 0x80 )
      {
        puts("You can't hack me!");
        return __readfsqword(0x28u) ^ v5;
      }
      puts("Enter the content: ");
      v1 = size_4;
      *((_QWORD *)&note + 2 * (int)v1) = malloc(size);
      *((_DWORD *)&note + 4 * (int)size_4 + 2) = size;
      if ( !*((_QWORD *)&note + 2 * (int)size_4) )
      {
        fwrite("error", 1u, 5u, stderr);
        exit(0);
      }
    }
    if ( !check_pass((_QWORD *)&note + 2 * (int)size_4) )
    {
      puts("go out!hacker!");
      exit(0);
    }
    get_input(*((_QWORD *)&note + 2 * (int)size_4), size);
    ++counts;
    puts("Done!");
  }
  else
  {
    puts("You can't hack me!");
  }
  return __readfsqword(0x28u) ^ v5;
}

unsigned __int64 delete_note()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter an index:");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA && *((_QWORD *)&note + 2 * (int)v1) )
  {
    free(*((void **)&note + 2 * (int)v1));
    *((_QWORD *)&note + 2 * (int)v1) = 0;
    *((_DWORD *)&note + 4 * (int)v1 + 2) = 0;
    --counts;
    puts("Done!");
  }
  else
  {
    puts("You can't hack me!");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 edit_note()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter an index:");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0xA && *((_QWORD *)&note + 2 * (int)v1) )
  {
    puts("Enter the content: ");
    get_input(*((_QWORD *)&note + 2 * (int)v1), *((_DWORD *)&note + 4 * (int)v1 + 2));
    puts("Done!");
  }
  else
  {
    puts("You can't hack me!");
  }
  return __readfsqword(0x28u) ^ v2;
}

int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  init();
  banner();
  while ( 1 )
  {
    menu();
    v3 = get_int();
    switch ( v3 )
    {
      case 1:
        add_note();
        break;
      case 2:
        delete_note();
        break;
      case 3:
        puts("None!");
        break;
      case 4:
        edit_note();
        break;
      default:
        puts("No such choices!");
        break;
    }
  }
}