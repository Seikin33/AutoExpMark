int __fastcall main(int argc, const char **argv, const char **envp)
{
  void (**v4)(void); // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  v4 = (void (**)(void))malloc(0x10u);
  *v4 = (void (*)(void))hello_message;
  v4[1] = (void (*)(void))goodbye_message;
  (*v4)();
  while ( 1 )
  {
    menu();
    read(0, buf, 8u);
    switch ( atoi(buf) )
    {
      case 1:
        show_item();
        break;
      case 2:
        add_item();
        break;
      case 3:
        change_item();
        break;
      case 4:
        remove_item();
        break;
      case 5:
        v4[1]();
        exit(0);
      default:
        puts("invaild choice!!!");
        break;
    }
  }
}

int menu()
{
  puts("----------------------------");
  puts("Bamboobox Menu");
  puts("----------------------------");
  puts("1.show the items in the box");
  puts("2.add a new item");
  puts("3.change the item in the box");
  puts("4.remove the item in the box");
  puts("5.exit");
  puts("----------------------------");
  return printf("Your choice:");
}

int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}

__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8u);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0;
      }
    }
  }
  return 0;
}

unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8u);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8u);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}

unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8u);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}