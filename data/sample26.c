int init()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  puts("My Dream is to be a writer,how about you?");
  return puts("Do you want to write your book?");
}

int init_name_message()
{
  puts("Now,please input your name,Mr. writer:");
  read(0, &name, 0x20u);
  puts("And write some message for your book?");
  message = malloc(0xB0u);
  read(0, message, 0xB0u);
  return puts("Ready!Let's begin!");
}

int read_int()
{
  char s[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(s, 0, 0x10u);
  read(0, s, 8u);
  return atoi(s);
}

int menu()
{
  puts("What do you want to do?");
  puts("1.Add a page");
  puts("2.Edit a page");
  puts("3.Delete a page");
  puts("4.Change name");
  puts("5.Change message");
  puts("6.Finish");
  return puts("Your choice >> ");
}

int add()
{
  int v1; // [rsp+4h] [rbp-Ch]
  int i; // [rsp+8h] [rbp-8h]
  int v3; // [rsp+Ch] [rbp-4h]

  v1 = -1;
  for ( i = 0; i <= 6; ++i )
  {
    if ( !*(&page_list + i) )
    {
      v1 = i;
      break;
    }
  }
  if ( v1 == -1 )
    return puts("Full!");
  printf("Page %d's size:\n", v1);
  v3 = read_int();
  if ( v3 <= 127 || v3 > 239 )
  {
    puts("Error size!");
    exit(0);
  }
  *(&page_list + v1) = malloc(v3);
  size_list[v1] = v3;
  return puts("Add success!Now you can edit it!");
}

int edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Which page do you want to edit?");
  v1 = read_int();
  if ( (unsigned int)v1 >= 8 || !*(&page_list + v1) || !size_list[v1] )
  {
    puts("Error index!");
    exit(0);
  }
  puts("Input your content:");
  read(0, *(&page_list + v1), size_list[v1]);
  return puts("Edit success!");
}

int delete()
{
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Which page do you want to delete?");
  v1 = read_int();
  if ( (unsigned int)v1 >= 8 || !*(&page_list + v1) )
  {
    puts("Error index!");
    exit(0);
  }
  free(*(&page_list + v1));
  *(&page_list + v1) = 0;
  size_list[v1] = 0;
  return puts("Delete success!");
}

int change_name()
{
  puts("Your new name:");
  read(0, &name, 0x20u);
  return puts("Done!");
}

void *change_message()
{
  void *result; // rax
  int v1; // [rsp+4h] [rbp-Ch]
  void *buf; // [rsp+8h] [rbp-8h]

  puts("So I think the old message is useless,right?");
  printf("Your message is saved at %p\n", message);
  free(message);
  puts("Your size of new message:");
  v1 = read_int();
  if ( v1 <= 127 || v1 > 239 )
  {
    puts("Error size!");
    exit(0);
  }
  buf = malloc(v1);
  puts("Input your new message:");
  read(0, buf, v1);
  puts("Done!");
  puts("Oh,I'm sorry,maybe you should say goodbye to the old message:");
  read(0, message, 0x10u);
  puts("New!");
  result = buf;
  message = buf;
  return result;
}

int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+8h] [rbp-8h]
  int v4; // [rsp+Ch] [rbp-4h]

  init();
  init_name_message();
  v3 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v4 = read_int();
      if ( v4 != 1 )
        break;
      add();
    }
    switch ( v4 )
    {
      case 2:
        edit();
        break;
      case 3:
        delete();
        break;
      case 4:
        change_name();
        break;
      case 5:
        if ( v3 )
        {
          puts("I think one chance is enough");
        }
        else
        {
          change_message();
          v3 = 1;
        }
        break;
      case 6:
        puts("Good job!");
        exit(0);
      default:
        puts("Invalid choice!");
        break;
    }
  }
}