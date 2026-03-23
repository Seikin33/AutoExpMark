void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  sub_4008CA();
  sub_400934();
  fly_init();
  while ( 1 )
  {
    put_menu();
    switch ( read_int() )
    {
      case 1:
        add_ticket();
        break;
      case 2:
        delete_ticket();
        break;
      case 3:
        edit_ticket();
        break;
      case 4:
        show_ticket();
        break;
      case 5:
        edit_info();
        break;
      case 6:
        show_info();
        break;
      case 7:
        exit(0);
      default:
        continue;
    }
  }
}

unsigned __int64 fly_init()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  bss_name = (char *)malloc(0x20u);
  saying = (char *)malloc(0x20u);
  memset(bss_name, 0, 0x20u);
  memset(saying, 0, 0x20u);
  puts("Your name: ");
  read(0, bss_name, 0x20u);
  puts("what do you want to say before take off(wu hu qi fei): ");
  read(0, saying, 0x20u);
  puts("Your age: ");
  age_int = read_int();
  return __readfsqword(0x28u) ^ v1;
}

int read_int()
{
  memset(nptr, 0, 0xAu);
  read(0, nptr, 0xAu);
  return atoi(nptr);
}

unsigned __int64 add_ticket()
{
  unsigned int v1; // [rsp+0h] [rbp-20h]
  int v2; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  puts("Index: ");
  v1 = read_int();
  if ( v1 > 5 )
  {
    puts("The cooperation was not very good!!!");
  }
  else if ( nbytes[v1 + 10] )
  {
    puts("Ticket exist!!!");
  }
  else
  {
    puts("Remarks size: ");
    v2 = read_int();
    if ( (unsigned int)v2 > 0x200 )
    {
      puts("Don't speak too much");
    }
    else
    {
      nbytes[v1 + 4] = (__int64)malloc(v2);
      nbytes[v1 + 10] = v2;
      puts("It's ok!!!");
    }
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 delete_ticket()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Index: ");
  v1 = read_int();
  if ( v1 > 3 )
  {
    puts("The cooperation was not very good!!!");
  }
  else if ( nbytes[v1 + 10] )
  {
    free((void *)nbytes[v1 + 4]);
    nbytes[v1 + 10] = 0;
    puts("It's ok!!!");
  }
  else
  {
    puts("It's empty!!!");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 edit_ticket()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Index: ");
  v1 = read_int();
  if ( v1 >= 4 )
  {
    puts("The cooperation was not very good!!!");
  }
  else if ( nbytes[v1 + 10] )
  {
    puts("Your remarks: ");
    read(0, (void *)nbytes[v1 + 4], nbytes[v1 + 10]);
    puts("It's ok!!!");
  }
  else
  {
    puts("It's empty!!!");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 show_ticket()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Index: ");
  v1 = read_int();
  if ( v1 > 5 )
  {
    puts("The cooperation was not very good!!!");
  }
  else if ( nbytes[v1 + 10] )
  {
    printf("Ticket %d: ", v1);
    puts((const char *)nbytes[v1 + 4]);
  }
  else
  {
    puts("It's empty!!!");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 edit_info()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  if ( nbytes )
  {
    puts("Just one chance!!!");
  }
  else
  {
    fly_init();
    nbytes = 1;
  }
  return __readfsqword(0x28u) ^ v1;
}

unsigned __int64 show_info()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  printf("Name: ");
  puts(bss_name);
  printf("Saying: ");
  puts(saying);
  printf("Age: ");
  printf("%lld\n", age_int);
  return __readfsqword(0x28u) ^ v1;
}