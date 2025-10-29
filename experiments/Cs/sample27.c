__int64 __fastcall readline(_BYTE *a1, int a2)
{
  int i; // [rsp+14h] [rbp-Ch]

  if ( a2 <= 0 )
    return 0;
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)read(0, a1, 1u) != 1 )
      return 1;
    if ( *a1 == 10 )
      break;
    ++a1;
    if ( i == a2 )
      break;
  }
  *a1 = 0;
  return 0;
}

int print_welcome()
{
  return puts("Welcome to ASISCTF book library");
}

__int64 print_menu()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  v1 = -1;
  puts("\n1. Create a book");
  puts("2. Delete a book");
  puts("3. Edit a book");
  puts("4. Print book detail");
  puts("5. Change current author name");
  puts("6. Exit");
  printf("> ");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 6 && v1 > 0 )
    return (unsigned int)v1;
  else
    return 0xFFFFFFFFLL;
}

__int64 find_empty_book_slot()
{
  int i; // [rsp+0h] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    if ( !*((_QWORD *)book_pointers + i) )
      return (unsigned int)i;
  }
  return 0xFFFFFFFFLL;
}

__int64 set_author_name()
{
  printf("Enter author name: ");
  if ( !(unsigned int)readline(author_name, 32) )
    return 0;
  printf("fail to read author_name");
  return 1;
}

__int64 delete_book()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  i = 0;
  printf("Enter the book id you want to delete: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*((_QWORD *)book_pointers + i) || **((_DWORD **)book_pointers + i) != v1); ++i )
      ;
    if ( i != 20 )
    {
      free(*(void **)(*((_QWORD *)book_pointers + i) + 8LL));
      free(*(void **)(*((_QWORD *)book_pointers + i) + 16LL));
      free(*((void **)book_pointers + i));
      *((_QWORD *)book_pointers + i) = 0;
      return 0;
    }
    printf("Can't find selected book!");
  }
  else
  {
    printf("Wrong id");
  }
  return 1;
}

int print_book_details()
{
  __int64 v0; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    v0 = *((_QWORD *)book_pointers + i);
    if ( v0 )
    {
      printf("ID: %d\n", **((_DWORD **)book_pointers + i));
      printf("Name: %s\n", *(const char **)(*((_QWORD *)book_pointers + i) + 8LL));
      printf("Description: %s\n", *(const char **)(*((_QWORD *)book_pointers + i) + 16LL));
      LODWORD(v0) = printf("Author: %s\n", (const char *)author_name);
    }
  }
  return v0;
}

__int64 edit_book()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  printf("Enter the book id you want to edit: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*((_QWORD *)book_pointers + i) || **((_DWORD **)book_pointers + i) != v1); ++i )
      ;
    if ( i == 20 )
    {
      printf("Can't find selected book!");
    }
    else
    {
      printf("Enter new book description: ");
      if ( !(unsigned int)readline(
                            *(_BYTE **)(*((_QWORD *)book_pointers + i) + 16LL),
                            *(_DWORD *)(*((_QWORD *)book_pointers + i) + 24LL) - 1) )
        return 0;
      printf("Unable to read new description");
    }
  }
  else
  {
    printf("Wrong id");
  }
  return 1;
}

__int64 create_book()
{
  int v1; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+4h] [rbp-1Ch]
  void *v3; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]
  void *v5; // [rsp+18h] [rbp-8h]

  v1 = 0;
  printf("\nEnter book name size: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
    goto LABEL_2;
  printf("Enter book name (Max 32 chars): ");
  ptr = malloc(v1);
  if ( !ptr )
  {
    printf("unable to allocate enough space");
    goto LABEL_17;
  }
  if ( (unsigned int)readline(ptr, v1 - 1) )
  {
    printf("fail to read name");
    goto LABEL_17;
  }
  v1 = 0;
  printf("\nEnter book description size: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
  {
LABEL_2:
    printf("Malformed size");
  }
  else
  {
    v5 = malloc(v1);
    if ( v5 )
    {
      printf("Enter book description: ");
      if ( (unsigned int)readline(v5, v1 - 1) )
      {
        printf("Unable to read description");
      }
      else
      {
        v2 = find_empty_book_slot();
        if ( v2 == -1 )
        {
          printf("Library is full");
        }
        else
        {
          v3 = malloc(0x20u);
          if ( v3 )
          {
            *((_DWORD *)v3 + 6) = v1;
            *((_QWORD *)book_pointers + v2) = v3;
            *((_QWORD *)v3 + 2) = v5;
            *((_QWORD *)v3 + 1) = ptr;
            *(_DWORD *)v3 = ++book_id_counter;
            return 0;
          }
          printf("Unable to allocate book struct");
        }
      }
    }
    else
    {
      printf("Fail to allocate memory");
    }
  }
LABEL_17:
  if ( ptr )
    free(ptr);
  if ( v5 )
    free(v5);
  if ( v3 )
    free(v3);
  return 1;
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  print_welcome();
  set_author_name();
  while ( 1 )
  {
    v3 = print_menu();
    if ( v3 == 6 )
      break;
    switch ( v3 )
    {
      case 1:
        create_book();
        break;
      case 2:
        delete_book();
        break;
      case 3:
        edit_book();
        break;
      case 4:
        print_book_details();
        break;
      case 5:
        set_author_name();
        break;
      default:
        puts("Wrong option");
        break;
    }
  }
  puts("Thanks to use our library software");
  return 0;
}