int menu()
{
  puts("=== Menu ===");
  printf("%d: Apple Store\n", 1);
  printf("%d: Add into your shopping cart\n", 2);
  printf("%d: Remove from your shopping cart\n", 3);
  printf("%d: List your shopping cart\n", 4);
  printf("%d: Checkout\n", 5);
  return printf("%d: Exit\n", 6);
}

int list()
{
  puts("=== Device List ===");
  printf("%d: iPhone 6 - $%d\n", 1, 199);
  printf("%d: iPhone 6 Plus - $%d\n", 2, 299);
  printf("%d: iPad Air 2 - $%d\n", 3, 499);
  printf("%d: iPad Mini 3 - $%d\n", 4, 399);
  return printf("%d: iPod Touch - $%d\n", 5, 199);
}

int __cdecl my_read(void *buf, size_t nbytes)
{
  int result; // eax
  ssize_t v3; // [esp+1Ch] [ebp-Ch]

  v3 = read(0, buf, nbytes);
  if ( v3 == -1 )
    return puts("Input Error.");
  result = (int)buf + v3;
  *((_BYTE *)buf + v3) = 0;
  return result;
}

char **__cdecl create(const char *a1, char *a2)
{
  char **v3; // [esp+1Ch] [ebp-Ch]

  v3 = (char **)malloc(0x10u);
  v3[1] = a2;
  asprintf(v3, "%s", a1);
  v3[2] = 0;
  v3[3] = 0;
  return v3;
}

int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}

int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}

unsigned int add()
{
  char **v1; // [esp+1Ch] [ebp-2Ch]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Device Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u);
  switch ( atoi(nptr) )
  {
    case 1:
      v1 = create("iPhone 6", (char *)0xC7);
      insert((int)v1);
      goto LABEL_8;
    case 2:
      v1 = create("iPhone 6 Plus", (char *)0x12B);
      insert((int)v1);
      goto LABEL_8;
    case 3:
      v1 = create("iPad Air 2", (char *)0x1F3);
      insert((int)v1);
      goto LABEL_8;
    case 4:
      v1 = create("iPad Mini 3", (char *)0x18F);
      insert((int)v1);
      goto LABEL_8;
    case 5:
      v1 = create("iPod Touch", (char *)0xC7);
      insert((int)v1);
LABEL_8:
      printf("You've put *%s* in your shopping cart.\n", *v1);
      puts("Brilliant! That's an amazing idea.");
      break;
    default:
      puts("Stop doing that. Idiot!");
      break;
  }
  return __readgsdword(0x14u) ^ v3;
}

unsigned int delete()
{
  int v1; // [esp+10h] [ebp-38h]
  int v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u);
  v3 = atoi(nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = *(_DWORD *)(v2 + 8);
      v5 = *(_DWORD *)(v2 + 12);
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *(const char **)v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = *(_DWORD *)(v2 + 8);
  }
  return __readgsdword(0x14u) ^ v7;
}

int cart()
{
  int v0; // eax
  int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  int i; // [esp+20h] [ebp-28h]
  _BYTE buf[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(buf, 0x15u);
  if ( buf[0] == 121 )
  {
    puts("==== Cart ====");
    for ( i = dword_804B070; i; i = *(_DWORD *)(i + 8) )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *(const char **)i, *(_DWORD *)(i + 4));
      v3 += *(_DWORD *)(i + 4);
    }
  }
  return v3;
}

unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2[5]; // [esp+18h] [ebp-20h] BYREF
  unsigned int v3; // [esp+2Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(v2, "%s", "iPhone 8");
    v2[1] = (char *)1;
    insert((int)v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v3;
}

unsigned int handler()
{
  char nptr[22]; // [esp+16h] [ebp-22h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(nptr, 0x15u);
    switch ( atoi(nptr) )
    {
      case 1:
        list();
        break;
      case 2:
        add();
        break;
      case 3:
        delete();
        break;
      case 4:
        cart();
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ v2;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}

void __noreturn timeout()
{
  puts("Times Up!");
  exit(0);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  signal(14, timeout);
  alarm(0x3Cu);
  memset(&myCart, 0, 0x10u);
  menu();
  return handler();
}