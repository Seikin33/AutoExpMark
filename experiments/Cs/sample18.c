unsigned int __cdecl sub_80485EC(const char *a1)
{
  size_t v1; // edx
  const char *v3; // [esp+28h] [ebp-10h]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = strlen(a1) - 1;
  v3 = &a1[v1];
  if ( &a1[v1] >= a1 && *v3 == 10 )
    *v3 = 0;
  return __readgsdword(0x14u) ^ v4;
}

unsigned int sub_8048644()
{
  char *v1; // [esp+18h] [ebp-10h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  v1 = dword_804A288;
  dword_804A288 = (char *)malloc(0x38u);
  if ( dword_804A288 )
  {
    *((_DWORD *)dword_804A288 + 13) = v1;
    printf("Rifle name: ");
    fgets(dword_804A288 + 25, 56, stdin);
    sub_80485EC(dword_804A288 + 25);
    printf("Rifle description: ");
    fgets(dword_804A288, 56, stdin);
    sub_80485EC(dword_804A288);
    ++dword_804A2A4;
  }
  else
  {
    puts("Something terrible happened!");
  }
  return __readgsdword(0x14u) ^ v2;
}

unsigned int sub_8048729()
{
  char *i; // [esp+14h] [ebp-14h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = dword_804A288; i; i = (char *)*((_DWORD *)i + 13) )
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
  return __readgsdword(0x14u) ^ v2;
}

unsigned int sub_80487B4()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(dword_804A2A8, 128, stdin);
  sub_80485EC(dword_804A2A8);
  return __readgsdword(0x14u) ^ v1;
}

unsigned int sub_8048810()
{
  char *v1; // [esp+14h] [ebp-14h]
  char *ptr; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = dword_804A288;
  if ( dword_804A2A4 )
  {
    while ( v1 )
    {
      ptr = v1;
      v1 = (char *)*((_DWORD *)v1 + 13);
      free(ptr);
    }
    dword_804A288 = 0;
    ++dword_804A2A0;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
  return __readgsdword(0x14u) ^ v3;
}

int sub_8048896()
{
  int v1; // [esp+18h] [ebp-30h] BYREF
  char s[32]; // [esp+1Ch] [ebp-2Ch] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  do
  {
    printf("Action: ");
    fgets(s, 32, stdin);
  }
  while ( !__isoc99_sscanf(s, "%u", &v1) );
  return v1;
}

unsigned int sub_8048906()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  puts("======= Status =======");
  printf("New:    %u times\n", dword_804A2A4);
  printf("Orders: %u times\n", dword_804A2A0);
  if ( *dword_804A2A8 )
    printf("Order Message: %s\n", dword_804A2A8);
  puts("======================");
  return __readgsdword(0x14u) ^ v1;
}

unsigned int sub_804898D()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  puts("What would you like to do?\n");
  printf("%u. Add new rifle\n", 1);
  printf("%u. Show added rifles\n", 2);
  printf("%u. Order selected rifles\n", 3);
  printf("%u. Leave a Message with your Order\n", 4);
  printf("%u. Show current stats\n", 5);
  printf("%u. Exit!\n", 6);
  while ( 1 )
  {
    switch ( sub_8048896() )
    {
      case 1:
        sub_8048644();
        break;
      case 2:
        sub_8048729();
        break;
      case 3:
        sub_8048810();
        break;
      case 4:
        sub_80487B4();
        break;
      case 5:
        sub_8048906();
        break;
      case 6:
        return __readgsdword(0x14u) ^ v1;
      default:
        continue;
    }
  }
}

int main()
{
  dword_804A2A4 = 0;
  dword_804A2A0 = 0;
  dword_804A2A8 = (char *)&unk_804A2C0;
  puts("Welcome to the OREO Original Rifle Ecommerce Online System!");
  puts(
    "\n"
    "     ,______________________________________\n"
    "    |_________________,----------._ [____]  -,__  __....-----=====\n"
    "                   (_(||||||||||||)___________/                   |\n"
    "                      `----------'   OREO [ ))\"-,                   |\n"
    "                                           \"\"    `,  _,--....___    |\n"
    "                                                   `/           \"\"\"\"\n"
    "\t");
  sub_804898D();
  return 0;
}