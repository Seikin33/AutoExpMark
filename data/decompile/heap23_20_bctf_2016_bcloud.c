void __noreturn main()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  sub_804899C();
  while ( 1 )
  {
    switch ( sub_8048760() )
    {
      case 1:
        sub_80489AE();
        break;
      case 2:
        sub_8048AA2();
        break;
      case 3:
        sub_8048AB7();
        break;
      case 4:
        sub_8048B63();
        break;
      case 5:
        sub_8048C08();
        break;
      case 6:
        sub_8048C4E();
      default:
        sub_8048C6C();
        break;
    }
  }
}

int sub_804899C()
{
  sub_80487A1();
  return sub_804884E();
}

unsigned int sub_80487A1()
{
  char s[64]; // [esp+1Ch] [ebp-5Ch] BYREF
  char *v2; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(s, 0, 0x50u);
  puts("Input your name:");
  sub_804868D(s, 64, 10);
  v2 = (char *)malloc(0x40u);
  dword_804B0CC = (int)v2;
  strcpy(v2, s);
  sub_8048779(v2);
  return __readgsdword(0x14u) ^ v3;
}

int __cdecl sub_804868D(int a1, int a2, char a3)
{
  char buf; // [esp+1Bh] [ebp-Dh] BYREF
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i < a2; ++i )
  {
    if ( read(0, &buf, 1u) <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  *(_BYTE *)(i + a1) = 0;
  return i;
}

int __cdecl sub_804868D(int a1, int a2, char a3)
{
  char buf; // [esp+1Bh] [ebp-Dh] BYREF
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i < a2; ++i )
  {
    if ( read(0, &buf, 1u) <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  *(_BYTE *)(i + a1) = 0;
  return i;
}

int __cdecl sub_8048779(const char *a1)
{
  printf("Hey %s! Welcome to BCTF CLOUD NOTE MANAGE SYSTEM!\n", a1);
  return puts("Now let's set synchronization options.");
}

unsigned int sub_804884E()
{
  char s[64]; // [esp+1Ch] [ebp-9Ch] BYREF
  char *v2; // [esp+5Ch] [ebp-5Ch]
  char v3[68]; // [esp+60h] [ebp-58h] BYREF
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(s, 0, 0x90u);
  puts("Org:");
  sub_804868D((int)s, 64, 10);
  puts("Host:");
  sub_804868D((int)v3, 64, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  dword_804B0C8 = (int)v2;
  dword_804B148 = (int)v4;
  strcpy(v4, v3);
  strcpy(v2, s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}

int sub_8048760()
{
  puts("1.New note\n2.Show note\n3.Edit note\n4.Delete note\n5.Syn\n6.Quit\noption--->>");
  return sub_8048709();
}

int sub_8048709()
{
  char nptr[20]; // [esp+18h] [ebp-20h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  sub_804868D((int)nptr, 16, 10);
  return atoi(nptr);
}

int sub_80489AE()
{
  int result; // eax
  int i; // [esp+18h] [ebp-10h]
  int v2; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i <= 9 && dword_804B120[i]; ++i )
    ;
  if ( i == 10 )
    return puts("Lack of space. Upgrade your account with just $100 :)");
  puts("Input the length of the note content:");
  v2 = sub_8048709();
  dword_804B120[i] = (int)malloc(v2 + 4);
  if ( !dword_804B120[i] )
    exit(-1);
  dword_804B0A0[i] = v2;
  puts("Input the content:");
  sub_804868D(dword_804B120[i], v2, 10);
  printf("Create success, the id is %d\n", i);
  result = i;
  dword_804B0E0[i] = 0;
  return result;
}

int sub_8048AA2()
{
  return puts("WTF? Something strange happened.");
}

int sub_8048AB7()
{
  unsigned int v1; // [esp+14h] [ebp-14h]
  int v2; // [esp+18h] [ebp-10h]
  int v3; // [esp+1Ch] [ebp-Ch]

  puts("Input the id:");
  v1 = sub_8048709();
  if ( v1 >= 0xA )
    return puts("Invalid ID.");
  v2 = dword_804B120[v1];
  if ( !v2 )
    return puts("Note has been deleted.");
  v3 = dword_804B0A0[v1];
  dword_804B0E0[v1] = 0;
  puts("Input the new content:");
  sub_804868D(v2, v3, 10);
  return puts("Edit success.");
}

int sub_8048B63()
{
  unsigned int v1; // [esp+18h] [ebp-10h]
  void *ptr; // [esp+1Ch] [ebp-Ch]

  puts("Input the id:");
  v1 = sub_8048709();
  if ( v1 >= 0xA )
    return puts("Invalid ID.");
  ptr = (void *)dword_804B120[v1];
  if ( !ptr )
    return puts("Note has been deleted.");
  dword_804B120[v1] = 0;
  dword_804B0A0[v1] = 0;
  free(ptr);
  return puts("Delete success.");
}

int sub_8048C08()
{
  int i; // [esp+1Ch] [ebp-Ch]

  puts("Syncing...");
  for ( i = 0; i <= 9; ++i )
    sub_8048BF5(i);
  return puts("Synchronization success.");
}

int __cdecl sub_8048BF5(int a1)
{
  int result; // eax

  result = a1;
  dword_804B0E0[a1] = 1;
  return result;
}

void __noreturn sub_8048C4E()
{
  puts("Bye!\n");
  exit(0);
}

int sub_8048C6C()
{
  return puts("Invalid option.");
}