void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(0x3Cu);
  puts("Input your name:");
  sub_4009BD(&unk_6020E0, 64, 10);
  puts("Input your address:");
  sub_4009BD(&unk_602180, 96, 10);
  while ( 1 )
  {
    switch ( (unsigned int)sub_400AFB() )
    {
      case 1u:
        sub_400B96();
        break;
      case 2u:
        sub_400CE6();
        break;
      case 3u:
        sub_400D43();
        break;
      case 4u:
        sub_400C67();
        break;
      case 5u:
        puts("Bye~");
        exit(0);
      case 6u:
        exit(0);
      default:
        continue;
    }
  }
}

unsigned __int64 __fastcall sub_4009BD(__int64 a1, __int64 a2, char a3)
{
  char buf; // [rsp+2Fh] [rbp-11h] BYREF
  unsigned __int64 i; // [rsp+30h] [rbp-10h]
  ssize_t v7; // [rsp+38h] [rbp-8h]

  for ( i = 0; a2 - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1u);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(a1 + i) = 0;
  return i;
}

__int64 sub_400AFB()
{
  puts("1.New note\n2.Show  note\n3.Edit note\n4.Delete note\n5.Quit\noption--->>");
  return sub_400A4A();
}

int sub_400A4A()
{
  char nptr[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  sub_4009BD((__int64)nptr, 16, 10);
  return atoi(nptr);
}

int sub_400B96()
{
  int v1; // eax
  unsigned int size; // [rsp+4h] [rbp-Ch]
  void *size_4; // [rsp+8h] [rbp-8h]

  if ( (unsigned int)dword_602160 > 3 )
    return puts("note lists are full");
  puts("Input the length of the note content:(less than 128)");
  size = sub_400A4A();
  if ( size > 0x80 )
    return puts("Too long");
  size_4 = malloc(size);
  puts("Input the note content:");
  sub_4009BD((__int64)size_4, size, 10);
  sub_400B10(size_4);
  *(&ptr + (unsigned int)dword_602160) = size_4;
  qword_602140[dword_602160] = size;
  v1 = dword_602160++;
  return printf("note add success, the id is %d\n", v1);
}

const char *__fastcall sub_400B10(const char *a1)
{
  const char *result; // rax
  int i; // [rsp+18h] [rbp-18h]
  int v3; // [rsp+1Ch] [rbp-14h]

  v3 = 0;
  for ( i = 0; i <= strlen(a1); ++i )
  {
    if ( a1[i] != 37 )
      a1[v3++] = a1[i];
  }
  result = &a1[v3];
  *result = 0;
  return result;
}

int sub_400CE6()
{
  __int64 v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  puts("Input the id of the note:");
  LODWORD(v0) = sub_400A4A();
  v2 = v0;
  if ( (unsigned int)v0 < 4 )
  {
    v0 = (__int64)*(&ptr + (int)v0);
    if ( v0 )
      LODWORD(v0) = printf("Content is %s\n", (const char *)*(&ptr + v2));
  }
  return v0;
}

unsigned __int64 sub_400D43()
{
  char *v0; // rbx
  unsigned int v2; // [rsp+8h] [rbp-E8h]
  int v3; // [rsp+Ch] [rbp-E4h]
  char *src; // [rsp+10h] [rbp-E0h]
  __int64 v5; // [rsp+18h] [rbp-D8h]
  char dest[128]; // [rsp+20h] [rbp-D0h] BYREF
  char *v7; // [rsp+A0h] [rbp-50h]
  unsigned __int64 v8; // [rsp+D8h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  if ( dword_602160 )
  {
    puts("Input the id of the note:");
    v2 = sub_400A4A();
    if ( v2 < 4 )
    {
      src = (char *)*(&ptr + (int)v2);
      v5 = qword_602140[v2];
      if ( src )
      {
        puts("do you want to overwrite or append?[1.overwrite/2.append]");
        v3 = sub_400A4A();
        if ( v3 == 1 || v3 == 2 )
        {
          if ( v3 == 1 )
            dest[0] = 0;
          else
            strcpy(dest, src);
          v7 = (char *)malloc(0xA0u);
          strcpy(v7, "TheNewContents:");
          printf(v7);
          sub_4009BD((__int64)(v7 + 15), 144, 10);
          sub_400B10(v7 + 15);
          v0 = v7;
          v0[v5 - strlen(dest) + 14] = 0;
          strncat(dest, v7 + 15, 0xFFFFFFFFFFFFFFFFLL);
          strcpy(src, dest);
          free(v7);
          puts("Edit note success!");
        }
        else
        {
          puts("Error choice!");
        }
      }
      else
      {
        puts("note has been deleted");
      }
    }
  }
  else
  {
    puts("Please add a note!");
  }
  return __readfsqword(0x28u) ^ v8;
}

int sub_400C67()
{
  __int64 v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  puts("Input the id of the note:");
  LODWORD(v0) = sub_400A4A();
  v2 = v0;
  if ( (unsigned int)v0 < 4 )
  {
    v0 = (__int64)*(&ptr + (int)v0);
    if ( v0 )
    {
      free(*(&ptr + v2));
      *(&ptr + v2) = 0;
      qword_602140[v2] = 0;
      LODWORD(v0) = puts("delete note success!");
    }
  }
  return v0;
}

