__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_4008BF();
  sub_400ACD(a1, a2);
  return 0;
}

int sub_4008BF()
{
  alarm(0x20u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  return puts(
           "   __  ___    ______   ___    \n"
           "  /  |/  /__ /_  __/__<  /_ __\n"
           " / /|_/ / _ `// / / __/ /\\ \\ /\n"
           "/_/  /_/\\_,_//_/ /_/ /_//_\\_\\ \n");
}

void __noreturn sub_400ACD()
{
  char s[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  *(_QWORD *)s = 0;
  v1 = 0;
  while ( 1 )
  {
    puts("choice>");
    fgets(s, 8, stdin);
    switch ( atoi(s) )
    {
      case 1:
        sub_400916();
        break;
      case 2:
        sub_4009D7(s, 8);
        break;
      case 3:
        sub_400A4D(s, 8);
        break;
      case 4:
        sub_400896();
        break;
      case 5:
        exit(0);
      default:
        puts("invalid");
        break;
    }
  }
}

unsigned __int64 sub_400916()
{
  int v0; // eax
  int v1; // ebx
  char s[24]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  if ( dword_6020BC <= 3 )
  {
    puts("size>");
    fgets(s, 8, stdin);
    v0 = atoi(s);
    if ( v0 && (unsigned __int64)v0 <= 0x78 )
    {
      v1 = dword_6020BC++;
      *(&buf + v1) = malloc(v0);
    }
    else
    {
      puts("No need");
    }
  }
  else
  {
    puts("No need");
  }
  return __readfsqword(0x28u) ^ v4;
}

unsigned __int64 sub_4009D7()
{
  __int64 v1; // [rsp+8h] [rbp-28h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index>");
  fgets(s, 8, stdin);
  v1 = atoi(s);
  free(*(&buf + v1));
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 sub_400A4D()
{
  __int64 v1; // [rsp+8h] [rbp-28h]
  char s[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index>");
  fgets(s, 8, stdin);
  v1 = atoi(s);
  read(0, *(&buf + v1), 8u);
  return __readfsqword(0x28u) ^ v3;
}

int sub_400896()
{
  if ( qword_602090 )
    return puts("Not yet");
  else
    return system("/bin/sh");
}