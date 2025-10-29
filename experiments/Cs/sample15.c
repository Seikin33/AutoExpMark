ssize_t sub_A00()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Welcome to notebook system");
  puts("Please input your name");
  return read(0, &unk_202060, 0x30u);
}

int sub_A9B()
{
  puts("1.Add note");
  puts("2.Delete note");
  puts("3.Show note");
  puts("4.update your name");
  puts("5.Edit note");
  return puts("6.exit");
}

unsigned __int64 sub_AEA()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Input the size");
  _isoc99_scanf("%d", &v1);
  if ( v1 <= 0 || v1 > 1023 )
  {
    puts("Size error!");
  }
  else
  {
    qword_202090 = malloc(v1);
    memset(qword_202090, 0, v1);
    unk_202040 = v1;
    puts("Add success");
  }
  return __readfsqword(0x28u) ^ v2;
}

int sub_BB1()
{
  if ( qword_202090 )
  {
    free(qword_202090);
    qword_202090 = 0;
  }
  return puts("Delete success");
}

int sub_BF3()
{
  int result; // eax

  result = (int)qword_202090;
  if ( qword_202090 )
    return puts((const char *)qword_202090);
  return result;
}

void *sub_C1B()
{
  void *result; // rax

  puts("Input the note");
  result = qword_202090;
  if ( qword_202090 )
    return (void *)read(0, qword_202090, unk_202040);
  return result;
}

ssize_t sub_C60()
{
  puts("Please input your name");
  return read(0, &unk_202060, 0x31u);
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_A00();
  while ( 1 )
  {
    sub_A9B();
    _isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 1:
        sub_AEA();
        break;
      case 2:
        sub_BB1();
        break;
      case 3:
        sub_BF3();
        break;
      case 4:
        sub_C60();
        break;
      case 5:
        sub_C1B();
        break;
      case 6:
        return 0;
      default:
        puts("Wrong choice");
        break;
    }
  }
}