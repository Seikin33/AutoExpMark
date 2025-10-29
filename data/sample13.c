int sub_ADD()
{
  puts("======================");
  puts("1.Add a girl's info");
  puts("2.Show info");
  puts("3.Edit info");
  puts("4.Call that girl!");
  puts("5.Exit lonely.");
  puts("======================");
  return printf("Input your choice:");
}

unsigned __int64 sub_B49()
{
  int v0; // ebx
  void **v1; // rbx
  _DWORD nbytes[7]; // [rsp+4h] [rbp-1Ch] BYREF

  *(_QWORD *)&nbytes[1] = __readfsqword(0x28u);
  if ( dword_20204C > 100 )
    puts("Enough!");
  v0 = dword_20204C;
  *((_QWORD *)&unk_202060 + v0) = malloc(0x18u);
  puts("Please input the size of girl's name");
  __isoc99_scanf("%d", nbytes);
  *(_DWORD *)(*((_QWORD *)&unk_202060 + dword_20204C) + 8LL) = nbytes[0];
  v1 = (void **)*((_QWORD *)&unk_202060 + dword_20204C);
  *v1 = malloc(nbytes[0]);
  puts("please inpute her name:");
  read(0, **((void ***)&unk_202060 + dword_20204C), nbytes[0]);
  puts("please input her call:");
  read(0, (void *)(*((_QWORD *)&unk_202060 + dword_20204C) + 12LL), 0xCu);
  *(_BYTE *)(*((_QWORD *)&unk_202060 + dword_20204C) + 23LL) = 0;
  puts("Done!");
  ++dword_20204C;
  return __readfsqword(0x28u) ^ *(_QWORD *)&nbytes[1];
}

int sub_CE9()
{
  return puts("Programmer is tired, delete it and add a new info.");
}

unsigned __int64 sub_CFC()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Please input the index:");
  __isoc99_scanf("%d", &v1);
  if ( *((_QWORD *)&unk_202060 + v1) )
  {
    puts("name:");
    puts(**((const char ***)&unk_202060 + v1));
    puts("phone:");
    puts((const char *)(*((_QWORD *)&unk_202060 + v1) + 12LL));
  }
  puts("Done!");
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 sub_DD6()
{
  unsigned int v0; // eax
  signed int v2; // [rsp+0h] [rbp-10h] BYREF
  int v3; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Be brave,speak out your love!");
  puts(&byte_11DE);
  puts("Please input the index:");
  __isoc99_scanf("%d", &v2);
  if ( (unsigned int)v2 >= 0x64 )
    exit(0);
  if ( *((_QWORD *)&unk_202060 + v2) )
    free(**((void ***)&unk_202060 + v2));
  v0 = time(0);
  srand(v0);
  v3 = rand() % 10;
  if ( v3 > 1 )
    puts("Oh, you have been refused.");
  else
    puts("Now she is your girl friend!");
  puts("Done!");
  return __readfsqword(0x28u) ^ v4;
}

void __noreturn sub_F08()
{
  int v0; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("Do you wanna a girl friend?");
  puts("Maybe she is hidden in the heap!");
  while ( 1 )
  {
    sub_ADD();
    __isoc99_scanf("%d", &v0);
    getchar();
    switch ( v0 )
    {
      case 1:
        sub_B49();
        break;
      case 2:
        sub_CFC();
        break;
      case 3:
        sub_CE9();
        break;
      case 4:
        sub_DD6();
        break;
      case 5:
        puts("Goodbye~");
        exit(0);
      default:
        puts("Wrong choice!");
        break;
    }
  }
}

void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  sub_A9A();
  sub_F08();
}