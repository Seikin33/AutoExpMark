int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  char vars0; // [rsp+0h] [rbp+0h] BYREF
  unsigned __int64 vars18; // [rsp+18h] [rbp+18h]

  vars18 = __readfsqword(0x28u);
  init(argc, argv, envp);
  while ( 1 )
  {
    puts("Children Heap");
    puts("=============");
    puts("1. Allocate");
    puts("2. Update");
    puts("3. Show");
    puts("4. Free");
    puts("5. Exit");
    __printf_chk(1, ">> ");
    v3 = fgets(&vars0, 16, stdin);
    switch ( (unsigned int)strtol(v3, 0, 10) )
    {
      case 1u:
        allocate();
        break;
      case 2u:
        update();
        break;
      case 3u:
        show();
        break;
      case 4u:
        delete();
        break;
      case 5u:
        puts("Bye!");
        exit(0);
      default:
        puts("Huh ?");
        exit(-1);
    }
  }
}

unsigned __int64 allocate()
{
  char *v0; // rax
  signed int v1; // eax
  __int64 v2; // rbx
  char *v3; // rax
  int v4; // ebp
  char *v5; // rbx
  char _0[24]; // [rsp+0h] [rbp+0h] BYREF
  unsigned __int64 vars18; // [rsp+18h] [rbp+18h]

  vars18 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  v0 = fgets(_0, 16, stdin);
  v1 = strtol(v0, 0, 10);
  if ( (unsigned int)v1 > 0xF )
    error("Invalid index!");
  v2 = v1;
  if ( ptrs[v1] )
    error("Index is already allocated!");
  __printf_chk(1, "Size: ");
  v3 = fgets(_0, 16, stdin);
  v4 = strtol(v3, 0, 10);
  if ( (unsigned int)(v4 - 16) > 0xF0 )
    error("Invalid size!");
  ptrs[v2] = malloc(v4);
  sizes[v2] = v4;
  __printf_chk(1, "Content: ");
  v5 = (char *)ptrs[v2];
  v5[read(0, v5, v4) - 1] = 0;
  return __readfsqword(0x28u) ^ vars18;
}

unsigned __int64 update()
{
  char *v0; // rax
  unsigned int v1; // eax
  __int64 v2; // rbx
  _BYTE *v3; // rbp
  char v5[24]; // [rsp+0h] [rbp-38h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  v0 = fgets(v5, 16, stdin);
  v1 = strtol(v0, 0, 10);
  if ( v1 > 0xF )
    error("Invalid index!");
  v2 = (int)v1;
  if ( !ptrs[v1] )
    error("Index is not allocated!");
  __printf_chk(1, "Content: ");
  v3 = (_BYTE *)ptrs[v2];
  v3[read(0, v3, (int)sizes[v2])] = 0;
  return __readfsqword(0x28u) ^ v6;
}

unsigned __int64 show()
{
  char *v0; // rax
  unsigned int v1; // eax
  const char *v2; // r8
  char v4[24]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-10h]

  v5 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  v0 = fgets(v4, 16, stdin);
  v1 = strtol(v0, 0, 10);
  if ( v1 > 0xF )
    error("Invalid index!");
  v2 = (const char *)ptrs[v1];
  if ( !v2 )
    error("Index is not allocated!");
  __printf_chk(1, "Chunk %d's content: %.*s\n", v1, sizes[v1], v2);
  return __readfsqword(0x28u) ^ v5;
}

unsigned __int64 delete()
{
  char *v0; // rax
  unsigned int v1; // eax
  __int64 v2; // rbx
  void *v3; // rdi
  char v5[24]; // [rsp+0h] [rbp-38h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  v0 = fgets(v5, 16, stdin);
  v1 = strtol(v0, 0, 10);
  if ( v1 > 0xF )
    error("Invalid index!");
  v2 = (int)v1;
  v3 = (void *)ptrs[v1];
  if ( !v3 )
    error("Index is not allocated!");
  free(v3);
  ptrs[v2] = 0;
  sizes[v2] = 0;
  return __readfsqword(0x28u) ^ v6;
}