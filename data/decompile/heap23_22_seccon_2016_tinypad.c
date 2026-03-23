int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  __int64 v4; // rdx
  __int64 v5; // rdx
  __int64 v6; // rdx
  size_t v7; // rax
  int v8; // eax
  __int64 v9; // rdx
  int v10; // eax
  __int64 v11; // rdx
  size_t v12; // rax
  __int64 v13; // rdx
  size_t v14; // rax
  __int64 v15; // rdx
  __int64 v16; // rdx
  int c; // [rsp+4h] [rbp-1Ch] BYREF
  int i; // [rsp+8h] [rbp-18h]
  int v20; // [rsp+Ch] [rbp-14h]
  int v21; // [rsp+10h] [rbp-10h]
  int v22; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v23; // [rsp+18h] [rbp-8h]

  v23 = __readfsqword(0x28u);
  v21 = 0;
  write_n(&unk_4019F0, 1, envp);
  write_n(
    "  ============================================================================\n"
    "// _|_|_|_|_|  _|_|_|  _|      _|  _|      _|  _|_|_|      _|_|    _|_|_|     \\\\\n"
    "||     _|        _|    _|_|    _|    _|  _|    _|    _|  _|    _|  _|    _|   ||\n"
    "||     _|        _|    _|  _|  _|      _|      _|_|_|    _|_|_|_|  _|    _|   ||\n"
    "||     _|        _|    _|    _|_|      _|      _|        _|    _|  _|    _|   ||\n"
    "\\\\     _|      _|_|_|  _|      _|      _|      _|        _|    _|  _|_|_|     //\n"
    "  ============================================================================\n",
    563,
    v3);
  write_n(&unk_4019F0, 1, v4);
  do
  {
    for ( i = 0; i <= 3; ++i )
    {
      LOBYTE(c) = i + 49;
      writeln("+------------------------------------------------------------------------------+\n", 81);
      write_n(" #   INDEX: ", 12, v5);
      writeln(&c, 1);
      write_n(" # CONTENT: ", 12, v6);
      if ( *(_QWORD *)&tinypad[16 * i + 264] )
      {
        v7 = strlen(*(const char **)&tinypad[16 * i + 264]);
        writeln(*(_QWORD *)&tinypad[16 * i + 264], v7);
      }
      writeln(&unk_4019F0, 1);
    }
    v20 = 0;
    v8 = getcmd();
    v21 = v8;
    if ( v8 == 68 )
    {
      write_n("(INDEX)>>> ", 11, v9);
      v20 = read_int();
      if ( v20 <= 0 || v20 > 4 )
      {
LABEL_29:
        writeln("Invalid index", 13);
        continue;
      }
      if ( !*(_QWORD *)&tinypad[16 * v20 + 240] )
      {
LABEL_31:
        writeln("Not used", 8);
        continue;
      }
      free(*(void **)&tinypad[16 * v20 + 248]);
      *(_QWORD *)&tinypad[16 * v20 + 240] = 0;
      writeln("\nDeleted.", 9);
    }
    else if ( v8 > 68 )
    {
      if ( v8 != 69 )
      {
        if ( v8 == 81 )
          continue;
LABEL_41:
        writeln("No such a command", 17);
        continue;
      }
      write_n("(INDEX)>>> ", 11, v9);
      v20 = read_int();
      if ( v20 <= 0 || v20 > 4 )
        goto LABEL_29;
      if ( !*(_QWORD *)&tinypad[16 * v20 + 240] )
        goto LABEL_31;
      c = 48;
      strcpy(tinypad, *(const char **)&tinypad[16 * v20 + 248]);
      while ( toupper(c) != 89 )
      {
        write_n("CONTENT: ", 9, v16);
        v12 = strlen(tinypad);
        writeln(tinypad, v12);
        write_n("(CONTENT)>>> ", 13, v13);
        v14 = strlen(*(const char **)&tinypad[16 * v20 + 248]);
        read_until(tinypad, v14, 10);
        writeln("Is it OK?", 9);
        write_n("(Y/n)>>> ", 9, v15);
        read_until(&c, 1, 10);
      }
      strcpy(*(char **)&tinypad[16 * v20 + 248], tinypad);
      writeln("\nEdited.", 8);
    }
    else
    {
      if ( v8 != 65 )
        goto LABEL_41;
      while ( v20 <= 3 )
      {
        v9 = 16 * (v20 + 16LL);
        if ( !*(_QWORD *)&tinypad[v9] )
          break;
        ++v20;
      }
      if ( v20 == 4 )
      {
        writeln("No space is left.", 17);
      }
      else
      {
        v22 = -1;
        write_n("(SIZE)>>> ", 10, v9);
        v22 = read_int();
        if ( v22 <= 0 )
        {
          v10 = 1;
        }
        else
        {
          v10 = v22;
          if ( (unsigned __int64)v22 > 0x100 )
            v10 = 256;
        }
        v22 = v10;
        *(_QWORD *)&tinypad[16 * v20 + 256] = v10;
        *(_QWORD *)&tinypad[16 * v20 + 264] = malloc(v22);
        v11 = 16 * (v20 + 16LL);
        if ( !*(_QWORD *)&tinypad[v11 + 8] )
        {
          writerrln("[!] No memory is available.", 27);
          exit(-1);
        }
        write_n("(CONTENT)>>> ", 13, v11);
        read_until(*(_QWORD *)&tinypad[16 * v20 + 264], v22, 10);
        writeln("\nAdded.", 7);
      }
    }
  }
  while ( v21 != 81 );
  return 0;
}

__int64 __fastcall read_n(int a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v5; // [rsp+28h] [rbp-18h]
  ssize_t v6; // [rsp+30h] [rbp-10h]

  if ( !a2 )
    return -1;
  if ( !a3 )
    return 0;
  v5 = 0;
  while ( v5 < a3 )
  {
    v6 = read(a1, (void *)(a2 + v5), a3 - v5);
    if ( v6 >= 0 )
    {
      if ( !v6 )
        return v5;
      v5 += v6;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return -1;
    }
  }
  return v5;
}

__int64 __fastcall write_n(int a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v5; // [rsp+28h] [rbp-18h]
  ssize_t v6; // [rsp+30h] [rbp-10h]

  if ( !a2 )
    return -1;
  if ( !a3 )
    return 0;
  v5 = 0;
  while ( v5 < a3 )
  {
    v6 = write(a1, (const void *)(a2 + v5), a3 - v5);
    if ( v6 >= 0 )
    {
      if ( !v6 )
        return v5;
      v5 += v6;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return -1;
    }
  }
  return v5;
}

unsigned __int64 __fastcall dummyinput(int a1)
{
  char i; // [rsp+17h] [rbp-9h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( a1 )
  {
    for ( i = 0; i != a1; read_n(&i, 1) )
      ;
  }
  return __readfsqword(0x28u) ^ v3;
}

__int64 __fastcall read_n(__int64 a1, unsigned __int64 a2)
{
  return read_n(0, a1, a2);
}

__int64 __fastcall read_until(__int64 a1, unsigned __int64 a2, int a3)
{
  unsigned __int64 i; // [rsp+28h] [rbp-18h]
  __int64 n; // [rsp+30h] [rbp-10h]

  for ( i = 0; i < a2; ++i )
  {
    n = read_n(0, a1 + i, 1u);
    if ( n < 0 )
      return -1;
    if ( !n || *(char *)(a1 + i) == a3 )
      break;
  }
  *(_BYTE *)(a1 + i) = 0;
  if ( i == a2 && *(_BYTE *)(a2 - 1 + a1) != 10 )
    dummyinput(a3);
  return i;
}

__int64 __fastcall write_n(__int64 a1, unsigned __int64 a2)
{
  return write_n(1, a1, a2);
}

__int64 __fastcall write_errn(__int64 a1, unsigned __int64 a2)
{
  return write_n(2, a1, a2);
}

__int64 __fastcall writeln(__int64 a1, unsigned __int64 a2)
{
  __int64 v3; // [rsp+10h] [rbp-10h]

  v3 = write_n(a1, a2);
  return write_n((__int64)"\n", 1u) + v3;
}

__int64 __fastcall writerrln(__int64 a1, unsigned __int64 a2)
{
  __int64 v3; // [rsp+10h] [rbp-10h]

  v3 = write_errn(a1, a2);
  return write_errn((__int64)"\n", 1u) + v3;
}

int read_int()
{
  char nptr[8]; // [rsp+0h] [rbp-20h] BYREF
  __int64 v2; // [rsp+8h] [rbp-18h]
  __int16 v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  *(_QWORD *)nptr = 0;
  v2 = 0;
  v3 = 0;
  read_until((__int64)nptr, 0x11u, 10);
  return atoi(nptr);
}