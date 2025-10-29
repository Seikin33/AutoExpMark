# 程序基本功能

该程序实现了一个简易的“便签（note）管理”功能，最多支持 4 个便签，提供新增、查看、编辑、删除与退出操作。程序启动时还会读取用户的姓名与地址作为基本信息。

- 输入与菜单：
  - 通过逐字节读取函数读取姓名与地址，并显示菜单。
  - 菜单项：1 新建、2 查看、3 编辑、4 删除、5/6 退出。

代码片段：
```7:11:experiments/Cs/sample3.c
  puts("Input your name:");
  sub_4009BD(&unk_6020E0, 64, 10);
  puts("Input your address:");
  sub_4009BD(&unk_602180, 96, 10);
  while ( 1 )
```

菜单与分发：
```57:71:experiments/Cs/sample3.c
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
```

- 新建便签（1）：申请指定大小的堆块，读取内容，并进行一次过滤处理后保存。
```73:93:experiments/Cs/sample3.c
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
```

- 查看便签（2）：按 id 打印对应便签内容。
```112:126:experiments/Cs/sample3.c
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
```

- 编辑便签（3）：支持覆盖或追加，使用栈上 `dest[128]` 作为暂存缓冲，拼接新内容后写回原便签。
```129:170:experiments/Cs/sample3.c
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
```

- 删除便签（4）：释放堆块并清零指针与长度。
```189:209:experiments/Cs/sample3.c
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
```

# 关键结构体

程序未定义显式的 C 结构体，但使用了若干关键的全局数据结构：

- `ptr`：长度为 4 的全局指针数组，保存每个 note 的堆指针。
  - 使用位置：
```88:93:experiments/Cs/sample3.c
  *(&ptr + (unsigned int)dword_602160) = size_4;
  qword_602140[dword_602160] = size;
  v1 = dword_602160++;
  return printf("note add success, the id is %d\n", v1);
```

- `qword_602140`：长度为 4 的全局数组，保存对应 note 的分配大小（上限 128）。
  - 使用位置：
```147:149:experiments/Cs/sample3.c
      src = (char *)*(&ptr + (int)v2);
      v5 = qword_602140[v2];
      if ( src )
```

- `dword_602160`：当前 note 数量计数器，最大为 4（索引 0..3）。
  - 使用位置：
```79:83:experiments/Cs/sample3.c
  if ( (unsigned int)dword_602160 > 3 )
    return puts("note lists are full");
  puts("Input the length of the note content:(less than 128)");
  size = sub_400A4A();
```

- `unk_6020E0[64]` 与 `unk_602180[96]`：分别存储用户名与地址的全局缓冲区。
  - 使用位置：
```7:10:experiments/Cs/sample3.c
  puts("Input your name:");
  sub_4009BD(&unk_6020E0, 64, 10);
  puts("Input your address:");
  sub_4009BD(&unk_602180, 96, 10);
```

# 漏洞成因

1) 堆 off-by-one 溢出（单字节越界写）

- 位置：过滤函数 `sub_400B10`。
```101:109:experiments/Cs/sample3.c
  v3 = 0;
  for ( i = 0; i <= strlen(a1); ++i )
  {
    if ( a1[i] != 37 )
      a1[v3++] = a1[i];
  }
  result = &a1[v3];
  *result = 0;
  return result;
```
- 成因分析：循环条件为 `i <= strlen(a1)`，会在最后一次迭代复制原字符串的 `\0` 终止符到 `a1[v3++]`，使 `v3` 在循环结束后等于“原始长度 + 1”。随后 `*(&a1[v3]) = 0` 再次写入一个终止符，导致在无 `%` 字符时对缓冲区尾部“再写入一个字节”的越界。这是典型的 off-by-one（单字节）堆溢出，可能破坏下一个堆块的元数据或紧邻字段，从而被利用实现堆布局破坏与控制流劫持。
- 影响范围：
  - 新建便签时在堆块上调用 `sub_400B10(size_4)`，直接对刚分配的 note 缓冲执行该越界写。
  - 编辑便签时也会对 `v7 + 15` 执行同样逻辑，尽管 `v7` 较大且预留空间较多，但该错误的写边界仍然存在。

2) 危险的格式化字符串用法

- 位置：编辑流程中对堆缓冲作为格式串调用 `printf`。
```159:162:experiments/Cs/sample3.c
          v7 = (char *)malloc(0xA0u);
          strcpy(v7, "TheNewContents:");
          printf(v7);
          sub_4009BD((__int64)(v7 + 15), 144, 10);
```
- 成因分析：`printf(v7)` 直接使用可变缓冲区作为格式串是危险模式。当前路径里在调用前将 `v7` 置为常量字符串，不包含 `%`，因此短期内不可利用；但一旦后续代码改动、路径复用或可控数据在 `printf` 前写入 `v7`，将立刻演化为可利用的格式化字符串漏洞。该模式属于不安全 API 使用，应统一改为 `printf("%s", v7);`。

3) 逻辑依赖不严谨导致的潜在栈溢出风险（与 1) 组合可利用）

- 位置：编辑流程的拼接逻辑。
```165:167:experiments/Cs/sample3.c
          v0[v5 - strlen(dest) + 14] = 0;
          strncat(dest, v7 + 15, 0xFFFFFFFFFFFFFFFFLL);
          strcpy(src, dest);
```
- 成因分析：`dest` 是 128 字节的栈缓冲。代码试图通过在 `v7` 中插入 `\0` 来限制拼接长度，使总长度不超过原分配大小 `v5`。然而这里完全依赖全局记录的 `v5=qword_602140[v2]` 的正确性，并使用了“无限大”长度参数的 `strncat`。一旦 `v5` 被破坏（例如通过 1) 的堆单字节越界影响相邻元数据或长度记录），则可能造成 `strncat` 依据错误的上界进行几乎不受限的拷贝，进而对 `dest[128]` 造成栈溢出。单独看该片段在正常路径下受限于 `v5<=128` 似乎安全，但与 1) 组合后存在可利用路径。

——

综上，最核心、确定可利用的内存破坏是 `sub_400B10` 的 off-by-one 堆溢出（再次写入终止符导致的单字节越界写）。此外，`printf(v7)` 属于危险用法，易在代码演进中蜕变为格式化字符串漏洞；编辑路径的拼接逻辑在与堆越界结合时也可能触发栈溢出。
