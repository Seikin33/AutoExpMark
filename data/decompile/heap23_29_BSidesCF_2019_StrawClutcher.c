int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rbx
  const char *v4; // rdi
  char *v5; // r12
  char *v6; // rax
  char *v7; // rax
  __int64 v8; // r8
  const char *v9; // r13
  char *v10; // r12
  char *v11; // r12
  __int64 j; // r13
  unsigned __int8 v13; // cl
  __int64 v14; // rax
  char *v15; // rsi
  const char *v16; // r14
  char *v17; // rsi
  char *v18; // rax
  const char *v19; // r15
  char *v20; // r12
  const char *v21; // r12
  const char *v22; // rsi
  const char *v23; // rdi
  char *v24; // r9
  char *v25; // r12
  char *v26; // r12
  __int64 k; // r13
  const char *v28; // r12
  const char *v29; // r14
  char *v30; // r12
  __int64 v31; // r14
  __int64 i; // r13
  void *v33; // rdi
  const char *v34; // r15
  char *v35; // rax
  signed __int64 v36; // r12
  char *v37; // rdx
  char *v38; // r12
  char *v39; // r15
  __int64 n; // r13
  char *v41; // rax
  unsigned __int64 v42; // r13
  __int64 v43; // r14
  __int64 v44; // rdx
  __int64 v45; // rcx
  const char *v46; // rdi
  char *v47; // rdi
  const char *v48; // r12
  char *v49; // rax
  char *v50; // r14
  char *v51; // r13
  _QWORD *m; // r12
  const char *v53; // rdi
  unsigned __int64 v54; // r14
  unsigned __int64 v55; // rdx
  size_t v56; // rax
  int *v57; // rax
  char v58; // r13
  char *v59; // rax
  char *v60; // rdi
  _QWORD *v62; // r13
  unsigned __int64 v63; // rax
  const char *v64; // rdi
  unsigned __int64 v65; // r8
  void *v66; // rsp
  __int64 v67; // rdx
  size_t v68; // rdx
  size_t v69; // rax
  int *v70; // rax
  char *v71; // rax
  char *v72; // rax
  size_t v73; // rsi
  __int64 v74; // r12
  void *v75; // rax
  __int64 v76; // rdx
  __int64 v77; // [rsp+0h] [rbp-60h] BYREF
  unsigned __int64 v78; // [rsp+8h] [rbp-58h]
  char *v79; // [rsp+10h] [rbp-50h]
  signed __int64 v80; // [rsp+18h] [rbp-48h]
  unsigned __int64 v81; // [rsp+28h] [rbp-38h]

  v81 = __readfsqword(0x28u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  v4 = "200 WaterDragon File Transfer Daemon";
  head = 0;
LABEL_2:
  puts(v4);
  while ( 2 )
  {
    if ( !linebuf_4366 )
    {
      linebuf_4366 = (char *)malloc(0x200u);
      linebuf_4366[511] = 0;
    }
    if ( !fgets(linebuf_4366, 511, stdin) )
      goto LABEL_551;
    v5 = linebuf_4366;
    v6 = strchr(linebuf_4366, 10);
    if ( v6 )
      *v6 = 0;
    v7 = strchr(v5, 13);
    if ( v7 )
      *v7 = 0;
    v8 = (unsigned int)*v5;
    v9 = v5 + 1;
    switch ( *v5 )
    {
      case 'D':
      case 'd':
        v8 = (unsigned int)v5[1];
        if ( v5[1] != 69 && v5[1] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 76 && v5[2] != 108 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[3];
        if ( v5[3] != 69 && v5[3] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[4];
        if ( v5[4] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[5];
        if ( v5[5] > 90 )
        {
          if ( (unsigned __int8)(v5[5] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v5[5] < 65 && (unsigned __int8)(v5[5] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v18 = v5 + 5;
        while ( 1 )
        {
          do
          {
            while ( 1 )
            {
              v8 = (unsigned int)*++v18;
              if ( *v18 <= 90 )
                break;
              if ( (unsigned __int8)(*v18 - 97) > 0x19u )
              {
                v3 = v5 + 1;
                goto LABEL_47;
              }
            }
          }
          while ( *v18 >= 65 );
          if ( *v18 == 46 )
            break;
          if ( *v18 < 46 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          if ( (unsigned __int8)(*v18 - 48) > 9u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        v8 = (unsigned int)v18[1];
        if ( v18[1] > 90 )
        {
          if ( (unsigned __int8)(v18[1] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v18[1] < 65 && (unsigned __int8)(v18[1] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v18[2];
        if ( v18[2] > 90 )
        {
          if ( (unsigned __int8)(v18[2] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v18[2] < 65 && (unsigned __int8)(v18[2] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v18[3];
        if ( v18[3] > 90 )
        {
          if ( (unsigned __int8)(v18[3] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v18[3] < 65 && (unsigned __int8)(v18[3] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v18[4];
        if ( v18[4] > 0 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v30 = strdup(v5 + 5);
        v31 = head;
        for ( i = head; ; i = *(_QWORD *)(i + 64) )
        {
          if ( !i )
          {
            __printf_chk(1, "400 Filename \"%s\" not found\n", v30);
            goto LABEL_502;
          }
          if ( !strcmp((const char *)i, v30) )
            break;
        }
        if ( v31 == i )
        {
          head = *(_QWORD *)(i + 64);
        }
        else
        {
          while ( i != *(_QWORD *)(v31 + 64) )
            v31 = *(_QWORD *)(v31 + 64);
          *(_QWORD *)(v31 + 64) = *(_QWORD *)(i + 64);
        }
        v33 = *(void **)(i + 48);
        if ( *(_DWORD *)(i + 56) )
          munmap(v33, *(_QWORD *)(i + 40));
        else
          free(v33);
        free((void *)i);
        __printf_chk(1, "200 Filename \"%s\" removed\n", v30);
        goto LABEL_502;
      case 'G':
      case 'g':
        v8 = (unsigned int)v5[1];
        if ( v5[1] != 69 && v5[1] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 84 && v5[2] != 116 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v10 = v5 + 2;
        goto LABEL_110;
      case 'H':
      case 'h':
        v8 = (unsigned int)v5[1];
        if ( v5[1] != 69 && v5[1] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 76 && v5[2] != 108 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[3];
        if ( v5[3] != 80 && v5[3] != 112 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[4];
        if ( v5[4] > 0 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        __printf_chk(
          1,
          "200. Recognized commands\n"
          "200. LOGIN userID clientID - perform login\n"
          "200. HELP - this command\n"
          "200. SITE GLOB parameter - perform server side globbing\n"
          "200. LIST - lists files on server\n"
          "200 Done!");
        continue;
      case 'L':
      case 'l':
        v8 = (unsigned int)v5[1];
        if ( v5[1] == 79 )
          goto LABEL_60;
        if ( v5[1] <= 79 )
        {
          if ( v5[1] != 73 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
LABEL_57:
          v8 = (unsigned int)v5[2];
          if ( v5[2] != 83 && v5[2] != 115 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[3];
          if ( v5[3] != 84 && v5[3] != 116 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          puts("231. Files as follows");
          for ( j = head; j; j = *(_QWORD *)(j + 64) )
            __printf_chk(1, "232. \"%s\" - %ld bytes\n", (const char *)j, *(_QWORD *)(j + 40));
          v4 = "231 Done!";
          goto LABEL_2;
        }
        if ( v5[1] == 105 )
          goto LABEL_57;
        if ( v5[1] != 111 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
LABEL_60:
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 71 && v5[2] != 103 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[3];
        if ( v5[3] != 73 && v5[3] != 105 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[4];
        if ( v5[4] != 78 && v5[4] != 110 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[5];
        if ( v5[5] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[6];
        if ( (unsigned int)(v5[6] - 97) > 0x19 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v19 = v5 + 6;
        v20 = v5 + 6;
        while ( 1 )
        {
          v8 = (unsigned int)v20[1];
          if ( v20[1] == 32 )
            break;
          if ( v20[1] < 32 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          ++v20;
          if ( (unsigned __int8)(v8 - 97) > 0x19u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        v8 = (unsigned int)v20[2];
        if ( v20[2] > 90 )
        {
          if ( v20[2] != 95 )
          {
            if ( v20[2] < 95 )
            {
              v3 = v9;
              goto LABEL_47;
            }
            if ( (unsigned __int8)(v20[2] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
        }
        else if ( v20[2] < 64 && v20[2] != 45 )
        {
          if ( v20[2] < 45 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          if ( (unsigned __int8)(v20[2] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        v28 = v20 + 2;
        v29 = v28;
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              v8 = (unsigned int)v29[1];
              if ( v29[1] <= 90 )
                break;
              ++v29;
              if ( (_BYTE)v8 != 95 )
              {
                if ( (char)v8 < 95 )
                {
                  v3 = v9;
                  goto LABEL_47;
                }
                if ( (unsigned __int8)(v8 - 97) > 0x19u )
                {
                  v3 = v9;
                  goto LABEL_47;
                }
              }
            }
            if ( v29[1] < 64 && v29[1] != 45 )
              break;
            ++v29;
          }
          if ( v29[1] <= 45 )
            break;
          ++v29;
          if ( (unsigned __int8)(v8 - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        if ( v29[1] )
        {
          v3 = v9;
          goto LABEL_47;
        }
        if ( strncmp(v19, "anonymous", 9u) )
        {
          g_LoggedIn = 0;
          v4 = "400 only supports anonymous logins!";
          goto LABEL_2;
        }
        if ( !g_Username )
          g_Username = strndup(v19, (int)v28 - (int)v19 - 1);
        if ( g_ClientID )
          free(g_ClientID);
        g_ClientID = strndup(v28, (int)v29 + 2 - (int)v28);
        puts("200 Successfully logged in!");
        g_LoggedIn = 1;
        continue;
      case 'P':
      case 'p':
        v8 = (unsigned int)v5[1];
        if ( v5[1] != 85 && v5[1] != 117 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 84 && v5[2] != 116 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v11 = v5 + 2;
        goto LABEL_128;
      case 'R':
      case 'r':
        v8 = (unsigned int)v5[1];
        if ( v5[1] != 69 && v5[1] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[2];
        if ( v5[2] == 84 )
          goto LABEL_44;
        if ( v5[2] > 84 )
        {
          if ( v5[2] == 110 )
            goto LABEL_93;
          if ( v5[2] != 116 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
LABEL_44:
          v8 = (unsigned int)v5[3];
          if ( v5[3] != 82 && v5[3] != 114 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v10 = v5 + 3;
LABEL_110:
          v8 = (unsigned int)v10[1];
          if ( v10[1] != 32 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v10[2];
          if ( v10[2] > 90 )
          {
            if ( (unsigned __int8)(v10[2] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v10[2] < 65 && (unsigned __int8)(v10[2] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v15 = v10 + 2;
          while ( 1 )
          {
            do
            {
              while ( 1 )
              {
                v8 = (unsigned int)*++v15;
                if ( *v15 <= 90 )
                  break;
                if ( (unsigned __int8)(*v15 - 97) > 0x19u )
                {
                  v3 = v9;
                  goto LABEL_47;
                }
              }
            }
            while ( *v15 >= 65 );
            if ( *v15 == 46 )
              break;
            if ( *v15 < 46 )
            {
              v3 = v9;
              goto LABEL_47;
            }
            if ( (unsigned __int8)(*v15 - 48) > 9u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          v8 = (unsigned int)v15[1];
          if ( v15[1] > 90 )
          {
            if ( (unsigned __int8)(v15[1] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v15[1] < 65 && (unsigned __int8)(v15[1] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v15[2];
          if ( v15[2] > 90 )
          {
            if ( (unsigned __int8)(v15[2] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v15[2] < 65 && (unsigned __int8)(v15[2] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v15[3];
          if ( v15[3] > 90 )
          {
            if ( (unsigned __int8)(v15[3] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v15[3] < 65 && (unsigned __int8)(v15[3] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v15[4];
          if ( v15[4] > 0 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v26 = strndup(v10 + 2, (int)v15 + 5 - ((int)v10 + 2));
          for ( k = head; ; k = *(_QWORD *)(k + 64) )
          {
            if ( !k )
            {
              __printf_chk(1, "354 Can't download file - \"%s\" - no such file!\n", v26);
              goto LABEL_553;
            }
            if ( !strcmp((const char *)k, v26) )
              break;
          }
          v54 = 0;
          __printf_chk(1, "200 File download started. Prepare to get %ld bytes\n", *(_QWORD *)(k + 40));
          while ( 1 )
          {
            v55 = *(_QWORD *)(k + 40);
            if ( v55 <= v54 )
              break;
            v56 = fwrite((const void *)(v54 + *(_QWORD *)(k + 48)), 1u, v55 - v54, stdout);
            if ( !v56 )
            {
              v57 = __errno_location();
              v58 = 0;
              v59 = strerror(*v57);
              __printf_chk(1, "400 Can't write data: %s\n", v59);
              goto LABEL_549;
            }
            v54 += v56;
          }
          puts("200 Data transferred!");
LABEL_553:
          v58 = 1;
LABEL_549:
          v60 = v26;
LABEL_550:
          free(v60);
          if ( !v58 )
            goto LABEL_551;
          continue;
        }
        if ( v5[2] != 78 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
LABEL_93:
        v8 = (unsigned int)v5[3];
        if ( v5[3] != 65 && v5[3] != 97 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[4];
        if ( v5[4] != 77 && v5[4] != 109 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[5];
        if ( v5[5] != 69 && v5[5] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[6];
        if ( v5[6] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[7];
        if ( v5[7] > 90 )
        {
          if ( (unsigned __int8)(v5[7] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v5[7] < 65 && (unsigned __int8)(v5[7] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v23 = v5 + 7;
        v24 = v5 + 7;
        while ( 1 )
        {
          do
          {
            while ( 1 )
            {
              v8 = (unsigned int)*++v24;
              if ( *v24 <= 90 )
                break;
              if ( (unsigned __int8)(*v24 - 97) > 0x19u )
              {
                v3 = v5 + 1;
                goto LABEL_47;
              }
            }
          }
          while ( *v24 >= 65 );
          if ( *v24 == 46 )
            break;
          if ( *v24 < 46 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          if ( (unsigned __int8)(*v24 - 48) > 9u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        v8 = (unsigned int)v24[1];
        if ( v24[1] > 90 )
        {
          if ( (unsigned __int8)(v24[1] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v24[1] < 65 && (unsigned __int8)(v24[1] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v24[2];
        if ( v24[2] > 90 )
        {
          if ( (unsigned __int8)(v24[2] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v24[2] < 65 && (unsigned __int8)(v24[2] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v24[3];
        if ( v24[3] > 90 )
        {
          if ( (unsigned __int8)(v24[3] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v24[3] < 65 && (unsigned __int8)(v24[3] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v24[4];
        if ( v24[4] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v24[5];
        if ( v24[5] > 90 )
        {
          if ( (unsigned __int8)(v24[5] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v24[5] < 65 && (unsigned __int8)(v24[5] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v48 = v24 + 5;
        v49 = v24 + 5;
        while ( 1 )
        {
          do
          {
            while ( 1 )
            {
              v8 = (unsigned int)*++v49;
              if ( *v49 <= 90 )
                break;
              if ( (unsigned __int8)(*v49 - 97) > 0x19u )
              {
                v3 = v9;
                goto LABEL_47;
              }
            }
          }
          while ( *v49 >= 65 );
          if ( *v49 == 46 )
            break;
          if ( *v49 < 46 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          if ( (unsigned __int8)(*v49 - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        v8 = (unsigned int)v49[1];
        if ( v49[1] > 90 )
        {
          if ( (unsigned __int8)(v49[1] - 97) > 0x19u )
          {
            v3 = v9;
            goto LABEL_47;
          }
LABEL_519:
          v8 = (unsigned int)v49[2];
          if ( v49[2] > 90 )
          {
            if ( (unsigned __int8)(v49[2] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v49[2] < 65 && (unsigned __int8)(v49[2] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v49[3];
          if ( v49[3] > 90 )
          {
            if ( (unsigned __int8)(v49[3] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v49[3] < 65 && (unsigned __int8)(v49[3] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v49[4];
          if ( v49[4] > 0 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v50 = strndup(v23, (int)v48 - (int)v23 - 1);
          if ( strlen(v50) > 0x1F )
          {
            v4 = "300 Filename too long.";
            goto LABEL_2;
          }
          v51 = strndup(v48, (int)v9 - (int)v48);
          if ( strlen(v50) > 0x1F )
          {
            v4 = "300 Destination filename too long.";
            goto LABEL_2;
          }
          for ( m = (_QWORD *)head; m; m = (_QWORD *)m[8] )
          {
            if ( !strcmp((const char *)m, v50) )
            {
              qmemcpy(m, v51, strlen(v51));
              v53 = "200 Filename renamed";
              goto LABEL_543;
            }
          }
          v53 = "400 File not found";
LABEL_543:
          puts(v53);
          free(v50);
          v47 = v51;
LABEL_544:
          free(v47);
          continue;
        }
        if ( v49[1] >= 65 || (unsigned __int8)(v49[1] - 48) <= 9u )
          goto LABEL_519;
        v3 = v9;
LABEL_47:
        __printf_chk(1, "error.. cursor is %s, marker is %s, and ch is '%c'\n", v9, v3, v8);
LABEL_551:
        puts("200 Thank you, have a nice day!");
        return 0;
      case 'S':
      case 's':
        v8 = (unsigned int)v5[1];
        if ( v5[1] == 84 )
          goto LABEL_75;
        if ( v5[1] > 84 )
        {
          if ( v5[1] == 105 )
            goto LABEL_72;
          if ( v5[1] != 116 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
LABEL_75:
          v8 = (unsigned int)v5[2];
          if ( v5[2] != 79 && v5[2] != 111 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[3];
          if ( v5[3] != 82 && v5[3] != 114 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v11 = v5 + 3;
LABEL_128:
          v8 = (unsigned int)v11[1];
          if ( v11[1] != 32 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v11[2];
          if ( v11[2] > 90 )
          {
            if ( (unsigned __int8)(v11[2] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v11[2] < 65 && (unsigned __int8)(v11[2] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v16 = v11 + 2;
          v17 = v11 + 2;
          while ( 1 )
          {
            do
            {
              while ( 1 )
              {
                v8 = (unsigned int)*++v17;
                if ( *v17 <= 90 )
                  break;
                if ( (unsigned __int8)(*v17 - 97) > 0x19u )
                {
                  v3 = v9;
                  goto LABEL_47;
                }
              }
            }
            while ( *v17 >= 65 );
            if ( *v17 == 46 )
              break;
            if ( *v17 < 46 )
            {
              v3 = v9;
              goto LABEL_47;
            }
            if ( (unsigned __int8)(*v17 - 48) > 9u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          v8 = (unsigned int)v17[1];
          if ( v17[1] > 90 )
          {
            if ( (unsigned __int8)(v17[1] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v17[1] < 65 && (unsigned __int8)(v17[1] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v17[2];
          if ( v17[2] > 90 )
          {
            if ( (unsigned __int8)(v17[2] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v17[2] < 65 && (unsigned __int8)(v17[2] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v17[3];
          if ( v17[3] > 90 )
          {
            if ( (unsigned __int8)(v17[3] - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v17[3] < 65 && (unsigned __int8)(v17[3] - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v17[4];
          if ( v17[4] != 32 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v17[5];
          if ( (unsigned int)(v17[5] - 48) > 9 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v34 = v17 + 5;
          v35 = v17 + 5;
          while ( 1 )
          {
            v8 = (unsigned int)*++v35;
            if ( !*v35 )
              break;
            if ( *v35 < 0 )
            {
              v3 = v9;
              goto LABEL_47;
            }
            if ( (unsigned __int8)(*v35 - 48) > 9u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          v36 = strtoul(v34, 0, 10);
          if ( !v36 )
          {
            v4 = "300 At least upload some data";
            goto LABEL_2;
          }
          v39 = strndup(v16, (int)v34 - (int)v16 - 1);
          for ( n = head; n; n = *(_QWORD *)(n + 64) )
          {
            if ( !strcmp((const char *)n, v39) )
            {
              puts("400 Filename already exists");
LABEL_557:
              v58 = 1;
              goto LABEL_558;
            }
          }
          if ( v36 > 0x800000 )
          {
            __printf_chk(1, "400 File size too large - %ld / %016x bytes.\n", v36, v36);
            goto LABEL_557;
          }
          v62 = calloc(0x48u, 1u);
          if ( !v62 )
            errx(1, "calloc: can't allocate");
          v63 = strlen(v39) + 1;
          v64 = "400 File name too long";
          if ( v63 - 1 <= 0x27 )
          {
            __strncpy_chk(v62, v39, v63 - 1, 40);
            v62[5] = v36;
            if ( v36 > 0xFFFFF )
            {
              *((_DWORD *)v62 + 14) = 1;
              v73 = v36;
              v74 = 0;
              v75 = mmap(0, v73, 3, 34, -1, 0);
              v62[6] = v75;
              if ( v75 == (void *)-1LL )
              {
                puts("400 file too large");
              }
              else
              {
                while ( 1 )
                {
                  v76 = v62[5];
                  if ( v76 <= v74 )
                    break;
                  v80 = fread((void *)(v62[6] + v80), 1u, v76 - v80, stdin);
                  if ( v80 <= 0 )
                  {
                    puts("400 unable to read data");
                    goto LABEL_581;
                  }
                  v74 += v80;
                }
              }
              goto LABEL_583;
            }
            v65 = 0;
            v66 = alloca(v36);
            v79 = (char *)&v77;
            while ( v36 > v65 )
            {
              v67 = v62[5];
              v78 = v65;
              v68 = v67 - v65;
              if ( v68 > 0x1000 )
                v68 = 4096;
              v69 = fread(&v79[v65], 1u, v68, stdin);
              if ( !v69 )
              {
                v70 = __errno_location();
                v71 = strerror(*v70);
                __printf_chk(1, "400. Unable to read data: %s\n", v71);
                goto LABEL_581;
              }
              v65 = v69 + v78;
            }
            v72 = (char *)malloc(v36);
            v62[6] = v72;
            if ( v72 )
            {
              qmemcpy(v72, v79, v36);
              puts("200 Entry created");
LABEL_583:
              v62[8] = head;
              head = v62;
              goto LABEL_557;
            }
            puts("400 Unable to allocate memory");
LABEL_581:
            v64 = "400 Unable to get data :(";
          }
          puts(v64);
          v58 = 0;
LABEL_558:
          v60 = v39;
          goto LABEL_550;
        }
        if ( v5[1] != 73 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
LABEL_72:
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 84 && v5[2] != 116 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[3];
        if ( v5[3] != 69 && v5[3] != 101 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[4];
        if ( v5[4] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[5];
        v13 = v5[5] - 69;
        if ( v13 > 0x24u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v14 = 1LL << v13;
        if ( ((1LL << v13) & 0x1000000010LL) != 0 )
        {
          v8 = (unsigned int)v5[6];
          if ( v5[6] != 78 && v5[6] != 110 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[7];
          if ( v5[7] != 68 && v5[7] != 100 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[8];
          if ( v5[8] != 69 && v5[8] != 101 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[9];
          if ( v5[9] != 88 && v5[9] != 120 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v25 = v5 + 9;
LABEL_389:
          v8 = (unsigned int)v25[1];
          if ( v25[1] != 32 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          v8 = (unsigned int)v25[2];
          if ( v25[2] > 90 )
          {
            if ( v25[2] < 97 )
            {
              v3 = v9;
              goto LABEL_47;
            }
            if ( v25[2] > 109 && (unsigned __int8)(v25[2] - 111) > 0xBu )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          else if ( v25[2] < 79 )
          {
            if ( v25[2] < 33 )
            {
              v3 = v9;
              goto LABEL_47;
            }
            if ( v25[2] > 57 && (unsigned __int8)(v25[2] - 65) > 0xCu )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          v37 = v25 + 2;
          while ( 1 )
          {
LABEL_452:
            while ( 1 )
            {
              v8 = (unsigned int)v37[1];
              if ( v37[1] <= 90 )
                break;
              if ( v37[1] < 97 )
              {
                v3 = v9;
                goto LABEL_47;
              }
              ++v37;
              if ( (char)v8 > 109 && (unsigned __int8)(v8 - 111) > 0xBu )
              {
                v3 = v9;
                goto LABEL_47;
              }
            }
            if ( v37[1] >= 79 )
              goto LABEL_454;
            if ( v37[1] <= 57 )
              break;
            ++v37;
            if ( (unsigned __int8)(v8 - 65) > 0xCu )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
          if ( v37[1] < 33 )
          {
            if ( v37[1] )
            {
              v3 = v9;
              goto LABEL_47;
            }
            __printf_chk(1, "300 Command \"%.*s\" is not supported", (_DWORD)v37 - (_DWORD)v25, v25 + 2);
            continue;
          }
LABEL_454:
          ++v37;
          goto LABEL_452;
        }
        if ( (v14 & 0x400000004LL) == 0 )
        {
          if ( (v14 & 0x100000001LL) == 0 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[6];
          if ( v5[6] != 88 && v5[6] != 120 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[7];
          if ( v5[7] != 69 && v5[7] != 101 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v8 = (unsigned int)v5[8];
          if ( v5[8] != 67 && v5[8] != 99 )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
          v25 = v5 + 8;
          goto LABEL_389;
        }
        v8 = (unsigned int)v5[6];
        if ( v5[6] != 76 && v5[6] != 108 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[7];
        if ( v5[7] != 79 && v5[7] != 111 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[8];
        if ( v5[8] != 66 && v5[8] != 98 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[9];
        if ( v5[9] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[10];
        if ( v5[10] < 33 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        if ( v5[10] > 57 && v5[10] < 65 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v38 = v5 + 10;
        do
        {
          while ( 1 )
          {
            v8 = (unsigned int)*++v38;
            if ( *v38 <= 57 )
              break;
            if ( *v38 < 65 )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
        }
        while ( *v38 >= 33 );
        if ( *v38 )
        {
          v3 = v9;
          goto LABEL_47;
        }
        v4 = "400 Command is not supported";
        goto LABEL_2;
      case 'T':
      case 't':
        v8 = (unsigned int)v5[1];
        if ( v5[1] != 82 && v5[1] != 114 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[2];
        if ( v5[2] != 85 && v5[2] != 117 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[3];
        if ( v5[3] != 78 && v5[3] != 110 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[4];
        if ( v5[4] != 67 && v5[4] != 99 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[5];
        if ( v5[5] != 32 )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v8 = (unsigned int)v5[6];
        if ( v5[6] > 90 )
        {
          if ( (unsigned __int8)(v5[6] - 97) > 0x19u )
          {
            v3 = v5 + 1;
            goto LABEL_47;
          }
        }
        else if ( v5[6] < 65 && (unsigned __int8)(v5[6] - 48) > 9u )
        {
          v3 = v5 + 1;
          goto LABEL_47;
        }
        v21 = v5 + 6;
        v22 = v21;
        do
        {
LABEL_304:
          while ( 1 )
          {
            v8 = (unsigned int)*++v22;
            if ( *v22 <= 90 )
              break;
            if ( (unsigned __int8)(*v22 - 97) > 0x19u )
            {
              v3 = v9;
              goto LABEL_47;
            }
          }
        }
        while ( *v22 >= 65 );
        if ( *v22 != 46 )
        {
          if ( *v22 < 46 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          if ( (unsigned __int8)(*v22 - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
          goto LABEL_304;
        }
        v8 = (unsigned int)v22[1];
        if ( v22[1] > 90 )
        {
          if ( (unsigned __int8)(v22[1] - 97) > 0x19u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        else if ( v22[1] < 65 && (unsigned __int8)(v22[1] - 48) > 9u )
        {
          v3 = v9;
          goto LABEL_47;
        }
        v8 = (unsigned int)v22[2];
        if ( v22[2] > 90 )
        {
          if ( (unsigned __int8)(v22[2] - 97) > 0x19u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        else if ( v22[2] < 65 && (unsigned __int8)(v22[2] - 48) > 9u )
        {
          v3 = v9;
          goto LABEL_47;
        }
        v8 = (unsigned int)v22[3];
        if ( v22[3] > 90 )
        {
          if ( (unsigned __int8)(v22[3] - 97) > 0x19u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        else if ( v22[3] < 65 && (unsigned __int8)(v22[3] - 48) > 9u )
        {
          v3 = v9;
          goto LABEL_47;
        }
        v8 = (unsigned int)v22[4];
        if ( v22[4] != 32 )
        {
          v3 = v9;
          goto LABEL_47;
        }
        v8 = (unsigned int)v22[5];
        if ( (unsigned int)(v22[5] - 48) > 9 )
        {
          v3 = v9;
          goto LABEL_47;
        }
        v41 = (char *)(v22 + 5);
        while ( 1 )
        {
          v8 = (unsigned int)*++v41;
          if ( !*v41 )
            break;
          if ( *v41 < 0 )
          {
            v3 = v9;
            goto LABEL_47;
          }
          if ( (unsigned __int8)(*v41 - 48) > 9u )
          {
            v3 = v9;
            goto LABEL_47;
          }
        }
        v42 = strtol(v22 + 5, 0, 10);
        v30 = strndup(v21, (int)v22 + 5 - (int)v21 - 1);
        v43 = head;
        while ( 2 )
        {
          if ( v43 )
          {
            if ( strcmp((const char *)v43, v30) )
            {
              v43 = *(_QWORD *)(v43 + 64);
              continue;
            }
            if ( v42 >= *(_QWORD *)(v43 + 40) )
            {
              __printf_chk(1, "400 New size must be smaller than existing size (%ld vs %ld)\n", v44, v45);
              goto LABEL_502;
            }
            *(_QWORD *)(v43 + 40) = v42;
            v46 = "200 File resized correctly!";
          }
          else
          {
            v46 = "400 File not found!";
          }
          break;
        }
        puts(v46);
LABEL_502:
        v47 = v30;
        goto LABEL_544;
      default:
        goto LABEL_47;
    }
  }
}