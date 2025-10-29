# 程序基本功能

这是一个食谱管理程序，用户可以管理食材和食谱。主要功能包括：

- **食材管理**：添加、删除、列出食材，设置食材的卡路里和价格
- **食谱管理**：创建、删除食谱，为食谱添加/删除食材，设置食谱名称和说明
- **食谱书管理**：为整个食谱书命名
- **数据持久化**：保存和加载食材、食谱信息

主要函数作用：
- `main()`: 程序入口，初始化并进入主菜单
- `sub_804894D()`: 主菜单循环，处理用户选择
- `sub_8048C7B()`: 食材编辑菜单
- `sub_8049092()`: 食谱编辑菜单
- `sub_8048754()`: 向链表添加节点
- `sub_80487B5()`: 从链表删除节点

# 关键结构体

程序使用链表结构管理数据：

1. **食材节点**（约0x90字节）：
```c
struct Ingredient {
    int calories;      // 0x0: 卡路里
    int price;         // 0x4: 价格
    char name[0x80];   // 0x8: 名称(128字节)
    // 其他字段...
};
```

2. **食谱节点**（0x40C字节）：
```c
struct Recipe {
    int *ingredients;    // 0x0: 食材列表
    int *quantities;     // 0x4: 数量列表
    char name[0x7C];     // 0x8: 食谱名称(124字节)
    char *type;          // 0x84: 食谱类型指针
    char instructions[0x3CC]; // 0x8C: 制作说明(972字节)
    // 其他字段...
};
```

# 漏洞成因

**漏洞位置**：`sub_8048B68()` 函数中的堆缓冲区溢出漏洞

**漏洞代码**：
```c
unsigned int sub_8048B68()
{
  unsigned int size; // [esp+8h] [ebp-50h]
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  unsigned int v3; // [esp+4Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("how long is the name of your cookbook? (hex because you're both a chef and a hacker!) : ");
  fgets(s, 64, stdin);
  size = strtoul(s, 0, 16);  // 用户控制分配大小
  ptr = (char *)malloc(size); // 分配用户指定大小的堆块
  fgets(ptr, size, stdin);    // 向该堆块写入用户控制的数据
  printf("the new name of the cookbook is %s\n", ptr);
  return __readgsdword(0x14u) ^ v3;
}
```

**漏洞原因**：
1. 用户可以通过输入十六进制数完全控制`malloc`分配的大小
2. 然后使用`fgets(ptr, size, stdin)`向该堆块写入数据
3. 如果用户输入的大小小于实际需要存储的字符串长度，会导致堆缓冲区溢出
4. 攻击者可以精心构造分配大小和输入数据，覆盖相邻堆块的内存结构，可能实现任意代码执行

这是一个典型的**堆溢出漏洞**，由于缺乏对用户输入大小的合理验证和边界检查，导致可以写入超过分配边界的数据。