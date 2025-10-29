# 程序基本功能

这是一个模拟Apple Store购物系统的程序，主要功能包括：

1. **menu()** - 显示主菜单选项
2. **list()** - 显示可购买的设备列表和价格
3. **add()** - 将选择的设备添加到购物车
4. **delete()** - 从购物车中移除设备
5. **cart()** - 查看购物车内容和总价
6. **checkout()** - 结账功能，计算总价
7. **handler()** - 处理用户输入的主循环

程序使用双向链表来管理购物车中的商品。

# 关键结构体

从代码中可以推断出购物车项的结构体：

```c
struct cart_item {
    char *name;        // 0x0: 商品名称
    int price;         // 0x4: 价格
    struct cart_item *next;  // 0x8: 下一个节点
    struct cart_item *prev;  // 0xC: 前一个节点
};
```

全局变量`myCart`和`dword_804B070`似乎都是指向购物车链表的指针。

# 漏洞成因

**漏洞位置：`checkout()`函数**

```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2[5]; // [esp+18h] [ebp-20h] BYREF
  unsigned int v3; // [esp+2Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(v2, "%s", "iPhone 8");  // 问题在这里
    v2[1] = (char *)1;
    insert((int)v2);
    v1 = 7175;
  }
  // ...
}
```

**漏洞原因：**

1. **栈缓冲区使用后传递给堆函数**：`v2`是栈上的局部数组（`char *v2[5]`），但在满足条件`v1 == 7174`时，程序调用`asprintf(v2, "%s", "iPhone 8")`，这会将新分配的堆地址写入`v2[0]`。

2. **悬垂指针问题**：随后程序调用`insert((int)v2)`将栈地址`v2`插入到全局购物车链表中。当`checkout()`函数返回时，栈帧被释放，但链表仍然保存着指向已释放栈内存的指针。

3. **Use-After-Free**：后续对购物车的操作（如`cart()`、`delete()`）会遍历这个链表，访问已经失效的栈内存，导致未定义行为。攻击者可能通过精心构造输入来利用这个条件，实现代码执行。

这是一个典型的**栈地址泄露到全局结构**导致的Use-After-Free漏洞。程序将局部变量的地址保存到全局链表中，当函数返回后，这些地址指向的内存可能被后续函数调用覆盖，但链表仍然引用这些已失效的地址。