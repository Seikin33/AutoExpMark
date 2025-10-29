根据上述调试会话，以下是内存状态变化的总结：

## 内存状态变化分析

### 1. 程序执行状态
- **当前执行点**：RIP指向`__read_nocancel+7` (0x795bbf52e360)，表明程序正在执行libc的系统调用（read）
- **进程状态**：程序已切换到shell环境（`/bin/dash`），从vmmap信息可见

### 2. Libc Hook区域状态
- **`__realloc_hook`**：地址`0x795bbf7fbb08`，值为`0x0000795bbf4bca70`
  - 指向`realloc_hook_ini`函数，这是libc内部的初始化函数
  - **状态**：未被成功覆盖为one-gadget地址

- **`__malloc_hook`**：地址`0x795bbf7fbb10`，值为`0x0000000000000000`
  - **状态**：未被设置，保持为NULL

### 3. One-gadget状态
- **计算地址**：`0x795bbf47c270` (libc_base + 0x45270)
  - 对应`do_system+1088`函数
  - **状态**：未被成功写入hook区域

### 4. 漏洞利用状态评估
从exp代码分析，攻击链包括：
1. 堆布局和chunk重叠
2. 泄露libc地址  
3. 尝试覆盖`__malloc_hook`和`__realloc_hook`
4. 触发one-gadget执行

**关键发现**：
- Hook覆盖**未完全成功**：`__realloc_hook`指向的是libc内部函数而非one-gadget
- 但程序仍然获得了shell执行权限，说明可能存在：
  - 其他成功的利用路径
  - 或者hook覆盖在某个时刻成功但随后被重置

### 5. 内存访问问题
- `heap`和`bins`命令失败，显示内存访问错误
- 这表明堆管理结构可能已被破坏或进程状态已改变
- 符合程序切换到shell后的状态特征

## 结论
虽然exp的hook覆盖策略没有完全按预期工作（hook未被正确设置为one-gadget），但程序仍然成功获得了shell执行权限，说明漏洞利用在某个环节取得了成功，可能是通过其他控制流劫持方式实现的。