import subprocess
import time
from typing import Union, List, Optional
import re
        
class TmuxGdbController:
    """
    一个用于自动化控制 tmux 和 GDB 调试流程的控制器。
    - 创建一个指定大小的 tmux 会话。
    - 运行脚本并自动发现 gdb.attach() 创建的新窗格。
    - 提供与特定窗格交互（发送命令、读取输出）的方法。
    """
    def __init__(self, session_name: str = "gdb_automation_session", width: int = 160, height: int = 48):
        """
        初始化控制器。
        - session_name: 要创建的 tmux 会话名称。
        - width: 会话的初始宽度（列数）。
        - height: 会话的初始高度（行数）。
        - GdbBuffer: 用于存储GDB窗格的输出，使用CircularBuffer类。
        """
        self.session_name = session_name
        # 确保环境干净，关闭可能存在的同名会话
        subprocess.run(["tmux", "kill-session", "-t", self.session_name], stderr=subprocess.DEVNULL)
        
        # 创建新的后台 tmux 会话，并使用 -x 和 -y 设置初始窗口大小
        print(f"创建新的 tmux 会话 '{self.session_name}'，大小为 {width}x{height}...")
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", self.session_name, "-x", str(width), "-y", str(height)],
            check=True
        )
        time.sleep(0.5)
        
        # 获取初始窗格ID
        self.panes = self.list_panes()
        self.gdb_pane: Optional[str] = None
        self.python_pane: Optional[str] = None
        print(f"会话已创建，初始窗格: {self.panes}")

    def list_panes(self) -> list[str]:
        """列出当前会话中的所有窗格ID。"""
        result = subprocess.run(
            ["tmux", "list-panes", "-s", "-t", self.session_name, "-F", "#{pane_id}"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip().split('\n')

    def send_command_to_pane(self, pane_id: str, command: str):
        """向指定的窗格发送命令。"""
        print(f"向窗格 {pane_id} 发送命令: {command}")
        subprocess.run(["tmux", "send-keys", "-t", pane_id, command, "C-m"], check=True)

    def send_key_combination_to_pane(self, pane_id: str, keys: list[str]):
        """
        向指定的窗格发送一个组合键序列。
        常见组合:
            1. ['C-b', 'S-P'] 会模拟按下 Ctrl-B 然后 Shift-P.
            2. ['C-l'] 会模拟按下 Ctrl-L然后清屏.
            3. ['C-m'] 会模拟按下 Ctrl-M然后回车.
        """
        print(f"向窗格 {pane_id} 发送组合键: {' '.join(keys)}")
        # 注意：这里我们不自动添加回车(C-m)，因为这些是控制键，不是文本命令。
        subprocess.run(["tmux", "send-keys", "-t", pane_id] + keys, check=True)

    def send_python_multi_line(self, pane_id: str,  func_content: List[str]):
        """
        向指定的窗格发送多行python代码，包括函数定义等其他需要多行输入的代码
        """
        for line in func_content:
            self.send_command_to_pane(pane_id, line)
        self.send_key_combination_to_pane(pane_id, ['C-m'])
        self.send_key_combination_to_pane(pane_id, ['C-m'])

    def read_pane_output(self, pane_id: str, clear_history: bool = True) -> str:
        """更新GdbBuffer，并读取指定窗格的新输出。"""
        print(f"读取窗格 {pane_id} 的输出...")
        time.sleep(1) # 等待命令执行和输出刷新
        
        result = subprocess.run(
            ["tmux", "capture-pane", "-p", "-t", pane_id],
            capture_output=True, text=True, check=True, errors='ignore'
        )

        # 每次读取之后，清除历史记录
        if clear_history:
            self.send_key_combination_to_pane(pane_id, ['C-L'])

        output = result.stdout
        # 压缩超过3个的连续换行符为3个
        output = re.sub(r'\n{4,}', '\n\n\n', output)
        return output

    def find_new_pane(self, existing_panes: list[str], timeout: int = 120) -> Union[str, None]:
        """轮询查找与现有窗格列表不同的新窗格。"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            current_panes = self.list_panes()
            new_panes = [p for p in current_panes if p not in existing_panes]
            if new_panes:
                print(f"发现新窗格: {new_panes[0]}")
                self.panes = current_panes
                return new_panes[0]
            time.sleep(0.5)
        print("超时：未找到新窗格。")
        return None
        
    def close(self):
        """关闭会话。"""
        print(f"正在关闭 tmux 会话: {self.session_name}")
        subprocess.run(["tmux", "kill-session", "-t", self.session_name], stderr=subprocess.DEVNULL)

    def __del__(self):
        self.close()

class MemoryInfoParser:
    def __init__(self, raw_memory_info: str):
        self.raw_memory_info = raw_memory_info
        self.info = self.parse_memory_info()
    
    def parse_memory_info(self) -> dict[str, str]:
        """解析来自GDB窗格的原始输出，提取由'pwndbg>'开头的每个命令及其输出。"""
        memory_info = {}
        # The (?m) flag enables multiline mode, so `^` matches the start of each line.
        # This splits the raw text into chunks, where each chunk begins with a command
        # that was executed at the pwndbg prompt.
        chunks = re.split(r'(?m)^pwndbg> ', self.raw_memory_info)

        for chunk in chunks:
            # Skip any empty chunks that might result from the split (e.g., the part before the first prompt).
            if not chunk.strip():
                continue

            lines = chunk.splitlines()
            # The first line of the chunk is the command itself.
            command = lines[0].strip()
            # The rest of the lines are the output of that command.
            output = "\n".join(lines[1:])
            
            # Store the output with the command as the key.
            # If a command is run multiple times, this will overwrite previous results for that same command,
            # which is usually the desired behavior (we want the latest state).
            if command:
                memory_info[command] = output.strip()
        
        return memory_info