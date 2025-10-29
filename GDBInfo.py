from __future__ import annotations
from dataclasses import dataclass
import os

@dataclass
class PrimaryInfo:
    Decompilation: str
    DynamicMemory: str
    def __str__(self):
        return f"PrimaryInfo(Decompilation:\n{self.Decompilation}\nDynamicMemory:\n{self.DynamicMemory})"

@dataclass
class AgentInfo:
    AgentExplorationInfo: str
    def __str__(self):
        return f"AgentInfo(AgentExplorationInfo:\n{self.AgentExplorationInfo})"

@dataclass
class GDBInfo:
    '''
    结构化表示GDBInfo
    1. LastInfo: 上一次的GDBInfo的摘要
    2. PrimaryInfo: 前置信息，包括反编译代码和初步的动态分析
    3. AgentInfo: Agent进行的动态分析，包括其他pwndbg的命令和结果
    '''
    LastInfo: str
    PrimaryInfo: PrimaryInfo
    AgentInfo: AgentInfo

    def __str__(self):
        return f"GDBInfo(LastInfo:\n{self.LastInfo}\nPrimaryInfo:\n{self.PrimaryInfo}\nAgentInfo:\n{self.AgentInfo})"

class EXPCode:
    '''
    输入:
        1. ExpCodePath: 原始的exp代码的路径
        2. DecompileCodePath: 反编译代码的路径
        3. InitializeCode: 初始化代码，例如：from pwn import *
        4. DIYFunctions: 自定义函数，例如：def alloc(size:int):
        5. ExploitCode: 利用代码，例如：alloc(0x80)
    类属性:
        1. NaiveExploitCode: 原始的exp代码，例如：alloc(0x80)
        2. DecompileCode: 反编译代码，例如：int main() {
        3. ExpCodePath: 原始的exp代码的路径
        4. InitializeCode: 初始化代码，例如：from pwn import *
        5. DIYFunctions: 自定义函数，例如：def alloc(size:int):
        6. ExploitCode: 利用代码，例如：alloc(0x80)
        7. FinishedEXPCodeIdx: 已经执行的ExploitCode的索引，例如：0
    '''

    def __init__(self, ExpCodePath: str, DecompileCodePath: str, InitializeCode: list[str], DIYFunctions: list[list[str]], ExploitCode: list[str]):
        with open(ExpCodePath, "r") as f:
            self.NaiveExploitCode = f.read()
        with open(DecompileCodePath, "r") as f:
            self.DecompileCode = f.read()
        self.ExpCodePath = ExpCodePath
        self.InitializeCode = InitializeCode
        self.DIYFunctions = DIYFunctions
        self.ExploitCode = ExploitCode
        self.FinishedEXPCodeIdx = 1

    def __str__(self):
        return os.path.basename(self.ExpCodePath)