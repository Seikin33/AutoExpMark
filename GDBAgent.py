import os
import json
import time
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from LLMConversation import Conversation, MessageRole
from LLMBackend import DeepSeekBackend, BackendResponse, QwenBackend
from LLMTools.Tool import ToolResult, ToolCall
from LLMLogger import logger
from LLMPromptTemplate import PromptManager
from tmux_gdb_controller import TmuxGdbController, MemoryInfoParser
from LLMTools.RunPwndbgCommand import RunPwndbgCommand
from GDBInfo import GDBInfo, PrimaryInfo, AgentInfo, EXPCode
from datetime import datetime
from getGlobalInfo import GlobalInfo

@dataclass
class ModelConfig:
    """LLM配置"""
    temperature: float = 0.7
    max_tokens: int = 65536

@dataclass
class GDBAgent:
    """GDB单步调试Agent，用于分析某一时刻的内存状态"""
    def __init__(
        self, 
        #primary_info:PrimaryInfo, 
        last_info:str, 
        config:ModelConfig,
        tmux_session:Optional[TmuxGdbController],
        exp_code:Optional[EXPCode] = None,
        #c_code:Optional[str] = None,
        auto_save_path: Optional[str] = None
    ):
        self.last_info = last_info
        self.exp_code = exp_code
        self.tools = {
            "RunPwndbgCommand": RunPwndbgCommand(),
        }
        self.backend = DeepSeekBackend(
            #model="deepseek-chat",
            model="deepseek-reasoner",
            tools=self.tools,
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            config=config,
        )
        self.backend_notool = DeepSeekBackend(
            #model="deepseek-chat",
            model="deepseek-reasoner",
            tools={},
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            config=config,
        )
        
        '''self.backend = QwenBackend(
            model="qwen-plus-latest",
            tools=self.tools,
            api_key=os.getenv("DASHSCOPE_API_KEY"),
            config=config,
        )
        self.backend_notool = QwenBackend(
            model="qwen-plus-latest",
            tools={},
            api_key=os.getenv("DASHSCOPE_API_KEY"),
            config=config,
        )'''
        self.conversation = Conversation(name="OneRoundGDBAgent")
        self.TmuxSession = tmux_session
        
        # 自动保存配置
        self.auto_save_path = auto_save_path
        self.auto_save_enabled = auto_save_path is not None
        # 工具调用参数记录
        self.tool_calls: List[str] = []
        self.tool_calls_save_path: Optional[str] = None
        if self.auto_save_enabled and self.auto_save_path is not None:
            # 确保保存目录存在
            os.makedirs(os.path.dirname(self.auto_save_path), exist_ok=True)
            logger.info(f"自动保存功能已启用，保存路径: {self.auto_save_path}")
            self.tool_calls_save_path = self._compute_tool_calls_save_path(self.auto_save_path)

        self.get_base_memory_info()

    def _auto_save_conversation(self):
        """自动保存对话历史"""
        if not self.auto_save_enabled or self.auto_save_path is None:
            return
            
        try:
            conversation_data = self.conversation.dump()
            with open(self.auto_save_path, 'w', encoding='utf-8') as f:
                json.dump(conversation_data, f, ensure_ascii=False, indent=2)
            logger.debug_message(f"对话历史已自动保存到: {self.auto_save_path}")
            # 同步保存工具调用参数
            self._auto_save_tool_calls()
        except Exception as e:
            logger.error(f"自动保存对话历史失败: {str(e)}")

    def _compute_tool_calls_save_path(self, conversation_path: str) -> str:
        """根据会话保存路径推导工具参数保存路径"""
        if conversation_path.endswith('.json'):
            return conversation_path[:-5] + '_toolparams.txt'
        return conversation_path + '.toolparams'

    def _auto_save_tool_calls(self) -> None:
        """自动保存本次会话内已记录的工具调用参数（逗号分隔）"""
        if not self.auto_save_enabled or self.tool_calls_save_path is None:
            return
        try:
            with open(self.tool_calls_save_path, 'w', encoding='utf-8') as f:
                f.write(",".join(self.tool_calls))
            logger.debug_message(f"工具调用参数已自动保存到: {self.tool_calls_save_path}")
        except Exception as e:
            logger.error(f"自动保存工具调用参数失败: {str(e)}")

    def save_conversation(self, file_path: str):
        """保存对话历史到JSON文件
        
        Args:
            file_path (str): 保存对话历史的文件路径
        """
        try:
            conversation_data = self.conversation.dump()
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(conversation_data, f, ensure_ascii=False, indent=2)
            logger.print(f"对话历史已保存到: {file_path}")
            # 同步保存工具参数
            tool_params_path = self._compute_tool_calls_save_path(file_path)
            with open(tool_params_path, 'w', encoding='utf-8') as f:
                f.write(",".join(self.tool_calls))
            logger.debug_message(f"工具调用参数已保存到: {tool_params_path}")
        except Exception as e:
            logger.print(f"保存对话历史失败: {str(e)}")
    
    def initialize_conversation(self):
        """初始化对话"""
        # 添加系统提示
        SystemPrompt = self.prompt_manager.get(
            'system_prompt', 
            tools_description=self.prompt_manager.get('tools_description'),
            Pwndbg_Commands=self.prompt_manager.get('Pwndbg_Commands')
        )
        self.conversation.append_system(SystemPrompt)
        #logger.system_message(SystemPrompt)
        self._auto_save_conversation()  # 自动保存

        # 添加用户提示
        UserPrompt = self.prompt_manager.get('user_prompt_get_plan')
        self.conversation.append_user(UserPrompt)
        #logger.user_message(UserPrompt)
        self._auto_save_conversation()  # 自动保存

        # 生成调试计划
        response = self.backend_notool.send(list(self.conversation.messages))

        while response.content == '':
            logger.error("Error: 生成调试计划失败，重新生成中")
            response = self.backend_notool.send(list(self.conversation.messages))
            
        self.response_parse(response)

        # 添加用户提示
        UserPrompt = self.prompt_manager.get('user_prompt_start_plan')
        self.conversation.append_user(UserPrompt)
        #logger.user_message(UserPrompt)
        self._auto_save_conversation()  # 自动保存
    
    def response_parse(self, response:BackendResponse)->bool:
        """
        使用 if/elif/else 和属性的真值进行判断
        返回的值用于确定要不要继续工具调用
        """
        if response.tool_call and response.content:
            logger.print("tool_call 和 content 都存在")
            self.conversation.append_assistant(response.content, response.tool_call)
            logger.assistant_thought(response.content)
            success, parsed_tool_call = self.backend.parse_tool_arguments(response.tool_call)
            if success:
                tool = self.tools[parsed_tool_call.name]
                # 记录工具调用参数（仅参数摘要）
                try:
                    summary = parsed_tool_call.param_summary() if hasattr(parsed_tool_call, 'param_summary') else None
                    if not summary:
                        # 兼容：从具体工具获取摘要
                        if hasattr(tool, 'param_summary'):
                            summary = tool.param_summary(parsed_tool_call)
                    if not summary:
                        # 兜底
                        summary = str(parsed_tool_call.arguments) if parsed_tool_call.arguments else ""
                    if summary:
                        self.tool_calls.append(summary)
                    self._auto_save_tool_calls()
                except Exception as _:
                    pass
                raw_result = tool.execute(parsed_tool_call, self.TmuxSession)
                self.conversation.append_observation(raw_result)
                logger.observation_message(str(raw_result.result))
                self._auto_save_conversation()  # 自动保存

                # 专用于本项目，其他项目请删除这行代码
                if "continue" in parsed_tool_call.arguments:
                    return False
                return True
            else:
                logger.error(f"Failed to parse tool arguments: {response.tool_call}")
                # 如果工具参数解析失败，添加一个空的assistant消息来避免消息序列问题
                self.conversation.append_assistant("工具参数解析失败", None)
                self._auto_save_conversation()
                return True

        elif response.tool_call:
            logger.print("\n只有 tool_call 存在，将伪造一个空assistant信息。")
            self.conversation.append_assistant("Auto-continue", response.tool_call, response.reasoning_content)
            logger.assistant_thought(response.reasoning_content)
            success, parsed_tool_call = self.backend.parse_tool_arguments(response.tool_call)
            if success:
                tool = self.tools[parsed_tool_call.name]
                # 记录工具调用参数（仅参数摘要）
                try:
                    summary = parsed_tool_call.param_summary() if hasattr(parsed_tool_call, 'param_summary') else None
                    if not summary and hasattr(tool, 'param_summary'):
                        summary = tool.param_summary(parsed_tool_call)
                    if not summary:
                        summary = str(parsed_tool_call.arguments) if parsed_tool_call.arguments else ""
                    if summary:
                        self.tool_calls.append(summary)
                    self._auto_save_tool_calls()
                except Exception as _:
                    pass
                raw_result = tool.execute(parsed_tool_call, self.TmuxSession)
                self.conversation.append_observation(raw_result)
                logger.observation_message(str(raw_result.result))
                self._auto_save_conversation()  # 自动保存

                if "continue" in parsed_tool_call.arguments:
                    return False

                return True
            else:
                logger.error(f"Failed to parse tool arguments: {response.tool_call}")
                # 如果工具参数解析失败，添加一个空的assistant消息来避免消息序列问题
                self.conversation.append_assistant("工具参数解析失败", None)
                self._auto_save_conversation()
                return True

        elif response.content:
            logger.print("只有 content 存在")
            self.conversation.append_assistant(response.content, None)
            #logger.assistant_thought(response.content)
            self._auto_save_conversation()  # 自动保存
            return False

        else:
            logger.print("tool_call 和 content 都不存在")
            return False
    
    def one_round_conversation(self, max_calls: int = 20):
        '''
        max_calls: 最大工具调用次数
        '''
        response = self.backend.send(list(self.conversation.messages))
        count = 0
        while self.response_parse(response):
            response = self.backend.send(list(self.conversation.messages))
            count += 1
            if count >= max_calls:
                logger.print(f"最大工具调用次数{max_calls}已达到，停止工具调用")
                self.TmuxSession.send_command_to_pane(self.TmuxSession.gdb_pane, "continue")
                break

        UserPrompt = self.prompt_manager.get('user_prompt_summary_memory_change')
        self.conversation.append_user(UserPrompt)
        #logger.user_message(UserPrompt)
        self.conversation.delete_all_reasoning_content()

        response = self.backend_notool.send(list(self.conversation.messages))
        self.response_parse(response)

    def load_history_conversation(self, file_path: str):
        """从JSON文件加载历史对话
        
        Args:
            file_path (str): 历史对话文件的路径
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                conversation_data = json.load(f)
            
            # 创建新的对话实例
            self.conversation = Conversation(name="gdb_agent")
            
            # 加载每条消息
            for msg_data in conversation_data:
                # 由于json文件中role是字符串，需要转换为MessageRole枚举类型
                match msg_data["role"]:
                    case "MessageRole.SYSTEM":
                        role = MessageRole.SYSTEM
                    case "MessageRole.USER":
                        role = MessageRole.USER
                    case "MessageRole.ASSISTANT":
                        role = MessageRole.ASSISTANT
                    case "MessageRole.OBSERVATION":
                        role = MessageRole.OBSERVATION
                    case _:
                        raise ValueError(f"Unknown message role: {msg_data['role']}")

                content = msg_data["content"]
                tool_data = None
                
                # 处理工具调用数据
                if role == MessageRole.ASSISTANT and "tool_call" in msg_data:
                    tool_call = msg_data["tool_call"]
                    tool_data = ToolCall(
                        name=tool_call["name"],
                        id=None,  # 历史数据中可能没有id
                        arguments=str(tool_call['parsed_args']),
                        parsed_arguments=tool_call['parsed_args']
                    )
                    #tool_data = tool_call
                elif role == MessageRole.OBSERVATION and "tool_result" in msg_data:
                    tool_result = msg_data["tool_result"]
                    tool_data = ToolResult(
                        name=tool_result["name"],
                        id="",  # 历史数据中可能没有id，使用空字符串
                        result=tool_result["result"]
                    )
                
                self.conversation.append(role, content, tool_data)
            
            logger.print(f"已从 {file_path} 加载历史对话")
        except Exception as e:
            logger.print(f"加载历史对话失败: {str(e)}")
            raise

    def get_base_memory_info(self) -> None:
        """
        获取gdb窗格的初始内存信息，并设置prompt_manager。
        """
        finished_exploit_code = "\n".join(self.exp_code.ExploitCode[:self.exp_code.FinishedEXPCodeIdx])
        time.sleep(3) # 等待pwndbg加载完成
        self.TmuxSession.send_key_combination_to_pane(self.TmuxSession.gdb_pane, ['C-c'])
        self.TmuxSession.send_key_combination_to_pane(self.TmuxSession.gdb_pane, ['C-l'])
        self.TmuxSession.send_command_to_pane(self.TmuxSession.gdb_pane, "heap")
        heap_info = self.TmuxSession.read_pane_output(self.TmuxSession.gdb_pane)
        self.TmuxSession.send_command_to_pane(self.TmuxSession.gdb_pane, "vmmap")
        vmmap_info = self.TmuxSession.read_pane_output(self.TmuxSession.gdb_pane)
        self.TmuxSession.send_command_to_pane(self.TmuxSession.gdb_pane, "bins")
        bins_info = self.TmuxSession.read_pane_output(self.TmuxSession.gdb_pane)
        self.TmuxSession.send_command_to_pane(self.TmuxSession.gdb_pane, "checksec")
        checksec_info = self.TmuxSession.read_pane_output(self.TmuxSession.gdb_pane)
        global_info = GlobalInfo(
            ChecksecStr=checksec_info,
            vmmapStr=vmmap_info,
            HeapStr=heap_info,
            BinsStr=bins_info
        )
        primary_info = PrimaryInfo(
            Decompilation=self.exp_code.DecompileCode,
            DynamicMemory=global_info.__str__()
        )

        self.prompt_manager = PromptManager(
            promptyaml="./LLMPrompts/AutuGDBPrompt.yaml",
            PrimaryInfo=primary_info,
            LastInfo=self.last_info,
            exp_code=self.exp_code,
            finished_exploit_code=finished_exploit_code
        )

    def get_last_info(self):
        # 查找最后一个Assistant角色的对话记录
        for message in reversed(list(self.conversation.messages)):
            if message.role == MessageRole.ASSISTANT:
                return message.content
        # 如果没有找到Assistant消息，返回空字符串
        return ""

    def get_first_info(self):
        # 查找第一个Assistant角色的对话记录
        for message in list(self.conversation.messages):
            if message.role == MessageRole.ASSISTANT:
                return message.content
        # 如果没有找到Assistant消息，返回空字符串
        return ""

    def enable_auto_save(self, file_path: str):
        """启用自动保存功能
        
        Args:
            file_path (str): 自动保存的文件路径
        """
        self.auto_save_path = file_path
        self.auto_save_enabled = True
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        logger.info(f"自动保存功能已启用，保存路径: {file_path}")
        # 同步配置工具参数保存路径并立即保存一次
        self.tool_calls_save_path = self._compute_tool_calls_save_path(file_path)
        self._auto_save_tool_calls()

    def disable_auto_save(self):
        """禁用自动保存功能"""
        self.auto_save_enabled = False
        self.auto_save_path = None
        self.tool_calls_save_path = None
        logger.info("自动保存功能已禁用")
