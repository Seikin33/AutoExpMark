from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional
class MessageRole(str, Enum):
    SYSTEM = "system"       # 系统级指令
    USER = "user"           # 用户输入
    ASSISTANT = "assistant" # AI响应
    OBSERVATION = "observation" # 工具执行结果


@dataclass(frozen=True)
class Message:
    """Holds message contents"""
    index: int
    role: MessageRole
    content: str
    tool_data: Optional[dict] = None
    reasoning_content: Optional[str] = None #仅限含工具调用的assistant消息才会保存，正常情况下的思维链是不保存的

    def dump(self):
        """
        Dump message to serialize to json.
        """
        d = {"role": str(self.role), "index": self.index, "content": self.content}
        if self.role == MessageRole.ASSISTANT and self.tool_data is not None:
            if self.tool_data.parsed_arguments is not None:
                d["tool_call"] = {"name": self.tool_data.name, "parsed_args": self.tool_data.parsed_arguments}
            else:
                d["tool_call"] = {"name": self.tool_data.name, "args": self.tool_data.arguments}
            d["reasoning_content"] = self.reasoning_content

            # 注意：reasoning_content 只在有工具调用的情况下才会保存，正常情况下的思维链是不保存的
            # 原因详见傻逼的deepseek-v3.2思考模式下的工具调用
            # 修改时间：2025.12.18
            # 参考文档：https://api-docs.deepseek.com/zh-cn/guides/thinking_mode#%E5%B7%A5%E5%85%B7%E8%B0%83%E7%94%A8
            
        elif self.role == MessageRole.OBSERVATION and self.tool_data is not None:
            d["tool_result"] = {"name": self.tool_data.name, "result": self.tool_data.result}
        return d

class Conversation:
    """Holds the messages of the entire conversation"""

    def __init__(self, name="", truncate_content=25000, len_observations=None):
        """
        truncate_content: truncate the OBSERVATION content length to these many characters.
        len_observations (int):
            Return last `len_observations` observations and truncate the rest in get_messages.
            None (default) means return all. This helps truncate the conversation to last few steps.
        """
        self.all_messages:list[Message] = []        
        self.round = 0
        self.name = name
        self.truncate_content = truncate_content
        self.len_observations = len_observations

    @property
    def messages(self):
        """
        Generator of messages of this conversation to send to the LLM for completion
        """
        
        trunc_before = -1
        if self.len_observations is not None:
            trunc_before = self.round - self.len_observations
        for m in self.all_messages:
            if m.role == MessageRole.OBSERVATION and m.index <= trunc_before:
                # Truncate observations
                continue
            elif m.role == MessageRole.ASSISTANT and m.index <= trunc_before:
                if m.content is not None:
                    # Remove tool calls from assistant actions and yield only thought
                    yield replace(m, tool_data=None)
                else:
                    # Without tool_call, message is empty so skip
                    continue
            else:
                yield m

    def dump(self):
        """
        Dump all messages to serialize to json.
        """
        return [m.dump() for m in self.all_messages]

    def delete_all_reasoning_content(self):
        self.all_messages = [
            replace(m, reasoning_content=None) if m.reasoning_content is not None else m
            for m in self.all_messages
        ]

    def next_round(self):
        self.round += 1
    def append(self, role, content, tool_data=None, reasoning_content=None):
        m = Message(index=self.round, role=role, content=content, tool_data=tool_data, reasoning_content=reasoning_content)
        self.all_messages.append(m)
    def append_system(self, content):
        self.append(MessageRole.SYSTEM, content)
    def append_user(self, content):
        self.append(MessageRole.USER, content)
    def append_assistant(self, content, tool_data, reasoning_content=None):
        self.append(MessageRole.ASSISTANT, content, tool_data, reasoning_content)
    def append_observation(self, tool_data):
        # Truncate length
        truncate_message = " ...very long output, trunctated!"
        if type(tool_data.result) == str and len(tool_data.result) > self.truncate_content:
            tool_data.result = tool_data.result[:self.truncate_content - len(truncate_message)] + truncate_message
        elif type(tool_data.result) == dict:
            for key in tool_data.result.keys():
                if type(tool_data.result[key]) == str and len(tool_data.result[key]) > self.truncate_content:
                    tool_data.result[key] = tool_data.result[key][:self.truncate_content - len(truncate_message)] + truncate_message

        self.append(MessageRole.OBSERVATION, None, tool_data)
