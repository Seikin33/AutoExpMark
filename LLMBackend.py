import json
from dataclasses import dataclass
from openai import OpenAI
from typing import Optional, Any

from LLMConversation import MessageRole
from LLMTools.Tool import ToolCall, ToolResult

@dataclass
class BackendResponse:
    """Holds the backend response"""
    content: Optional[str] = None
    error: Optional[str] = None
    tool_call: Optional[ToolCall] = None
    cost: float = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __str__(self):
        return (f"content='{self.content}'" if self.content else "") + \
                (f"tool_call='{self.tool_call.arguments}'" if self.tool_call else "") + \
                (f"error='{self.error}'" if self.error else "") + \
                (f"cost={self.cost}")

class Backend:
    """Base class for LLM Backend"""
    NAME = "base" # Set the backend name
    # Set the model details for each subclass
    MODELS = {
        # "name": {
        #    "max_context": <int>,
        #    "cost_per_input_token": <float>,
        #    "cost_per_output_token": <float>
        # }
    }

    def __init__(self, model, tools, config):
        if self.NAME == "base" or len(self.MODELS) == 0:
            # This error will only occur if subclass is not defined properly or base class is instantiated
            raise NotImplementedError("Backend name or models not set, initialize the details in the subclass")
        if model not in self.MODELS:
            raise KeyError(f"Model {model} not in configured models for backend {self.NAME}.\n" + \
                            f"Select from: {', '.join(self.MODELS.keys())}")
        self.model = model
        self.tools = tools
        self.config = config
        self.in_price = self.MODELS[model]["cost_per_input_token"]
        self.out_price = self.MODELS[model]["cost_per_output_token"]

    def get_param(self, param: str):
        return getattr(self.config, param)

    def parse_tool_arguments(self, tool_call):
        # Don't need to parse if the arguments are already parsed;
        # this can happen if the tool call was created with parsed arguments
        if tool_call.parsed_arguments:
            return True, tool_call
        try:
            if type(tool_call.arguments) == str:
                tool_call.parsed_arguments = json.loads(tool_call.arguments)
            else:
                tool_call.parsed_arguments = tool_call.arguments
            tool = self.tools[tool_call.name]

            present = set(tool_call.parsed_arguments.keys())
            if missing := (tool.REQUIRED_PARAMETERS - present):
                tool_res = ToolResult.error_for_call(
                                tool_call, f"Missing required parameters for {tool_call.name}: {missing}")
                return False, tool_res
            # Cleanup extra params
            for extra_param in (present - set(tool.PARAMETERS.keys())):
                del tool_call.parsed_arguments[extra_param]
            # Cast the params correctly
            for param in tool.PARAMETERS:
                ty = tool.PARAMETERS[param][0]
                if param in tool_call.parsed_arguments and ty == "number":
                    tool_call.parsed_arguments[param] = float(tool_call.parsed_arguments[param])

            return True, tool_call
        except json.JSONDecodeError as e:
            tool_res = ToolResult.error_for_call(
                            tool_call, f"{type(e).__name__} while decoding parameters for {tool_call.name}: {e}")
            return False, tool_res
        except ValueError as e:
            msg = f"Type error in parameters for {tool_call.name}: {e}"
            tool_res = ToolResult.error_for_call(tool_call, msg)
            return False, tool_res

    # 保持工具模式生成逻辑不变
    @staticmethod
    def get_tool_schema(tool):
        return {
            "type": "function",
            "function": {
                "name": tool.NAME,
                "description": tool.DESCRIPTION,
                "parameters": {
                    "type": "object",
                    "properties": {
                        n: {
                            "type": p[0], 
                            "description": p[1]
                            } for n, p in tool.PARAMETERS.items()
                        },
                    "required": list(tool.REQUIRED_PARAMETERS),
                }
            }
        }

    def send(self, messages):
        # 消息格式转换（与OpenAI兼容）
        formatted_messages = []
        for m in messages:
            if m.role == MessageRole.OBSERVATION:
                # Extract the innermost result to avoid serialization errors with nested ToolResult objects.
                result_to_serialize = m.tool_data.result
                if isinstance(result_to_serialize, ToolResult):
                    result_to_serialize = result_to_serialize.result
                
                formatted_messages.append({
                    "role": "tool",
                    "content": json.dumps(result_to_serialize),
                    "tool_call_id": m.tool_data.id
                })
            elif m.role == MessageRole.ASSISTANT:
                msg: dict[str, Any] = {"role": m.role.value}
                if m.content:
                    msg["content"] = m.content
                if m.tool_data:
                    msg["tool_calls"] = [{
                        "id": m.tool_data.id,
                        "type": "function",
                        "function": {
                            "name": m.tool_data.name,
                            "arguments": m.tool_data.arguments
                        }
                    }]
                formatted_messages.append(msg)
            else:
                formatted_messages.append({
                    "role": m.role.value,
                    "content": m.content
                })

        # 调用DeepSeek API
        api_params = {
            "model": self.model,
            "messages": formatted_messages,
            "temperature": self.get_param("temperature"),
            "max_tokens": self.get_param("max_tokens")
        }
        
        # 只有当有工具时才添加tools参数
        if self.tool_schemas:
            api_params["tools"] = self.tool_schemas
        
        response = self.client.chat.completions.create(**api_params)

        try:
            # 统计用量与成本（OpenAI usage 字段）
            prompt_tokens = 0
            completion_tokens = 0
            total_tokens = 0
            cost = 0
            if response.usage:
                prompt_tokens = getattr(response.usage, "prompt_tokens", 0)
                completion_tokens = getattr(response.usage, "completion_tokens", 0)
                total_tokens = getattr(response.usage, "total_tokens", prompt_tokens + completion_tokens)
                cost = (self.in_price * prompt_tokens + self.out_price * completion_tokens)
            
            # 解析工具调用
            tool_call = None
            if response.choices[0].message.tool_calls:
                oai_call = response.choices[0].message.tool_calls[0]
                tool_call = ToolCall(
                    name=oai_call.function.name,
                    id=oai_call.id,
                    arguments=oai_call.function.arguments
                )
            
            return BackendResponse(
                content=response.choices[0].message.content,
                tool_call=tool_call,
                cost=cost,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens
            )
        
        except Exception as e:
            return BackendResponse(error=f"DeepSeek API Error: {str(e)}") 

class DeepSeekBackend(Backend):
    NAME = 'deepseek'
    MODELS = {
        "deepseek-chat": {  # DeepSeek模型标识
            "max_context": 65536,
            "cost_per_input_token": 2e-06,  # 示例定价
            "cost_per_output_token": 8e-06
        },
        "deepseek-reasoner": {
            "max_context": 65536,
            "cost_per_input_token": 4e-06,
            "cost_per_output_token": 16e-06
        }
    }

    def __init__(self, model, tools, api_key, config):
        super().__init__(model, tools, config)
        # 配置DeepSeek客户端
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com/v1",  # DeepSeek API端点
        )
        self.tool_schemas = [self.get_tool_schema(tool) for tool in tools.values()]

class QwenBackend(Backend):
    NAME = 'qwen'
    MODELS = {
        "qwen-plus-latest": {
            "max_context": 16384,
            "cost_per_input_token": 8e-07,
            "cost_per_output_token": 2e-06
        },
        "qwen-max": {
            "max_context": 16384,
            "cost_per_input_token": 8e-07,
            "cost_per_output_token": 2e-06
        },
        "qwen-long": {
            "max_context": 16384,
            "cost_per_input_token": 8e-07,
            "cost_per_output_token": 2e-06
        },
        "qwen-plus-2025-09-11":{
            "max_context": 16384,
            "cost_per_input_token": 8e-07,
            "cost_per_output_token": 2e-06
        }
    }

    def __init__(self, model, tools, api_key, config):
        super().__init__(model, tools, config)
        # 配置DeepSeek客户端
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # DeepSeek API端点
        )
        self.tool_schemas = [self.get_tool_schema(tool) for tool in tools.values()]