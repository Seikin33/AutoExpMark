# 暂时不使用
import os
from typing import Any, Dict, List, Optional

from LLMBackend import DeepSeekBackend, BackendResponse
from LLMTools.Tool import ToolCall, ToolResult
from MCP.mcp_client import McpProcessClient


class DeepSeekMCPBackend(DeepSeekBackend):
    """
    使用 DeepSeek 作为 LLM，使用 MCP 进程提供工具：
    - 启动 MCP 工具进程(默认: python -u MCP/mcp_server_pwndbg.py)
    - 从 MCP 获取工具 schemas，并作为 OpenAI function tools 提供给 DeepSeek
    - 需要时可通过 execute_tool_call 调用 MCP 工具
    """
    def __init__(
        self,
        model: str,
        mcp_command: Optional[List[str]] = None,
        api_key: Optional[str] = None,
        config: Any = None,
    ):
        # 初始化 DeepSeek(不使用本地 tools 字典)
        super().__init__(model=model, tools={}, api_key=api_key or os.getenv("DEEPSEEK_API_KEY"), config=config)

        # 启动 MCP 进程客户端
        cmd = mcp_command or ["python", "-u", "MCP/mcp_server_pwndbg.py"]
        self.mcp = McpProcessClient(cmd)
        self.mcp.initialize()
        self._mcp_tools = self.mcp.tools_list()
        # 将 MCP 的 JSON Schema 直接作为 OpenAI tools 的 parameters
        self.tool_schemas = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                },
            }
            for t in self._mcp_tools
        ]

    def execute_tool_call(self, tool_call: ToolCall) -> ToolResult:
        """
        通过 MCP 调用对应工具，并返回 ToolResult。
        """
        name = tool_call.name
        args = tool_call.parsed_arguments or {}
        result = self.mcp.tools_call(name, args)
        # MCP 约定: result = { content: [{type: "text", text: "..."}], is_error: bool }
        payload: Dict[str, Any] = {
            "mcp": result,
        }
        if isinstance(result, dict) and "content" in result:
            try:
                # 尝试从 text 解包为 JSON
                from json import loads
                texts = [c.get("text", "") for c in result.get("content", [])]
                joined = "\n".join(texts)
                payload["parsed_json"] = loads(joined)
            except Exception:
                pass
        return ToolResult(name=name, id=tool_call.id, result=payload)


