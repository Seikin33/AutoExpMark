import sys
import os
import json
import threading
import traceback
from typing import Any, Dict

# 项目内导入
from LLMTools.RunPwndbgCommand import RunPwndbgCommand
from tmux_gdb_controller import TmuxGdbController


class JsonRpcStdio:
    """
    基于 Content-Length 的 JSON-RPC(兼容 MCP over stdio) 编解码器。
    - 读取 stdin，解析形如：
        Content-Length: <len>\r\n
        \r\n
        {json}
    - 写回同样头的响应。
    """
    def __init__(self):
        self._stdin = sys.stdin.buffer
        self._stdout = sys.stdout.buffer
        self._lock = threading.Lock()

    def _read_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        line_parts: list[bytes] = []
        # 读取到空行(\r\n)为止
        while True:
            line = self._stdin.readline()
            if not line:
                return {}
            if line in (b"\r\n", b"\n"):
                break
            line_parts.append(line)
        for raw in line_parts:
            s = raw.decode("utf-8", errors="ignore").strip()
            if not s:
                continue
            if ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def read(self) -> Dict[str, Any] | None:
        headers = self._read_headers()
        if not headers:
            return None
        length_str = headers.get("content-length")
        if not length_str:
            return None
        try:
            length = int(length_str)
        except ValueError:
            return None
        body = self._stdin.read(length)
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None

    def write(self, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        with self._lock:
            self._stdout.write(f"Content-Length: {len(data)}\r\n\r\n".encode("ascii"))
            self._stdout.write(data)
            self._stdout.flush()


class PwndbgMcpServer:
    """
    一个最小可用的 MCP 工具服务端：
    - methods: initialize, ping, tools/list, tools/call
    - tool: RunPwndbgCommand(command: string)
    """
    def __init__(self, session_name: str | None = None):
        self.rpc = JsonRpcStdio()
        self.tool = RunPwndbgCommand()
        self.session_name = session_name or os.getenv("MCP_GDB_SESSION", "mcp_gdb_session")
        self.gdb = TmuxGdbController(session_name=self.session_name)

    # --- MCP Handlers ---
    def handle_initialize(self, req: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "serverInfo": {"name": "pwndbg-mcp-server", "version": "0.1.0"},
            "capabilities": {
                "tools": {"list": True, "call": True},
            },
        }
        return self._ok(req, result)

    def handle_ping(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._ok(req, {"pong": True})

    def handle_tools_list(self, req: Dict[str, Any]) -> Dict[str, Any]:
        # MCP 工具描述（与 JSON Schema 兼容）
        tools = [
            {
                "name": self.tool.NAME,
                "description": self.tool.DESCRIPTION,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command to run in pwndbg"}
                    },
                    "required": ["command"],
                },
            }
        ]
        return self._ok(req, {"tools": tools})

    def handle_tools_call(self, req: Dict[str, Any]) -> Dict[str, Any]:
        params = req.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name != self.tool.NAME:
            return self._err(req, code=-32602, message=f"Unknown tool: {name}")
        try:
            # 适配现有工具接口
            from LLMTools.Tool import ToolCall

            call = ToolCall(name=name, arguments=arguments, parsed_arguments=arguments)
            result = self.tool.execute(call, self.gdb)
            return self._ok(req, {
                "content": [{
                    "type": "text",
                    "text": json.dumps(result.result, ensure_ascii=False)
                }],
                "is_error": False
            })
        except Exception as e:
            return self._ok(req, {
                "content": [{"type": "text", "text": str(e)}],
                "is_error": True
            })

    # --- JSON-RPC helpers ---
    def _ok(self, req: Dict[str, Any], result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": result}

    def _err(self, req: Dict[str, Any], code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": code, "message": message}}

    def serve_forever(self) -> None:
        while True:
            req = self.rpc.read()
            if req is None:
                break
            try:
                method = req.get("method")
                if method == "initialize":
                    resp = self.handle_initialize(req)
                elif method == "ping":
                    resp = self.handle_ping(req)
                elif method == "tools/list":
                    resp = self.handle_tools_list(req)
                elif method == "tools/call":
                    resp = self.handle_tools_call(req)
                else:
                    resp = self._err(req, -32601, f"Method not found: {method}")
            except Exception:
                tb = traceback.format_exc()
                resp = self._err(req, -32000, f"Internal error\n{tb}")
            self.rpc.write(resp)


def main():
    server = PwndbgMcpServer()
    server.serve_forever()


if __name__ == "__main__":
    main()


