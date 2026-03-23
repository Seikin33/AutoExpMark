import json
import subprocess
import threading
from typing import Any, Dict, List, Optional


class McpProcessClient:
    """
    一个最小 JSON-RPC(兼容 MCP) 客户端，通过启动子进程并使用 stdio 通信。
    """
    def __init__(self, command: List[str]):
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            bufsize=0,
        )
        assert self._proc.stdin and self._proc.stdout
        self._stdin = self._proc.stdin
        self._stdout = self._proc.stdout
        self._write_lock = threading.Lock()
        self._next_id = 1

    def _read_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        line_parts: list[bytes] = []
        while True:
            line = self._stdout.readline()
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

    def _read(self) -> Dict[str, Any] | None:
        headers = self._read_headers()
        if not headers:
            return None
        length_str = headers.get("content-length")
        if not length_str:
            return None
        length = int(length_str)
        body = self._stdout.read(length)
        if not body:
            return None
        return json.loads(body.decode("utf-8"))

    def _write(self, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        with self._write_lock:
            self._stdin.write(f"Content-Length: {len(data)}\r\n\r\n".encode("ascii"))
            self._stdin.write(data)
            self._stdin.flush()

    def _next_request_id(self) -> int:
        rid = self._next_id
        self._next_id += 1
        return rid

    # ---- MCP API ----
    def initialize(self) -> Dict[str, Any]:
        rid = self._next_request_id()
        self._write({"jsonrpc": "2.0", "id": rid, "method": "initialize", "params": {}})
        resp = self._read()
        return resp["result"] if resp and "result" in resp else {}

    def tools_list(self) -> List[Dict[str, Any]]:
        rid = self._next_request_id()
        self._write({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
        resp = self._read()
        if resp and "result" in resp:
            return resp["result"].get("tools", [])
        return []

    def tools_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        rid = self._next_request_id()
        self._write({
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        resp = self._read() or {}
        return resp.get("result", {})

    def close(self) -> None:
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
        except Exception:
            pass


