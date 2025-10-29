from LLMTools.Tool import Tool, ToolCall, ToolResult
from LLMLogger import logger
from tmux_gdb_controller import TmuxGdbController, MemoryInfoParser

class RunPwndbgCommand(Tool):
    NAME = "RunPwndbgCommand"
    DESCRIPTION = "Run a command in pwndbg"
    PARAMETERS = {
        "command": ("string", "The command to run in pwndbg")
    }
    REQUIRED_PARAMETERS = {"command"}
    
    def execute(self, tool_call: ToolCall, gdbsession:TmuxGdbController) -> ToolResult:
        """
        执行pwndbg命令，并返回结果
        参数：
            tool_call: LLM返回的工具调用
            gdbsession: 当前对话正在使用的TmuxGdbController
            lastgdbinfo: 上一次执行pwndbg命令后的gdb窗格截图
        返回：
            ToolResult: 包含工具调用ID、工具名称、工具结果
        """
        args = tool_call.parsed_arguments
        command = args["command"]
        try:
            gdbsession.send_command_to_pane(gdbsession.gdb_pane, command)
            rawresult = gdbsession.read_pane_output(gdbsession.gdb_pane)
            result = MemoryInfoParser(rawresult)
            logger.info(f"RunPwndbgCommand执行成功，处理后的信息为：\n{result.info}\n")
            return ToolResult(
                name=self.NAME,
                id=tool_call.id,
                result={"gdb_output": result.info},
            )
        except Exception as e:
            return ToolResult(
                name=self.NAME,
                id=tool_call.id,
                result={"error": str(e)},
            )

    @staticmethod
    def param_summary(tool_call: ToolCall) -> str:
        """返回该工具的关键参数摘要（即command）"""
        try:
            if tool_call.parsed_arguments and "command" in tool_call.parsed_arguments:
                return str(tool_call.parsed_arguments["command"])
        except Exception:
            pass
        return ""