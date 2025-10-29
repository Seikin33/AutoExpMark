from tmux_gdb_controller import TmuxGdbController
from GDBInfo import EXPCode, PrimaryInfo
from LLMLogger import logger
from GDBAgent import GDBAgent, ModelConfig
from data.structuredEXP import *
import os
import time
from SummarizeLLM import SummarizeLLM
import concurrent.futures
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn
import threading
from typing import List
# Add a lock for thread-safe logging
log_lock = threading.Lock()

def InitTerminal(TmuxSession:TmuxGdbController, exp_code:EXPCode):
    try:
        TmuxSession.python_pane = TmuxSession.panes[0]
        TmuxSession.send_command_to_pane(TmuxSession.python_pane, "python")
        with log_lock:
            logger.info(f"[{exp_code.ExpName}] 初始化python终端")
        for commandline in exp_code.InitializeCode:
            TmuxSession.send_command_to_pane(TmuxSession.python_pane, commandline)
        with log_lock:
            logger.info(f"[{exp_code.ExpName}] exp初始加载完成")
        for func in exp_code.DIYFunctions:
            TmuxSession.send_python_multi_line(TmuxSession.python_pane, func)
        with log_lock:
            logger.info(f"[{exp_code.ExpName}] exp自定义函数加载完成")

        TmuxSession.send_command_to_pane(TmuxSession.python_pane, "gdb.attach(p)")
        gdb_pane = TmuxSession.find_new_pane(existing_panes=[TmuxSession.python_pane])
        if not gdb_pane:
            with log_lock:
                logger.error(f"[{exp_code.ExpName}] 找不到新的gdb窗格")
            return False
        TmuxSession.send_command_to_pane(gdb_pane, "continue")
        TmuxSession.gdb_pane = gdb_pane

        with log_lock:
            logger.info(f"[{exp_code.ExpName}] gdb终端加载完成")
        return True
    except Exception as e:
        with log_lock:
            logger.error(f"[{exp_code.ExpName}] InitTerminal失败: {e}")
        return False

def AnalyseEXP(exp:EXPCode, progress: Progress, task_id):
    DynamicMemoryInfoList:list[str] = ['None']
    exp_name = os.path.basename(exp.ExpCodePath).rsplit('.', 1)[0].replace('-', '_')
    exp.ExpName = exp_name # Store exp_name in the object for easy access
    session_name = f"debug_automation_{exp_name}"
    TmuxSession = TmuxGdbController(session_name=session_name, width=500, height=200)
    
    try:
        if not InitTerminal(TmuxSession, exp):
            raise Exception("InitTerminal failed")
        
        auto_save_dir = "conversation_logs"
        os.makedirs(auto_save_dir, exist_ok=True)
        
        total_steps = len(exp.ExploitCode)
        progress.update(task_id, total=total_steps)
        progress.start_task(task_id)

        for i, exp_code in enumerate(exp.ExploitCode):
            TmuxSession.send_command_to_pane(TmuxSession.python_pane, exp_code)
            print(TmuxSession.read_pane_output(TmuxSession.python_pane))
            ctx = TmuxSession.read_pane_output(TmuxSession.gdb_pane)
            
            
            timestamp = int(time.time())
            auto_save_path = os.path.join(auto_save_dir, f"conversation_{exp_name}_step_{exp.FinishedEXPCodeIdx}_{timestamp}.json")
            
            k0lastinfo = 'None'
            
            gdbagent = GDBAgent(
                #primary_info=primary_info,
                last_info=k0lastinfo,
                config=ModelConfig(
                    temperature=0.7,
                    max_tokens=8192
                ),
                tmux_session=TmuxSession,
                exp_code=exp,
                auto_save_path=auto_save_path
            )

            gdbagent.initialize_conversation()
            # 保存调试计划
            step_log_dir = f"./conversation_logs/{exp_name}"
            os.makedirs(step_log_dir, exist_ok=True)
            debug_plan = gdbagent.get_first_info()
            with open(os.path.join(step_log_dir, f"debug_plan_{exp_name}_{exp.FinishedEXPCodeIdx}.md"), "w") as f:
                f.write(debug_plan)
            
            # 开始工具调试
            gdbagent.one_round_conversation(max_calls=20)
            gdbagent.add_user_message("总结上述对话中涉及到的内存变化。")

            # 保存步骤总结
            step_log_dir = f"./conversation_logs/{exp_name}"
            step_summary = gdbagent.get_last_info()
            with open(os.path.join(step_log_dir, f"step_summary_{exp_name}_{exp.FinishedEXPCodeIdx}.md"), "w") as f:
                f.write(step_summary)
            
            DynamicMemoryInfoList.append(step_summary)
            exp.FinishedEXPCodeIdx += 1
            progress.update(task_id, advance=1, description=f"[cyan]Analyzing [bold]{exp_name}[/bold]: Step {i+1}/{total_steps}")

        DynamicMemoryInfoList = DynamicMemoryInfoList[1:]
        finalLLM = SummarizeLLM(exp, DynamicMemoryInfoList)
        finalLLM.get_summary()
        progress.update(task_id, completed=total_steps, description=f"[green]Finished [bold]{exp_name}[/bold]")
    except Exception as e:
        with log_lock:
            logger.error(f"分析 '{exp_name}' 过程中发生错误: {e}")
        progress.update(task_id, description=f"[red]Error in [bold]{exp_name}[/bold]")
    finally:
        TmuxSession.close()
        with log_lock:
            logger.info(f"会话 '{session_name}' 已清理。")

def main():
    exps:List[EXPCode] = [
        #sample0,
        #sample1,
        #sample2,
        #sample3,
        #sample4,
        #sample5,
        #sample6,
        #sample7,
        #sample8,
        #sample9,
        #sample10,
        #sample11,
        #sample12,
        #sample13,
        #sample14,
        #sample15,
        #sample16,
        #sample17,
        #sample18,
        #sample20,
        #sample21,
        #sample22,
        #sample25,
        #sample26,
        sample27,
    ]

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        transient=True
    ) as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(exps)) as executor:
            futures = []
            for i, exp in enumerate(exps):
                if i > 0:
                    time.sleep(30)
                exp_name = os.path.basename(exp.ExpCodePath).rsplit('.', 1)[0].replace('-', '_')
                task_id = progress.add_task(f"[cyan]Queueing [bold]{exp_name}[/bold]", total=None, start=False)
                futures.append(executor.submit(AnalyseEXP, exp, progress, task_id))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    with log_lock:
                        logger.error(f"A thread raised an exception: {e}")

if __name__ == "__main__":
    main()
