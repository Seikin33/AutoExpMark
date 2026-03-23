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
            raise Exception("Init Terminal failed")
        
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
            
            gdbagent = GDBAgent(
                #primary_info=primary_info,
                last_info=DynamicMemoryInfoList[exp.FinishedEXPCodeIdx-1],
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
            gdbagent.one_round_conversation(max_calls=10)

            # 保存步骤总结
            step_log_dir = f"./conversation_logs/{exp_name}"
            step_summary = gdbagent.get_last_info()
            with open(os.path.join(step_log_dir, f"step_summary_{exp_name}_{exp.FinishedEXPCodeIdx}.json"), "w") as f:
                f.write(step_summary)
            
            DynamicMemoryInfoList.append(step_summary)
            exp.FinishedEXPCodeIdx += 1
            progress.update(task_id, advance=1, description=f"[cyan]Analyzing [bold]{exp_name}[/bold]: Step {i+1}/{total_steps}")

        DynamicMemoryInfoList = DynamicMemoryInfoList[1:]

        with open(f'./data/writeup/{exp_name}.md','r') as f:
            groundtruth_md = f.read()

        finalLLM = SummarizeLLM(exp, DynamicMemoryInfoList, groundtruth_md)
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
        heap23_00_hitcon_2014_stkof,
        #heap23_01_guosai_201x_pwn1,
        #heap23_02_wdb_2018_babyheap,
        #heap23_04_search_engine,
        #heap23_05_cookbook,
        #heap23_06_hitcon_2016_sleepyholder,
        #heap23_07_0ctf_2017_babyheap,
        #heap23_08_hitcontrainning_lab11_bamboobox,
        #heap23_09_qwb_2018_silent2,
        #heap23_10_0CTF_2015_FreeNote,
        #heap23_11_pwnable_applestore,
        #heap23_12_axb_2019_heap,
        #heap23_13_starctf_2019_girlfriend,
        #heap23_14_wustctf_2020_easyfast,
        #heap23_15_nsctf_online_2019_pwn2,
        #heap23_16_zctf_2016_note3,
        #heap23_17_ZJCTF_2019_Easyheap,
        #heap23_18_hacklu_2014_oreo,
        #heap23_20_bctf_2016_bcloud,
        #heap23_21_lctf_2016_pwn200,
        #heap23_22_seccon_2016_tinypad,
        #heap23_25_pwnhub_einherjar_level1,
        #heap23_26_ctfhub_lore_level1,
        #heap23_27_Asis_2016_b00ks
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
