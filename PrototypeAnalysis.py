from tmux_gdb_controller import TmuxGdbController
from GDBInfo import PrimaryInfo
from LLMLogger import logger
from GDBAgent import GDBAgent_Prototype, ModelConfig
from typing import List
import os
import time
from SummarizeLLM import SummarizeLLM_Prototype
import concurrent.futures
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn
import threading

# Add a lock for thread-safe logging
log_lock = threading.Lock()

prototype_breakpoint = {
    "fastbin_dup": [14,29,34],
    "fastbin_dup_consolidate": [32, 36, 38, 50, 57, 64],
    "fastbin_dup_into_stack": [23, 29, 32, 36, 39, 50, 51],
    "house_of_gods": [85, 112, 171, 223, 296, 314, 331, 361, 380],
    "house_of_lore": [43, 67, 72, 81, 92, 99, 103, 115],
    "house_of_mind_fastbin": [122, 156, 161, 180, 197, 218, 222],
    "house_of_orange": [50, 76, 122, 175, 214, 253, 257, 264],
    "house_of_roman": [139, 201, 251, 266, 331, 355, 379, 392, 394],
    "house_of_storm": [67, 132, 138, 142, 177, 214, 243, 249],
    "mmap_overlapping_chunks": [66, 92, 108, 124, 135, 143],
    "sysmalloc_int_free": [72, 98, 125, 156],
    "house_of_einherjar_hollk": [34, 49, 52, 53],
    "house_of_einherjar": [28, 60, 92, 107, 108],
    "house_of_force": [36, 71, 74, 84],
    "house_of_spirit": [9, 31, 34, 35],
    "large_bin_attack": [49, 56, 63, 70, 71, 75, 81, 101, 113],
    "overlapping_chunks": [22, 23, 24, 33, 53, 67, 72, 74],
    "overlapping_chunks_2": [33,50,55,59,63,66,78],
    "poison_null_byte": [44, 61, 81, 91, 99, 100, 103, 114],
    "unsafe_unlink": [22, 23, 49, 53, 62],
    "unsorted_bin_attack": [13, 19, 31, 33],
    "unsorted_bin_into_stack": [19, 34, 38, 40],
}

def Init(TmuxSession:TmuxGdbController, prototype_name:str):
    try:
        TmuxSession.gdb_pane = TmuxSession.panes[0]
        TmuxSession.send_command_to_pane(TmuxSession.gdb_pane, f"gdb ./data/Prototype/{prototype_name}")

        breakpoint_list = prototype_breakpoint[prototype_name]
        for breakpoint in breakpoint_list:
            TmuxSession.send_command_to_pane(TmuxSession.gdb_pane, f"b {prototype_name}.c:{breakpoint}")
        TmuxSession.send_command_to_pane(TmuxSession.gdb_pane, f"r")
        with log_lock:
            logger.info(f"[{prototype_name}] GDB session started with breakpoints.")
        return True
    except Exception as e:
        with log_lock:
            logger.error(f"[{prototype_name}] Init failed: {e}")
        return False

def AnalysePrototype(prototype_name:str, progress: Progress, task_id):
    DynamicMemoryInfoList = ['None\n']
    session_name = f"ExploitPrototypeAnalysis_{prototype_name}"
    TmuxSession = TmuxGdbController(session_name=session_name, width=500, height=200)
    breakpoint_list = prototype_breakpoint[prototype_name]
    
    try:
        if not Init(TmuxSession, prototype_name):
            raise Exception("InitTerminal failed")

        auto_save_dir = "conversation_prototype_logs"
        os.makedirs(auto_save_dir, exist_ok=True)

        with open(f"./data/Prototype/{prototype_name}.c", "r") as f:
            source_code = f.read()

        total_steps = len(breakpoint_list)
        progress.update(task_id, total=total_steps)
        progress.start_task(task_id)

        for i in range(len(breakpoint_list)):
            primary_info = PrimaryInfo(
                Decompilation=source_code,
                #由于DeepSeek-v3的非思考模式是智障，给他初始信息也读不明白，就不加入干扰信息了
                #DynamicMemory=TmuxSession.get_base_memory_info(TmuxSession.gdb_pane)
                DynamicMemory="None\n"
            )
            timestamp = int(time.time())
            auto_save_path = os.path.join(auto_save_dir, f"conversation_{prototype_name}_step_{i}_{timestamp}.json")
            
            gdb_prototype_agent = GDBAgent_Prototype(
                prototype_name=prototype_name,
                last_info=DynamicMemoryInfoList[i],
                breakpoint_list=breakpoint_list,
                primary_info=primary_info,
                tmux_session=TmuxSession,
                config=ModelConfig(
                    temperature=0.7,
                    max_tokens=8192
                ),
                auto_save_path=auto_save_path
            )
            gdb_prototype_agent.initialize_conversation(breakpoint_list[i])
            gdb_prototype_agent.one_round_conversation()
            gdb_prototype_agent.add_user_message("总结上述对话中涉及到的内存变化。")
            DynamicMemoryInfoList.append(gdb_prototype_agent.get_last_info())
            progress.update(task_id, advance=1, description=f"[cyan]Analyzing [bold]{prototype_name}[/bold]: Step {i+1}/{total_steps}")

        DynamicMemoryInfoList = DynamicMemoryInfoList[1:]
        finalLLM = SummarizeLLM_Prototype(prototype_name, source_code, DynamicMemoryInfoList, breakpoint_list)
        finalLLM.get_summary()
        progress.update(task_id, completed=total_steps, description=f"[green]Finished [bold]{prototype_name}[/bold]")

    except Exception as e:
        with log_lock:
            logger.error(f"分析 '{prototype_name}' 过程中发生错误: {e}")
        progress.update(task_id, description=f"[red]Error in [bold]{prototype_name}[/bold]")
    finally:
        TmuxSession.close()
        with log_lock:
            logger.info(f"会话 '{session_name}' 已清理。")

def main():
    prototypes = list(prototype_breakpoint.keys())

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        transient=True
    ) as progress:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(prototypes)) as executor:
            futures = []
            for i, prototype_name in enumerate(prototypes):
                if i > 0:
                    time.sleep(30)
                task_id = progress.add_task(f"[cyan]Queueing [bold]{prototype_name}[/bold]", total=None, start=False)
                futures.append(executor.submit(AnalysePrototype, prototype_name, progress, task_id))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    with log_lock:
                        logger.error(f"A thread raised an exception: {e}")

if __name__ == "__main__":
    main()
