from LLMPromptTemplate import PromptManager
from GDBInfo import PrimaryInfo, EXPCode
from LLMLogger import logger
from LLMBackend import DeepSeekBackend, QwenBackend
from GDBInfo import PrimaryInfo
import os
from dataclasses import dataclass
from LLMConversation import Conversation
from datetime import datetime
from data.structuredEXP import *
import concurrent.futures
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn
import threading
import json
import re
import glob
from collections import defaultdict
from typing import List

@dataclass
class ModelConfig:
    """LLM配置"""
    temperature: float = 0.7
    max_tokens: int = 65536

class SummarizeLLM:
    def __init__(
        self, 
        exp_code:EXPCode, 
        DynamicMemoryInfoList:list[str],
        groundtruth_writeup:str
    ):
        MemoryInfoSummary = ""
        count = 1
        for code_line, dynamic_memory_info in zip(exp_code.ExploitCode, DynamicMemoryInfoList):
            MemoryInfoSummary += f"Step {count}: {code_line}\n{dynamic_memory_info}\n"
            count += 1
        self.exp_name = os.path.basename(exp_code.ExpCodePath).split('.')[0]
        self.prompt_manager = PromptManager(
            promptyaml="./LLMPrompts/SummarizeNewPrompt.yaml",
            groundtruth_writeup=groundtruth_writeup,
            decompilation_code=exp_code.DecompileCode,
            MemoryInfoSummary=MemoryInfoSummary
        )
        self.backend = DeepSeekBackend(
            model="deepseek-reasoner",
            tools={},
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            config=ModelConfig(
                temperature=1.0,
                max_tokens=65536
            )
        )
        
        '''self.backend = QwenBackend(
            model="qwen-plus-latest",
            tools={},
            api_key=os.getenv("DASHSCOPE_API_KEY"),
            config=ModelConfig(
                temperature=0.7,
                max_tokens=16384
            )
        )'''
        
        self.conversation = Conversation(name="SummarizeLLM")
        self.conversation.append_system(self.prompt_manager.get("system_prompt"))
        self.conversation.append_user(self.prompt_manager.get("user_prompt"))
    
    def get_summary(self):
        response = self.backend.send(list(self.conversation.messages))
        if response.content:
            self.conversation.append_assistant(response.content, response.tool_call)
            logger.assistant_thought(response.content)
            with open(f"summary_{self.exp_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", "w") as f:
                f.write(response.content)
            return response.content
        else:
            logger.print("No response content from LLM")
            return None

    def print_prompt(self):
        logger.print(self.prompt_manager.get("system_prompt"))
        logger.print(self.prompt_manager.get("user_prompt"))

class SummarizeLLM_Prototype:
    def __init__(
            self, 
            prototype_name:str, 
            source_code:str, 
            DynamicMemoryInfoList:list[str],
            breakpoint_list:list[int]
        ):
        MemoryInfoSummary = ""
        for dynamic_memory_info, breakpoint in zip(DynamicMemoryInfoList, breakpoint_list):
            MemoryInfoSummary += f"Line {breakpoint}: {dynamic_memory_info}\n"
        self.prototype_name = prototype_name
        self.prompt_manager = PromptManager(
            promptyaml="./LLMPrompts/SummarizePrompt_Prototype.yaml",
            prototype_name=prototype_name,
            source_code=source_code,
            MemoryInfoSummary=MemoryInfoSummary
        )
        self.backend = DeepSeekBackend(
            model="deepseek-reasoner",
            tools={},
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            config=ModelConfig(
                temperature=0.7,
                max_tokens=8192
            )
        )
        self.conversation = Conversation(name="SummarizeLLM_Prototype")
        self.conversation.append_system(self.prompt_manager.get("system_prompt"))
        self.conversation.append_user(self.prompt_manager.get("user_prompt"))

    def get_summary(self):
        response = self.backend.send(list(self.conversation.messages))
        if response.content:
            self.conversation.append_assistant(response.content, response.tool_call)
            logger.assistant_thought(response.content)
            with open(f"summary_{self.prototype_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", "w") as f:
                f.write(response.content)
            return response.content
        else:
            logger.print("No response content from LLM")

log_lock = threading.Lock()

def process_and_summarize_sample(sample_name, summaries, progress, task_id):
    """Processes a single sample: sorts summaries, calls LLM, and updates progress."""
    try:
        progress.start_task(task_id)
        progress.update(task_id, description=f"[cyan]Processing [bold]{sample_name}[/bold]...")

        # Sort summaries by step number
        summaries.sort(key=lambda x: x[0])
        dynamic_memory_info_list = [summary for step, summary in summaries]

        # Get the corresponding EXPCode object
        exp_code_obj_name = f"{sample_name}"
        if sample_name == "sample19":
            exp_code_obj_name = "sample19_exp"  # Special case from structuredEXP.py
        
        # This needs access to the global scope where structuredEXP is imported
        exp_code_obj = eval(exp_code_obj_name)

        summarizer = SummarizeLLM(
            exp_code=exp_code_obj,
            DynamicMemoryInfoList=dynamic_memory_info_list
        )
        summary = summarizer.get_summary()

        if summary:
            progress.update(task_id, completed=1, description=f"[green]Finished [bold]{sample_name}[/bold]")
        else:
            progress.update(task_id, description=f"[yellow]No summary for [bold]{sample_name}[/bold]")

    except NameError:
        with log_lock:
            logger.error(f"EXPCode object for {sample_name} not found. Skipping.")
        progress.update(task_id, description=f"[red]Error (NameError) in [bold]{sample_name}[/bold]")
    except Exception as e:
        with log_lock:
            logger.error(f"An error occurred while processing {sample_name}: {e}")
        progress.update(task_id, description=f"[red]Error in [bold]{sample_name}[/bold]")

def main_summary_generation():
    """Main function to find logs, parse them, and generate summaries concurrently."""
    log_dir = "/root/AutoExpMarkDocker/conversation_logs/20250906-2/"
    log_files = os.listdir(log_dir)

    sample_summaries = defaultdict(list)

    for log_file in log_files:
        match = re.match(r"conversation_(sample\d+)_step_(\d+)_.*?\.json", log_file)
        if match:
            sample_name = match.group(1)
            step = int(match.group(2))
            
            with open(os.path.join(log_dir, log_file), 'r') as f:
                try:
                    conversation_data = json.load(f)
                    if conversation_data and isinstance(conversation_data, list):
                        last_assistant_message = None
                        for message in reversed(conversation_data):
                            if message.get("role") == "MessageRole.ASSISTANT":
                                last_assistant_message = message.get("content")
                                break
                        
                        if last_assistant_message:
                            sample_summaries[sample_name].append((step, last_assistant_message))
                except json.JSONDecodeError:
                    with log_lock:
                        logger.warning(f"Could not decode JSON from {log_file}")

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        transient=False  # Keep the progress bar after finishing
    ) as progress:
        max_workers = len(sample_summaries) if sample_summaries else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for sample_name, summaries in sample_summaries.items():
                task_id = progress.add_task(f"[cyan]Queued [bold]{sample_name}[/bold]", total=1, start=False)
                futures.append(executor.submit(process_and_summarize_sample, sample_name, summaries, progress, task_id))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    with log_lock:
                        logger.error(f"A summary generation thread raised an exception: {e}")

if __name__ == "__main__":
    exp_names = [
        "heap23_00_hitcon_2014_stkof",
        "heap23_01_guosai_201x_pwn1",
        "heap23_02_wdb_2018_babyheap",
        "heap23_04_search_engine",
        "heap23_05_cookbook",
        "heap23_06_hitcon_2016_sleepyholder",
        "heap23_07_0ctf_2017_babyheap",
        "heap23_08_hitcontrainning_lab11_bamboobox",
    ]
    exps:List[EXPCode] = [
        #heap23_00_hitcon_2014_stkof,
        #heap23_01_guosai_201x_pwn1,
        #heap23_02_wdb_2018_babyheap,
        #heap23_04_search_engine,
        #heap23_05_cookbook,
        #heap23_06_hitcon_2016_sleepyholder,
        #heap23_07_0ctf_2017_babyheap,
        #heap23_08_hitcontrainning_lab11_bamboobox,
        heap23_09_qwb_2018_silent2,
        heap23_10_0CTF_2015_FreeNote,
        heap23_11_pwnable_applestore,
        heap23_12_axb_2019_heap,
        heap23_13_starctf_2019_girlfriend,
        heap23_14_wustctf_2020_easyfast,
        heap23_15_nsctf_online_2019_pwn2,
        heap23_16_zctf_2016_note3,
        heap23_17_ZJCTF_2019_Easyheap,
        heap23_18_hacklu_2014_oreo,
        heap23_19_0ctf_2018_heapstorm2,
        heap23_20_bctf_2016_bcloud,
        heap23_21_lctf_2016_pwn200,
        heap23_22_seccon_2016_tinypad,
        #heap23_23_xihu_2019_storm_note,
        heap23_25_pwnhub_einherjar_level1,
        heap23_26_ctfhub_lore_level1,
        heap23_27_Asis_2016_b00ks
    ]
    for exp in exps:
        exp_name = str(exp)
        #with open(f'./data/writeup/{exp_name}.md','r') as f:
        #    groundtruth_md = f.read()
        with open(f'./data/exp/{exp_name}.py','r') as f:
            groundtruth_md = f.read()
        length = len(exp.ExploitCode)
        DynamicMemoryInfoList = []
        '''for i in range(1, length+1):
            # 优先匹配带有时间戳的历史对话文件：conversation_{exp_name}_step_{i}_<任意数字>.json
            pattern = f'./conversation_logs/{exp_name}/step_summary_{exp_name}_{i}.json'
            target_path = pattern

            with open(target_path, 'r') as f:
                conversation_data = f.read()
                DynamicMemoryInfoList.append(conversation_data)'''
        finalLLM = SummarizeLLM(exp, DynamicMemoryInfoList, groundtruth_md)
        finalLLM.get_summary()