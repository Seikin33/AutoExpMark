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
from collections import defaultdict

@dataclass
class ModelConfig:
    """LLM配置"""
    temperature: float = 0.7
    max_tokens: int = 65536

class SummarizeLLM:
    def __init__(self, exp_code:EXPCode, DynamicMemoryInfoList:list[str]):
        MemoryInfoSummary = ""
        count = 1
        for code_line, dynamic_memory_info in zip(exp_code.ExploitCode, DynamicMemoryInfoList):
            MemoryInfoSummary += f"Step {count}: {code_line}\n{dynamic_memory_info}\n"
            count += 1
        self.exp_name = os.path.basename(exp_code.ExpCodePath).split('.')[0]
        self.prompt_manager = PromptManager(
            promptyaml="./LLMPrompts/SummarizePrompt.yaml",
            exp_code=exp_code,
            decompilation_code=exp_code.DecompileCode,
            MemoryInfoSummary=MemoryInfoSummary
        )
        self.backend = DeepSeekBackend(
            model="deepseek-reasoner",
            tools={},
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            config=ModelConfig(
                temperature=0.7,
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
    main_summary_generation()
    