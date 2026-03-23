from dataclasses import dataclass
from typing import List
from pprint import pprint
@dataclass
class Checksec:
    Arch: str
    Relro: str
    Stack: str
    Nx: str
    Pie: str

@dataclass
class BaseAddr:
    libc: int
    heap: int
    stack: int
    program_code: int
    program_rodata: int
    program_data: int

'''@dataclass
class Bins:
    fastbins: dict[str, str]
    unsortedbin: dict[str, str]
    smallbins: dict[str, str]
    largebins: dict[str, str]'''

@dataclass
class Heap:
    prev_size: str
    size: str
    fd: str
    bk: str
    fd_nextsize: str
    bk_nextsize: str

class GlobalInfo:
    def __init__(
        self,
        ChecksecStr: str,
        vmmapStr: str,
        HeapStr: str,
        BinsStr: str = ""
    ):
        self.checksec = self._get_checksec(ChecksecStr)
        self.base_addr = self._get_base_addr(vmmapStr)
        self.heaps = self._get_heap(HeapStr)
        self.bins = self._get_bins(BinsStr)
    def _get_checksec(self, ChecksecStr: str) -> Checksec:
        checksec = Checksec(
            Arch=ChecksecStr.split("Arch:")[1].split("\n")[0].strip(),
            Relro=ChecksecStr.split("RELRO:")[1].split("\n")[0].strip(),
            Stack=ChecksecStr.split("Stack:")[1].split("\n")[0].strip(),
            Nx=ChecksecStr.split("NX:")[1].split("\n")[0].strip(),
            Pie=ChecksecStr.split("PIE:")[1].split("\n")[0].strip()
        )
        return checksec

    def _get_base_addr(self, vmmapStr: str) -> BaseAddr:
        libc_addr = None
        heap_addr = None
        stack_addr = None
        program_code_addr = None
        program_rodata_addr = None
        program_data_addr = None

        program_path = None

        for raw_line in vmmapStr.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            # expect lines like: 0xSTART 0xEND PERMS ... PATH
            if not parts or not parts[0].startswith("0x"):
                continue
            if len(parts) < 4:
                continue

            start_str = parts[0]
            perms = parts[2]
            path = parts[-1] if parts[-1] else ""

            # parse start address
            try:
                start_addr = int(start_str, 16)
            except ValueError:
                continue

            # heap / stack
            if path == "[heap]" and heap_addr is None:
                heap_addr = start_addr
                continue
            if path == "[stack]" and stack_addr is None:
                stack_addr = start_addr
                continue

            # libc text segment base (first r-x mapping for libc)
            if ("libc" in path) and perms.startswith("r-x") and libc_addr is None:
                libc_addr = start_addr
                continue

            # determine program main binary path by first r-x mapping not in /lib and not [*]
            is_special = path.startswith("[") and path.endswith("]")
            is_lib = path.startswith("/lib") or "/lib/" in path
            if not is_special and not is_lib:
                if perms.startswith("r-x") and program_path is None:
                    program_path = path
                    program_code_addr = start_addr
                    continue

            # collect rodata/data for the detected program path
            if program_path is not None and path == program_path:
                if program_rodata_addr is None and perms.startswith("r--"):
                    program_rodata_addr = start_addr
                    continue
                if program_data_addr is None and perms.startswith("rw-"):
                    program_data_addr = start_addr
                    continue

        base_addr = BaseAddr(
            libc=libc_addr or 0,
            heap=heap_addr or 0,
            stack=stack_addr or 0,
            program_code=program_code_addr or 0,
            program_rodata=program_rodata_addr or 0,
            program_data=program_data_addr or 0
        )
        return base_addr

    def _get_bins(self, BinsStr: str) -> List[str]:
        if not BinsStr:
            return []
        return BinsStr.splitlines()[1:]

    def _get_heap(self, HeapStr: str) -> dict[str, Heap]:
        heap_base = self.base_addr.heap

        heaps: dict[str, Heap] = {}

        lines = HeapStr.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            # match chunk header like: "0x71fc000 PREV_INUSE {" or "0x71fc200 {"
            if line.startswith("0x") and line.endswith("{"):
                # extract chunk start address (first token)
                addr_token = line.split()[0]
                try:
                    chunk_addr = int(addr_token, 16)
                except ValueError:
                    i += 1
                    continue

                # read fields until closing '}'
                i += 1
                fields = {
                    "prev_size": "",
                    "size": "",
                    "fd": "",
                    "bk": "",
                    "fd_nextsize": "",
                    "bk_nextsize": "",
                }
                while i < len(lines):
                    inner = lines[i].rstrip()
                    if inner.strip() == "}":
                        break
                    # lines like: "  prev_size = 0," (comma optional on last field)
                    if "=" in inner:
                        key_part, value_part = inner.split("=", 1)
                        key = key_part.strip()
                        value = value_part.strip()
                        # drop trailing comma if present
                        if value.endswith(","):
                            value = value[:-1].rstrip()
                        if key in fields:
                            fields[key] = value
                    i += 1

                # try convert prev_size and size to hex and append to original string
                for num_key in ("prev_size", "size"):
                    raw_val = fields[num_key]
                    if not raw_val:
                        continue
                    # skip if already contains hex notation
                    if "0x" in raw_val.lower():
                        continue
                    try:
                        num_val = int(raw_val, 0)
                        #fields[num_key] = f"{raw_val} (0x{num_val:x})"
                        fields[num_key] = f"0x{num_val:x}"
                    except Exception:

                        pass

                # compute offset relative to heap base
                offset_int = max(0, chunk_addr - (heap_base or 0))
                offset_key = hex(offset_int)

                heaps[offset_key] = Heap(
                    prev_size=fields["prev_size"],
                    size=fields["size"],
                    fd=fields["fd"],
                    bk=fields["bk"],
                    fd_nextsize=fields["fd_nextsize"],
                    bk_nextsize=fields["bk_nextsize"],
                )

                # move past '}'
                while i < len(lines) and lines[i].strip() != "}":
                    i += 1
                if i < len(lines) and lines[i].strip() == "}":
                    i += 1
                continue

            i += 1

        return heaps

    def __str__(self):
        # build heap markdown table
        header = "编号|偏移|prev_size|size|fd|bk|fd_nextsize|bk_nextsize"
        separator = "-|-|-|-|-|-|-|-"
        rows: List[str] = []
        # sort by numeric offset
        sorted_items = sorted(self.heaps.items(), key=lambda kv: int(kv[0], 16))
        for idx, (offset_hex, heap_obj) in enumerate(sorted_items):
            rows.append(
                f"{idx}|{offset_hex}|{heap_obj.prev_size}|{heap_obj.size}|{heap_obj.fd}|{heap_obj.bk}|{heap_obj.fd_nextsize}|{heap_obj.bk_nextsize}"
            )

        heap_table = "\n".join([header, separator] + rows) if rows else "(空)"

        bins_str = "\n".join(self.bins) if self.bins else "(空)"

        return f"""
# Checksec:
- 架构: {self.checksec.Arch}
- RELRO: {self.checksec.Relro}
- Stack: {self.checksec.Stack}
- NX: {self.checksec.Nx}
- PIE: {self.checksec.Pie}

# 基址:
- libc基址: {hex(self.base_addr.libc)}
- 堆基址: {hex(self.base_addr.heap)}
- 栈基址: {hex(self.base_addr.stack)}
- 代码段.data基址: {hex(self.base_addr.program_code)}
- 只读数据段.rodata基址: {hex(self.base_addr.program_rodata)}
- 数据段.data基址: {hex(self.base_addr.program_data)}

# Heap状态:
{heap_table}


# Bins状态:
{bins_str}
        """

if __name__ == "__main__":
    testChecksecStr = "pwndbg> checksec\n[*] '/root/AutoExpMarkDocker-ds-k2/data/sample1'\n    Arch:     amd64-64-little\n    RELRO:    Full RELRO\n    Stack:    Canary found\n    NX:       NX enabled\n    PIE:      No PIE (0x400000)\n"
    testVmmapsStr = "pwndbg> vmmap\nLEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA\n          0x400000           0x402000 r-xp     2000 0      /root/AutoExpMarkDocker-ds-k2/data/sample1\n          0x601000           0x602000 r--p     1000 1000   /root/AutoExpMarkDocker-ds-k2/data/sample1\n          0x602000           0x603000 rw-p     1000 2000   /root/AutoExpMarkDocker-ds-k2/data/sample1\n         0x71fc000          0x721d000 rw-p    21000 0      [heap]\n    0x7ce31811e000     0x7ce3182de000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so\n    0x7ce3182de000     0x7ce3184de000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so\n    0x7ce3184de000     0x7ce3184e2000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so\n    0x7ce3184e2000     0x7ce3184e4000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so\n    0x7ce3184e4000     0x7ce3184e8000 rw-p     4000 0\n    0x7ce3184e8000     0x7ce31850e000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so\n    0x7ce318703000     0x7ce318706000 rw-p     3000 0\n    0x7ce31870d000     0x7ce31870e000 r--p     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so\n    0x7ce31870e000     0x7ce31870f000 rw-p     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so\n    0x7ce31870f000     0x7ce318710000 rw-p     1000 0\n    0x7fff64a30000     0x7fff64a51000 rw-p    21000 0      [stack]\n    0x7fff64bd7000     0x7fff64bdb000 r--p     4000 0      [vvar]\n    0x7fff64bdb000     0x7fff64bdd000 r-xp     2000 0      [vdso]\n"
    testHeapStr = "pwndbg> heap\nTop Chunk: 0x71fc400\nLast Remainder: 0\n\n0x71fc000 PREV_INUSE {\n  prev_size = 0,\n  size = 257,\n  fd = 0x61616161,\n  bk = 0x0,\n  fd_nextsize = 0x0,\n  bk_nextsize = 0x0\n}\n0x71fc100 PREV_INUSE {\n  prev_size = 0,\n  size = 257,\n  fd = 0x0,\n  bk = 0x1f1,\n  fd_nextsize = 0x7ce3184e2b78 <main_arena+88>,\n  bk_nextsize = 0x7ce3184e2b78 <main_arena+88>\n}\n0x71fc200 {\n  prev_size = 240,\n  size = 256,\n  fd = 0x63636363,\n  bk = 0x0,\n  fd_nextsize = 0x0,\n  bk_nextsize = 0x0\n}\n0x71fc300 {\n  prev_size = 496,\n  size = 256,\n  fd = 0x64646464,\n  bk = 0x0,\n  fd_nextsize = 0x0,\n  bk_nextsize = 0x0\n}\nvmmap\n0x71fc400 PREV_INUSE {\n  prev_size = 0,\n  size = 134145,\n  fd = 0x0,\n  bk = 0x0,\n  fd_nextsize = 0x0,\n  bk_nextsize = 0x0\n}\n"
    testBinsStr = "pwndbg> bins\nfastbins\n0x20: 0x0\n0x30: 0x0\n0x40: 0x0\n0x50: 0x0\n0x60: 0x0\n0x70: 0x0\n0x80: 0x0\nunsortedbin\nall: 0x71fc110 ◂— 0x7ce3184e2b78\nsmallbins\nempty\nlargebins\nempty\n"
    globalInfo = GlobalInfo(testChecksecStr, testVmmapsStr, testHeapStr, testBinsStr)
    print(globalInfo)