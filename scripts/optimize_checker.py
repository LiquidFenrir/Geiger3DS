import sys
import asyncio
import sqlite3
import json
from collections import namedtuple
from typing import *

# echo | gcc -std=c23 -O1 -fdump-passes -c -o /dev/null -x c - 2> passes_O1.txt
# gcc -std=c23 -x c -O1 -Q --help=optimizers | tail -n +8 > optimizers_O1.txt
# gcc -std=c23 -x c -O1 -Q --help=params | tail -n +8 > params_O1.txt

pass_row_t = namedtuple('pass_row_t', ['exe_id', 'row_num', 'parent_row', 'depth', 'name', 'state'])
time_row_t = namedtuple('time_row_t', ['exe_id', 'row_num', 'parent_row', 'name', 'wall_time'])

# prefix: -W
flags_warns="""
no-cpp
stack-usage=8
"""
# prefix: -Wl,
flags_linker="""
-eentry
"""
# prefix: -m
flags_m="""
no-red-zone
tune=generic
arch=sandybridge
64
no-mmx
fpmath=sse
avx
asm=intel
"""
# directly pass
flags_raw="""
-nostdlib
-std=c23
-O1
"""
# prefix: -f
flags_feature="""
diagnostics-format=sarif-stderr
time-report
time-report-details
freestanding
"""
# prefix: -fno-
flags_disabled_opt="""
branch-count-reg
code-hoisting
compare-elim
cprop-registers
crossjumping
dce
delayed-branch
dse
gcse
guess-branch-probability
if-conversion
if-conversion2
inline-functions-called-once
ipa-modref
ipa-profile
ipa-pure-const
ipa-reference
ipa-reference-addressable
move-loop-invariants
move-loop-stores
reorder-blocks
reorder-functions
ssa-phiopt
thread-jumps
toplevel-reorder
tree-bit-ccp
tree-ccp
tree-dce
tree-dominator-opts
tree-dse
tree-fre
tree-partial-pre
tree-pre
tree-pta
tree-reassoc
tree-tail-merge
unwind-tables
"""
flags_params="""
"""
flags_order=(
    ("-W", flags_warns),
    ("-Wl,", flags_linker),
    ("-m", flags_m),
    ("", flags_raw),
    ("-f", flags_feature),
    ("-fno-", flags_disabled_opt),
    ("--param=", flags_params),
)

def add_flags(extra: Dict[str, str], order: Iterable[Tuple[str, str]] = flags_order) -> List[Tuple[str, str]]:
    return [(k, v + extra.get(k, "")) for k, v in order]

def override_flags(override: Dict[str, str], order: Iterable[Tuple[str, str]] = flags_order) -> List[Tuple[str, str]]:
    return [(k, override.get(k, v)) for k, v in order]

def bake_flags(order: Iterable[Tuple[str, str]] = flags_order) -> str:
    # return " ".join((prefix if len(flags) != 0 else "") + f" {prefix}".join(row) for prefix, flags in order for row in map(str.trim, flags.trim().splitlines()) if row)
    return " ".join(f"{prefix}{row}" for prefix, flags in order for row in map(str.strip, flags.strip().splitlines()) if row)

def treevisit(tree, get_child, do_stuff, parent_idx = None, idx_init: int = 0, depth: int = 0) -> int:
    idx = idx_init
    for val in tree:
        do_stuff(val, parent_idx, idx, depth)
        idx = treevisit(get_child(val), get_child, do_stuff, idx, idx + 1, depth + 1)
    return idx

async def run(src_path, con, new_flag):
    print(f"Try {new_flag}")
    cmd = f"gcc -o /dev/null -c {src_path} -S {bake_flags()} {new_flag}"
    with con:
        cur = con.execute("INSERT INTO exe_command(timestamp, command) VALUES(datetime('now'), ?) RETURNING id", (cmd,))
        exe_id = cur.fetchone()[0]

    start_time = asyncio.get_running_loop().time()
    proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE)
    stdout = await proc.communicate()
    end_time = asyncio.get_running_loop().time()
    run_time = end_time - start_time

    returncode = proc.returncode
    if not stdout:
        print("fail")
    
    with con:
        con.execute("INSERT INTO exe_results(exe_id, resultcode, total_time) VALUES(?, ?, ?)", (exe_id, returncode, run_time))

    stdout_text = stdout.decode()
    idx = 0
    stdout_it = iter(stdout_text)
    depths = [(0, None)]
    passes = []
    row_id = 0
    statemap = {'ON': True, 'OFF': False}
    while True:
        d = 0
        for i, c in enumerate(stdout_it, idx):
            idx += 1
            if c == ' ':
                d += 1
            else:
                break
        if d == 0:
            break
        
        rowname = [c]
        for i, c in enumerate(stdout_it, idx):
            idx += 1
            if c != ' ':
                rowname.append(c)
            else:
                break
        rowname = ''.join(rowname)

        # reach ':'
        for i, c in enumerate(stdout_it, idx):
            idx += 1
            if c != ' ':
                break
        
        # skip over next two ' '
        next(stdout_it)
        next(stdout_it)
        idx += 2
        rowstate = []
        for i, c in enumerate(stdout_it, idx):
            idx += 1
            if c != '\n':
                rowstate.append(c)
            else:
                break
        rowstate = ''.join(rowstate)

        parent_row_data = depths[-1]
        if d > parent_row_data[0]:
            depths.append((d, row_id))
        elif d == parent_row_data[0]:
            depths[-1][1] = row_id
            parent_row_data = depths[-2]
        else:
            while d < parent_row_data[0]:
                depths.pop()
                depths[-1][1] = row_id
                parent_row_data = depths[-2]

        row_depth = len(depths)

        passes.append(pass_row_t(exe_id=exe_id, row_num=row_id, parent_row=parent_row_data[1], depth=row_depth, name=rowname, state=statemap[rowstate]))
        row_id += 1

    sarif_json = json.loads(stdout_text[idx:])
    sarif_timevars = sarif_json["runs"][0]["invocations"][0]["properties"]["gcc/timeReport"]["timevars"]

    timevars = []
    treevisit(sarif_timevars, lambda tv: tv.get("children", ''), lambda tv, parent_idx, idx, depth: timevars.append(time_row_t(exe_id=exe_id, row_num=idx, parent_row=parent_idx, depth=depth, name=tv["name"], wall_time=tv["elapsed"]["wall"])))

    with con:
        if passes:
            value_str = "(" + ", ".join("?" * 5) + ")"
            con.execute("INSERT INTO exe_results_passrow(exe_id, row_num, parent_row, name, state) VALUES " + ", ".join(value_str for _ in range(len(passes))), passes)
        if timevars:
            value_str = "(" + ", ".join("?" * 5) + ")"
            con.execute("INSERT INTO exe_results_timerow(exe_id, row_num, parent_row, name, wall_time) VALUES " + ", ".join(value_str for _ in range(len(timevars))), timevars)

    print(f"Done {new_flag}")

async def main():
    src_file_path = sys.argv[1]
    todo_optfile_path = sys.argv[2]
    sqlite3_db_path = sys.argv[3]

    with open(todo_optfile_path) as todo_optfile:
        todo_opt_list = todo_optfile.readlines()

    assert(sqlite3.threadsafety == 3)
    con = sqlite3.connect(sqlite3_db_path, autocommit=False)
    with con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS exe_command (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                command TEXT NOT NULL
            );
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS exe_results (
                exe_id INTEGER NOT NULL,
                resultcode TINYINT NOT NULL,
                total_time REAL NOT NULL
                CONSTRAINT key PRIMARY KEY(exe_id),
                CONSTRAINT exe FOREIGN KEY(exe_id) REFERENCES exe_command(id)
            );
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS exe_results_passrow (
                exe_id INTEGER NOT NULL,
                row_num INTEGER NOT NULL,
                parent_row INTEGER,
                name TEXT NOT NULL,
                state BOOLEAN NOT NULL,
                CONSTRAINT key PRIMARY KEY(exe_id, row_num),
                CONSTRAINT exe FOREIGN KEY(exe_id) REFERENCES exe_command(id)
            );
        """)
        # CONSTRAINT parent FOREIGN KEY(exe_id, parent_row) REFERENCES exe_results_passrow(exe_id, row_num)
        con.execute("""
            CREATE TABLE IF NOT EXISTS exe_results_timerow (
                exe_id INTEGER NOT NULL,
                row_num INTEGER NOT NULL,
                parent_row INTEGER,
                name TEXT NOT NULL,
                wall_time REAL NOT NULL,
                CONSTRAINT key PRIMARY KEY(exe_id, row_num),
                CONSTRAINT exe FOREIGN KEY(exe_id) REFERENCES exe_command(id)
            );
        """)
        # CONSTRAINT parent FOREIGN KEY(exe_id, parent_row) REFERENCES exe_results_timerow(exe_id, row_num)

    print("setup")
    tries = []
    for todo in todo_opt_list:
        todo_ = todo.strip()
        if not todo_:
            continue
        tries.append(run(src_file_path, con, todo_))

    print("start")
    await asyncio.gather(tries)
    print("finishing")
    con.close()
    print("done")

asyncio.run(main())
