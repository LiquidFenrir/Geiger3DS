import sys

def main(unvisited_path, objdump_file_path):
    addrs_list = []
    constant_addrs = {}
    nop_addrs = set()
    constant_sizes = {}
    constant_addrs_last = 0
    with open(objdump_file_path) as objdump_file_path_f:
        for line in objdump_file_path_f:
            if line.startswith("  "):
                addr_txt, bytes_txt, remains = line[2:].split('\t', 2)
                addr = int(addr_txt[:-1], 16) # remove ':'

                constant_addrs_last = addr
                if remains[0] == '.' or bytes_txt[:-1] == "00000000":
                    # .word or zero'd u32 'inside' a function
                    constant_addrs[constant_addrs_last] = bytes_txt[:-1]
                    constant_sizes[constant_addrs_last] = 4
                    addrs_list.append(constant_addrs_last)
                    constant_addrs_last += 4
                elif bytes_txt[:-4] == "e320f" or "nop\t" in remains:
                    nop_addrs.add(addr)
                else:
                    # instruction
                    pass
            else:
                # label
                pass

    unvisited_locs = []
    with open(unvisited_path) as unvisited_path_f:
        for unvisited_line in unvisited_path_f:
            # "unvisited: xxxxxxxx - xxxxxxxx (length xxxxxxxx)"
            pair = (int(unvisited_line[11:11+8], 16), int(unvisited_line[22:22+8], 16))
            unvisited_locs.append(pair)

    unvisited_locs_idx = 0
    cur_chunk = (0, 0)
    i = addrs_list[0]
    while i <= addrs_list[-1]:
        if unvisited_locs_idx < len(unvisited_locs):
            if i == unvisited_locs[unvisited_locs_idx][0]:
                cur_chunk = tuple(unvisited_locs[unvisited_locs_idx])
                # print(f"start chunk: {i:08x}")
            elif i == unvisited_locs[unvisited_locs_idx][1]:
                unvisited_locs_idx += 1
                cur_chunk = (0, 0)
                # print(f"endof chunk: {i:08x}")
        val = constant_addrs.get(i)
        sz = constant_sizes.get(i)
        if i not in nop_addrs:
            if val is None:
                if cur_chunk != (0, 0):
                    print(f"have instr {i:08x} in chunk {cur_chunk[0]:08x} - {cur_chunk[1]:08x} (length {cur_chunk[1] - cur_chunk[0]:08x})")
            else:
                if cur_chunk == (0, 0):
                    print(f"have const {i:08x} outside chunk")

        if sz is None:
            i ^= (i & 3)
            i += 4 # assume missings are because of instructions, so align to next
        else:
            i += sz

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
