import re

INPUT_FILE = r"C:\Users\xmaxt\Desktop\IDADEC\new\strong_xor_candidates.txt"

FUNC_WINDOW = 0x200

def parse_address(line):
    # Find any long hex chunk (IDA-style safe)
    matches = re.findall(r'\b[0-9A-Fa-f]{8,16}\b', line)
    if not matches:
        return None

    # Take the longest match (best chance it's the address)
    best = max(matches, key=len)

    return int(best, 16)

with open(INPUT_FILE, "r", errors="ignore") as f:
    lines = f.readlines()

addresses = []

for line in lines:
    addr = parse_address(line)
    if addr:
        addresses.append(addr)

print(f"[+] Extracted addresses: {len(addresses)}")

if not addresses:
    print("Still no addresses found — file is not parsable.")
    exit()

addresses = sorted(set(addresses))

clusters = []
current = [addresses[0]]

for addr in addresses[1:]:
    if addr - current[-1] <= FUNC_WINDOW:
        current.append(addr)
    else:
        clusters.append(current)
        current = [addr]

clusters.append(current)

clusters.sort(key=lambda x: len(x), reverse=True)

print("\nTop XOR clusters:\n")

for i, c in enumerate(clusters[:20]):
    print(f"{i+1}. Count={len(c)} | 0x{c[0]:X} - 0x{c[-1]:X}")