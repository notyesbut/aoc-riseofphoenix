import re

path = r"C:\Users\xmaxt\Desktop\IDADEC\new\strong_xor_candidates.txt"

with open(path, "r", encoding="utf-8", errors="ignore") as f:
    data = f.read()

# split by function boundaries (adjust if needed)
functions = re.split(r"\n(?=0x[0-9A-Fa-f]{6,})", data)

keywords = [
    "BYTE1", "BYTE2", "HIBYTE",
    "+ 274", "+ 530", "+ 786",
    "xor", "^", "rol", "ror"
]

scored = []

for idx, fn in enumerate(functions):
    score = sum(fn.count(k) for k in keywords)

    if score > 10:   # IMPORTANT: function-level threshold
        scored.append((score, idx, fn[:200]))

scored.sort(reverse=True)

print("Top function-level candidates:\n")
for s in scored[:20]:
    print(s[0], "score ->", s[2])