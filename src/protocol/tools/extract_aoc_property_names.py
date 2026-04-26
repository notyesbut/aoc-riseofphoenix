#!/usr/bin/env python3
"""
Extract UE5 property-name strings from the AoC client binary.

UE5 embeds every UPROPERTY() identifier as a literal C string in .rdata
(used for reflection — UClass::FindPropertyByName, etc.).  We scan the
binary for strings matching common character-property naming patterns:

    - CamelCase words (MaxHealth, CurrentMana, CharacterName)
    - Attribute-set prefixes (AS_, GE_, GC_ — Gameplay-Ability System)
    - Blueprint path fragments (/Game/Characters/..., AttributeSet_*)

Output:
    dist/Release/aoc_property_names.txt    — sorted, deduplicated list
    dist/Release/aoc_attribute_sets.txt    — class paths (AttributeSet blueprints)

Usage:
    python src/protocol/tools/extract_aoc_property_names.py
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8')

BIN_PATH = Path(r"C:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe")
OUT_DIR = HERE.parent.parent.parent / 'dist' / 'Release'

# Strings in the binary are C strings (NUL-terminated).  We scan for
# ASCII sequences of length >=4 ending in NUL, matching our patterns.

def extract_strings(data, min_len=4, max_len=100):
    """Yield all printable ASCII C-strings of length [min_len, max_len]."""
    buf = bytearray()
    i = 0
    N = len(data)
    while i < N:
        b = data[i]
        if 0x20 <= b < 0x7F:
            buf.append(b)
        else:
            if b == 0 and min_len <= len(buf) <= max_len:
                yield buf.decode('ascii', errors='replace')
            buf.clear()
        i += 1


def looks_like_property_name(s):
    """True if 's' looks like a UE5 UPROPERTY identifier.

    Heuristics:
      - Starts with uppercase letter
      - Contains only [A-Za-z0-9_]
      - Length 3..50
      - Contains at least one lowercase letter (rules out macro names)
      - Has "camel-case" signature: at least one upper→lower transition
        OR ends with one of the common UE5 suffixes.
    """
    if len(s) < 3 or len(s) > 50:
        return False
    if not re.match(r'^[A-Z][A-Za-z0-9_]+$', s):
        return False
    if not re.search(r'[a-z]', s):
        return False
    # Must have Some Lower Case + transitions, OR be a known suffix form
    if re.search(r'[A-Z][a-z]', s):
        return True
    return False


def looks_like_attribute_set(s):
    """Match AS_*, GE_*, GC_* GAS naming or AttributeSet_* or /Game/... paths."""
    if s.startswith(('AS_', 'GE_', 'GC_', 'GA_', 'AttributeSet_')):
        return True
    if s.startswith('/Game/') and ('Character' in s or 'Ability' in s
                                      or 'Stat' in s or 'Class' in s
                                      or 'Race' in s):
        return True
    return False


# Character-property keywords — boost confidence if we see these words.
CHAR_KEYWORDS = {
    'Health', 'Mana', 'Stamina', 'Energy',
    'Level', 'Experience', 'XP',
    'Strength', 'Dexterity', 'Intelligence', 'Vitality', 'Agility', 'Wisdom',
    'Constitution', 'Charisma', 'Luck',
    'Attack', 'Defense', 'Magic', 'Armor', 'Resistance',
    'Gold', 'Currency', 'Coin',
    'Character', 'Player', 'Actor',
    'Class', 'Race', 'Faction', 'Guild',
    'Name', 'Title', 'Tag',
    'Speed', 'Move', 'Walk', 'Run', 'Jump',
    'Hit', 'Damage', 'Heal', 'Crit',
    'Buff', 'Debuff', 'Effect', 'Ability', 'Skill',
    'Inventory', 'Equipment', 'Slot', 'Item', 'Weapon',
    'Quest', 'Journal',
    'Position', 'Location', 'Rotation', 'Transform', 'Velocity',
    'Max', 'Min', 'Current', 'Base', 'Percent',
}


def has_character_keyword(s):
    for kw in CHAR_KEYWORDS:
        if kw in s:
            return True
    return False


def main():
    if not BIN_PATH.exists():
        print(f"ERROR: client binary not found: {BIN_PATH}")
        print("Edit BIN_PATH in this script if AoC is installed elsewhere.")
        return 1

    print(f"Reading {BIN_PATH} ({BIN_PATH.stat().st_size // 1024 // 1024} MB)...")
    data = BIN_PATH.read_bytes()

    print("Scanning for ASCII strings...")
    strings = list(extract_strings(data))
    print(f"  Total ASCII strings: {len(strings):,}")

    # Filter 1: property names
    prop_names = set()
    for s in strings:
        if looks_like_property_name(s):
            prop_names.add(s)
    print(f"  Looks like property names: {len(prop_names):,}")

    # Filter 2: character-specific subset (higher confidence)
    char_props = {s for s in prop_names if has_character_keyword(s)}
    print(f"  Likely character properties: {len(char_props):,}")

    # Filter 3: attribute set / blueprint paths
    attr_sets = {s for s in strings if looks_like_attribute_set(s)}
    print(f"  Blueprint/AttributeSet paths: {len(attr_sets):,}")

    # Write output
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    prop_out = OUT_DIR / 'aoc_property_names.txt'
    with prop_out.open('w', encoding='utf-8') as f:
        f.write("# AoC UE5 property names extracted from AOCClient-Win64-Shipping.exe\n")
        f.write("# (character-specific subset — looks like UPROPERTY identifiers)\n")
        f.write("#\n")
        f.write(f"# Total: {len(char_props):,}\n\n")
        for s in sorted(char_props):
            f.write(s + '\n')
    print(f"\nWrote {prop_out}")

    all_prop_out = OUT_DIR / 'aoc_property_names_all.txt'
    with all_prop_out.open('w', encoding='utf-8') as f:
        f.write("# AoC UE5 property names (ALL, including non-character)\n")
        f.write(f"# Total: {len(prop_names):,}\n\n")
        for s in sorted(prop_names):
            f.write(s + '\n')
    print(f"Wrote {all_prop_out}")

    attr_out = OUT_DIR / 'aoc_attribute_sets.txt'
    with attr_out.open('w', encoding='utf-8') as f:
        f.write("# AoC Blueprint / AttributeSet paths\n")
        f.write(f"# Total: {len(attr_sets):,}\n\n")
        for s in sorted(attr_sets):
            f.write(s + '\n')
    print(f"Wrote {attr_out}")

    # Print a preview of the character properties
    print()
    print("=== Sample character properties (first 40) ===")
    for s in sorted(char_props)[:40]:
        print(f"  {s}")
    if len(char_props) > 40:
        print(f"  ... ({len(char_props) - 40} more)")

    print()
    print("=== Sample attribute-set paths (first 20) ===")
    for s in sorted(attr_sets)[:20]:
        print(f"  {s}")
    if len(attr_sets) > 20:
        print(f"  ... ({len(attr_sets) - 20} more)")

    return 0


if __name__ == '__main__':
    sys.exit(main())
