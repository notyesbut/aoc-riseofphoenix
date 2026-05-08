# Dumper-7 .idmap loader for IDA Pro
# Run from IDA: File -> Script file... -> select this script
# Or paste into IDA's Python console
#
# .idmap format (per Dumper-7 ReadMe):
#   struct Identifier {
#       uint32 Offset;          // Relative to ImageBase
#       uint16 NameLength;
#       char Name[NameLength];  // Not NUL-terminated
#   }
#   ...repeated until EOF
#
# Compatible with IDA 7.7+ and IDA 8.x

import struct
import os

import idaapi
import idc
import ida_name
import ida_bytes
import ida_funcs

IDMAP_PATH = r"C:\Dumper-7\5.6.0-438018+++game+jvs_game_rel-AOC\IDAMappings\5.6.0-438018+++game+jvs_game_rel-AOC.idmap"

def main():
    if not os.path.exists(IDMAP_PATH):
        print("[!] idmap file not found: {}".format(IDMAP_PATH))
        return

    image_base = idaapi.get_imagebase()
    print("[+] ImageBase = 0x{:X}".format(image_base))

    with open(IDMAP_PATH, "rb") as f:
        data = f.read()

    print("[+] Loaded {} bytes from idmap".format(len(data)))

    pos = 0
    applied = 0
    skipped = 0
    failed = 0

    while pos + 6 <= len(data):
        # uint32 Offset, uint16 NameLength
        (offset, name_len) = struct.unpack_from("<IH", data, pos)
        pos += 6

        if pos + name_len > len(data):
            print("[!] Truncated entry at pos {} - stopping".format(pos))
            break

        try:
            name = data[pos:pos + name_len].decode("utf-8", errors="replace")
        except Exception as e:
            name = data[pos:pos + name_len].decode("latin-1", errors="replace")
        pos += name_len

        addr = image_base + offset

        # Sanitize name for IDA (no spaces, special chars cleaned)
        clean_name = name.replace(" ", "_").replace("<", "_").replace(">", "_")
        clean_name = clean_name.replace(",", "_").replace("*", "_").replace("&", "_")
        clean_name = clean_name.replace("(", "_").replace(")", "_").replace(":", "_")
        clean_name = clean_name.replace("[", "_").replace("]", "_").replace("'", "_")

        # Apply name; SN_FORCE = overwrite existing names if any
        try:
            if ida_name.set_name(addr, clean_name, ida_name.SN_FORCE | ida_name.SN_NOWARN):
                applied += 1
                if applied % 500 == 0:
                    print("  ... applied {} so far".format(applied))
            else:
                skipped += 1
        except Exception as e:
            failed += 1

    print("\n[+] Done.")
    print("  Applied: {}".format(applied))
    print("  Skipped: {}".format(skipped))
    print("  Failed:  {}".format(failed))
    print("\nRefresh IDA's view (F5 / press 'g' to navigate) to see the new names.")


if __name__ == "__main__":
    main()
