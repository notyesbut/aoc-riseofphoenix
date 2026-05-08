// Dumper-7 .idmap loader for IDA (IDC version)
// Run from IDA: File -> Script file... -> select this script
//
// .idmap format (per Dumper-7 ReadMe):
//   struct Identifier {
//       uint32 Offset;          // Relative to ImageBase, little-endian
//       uint16 NameLength;      // little-endian
//       char Name[NameLength];  // Not NUL-terminated
//   }
//   ...repeated until EOF

#include <idc.idc>

static main()
{
    auto idmap_path, fp, file_size, image_base;
    auto applied, failed, total, offset, name_len, name, addr;
    auto i, b;

    idmap_path = "C:\\Dumper-7\\5.6.0-438018+++game+jvs_game_rel-AOC\\IDAMappings\\5.6.0-438018+++game+jvs_game_rel-AOC.idmap";

    fp = fopen(idmap_path, "rb");
    if (fp == 0)
    {
        Message("[!] Failed to open: %s\n", idmap_path);
        return;
    }

    // Determine file size: seek to end, ftell, seek back to start
    fseek(fp, 0, 2);   // SEEK_END
    file_size = ftell(fp);
    fseek(fp, 0, 0);   // SEEK_SET

    image_base = get_imagebase();
    Message("[+] Dumper-7 idmap loader\n");
    Message("[+] ImageBase = 0x%X\n", image_base);
    Message("[+] File size = %d bytes\n", file_size);
    Message("[+] Applying names...\n\n");

    applied = 0;
    failed  = 0;
    total   = 0;

    while (ftell(fp) + 6 <= file_size)
    {
        // uint32 Offset (little-endian)
        offset = readlong(fp, 0);

        // uint16 NameLength (little-endian)
        name_len = readshort(fp, 0);

        if (name_len <= 0 || name_len > 1024)
        {
            Message("[!] Bad name_len=%d at entry %d, stopping\n", name_len, total);
            break;
        }

        if (ftell(fp) + name_len > file_size)
        {
            Message("[!] Truncated name at entry %d\n", total);
            break;
        }

        // Read name byte-by-byte; sanitize anything not [A-Za-z0-9_] -> '_'
        name = "";
        for (i = 0; i < name_len; i = i + 1)
        {
            b = fgetc(fp);
            if (b < 0)
            {
                break;
            }

            //  0-9 (48..57)  A-Z (65..90)  a-z (97..122)  _ (95)
            if ((b >= 48 && b <= 57)  ||
                (b >= 65 && b <= 90)  ||
                (b >= 97 && b <= 122) ||
                 b == 95)
            {
                name = name + form("%c", b);
            }
            else
            {
                name = name + "_";
            }
        }

        addr = image_base + offset;

        // 0x900 = SN_NOWARN(0x100) | SN_FORCE(0x800)
        // Overwrites existing names without warning
        if (set_name(addr, name, 0x900))
        {
            applied = applied + 1;
        }
        else
        {
            failed = failed + 1;
        }

        total = total + 1;

        if (total % 1000 == 0)
        {
            Message("  processed %d  applied %d\n", total, applied);
        }
    }

    fclose(fp);

    Message("\n[+] Done.\n");
    Message("  Total entries:  %d\n", total);
    Message("  Names applied:  %d\n", applied);
    Message("  Failed:         %d\n", failed);
    Message("\n[+] Use 'g' (Goto address/name) and type a class name like:\n");
    Message("      UNetConnection\n");
    Message("      UCharacterAppearanceComponent\n");
    Message("      UIntrepidNetDriver\n");
    Message("    All matching offsets will resolve.\n");
}
