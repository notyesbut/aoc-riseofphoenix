// ============================================================================
//  ida_dump_propparams.idc — dump raw FPropertyParams struct bytes
//
//  We've confirmed the AAoCPlayerController property table layout: each
//  entry starts with a name pointer at +0x00 and (for replicated props)
//  a RepNotify function name pointer at +0x08.
//
//  This script dumps the full bytes of 4 known entries so we can reverse
//  the struct layout:
//    - Find PropertyFlags field (look for 0x20 / CPF_Net bit)
//    - Find Offset field (where in the class instance the value lives)
//    - Find array-dim / type-info fields
//    - Count entries between known positions to compute cmd_index
//
//  Usage: File -> Script file... -> pick this .idc.
//  Output: hex + ASCII dump of 80 bytes starting at each entry.
// ============================================================================

#include <idc.idc>


static dump_struct(label, ea, nbytes) {
    auto i, b, hex_col, ascii_col, line_start;

    Message(sprintf("\n==== %s @ 0x%X ====\n", label, ea));

    i = 0;
    while (i < nbytes) {
        line_start = i;
        hex_col = "";
        ascii_col = "";
        while (i < nbytes && i - line_start < 16) {
            b = get_wide_byte(ea + i);
            hex_col = hex_col + sprintf("%02X ", b);
            if (b >= 0x20 && b < 0x7F)
                ascii_col = ascii_col + sprintf("%c", b);
            else
                ascii_col = ascii_col + ".";
            i = i + 1;
        }
        // Pad hex column to 48 chars
        while (strlen(hex_col) < 48) hex_col = hex_col + " ";
        Message(sprintf("  +0x%02X  %s %s\n", line_start, hex_col, ascii_col));
    }
}


// Also try to identify PropertyFlags position by looking for QWORDs
// with the 0x20 (CPF_Net) bit set, among the first 64 bytes of the struct.
static find_flags(label, ea) {
    auto off, q, bit_net;
    bit_net = 0x20;
    Message(sprintf("\n  Candidate PropertyFlags for %s:\n", label));
    off = 0;
    while (off < 64) {
        q = get_qword(ea + off);
        // CPF_Net = 0x20; typical replicated property has at least this bit
        // plus a few others like CPF_BlueprintVisible (0x4), CPF_Edit (0x1), etc.
        if ((q & bit_net) == bit_net && q < 0x100000000) {  // not a pointer (small value)
            Message(sprintf("    +0x%02X: 0x%016X (CPF_Net bit set)\n", off, q));
        }
        off = off + 8;
    }
}


static main() {
    Message("\n################################################################\n");
    Message("  FPropertyParams struct byte dumps\n");
    Message("################################################################\n");

    // The 11 OnRep-replicated properties of AAoCPlayerController
    // (linear order in .rdata — see scanned.txt).  Dumping 4 to start;
    // add more if we need cross-validation.
    dump_struct("bRegisteredForDamageMeter (1st replicated)", 0x14B6CD930, 80);
    find_flags("bRegisteredForDamageMeter", 0x14B6CD930);

    dump_struct("CharacterName (7th replicated)",           0x14B6D4BD0, 80);
    find_flags("CharacterName", 0x14B6D4BD0);

    dump_struct("CurrentDialogueInstance (11th replicated)", 0x14B6D5370, 80);
    find_flags("CurrentDialogueInstance", 0x14B6D5370);

    // Also dump CharacterArchetype on its different cluster for comparison
    dump_struct("CharacterArchetype (CharacterInfoComponent)", 0x14B57E590, 80);
    find_flags("CharacterArchetype", 0x14B57E590);

    Message("\n################################################################\n");
    Message("  Done — paste output.  Especially interesting:\n");
    Message("  - Which offset consistently holds the same value across entries?\n");
    Message("  - Where does the pattern 0x0000000200000020 or similar appear?\n");
    Message("    (that's CPF_Net | CPF_ConstInit or other replication flags)\n");
    Message("################################################################\n");
}
