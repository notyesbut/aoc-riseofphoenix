#!/usr/bin/env python3
"""Bit-aligned PME (PackageMap Export) bunch walker.

Wire format from package_map_exporter.cpp:
  PME section in a bunch payload:
    [1 bit] bHasRepLayoutExport = 0
    [u32]   NumGUIDsInBunch (LSB-first)
    For each:
      [128 bits] FIntrepidNetworkGUID (ObjectId u64 + ServerId u32 + Randomizer u32)
      if GUID.ObjectId != 0:
        [8 bits] ExportFlags (bit 0 = bHasPath, bit 1 = bNoLoad, bit 2 = bHasChecksum)
        if bHasPath:
          [recursive outer entry]
          [FString path] (int32 save_num + ASCII bytes + NUL)
          if bHasChecksum:
            [u32] checksum

Find what NetGUID 7193 (subobject reference on ch=3) actually maps to.
"""
import struct, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PATH = r"C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\replay_data.bin"

def rb(buf, off, n=1):
    v = 0
    for i in range(n):
        v |= ((buf[(off+i)>>3] >> ((off+i)&7)) & 1) << i
    return v, off + n

def rsip(buf, off):
    val = 0; sh = 0
    for _ in range(10):
        bv, off = rb(buf, off, 8)
        val |= (bv >> 1) << sh
        if (bv & 1) == 0: break
        sh += 7
    return val, off

def read_intrepid_guid(buf, off):
    """Read 128-bit FIntrepidNetworkGUID = 4 × u32 LSB-first.
    Layout: ObjectId u64 (low 32 + high 32), ServerId u32, Randomizer u32."""
    obj_lo, off = rb(buf, off, 32)
    obj_hi, off = rb(buf, off, 32)
    srv,    off = rb(buf, off, 32)
    rnd,    off = rb(buf, off, 32)
    obj_id = obj_lo | (obj_hi << 32)
    return (obj_id, srv, rnd), off

def read_fstring(buf, off, max_chars=512):
    """Read FString: int32 save_num + save_num bytes (ASCII or UCS2)."""
    save_num, off = rb(buf, off, 32)
    # Convert from unsigned to signed
    if save_num >= 0x80000000:
        save_num -= 0x100000000
    if save_num == 0:
        return "", off
    if save_num < 0:
        # UCS2
        n = -save_num
        if n > max_chars: return "<TOO_LONG_UCS2>", off
        s = ""
        for i in range(n):
            wc, off = rb(buf, off, 16)
            if wc == 0: break
            if wc < 128: s += chr(wc)
            else: s += "?"
        return s, off
    else:
        # ASCII
        if save_num > max_chars: return f"<TOO_LONG_ASCII_{save_num}>", off
        s = ""
        for i in range(save_num):
            c, off = rb(buf, off, 8)
            if c == 0: break
            if 32 <= c < 127: s += chr(c)
            else: s += f"\\x{c:02x}"
        return s, off

def read_export_entry(buf, off, depth=0):
    """Recursively read one export entry. Returns (entry_dict, new_off)."""
    guid, off = read_intrepid_guid(buf, off)
    if guid[0] == 0:
        return {"guid": guid, "is_terminator": True}, off
    flags, off = rb(buf, off, 8)
    has_path = bool(flags & 0x01)
    no_load  = bool(flags & 0x02)
    has_checksum = bool(flags & 0x04)
    entry = {
        "guid": guid,
        "flags": flags,
        "has_path": has_path,
        "no_load": no_load,
        "has_checksum": has_checksum,
        "outer": None,
        "path": "",
        "checksum": 0,
    }
    if has_path:
        outer, off = read_export_entry(buf, off, depth + 1)
        entry["outer"] = outer
        path, off = read_fstring(buf, off)
        entry["path"] = path
        if has_checksum:
            cs, off = rb(buf, off, 32)
            entry["checksum"] = cs
    return entry, off

def read_pme_section(buf, off, max_bits, label=""):
    """Read PME section at given bit offset. Returns list of entries."""
    has_rep_layout, off = rb(buf, off, 1)
    if has_rep_layout != 0:
        return [], off, "first bit was 1 (RepLayout export, not NetGUID)"
    num_guids, off = rb(buf, off, 32)
    if num_guids > 1000:
        return [], off, f"NumGUIDs={num_guids} suspicious — likely misframe"
    entries = []
    for i in range(num_guids):
        if off >= max_bits:
            return entries, off, f"ran out of bits at entry {i}"
        try:
            entry, off = read_export_entry(buf, off)
            entries.append(entry)
        except Exception as e:
            return entries, off, f"exception at entry {i}: {e}"
    return entries, off, "OK"

def fmt_guid(g):
    obj, srv, rnd = g
    return f"Obj={obj} Srv={srv} Rnd={rnd}"

def fmt_path_chain(entry, indent=0):
    """Recursively format the path chain."""
    prefix = "  " * indent
    if entry.get("is_terminator"):
        return f"{prefix}<terminator>"
    s = f"{prefix}{fmt_guid(entry['guid'])} flags={entry['flags']:#x} path='{entry['path']}'"
    if entry["outer"]:
        s += "\n" + fmt_path_chain(entry["outer"], indent + 1)
    return s

# ─── Parse all PME-bearing bunches in first 30 packets ─────────────────
with open(PATH, 'rb') as f: data = f.read()
p = 12 + 6 + 6 + 1 + 1 + 2 + 2 + 4

print("Scanning first 30 packets for PME bunches...\n")
all_entries = []  # (pkt_idx, ch, entry)

for i in range(30):
    ts, raw_size, oseq, oack, bstart, bbits = struct.unpack_from('<IHHHHH', data, p); p += 14
    p += 6
    raw = data[p:p+raw_size]; p += raw_size
    if bbits < 30: continue

    b = bstart
    end_all = bstart + bbits
    bunch_idx = 0
    try:
        while b < end_all - 20:
            b0 = b
            v, b = rb(raw, b, 1); b_ctrl = v
            b_open = 0
            if b_ctrl:
                v, b = rb(raw, b, 1); b_open = v
                v, b = rb(raw, b, 1); b_close = v
                if b_close:
                    # CloseReason SerializeInt(7)
                    bits_consumed = 0
                    for _ in range(3):
                        bits_consumed += 1
                    b += bits_consumed
            v, b = rb(raw, b, 1); rp = v
            v, b = rb(raw, b, 1); rel = v
            ch, b = rsip(raw, b)
            if ch > 1000: break
            v, b = rb(raw, b, 1); pme = v
            v, b = rb(raw, b, 1); mbg = v
            v, b = rb(raw, b, 1); part = v
            if rel:
                nb = 10 if ch == 0 else 12
                v, b = rb(raw, b, nb)
            b_pi = 0
            if part:
                v, b = rb(raw, b, 1); b_pi = v
                v, b = rb(raw, b, 1); v, b = rb(raw, b, 1)
            chname_present = (rel or b_open) and (not part or b_pi)
            if chname_present:
                v, b = rb(raw, b, 1)
                if v: ig, b = rsip(raw, b)
                else:
                    save_num, b = rb(raw, b, 32)
                    n = save_num
                    if n > 0 and n < 256: b += n * 8
                    elif n < 0: b += -n * 16
            bdb, b = rb(raw, b, 13)
            if bdb > end_all - b: break
            payload_start = b
            payload_end = b + bdb

            if pme:
                # Read PME section at start of payload
                entries, after, status = read_pme_section(raw, payload_start, payload_end,
                                                          label=f"pkt#{i}.bunch{bunch_idx} ch={ch}")
                if entries or "OK" in status:
                    print(f"pkt#{i}.bunch{bunch_idx}  ch={ch}  PME={pme} bdb={bdb}  → {len(entries)} entries [{status}]")
                    for ent in entries[:30]:
                        if ent.get("is_terminator"):
                            print(f"   <terminator>")
                        else:
                            print(f"   ObjId={ent['guid'][0]:>6d}  Srv={ent['guid'][1]}  Rnd={ent['guid'][2]}  flags={ent['flags']:#04x}  path='{ent['path']}'")
                            if ent["outer"] and not ent["outer"].get("is_terminator"):
                                outer = ent["outer"]
                                print(f"     outer: ObjId={outer['guid'][0]}  path='{outer['path']}'")
                            all_entries.append((i, ch, ent))
            b = payload_end
            bunch_idx += 1
            if bunch_idx > 30: break
    except Exception as e:
        pass

# Look for GUID 7193
print(f"\n{'='*70}")
print(f"SEARCHING FOR NetGUID ObjectId=7193")
print(f"{'='*70}")
matches = [(pkt, ch, e) for pkt, ch, e in all_entries if e["guid"][0] == 7193]
if matches:
    print(f"\nFound {len(matches)} export entries for ObjectId=7193:")
    for pkt, ch, e in matches:
        print(f"\n  pkt#{pkt} ch={ch}:")
        print(fmt_path_chain(e, indent=2))
else:
    print(f"\nNo PME exports found for ObjectId=7193 in first 30 packets.")
    print(f"Total exports collected: {len(all_entries)}")
    # Show all unique ObjectIds found
    ids = sorted(set(e["guid"][0] for _,_,e in all_entries if e["guid"][0] != 0))
    print(f"Unique ObjectIds exported in first 30 packets: {ids[:50]}")
