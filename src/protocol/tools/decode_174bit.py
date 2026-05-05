#!/usr/bin/env python3
"""Walk bits of a captured 174-bit bunch to find ACTUAL field structure."""
import json, sys, math
from pathlib import Path
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import phase1_parser as P

JSONL = HERE / "replay_full.jsonl"

def get_bit(data, bp): return (data[bp >> 3] >> (bp & 7)) & 1

def read_n(data, pos, n):
    """Read n bits LSB-first into integer."""
    v = 0
    for i in range(n):
        v |= get_bit(data, pos + i) << i
    return v, pos + n

def read_si(data, pos, max_val):
    if max_val <= 1: nb = 1
    else: nb = math.ceil(math.log2(max_val + 1))
    v, p = read_n(data, pos, nb)
    return v, p, nb

def read_sip(data, pos):
    """UE5 NETWORK SIP: bit 0 = continue flag, bits 1-7 = data."""
    val = 0; shift = 0
    for _ in range(5):
        b, pos = read_n(data, pos, 8)
        val |= ((b >> 1) & 0x7F) << shift
        shift += 7
        if not (b & 1): break
    return val, pos

def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    target_chseq = int(sys.argv[1]) if len(sys.argv) > 1 else 68
    target_pkt = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    with open(JSONL, 'r', encoding='utf-8') as f:
        for line in f:
            try: rec = json.loads(line)
            except: continue
            if rec.get('dir') != 'S>C': continue
            try: raw = bytes.fromhex(rec.get('hex',''))
            except: continue
            parsed = P.parse_packet(raw, 'S>C')
            if parsed is None: continue
            for b in parsed['bunches']:
                if b['ch'] != 3 or not b['reliable']: continue
                if b['ch_seq'] != target_chseq: continue
                if target_pkt and parsed['seq'] != target_pkt: continue
                if b['bunch_data_bits'] != 174: continue
                # Found
                data = parsed['inner_data']
                ds = b['data_start']
                size = b['bunch_data_bits']
                print(f"chSeq={b['ch_seq']} pkt={parsed['seq']} size={size}")
                print(f"hex: {P.extract_realigned(data, ds, size).hex()}")
                # Print bit string
                bits = ''.join(str(get_bit(data, ds+i)) for i in range(size))
                print("\nBits (LSB-first within bytes):")
                for i in range(0, len(bits), 8):
                    print(f"  bit {i:3d}: {bits[i:i+8]}")
                
                # Walk the structure
                pos = ds
                bOut, pos = read_n(data, pos, 1); print(f"\n[bit 0] bOutermostEnd = {bOut}")
                bChAct, pos = read_n(data, pos, 1); print(f"[bit 1] bIsChannelActor = {bChAct}")
                npb, pos = read_sip(data, pos); print(f"[bit 2..] SIP NumPayloadBits = {npb} (consumed {pos - ds - 2} bits)")
                inner_start = pos
                inner_end = inner_start + npb
                end_marker_bit = ds + size - 1
                print(f"  inner range: bit {inner_start - ds} .. {inner_end - ds} ({npb} bits)")
                print(f"  end marker at bit {end_marker_bit - ds}: {get_bit(data, end_marker_bit)}")
                print()
                
                # Try several FIELD-format hypotheses
                print("=== HYPOTHESES ===")
                
                # H1: [SerializeInt(handle, 4096) 12 bits][SIP NumBits][payload]
                p = inner_start
                h, p, _ = read_si(data, p, 4096)
                sn, p = read_sip(data, p)
                pay = inner_end - p
                print(f"H1 [SI(4096)]: handle={h} SIP(NumBits)={sn} payload_bits_left={pay}")
                
                # H2: [SerializeInt(handle, MAX) variable][NO SIP][128 bit GUID][trailer]
                # Try with no SIP, find what makes 128 bits available before trailer
                # If trailer is fixed 16 bits: handle uses 156-128-16 = 12 bits → SI(4096)
                # If trailer is fixed 8 bits: handle uses 156-128-8 = 20 bits → MAX 2^20
                # If no trailer: handle = 28 bits → unusual
                
                # H3: [SIP(handle+1)][128 bit GUID][SIP(0) terminator]
                p = inner_start
                sh, p = read_sip(data, p)
                guid_start = p
                guid_end = guid_start + 128
                term_start = guid_end
                if term_start < inner_end:
                    term, after_term = read_sip(data, term_start)
                    print(f"H3 [SIP(handle+1)+128GUID+SIP(0)]: handle={sh-1 if sh > 0 else None}")
                    print(f"  GUID bits: {P.extract_realigned(data, guid_start, 128).hex()}")
                    print(f"  trailing SIP value: {term} ({after_term - term_start} bits) | remaining: {inner_end - after_term}")
                
                # H4: [12 bit handle][1 bit null][128 bit GUID][trailer]
                p = inner_start
                h, p, _ = read_si(data, p, 4096)
                nb, p = read_n(data, p, 1)
                guid_hex = P.extract_realigned(data, p, 128).hex()
                trailer = inner_end - p - 128
                print(f"H4 [SI(4096)+1bit+128GUID+trailer]: handle={h} null_bit={nb} guid={guid_hex} trailer={trailer} bits")
                if trailer > 0:
                    tval, _ = read_n(data, p + 128, trailer)
                    print(f"  trailer raw: {tval} (hex: {tval:x})")
                
                # H5: [12 bit handle][16 bit raw NumBits][128 bit GUID]
                p = inner_start
                h, p, _ = read_si(data, p, 4096)
                rb, p = read_n(data, p, 16)
                guid_hex = P.extract_realigned(data, p, 128).hex()
                tail = inner_end - p - 128
                print(f"H5 [SI(4096)+16bitRaw+128GUID]: handle={h} raw16={rb} (=0x{rb:04x}) guid={guid_hex} tail={tail}")
                
                return
    print("Not found")

main()
