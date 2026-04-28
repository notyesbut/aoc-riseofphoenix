## Name-update cmd_index Verification Across Sessions

### Investigation Summary

**Scope**: Analyzed 179 capture logs from 2026-04-16 through 2026-04-23 (before hybrid mode implementation)

**Logs Analyzed**: From `dist/Release/logs/capture-202604*.jsonl` directory

**Search Strategy**:
1. Searched for cmd_index 0x6a (0x6A) byte patterns in all game packets
2. Looked for 4-byte LE length prefixes followed by printable ASCII strings
3. Examined both S>C and C>S packets for name-like FStrings
4. Checked for patterns with custom_name metadata

### Findings

**0x6a Pattern Locations**: ✓ CONFIRMED PRESENT

The cmd_index byte `0x6a` was found in multiple capture logs:
- File: `capture-20260418-181518.jsonl` - Found at 10+ locations across multiple packet sizes
- File: `capture-20260418-184847.jsonl` - Found in large C>S packets (1024 bytes)
- File: `capture-20260419-*.jsonl` - Consistent pattern across multiple sessions

**Wire Format Analysis**:

The 0x6a byte appears followed by binary data (not simple LE length + string):
```
Example from capture-20260418-181518.jsonl:
6a 96 82 60 6e ... (followed by non-ASCII binary)
6a b2 60 63 81 ... (followed by non-ASCII binary)
6a b2 e0 04 80 ... (followed by non-ASCII binary)
```

This differs from the hypothesized format `[0x6a][4B LE length][ASCII][NUL]`. The data after 0x6a appears to be encoded property updates or other structured data, not direct FString name fields.

### FString Name Search Results

**Search for 4-byte LE length + ASCII pattern**: Found 159 potential candidates across ranger PCAP
- Most candidates were 3-6 bytes of non-dictionary text
- Appeared in packets #215 and later
- Examples: ' #2', ' #B', 'A%2', 'yVmHMc', '(w@s'
- Conclusion: Game event data, not player names

### Limitation

The capture logs from Apr 16-23 appear to be predominantly:
- Initial authentication/NMT (Network Message Transport) protocol
- Property replication streams
- KeepAlive packets
- Limited player spawn or name-update events

**The logs do not contain explicit character name metadata or simple FString patterns for names.**

### Technical Observations

1. The 0x6a command index IS present in network traffic (confirmed in multiple logs)
2. The command is likely used for property updates or game state changes
3. The wire format is more complex than simple length-prefixed strings
4. Name updates (if 0x6a is indeed the name command) are likely encoded within UE5's bit-packed replication stream

### Recommendation for Future Analysis

To definitively map the name-update wire format:
1. Use existing decoder scripts (`src/protocol/tools/decode_pkt78.py`, etc.) to parse full bit-level structure
2. Examine packets with known character name changes (spawn with explicit name vs respawn)
3. Correlate 0x6a appearances with nearby FName/FString fields in property streams
4. Create test cases with controlled name variations to observe byte-level changes

### Conclusion

**cmd=0x6A presence**: ✓ CONFIRMED in network traffic
**Universal name marker**: ? INCONCLUSIVE (pattern present, but format not decoded)
**Length prefix format**: ? NOT MATCHED in observed data

The simple format `[0x6A][4B LE length][ASCII][NUL]` does not appear in the analyzed logs. The actual wire encoding is likely part of the larger UE5 bunch/property replication protocol.
