# UE5 PackageMapClient Internals — NetGUID Export/Import Wire Format

Source: `C:\dev\UnrealEngine\Engine\Source\Runtime\Engine\Private\PackageMapClient.cpp`

---

## 1. FNetworkGUID — On-Wire Serialization

```cpp
// File: Engine/Source/Runtime/Core/Public/Misc/NetworkGuid.h
class FNetworkGUID
{
public:
    union
    {
        uint32 Value;       // deprecated in 5.3
        uint64 ObjectId;    // the actual field used
    };

    friend FArchive& operator<<(FArchive& Ar, FNetworkGUID& G)
    {
        Ar.SerializeIntPacked64(G.ObjectId);
        return Ar;
    }

    bool IsDynamic() const { return IsValid() && !IsStatic(); }
    bool IsStatic()  const { return ObjectId & 1; }
    bool IsValid()   const { return ObjectId > 0; }
    bool IsDefault() const { return (ObjectId == 1); } // A valid but unassigned NetGUID

    static FNetworkGUID GetDefault() { return CreateFromIndex(0, true); }

    static FNetworkGUID CreateFromIndex(uint64 NetIndex, bool bIsStatic)
    {
        FNetworkGUID NewGuid;
        NewGuid.ObjectId = NetIndex << 1 | (bIsStatic ? 1 : 0);
        return NewGuid;
    }
};
```

### SerializeIntPacked64 encoding (varint, 7-bit + 1-bit more flag, LSB first)

```cpp
// File: Engine/Source/Runtime/Core/Private/Serialization/Archive.cpp
void FArchive::SerializeIntPacked64(uint64& Value)
{
    if (IsLoading())
    {
        Value = 0;
        uint8 cnt = 0;
        uint8 more = 1;
        while (more)
        {
            uint8 NextByte;
            Serialize(&NextByte, 1);           // Read next byte
            more = NextByte & 1;               // bit 0 = "more" flag
            NextByte = NextByte >> 1;           // Shift to get actual 7 bit value
            Value += (uint64)NextByte << (7 * cnt++);
        }
    }
    else
    {
        uint8 PackedBytes[10];
        int32 PackedByteCount = 0;
        uint64 Remaining = Value;
        while (true)
        {
            uint8 nextByte = Remaining & 0x7f;  // Get next 7 bits to write
            Remaining = Remaining >> 7;
            nextByte = nextByte << 1;            // Make room for 'more' bit
            if (Remaining > 0)
            {
                nextByte |= 1;                   // set more bit
                PackedBytes[PackedByteCount++] = nextByte;
            }
            else
            {
                PackedBytes[PackedByteCount++] = nextByte;
                break;
            }
        }
        Serialize(PackedBytes, PackedByteCount);
    }
}
```

**Key:** Each byte: bit0 = "more bytes follow", bits 1-7 = 7 data bits.
Value is reconstructed: `sum of (byte >> 1) << (7 * byte_index)`.

---

## 2. FExportFlags — The Export Flags Byte

```cpp
struct FExportFlags
{
    union
    {
        struct
        {
            uint8 bHasPath              : 1;  // bit 0: path name follows
            uint8 bNoLoad               : 1;  // bit 1: client should NOT try to load this
            uint8 bHasNetworkChecksum   : 1;  // bit 2: a uint32 network checksum follows
        };
        uint8 Value;
    };

    FExportFlags()
    {
        Value = 0;
    }
};
```

**YES, ExportFlags is always a single `uint8` (8 bits)**, serialized with `Ar << ExportFlags.Value`.
Only 3 bits are defined:
- **Bit 0** (`bHasPath`): If set, object path (FString), outer (recursive NetGUID), and optionally checksum follow.
- **Bit 1** (`bNoLoad`): If set, client should not try to load/resolve this object.
- **Bit 2** (`bHasNetworkChecksum`): If set, a `uint32` network checksum follows after the path name.

---

## 3. ENetworkChecksumMode

```cpp
enum class ENetworkChecksumMode : uint8
{
    None            = 0,  // Don't use checksums
    SaveAndUse      = 1,  // Save checksums in stream, and use to validate while loading packages
    SaveButIgnore   = 2,  // Save checksums in stream, but ignore when loading packages
};
```

`bHasNetworkChecksum` is set to 1 when `NetworkChecksumMode != None`.

---

## 4. InternalWriteObject — WRITING (Server → Client)

```cpp
// Line 889-1025
void UPackageMapClient::InternalWriteObject(
    FArchive & Ar, FNetworkGUID NetGUID,
    UObject* Object, FString ObjectPathName, UObject* ObjectOuter)
{
    const bool bNoLoad = !GuidCache->CanClientLoadObject(Object, NetGUID);

    // Track MustBeMapped guids for async loading pause logic
    if (GuidCache->ShouldAsyncLoad() && IsNetGUIDAuthority()
        && !GuidCache->IsExportingNetGUIDBunch && !bNoLoad)
    {
        MustBeMappedGuidsInLastBunch.AddUnique(NetGUID);
    }

    // 1) Write NetGUID (varint packed64)
    Ar << NetGUID;
    NET_CHECKSUM(Ar);

    if (!NetGUID.IsValid())
        return;   // done

    // 2) Write ExportFlags
    FExportFlags ExportFlags;
    ExportFlags.bHasNetworkChecksum = (NetworkChecksumMode != None) ? 1 : 0;

    if (NetGUID.IsDefault())
    {
        // CLIENT sending default guid to server
        ExportFlags.bHasPath = 1;
        Ar << ExportFlags.Value;       // ← uint8
    }
    else if (GuidCache->IsExportingNetGUIDBunch)
    {
        // SERVER exporting GUID in a NetGUID bunch
        if (Object != nullptr)
            ExportFlags.bHasPath = ShouldSendFullPath(Object, NetGUID) ? 1 : 0;
        else
            ExportFlags.bHasPath = ObjectPathName.IsEmpty() ? 0 : 1;

        ExportFlags.bNoLoad = bNoLoad ? 1 : 0;
        Ar << ExportFlags.Value;       // ← uint8
    }
    // NOTE: if neither IsDefault nor IsExportingNetGUIDBunch, NO ExportFlags written!

    // 3) If bHasPath, write the full path data
    if (ExportFlags.bHasPath)
    {
        // Get object name and outer
        if (Object != nullptr) {
            ObjectPathName = Object->GetName();
            ObjectOuter = Object->GetOuter();
        }

        const bool bIsPackage = (NetGUID.IsStatic() && Object != nullptr && Object->GetOuter() == nullptr);

        // 3a) Recursively write outer's NetGUID (which may also have path)
        FNetworkGUID OuterNetGUID = GuidCache->GetOrAssignNetGUID(ObjectOuter);
        InternalWriteObject(Ar, OuterNetGUID, ObjectOuter, TEXT(""), nullptr);

        // 3b) Remap and write object name string
        GEngine->NetworkRemapPath(Connection, ObjectPathName, false);
        Ar << ObjectPathName;  // FString serialization

        // 3c) Optionally write network checksum (uint32)
        if (ExportFlags.bHasNetworkChecksum)
        {
            uint32 NetworkChecksum = GuidCache->GetNetworkChecksum(Object);
            Ar << NetworkChecksum;
        }

        // Cache the result
        if (FNetGuidCacheObject* CacheObject = GuidCache->ObjectLookup.Find(NetGUID))
        {
            CacheObject->PathName = FName(*ObjectPathName);
            CacheObject->OuterGUID = OuterNetGUID;
            CacheObject->bNoLoad = ExportFlags.bNoLoad;
            CacheObject->bIgnoreWhenMissing = ExportFlags.bNoLoad;
            CacheObject->NetworkChecksum = NetworkChecksum;
        }

        if (GuidCache->IsExportingNetGUIDBunch)
            CurrentExportNetGUIDs.Add(NetGUID);
    }
}
```

---

## 5. InternalLoadObject — READING (Client receives from Server)

```cpp
// Line 1082-1293
FNetworkGUID UPackageMapClient::InternalLoadObject(
    FArchive & Ar, UObject *& Object,
    const int32 InternalLoadObjectRecursionCount)
{
    if (InternalLoadObjectRecursionCount > INTERNAL_LOAD_OBJECT_RECURSION_LIMIT)
    {
        Ar.SetError();
        Object = NULL;
        return FNetworkGUID();
    }

    // ---- Step 1: Read NetGUID ----
    FNetworkGUID NetGUID;
    Ar << NetGUID;                    // SerializeIntPacked64
    NET_CHECKSUM_OR_END(Ar);          // no-op in shipping builds

    if (Ar.IsError() || !NetGUID.IsValid())
    {
        Object = NULL;
        return NetGUID;
    }

    // ---- Step 2: Try to resolve NetGUID from cache ----
    if (NetGUID.IsValid() && !NetGUID.IsDefault())
    {
        Object = GetObjectFromNetGUID(NetGUID, GuidCache->IsExportingNetGUIDBunch);
    }

    // ---- Step 3: Read ExportFlags (ONLY if Default or Exporting) ----
    FExportFlags ExportFlags;

    if (NetGUID.IsDefault() || GuidCache->IsExportingNetGUIDBunch)
    {
        Ar << ExportFlags.Value;      // ← uint8 read
        if (Ar.IsError()) { Object = NULL; return NetGUID; }
    }

    if (GuidCache->IsExportingNetGUIDBunch)
    {
        GuidCache->ImportedNetGuids.Add(NetGUID);
    }

    // ---- Step 4: If bHasPath, read the full export data ----
    if (ExportFlags.bHasPath)
    {
        UObject* ObjOuter = NULL;

        // 4a) Recursively read outer's NetGUID (and its path if needed)
        FNetworkGUID OuterGUID = InternalLoadObject(Ar, ObjOuter, InternalLoadObjectRecursionCount + 1);

        // 4b) Read object name (FString)
        FString ObjectName;
        Ar << ObjectName;

        // 4c) Read network checksum if flagged
        uint32 NetworkChecksum = 0;
        if (ExportFlags.bHasNetworkChecksum)
        {
            Ar << NetworkChecksum;     // uint32
        }

        const bool bIsPackage = NetGUID.IsStatic() && !OuterGUID.IsValid();

        if (Ar.IsError()) { Object = NULL; return NetGUID; }

        GEngine->NetworkRemapPath(Connection, ObjectName, true);

        if (NetGUID.IsDefault())
        {
            // CLIENT → SERVER: server resolves the object and assigns a real NetGUID
            Object = StaticFindObject(UObject::StaticClass(), ObjOuter, *ObjectName, false);
            if (Object == nullptr && bIsPackage)
                Object = LoadPackage(nullptr, FPackagePath::FromPackageNameChecked(ObjectName), LOAD_None);

            // Validate checksum
            if (NetworkChecksum != 0 && NetworkChecksumMode == SaveAndUse)
            {
                const uint32 CompareNetworkChecksum = GuidCache->GetNetworkChecksum(Object);
                if (CompareNetworkChecksum != NetworkChecksum)
                {
                    // MISMATCH ERROR
                    Object = NULL;
                    return NetGUID;
                }
            }

            // Assign real guid
            NetGUID = GuidCache->GetOrAssignNetGUID(Object);
            HandleUnAssignedObject(Object);
            return NetGUID;
        }
        else if (Object != nullptr)
        {
            // Already resolved — sanity check only
            SanityCheckExport(GuidCache.Get(), Object, NetGUID, ObjectName, ObjOuter, OuterGUID, ExportFlags);
            return NetGUID;
        }

        // SERVER authority couldn't resolve → warning
        if (IsNetGUIDAuthority())
            return NetGUID;

        // CLIENT: register path and try to resolve
        const bool bIgnoreWhenMissing = ExportFlags.bNoLoad;
        GuidCache->RegisterNetGUIDFromPath_Client(
            NetGUID, ObjectName, OuterGUID, NetworkChecksum,
            ExportFlags.bNoLoad, bIgnoreWhenMissing);

        Object = GuidCache->GetObjectFromNetGUID(NetGUID, GuidCache->IsExportingNetGUIDBunch);
    }

    return NetGUID;
}
```

---

## 6. Wire Format Summary — InternalWriteObject / InternalLoadObject

### Case A: Normal object reference (NOT in export bunch, NOT default)
```
[NetGUID]        ← SerializeIntPacked64 (varint)
                   (NO ExportFlags, NO path — just the GUID reference)
```

### Case B: Inside a NetGUID Export Bunch (IsExportingNetGUIDBunch = true)
```
[NetGUID]        ← SerializeIntPacked64
[ExportFlags]    ← uint8
  If ExportFlags.bHasPath:
    [OuterNetGUID]       ← RECURSIVE InternalWriteObject (may itself have path!)
    [ObjectPathName]     ← FString (length-prefixed, see UE FString serialization)
    If ExportFlags.bHasNetworkChecksum:
      [NetworkChecksum]  ← uint32
```

### Case C: Default NetGUID (client → server, ObjectId == 1)
```
[NetGUID=1]      ← SerializeIntPacked64 (value 1 = static index 0)
[ExportFlags]    ← uint8 (always bHasPath=1)
  [OuterNetGUID]       ← RECURSIVE
  [ObjectPathName]     ← FString
  If ExportFlags.bHasNetworkChecksum:
    [NetworkChecksum]  ← uint32
```

---

## 7. NetGUID Export Bunch Framing

```
[0 bit]                     ← 1 bit: 0 = NetGUID export, 1 = RepLayout export
[NumGUIDsInBunch]           ← int32 (SerializeIntPacked or regular << operator)
[NET_CHECKSUM]              ← no-op in shipping
  For each GUID (NumGUIDsInBunch times):
    [InternalLoadObject data]  ← as described in Case B above
```

Written by `ExportNetGUID` → `ExportNetGUIDHeader` on server.
Read by `ReceiveNetGUIDBunch` on client.

---

## 8. ShouldSendFullPath

```cpp
bool UPackageMapClient::ShouldSendFullPath(const UObject* Object, const FNetworkGUID &NetGUID)
{
    if (!Connection) return false;

    // Already exported in this bunch?
    if (CurrentExportBunch != NULL && CurrentExportBunch->ExportNetGUIDs.Contains(NetGUID))
        return false;

    if (!NetGUID.IsValid()) return false;

    // Only export stably-named objects
    if (!Object->IsNameStableForNetworking())
        return false;   // Dynamic objects referenced by GUID only

    // Default GUIDs always need full path
    if (NetGUID.IsDefault())
        return true;

    // If not yet acknowledged by remote, send full path
    return !NetGUIDHasBeenAckd(NetGUID);
}
```

---

## 9. NET_CHECKSUM Macros

```cpp
// File: Engine/Source/Runtime/CoreUObject/Public/UObject/CoreNet.h

#define NET_ENABLE_CHECKSUMS 0

#if !(UE_BUILD_SHIPPING || UE_BUILD_TEST) && NET_ENABLE_CHECKSUMS

#define NET_CHECKSUM_OR_END(Ser) { SerializeChecksum(Ser, 0xE282FA84, true); }
#define NET_CHECKSUM(Ser)        { SerializeChecksum(Ser, 0xE282FA84, false); }
#define NET_CHECKSUM_CUSTOM(Ser, x) { SerializeChecksum(Ser, x, false); }
#define NET_CHECKSUM_IGNORE(Ser) { uint32 Magic = 0; Ser << Magic; }

#else

// No-ops in shipping/test builds (and NET_ENABLE_CHECKSUMS is 0 by default)
#define NET_CHECKSUM(Ser)
#define NET_CHECKSUM_IGNORE(Ser)
#define NET_CHECKSUM_CUSTOM(Ser, x)
#define NET_CHECKSUM_OR_END(ser)

#endif
```

**In production builds, NET_CHECKSUM macros are ALL no-ops. They write/read NOTHING.**

---

## 10. Key Answers to Your Questions

| Question | Answer |
|----------|--------|
| **All bits/fields of ExportFlags?** | 3 bits: `bHasPath` (bit 0), `bNoLoad` (bit 1), `bHasNetworkChecksum` (bit 2). Remaining bits 3-7 unused (always 0). |
| **Is ExportFlags always uint8?** | **YES**, always `uint8`. Serialized as `Ar << ExportFlags.Value`. |
| **When is ExportFlags read?** | **ONLY** when `NetGUID.IsDefault()` OR `GuidCache->IsExportingNetGUIDBunch`. Otherwise it's NOT present in the stream. |
| **When is the path FString read?** | After ExportFlags, only if `ExportFlags.bHasPath == 1`. Order: OuterNetGUID (recursive) → ObjectPathName (FString) → optional checksum. |
| **When is the checksum read?** | After ObjectPathName, only if `ExportFlags.bHasNetworkChecksum == 1`. It's a `uint32`. |
| **What determines whether to export a GUID as full?** | `ShouldSendFullPath()`: must be stably named, not yet ACKd, and valid. OR `IsDefault()` (always full). |
| **Is there an `bIsExporting` flag?** | Yes: `GuidCache->IsExportingNetGUIDBunch` (bool). It's set to `true` inside `ExportNetGUID` and `ReceiveNetGUIDBunch` via `TGuardValue`. Controls whether ExportFlags is read/written. |
| **`NETWORK_GUID_CHECKSUM` macro?** | **Does NOT exist** in UE5. You may be thinking of `NET_CHECKSUM` which is a no-op in shipping builds, or `bHasNetworkChecksum` in ExportFlags. |

---

## 11. FString Wire Format (for reference)

UE5 FString serialization via `FArchive& operator<<(FArchive&, FString&)`:
```
[int32 Length]    ← negative = UTF-16, positive = Latin1/UTF-8 (SaveNum)
[char[] Data]     ← Length bytes (includes null terminator in the count)
```
If Length < 0: UTF-16 encoding, actual char count = -Length, each char is 2 bytes.
If Length > 0: ASCII/Latin1, each char is 1 byte.
If Length == 0: empty string (no data bytes).
