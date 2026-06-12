// Compatibility shims for MSVC STL vectorized algorithm helpers referenced by
// some vcpkg-built gRPC objects on the Visual Studio 18 2026 toolchain.
// Remove this file once the toolchain/runtime pair resolves these symbols
// through the standard import libraries again.

#if defined(_MSC_VER) && defined(_M_X64)

extern "C" const void* __stdcall __std_min_element_8i(const void* first,
                                                       const void* last) noexcept {
    const auto* cursor = static_cast<const long long*>(first);
    const auto* end = static_cast<const long long*>(last);
    if (cursor == end) {
        return first;
    }

    const auto* best = cursor;
    for (++cursor; cursor != end; ++cursor) {
        if (*cursor < *best) {
            best = cursor;
        }
    }
    return best;
}

extern "C" const void* __stdcall __std_max_element_d_(const void* first,
                                                       const void* last) noexcept {
    const auto* cursor = static_cast<const double*>(first);
    const auto* end = static_cast<const double*>(last);
    if (cursor == end) {
        return first;
    }

    const auto* best = cursor;
    for (++cursor; cursor != end; ++cursor) {
        if (*best < *cursor) {
            best = cursor;
        }
    }
    return best;
}

#endif
