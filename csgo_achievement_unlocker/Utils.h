/*
 * Copyright (c) 2019, x64architecture (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <cstdint>

namespace csgo_achievement_unlocker {

template <typename T>
T MakePtr(uintptr_t base, ptrdiff_t offset = 0)
{
    return reinterpret_cast<T>(base + offset);
}

template <typename T>
T MakePtr(const void* base, ptrdiff_t offset = 0)
{
    return reinterpret_cast<T>((uintptr_t)base + offset);
}

template <typename T>
T CreateInterface(HMODULE module, const char* interface)
{
    using CreateInterfaceFn = void*(__cdecl*)(const char*, int*);
    auto CreateInterface = MakePtr<CreateInterfaceFn>(GetProcAddress(module, "CreateInterface"));
    return MakePtr<T>(CreateInterface(interface, nullptr));
}

static uintptr_t FindPattern(uintptr_t base, uintptr_t end, const uint8_t* signature, size_t signatureLength)
{
    uint8_t* basePtr = MakePtr<uint8_t*>(base);
    uint8_t* endPtr = MakePtr<uint8_t*>(end);

    auto compare = [](uint8_t val1, uint8_t val2) {
        return (val1 == val2 || val2 == 0);
    };
    uint8_t* search = std::search(basePtr, endPtr, signature, signature + signatureLength, compare);
    if (search == endPtr)
        return 0;

    return reinterpret_cast<uintptr_t>(search);
}

static bool GetTextSectionInformation(uintptr_t imageBase, uintptr_t& sectionStart, uintptr_t& sectionEnd)
{
    const IMAGE_DOS_HEADER* dosHdr;
    const IMAGE_NT_HEADERS* ntHdr;

    dosHdr = MakePtr<const IMAGE_DOS_HEADER*>(imageBase);
    ntHdr = MakePtr<const IMAGE_NT_HEADERS*>(dosHdr, dosHdr->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i, ++section) {
        const char* sectionName = MakePtr<const char*>(section->Name);
        if (strncmp(sectionName, ".text\0\0\0", 8) == 0) {
            sectionStart = imageBase + section->VirtualAddress;
            sectionEnd = sectionStart + section->Misc.VirtualSize;
            return true;
        }
    }

    return false;
}

} // namespace csgo_achievement_unlocker