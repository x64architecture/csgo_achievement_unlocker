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

#include <cstdio>

#include "IVEngineClient.h"
#include "IAchievementMgr.h"
#include "Utils.h"

using namespace csgo_achievement_unlocker;
using namespace csgo_achievement_unlocker::csgo;

static __declspec(naked) void __stdcall Invoke_AwardAchievement(int id, int nPlayerSlot)
{
    __asm {
        push    ebp
        mov     ebp, esp
        sub     esp, 10h
        
        push    ebx
        mov     ebx, id

        push    esi
        mov     esi, ecx
        mov     dword ptr [ebp - 8], esi

        // needed to preserve the stack edi is pushed in a part of
        // the code that we jump over
        push    edi

        jmp     eax
    }
}

static inline void Invoke_Stub_AwardAchievement(void* jump_target, void* thisptr, int id, int nPlayerSlot)
{
    // stdcall info
    // arguments pushed from right -> left
    // callee cleans up stack
    __asm {
        mov     eax, jump_target
        mov     ecx, thisptr
        push    nPlayerSlot
        push    id
        call    Invoke_AwardAchievement
    }
}

static bool UnlockAllAchievements(FILE* fp)
{
    HMODULE client_module = GetModuleHandleW(L"client_panorama.dll");
    if (client_module == NULL) {
        fprintf(fp, "GetModuleHandleW() failed!\n");
        return false;
    }
    fprintf(fp, "client.dll: [0x%p]\n", client_module);

    HMODULE engine_module = GetModuleHandleW(L"engine.dll");
    if (engine_module == NULL) {
        fprintf(fp, "GetModuleHandleW() failed!\n");
        return false;
    }
    fprintf(fp, "engine.dll: [0x%p]\n", engine_module);

    auto engine = CreateInterface<IVEngineClient*>(engine_module, "VEngineClient014");
    if (engine == nullptr) {
        fprintf(fp, "Failed to create VEngineClient interface!\n");
        return false;
    }
    fprintf(fp, "IVEngineClient: [0x%p]\n", engine);

    uintptr_t client_text_start, client_text_end;
    if (!GetTextSectionInformation((uintptr_t)client_module, client_text_start, client_text_end)) {
        fprintf(fp, "Failed to obtain text section information!\n");
        return false;
    }

    const uint8_t sig[] = { 0x8B, 0x7D, 0x0C, 0x83, 0xFF, 0x01, 0x0F, 0x8D };
    void* jump_target = MakePtr<void*>(FindPattern(client_text_start, client_text_end, sig, sizeof(sig)));
    if (jump_target == nullptr) {
        fprintf(fp, "Failed to find 'jump_target' signature!\n");
        return false;
    }
    fprintf(fp, "jump_target: [0x%p]\n", jump_target);

    IAchievementMgr* achievementMgr = engine->GetAchievementMgr();
    if (achievementMgr == nullptr) {
        fprintf(fp, "Failed to acquire 'achievementMgr'!\n");
        return false;
    }

    void* thisptr = MakePtr<void*>(MakePtr<uintptr_t*>(achievementMgr)[1]);
    // just because sv_cheats was on doesn't mean we 'cheat'
    ptrdiff_t wereCheatsEverOnOffset;
    {
        uintptr_t* vtable = *MakePtr<uintptr_t**>(achievementMgr);
        wereCheatsEverOnOffset = *MakePtr<ptrdiff_t*>(vtable[11], 5);
    }
    fprintf(fp, "were_cheats_ever_on offset: [0x%td]\n", wereCheatsEverOnOffset);
    *MakePtr<bool*>(thisptr, wereCheatsEverOnOffset) = false;

    // Print achievement information
    for (int i = 0; i < achievementMgr->GetAchievementCount(); i++) {
        // Use player index 0 for first player, split screen player has a different index
        IAchievement* achievement = achievementMgr->GetAchievementByIndex(i, 0);
        if (achievement == nullptr)
            continue;
        // All the other IAchievement functions I tested return the same value
        fprintf(fp, "name: %s, id: %d, state: %s\n",
          achievement->GetName(),
          achievement->GetAchievementID(),
          achievement->IsAchieved() ? "achieved" : "unachieved"
        );
    }

    for (int i = 0; i < achievementMgr->GetAchievementCount(); i++) {
        // Use player index 0 for first player, split screen player has a different index
        IAchievement* achievement = achievementMgr->GetAchievementByIndex(i, 0);
        if (achievement == nullptr)
            continue;

        if (!achievement->IsAchieved()) {
            Invoke_Stub_AwardAchievement(jump_target, thisptr, achievement->GetAchievementID(), 0);
            fprintf(fp, "Unlocking achievement %s [%d]\n", achievement->GetName(), achievement->GetAchievementID());
        }
    }

    return true;
}

static DWORD WINAPI cheat_thread(LPVOID hModule)
{
    FILE* fp;
    errno_t err;

    err = _wfopen_s(&fp, L"csgo_achievement_unlocker.txt", L"a+");
    if (err == 0 && fp != nullptr) {
        fprintf(fp, "[csgo_achievement_unlocker]\n\n");
        UnlockAllAchievements(fp);
        fprintf(fp, "\n");
        fclose(fp);
    }

    FreeLibraryAndExitThread((HMODULE)hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        if (CreateThread(NULL, 0, cheat_thread, hModule, 0, NULL) == NULL)
            return FALSE;
        return TRUE;
    }

    return TRUE;
}
