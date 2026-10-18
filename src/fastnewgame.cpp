#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>
#include <limits>
#include <string>
#include <sstream>

namespace {
constexpr DWORD kImageBase = 0x00400000;
constexpr DWORD kGenerationStart = 0x005D36D8;
constexpr DWORD kGenerationEnd   = 0x005D6D94;
constexpr DWORD kCalcGalaxy     = 0x004D75BC;
constexpr DWORD kCalcPlayerStar = 0x004D75D0;
constexpr DWORD kThreadExecute  = 0x0072F91C;
constexpr DWORD kThreadPointer  = 0x00881FD0;
constexpr DWORD kJobOffset      = 0x2C;
constexpr wchar_t kId[] = L"FHD_FastNewGame";
constexpr wchar_t kVersion[] = L"0.3.0";
constexpr std::uint32_t kHostApi = 1;

using LogFn = void (WINAPI*)(const wchar_t*, const wchar_t*);
using ConfigBoolFn = BOOL (WINAPI*)(const wchar_t*, const wchar_t*, const wchar_t*, BOOL);
struct Host {
    std::uint32_t size;
    std::uint32_t apiVersion;
    HMODULE gameModule;
    const wchar_t* gameRoot;
    const wchar_t* executablePath;
    const wchar_t* pluginRoot;
    const wchar_t* configPath;
    LogFn log;
    ConfigBoolFn configGetBool;
    void* configGetInt;
    void* configGetString;
};
struct Info {
    std::uint32_t size;
    std::uint32_t requiredHostApi;
    wchar_t id[64];
    wchar_t version[32];
    wchar_t description[160];
    std::uint64_t exclusiveCapabilities;
};
constexpr std::size_t kInfoBase = offsetof(Info, exclusiveCapabilities);
constexpr std::size_t kHostBase = offsetof(Host, configGetBool);
using CalcFn = void (__cdecl*)();
struct Patch {
    BYTE* instruction = nullptr;
    DWORD originalTarget = 0;
    BYTE originalBytes[5] = {};
    bool installed = false;
};
std::array<Patch, 3> g_patches;
BYTE* g_base = nullptr;
DWORD g_imageSize = 0;
LogFn g_log = nullptr;
CalcFn g_origGalaxy = nullptr;
CalcFn g_origStar = nullptr;

void Log(const std::wstring& s) {
    if (g_log) g_log(kId, s.c_str());
}

BYTE* FromAddress(DWORD originalVa) {
    if (originalVa < kImageBase) return nullptr;
    DWORD rva = originalVa - kImageBase;
    return (g_base && rva < g_imageSize) ? g_base + rva : nullptr;
}

bool IsExecutable(BYTE* p, DWORD length = 1) {
    if (!p || !g_base || p < g_base || static_cast<std::size_t>(p - g_base) + length > g_imageSize) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(g_base + dos->e_lfanew);
    const auto* section = IMAGE_FIRST_SECTION(nt);
    const std::size_t rva = static_cast<std::size_t>(p - g_base);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD start = section[i].VirtualAddress;
        DWORD size = section[i].Misc.VirtualSize;
        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            rva >= start && rva + length <= static_cast<std::size_t>(start) + size) return true;
    }
    return false;
}

bool PrepareImage(HMODULE module, std::wstring& error) {
    if (!module) { error = L"missing game module"; return false; }
    g_base = reinterpret_cast<BYTE*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(g_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > 4096) {
        error = L"invalid DOS header"; return false;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(g_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt->OptionalHeader.ImageBase != kImageBase) {
        error = L"unsupported executable architecture/layout"; return false;
    }
    g_imageSize = nt->OptionalHeader.SizeOfImage;
    if (g_imageSize < kThreadPointer - kImageBase + sizeof(void*)) {
        error = L"image too small for 2.1.2500 offsets"; return false;
    }
    if (!IsExecutable(FromAddress(kGenerationStart), kGenerationEnd-kGenerationStart) ||
        !IsExecutable(FromAddress(kCalcGalaxy), 8) ||
        !IsExecutable(FromAddress(kCalcPlayerStar), 8) ||
        !IsExecutable(FromAddress(kThreadExecute), 8)) {
        error = L"expected executable sections not found"; return false;
    }
    g_origGalaxy = reinterpret_cast<CalcFn>(FromAddress(kCalcGalaxy));
    g_origStar = reinterpret_cast<CalcFn>(FromAddress(kCalcPlayerStar));
    return true;
}

bool Discover(std::wstring& error) {
    unsigned galaxy = 0, star = 0;
    BYTE* begin = FromAddress(kGenerationStart);
    BYTE* end = FromAddress(kGenerationEnd);
    if (!begin || !end || end <= begin) { error = L"generator bounds unavailable"; return false; }
    for (BYTE* p = begin; p + 5 <= end; ++p) {
        if (*p != 0xE8) continue;
        std::int32_t rel = 0;
        std::memcpy(&rel, p+1, sizeof(rel));
        BYTE* target = p + 5 + rel;
        if (target != FromAddress(kCalcGalaxy) && target != FromAddress(kCalcPlayerStar)) continue;
        if (galaxy + star >= g_patches.size()) { error = L"too many matching call sites"; return false; }
        Patch& rec = g_patches[galaxy + star];
        rec.instruction = p;
        rec.originalTarget = target == FromAddress(kCalcGalaxy) ? kCalcGalaxy : kCalcPlayerStar;
        std::memcpy(rec.originalBytes, p, sizeof(rec.originalBytes));
        if (target == FromAddress(kCalcGalaxy)) ++galaxy; else ++star;
        p += 4;
    }
    // Exactly one initial galaxy turn and one per loop, and one player-star turn per loop.
    if (galaxy != 2 || star != 1) {
        std::wostringstream o;
        o << L"unsupported code: galaxy_call_sites=" << galaxy << L" star_call_sites=" << star;
        error = o.str();
        return false;
    }
    return true;
}

// Delphi TThreadCalc.Execute expects its object instance in EAX, with no stack args.
// Calling the original method keeps the full 300-day game logic intact.
void InvokeOriginalCalculation(DWORD job, CalcFn fallback) {
    if (!g_base || !fallback) return;
    void* context = *reinterpret_cast<void**>(FromAddress(kThreadPointer));
    if (!context) { fallback(); return; }
    *reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(context) + kJobOffset) = job;
    void* execute = FromAddress(kThreadExecute);
    __asm {
        mov eax, context
        call execute
    }
}

extern "C" void __cdecl FastGalaxy() { InvokeOriginalCalculation(1, g_origGalaxy); }
extern "C" void __cdecl FastPlayerStar() { InvokeOriginalCalculation(2, g_origStar); }

bool ModifyPatch(Patch& patch, bool apply, std::wstring& error) {
    if (!patch.instruction) { error = L"empty patch"; return false; }
    BYTE desired[5] = {};
    if (apply) {
        desired[0] = 0xE8;
        BYTE* destination = reinterpret_cast<BYTE*>(
            patch.originalTarget == kCalcGalaxy ? reinterpret_cast<void*>(&FastGalaxy) :
                                                   reinterpret_cast<void*>(&FastPlayerStar));
        std::intptr_t displacement = destination - (patch.instruction + 5);
        if (displacement < std::numeric_limits<std::int32_t>::min() ||
            displacement > std::numeric_limits<std::int32_t>::max()) {
            error = L"native DLL too far from game image"; return false;
        }
        const auto rel = static_cast<std::int32_t>(displacement);
        std::memcpy(desired + 1, &rel, sizeof(rel));
        if (std::memcmp(patch.instruction, patch.originalBytes, 5) != 0) {
            error = L"conflicting engine hook detected"; return false;
        }
    } else {
        std::memcpy(desired, patch.originalBytes, sizeof(desired));
    }
    DWORD previous = 0;
    if (!VirtualProtect(patch.instruction, 5, PAGE_EXECUTE_READWRITE, &previous)) {
        error = L"VirtualProtect failed"; return false;
    }
    std::memcpy(patch.instruction, desired, 5);
    FlushInstructionCache(GetCurrentProcess(), patch.instruction, 5);
    DWORD ignored = 0;
    VirtualProtect(patch.instruction, 5, previous, &ignored);
    patch.installed = apply;
    return true;
}

bool Install(std::wstring& error) {
    unsigned completed = 0;
    for (auto& patch: g_patches) {
        if (!ModifyPatch(patch, true, error)) {
            for (unsigned i=completed; i>0; --i) {
                std::wstring ignored;
                ModifyPatch(g_patches[i-1], false, ignored);
            }
            return false;
        }
        ++completed;
    }
    return true;
}
} // anonymous namespace

extern "C" BOOL WINAPI XenoPlugin_Query(Info* info) {
    if (!info || info->size < kInfoBase) return FALSE;
    info->requiredHostApi = kHostApi;
    lstrcpynW(info->id, kId, static_cast<int>(_countof(info->id)));
    lstrcpynW(info->version, kVersion, static_cast<int>(_countof(info->version)));
    lstrcpynW(info->description, L"Preserves all 300 original preparation turns; synchronizes 601 calculations",
             static_cast<int>(_countof(info->description)));
    if (info->size >= sizeof(Info)) info->exclusiveCapabilities = 0;
    return TRUE;
}

extern "C" DWORD WINAPI XenoPlugin_Initialize(const Host* host) {
    if (!host || host->size < kHostBase || host->apiVersion < kHostApi || !host->gameModule)
        return 1;
    g_log = host->log;
    if (host->size >= offsetof(Host, configGetInt) && host->configGetBool &&
        !host->configGetBool(host->configPath, L"FastNewGame", L"Enabled", TRUE)) {
        Log(L"disabled by configuration");
        return 0;
    }
    std::wstring error;
    if (!PrepareImage(host->gameModule, error) || !Discover(error) || !Install(error)) {
        Log(L"native patch was NOT installed: " + error);
        return 2;
    }
    Log(L"installed 3 call-site hooks; all 300 original preparation days preserved");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);
    return TRUE;
}
