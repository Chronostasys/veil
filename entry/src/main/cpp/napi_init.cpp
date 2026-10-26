// NAPI shim for the Go engine.
//
// The HAP must build before `libveilcore.so` exists, so this translation unit
// never links against it: it dlopen()s the engine on first use and forwards the
// three exported entry points. Every function returns a JSON string; the ArkTS
// side parses it and decides what to show.
//
// Go contract (core/cmd, c-shared):
//   char* VeilStart(char* configPath, char* socketPath);
//   char* VeilCall(char* method, char* params);
//   char* VeilShutdown();
// The returned pointer is owned by Go and only valid until the next call into
// the engine — we copy it into a std::string immediately and never free it.

#include <dlfcn.h>
#include <string>

#include "napi/native_api.h"
#include <hilog/log.h>

// When the Go engine is linked in statically (the normal HarmonyOS build), the
// engine symbols are resolved by the linker. Otherwise they are looked up with
// dlopen at runtime, which is only useful on hosts that allow dynamically
// loaded Go libraries.
#ifdef VEIL_STATIC_CORE
extern "C" char* VeilStart(char* configPath, char* socketPath);
extern "C" char* VeilCall(char* method, char* params);
extern "C" char* VeilShutdown();
#endif

// Called by the Go core (bridge/main.go) so its log is visible through
// `hdc shell hilog` without touching the UI.
extern "C" void veil_hilog(int level, const char* msg)
{
    OH_LOG_Print(LOG_APP, static_cast<LogLevel>(level), 0x00FF, "veilcore", "%{public}s", msg);
}

namespace {

using VeilStartFn = char* (*)(char*, char*);
using VeilCallFn = char* (*)(char*, char*);
using VeilShutdownFn = char* (*)();

VeilStartFn g_start = nullptr;
VeilCallFn g_call = nullptr;
VeilShutdownFn g_shutdown = nullptr;
std::string g_loadError;

// The engine ships next to the shim inside the HAP's lib directory, so the
// plain soname is enough for the dynamic loader.
constexpr const char* kCoreLibrary = "libveilcore.so";

bool EnsureLoaded()
{
#ifdef VEIL_STATIC_CORE
    g_start = &VeilStart;
    g_call = &VeilCall;
    g_shutdown = &VeilShutdown;
    return true;
#else
    if (g_start != nullptr && g_call != nullptr && g_shutdown != nullptr) {
        return true;
    }
    void* handle = dlopen(kCoreLibrary, RTLD_LAZY | RTLD_GLOBAL);
    if (handle == nullptr) {
        const char* err = dlerror();
        g_loadError = std::string("无法加载 ") + kCoreLibrary + ": " +
                      (err != nullptr ? err : "unknown dlopen error");
        return false;
    }
    g_start = reinterpret_cast<VeilStartFn>(dlsym(handle, "VeilStart"));
    g_call = reinterpret_cast<VeilCallFn>(dlsym(handle, "VeilCall"));
    g_shutdown = reinterpret_cast<VeilShutdownFn>(dlsym(handle, "VeilShutdown"));
    if (g_start == nullptr || g_call == nullptr || g_shutdown == nullptr) {
        g_loadError = std::string(kCoreLibrary) + " 缺少 VeilStart/VeilCall/VeilShutdown 导出";
        g_start = nullptr;
        g_call = nullptr;
        g_shutdown = nullptr;
        return false;
    }
    return true;
#endif
}

std::string EscapeJson(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out.push_back(c);
                break;
        }
    }
    return out;
}

std::string FailureJson(const std::string& message)
{
    return std::string("{\"ok\":false,\"error\":\"") + EscapeJson(message) + "\"}";
}

napi_value MakeString(napi_env env, const std::string& value)
{
    napi_value result = nullptr;
    napi_create_string_utf8(env, value.c_str(), value.size(), &result);
    return result;
}

std::string ReadString(napi_env env, napi_value value)
{
    size_t length = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok) {
        return std::string();
    }
    std::string out(length, '\0');
    size_t copied = 0;
    napi_get_value_string_utf8(env, value, out.data(), length + 1, &copied);
    out.resize(copied);
    return out;
}

// Copies the engine's reply before anything else can call into Go again.
std::string TakeReply(char* raw)
{
    if (raw == nullptr) {
        return FailureJson("引擎没有返回内容");
    }
    return std::string(raw);
}

napi_value Start(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 2) {
        return MakeString(env, FailureJson("start 需要 configPath 与 socketPath"));
    }
    if (!EnsureLoaded()) {
        return MakeString(env, FailureJson(g_loadError));
    }
    std::string configPath = ReadString(env, args[0]);
    std::string socketPath = ReadString(env, args[1]);
    return MakeString(env, TakeReply(g_start(configPath.data(), socketPath.data())));
}

napi_value Call(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        return MakeString(env, FailureJson("call 需要 method"));
    }
    if (!EnsureLoaded()) {
        return MakeString(env, FailureJson(g_loadError));
    }
    std::string method = ReadString(env, args[0]);
    std::string params = argc >= 2 ? ReadString(env, args[1]) : std::string("{}");
    return MakeString(env, TakeReply(g_call(method.data(), params.data())));
}

napi_value Shutdown(napi_env env, napi_callback_info info)
{
    (void)info;
    if (!EnsureLoaded()) {
        return MakeString(env, FailureJson(g_loadError));
    }
    return MakeString(env, TakeReply(g_shutdown()));
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        {"start", nullptr, Start, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"call", nullptr, Call, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"shutdown", nullptr, Shutdown, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

} // namespace

static napi_module g_veilModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "veil",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterVeilModule(void)
{
    napi_module_register(&g_veilModule);
}
