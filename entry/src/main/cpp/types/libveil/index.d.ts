/**
 * Type surface of the NAPI shim (entry/src/main/cpp/napi_init.cpp).
 *
 * Every function returns a JSON string; parse it and check `ok`. The shim
 * dlopen()s libveilcore.so lazily, so calling these before the Go artifact is
 * shipped yields `{"ok":false,"error":"无法加载 libveilcore.so: ..."}`.
 */
export const start: (configPath: string, socketPath: string) => string;
export const call: (method: string, paramsJson: string) => string;
export const shutdown: () => string;
