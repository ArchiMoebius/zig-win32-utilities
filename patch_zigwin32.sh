#!/usr/bin/env bash

grep -r SE_PRIVILEGE_DISABLED ./zigwin32/ 2>&1 > /dev/null
if [ "$?" == "1" ]; then
    sed -i 's/ENABLED = 2,/DISABLED = 0,\n    ENABLED = 2,/g' zigwin32/win32/security.zig
    sed -i 's/pub const SE_PRIVILEGE_ENABLED = TOKEN_PRIVILEGES_ATTRIBUTES.ENABLED;/pub const SE_PRIVILEGE_DISABLED = TOKEN_PRIVILEGES_ATTRIBUTES.DISABLED;\npub const SE_PRIVILEGE_ENABLED = TOKEN_PRIVILEGES_ATTRIBUTES.ENABLED;/g' zigwin32/win32/security.zig
    sed -i 's:pub const SE_PRIVILEGE_ENABLED = @import("../win32.zig").security.SE_PRIVILEGE_ENABLED;:pub const SE_PRIVILEGE_DISABLED = @import("../win32.zig").security.SE_PRIVILEGE_DISABLED;\npub const SE_PRIVILEGE_ENABLED = @import("../win32.zig").security.SE_PRIVILEGE_ENABLED;:g' zigwin32/win32/everything.zig
    echo "[+] Patched!"
fi