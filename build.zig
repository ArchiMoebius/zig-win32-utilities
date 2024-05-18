const std = @import("std");

const targets: []const std.zig.CrossTarget = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
};

pub fn package(b: *std.Build, exe: *std.Build.Step.Compile, t: std.zig.CrossTarget) !void {
    const target_output = b.addInstallArtifact(exe, .{
        .dest_dir = .{
            .override = .{
                .custom = try t.zigTriple(b.allocator),
            },
        },
    });

    b.getInstallStep().dependOn(&target_output.step);

    return;
}

pub fn build(b: *std.Build) !void {
    const sources = [_][]const u8{
        "ModifyPrivilege_windows.zig",
        "HighToSystem_windows.zig",
        "BackupOperatorToDomainAdministrator_windows.zig",
        "Shortcut_windows.zig",
        "shellcode_windows.zig",
        "shellcode_linux.zig",
    };

    const optimize = b.standardOptimizeOption(.{});

    const zigwin32 = b.createModule(.{
        .root_source_file = .{ .path = "zigwin32/win32.zig" },
    });

    for (targets) |t| {
        for (sources) |source| {
            var file: ?[]const u8 = "";

            if (std.mem.containsAtLeast(u8, source, 1, "_windows")) {
                if (t.os_tag != .windows) {
                    continue;
                }

                var parts = std.mem.tokenizeSequence(u8, source, "_windows");
                file = parts.next();
            }

            if (std.mem.containsAtLeast(u8, source, 1, "_linux")) {
                if (t.os_tag != .linux) {
                    continue;
                }

                var parts = std.mem.tokenizeSequence(u8, source, "_linux");
                file = parts.next();
            }

            const exe = b.addExecutable(.{
                .name = file.?,
                .root_source_file = .{ .path = source },
                .target = b.resolveTargetQuery(.{
                    .abi = t.abi,
                    .cpu_arch = t.cpu_arch,
                    .os_tag = t.os_tag, // std.Target.Os.Tag.freestanding,
                }),
                .optimize = optimize,
            });

            if (t.os_tag == .windows) {
                exe.root_module.addImport("win32", zigwin32);
            }

            try package(b, exe, t);
        }
    }
}
