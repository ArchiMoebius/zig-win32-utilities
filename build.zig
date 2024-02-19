const std = @import("std");

const targets: []const std.zig.CrossTarget = &.{
    //.{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
};

pub fn package(b: *std.Build, exe: *std.build.Step.Compile, t: std.zig.CrossTarget) !void {
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
        "ModifyPrivilege",
        "HighToSystem",
        "BackupOperatorToDomainAdministrator",
    };

    const optimize = b.standardOptimizeOption(.{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const zigwin32 = b.createModule(.{
        .source_file = .{ .path = "zigwin32/win32.zig" },
    });
    var deps: [1]std.build.ModuleDependency = undefined;
    deps[0] = std.build.ModuleDependency{ .name = "zigwin32", .module = zigwin32 };

    for (targets) |t| {
        for (sources) |source| {
            const filename = std.fmt.allocPrint(allocator, "{s}.zig", .{source}) catch return;
            defer allocator.free(filename);
            const exe = b.addExecutable(.{
                .name = source,
                .root_source_file = .{ .path = filename },
                .target = t,
                .optimize = optimize,
            });

            exe.addModule("win32", zigwin32);

            try package(b, exe, t);
        }
    }
}
