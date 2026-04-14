const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- BPF compilation (shared by all targets) ---
    // Recompile BPF probe if vmlinux.h is available; otherwise use committed .bpf.o.
    // CI runners often lack the host kernel's BTF, so this keeps builds working.
    const bpf_compile = b.addSystemCommand(&.{
        "sh", "-c",
        "test -f bpf/vmlinux.h && clang -target bpf -D__TARGET_ARCH_x86_64 -O2 -g -I bpf -c bpf/ssh_monitor.bpf.c -o src/detect/ssh_monitor.bpf.o || echo 'note: bpf/vmlinux.h not found, using committed .bpf.o'",
    });

    // --- Dev build (default) ---
    // zig build
    const exe = addExe(b, target, optimize, false, false, &bpf_compile.step);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run ssh-notifier").dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(exe_tests).step);

    // --- Release: dynamic (glibc) ---
    // zig build release
    // Runtime deps: glibc, libsystemd.so, libbpf.so
    const release_step = b.step("release", "Build glibc production binary (ReleaseSmall, LTO, strip, upx)");
    {
        const resolved = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu });
        const rel_exe = addExe(b, resolved, .ReleaseSmall, true, true, &bpf_compile.step);
        const install = b.addInstallArtifact(rel_exe, .{
            .dest_dir = .{ .override = .{ .custom = "release" } },
            .dest_sub_path = "ssh-notifier-x86_64-linux",
        });
        const upx = b.addSystemCommand(&.{ "upx", "--best", "--lzma" });
        upx.addArg(b.getInstallPath(.{ .custom = "release" }, "ssh-notifier-x86_64-linux"));
        upx.step.dependOn(&install.step);
        release_step.dependOn(&upx.step);
    }

    // --- Release: fully static (musl) ---
    // zig build release-static -Dmusl-sysroot=/path/to/sysroot
    // Produces a zero-dependency static binary. Requires .a files compiled
    // against musl for: libsystemd, libbpf, libelf, zlib.
    // CI builds these from source (see .github/workflows/release.yml).
    const static_step = b.step("release-static", "Build fully static musl binary (needs -Dmusl-sysroot)");
    const musl_sysroot = b.option([]const u8, "musl-sysroot", "Path to musl sysroot with static libs");

    // Each architecture needs its own musl sysroot with native .a files.
    // aarch64 requires a cross-compilation sysroot (not yet supported in CI).
    inline for (.{
        .{ .arch = std.Target.Cpu.Arch.x86_64, .name = "x86_64-linux-static" },
    }) |rt| {
        if (musl_sysroot) |sysroot| {
            const resolved = b.resolveTargetQuery(.{ .cpu_arch = rt.arch, .os_tag = .linux, .abi = .musl });
            const rel_exe = addStaticExe(b, resolved, &bpf_compile.step, sysroot);
            const install = b.addInstallArtifact(rel_exe, .{
                .dest_dir = .{ .override = .{ .custom = "release" } },
                .dest_sub_path = "ssh-notifier-" ++ rt.name,
            });
            const upx = b.addSystemCommand(&.{ "upx", "--best", "--lzma" });
            upx.addArg(b.getInstallPath(.{ .custom = "release" }, "ssh-notifier-" ++ rt.name));
            upx.step.dependOn(&install.step);
            static_step.dependOn(&upx.step);
        }
    }
}

/// Standard executable — dynamic linking for glibc, used for dev and glibc release.
fn addExe(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: bool,
    lto: bool,
    bpf_step: *std.Build.Step,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "ssh-notifier",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = if (strip) true else null,
        }),
    });
    exe.root_module.linkSystemLibrary("libsystemd", .{});
    exe.root_module.linkSystemLibrary("bpf", .{});
    exe.root_module.link_libc = true;
    if (lto) exe.want_lto = true;

    // Explicit targets (release) need manual library paths
    if (optimize == .ReleaseSmall) {
        exe.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
        // Fedora/RHEL
        exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib64" });
        // Debian/Ubuntu
        if (std.fs.accessAbsolute("/usr/lib/x86_64-linux-gnu", .{})) |_|
            exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" })
        else |_| {}
    }
    exe.step.dependOn(bpf_step);
    return exe;
}

/// Fully static executable — musl, all deps linked statically from sysroot.
fn addStaticExe(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    bpf_step: *std.Build.Step,
    sysroot: []const u8,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "ssh-notifier",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
            .strip = true,
        }),
    });
    // All deps static from sysroot — use bare names (linker prepends "lib")
    // elogind archive has internal cross-deps — force whole inclusion
    exe.root_module.addObjectFile(.{ .cwd_relative = b.fmt("{s}/lib/libelogind.a", .{sysroot}) });
    exe.root_module.linkSystemLibrary("bpf", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("elf", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("z", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("zstd", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("cap", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("mount", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("blkid", .{ .preferred_link_mode = .static });
    exe.root_module.linkSystemLibrary("udev", .{ .preferred_link_mode = .static });
    exe.root_module.link_libc = true;
    exe.want_lto = true;

    // Point to musl sysroot for headers and .a files
    exe.root_module.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{sysroot}) });
    exe.root_module.addSystemIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{sysroot}) });
    exe.root_module.addSystemIncludePath(.{ .cwd_relative = b.fmt("{s}/usr/include", .{sysroot}) });
    exe.step.dependOn(bpf_step);
    return exe;
}
