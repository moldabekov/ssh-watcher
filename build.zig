const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- BPF compilation (Linux only) ---
    // Recompile BPF probe if vmlinux.h is available; otherwise use committed .bpf.o.
    // CI runners often lack the host kernel's BTF, so this keeps builds working.
    const bpf_compile: ?*std.Build.Step = if (target.result.os.tag == .linux) blk: {
        const step = b.addSystemCommand(&.{
            "sh", "-c",
            "test -f bpf/vmlinux.h && clang -target bpf -D__TARGET_ARCH_x86_64 -O2 -g -I bpf -c bpf/ssh_monitor.bpf.c -o src/detect/ssh_monitor.bpf.o || echo 'note: bpf/vmlinux.h not found, using committed .bpf.o'",
        });
        break :blk &step.step;
    } else null;

    // --- Dev build (default) ---
    // zig build
    const exe = addExe(b, target, optimize, false, false, bpf_compile);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run ssh-watcher").dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(exe_tests).step);

    // --- Release: dynamic (glibc) ---
    // zig build release
    // Runtime deps: glibc, libsystemd.so, libbpf.so
    const release_step = b.step("release", "Build glibc production binary (ReleaseSmall, LTO, strip, upx)");
    {
        const resolved = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu });
        const rel_exe = addExe(b, resolved, .ReleaseSmall, true, true, bpf_compile);
        const install = b.addInstallArtifact(rel_exe, .{
            .dest_dir = .{ .override = .{ .custom = "release" } },
            .dest_sub_path = "ssh-watcher-x86_64-linux",
        });
        // UPX is Linux-only; breaks macOS code signing
        if (resolved.result.os.tag == .linux) {
            const upx = b.addSystemCommand(&.{ "upx", "--best", "--lzma" });
            upx.addArg(b.getInstallPath(.{ .custom = "release" }, "ssh-watcher-x86_64-linux"));
            upx.step.dependOn(&install.step);
            release_step.dependOn(&upx.step);
        } else {
            release_step.dependOn(&install.step);
        }
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
            const rel_exe = addStaticExe(b, resolved, bpf_compile, sysroot);
            const install = b.addInstallArtifact(rel_exe, .{
                .dest_dir = .{ .override = .{ .custom = "release" } },
                .dest_sub_path = "ssh-watcher-" ++ rt.name,
            });
            // UPX is Linux-only; static build is always Linux so always apply
            const upx = b.addSystemCommand(&.{ "upx", "--best", "--lzma" });
            upx.addArg(b.getInstallPath(.{ .custom = "release" }, "ssh-watcher-" ++ rt.name));
            upx.step.dependOn(&install.step);
            static_step.dependOn(&upx.step);
        }
    }

    // --- Release: macOS (x86_64 + aarch64) ---
    // zig build release-macos
    // Cross-compiles both architectures. No UPX (breaks macOS code signing).
    // LTO is disabled on macOS: Zig uses the system linker (ld64) by
    // default here to keep ad-hoc codesigning compatible, and ld64
    // does not speak LLVM bitcode. Switching to LLD would require
    // re-signing gymnastics. ReleaseSmall + strip still gets us ~300 KB.
    const macos_step = b.step("release-macos", "Build macOS production binaries (ReleaseSmall, strip)");
    inline for (.{
        .{ .arch = std.Target.Cpu.Arch.x86_64, .name = "x86_64-macos" },
        .{ .arch = std.Target.Cpu.Arch.aarch64, .name = "aarch64-macos" },
    }) |rt| {
        const resolved = b.resolveTargetQuery(.{ .cpu_arch = rt.arch, .os_tag = .macos });
        const rel_exe = addExe(b, resolved, .ReleaseSmall, true, false, null);
        const install = b.addInstallArtifact(rel_exe, .{
            .dest_dir = .{ .override = .{ .custom = "release" } },
            .dest_sub_path = "ssh-watcher-" ++ rt.name,
        });
        macos_step.dependOn(&install.step);
    }
}

/// Standard executable — dynamic linking, used for dev builds and glibc/macOS release.
fn addExe(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: bool,
    lto: bool,
    bpf_step: ?*std.Build.Step,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "ssh-watcher",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = if (strip) true else null,
        }),
    });

    // OS-conditional library linking. Names match each platform's
    // pkg-config / framework lookup rules — "libsystemd" is the
    // pkg-config package name (not just the SONAME), so we must keep
    // the "lib" prefix here even though "bpf" and "bsm" omit it.
    const os_tag = target.result.os.tag;
    if (os_tag == .linux) {
        exe.root_module.linkSystemLibrary("libsystemd", .{});
        exe.root_module.linkSystemLibrary("bpf", .{});
    } else if (os_tag == .macos) {
        exe.root_module.linkSystemLibrary("bsm", .{});
        // Zig 0.15.2 does not auto-discover macOS SDK library paths
        // when cross-compiling. Read SDKROOT (set by CI via
        // `xcrun --show-sdk-path`) and add <sdk>/usr/lib so linkSystemLibrary
        // can resolve libbsm.tbd.
        if (std.process.getEnvVarOwned(b.allocator, "SDKROOT")) |sdkroot| {
            exe.root_module.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/usr/lib", .{sdkroot}) });
            exe.root_module.addSystemIncludePath(.{ .cwd_relative = b.fmt("{s}/usr/include", .{sdkroot}) });
        } else |_| {
            // SDKROOT unset — build may still succeed on a native macOS
            // host if xcrun auto-discovery works.
        }
    }
    exe.root_module.link_libc = true;
    if (lto) exe.want_lto = true;

    // Explicit Linux release targets need manual library paths
    if (optimize == .ReleaseSmall and os_tag == .linux) {
        exe.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
        // Fedora/RHEL
        exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib64" });
        // Debian/Ubuntu
        if (std.fs.accessAbsolute("/usr/lib/x86_64-linux-gnu", .{})) |_|
            exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu" })
        else |_| {}
    }
    if (bpf_step) |step| exe.step.dependOn(step);
    return exe;
}

/// Fully static executable — musl, all deps linked statically from sysroot.
fn addStaticExe(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    bpf_step: ?*std.Build.Step,
    sysroot: []const u8,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "ssh-watcher",
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
    if (bpf_step) |step| exe.step.dependOn(step);
    return exe;
}
