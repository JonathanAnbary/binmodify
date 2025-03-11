const std = @import("std");
const builtin = @import("builtin");

const arch = @import("arch.zig");
const ElfModder = @import("elf/Modder.zig");
const ElfParsed = @import("elf/Parsed.zig");
const CoffModder = @import("coff/Modder.zig");
const CoffParsed = @import("coff/Parsed.zig");
const common = @import("common.zig");
const ctl_asm = @import("ctl_asm.zig");

pub const PatchInfo: type = extern struct {
    cave_addr: u64,
    cave_size: u64,
};

pub fn Patcher(Modder: type, Disasm: type) type {
    return struct {
        modder: Modder,
        ctl_assembler: ctl_asm.CtlFlowAssembler,
        disasm: Disasm,

        const Self = @This();
        pub const Error = Modder.Error || Disasm.Error || arch.Error;

        pub fn init(
            gpa: std.mem.Allocator,
            reader: anytype,
            parsed: anytype,
        ) Error!Self {
            var modder: Modder = try Modder.init(gpa, parsed, reader);
            errdefer modder.deinit(gpa);
            const farch = try parsed.get_arch();
            // NOTE: mode might be something that is not constant across the file.
            const fmode = try parsed.get_mode();
            const fendian = try parsed.get_endian();
            var disasm: Disasm = try Disasm.init(farch, fmode, fendian);
            errdefer disasm.deinit();

            return Self{
                .modder = modder,
                .ctl_assembler = try ctl_asm.CtlFlowAssembler.init(farch, fmode, fendian),
                .disasm = disasm,
            };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.modder.deinit(gpa);
            self.disasm.deinit();
        }

        pub fn pure_patch(self: *Self, addr: u64, patch: []const u8, stream: anytype) !PatchInfo {
            // TODO: think about this 20 (pull out of my ass as the maximum partial instruction size that might be needed).
            var buff: [ctl_asm.CtlFlowAssembler.MAX_CTL_FLOW + 20]u8 = undefined;
            const off_before_patch = try self.modder.addr_to_off(addr);
            try stream.seekTo(off_before_patch);
            const max = try stream.read(&buff);
            const ctl_trasnfer_size = (ctl_asm.CtlFlowAssembler.ARCH_TO_CTL_FLOW.get(self.ctl_assembler.arch) orelse return Error.ArchNotSupported).len;
            const insn_to_move_siz = self.disasm.min_insn_size(ctl_trasnfer_size, buff[0..max]);
            std.debug.assert(insn_to_move_siz < buff.len);
            const cave_size = patch.len + insn_to_move_siz + ctl_trasnfer_size;
            const cave_option = (try self.modder.get_cave_option(cave_size, common.FileRangeFlags{ .read = true, .execute = true })) orelse return Error.NoFreeSpace;
            // std.debug.print("\ncave_option = {}\n", .{cave_option});
            try self.modder.create_cave(cave_size, cave_option, stream);
            // if (T == CoffModder) {
            //     for (self.modder.sechdrs) |*sechdr| {
            //         std.debug.print("{X} - {X} - {X} - {X}\n", .{ sechdr.virtual_address, sechdr.virtual_size, sechdr.pointer_to_raw_data, sechdr.size_of_raw_data });
            //     }
            // }

            const off_after_patch = try self.modder.addr_to_off(addr);
            // TODO: mismatch between filesz and memsz is gonna screw me over.
            const cave_off = self.modder.cave_to_off(cave_option, cave_size);
            const cave_addr = try self.modder.off_to_addr(cave_off);
            try stream.seekTo(cave_off);
            if (try stream.write(patch) != patch.len) return Error.UnexpectedEof;
            try stream.seekTo(cave_off + patch.len);
            if (try stream.write(buff[0..insn_to_move_siz]) != insn_to_move_siz) return Error.UnexpectedEof;
            const patch_to_cave_size = try self.ctl_assembler.assemble_ctl_transfer(addr, cave_addr, &buff);
            std.debug.assert(patch_to_cave_size == ctl_trasnfer_size);
            try stream.seekTo(off_after_patch);
            if (try stream.write(buff[0..patch_to_cave_size]) != patch_to_cave_size) return Error.UnexpectedEof;
            const cave_to_patch_size = try self.ctl_assembler.assemble_ctl_transfer(cave_addr + patch.len + insn_to_move_siz, addr + insn_to_move_siz, &buff);
            std.debug.assert(cave_to_patch_size == ctl_trasnfer_size);
            try stream.seekTo(cave_off + patch.len + insn_to_move_siz);
            if (try stream.write(buff[0..cave_to_patch_size]) != cave_to_patch_size) return Error.UnexpectedEof;
            return .{ .cave_addr = cave_addr, .cave_size = cave_size };
        }
    };
}
