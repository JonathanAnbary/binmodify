BinModify
=========

Bin(ary) Mod(ify) is a lightweight tool for patching binary executables.

Features:

- Creating code caves.
- Inserting inline hooks.

Together these features allow for writing to binary files as though they were textual files! Inserting extra code inbetween existing instructions.

Usage
=====

Run `zig build` in order to build the command line application and the static library.

You can also use `binmodify` via the zig build system by running:
```bash
zig fetch --save <binmodify>
```
And then add the following to your `build.zig`:
```zig
const binmodify = b.dependency("binmodify", .{
    .target = target,
    .optimize = optimize,
});

your_module.addImport("binmodify", binmodify.module("binmodify")); // replace the module with cbinmodify if you need the c api.
```

Testing
=======

Testing the application requires an additional dependency on keystone, 
and since it is not packaged via build.zig you will need cmake in order to build it.  

I suggest setting CC and CXX to zig-cc and zig-c++ respectivly and then following the instructions at [keystone README](keystone/README.md).

Test coverage is quite crap since Im lazy, in addition the PE tests have only been ran infrequently due to wine being too difficult.

Planned features
================

These are the features I plan to add:

- Macho support (currently only the Elf and PE formats are supported, might not be possible due to required signatures on macho).
- New file ranges creation (currently file ranges can be extended but not created, This will require to resize the phdr table in elf, which might not be easy, have not looked into it for PE).
- General api improvments (Im only really using this in [binmodify_plug](https://github.com/JonathanAnbary/binmodify_plug) which makes the project very tightly coupled and probably blinds me to some better api design).
