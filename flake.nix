{
  description = "Patch binary files with ease";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zls-overlay.url = "github:zigtools/zls";
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    ...
  }:
  let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    zig = inputs.zig-overlay.packages.x86_64-linux.master;
    # zig = inputs.zig-overlay.packages.x86_64-linux.default;
    zls = inputs.zls-overlay.packages.x86_64-linux.zls.overrideAttrs (old: {
            nativeBuildInputs = [ zig ];
          });
  in
  {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages = [
        zls
        zig
      ];
    };
  };
}
