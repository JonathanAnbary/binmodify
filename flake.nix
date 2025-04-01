{
  description = "Patch binary files with ease";
  inputs = {
    nixpkgs-stable.url = "github:NixOS/nixpkgs/nixos-24.11";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    # zls-overlay.url = "github:zigtools/zls";
    zls-overlay.url = "github:zigtools/zls/0.14.0";
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    nixpkgs-stable,
    ...
  }:
  let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    pkgs-stable = nixpkgs-stable.legacyPackages.x86_64-linux;
    # zig = inputs.zig-overlay.packages.x86_64-linux.master;
    zig = inputs.zig-overlay.packages.x86_64-linux."0.14.0";
    zls = inputs.zls-overlay.packages.x86_64-linux.zls.overrideAttrs (old: {
            nativeBuildInputs = [ zig ];
          });
  in
  {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages = [
        zls
        zig
        pkgs-stable.qemu
        pkgs-stable.wine64
        pkgs-stable.wineWowPackages.stable
        (pkgs.python3.withPackages (python-pkgs: with python-pkgs; [
        # select Python packages here
        ipython
        python-lsp-server
      ]))
      ];
    };
  };
}
