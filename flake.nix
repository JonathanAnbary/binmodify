{
  description = "Patch binary files with ease";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    zls-overlay.url = "github:zigtools/zls";
    # zls-overlay.url = "github:zigtools/zls/0.13.0";
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    ...
  }:
  let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    zig = inputs.zig-overlay.packages.x86_64-linux.master;
    # zig = inputs.zig-overlay.packages.x86_64-linux."0.13.0";
    zls = inputs.zls-overlay.packages.x86_64-linux.zls.overrideAttrs (old: {
            nativeBuildInputs = [ zig ];
          });
  in
  {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages = [
        zls
        zig
        pkgs.wine64
        pkgs.wineWowPackages.stable
        pkgs.winetricks
        (pkgs.python3.withPackages (python-pkgs: with python-pkgs; [
        # select Python packages here
        ipython
        python-lsp-server
      ]))
      ];
    };
  };
}
