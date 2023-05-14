{
  description = "High-level tracing language for Linux eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-22.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    # This flake only supports 64-bit linux systems.
    # Note bpftrace support aarch32 but for simplicity we'll omit it for now.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          # Overlay to specify build should use the specific libbpf we want
          libbpfVersion = "1.2.0";
          libbpfOverlay =
            (self: super: {
              libbpf_1 = super.libbpf_1.overrideAttrs (old: {
                version = libbpfVersion;
                src = super.fetchFromGitHub {
                  owner = "libbpf";
                  repo = "libbpf";
                  rev = "v${libbpfVersion}";
                  # If you don't know the hash the first time, set:
                  # hash = "";
                  # then nix will fail the build with such an error message:
                  # hash mismatch in fixed-output derivation '/nix/store/m1ga09c0z1a6n7rj8ky3s31dpgalsn0n-source':
                  # specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                  # got:    sha256-173gxk0ymiw94glyjzjizp8bv8g72gwkjhacigd1an09jshdrjb4
                  sha256 = "sha256-NimK4pdYcai21hZHdP1mBX1MOlNY61iDJ+PDYwpRuVE=";
                };
              });
            });

          # Overlay to specify build should use the specific bcc we want
          bccVersion = "0.27.0";
          bccOverlay =
            (self: super: {
              bcc = super.bcc.overridePythonAttrs (old: {
                version = bccVersion;
                src = super.fetchFromGitHub {
                  owner = "iovisor";
                  repo = "bcc";
                  rev = "v${bccVersion}";
                  sha256 = "sha256-+RK5RZcoNHlgMOFPgygRf2h+OZGxR9gJ+fTbYjDB6Ww=";
                };
                # Seems like these extra tools are needed to build bcc
                nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.python310Packages.setuptools pkgs.zip ];
              });
            });

          # We need to use two overlays so that bcc inherits the our pinned libbpf
          pkgs = import nixpkgs { inherit system; overlays = [ libbpfOverlay bccOverlay ]; };
        in
        {
          # Set formatter for `nix fmt` command
          formatter = pkgs.nixpkgs-fmt;

          # Define package set
          packages = rec {
            # Default package is bpftrace binary
            default = bpftrace;

            # Derivation for bpftrace binary
            bpftrace =
              with pkgs;
              pkgs.stdenv.mkDerivation rec {
                name = "bpftrace";

                src = self;

                nativeBuildInputs = [ cmake ninja bison flex gcc12 ];

                buildInputs = with llvmPackages_15;
                  [
                    asciidoctor
                    bcc
                    cereal
                    elfutils
                    gtest
                    libbpf_1
                    libbfd
                    libclang
                    libelf
                    libffi
                    libopcodes
                    libpcap
                    libsystemtap
                    llvm
                    pahole
                    xxd
                    zlib
                  ];

                # Release flags
                cmakeFlags = [
                  "-DCMAKE_BUILD_TYPE=Release"
                  "-DUSE_SYSTEM_BPF_BCC=ON"
                ];
              };
          };

          # Define apps that can be run with `nix run`
          apps.default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/bpftrace";
          };
        });
}
