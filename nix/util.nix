# Copyright (c) The mlkem-native project authors
# Copyright (c) The slhdsa-c project authors
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

{ pkgs, cbmc, bitwuzla, z3 }:
rec {
  glibc-join = p: p.buildPackages.symlinkJoin {
    name = "glibc-join";
    paths = [ p.glibc p.glibc.static ];
  };

  wrap-gcc = p: p.buildPackages.wrapCCWith {
    cc = p.buildPackages.gcc.cc;
    bintools = p.buildPackages.wrapBintoolsWith {
      bintools = p.buildPackages.binutils-unwrapped;
      libc = glibc-join p;
    };
  };

  native-gcc =
    if pkgs.stdenv.isDarwin
    then pkgs.clang
    else wrap-gcc pkgs;

  # cross is for determining whether to install the cross toolchain dependencies or not
  _toolchains = { cross ? true }:
    let
      x86_64-gcc = wrap-gcc pkgs.pkgsCross.gnu64;
      aarch64-gcc = wrap-gcc pkgs.pkgsCross.aarch64-multiplatform;
      riscv64-gcc = wrap-gcc pkgs.pkgsCross.riscv64;
      riscv32-gcc = wrap-gcc pkgs.pkgsCross.riscv32;
      ppc64le-gcc = wrap-gcc pkgs.pkgsCross.powernv;
    in
    # NOTE:
      # - native toolchain should be equipped in the shell via `mkShellWithCC` (see `mkShell`)
      # - only install extra cross-compiled toolchains if not on darwin or `cross` is specifally set to true
      # - providing cross compilation toolchain (x86_64/aarch64-linux) for darwin can be cumbersome
      #   and won't just work for now
      # - equip all toolchains if cross is explicitly set to true
      # - On some machines, `native-gcc` needed to be evaluated lastly (placed as the last element of the toolchain list), or else would result in environment variables (CC, AR, ...) overriding issue.
    # pkgs.lib.optionals cross [ pkgs.qemu x86_64-gcc aarch64-gcc riscv64-gcc riscv32-gcc ppc64le-gcc ]
    pkgs.lib.optionals cross [ pkgs.qemu ]
    ++ pkgs.lib.optionals cross [ native-gcc ]
    # git is not available in the nix shell on Darwin. As a workaround we add git as a dependency here.
    # Initially, we expected this to be fixed by https://github.com/NixOS/nixpkgs/pull/353893, but that does not seem to be the case.
    ++ pkgs.lib.optionals (pkgs.stdenv.isDarwin) [ pkgs.git ]
    ++ builtins.attrValues {
      inherit (pkgs.python3Packages) sympy pyyaml;
      inherit (pkgs)
        gnumake
        python3;
    };

  # NOTE: idiomatic nix way of properly setting the $CC in a nix shell
  mkShellWithCC = cc: attrs: (pkgs.mkShellNoCC.override { stdenv = pkgs.overrideCC pkgs.stdenv cc; }) (
    attrs // {
      shellHook = ''
        export PATH=$PWD/scripts:$PATH
      '';
    }
  );
  mkShellNoCC = mkShellWithCC null;
  mkShell = mkShellWithCC native-gcc;

  mkShellWithCC' = cc:
    mkShellWithCC cc {
      packages = [ pkgs.python3 ];
      hardeningDisable = [ "fortify" ];
    };

  # some customized packages
  linters = pkgs.symlinkJoin {
    name = "pqcp-linters";
    paths = builtins.attrValues {
      clang-tools = pkgs.clang-tools.overrideAttrs {
        unwrapped = pkgs.llvmPackages.clang-unwrapped;
      };

      inherit (pkgs.llvmPackages)
        bintools;

      inherit (pkgs)
        nixpkgs-fmt
        shfmt;

      inherit (pkgs.python3Packages)
        mpmath sympy black pyparsing pyyaml;
    };
  };

  cbmc_pkgs = pkgs.callPackage ./cbmc {
    inherit cbmc bitwuzla z3;
  };

  # Helper function to build individual cross toolchains
  _individual_toolchain = { name, cross_compilers }:
    let
      common_deps = builtins.attrValues
        {
          inherit (pkgs.python3Packages) sympy pyyaml;
          inherit (pkgs)
            gnumake
            python3
            qemu;
        } ++ pkgs.lib.optionals (pkgs.stdenv.isDarwin) [ pkgs.git ];
    in
    pkgs.symlinkJoin {
      name = "toolchain-${name}";
      paths = cross_compilers ++ common_deps ++ [ native-gcc ];
    };

  # Individual cross toolchains
  toolchain_x86_64 = _individual_toolchain {
    name = "x86_64";
    cross_compilers = [ (wrap-gcc pkgs.pkgsCross.gnu64) ];
  };

  toolchain_aarch64 = _individual_toolchain {
    name = "aarch64";
    cross_compilers = [ (wrap-gcc pkgs.pkgsCross.aarch64-multiplatform) ];
  };

  toolchain_riscv64 = _individual_toolchain {
    name = "riscv64";
    cross_compilers = [ (wrap-gcc pkgs.pkgsCross.riscv64) ];
  };

  toolchain_riscv32 = _individual_toolchain {
    name = "riscv32";
    cross_compilers = [ (wrap-gcc pkgs.pkgsCross.riscv32) ];
  };

  toolchain_ppc64le = _individual_toolchain {
    name = "ppc64le";
    cross_compilers = [ (wrap-gcc pkgs.pkgsCross.powernv) ];
  };

  toolchains = pkgs.symlinkJoin {
    name = "toolchains";
    paths = _toolchains { };
  };

  toolchains_native = pkgs.symlinkJoin {
    name = "toolchains-native";
    paths = _toolchains { cross = false; };
  };
}
