{
  description = "Reimplementation of the NixOS firewall with nftables";
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-22.05";

  outputs = { self, nixpkgs }: {

    nixosModules.nft-firewall = { config, pkgs, lib, modulesPath, ... }: {
      imports = [ ./nft-firewall.nix ];
    };

    nixosModules.nft-nat = { config, pkgs, lib, modulesPath, ... }: {
      imports = [ ./nft-nat.nix ];
    };

    nixosModules.default = { ... }: {
      imports = [ self.nixosModules.nft-firewall self.nixosModules.nft-nat ];
    };

    # $flake#$flakeAttr.config.system.build.vm
    vms = {
      test = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [ self.nixosModules.default ./vmconfig.nix ];
      };
    };
  };
}
