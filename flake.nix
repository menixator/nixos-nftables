{
  description = "Reimplementation of the NixOS firewall with nftables";

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

  };
}
