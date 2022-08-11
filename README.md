# nftables for NixOS

An implementation of the NixOS firewall (`networking.firewall` and
`networking.nat`) on top of nftables instead of iptables.

Apparently iptables is "legacy", but the most immediate gain is atomic
applications of firewall rules.

## Usage

Add this repository to your flake's inputs:

```nix
inputs.nixos-nftables.url = "github:menixator/nixos-nftables";
```

Import `nixos-nftables.nixosModules.default` into your `nixOsConfigurations`

```nix
nixosConfigurations.<hostname> = nixpkgs.lib.nixosSystem {
  # ...
  modules = [
    nixos-nftables.nixosModules.default
  ];
}
```

## Notes and Caveats about the fork

The rule generation was provided by
[thefloweringash/nixos-nftables](https://github.com/thefloweringash/nixos-nftables).
This fork just repackages it as a flake and straight up overrides the nixos
firewall to use nftables.

Currently, any packages that use the following properties to add custom
commands will be seven different kinds of broken:
  - `networking.firewall.extraCommands`
  - `networking.firewall.extraStopCommands`
  - `networking.nat.extraStopCommands`
  - `networking.nat.extraCommands`

The iptables rules within these properties can be translated but since anything
that relies on the nixos `firewall` or `nat` module will assume that they will
be in a shell script, things get a little tricky. One way would be to
keep these in an extra bash script and run them where it is necessary, and
translate all the iptables calls to nft. However, even this is problematic
since `nftables` at the moment does not have the ability to remove rules
without handles. So translation is not a silver bullet for this issue. Using a
shell script with nft will also prevent you from taking advantage of the atomic
nature of nft rule additions.



Disclaimer: I have personally not setup any kind of testing infrastructure but
@thefloweringash has tested rules generation quite extensively. I can't
piggyback on @thefloweringash's testing infrastructure as qemu seems to be
dying probably because I'm running nix in a virtualized environment.

Regardless since this package overrides a pretty ubiquitous module, expect some
scuffed behavior when installing network services.

### TODO:
 - [ ] Update inline documentation. The documentation for all the options were
   copied from NixOS's firewall/nat module
 - [ ] Add the ability to enable standalone natting. NixOS does this by
   enabling a separate systemd service if firewall is disabled and natting is
   enabled.
 - [ ] Find a way to translate the custom commands. Eg: using `iptables-translate`
 - [ ] Setup a way to test the rules


## Notes and caveats

This implementation is a precise port of the firewall from NixOS. It
was ported by hand, but is verified against the output of
`iptables-restore-translate`, which converts `iptables-save` output
into an nft script. For debugging and verifying, see the test cases in
`default.nix` and build the diffs via `nix-build -A diff`.

nftables offers matching on `ip`, `ip6`, and `inet`, which supports
both. Users probably want to use the `inet` family, since the
distinction between ipv4 and ipv6 isn't normally important, and the
`ip46helper` is gone. However, this port only translates to `ip` and
`ip6` to mimic `iptables` and `ip6tables`.

In `iptables` every rule implicitly has a counter, while in `nftables`
counters are explicit. In order to match the old behavior (and
`iptables-restore-translate`), all rules have a counter added.

## TODO

 - [ ] Test more
 - [ ] Upstream

