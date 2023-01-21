{ config, lib, pkgs, ... }:

with lib;

let
  inherit (lib) mkIf concatMapStrings optionalString elemAt isInt;

  cfg = config.networking.nat;

  dest = if cfg.externalIP == null then
    "masquerade"
  else
    "snat to ${cfg.externalIP}";

  oifExternal = optionalString (cfg.externalInterface != null)
    ''oifname "${cfg.externalInterface}"'';

  iptablesPortsToNftables = range:
    if isInt range then
      toString range
    else
      let m = builtins.match "([0-9]+):([0-9]+)" range;
      in if m == null then
        range # assume a single port, rely in input validation.
      else
        "${elemAt m 0}-${elemAt m 1}";

in {

  disabledModules = [
    "services/networking/nat.nix"
    "services/networking/nat-nftables.nix"
    "services/networking/nat-iptables.nix"
  ];
  ###### interface

  options = {

    networking.nat.enable = mkOption {
      type = types.bool;
      default = false;
      description = lib.mdDoc ''
        Whether to enable Network Address Translation (NAT).
      '';
    };

    networking.nat.enableIPv6 = mkOption {
      type = types.bool;
      default = false;
      description = lib.mdDoc ''
        Whether to enable IPv6 NAT.
      '';
    };

    networking.nat.internalInterfaces = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "eth0" ];
      description = lib.mdDoc ''
        The interfaces for which to perform NAT. Packets coming from
        these interface and destined for the external interface will
        be rewritten.
      '';
    };

    networking.nat.internalIPs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "192.168.1.0/24" ];
      description = lib.mdDoc ''
        The IP address ranges for which to perform NAT.  Packets
        coming from these addresses (on any interface) and destined
        for the external interface will be rewritten.
      '';
    };

    networking.nat.internalIPv6s = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "fc00::/64" ];
      description = lib.mdDoc ''
        The IPv6 address ranges for which to perform NAT.  Packets
        coming from these addresses (on any interface) and destined
        for the external interface will be rewritten.
      '';
    };

    networking.nat.externalInterface = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "eth1";
      description = lib.mdDoc ''
        The name of the external network interface.
      '';
    };

    networking.nat.externalIP = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "203.0.113.123";
      description = lib.mdDoc ''
        The public IP address to which packets from the local
        network are to be rewritten.  If this is left empty, the
        IP address associated with the external interface will be
        used.
      '';
    };

    networking.nat.externalIPv6 = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "2001:dc0:2001:11::175";
      description = lib.mdDoc ''
        The public IPv6 address to which packets from the local
        network are to be rewritten.  If this is left empty, the
        IP address associated with the external interface will be
        used.
      '';
    };

    networking.nat.forwardPorts = mkOption {
      type = with types;
        listOf (submodule {
          options = {
            sourcePort = mkOption {
              type = types.either types.int
                (types.strMatching "[[:digit:]]+:[[:digit:]]+");
              example = 8080;
              description = lib.mdDoc ''
                Source port of the external interface; to specify a port range, use a string with a colon (e.g. "60000:61000")'';
            };

            destination = mkOption {
              type = types.str;
              example = "10.0.0.1:80";
              description = lib.mdDoc
                "Forward connection to destination ip:port (or [ipv6]:port); to specify a port range, use ip:start-end";
            };

            proto = mkOption {
              type = types.str;
              default = "tcp";
              example = "udp";
              description = lib.mdDoc "Protocol of forwarded connection";
            };

            loopbackIPs = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = literalExpression ''[ "55.1.2.3" ]'';
              description = lib.mdDoc
                "Public IPs for NAT reflection; for connections to `loopbackip:sourcePort' from the host itself and from other hosts behind NAT";
            };
          };
        });
      default = [ ];
      example = [
        {
          sourcePort = 8080;
          destination = "10.0.0.1:80";
          proto = "tcp";
        }
        {
          sourcePort = 8080;
          destination = "[fc00::2]:80";
          proto = "tcp";
        }
      ];
      description = lib.mdDoc ''
        List of forwarded ports from the external interface to
        internal destinations by using DNAT. Destination can be
        IPv6 if IPv6 NAT is enabled.
      '';
    };

    networking.nat.dmzHost = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "10.0.0.1";
      description = lib.mdDoc ''
        The local IP address to which all traffic that does not match any
        forwarding rule is forwarded.
      '';
    };

    networking.nat.extraCommands = mkOption {
      type = types.lines;
      default = "";
      example = "iptables -A INPUT -p icmp -j ACCEPT";
      description = lib.mdDoc ''
        Additional shell commands executed as part of the nat
        initialisation script.
      '';
    };

    networking.nat.extraStopCommands = mkOption {
      type = types.lines;
      default = "";
      example = "iptables -D INPUT -p icmp -j ACCEPT || true";
      description = lib.mdDoc ''
        Additional shell commands executed as part of the nat
        teardown script.
      '';
    };

  };

  config = mkIf config.networking.nat.enable {

    assertions = [
      {
        assertion = cfg.enableIPv6 -> config.networking.enableIPv6;
        message = "networking.nat.enableIPv6 requires networking.enableIPv6";
      }
      {
        assertion = (cfg.dmzHost != null) -> (cfg.externalInterface != null);
        message =
          "networking.nat.dmzHost requires networking.nat.externalInterface";
      }
      {
        assertion = (cfg.forwardPorts != [ ])
          -> (cfg.externalInterface != null);
        message =
          "networking.nat.forwardPorts requires networking.nat.externalInterface";
      }
    ];

    boot = {
      kernelModules = [ "nf_nat_ftp" ];
      kernel.sysctl = {
        "net.ipv4.conf.all.forwarding" = mkOverride 99 true;
        "net.ipv4.conf.default.forwarding" = mkOverride 99 true;
      } // optionalAttrs cfg.enableIPv6 {
        # Do not prevent IPv6 autoconfiguration.
        # See <http://strugglers.net/~andy/blog/2011/09/04/linux-ipv6-router-advertisements-and-forwarding/>.
        "net.ipv6.conf.all.accept_ra" = mkOverride 99 2;
        "net.ipv6.conf.default.accept_ra" = mkOverride 99 2;

        # Forward IPv6 packets.
        "net.ipv6.conf.all.forwarding" = mkOverride 99 true;
        "net.ipv6.conf.default.forwarding" = mkOverride 99 true;
      };
    };

    # TODO: priority offsets
    systemd.services.nat = let
      natStartRules = pkgs.writeText "nixos-nat-start.nft" ''
          add table inet nixos-nat
          flush table inet nixos-nat
          delete table inet nixos-nat

          table ip nixos-nat {

            chain prerouting	{ type nat hook prerouting priority dstnat; }
            chain input		{ type nat hook input priority 100; }
            chain output		{ type nat hook output priority -100; }
            chain postrouting	{ type nat hook postrouting priority srcnat; }

            chain nixos-nat-pre {
              # We can't match on incoming interface in POSTROUTING, so
              # mark packets coming from the internal interfaces.
              ${
                concatMapStrings (iface: ''
                  iifname "${iface}" counter meta mark set 1
                '') cfg.internalInterfaces
              }
            }

            chain nixos-nat-post {
              # NAT the marked packets.
              ${
                optionalString (cfg.internalInterfaces != [ ]) ''
                  ${oifExternal} meta mark 1 counter ${dest}
                ''
              }

              # NAT packets coming from the internal IPs.
              ${
                concatMapStrings (range: ''
                  ${oifExternal} ip saddr ${range} counter ${dest}
                '') cfg.internalIPs
              }
            }
          }

        # NAT from external ports to internal ports.
        ${concatMapStrings (fwd:
          let nftSourcePort = iptablesPortsToNftables fwd.sourcePort;
          in ''
            add rule ip nixos-nat nixos-nat-pre iifname "${cfg.externalInterface}" ${fwd.proto} dport ${nftSourcePort} counter dnat to ${fwd.destination}

            ${concatMapStrings (loopbackip:
              let
                m = builtins.match "([0-9.]+):([0-9-]+)" fwd.destination;
                destinationIP = if (m == null) then
                  throw "bad ip:ports `${fwd.destination}'"
                else
                  elemAt m 0;
                destinationPorts = if (m == null) then
                  throw "bad ip:ports `${fwd.destination}'"
                else
                  elemAt m 1;
              in ''
                # Allow connections to ${loopbackip}:${nftSourcePort} from the host itself
                add rule ip nixos-nat output ip daddr ${loopbackip} ${fwd.proto} dport ${nftSourcePort} counter dnat to ${fwd.destination}

                # Allow connections to ${loopbackip}:${nftSourcePort} from other hosts behind NAT
                add rule ip nixos-nat nixos-nat-pre ip daddr ${loopbackip} ${fwd.proto} dport ${nftSourcePort} counter dnat to ${fwd.destination}

                add rule ip nixos-nat nixos-nat-post ip daddr ${destinationIP} ${fwd.proto} dport ${
                  iptablesPortsToNftables destinationPorts
                } counter snat to ${loopbackip}
              '') fwd.loopbackIPs}
          '') cfg.forwardPorts}

        ${optionalString (cfg.dmzHost != null) ''
          add rule ip nixos-nat nixos-nat-pre iifname "${cfg.externalInterface}" counter dnat to ${cfg.dmzHost}
        ''}

        # Append our chains to the nat tables
        add rule ip nixos-nat prerouting counter jump nixos-nat-pre
        add rule ip nixos-nat postrouting counter jump nixos-nat-post
      '';

      natStopRules = ''
        add table inet nixos-nat
        flush table inet nixos-nat
        delete table inet nixos-nat
      '';

    in {
      description = "Network Address Translation";
      wantedBy = [ "network.target" ];
      after = [ "network-pre.target" "systemd-modules-load.service" ];
      # TODO: make packages configurable
      path = [ pkgs.nftables ];
      unitConfig.ConditionCapability = "CAP_NET_ADMIN";

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      script = "nft -f ${natStartRules}";
      preStop = "nft -f ${natStopRules}";
    };

  };

}
