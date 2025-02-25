{ config, lib, pkgs, ... }:

with lib;

let
  inherit (lib) mkIf concatMapStrings optionalString elemAt isInt;

  cfg = config.networking.nat;

  dest =
    if cfg.externalIP == null then
      "masquerade"
    else
      "snat ip to ${cfg.externalIP}";

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

in
{

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


    networking.nat.mark = mkOption {
      type = types.ints.u32;
      default = 1;
      example = "1";
      description = lib.mdDoc ''
        The mark used for natting
      '';
    };

    # actually a 32bit but it can overrun into other hooks so
    networking.nat.priorityOffset = mkOption {
      type = types.ints.s8;
      default = 0;
      description = ''
        An nft priority expression which will be used for the rpfilter base chain
        You may use any nft priority expression that's valid in the `input` hook.
        https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
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
    systemd.services.nat =
      let
        mark = (toString config.networking.nat.mark);

        # startingPriority can be a string or a number
        reducePriority = startingPriority: offset:
          let
            signedStringify = int:
              if int > 0 then "+${toString int}"
              else toString int;

          in
          if offset == 0 then toString startingPriority else
          if builtins.typeOf startingPriority == "string" then
            "${startingPriority}${signedStringify offset}"
          else
            "${ toString (startingPriority + offset)}";


        natStartRules = pkgs.writeText "nixos-nat-start.nft" ''
            add table inet nixos-nat
            flush table inet nixos-nat
            delete table inet nixos-nat

            table inet nixos-nat {

              chain prerouting	{ type nat hook prerouting priority ${reducePriority "dstnat" cfg.priorityOffset}; }
              chain input		{ type nat hook input priority ${reducePriority 100 cfg.priorityOffset}; }
              chain output		{ type nat hook output priority ${reducePriority (-100) cfg.priorityOffset}; }
              chain postrouting	{ type nat hook postrouting priority ${reducePriority "srcnat" cfg.priorityOffset}; }

              chain nixos-nat-pre {
                # We can't match on incoming interface in POSTROUTING, so
                # mark packets coming from the internal interfaces.
                ${
                  concatMapStrings (iface: ''
                    iifname "${iface}" counter meta mark set ${mark}
                  '') cfg.internalInterfaces
                }
              }

              chain nixos-nat-post {
                # NAT the marked packets.
                ${
                  optionalString (cfg.internalInterfaces != [ ]) ''
                    ${oifExternal} meta mark ${mark} counter ${dest}
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
              add rule inet nixos-nat nixos-nat-pre iifname "${cfg.externalInterface}" ${fwd.proto} dport ${nftSourcePort} counter dnat ip to ${fwd.destination}

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
                  #FIXME: DNAT to ipv6 is broken
                in ''
                  # Allow connections to ${loopbackip}:${nftSourcePort} from the host itself
                  add rule inet nixos-nat output ip daddr ${loopbackip} ${fwd.proto} dport ${nftSourcePort} counter dnat ip to ${fwd.destination}

                  # Allow connections to ${loopbackip}:${nftSourcePort} from other hosts behind NAT
                  add rule inet nixos-nat nixos-nat-pre ip daddr ${loopbackip} ${fwd.proto} dport ${nftSourcePort} counter dnat ip to ${fwd.destination}

                  add rule inet nixos-nat nixos-nat-post ip daddr ${destinationIP} ${fwd.proto} dport ${
                    iptablesPortsToNftables destinationPorts
                  } counter snat ip to ${loopbackip}
                '') fwd.loopbackIPs}
            '') cfg.forwardPorts}

          ${optionalString (cfg.dmzHost != null) ''
            add rule inet nixos-nat nixos-nat-pre iifname "${cfg.externalInterface}" counter dnat ip to ${cfg.dmzHost}
          ''}

          # Append our chains to the nat tables
          add rule inet nixos-nat prerouting counter jump nixos-nat-pre
          add rule inet nixos-nat postrouting counter jump nixos-nat-post
        '';

        natStopRules = pkgs.writeText "nixos-nat-start.nft" ''
          add table inet nixos-nat
          flush table inet nixos-nat
          delete table inet nixos-nat
        '';

      in
      {
        description = "Network Address Translation";
        wantedBy = [ "sysinit.target" ];
        wants = [ "network-pre.target" ];
        before = [ "network-pre.target" ];
        after = [ "systemd-modules-load.service" ];

        # FIXME: this module may also try to load kernel modules, but
        # containers don't have CAP_SYS_MODULE.  So the host system had
        # better have all necessary modules already loaded.
        unitConfig.ConditionCapability = "CAP_NET_ADMIN";
        unitConfig.DefaultDependencies = false;
        # TODO: make packages configurable
        path = [ pkgs.nftables ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };

        script = "nft -f ${natStartRules}";
        preStop = "nft -f ${natStopRules}";
      };

  };

}
