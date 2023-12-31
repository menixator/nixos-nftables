{ config, lib, pkgs, ... }:

# TODO: check if IPv6 DHCP works with rpfilter on
# TODO: priorityOffset validation
with lib;

let
  inherit (lib)
    mkOption types flip concatMapStrings optionalString concatStrings
    mapAttrsToList mapAttrs optionals;

  cfg = config.networking.firewall;

  inherit (config.boot.kernelPackages) kernel;

  kernelHasRPFilter =
    ((kernel.config.isEnabled or (x: false)) "IP_NF_MATCH_RPFILTER")
    || (kernel.features.netfilterRPFilter or false);

  defaultInterface = {
    default = mapAttrs (name: value: cfg.${name}) commonOptions;
  };
  allInterfaces = defaultInterface // cfg.interfaces;

  optionalStringForIPv6 = optionalString config.networking.enableIPv6;

  canonicalizePortList = ports:
    lib.unique (builtins.sort builtins.lessThan ports);

  commonOptions = {
    allowedTCPPorts = mkOption {
      type = types.listOf types.port;
      default = [ ];
      apply = canonicalizePortList;
      example = [ 22 80 ];
      description = ''
        List of TCP ports on which incoming connections are
        accepted.
      '';
    };

    allowedTCPPortRanges = mkOption {
      type = types.listOf (types.attrsOf types.port);
      default = [ ];
      example = [{
        from = 8999;
        to = 9003;
      }];
      description = ''
        A range of TCP ports on which incoming connections are
        accepted.
      '';
    };

    allowedUDPPorts = mkOption {
      type = types.listOf types.port;
      default = [ ];
      apply = canonicalizePortList;
      example = [ 53 ];
      description = ''
        List of open UDP ports.
      '';
    };

    allowedUDPPortRanges = mkOption {
      type = types.listOf (types.attrsOf types.port);
      default = [ ];
      example = [{
        from = 60000;
        to = 61000;
      }];
      description = ''
        Range of open UDP ports.
      '';
    };
  };
in {

  # Disable the firewall module so that we don't get a multiple definition error
  disabledModules = [
    "services/networking/firewall.nix"
    "services/networking/firewall-iptables.nix"
    "services/networking/firewall-nftables.nix"
  ];

  ###### interface

  options = {

    networking.firewall = {

      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether to enable the firewall.  This is a simple stateful
          firewall that blocks connection attempts to unauthorised TCP
          or UDP ports on this machine.  It does not affect packet
          forwarding.
        '';
      };

      sets = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Definitions of any sets that can then be used within the firewall rules
        '';
      };

      extraInputRules = mkOption {
        type = types.lines;
        default = "";
        example = "";
        description = lib.mdDoc ''
          Ignored
        '';
      };

      extraForwardRules = mkOption {
        type = types.lines;
        default = "";
        example = "";
        description = lib.mdDoc ''
          Ignored
        '';
      };

      package = mkOption {
        type = types.package;
        default = pkgs.nftables;
        defaultText = literalExpression "pkgs.nftables";
        example = literalExpression "pkgs.nftables";
        description = ''
          The iptables package to use for running the firewall service."
        '';
      };

      logRefusedConnections = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether to log rejected or dropped incoming connections.
          Note: The logs are found in the kernel logs, i.e. dmesg
          or journalctl -k.
        '';
      };

      logRefusedPackets = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to log all rejected or dropped incoming packets.
          This tends to give a lot of log messages, so it's mostly
          useful for debugging.
          Note: The logs are found in the kernel logs, i.e. dmesg
          or journalctl -k.
        '';
      };

      logRefusedUnicastsOnly = mkOption {
        type = types.bool;
        default = true;
        description = ''
          If <option>networking.firewall.logRefusedPackets</option>
          and this option are enabled, then only log packets
          specifically directed at this machine, i.e., not broadcasts
          or multicasts.
        '';
      };

      rejectPackets = mkOption {
        type = types.bool;
        default = false;
        description = ''
          If set, refused packets are rejected rather than dropped
          (ignored).  This means that an ICMP "port unreachable" error
          message is sent back to the client (or a TCP RST packet in
          case of an existing connection).  Rejecting packets makes
          port scanning somewhat easier.
        '';
      };

      trustedInterfaces = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "enp0s2" ];
        description = ''
          Traffic coming in from these interfaces will be accepted
          unconditionally.  Traffic from the loopback (lo) interface
          will always be accepted.
        '';
      };

      allowPing = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether to respond to incoming ICMPv4 echo requests
          ("pings").  ICMPv6 pings are always allowed because the
          larger address space of IPv6 makes network scanning much
          less effective.
        '';
      };

      pingLimit = mkOption {
        type = types.nullOr (types.separatedString " ");
        default = null;
        example = "--limit 1/minute --limit-burst 5";
        description = ''
          If pings are allowed, this allows setting rate limits
          on them.  If non-null, this option should be in the form of
          flags like "--limit 1/minute --limit-burst 5"
        '';
      };

      checkReversePath = mkOption {
        type = types.either types.bool (types.enum [ "strict" "loose" ]);
        default = kernelHasRPFilter;
        defaultText = literalDocBook
          "<literal>true</literal> if supported by the chosen kernel";
        example = "loose";
        description = ''
          Performs a reverse path filter test on a packet.  If a reply
          to the packet would not be sent via the same interface that
          the packet arrived on, it is refused.
          If using asymmetric routing or other complicated routing, set
          this option to loose mode or disable it and setup your own
          counter-measures.
          This option can be either true (or "strict"), "loose" (only
          drop the packet if the source address is not reachable via any
          interface) or false.  Defaults to the value of
          kernelHasRPFilter.
        '';
      };

      logReversePathDrops = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Logs dropped packets failing the reverse path filter test if
          the option networking.firewall.checkReversePath is enabled.
        '';
      };

      connectionTrackingModules = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "ftp"
          "irc"
          "sane"
          "sip"
          "tftp"
          "amanda"
          "h323"
          "netbios_sn"
          "pptp"
          "snmp"
        ];
        description = ''
          List of connection-tracking helpers that are auto-loaded.
          The complete list of possible values is given in the example.
          As helpers can pose as a security risk, it is advised to
          set this to an empty list and disable the setting
          networking.firewall.autoLoadConntrackHelpers unless you
          know what you are doing. Connection tracking is disabled
          by default.
          Loading of helpers is recommended to be done through the
          CT target.  More info:
          https://home.regit.org/netfilter-en/secure-use-of-helpers/
        '';
      };

      autoLoadConntrackHelpers = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Whether to auto-load connection-tracking helpers.
          See the description at networking.firewall.connectionTrackingModules
          (needs kernel 3.5+)
        '';
      };

      preRefuseRules = mkOption {
        type = types.lines;
        default = "";
        example = "udp port 53 accept";
        description = ''
          Custom nft rules to be added just before the firewall decides to reject a packet
        '';
      };

      preAllowRules = mkOption {
        type = types.lines;
        default = "";
        example = "udp port 53 accept";
        description = ''
          Custom nft rules to be added just before the firewall decides to allow a packet
        '';
      };

      priorityOffset = mkOption {
        type = types.ints.s8;
        default = 1;
        description = ''
          An nft priority expression which will be used for the rpfilter base chain
          You may use any nft priority expression that's valid in the `input` hook.
          https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
        '';
      };

      extraRules = mkOption {
        type = types.lines;
        default = "";
        example = "udp port 53 accept";
        description = ''
          Additional nft rules to be added to the firewall
        '';
      };

      extraCommands = mkOption {
        type = types.lines;
        default = "";
        example = "iptables -A INPUT -p icmp -j ACCEPT";
        description = ''
          Additional shell commands executed as part of the firewall
          initialisation script.  These are executed just before the
          final "reject" firewall rule is added, so they can be used
          to allow packets that would otherwise be refused.
        '';
      };

      extraPackages = mkOption {
        type = types.listOf types.package;
        default = [ ];
        example = literalExpression "[ pkgs.ipset ]";
        description = ''
          Additional packages to be included in the environment of the system
          as well as the path of networking.firewall.extraCommands.
        '';
      };

      extraStopCommands = mkOption {
        type = types.lines;
        default = "";
        example = "iptables -P INPUT ACCEPT";
        description = ''
          Additional shell commands executed as part of the firewall
          shutdown script.  These are executed just after the removal
          of the NixOS input rule, or if the service enters a failed
          state.
        '';
      };

      defaultAllowedSet = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "";
        description = ''
          Name of the set to check against for connections connecting to opened ports 
        '';
      };

      interfaces = mkOption {
        default = { };
        type = with types; attrsOf (submodule [{ options = commonOptions; }]);
        description = ''
          Interface-specific open ports.
        '';
      };
    } // commonOptions;

  };
  ###### implementation

  # FIXME: Maybe if `enable' is false, the firewall should still be
  # built but not started by default?
  config = let

  in mkIf cfg.enable {

    warnings = let
      hasReferencesToIptables = v: (builtins.match ".*iptables.*" v) != null;

    in builtins.filter (warning: warning != "") [
      # TODO: warnings for ip6tables
      (optionalString (hasReferencesToIptables cfg.extraCommands) ''
        `networking.firewall.extraCommands' has references to `iptables'.
        This config is using `nixos-nftables` which can lead to unexpected behavior if used together with iptables.
      '')

      (optionalString (hasReferencesToIptables cfg.extraStopCommands) ''
        `networking.firewall.extraStopCommands' has references to `iptables'.
        This config is using `nixos-nftables` which can lead to unexpected behavior if used together with iptables.
      '')
    ];

    networking.firewall.trustedInterfaces = [ "lo" ];

    environment.systemPackages = [ cfg.package ] ++ cfg.extraPackages;

    # FIXME: clean up any modules that aren't required for nftables
    boot.kernelModules = (optional cfg.autoLoadConntrackHelpers "nf_conntrack")
      ++ map (x: "nf_conntrack_${x}") cfg.connectionTrackingModules;
    boot.extraModprobeConfig = optionalString cfg.autoLoadConntrackHelpers ''
      options nf_conntrack nf_conntrack_helper=1
    '';

    assertions = [
      # This is approximately "checkReversePath -> kernelHasRPFilter",
      # but the checkReversePath option can include non-boolean
      # values.
      {
        assertion = cfg.checkReversePath == false || kernelHasRPFilter;
        message = "This kernel does not support rpfilter";
      }
    ];

    systemd.services.firewall = let
      writeShScript = name: text:
        let
          dir = pkgs.writeScriptBin name ''
            #!${pkgs.runtimeShell}
            ${text}
          '';
        in "${dir}/bin/${name}";

      priorityOffset = if cfg.priorityOffset > 0 then
        "+${builtins.toString cfg.priorityOffset}"
      else
        "-${builtins.toString cfg.priorityOffset}";

      remove46Chain = table: chain: ''
        # adding the chain wont cause issues if the chain exists
        add chain inet ${table} ${chain}
        flush chain inet ${table} ${chain}
        delete chain inet ${table} ${chain}
      '';

      addChain = chain: ''
        ${chain}
      '';

      allow = ''
        # The "allow" chain just accepts packets.

        chain allow {
          counter accept
        }
      '';

      refuse = ''
        # The "refuse" chain rejects or drops packets.

        chain refuse {

          ${
            if cfg.rejectPackets then ''
              # Send a reset for existing TCP connections that we've
              # somehow forgotten about.  Send ICMP "port unreachable"
              # for everything else.
              tcp flags & (fin | syn | rst | ack) != syn counter reject with tcp reset
              counter reject
            '' else ''
              counter drop
            ''
          }

        }
      '';

      log-refuse = ''
        # The "log-refuse" chain performs logging, then
        # jumps to the "refuse" chain.

        chain log-refuse {

          ${
            optionalString cfg.logRefusedConnections ''
              tcp flags & (fin | syn | rst | ack) == syn \
                counter log prefix "refused connection: " level info
            ''
          }

          ${
            optionalString
            (cfg.logRefusedPackets && !cfg.logRefusedUnicastsOnly) ''
              meta pkttype broadcast counter log prefix "refused broadcast: " level info
              meta pkttype multicast counter log prefix "refused multicast: " level info
            ''
          }

          meta pkttype != host counter jump refuse

          ${
            optionalString cfg.logRefusedPackets ''
              counter log prefix "refused packet: " level info
            ''
          }

          counter jump refuse

        }
      '';

      rpfilter = ''
        # Perform a reverse-path test to refuse spoofers
        # For now, we just drop, as the raw table doesn't have a log-refuse yet
        chain rpfilter {
          type filter hook prerouting priority raw${priorityOffset}; policy accept;

          fib saddr . mark . iif oif != 0 counter return

          # Allows this host to act as a DHCP4 client without first having to use APIPA
          udp sport 67 udp dport 68 counter return

          # Allows this host to act as a DHCPv4 server
          ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter return

          ${
            optionalString cfg.logReversePathDrops ''
              counter log prefix "rpfilter drop: " level info
            ''
          }

          counter drop
        }
      '';

      core = ''
        # The "core" chain does the actual work.
        chain core {
          type filter hook input priority filter${priorityOffset}; policy accept;

          # Accept all traffic on the trusted interfaces.
          ${
            flip concatMapStrings cfg.trustedInterfaces (iface: ''
              iifname "${iface}" counter jump pre-allow comment "trusted interface: ${iface}"
            '')
          }

          # Accept packets from established or related connections.
          ct state established,related counter jump pre-allow

          # Accept connections to the allowed TCP ports.
          ${
            concatStrings (mapAttrsToList (iface: cfg:
              concatMapStrings (port: ''
                ${
                  optionalString (iface != "default") ''iifname "${iface}" ''
                }tcp dport ${toString port} counter jump pre-allow comment "accept TCP requests from ports ${toString port}"
              '') cfg.allowedTCPPorts) allInterfaces)
          }

          # Accept connections to the allowed TCP port ranges.
          ${
            concatStrings (mapAttrsToList (iface: cfg:
              concatMapStrings (rangeAttr:
                let
                  range = toString rangeAttr.from + "-" + toString rangeAttr.to;
                in ''
                  ${
                    optionalString (iface != "default") ''iifname "${iface}" ''
                  }tcp dport ${range} counter jump pre-allow comment "accept TCP requests from ports ${range}"
                '') cfg.allowedTCPPortRanges) allInterfaces)
          }

          # Accept connections to the allowed UDP ports.
          ${
            concatStrings (mapAttrsToList (iface: cfg:
              concatMapStrings (port: ''
                ${
                  optionalString (iface != "default") ''iifname "${iface}" ''
                }udp dport ${toString port} counter jump pre-allow comment "accept UDP connections on port ${toString port}"
              '') cfg.allowedUDPPorts) allInterfaces)
          }

          # Accept connections to the allowed UDP port ranges.
          ${
            concatStrings (mapAttrsToList (iface: cfg:
              concatMapStrings (rangeAttr:
                let
                  range = toString rangeAttr.from + "-" + toString rangeAttr.to;
                in ''
                  ${
                    optionalString (iface != "default") ''iifname "${iface}" ''
                  }udp dport ${range} counter jump pre-allow comment "accept UDP requests from ports ${range}"
                '') cfg.allowedUDPPortRanges) allInterfaces)
          }

          ${
          # TODO: ping limit
          # Optionally respond to ICMPv4 pings.
            optionalString cfg.allowPing ''
              icmp type echo-request counter jump pre-allow comment "respond to ICMPv4 echo-requests(pings)" 
            ''
          }

          ${
          # FIXME: why is this here and not in rpfilter? 
            optionalStringForIPv6 ''
              # Accept all ICMPv6 messages except redirects and node
              # information queries (type 139).  See RFC 4890, section
              # 4.4.
              # FIXME: we're dropping this?

              # FIXME: we say that we are accepting all ICMPv6 messages 
              # redirects and node information queries are being dropped but
              # only nd-redirect gets dropped

              icmpv6 type nd-redirect counter drop comment "drop ICMPv6 nd-redirect"
              
              meta l4proto ipv6-icmp counter jump pre-allow comment "allow all other ICMPv6 requests through"

              # Allow this host to act as a DHCPv6 client
              ip6 daddr fe80::/64 udp dport 546 counter jump pre-allow comment "allow this host to act as a DHCPv6 client"
            ''
          }


          counter jump pre-refuse
        }
      '';
      pre-allow = ''
        # The "pre-allow" chain runs user defined rules before jumping
        # to the allow chain
        chain pre-allow {
          ${cfg.preAllowRules}
          counter jump allow
        }
      '';

      pre-refuse = ''
        # The "pre-refuse" chain runs custom rules before jumping to
        # the log-refuse.

        chain pre-refuse {
          ${cfg.preRefuseRules}
          counter jump log-refuse
        }
      '';

      firewallCfg = pkgs.writeText "rules.nft" ''
        add table inet nixos-firewall
        flush table inet nixos-firewall
        delete table inet nixos-firewall

        add table inet nixos-firewall {
          comment "NixOS Firewall for IPv4/IPv6"
        ${optionalString ((builtins.length cfg.sets) > 0) ''
                  # defined sets
          ${builtins.concatStringsSep "\n" cfg.sets}
        ''}

        # these two chains should not have dependencies
        ${addChain allow}
        ${addChain refuse}

        # This chain depends on allow
        ${addChain pre-allow}

        # This chain depends on refuse
        ${addChain log-refuse}

        # This chain depends on refuse
        ${addChain pre-refuse}

        ${optionalString (kernelHasRPFilter && (cfg.checkReversePath != false))
        (addChain rpfilter)}
        ${addChain core}

        };

        # networking.firewall.extraRules {

        ${cfg.extraRules}

        # } // networking.firewall.extraRules
      '';

      startScript = writeShScript "firewall-start" ''
        # nixos firewall start script
        nft -f ${firewallCfg}

        # networking.firewall.extraCommands
        ${cfg.extraCommands}
      '';

      reloadScript = writeShScript "firewall-reload" ''
        # nixos firewall reload script

        # The -c will dry run the new config and complain if there are any
        # issues.
        if ! nft -c -f ${firewallCfg}; then
          echo "The Firewall config has issues. Refusing to reload"
          exit 1
        fi

        # since extraStopCommands needs to run here, we will first nuke the
        # firewall, and start dropping packets. This is to prevent any packets
        # that would have otherwise been dropped from reaching the system while
        # `extraStopCommands` are running. We do not have to do any cleanup on
        # this as the firewall will nuke the the nixos-firewall table if it exists on
        # startup

        # TODO: inet support please

        nft -f - <<EOF
          add table inet nixos-firewall
          flush table inet nixos-firewall
          delete table inet nixos-firewall

          table inet nixos-firewall {
            chain temp {
              # TODO: 
              type filter hook input priority filter; policy accept;

              # Allow already established connections through
              ct state established,related accept
               
              # Drop everything else
              drop
            }
          }
        EOF

        # networking.firewall.extraCommands
        ${cfg.extraStopCommands}

        if ! ${startScript}; then
          echo "Failed to reload firewall... Stopping"
          ${stopScript}
          exit 1
        fi
      '';

      stopScript = writeShScript "firewall-stop" ''

        nft -f - <<EOF
          add table inet nixos-firewall
          flush table inet nixos-firewall
          delete table inet nixos-firewall
        EOF

        # networking.firewall.extraStopCommands
        ${cfg.extraStopCommands}
      '';

    in {
      description = "Firewall";
      wantedBy = [ "sysinit.target" ];
      wants = [ "network-pre.target" ];
      before = [ "network-pre.target" ];
      after = [ "systemd-modules-load.service" ];

      path = [ cfg.package ] ++ cfg.extraPackages;

      # FIXME: this module may also try to load kernel modules, but
      # containers don't have CAP_SYS_MODULE.  So the host system had
      # better have all necessary modules already loaded.
      unitConfig.ConditionCapability = "CAP_NET_ADMIN";
      unitConfig.DefaultDependencies = false;

      reloadIfChanged = true;

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # the @ will make the the second specified token to be passed as "argv[0]" to the
        # executed process (instead of the actual filename), followed by the
        # further arguments specified.
        ExecStart = "@${startScript} firewall-start";
        ExecReload = "@${reloadScript} firewall-reload";
        ExecStop = "@${stopScript} firewall-stop";
      };
    };

  };
}
