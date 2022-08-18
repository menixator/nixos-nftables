{ config, lib, pkgs, ... }:

with lib;

let
  inherit (lib)
    mkOption types flip concatMapStrings optionalString concatStrings
    mapAttrsToList mapAttrs optionals;

  utils = import ./utils.nix;

  cfg = config.networking.firewall;

  base = pkgs.writeText "base.nft" ''
    # Ipv4
    #===========================================================================
    ${utils.genIPBaseTables "ip"}

    ${optionalString config.networking.enableIPv6 ''
      # Ipv6
      #===========================================================================
      ${utils.genIPBaseTables "ip6"}

    ''}
  '';

  inherit (config.boot.kernelPackages) kernel;

  kernelHasRPFilter =
    ((kernel.config.isEnabled or (x: false)) "IP_NF_MATCH_RPFILTER")
    || (kernel.features.netfilterRPFilter or false);

  defaultInterface = {
    default = mapAttrs (name: value: cfg.${name}) commonOptions;
  };
  allInterfaces = defaultInterface // cfg.interfaces;

  remove46Chain = table: chain: ''
    flush chain ip ${table} ${chain}
    delete chain ip ${table} ${chain}

    ${optionalString config.networking.enableIPv6 ''
      flush chain ip6 ${table} ${chain}
      delete chain ip6 ${table} ${chain}

    ''}
  '';

  add46Entity = table: ent: ''
    table ip ${table} {

    ${ent "v4"}

    }

    ${optionalString config.networking.enableIPv6 ''
      table ip6 ${table} {

      ${ent "v6"}

      }
    ''}
  '';

  nixos-fw-accept = family: ''
    # The "nixos-fw-accept" chain just accepts packets.

    chain nixos-fw-accept {
      counter accept
    }
  '';

  nixos-fw-refuse = family: ''
    # The "nixos-fw-refuse" chain rejects or drops packets.

    chain nixos-fw-refuse {

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

  nixos-fw-log-refuse = family: ''
    # The "nixos-fw-log-refuse" chain performs logging, then
    # jumps to the "nixos-fw-refuse" chain.

    chain nixos-fw-log-refuse {

      ${
        optionalString cfg.logRefusedConnections ''
          tcp flags & (fin | syn | rst | ack) == syn \
            counter log prefix "refused connection: " level info
        ''
      }

      ${
        optionalString (cfg.logRefusedPackets && !cfg.logRefusedUnicastsOnly) ''
          meta pkttype broadcast counter log prefix "refused broadcast: " level info
          meta pkttype multicast counter log prefix "refused multicast: " level info
        ''
      }

      meta pkttype != host counter jump nixos-fw-refuse

      ${
        optionalString cfg.logRefusedPackets ''
          counter log prefix "refused packet: " level info
        ''
      }

      counter jump nixos-fw-refuse

    }
  '';

  nixos-fw-rpfilter = family: ''
    # Perform a reverse-path test to refuse spoofers
    # For now, we just drop, as the raw table doesn't have a log-refuse yet
    chain nixos-fw-rpfilter {

      fib saddr . mark . iif oif != 0 counter return

      ${
        optionalString (family == "v4") ''
          # Allows this host to act as a DHCP4 client without first having to use APIPA
          udp sport 67 udp dport 68 counter return

          # Allows this host to act as a DHCPv4 server
          ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter return
        ''
      }

      ${
        optionalString cfg.logReversePathDrops ''
          counter log prefix "rpfilter drop: " level info
        ''
      }

      counter drop
    }
  '';

  nixos-fw-core = family: ''
    # The "nixos-fw-core" chain does the actual work.
    chain nixos-fw-core {

      # Accept all traffic on the trusted interfaces.
      ${
        flip concatMapStrings cfg.trustedInterfaces (iface: ''
          iifname "${iface}" counter jump nixos-fw-pre-accept
        '')
      }

      # Accept packets from established or related connections.
      ct state established,related counter jump nixos-fw-pre-accept

      # Accept connections to the allowed TCP ports.
      ${
        concatStrings (mapAttrsToList (iface: cfg:
          concatMapStrings (port: ''
            ${
              optionalString (iface != "default") ''iifname "${iface}" ''
            }tcp dport ${toString port} counter jump nixos-fw-pre-accept
          '') cfg.allowedTCPPorts) allInterfaces)
      }

      # Accept connections to the allowed TCP port ranges.
      ${
        concatStrings (mapAttrsToList (iface: cfg:
          concatMapStrings (rangeAttr:
            let range = toString rangeAttr.from + "-" + toString rangeAttr.to;
            in ''
              ${
                optionalString (iface != "default") ''iifname "${iface}" ''
              }tcp dport ${range} counter jump nixos-fw-pre-accept
            '') cfg.allowedTCPPortRanges) allInterfaces)
      }

      # Accept connections to the allowed UDP ports.
      ${
        concatStrings (mapAttrsToList (iface: cfg:
          concatMapStrings (port: ''
            ${
              optionalString (iface != "default") ''iifname "${iface}" ''
            }udp dport ${toString port} counter jump nixos-fw-pre-accept
          '') cfg.allowedUDPPorts) allInterfaces)
      }

      # Accept connections to the allowed UDP port ranges.
      ${
        concatStrings (mapAttrsToList (iface: cfg:
          concatMapStrings (rangeAttr:
            let range = toString rangeAttr.from + "-" + toString rangeAttr.to;
            in ''
              ${
                optionalString (iface != "default") ''iifname "${iface}" ''
              }udp dport ${range} counter jump nixos-fw-pre-accept
            '') cfg.allowedUDPPortRanges) allInterfaces)
      }

      ${
      # TODO: ping limit
        optionalString (family == "v4") ''
          # Optionally respond to ICMPv4 pings.
          ${optionalString cfg.allowPing ''
            icmp type echo-request counter jump nixos-fw-pre-accept
          ''}
        ''
      }

      ${
        optionalString (family == "v6") ''
          # Accept all ICMPv6 messages except redirects and node
          # information queries (type 139).  See RFC 4890, section
          # 4.4.
          icmpv6 type nd-redirect counter drop
          meta l4proto 58 counter jump nixos-fw-pre-accept

          # Allow this host to act as a DHCPv6 client
          ip6 daddr fe80::/64 udp dport 546 counter jump nixos-fw-pre-accept
        ''
      }


      counter jump nixos-fw-pre-refuse
      ${
      # TODO: Isnt this broken?
        optionalString config.networking.enableIPv6 ''
          counter jump nixos-fw-pre-refuse
        ''
      }
    }
  '';

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
  disabledModules = [ "services/networking/firewall.nix" ];

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

      preAcceptRules = mkOption {
        type = types.lines;
        default = "";
        example = "udp port 53 accept";
        description = ''
          Custom nft rules to be added just before the firewall decides to accept a packet
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

      nixos-fw-pre-accept = family: ''
        # The "nixos-fw-pre-accept" chain runs user defined rules before jumping
        # to the nixos-fw-accept chain
        chain nixos-fw-pre-accept {
          ${cfg.preAcceptRules}
          counter jump nixos-fw-accept
        }
      '';

      nixos-fw-pre-refuse = family: ''
        # The "nixos-fw-pre-refuse" chain runs custom rules before jumping to
        # the nixos-fw-log-refuse.

        chain nixos-fw-pre-refuse {
          ${cfg.preRefuseRules}
          counter jump nixos-fw-log-refuse
        }
      '';

      firewallCfg = pkgs.writeText "rules.nft" ''
        include "${base}"

        ${add46Entity "filter" nixos-fw-accept}
        ${add46Entity "filter" nixos-fw-pre-accept}
        ${add46Entity "filter" nixos-fw-refuse}
        ${add46Entity "filter" nixos-fw-log-refuse}
        ${add46Entity "filter" nixos-fw-pre-refuse}
        ${optionalString
        (kernelHasRPFilter && (cfg.checkReversePath != false)) ''
          ${add46Entity "raw" nixos-fw-rpfilter}
          add rule ip raw prerouting counter jump nixos-fw-rpfilter
          ${optionalString config.networking.enableIPv6 ''
            add rule ip6 raw prerouting counter jump nixos-fw-rpfilter
          ''}
        ''}
        ${add46Entity "filter" nixos-fw-core}

        # networking.firewall.extraRules {

        ${cfg.extraRules}

        # } // networking.firewall.extraRules


        add rule ip filter input counter jump nixos-fw-core # handle 11
        ${optionalString config.networking.enableIPv6 ''
          add rule ip6 filter input counter jump nixos-fw-core # handle 22
        ''}
      '';

      startScript = writeShScript "firewall-start" ''
        # nixos firewall start script
        ${cfg.package}/bin/nft -f ${firewallCfg}

        # networking.firewall.extraCommands
        ${cfg.extraCommands}
      '';

      # TODO: Fix this
      reloadScript = writeShScript "firewall-reload" ''
        # nixos firewall reload script




        ${cfg.package}/bin/nft -f ${firewallCfg}

        # networking.firewall.extraCommands
        ${cfg.extraCommands}
      '';

      # assuming that prefix is a valid nft identifier there should not be a need to escape anything
      generateNftNukeRules = prefix: ''
        read -r -d "" FILTER <<EOF
        [
        .nftables[] |
          select(
            .rule and (.rule.chain | startswith("${prefix}") | not )
            and (
              .rule.expr[] | select(.jump != null and (.jump.target | startswith("${prefix}")) )
            )
         )
        | [.rule.family, .rule.table, .rule.chain, .rule.handle | tostring ] | join("\t")
        ] | join("\\n")
        EOF
         
        RULES_TO_BE_REMOVED=$(sudo nft -j  list ruleset | jq -r "$FILTER")
        NFT_RULE_REMOVE_COMMANDS=""
         
        if [[ "$RULES_TO_BE_REMOVED" != "" && $RULES_TO_BE_REMOVED != $'\n' ]]; then
          while read -r rule; do
            while IFS=$'\t' read -r    \
              NFT_FAMILY        \
              NFT_TABLE         \
              NFT_CHAIN         \
              NFT_HANDLE        \
              ;
            do 
              printf -v NFT_RULE_REMOVE_COMMANDS "$NTF_RULE_REMOVE_COMMANDS\ndelete rule $NFT_FAMILY $NFT_TABLE $NFT_CHAIN handle $NFT_HANDLE"
            done <<< "$rule"
          done <<< "$RULES_TO_BE_REMOVED"
        fi

      '';

      stopScript = writeShScript "firewall-stop" ''
        ${generateNftNukeRules "nixos-fw-"}

        sudo nft -f - <<EOF
        $NFT_RULE_REMOVE_COMMANDS

        # the order matters here
        ${remove46Chain "filter" "nixos-fw-core"}
        ${remove46Chain "filter" "nixos-fw-pre-refuse"}
        ${remove46Chain "filter" "nixos-fw-log-refuse"}
        ${remove46Chain "filter" "nixos-fw-refuse"}

        ${remove46Chain "filter" "nixos-fw-pre-accept"}
        ${remove46Chain "filter" "nixos-fw-accept"}
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

      path = [ cfg.package ] ++ cfg.extraPackages ++ [ pkgs.jq ];

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
