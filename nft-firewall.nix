{ config, lib, pkgs, ... }:

with lib;

let
  inherit (lib)
    mkOption types flip concatMapStrings optionalString concatStrings
    mapAttrsToList mapAttrs optionals;

  cfg = config.networking.firewall;

  # This is ordered to match iptables-save, so the diffs are smaller.
  # Order is not important once this module is no longer an active
  # porting job.
  defaultConfigs = [
    "ipv4-nat.nft"
    "ipv4-raw.nft"
    "ipv4-filter.nft"
    # "ipv4-mangle.nft"
  ] ++ optionals config.networking.enableIPv6 [
    "ipv6-filter.nft"
    #"ipv6-mangle.nft"
    "ipv6-nat.nft"
    "ipv6-raw.nft"
  ];

  inherit (config.boot.kernelPackages) kernel;

  kernelHasRPFilter =
    ((kernel.config.isEnabled or (x: false)) "IP_NF_MATCH_RPFILTER")
    || (kernel.features.netfilterRPFilter or false);

  defaultInterface = {
    default = mapAttrs (name: value: cfg.${name}) commonOptions;
  };
  allInterfaces = defaultInterface // cfg.interfaces;

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

  nixos-fw = family: ''
    # The "nixos-fw" chain does the actual work.
    chain nixos-fw {

      # Accept all traffic on the trusted interfaces.
      ${
        flip concatMapStrings cfg.trustedInterfaces (iface: ''
          iifname "${iface}" counter jump nixos-fw-accept
        '')
      }

      # Accept packets from established or related connections.
      ct state established,related counter jump nixos-fw-accept

      # Accept connections to the allowed TCP ports.
      ${
        concatStrings (mapAttrsToList (iface: cfg:
          concatMapStrings (port: ''
            ${
              optionalString (iface != "default") ''iifname "${iface}" ''
            }tcp dport ${toString port} counter jump nixos-fw-accept
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
              }tcp dport ${range} counter jump nixos-fw-accept
            '') cfg.allowedTCPPortRanges) allInterfaces)
      }

      # Accept connections to the allowed UDP ports.
      ${
        concatStrings (mapAttrsToList (iface: cfg:
          concatMapStrings (port: ''
            ${
              optionalString (iface != "default") ''iifname "${iface}" ''
            }udp dport ${toString port} counter jump nixos-fw-accept
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
              }udp dport ${range} counter jump nixos-fw-accept
            '') cfg.allowedUDPPortRanges) allInterfaces)
      }

      ${
        optionalString (family == "v4") ''
          # Optionally respond to ICMPv4 pings.
          ${optionalString cfg.allowPing ''
            icmp type echo-request counter jump nixos-fw-accept
          ''}
        ''
      }

      ${
        optionalString (family == "v6") ''
          # Accept all ICMPv6 messages except redirects and node
          # information queries (type 139).  See RFC 4890, section
          # 4.4.
          icmpv6 type nd-redirect counter drop
          meta l4proto 58 counter jump nixos-fw-accept

          # Allow this host to act as a DHCPv6 client
          ip6 daddr fe80::/64 udp dport 546 counter jump nixos-fw-accept
        ''
      }
    }
  '';

  firewallCfg = pkgs.writeText "rules.nft" ''
    flush ruleset

    ${flip concatMapStrings defaultConfigs (configFile: ''
      include "${pkgs.nftables}/share/nftables/${configFile}"
    '')}

    ${add46Entity "filter" nixos-fw-accept}
    ${add46Entity "filter" nixos-fw-refuse}
    ${add46Entity "filter" nixos-fw-log-refuse}
    ${optionalString (kernelHasRPFilter && (cfg.checkReversePath != false)) ''
      ${add46Entity "raw" nixos-fw-rpfilter}
      add rule ip raw prerouting counter jump nixos-fw-rpfilter
      ${optionalString config.networking.enableIPv6 ''
        add rule ip6 raw prerouting counter jump nixos-fw-rpfilter
      ''}
    ''}
    ${add46Entity "filter" nixos-fw}

    #{config.build.debug.nftables.extraCommands}
    ${cfg.extraCommands}

    add rule ip filter nixos-fw counter jump nixos-fw-log-refuse
    ${optionalString config.networking.enableIPv6 ''
      add rule ip6 filter nixos-fw counter jump nixos-fw-log-refuse
    ''}

    add rule ip filter input counter jump nixos-fw
    ${optionalString config.networking.enableIPv6 ''
      add rule ip6 filter input counter jump nixos-fw
    ''}
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
  config = mkIf cfg.enable {

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

    systemd.services.firewall = {
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
        ExecStart = "${cfg.package}/bin/nft -f ${firewallCfg}";
        ExecReload = "${cfg.package}/bin/nft -f ${firewallCfg}";
        ExecStop = "${cfg.package}/bin/nft flush ruleset";
      };
    };

  };
}
