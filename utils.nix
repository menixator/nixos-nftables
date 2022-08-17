{
  genIPBaseTables = fam: ''
    # Raw
    #=======================================================================
    # Hook: filter
    # Priority: -300

    table ${fam} raw {
      chain prerouting	{ type filter hook prerouting priority raw; }
      chain output	{ type filter hook output priority raw; }
    }

    # Mangle
    #=======================================================================
    # Hook: route
    # Priority: -150

    table ip mangle {
      chain output { type route hook output priority mangle; }
    }

    # NAT(Destination)
    #=======================================================================
    # Hook: nat
    # Priority: -100
    # Note: The priority value `dstnat` will not work for hook other than `postrouting`

    table ${fam} nat {
      chain prerouting	{ type nat hook prerouting priority dstnat; }
      chain output  	{ type nat hook output priority -100; }
    }

    # Filter
    #=======================================================================
    # Hook: filter
    # Priority: 0

    table ${fam} filter {
      chain input	{ type filter hook input priority filter;   }
      chain forward	{ type filter hook forward priority filter; }
      chain output	{ type filter hook output priority filter;  }
    }

    # NAT(Source)
    #=======================================================================
    # Priority: 100
    # Note: priority srcnat does not work for any hook but `postrouting`.

    table ${fam} nat {
      chain input       { type nat hook input priority 100; }
      chain postrouting	{ type nat hook postrouting priority srcnat; }
    }
  '';
}
