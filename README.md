# lua-lease-monitor

A lua script that provides DHCP lease information that flows via the
local access point.

The snooping happens with via data provided by [udhcpsnoop](https://github.com/blogic/udhcpsnoop)

There is a patch that applies against the hostapd_stations collector
that is part of prometheus-node-exporter-lua maintained in
openwrt/packages.

I've used this setup to enhance station information with IP addresses
and hostnames to get a richer Grafana dashboard experience.

It should honestly be cleaned up and packaged for public consumption
via the packages feed. That's a todo for another time, for now this
repository serves as a code dump for anyone to make us of it.
