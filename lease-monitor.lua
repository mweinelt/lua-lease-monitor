#!/usr/bin/env lua

require "ubus"
require "uloop"
require "os"

uloop.init()

local conn = ubus.connect()
if not conn then
	error("Failed to connect to ubus")
end

local leases = {}

-- read bytes from a hex string
function read_byte(data, pos, len)
	return data:sub(2*pos + 1, 2*pos + 2*len)
end

-- convert one byte each to ascii char
function read_string(str)
	return (str:gsub('..', function (byte)
		return string.char(tonumber(byte, 16))
	end))
end

function read_int(str)
	return tonumber(str, 16)
end

function read_mac(str)
	local m1, m2, m3, m4, m5, m6 = str:match("(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)")
	return string.format("%s:%s:%s:%s:%s:%s", m1, m2, m3, m4, m5, m6)
end

function read_ipv4(str)
	local o1, o2, o3, o4 = str:match("(%x%x)(%x%x)(%x%x)(%x%x)")
	o1 = tonumber(o1, 16)
	o2 = tonumber(o2, 16)
	o3 = tonumber(o3, 16)
	o4 = tonumber(o4, 16)
	return string.format("%d.%d.%d.%d", o1, o2, o3, o4)
end

-- partial option value decoding table
option_decode_cb = {
	[1] = read_ipv4,
	[2] = read_ipv4,
	[3] = read_ipv4,
	[4] = read_ipv4,
	[5] = read_ipv4,

	[12] = read_string,
	[15] = read_string,

	[50] = read_ipv4,
	[51] = read_int,
	[53] = read_int,
	[57] = read_int,
	[58] = read_int,
	[59] = read_int,

	[60] = read_string,
	[61] = read_string,
}

function parse_dhcp4_packet(payload)
	print(os.date("%c"))

	-- Ethernet (14 Byte)
	ether = read_byte(payload, 0, 14)

	ether_dst = read_mac(read_byte(ether, 0, 6))
	ether_src = read_mac(read_byte(ether, 6,  6))
	ether_type = read_byte(ether, 12, 2)

	-- IPv4 (20 Byte)
	ip = read_byte(payload, 14, 20)

	ip_version = tonumber(read_byte(ip, 0, 0.5), 16)
	ip_length = tonumber(read_byte(ip, 0.5, 0.5), 16)
	ip_src = read_ipv4(read_byte(ip, 12, 4))
	ip_dst = read_ipv4(read_byte(ip, 16, 4))

	-- UDP (8 Byte)
	udp = read_byte(payload, 14+20, 8)

	udp_src_port = tonumber(read_byte(udp, 0, 2), 16)
	udp_dst_port = tonumber(read_byte(udp, 2, 2), 16)
	udp_len = tonumber(read_byte(udp, 4, 2), 16)
	udp_chksum = read_byte(udp, 6, 2)

	-- DHCP
	dhcp = read_byte(payload, 14 + 20 + 8, udp_len)

	-- 1 byte values
	op = tonumber(read_byte(dhcp, 0, 1), 16)
	htype = tonumber(read_byte(dhcp, 1, 1), 16)
	hlen = tonumber(read_byte(dhcp, 2, 1), 16)
	hops = tonumber(read_byte(dhcp, 3, 1), 16)
	-- print(op, htype, hlen, hops)

	-- xid 4 byte
	xid = read_byte(dhcp, 4, 4)

	-- secs 2 byte
	secs = read_byte(dhcp, 8, 2)
	-- flags 2 byte
	flags = read_byte(dhcp, 10, 2)

	ciaddr = read_ipv4(read_byte(dhcp, 12, 4))
	yiaddr = read_ipv4(read_byte(dhcp, 16, 4))
	siaddr = read_ipv4(read_byte(dhcp, 20, 4))
	giaddr = read_ipv4(read_byte(dhcp, 24, 4))

	-- chaddr up to 16 byte
	chaddr = read_mac(read_byte(dhcp, 28, hlen))

	magic_cookie = read_byte(dhcp, 236, 4)

	i = 240;
	-- print("options", dhcp:sub(240*2+1))
	options = {}

	repeat
		opcode = read_int(read_byte(dhcp, i, 1))
		oplen = tonumber(read_byte(dhcp, i+1, 1), 16)
		opvalue = read_byte(dhcp, i+2, oplen)
		decoder = option_decode_cb[opcode]
		if decoder then
			opvalue = decoder(opvalue)
		end
		options[opcode] = opvalue
		i = i + 2 + oplen
	until (read_byte(dhcp, i, 1) == "ff")

	print(string.format("%s -> %s", ether_src, ether_dst))
	print(string.format("%s -> %s", ip_src, ip_dst))
	print(string.format("DHCP (op: %s, msg_type: %s)", op, options[53]))

	for k,v in pairs(options) do
		print("\tOption:", k, ":", v)
	end

	-- request (mac, hostname)
	lease = leases[chaddr]
	if lease == nil then
		leases[chaddr] = {
			hostname = options[12],
		}
	else
		-- DHCPREQUEST
		if options[53] == 3 then
			lease.hostname = options[12]
			if options[50] then
				lease.ip = options[50]
			end

		-- DHCPACK
		elseif options[53] == 5 then
			if options[50] then
				lease.ip = options[50]
			end
			lease.expiry = os.time(os.date("!*t")) + options[51]
		end
	end

end

local method_cbs = {
	["ack"] = parse_dhcp4_packet,
	["request"] = parse_dhcp4_packet
}

function dhcpsnoop_cb(packet, method)
	cb = method_cbs[method]
	if cb then
		cb(packet["packet"])
	end
end


local sub = {
	notify = dhcpsnoop_cb
}

local pub = {
	dhpcmon = {
		get_leases = {
			function(req, msg)
				conn:reply(req, { leases = leases })
			end, {}
		}
	}
}


conn:subscribe("dhcpsnoop", sub)
conn:add(pub)

uloop.run()
