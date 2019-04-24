mnl = require'cujo.mnl'
posix = require'posix'

local function conntrack_cb(ev, id, ipv,
		ol4protonum, osrcport, odstport, osrcip, odstip, opkts, obytes, -- orig
		rl4protonum, rsrcport, rdstport, rsrcip, rdstip, rpkts, rbytes) -- reply
	print(ev, id, ipv,
		ol4protonum, osrcport, odstport, mnl.bintoip(ipv, osrcip), mnl.bintoip(ipv, odstip), opkts, obytes,
		rl4protonum, rsrcport, rdstport, mnl.bintoip(ipv, rsrcip), mnl.bintoip(ipv, rdstip), rpkts, rbytes)
end

function conntrack()
	local sk = mnl.new('netfilter', conntrack_cb)
	sk:setnonblock(false)
	while true do
		sk:trigger()
		repeat until not sk:process()
		print('--------------------------------------------------------------------------------')
		posix.sleep(2)
	end
end

local function neighbor_cb(ev, ipv, ifi, mac, ip)
	print(ev, ipv, ifi, mnl.bintomac(mac), mnl.bintoip(ipv, ip))
end

function neigh()
	local sk = mnl.new('route', neighbor_cb)
	sk:trigger()
	while true do
		repeat until not sk:process()
		print('--------------------------------------------------------------------------------')
		--posix.sleep(2)
	end
end
