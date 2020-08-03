-- Copyright (c) 2019-2020, CUJO LLC.
-- 
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
-- 
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
-- 
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

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
	end
end
