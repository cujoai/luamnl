/*
 * Copyright (c) 2019, CUJO LLC.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <endian.h>
#include <fcntl.h>
#include <netinet/ether.h>

#include <linux/if.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/rtnetlink.h>

#include <libmnl/libmnl.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define MAKE_ATTR_CB(NAME, MAX)                                                \
static int NAME(const struct nlattr *attr, void *data)                         \
{                                                                              \
	const struct nlattr **tb = data;                                       \
	if (mnl_attr_type_valid(attr, MAX) > 0)                                \
		tb[mnl_attr_get_type(attr)] = attr;                            \
	return MNL_CB_OK;                                                      \
}

MAKE_ATTR_CB(cta_attr_cb, CTA_MAX + 1)
MAKE_ATTR_CB(cta_proto_attr_cb, CTA_PROTO_MAX + 1)
MAKE_ATTR_CB(cta_ip_attr_cb, CTA_IP_MAX + 1)
MAKE_ATTR_CB(cta_counters_attr_cb, CTA_COUNTERS_MAX + 1)
MAKE_ATTR_CB(nda_attr_cb, NDA_MAX + 1)

#define LMNL_SOCKET_METATABLE "lmnl.socket"

struct lmnl_vtable {
	int (*process_cb)(const struct nlmsghdr *, void *);
	int (*trigger)(lua_State *, struct mnl_socket *);
};

struct lmnl {
	struct mnl_socket        *sk;
	const struct lmnl_vtable *vt;
	uint8_t b[0];
};

static const char *family2ipv(int family)
{
	switch (family) {
	case AF_UNSPEC: return "unspec";
	case AF_INET:   return "ip4";
	case AF_INET6:  return "ip6";
	default: return NULL;
	}
}

static void extract_ip(lua_State *L, int family, const struct nlattr *a)
{
	size_t n = family == AF_INET ? sizeof(struct in_addr) :
	           family == AF_INET6 ? sizeof(struct in6_addr) : 0;
	if (a && n) lua_pushlstring(L, mnl_attr_get_payload(a), n);
	else lua_pushnil(L);
}

static void extract_mac(lua_State *L, const struct nlattr *a)
{
	if (a) {
		const char *buf = mnl_attr_get_payload(a);
		int64_t num = 0;
		for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
			num += (int64_t)(buf[ETHER_ADDR_LEN - 1 - i] & 0xFF) << (i * 8);
		}
		lua_pushinteger(L, num);
	} else lua_pushnil(L);
}

static void extract_protonum(lua_State *L, const struct nlattr *a)
{
	if (a) lua_pushinteger(L, mnl_attr_get_u8(a));
	else lua_pushnil(L);
}

static void extract_port(lua_State *L, const struct nlattr *a)
{
	if (a) lua_pushinteger(L, ntohs(mnl_attr_get_u16(a)));
	else lua_pushnil(L);
}

static void extract_bytes_or_packets(lua_State *L, const struct nlattr *a)
{
	if (a) lua_pushinteger(L, be64toh(mnl_attr_get_u64(a)));
	else lua_pushnil(L);
}

static void nf_parse_counters(lua_State *L, const struct nlattr *nest)
{
	const struct nlattr *tb[CTA_COUNTERS_MAX + 1] = {};
	if (nest) mnl_attr_parse_nested(nest, cta_counters_attr_cb, tb);

	extract_bytes_or_packets(L, tb[CTA_COUNTERS_PACKETS]);
	extract_bytes_or_packets(L, tb[CTA_COUNTERS_BYTES]);
}

static void nf_parse_tuple_proto(lua_State *L, const struct nlattr *nest)
{
	const struct nlattr *tb[CTA_PROTO_MAX + 1] = {};
	if (nest) mnl_attr_parse_nested(nest, cta_proto_attr_cb, tb);

	extract_protonum(L, tb[CTA_PROTO_NUM]);
	extract_port(L, tb[CTA_PROTO_SRC_PORT]);
	extract_port(L, tb[CTA_PROTO_DST_PORT]);
}

static void nf_parse_tuple_ip(lua_State *L, int family,
	const struct nlattr *nest)
{
	const struct nlattr *tb[CTA_IP_MAX + 1] = {};
	if (nest) mnl_attr_parse_nested(nest, cta_ip_attr_cb, tb);

	int src, dst;
	switch (family) {
	case AF_INET:  src = CTA_IP_V4_SRC; dst = CTA_IP_V4_DST; break;
	case AF_INET6: src = CTA_IP_V6_SRC; dst = CTA_IP_V6_DST; break;
	default: luaL_error(L, "expected AF_INET or AF_INET6.");
	}
	extract_ip(L, family, tb[src]);
	extract_ip(L, family, tb[dst]);
}

static void nf_parse_tuple(lua_State *L, int family, const struct nlattr *nest)
{
	const struct nlattr *tb[CTA_COUNTERS_MAX + 1] = {};
	if (nest) mnl_attr_parse_nested(nest, cta_counters_attr_cb, tb);

	nf_parse_tuple_proto(L, tb[CTA_TUPLE_PROTO]);
	nf_parse_tuple_ip(L, family, tb[CTA_TUPLE_IP]);
}

static int netfilter_process_cb(const struct nlmsghdr *nlh, void *data)
{
	lua_State *L = data;
	const struct nlattr *tb[CTA_MAX + 1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	mnl_attr_parse(nlh, sizeof(*nfg), cta_attr_cb, tb);

	lua_getuservalue(L, 1);
	int n = lua_gettop(L);
	int isnew = (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) != 0;
	switch (nlh->nlmsg_type & 0xff) {
	case IPCTNL_MSG_CT_NEW:
		lua_pushstring(L, isnew ? "new" : "update");
		break;
	case IPCTNL_MSG_CT_DELETE:
		lua_pushstring(L, "del");
		break;
	default:
		lua_pop(L, 1);
		return MNL_CB_OK;
	}
	lua_pushlightuserdata(L, (void *)mnl_attr_get_u64(tb[CTA_ID]));
	lua_pushstring(L, family2ipv(nfg->nfgen_family));
	nf_parse_tuple(L, nfg->nfgen_family, tb[CTA_TUPLE_ORIG]);
	nf_parse_counters(L, tb[CTA_COUNTERS_ORIG]);
	nf_parse_tuple(L, nfg->nfgen_family, tb[CTA_TUPLE_REPLY]);
	nf_parse_counters(L, tb[CTA_COUNTERS_REPLY]);
	return lua_pcall(L, lua_gettop(L) - n, 0, 0) != LUA_OK ?
		MNL_CB_ERROR : MNL_CB_OK;
}

static int route_process_cb(const struct nlmsghdr *nlh, void *data)
{
	lua_State *L = data;
	const struct nlattr *tb[NDA_MAX + 1] = {};
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	mnl_attr_parse(nlh, sizeof(*ndm), nda_attr_cb, tb);

	lua_getuservalue(L, 1);
	int n = lua_gettop(L);
	switch (nlh->nlmsg_type) {
	case RTM_DELNEIGH: lua_pushstring(L, "del"); break;
	case RTM_GETNEIGH: lua_pushstring(L, "get"); break;
	case RTM_NEWNEIGH: lua_pushstring(L, "new"); break;
	default:
		lua_pop(L, 1);
		return MNL_CB_OK;
	}
	lua_pushstring(L, family2ipv(ndm->ndm_family));
	lua_pushinteger(L, ndm->ndm_ifindex);
	extract_mac(L, tb[NDA_LLADDR]);
	extract_ip(L, ndm->ndm_family, tb[NDA_DST]);
	return lua_pcall(L, lua_gettop(L) - n, 0, 0) != LUA_OK ?
		MNL_CB_ERROR : MNL_CB_OK;
}

static struct lmnl *lmnl_getudata(lua_State *L, int i)
{
	struct lmnl *me = luaL_checkudata(L, i, LMNL_SOCKET_METATABLE);
	if (me->sk == NULL) luaL_error(L, "attempt to use a closed socket");
	return me;
}

typedef int (*getflags)(lua_State *, const char *);

static int netfilter_getflags(lua_State *L, const char *mode)
{
	int flags = 0;
	for (; *mode; ++mode) switch (*mode) {
	case 'n': flags |= NF_NETLINK_CONNTRACK_NEW; break;
	case 'u': flags |= NF_NETLINK_CONNTRACK_UPDATE; break;
	case 'd': flags |= NF_NETLINK_CONNTRACK_DESTROY; break;
	default: luaL_error(L, "unknown mode char (got '%c')", *mode);
	}
	return flags;
}

static int route_getflags(lua_State *L, const char *mode)
{
	int flags = 0;
	for (; *mode; ++mode) switch (*mode) {
	case 'n': flags |= RTM_NEWNEIGH; break;
	case 'g': flags |= RTM_GETNEIGH; break;
	case 'd': flags |= RTM_DELNEIGH; break;
	default: luaL_error(L, "unknown mode char (got '%c')", *mode);
	}
	return flags;
}

static int process_cb(lua_State *L)
{
	struct lmnl *me = lmnl_getudata(L, 1);
	int n = mnl_socket_recvfrom(me->sk, me->b, MNL_SOCKET_BUFFER_SIZE);
	if (n > 0) {
		if (mnl_cb_run(me->b, n, 0, 0, me->vt->process_cb, L) ==
		    MNL_CB_ERROR) {
			return lua_error(L);
		} else {
			lua_pushboolean(L, true);
			return 1;
		}
	}
	lua_pushnil(L);
	lua_pushstring(L, n == EAGAIN || n == EWOULDBLOCK ?
		       "timeout" : strerror(errno));
	return 2;
}

static int gc(lua_State *L)
{
	struct lmnl *me = lmnl_getudata(L, 1);
	if (me->sk) {
		mnl_socket_close(me->sk);
		me->sk = NULL;
	}
	return 0;
}

static int getfd(lua_State *L)
{
	struct lmnl *me = lmnl_getudata(L, 1);
	lua_pushinteger(L, mnl_socket_get_fd(me->sk));
	return 1;
}

static const char *afnames[] = {"all", "ip4", "ip6", NULL};
static const int  afvalues[] = {AF_UNSPEC, AF_INET, AF_INET6};

static int netfilter_trigger(lua_State *L, struct mnl_socket *sk)
{
	int ret, inet = afvalues[luaL_checkoption(L, 2, "all", afnames)];
	struct {
		struct nlmsghdr h;
		struct nfgenmsg nf;
	} req = {{
			.nlmsg_len = sizeof(req),
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
		}, {
			.nfgen_family = inet,
	}};
	if ((ret = mnl_socket_sendto(sk, &req, req.h.nlmsg_len)) < 0) {
		luaL_error(L, "failed to send netlink message %s.",
			   strerror(ret));
	}
	return 0;
}

static int route_trigger(lua_State *L, struct mnl_socket *sk)
{
	int ret, inet = afvalues[luaL_checkoption(L, 2, "all", afnames)];
	struct {
		struct nlmsghdr h;
		struct rtgenmsg rt;
	} req = {{
			.nlmsg_len = sizeof(req),
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
			.nlmsg_type = RTM_GETNEIGH,
		}, {
			.rtgen_family = inet,
	}};
	return mnl_socket_sendto(sk, &req, req.h.nlmsg_len);
}
static int trigger(lua_State *L)
{
	struct lmnl *me = lmnl_getudata(L, 1);
	if (me->vt->trigger(L, me->sk) < 0) {
		luaL_error(L, "failed to send netlink message %s.",
			   strerror(errno));
	}
	return 0;
}

static bool setfdnonblock(int fd, bool yes)
{
	int oldflags = fcntl(fd, F_GETFL, 0);
	int newflags = yes ?  (oldflags |  O_NONBLOCK):
	      (oldflags & ~O_NONBLOCK);
	return (oldflags != -1) && fcntl(fd, F_SETFL, newflags) != -1;
}

static int setnonblock(lua_State *L)
{
	struct lmnl *me = lmnl_getudata(L, 1);
	int yes = lua_toboolean(L, 2);
	int fd = mnl_socket_get_fd(me->sk);
	if (!setfdnonblock(fd, yes))
		luaL_error(L, "failed to change blocking state with: %s.",
			   strerror(errno));
	return 0;
}

static int setrxsize(lua_State *L)
{
	struct lmnl *me = lmnl_getudata(L, 1);
	size_t newsize = lua_tointeger(L, 2);
	if (setsockopt(mnl_socket_get_fd(me->sk),
			     SOL_SOCKET, SO_RCVBUFFORCE,
			     &newsize, sizeof(newsize)) != 0)
		luaL_error(L, "failed to change receive buffer size: %s.",
			   strerror(errno));
	return 0;
}

static const struct lmnl_vtable route_vtable = {
	.process_cb = route_process_cb,
	.trigger    = route_trigger,
};

static const struct lmnl_vtable netfilter_vtable = {
	.process_cb = netfilter_process_cb,
	.trigger    = netfilter_trigger,
};

static const luaL_Reg lmnl_methods[] = {
	{"__gc",        gc},
	{"close",       gc},
	{"getfd",       getfd},
	{"process",     process_cb},
	{"setnonblock", setnonblock},
	{"setrxsize",   setrxsize},
	{"trigger",     trigger},
	{NULL,          NULL},
};

static int new(lua_State *L)
{
	const char *busnames[]          = {"netfilter",        "route", NULL};
	const int   busnums[]           = {NETLINK_NETFILTER,  NETLINK_ROUTE};
	const struct lmnl_vtable *vts[] = {&netfilter_vtable,  &route_vtable};
	getflags    getflags[]          = {netfilter_getflags, route_getflags};

	int i = luaL_checkoption(L, 1, NULL, busnames);
	luaL_argcheck(L, lua_isfunction(L, 2), 2, "callback expected");
	int flags = getflags[i](L, luaL_optstring(L, 3, ""));

	struct mnl_socket *sk = mnl_socket_open(busnums[i]);
	if (sk == NULL) goto cleanup;

	if (mnl_socket_bind(sk, flags, MNL_SOCKET_AUTOPID) < 0) goto cleanup;

	struct lmnl *me = lua_newuserdata(L,
		sizeof(struct lmnl) + MNL_SOCKET_BUFFER_SIZE);
	if (me == NULL) goto cleanup;
	me->sk  = sk;
	me->vt  = vts[i];

	luaL_getmetatable(L, LMNL_SOCKET_METATABLE);
	lua_setmetatable(L, -2);

	lua_pushvalue(L, 2);
	lua_setuservalue(L, -2);

	setfdnonblock(mnl_socket_get_fd(sk), true);
	return 1;

cleanup:
	if (sk) mnl_socket_close(sk);
	luaL_error(L, "failed to create nml socket");
	return 0;
}

static size_t addr_size[] = {sizeof(struct in_addr), sizeof(struct in6_addr)};
static int addr_domain[] = {AF_INET, AF_INET6};
static const char *const addr_opts[] = {"ip4", "ip6", NULL};

static int
iptobin(lua_State *L)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int kind = luaL_checkoption(L, 1, NULL, addr_opts);
	const char *addr = luaL_checkstring(L, 2);
	if (inet_pton(addr_domain[kind], addr, buf) == 1) {
		lua_pushlstring(L, buf, addr_size[kind]);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, strerror(errno));
	return 2;
}

static int
bintoip(lua_State *L)
{
	static size_t maxsz[] = {INET_ADDRSTRLEN, INET6_ADDRSTRLEN};
	unsigned char buf[INET6_ADDRSTRLEN];
	int kind = luaL_checkoption(L, 1, NULL, addr_opts);
	size_t n;
	const char *addr = luaL_checklstring(L, 2, &n);
	luaL_argcheck(L, n == addr_size[kind], 2, "invalid address");
	if (inet_ntop(addr_domain[kind], addr, buf, maxsz[kind]) != NULL) {
		lua_pushstring(L, buf);
		return 1;
	}
	lua_pushnil(L);
	lua_pushstring(L, strerror(errno));
	return 2;
}

static const luaL_Reg functions[] = {
	{"new",      new},
	{"iptobin",  iptobin},
	{"bintoip",  bintoip},
	{NULL,       NULL},
};

LUAMOD_API int luaopen_cujo_mnl(lua_State *L)
{
	luaL_newmetatable(L, LMNL_SOCKET_METATABLE);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, lmnl_methods, 0);
	luaL_newlib(L, functions);
	return 1;
}
