/*
 * Copyright (c) 2020 Darren Tucker <dtucker@openbsd.org>
 * Copyright (c) 2024 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/tree.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "addr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "srclimit.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"

ਸਥਿਰ ਪੂਰਨ max_children, max_persource, ipv4_masklen, ipv6_masklen;
ਸਥਿਰ ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty penalty_cfg;
ਸਥਿਰ ਅੱਖਰ *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ਸਥਿਰ ਬਣਤਰ ਬੱਚਾ_info {
	ਪੂਰਨ id;
	ਬਣਤਰ xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ਬਣਤਰ penalty {
	ਬਣਤਰ xaddr addr;
	ਦੁੱਗਣਾ expiry;
	ਪੂਰਨ ਸਰਗਰਮ;
	ਅਚਲ ਅੱਖਰ *reason;
	RB_ਇੰਦਰਾਜ(penalty) by_addr;
	RB_ਇੰਦਰਾਜ(penalty) by_expiry;
};
ਸਥਿਰ ਪੂਰਨ penalty_addr_cmp(ਬਣਤਰ penalty *a, ਬਣਤਰ penalty *b);
ਸਥਿਰ ਪੂਰਨ penalty_expiry_cmp(ਬਣਤਰ penalty *a, ਬਣਤਰ penalty *b);
RB_ਸਿਰ(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_ਸਿਰ(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ਸਥਿਰ ਮਾਪ_t npenalties4, npenalties6;

ਸਥਿਰ ਪੂਰਨ
srclimit_ਨਕਾਬ_addr(ਅਚਲ ਬਣਤਰ xaddr *addr, ਪੂਰਨ ਬਿੱਟ, ਬਣਤਰ xaddr *masked)
{
	ਬਣਤਰ xaddr xmask;

	/* Mask address off address to desired size. */
	ਜੇ (addr_netmask(addr->af, ਬਿੱਟ, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, ਬਿੱਟ);
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
srclimit_peer_addr(ਪੂਰਨ sock, ਬਣਤਰ xaddr *addr)
{
	ਬਣਤਰ sockaddr_storage storage;
	socklen_t addrlen = ਆਕਾਰ(storage);
	ਬਣਤਰ sockaddr *sa = (ਬਣਤਰ sockaddr *)&storage;

	ਜੇ (getpeername(sock, sa, &addrlen) != 0)
		ਵਾਪਸ 1;	/* not remote socket? */
	ਜੇ (addr_sa_ਮੰਜ਼ਿਲ_xaddr(sa, addrlen, addr) != 0)
		ਵਾਪਸ 1;	/* unknown address family? */
	ਵਾਪਸ 0;
}

ਖਾਲੀ
srclimit_init(ਪੂਰਨ max, ਪੂਰਨ persource, ਪੂਰਨ ipv4len, ਪੂਰਨ ipv6len,
    ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty *penalty_conf, ਅਚਲ ਅੱਖਰ *penalty_exempt_conf)
{
	ਪੂਰਨ i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ਜੇ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ਨਿਰਾ ?
	    ਨਿਰਾ : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ਜੇ (max_persource == ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)	/* no limit */
		ਵਾਪਸ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ਜੇ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, ਆਕਾਰ(*children));
	ਲਈ (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
ਪੂਰਨ
srclimit_check_allow(ਪੂਰਨ sock, ਪੂਰਨ id)
{
	ਬਣਤਰ xaddr xa, xb;
	ਪੂਰਨ i, ਬਿੱਟ, ਪਹਿਲਾ_ਅਣਵਰਤਿਆ, ਗਿਣਤੀ_2 = 0;
	ਅੱਖਰ xas[NI_MAXHOST];

	ਜੇ (max_persource == ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)	/* no limit */
		ਵਾਪਸ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ਜੇ (srclimit_peer_addr(sock, &xa) != 0)
		ਵਾਪਸ 1;
	ਬਿੱਟ = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ਜੇ (srclimit_ਨਕਾਬ_addr(&xa, ਬਿੱਟ, &xb) != 0)
		ਵਾਪਸ 1;

	ਪਹਿਲਾ_ਅਣਵਰਤਿਆ = max_children;
	/* Count matching entries and find first unused one. */
	ਲਈ (i = 0; i < max_children; i++) {
		ਜੇ (children[i].id == -1) {
			ਜੇ (i < ਪਹਿਲਾ_ਅਣਵਰਤਿਆ)
				ਪਹਿਲਾ_ਅਣਵਰਤਿਆ = i;
		} ਨਹੀਂਤਾਂ ਜੇ (addr_cmp(&children[i].addr, &xb) == 0) {
			ਗਿਣਤੀ_2++;
		}
	}
	ਜੇ (addr_ntop(&xa, xas, ਆਕਾਰ(xas)) != 0) {
		debug3_f("addr ntop failed");
		ਵਾਪਸ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, ਬਿੱਟ, ਗਿਣਤੀ_2, max_persource);

	ਜੇ (ਪਹਿਲਾ_ਅਣਵਰਤਿਆ == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ਵਾਪਸ 0;
	}
	ਜੇ (ਪਹਿਲਾ_ਅਣਵਰਤਿਆ < 0 || ਪਹਿਲਾ_ਅਣਵਰਤਿਆ >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ਜੇ (ਗਿਣਤੀ_2 >= max_persource)
		ਵਾਪਸ 0;

	/* Connection allowed, store masked address. */
	children[ਪਹਿਲਾ_ਅਣਵਰਤਿਆ].id = id;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&children[ਪਹਿਲਾ_ਅਣਵਰਤਿਆ].addr, &xb, ਆਕਾਰ(xb));
	ਵਾਪਸ 1;
}

ਖਾਲੀ
srclimit_ਪੂਰਾ(ਪੂਰਨ id)
{
	ਪੂਰਨ i;

	ਜੇ (max_persource == ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)	/* no limit */
		ਵਾਪਸ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	ਲਈ (i = 0; i < max_children; i++) {
		ਜੇ (children[i].id == id) {
			children[i].id = -1;
			ਵਾਪਸ;
		}
	}
}

ਸਥਿਰ ਪੂਰਨ
penalty_addr_cmp(ਬਣਤਰ penalty *a, ਬਣਤਰ penalty *b)
{
	ਵਾਪਸ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ਸਥਿਰ ਪੂਰਨ
penalty_expiry_cmp(ਬਣਤਰ penalty *a, ਬਣਤਰ penalty *b)
{
	ਜੇ (a->expiry != b->expiry)
		ਵਾਪਸ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ਵਾਪਸ addr_cmp(&a->addr, &b->addr);
}

ਸਥਿਰ ਖਾਲੀ
expire_penalties_from_ਰੁੱਖ(ਦੁੱਗਣਾ now, ਅਚਲ ਅੱਖਰ *t,
    ਬਣਤਰ penalties_by_expiry *by_expiry,
    ਬਣਤਰ penalties_by_addr *by_addr, ਮਾਪ_t *npenaltiesp)
{
	ਬਣਤਰ penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_ਸੁਰੱਖਿਅਤ(penalty, penalties_by_expiry, by_expiry, tmp) {
		ਜੇ (penalty->expiry >= now)
			ਰੋਕੋ;
		ਜੇ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		ਮੁਕਤ(penalty);
		ਜੇ ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

ਸਥਿਰ ਖਾਲੀ
expire_penalties(ਦੁੱਗਣਾ now)
{
	expire_penalties_from_ਰੁੱਖ(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_ਰੁੱਖ(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

ਸਥਿਰ ਖਾਲੀ
addr_masklen_ntop(ਬਣਤਰ xaddr *addr, ਪੂਰਨ masklen, ਅੱਖਰ *s, ਮਾਪ_t slen)
{
	ਮਾਪ_t o;

	ਜੇ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ਵਾਪਸ;
	}
	ਜੇ ((o = ਲੜੀ_ਲੰਬਾਈ(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

ਪੂਰਨ
srclimit_penalty_check_allow(ਪੂਰਨ sock, ਅਚਲ ਅੱਖਰ **reason)
{
	ਬਣਤਰ xaddr addr;
	ਬਣਤਰ penalty ਲੱਭੋ, *penalty;
	ਦੁੱਗਣਾ now;
	ਪੂਰਨ ਬਿੱਟ, max_sources, ਉਛਾਲ_ਬਹੁਲਕ;
	ਅੱਖਰ addr_s[NI_MAXHOST];
	ਬਣਤਰ penalties_by_addr *by_addr;
	ਮਾਪ_t npenalties;

	ਜੇ (!penalty_cfg.enabled)
		ਵਾਪਸ 1;
	ਜੇ (srclimit_peer_addr(sock, &addr) != 0)
		ਵਾਪਸ 1;
	ਜੇ (penalty_exempt != ਨਿਰਾ) {
		ਜੇ (addr_ntop(&addr, addr_s, ਆਕਾਰ(addr_s)) != 0)
			ਵਾਪਸ 1; /* shouldn't happen */
		ਜੇ (addr_ਮੇਲ_list(addr_s, penalty_exempt) == 1) {
			ਵਾਪਸ 1;
		}
	}
	now = monotime_double();
	expire_penalties(now);
	by_addr = addr.af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr.af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	ਉਛਾਲ_ਬਹੁਲਕ = addr.af == AF_INET ?
	    penalty_cfg.ਉਛਾਲ_ਬਹੁਲਕ : penalty_cfg.ਉਛਾਲ_mode6;
	npenalties = addr.af == AF_INET ?  npenalties4 : npenalties6;
	ਜੇ (npenalties >= (ਮਾਪ_t)max_sources &&
	    ਉਛਾਲ_ਬਹੁਲਕ == ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL) {
		*reason = "too many penalised addresses";
		ਵਾਪਸ 0;
	}
	ਬਿੱਟ = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&ਲੱਭੋ, 0, ਆਕਾਰ(ਲੱਭੋ));
	ਜੇ (srclimit_ਨਕਾਬ_addr(&addr, ਬਿੱਟ, &ਲੱਭੋ.addr) != 0)
		ਵਾਪਸ 1;
	ਜੇ ((penalty = RB_ਲੱਭੋ(penalties_by_addr, by_addr, &ਲੱਭੋ)) == ਨਿਰਾ)
		ਵਾਪਸ 1; /* no penalty */
	ਜੇ (penalty->expiry < now) {
		expire_penalties(now);
		ਵਾਪਸ 1; /* expired penalty */
	}
	ਜੇ (!penalty->ਸਰਗਰਮ)
		ਵਾਪਸ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
srclimit_early_expire_penalties_from_ਰੁੱਖ(ਅਚਲ ਅੱਖਰ *t,
    ਬਣਤਰ penalties_by_expiry *by_expiry,
    ਬਣਤਰ penalties_by_addr *by_addr, ਮਾਪ_t *npenaltiesp, ਮਾਪ_t max_sources)
{
	ਬਣਤਰ penalty *p = ਨਿਰਾ;
	ਪੂਰਨ ਬਿੱਟ;
	ਅੱਖਰ s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ਜਦੋਂ (*npenaltiesp > max_sources) {
		ਜੇ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ਨਿਰਾ)
			fatal_f("internal error: %s table corrupt (find)", t);
		ਬਿੱਟ = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, ਬਿੱਟ, s, ਆਕਾਰ(s));
		debug3_f("%s overflow, remove %s", t, s);
		ਜੇ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		ਮੁਕਤ(p);
		(*npenaltiesp)--;
	}
}

ਸਥਿਰ ਖਾਲੀ
srclimit_early_expire_penalties(ਖਾਲੀ)
{
	srclimit_early_expire_penalties_from_ਰੁੱਖ("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (ਮਾਪ_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_ਰੁੱਖ("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (ਮਾਪ_t)penalty_cfg.max_sources6);
}

ਖਾਲੀ
srclimit_penalise(ਬਣਤਰ xaddr *addr, ਪੂਰਨ penalty_type)
{
	ਬਣਤਰ xaddr masked;
	ਬਣਤਰ penalty *penalty = ਨਿਰਾ, *existing = ਨਿਰਾ;
	ਦੁੱਗਣਾ now;
	ਪੂਰਨ ਬਿੱਟ, max_sources = 0, ਉਛਾਲ_ਬਹੁਲਕ;
	ਦੁੱਗਣਾ penalty_secs;
	ਅੱਖਰ addrnetmask[NI_MAXHOST + 4];
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ, *t;
	ਮਾਪ_t *npenaltiesp = ਨਿਰਾ;
	ਬਣਤਰ penalties_by_addr *by_addr = ਨਿਰਾ;
	ਬਣਤਰ penalties_by_expiry *by_expiry = ਨਿਰਾ;

	ਜੇ (!penalty_cfg.enabled)
		ਵਾਪਸ;
	ਜੇ (penalty_exempt != ਨਿਰਾ) {
		ਜੇ (addr_ntop(addr, addrnetmask, ਆਕਾਰ(addrnetmask)) != 0)
			ਵਾਪਸ; /* shouldn't happen */
		ਜੇ (addr_ਮੇਲ_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ਵਾਪਸ;
		}
	}

	ਚੋਣ (penalty_type) {
	ਹਾਲਤ SRCLIMIT_PENALTY_NONE:
		ਵਾਪਸ;
	ਹਾਲਤ SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		ਰੋਕੋ;
	ਹਾਲਤ SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		ਰੋਕੋ;
	ਹਾਲਤ SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		ਰੋਕੋ;
	ਹਾਲਤ SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		ਰੋਕੋ;
	ਹਾਲਤ SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		ਰੋਕੋ;
	ਹਾਲਤ SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	ਜੇ (penalty_secs <= 0)
		ਵਾਪਸ;

	ਬਿੱਟ = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ਜੇ (srclimit_ਨਕਾਬ_addr(addr, ਬਿੱਟ, &masked) != 0)
		ਵਾਪਸ;
	addr_masklen_ntop(addr, ਬਿੱਟ, addrnetmask, ਆਕਾਰ(addrnetmask));

	now = monotime_double();
	expire_penalties(now);
	by_expiry = addr->af == AF_INET ?
	    &penalties_by_expiry4 : &penalties_by_expiry6;
	by_addr = addr->af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr->af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	ਉਛਾਲ_ਬਹੁਲਕ = addr->af == AF_INET ?
	    penalty_cfg.ਉਛਾਲ_ਬਹੁਲਕ : penalty_cfg.ਉਛਾਲ_mode6;
	npenaltiesp = addr->af == AF_INET ?  &npenalties4 : &npenalties6;
	t = addr->af == AF_INET ? "ipv4" : "ipv6";
	ਜੇ (*npenaltiesp >= (ਮਾਪ_t)max_sources &&
	    ਉਛਾਲ_ਬਹੁਲਕ == ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ਵਾਪਸ;
	}

	penalty = xcalloc(1, ਆਕਾਰ(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ਜੇ ((existing = RB_ਪਾਓ(penalties_by_addr, by_addr,
	    penalty)) == ਨਿਰਾ) {
		/* penalty didn't previously exist */
		ਜੇ (penalty_secs > penalty_cfg.penalty_min)
			penalty->ਸਰਗਰਮ = 1;
		ਜੇ (RB_ਪਾਓ(penalties_by_expiry, by_expiry, penalty) != ਨਿਰਾ)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->ਸਰਗਰਮ ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->ਸਰਗਰਮ ? "active" : "deferred",
		    penalty_secs, reason);
		ਜੇ (++(*npenaltiesp) > (ਮਾਪ_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ਵਾਪਸ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->ਸਰਗਰਮ ? "active" : "inactive", t,
	    addrnetmask, (ਲੰਮਾ ਲੰਮਾ)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ਜੇ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ਜੇ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ਜੇ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->ਸਰਗਰਮ) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->ਸਰਗਰਮ = 1;
	}
	existing->reason = penalty->reason;
	ਮੁਕਤ(penalty);
	penalty = ਨਿਰਾ;
	/* Re-insert into expiry tree */
	ਜੇ (RB_ਪਾਓ(penalties_by_expiry, by_expiry, existing) != ਨਿਰਾ)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ਸਥਿਰ ਖਾਲੀ
srclimit_penalty_info_for_ਰੁੱਖ(ਅਚਲ ਅੱਖਰ *t,
    ਬਣਤਰ penalties_by_expiry *by_expiry, ਮਾਪ_t npenalties)
{
	ਬਣਤਰ penalty *p = ਨਿਰਾ;
	ਪੂਰਨ ਬਿੱਟ;
	ਅੱਖਰ s[NI_MAXHOST + 4];
	ਦੁੱਗਣਾ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		ਬਿੱਟ = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, ਬਿੱਟ, s, ਆਕਾਰ(s));
		ਜੇ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ਨਹੀਂਤਾਂ {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

ਖਾਲੀ
srclimit_penalty_info(ਖਾਲੀ)
{
	srclimit_penalty_info_for_ਰੁੱਖ("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_ਰੁੱਖ("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
