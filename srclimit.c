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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/tree.h>

#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "addr.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "srclimit.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "match.h"

நிலையான முழு max_children, max_persource, ipv4_masklen, ipv6_masklen;
நிலையான கட்டமைப்பு per_source_penalty penalty_cfg;
நிலையான எழுத்து *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
நிலையான கட்டமைப்பு child_info {
	முழு id;
	கட்டமைப்பு xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
கட்டமைப்பு penalty {
	கட்டமைப்பு xaddr addr;
	இரட்டை expiry;
	முழு active;
	மாறிலி எழுத்து *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
நிலையான முழு penalty_addr_cmp(கட்டமைப்பு penalty *a, கட்டமைப்பு penalty *b);
நிலையான முழு penalty_expiry_cmp(கட்டமைப்பு penalty *a, கட்டமைப்பு penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
நிலையான size_t npenalties4, npenalties6;

நிலையான முழு
srclimit_mask_addr(மாறிலி கட்டமைப்பு xaddr *addr, முழு bits, கட்டமைப்பு xaddr *masked)
{
	கட்டமைப்பு xaddr xmask;

	/* Mask address off address to desired size. */
	எனில் (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		திரும்பு -1;
	}
	திரும்பு 0;
}

நிலையான முழு
srclimit_peer_addr(முழு sock, கட்டமைப்பு xaddr *addr)
{
	கட்டமைப்பு sockaddr_storage storage;
	socklen_t addrlen = அளவு(storage);
	கட்டமைப்பு sockaddr *sa = (கட்டமைப்பு sockaddr *)&storage;

	எனில் (getpeername(sock, sa, &addrlen) != 0)
		திரும்பு 1;	/* not remote socket? */
	எனில் (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		திரும்பு 1;	/* unknown address family? */
	திரும்பு 0;
}

வெறுமை
srclimit_init(முழு max, முழு persource, முழு ipv4len, முழு ipv6len,
    கட்டமைப்பு per_source_penalty *penalty_conf, மாறிலி எழுத்து *penalty_exempt_conf)
{
	முழு i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	எனில் (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == வெற்று ?
	    வெற்று : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	எனில் (max_persource == INT_MAX)	/* no limit */
		திரும்பு;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	எனில் (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, அளவு(*children));
	க்கு (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
முழு
srclimit_check_allow(முழு sock, முழு id)
{
	கட்டமைப்பு xaddr xa, xb;
	முழு i, bits, first_unused, மொத்தம் = 0;
	எழுத்து xas[NI_MAXHOST];

	எனில் (max_persource == INT_MAX)	/* no limit */
		திரும்பு 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	எனில் (srclimit_peer_addr(sock, &xa) != 0)
		திரும்பு 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	எனில் (srclimit_mask_addr(&xa, bits, &xb) != 0)
		திரும்பு 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	க்கு (i = 0; i < max_children; i++) {
		எனில் (children[i].id == -1) {
			எனில் (i < first_unused)
				first_unused = i;
		} இல்லையெனில் எனில் (addr_cmp(&children[i].addr, &xb) == 0) {
			மொத்தம்++;
		}
	}
	எனில் (addr_ntop(&xa, xas, அளவு(xas)) != 0) {
		debug3_f("addr ntop failed");
		திரும்பு 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, மொத்தம், max_persource);

	எனில் (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		திரும்பு 0;
	}
	எனில் (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	எனில் (மொத்தம் >= max_persource)
		திரும்பு 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, அளவு(xb));
	திரும்பு 1;
}

வெறுமை
srclimit_done(முழு id)
{
	முழு i;

	எனில் (max_persource == INT_MAX)	/* no limit */
		திரும்பு;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	க்கு (i = 0; i < max_children; i++) {
		எனில் (children[i].id == id) {
			children[i].id = -1;
			திரும்பு;
		}
	}
}

நிலையான முழு
penalty_addr_cmp(கட்டமைப்பு penalty *a, கட்டமைப்பு penalty *b)
{
	திரும்பு addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

நிலையான முழு
penalty_expiry_cmp(கட்டமைப்பு penalty *a, கட்டமைப்பு penalty *b)
{
	எனில் (a->expiry != b->expiry)
		திரும்பு a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	திரும்பு addr_cmp(&a->addr, &b->addr);
}

நிலையான வெறுமை
expire_penalties_from_மரம்(இரட்டை now, மாறிலி எழுத்து *t,
    கட்டமைப்பு penalties_by_expiry *by_expiry,
    கட்டமைப்பு penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	கட்டமைப்பு penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		எனில் (penalty->expiry >= now)
			நிறுத்து;
		எனில் (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		விடுவி(penalty);
		எனில் ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

நிலையான வெறுமை
expire_penalties(இரட்டை now)
{
	expire_penalties_from_மரம்(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_மரம்(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

நிலையான வெறுமை
addr_masklen_ntop(கட்டமைப்பு xaddr *addr, முழு masklen, எழுத்து *s, size_t slen)
{
	size_t o;

	எனில் (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		திரும்பு;
	}
	எனில் ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

முழு
srclimit_penalty_check_allow(முழு sock, மாறிலி எழுத்து **reason)
{
	கட்டமைப்பு xaddr addr;
	கட்டமைப்பு penalty find, *penalty;
	இரட்டை now;
	முழு bits, max_sources, overflow_mode;
	எழுத்து addr_s[NI_MAXHOST];
	கட்டமைப்பு penalties_by_addr *by_addr;
	size_t npenalties;

	எனில் (!penalty_cfg.enabled)
		திரும்பு 1;
	எனில் (srclimit_peer_addr(sock, &addr) != 0)
		திரும்பு 1;
	எனில் (penalty_exempt != வெற்று) {
		எனில் (addr_ntop(&addr, addr_s, அளவு(addr_s)) != 0)
			திரும்பு 1; /* shouldn't happen */
		எனில் (addr_match_list(addr_s, penalty_exempt) == 1) {
			திரும்பு 1;
		}
	}
	now = monotime_double();
	expire_penalties(now);
	by_addr = addr.af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr.af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	overflow_mode = addr.af == AF_INET ?
	    penalty_cfg.overflow_mode : penalty_cfg.overflow_mode6;
	npenalties = addr.af == AF_INET ?  npenalties4 : npenalties6;
	எனில் (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		திரும்பு 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, அளவு(find));
	எனில் (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		திரும்பு 1;
	எனில் ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == வெற்று)
		திரும்பு 1; /* no penalty */
	எனில் (penalty->expiry < now) {
		expire_penalties(now);
		திரும்பு 1; /* expired penalty */
	}
	எனில் (!penalty->active)
		திரும்பு 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	திரும்பு 0;
}

நிலையான வெறுமை
srclimit_early_expire_penalties_from_மரம்(மாறிலி எழுத்து *t,
    கட்டமைப்பு penalties_by_expiry *by_expiry,
    கட்டமைப்பு penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	கட்டமைப்பு penalty *p = வெற்று;
	முழு bits;
	எழுத்து s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	போது (*npenaltiesp > max_sources) {
		எனில் ((p = RB_MIN(penalties_by_expiry, by_expiry)) == வெற்று)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, அளவு(s));
		debug3_f("%s overflow, remove %s", t, s);
		எனில் (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		விடுவி(p);
		(*npenaltiesp)--;
	}
}

நிலையான வெறுமை
srclimit_early_expire_penalties(வெறுமை)
{
	srclimit_early_expire_penalties_from_மரம்("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_மரம்("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

வெறுமை
srclimit_penalise(கட்டமைப்பு xaddr *addr, முழு penalty_type)
{
	கட்டமைப்பு xaddr masked;
	கட்டமைப்பு penalty *penalty = வெற்று, *existing = வெற்று;
	இரட்டை now;
	முழு bits, max_sources = 0, overflow_mode;
	இரட்டை penalty_secs;
	எழுத்து addrnetmask[NI_MAXHOST + 4];
	மாறிலி எழுத்து *reason = வெற்று, *t;
	size_t *npenaltiesp = வெற்று;
	கட்டமைப்பு penalties_by_addr *by_addr = வெற்று;
	கட்டமைப்பு penalties_by_expiry *by_expiry = வெற்று;

	எனில் (!penalty_cfg.enabled)
		திரும்பு;
	எனில் (penalty_exempt != வெற்று) {
		எனில் (addr_ntop(addr, addrnetmask, அளவு(addrnetmask)) != 0)
			திரும்பு; /* shouldn't happen */
		எனில் (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			திரும்பு;
		}
	}

	தேர்வு (penalty_type) {
	நிலை SRCLIMIT_PENALTY_NONE:
		திரும்பு;
	நிலை SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		நிறுத்து;
	நிலை SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		நிறுத்து;
	நிலை SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		நிறுத்து;
	நிலை SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		நிறுத்து;
	நிலை SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		நிறுத்து;
	நிலை SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		நிறுத்து;
	இயல்பு:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	எனில் (penalty_secs <= 0)
		திரும்பு;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	எனில் (srclimit_mask_addr(addr, bits, &masked) != 0)
		திரும்பு;
	addr_masklen_ntop(addr, bits, addrnetmask, அளவு(addrnetmask));

	now = monotime_double();
	expire_penalties(now);
	by_expiry = addr->af == AF_INET ?
	    &penalties_by_expiry4 : &penalties_by_expiry6;
	by_addr = addr->af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr->af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	overflow_mode = addr->af == AF_INET ?
	    penalty_cfg.overflow_mode : penalty_cfg.overflow_mode6;
	npenaltiesp = addr->af == AF_INET ?  &npenalties4 : &npenalties6;
	t = addr->af == AF_INET ? "ipv4" : "ipv6";
	எனில் (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		திரும்பு;
	}

	penalty = xcalloc(1, அளவு(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	எனில் ((existing = RB_செருகு(penalties_by_addr, by_addr,
	    penalty)) == வெற்று) {
		/* penalty didn't previously exist */
		எனில் (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		எனில் (RB_செருகு(penalties_by_expiry, by_expiry, penalty) != வெற்று)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		எனில் (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		திரும்பு;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	எனில் (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	எனில் (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	எனில் (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	விடுவி(penalty);
	penalty = வெற்று;
	/* Re-insert into expiry tree */
	எனில் (RB_செருகு(penalties_by_expiry, by_expiry, existing) != வெற்று)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

நிலையான வெறுமை
srclimit_penalty_info_for_மரம்(மாறிலி எழுத்து *t,
    கட்டமைப்பு penalties_by_expiry *by_expiry, size_t npenalties)
{
	கட்டமைப்பு penalty *p = வெற்று;
	முழு bits;
	எழுத்து s[NI_MAXHOST + 4];
	இரட்டை now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, அளவு(s));
		எனில் (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		இல்லையெனில் {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

வெறுமை
srclimit_penalty_info(வெறுமை)
{
	srclimit_penalty_info_for_மரம்("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_மரம்("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
