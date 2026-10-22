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

#ضمن "includes.h"

#ضمن <sys/socket.h>
#ضمن <sys/types.h>
#ضمن <sys/tree.h>

#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "addr.h"
#ضمن "canohost.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "srclimit.h"
#ضمن "xmalloc.h"
#ضمن "servconf.h"
#ضمن "match.h"

ساكن صحيح max_children, max_persource, ipv4_masklen, ipv6_masklen;
ساكن بنية per_source_penalty penalty_cfg;
ساكن حرف *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ساكن بنية child_info {
	صحيح id;
	بنية xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
بنية penalty {
	بنية xaddr addr;
	مزدوج expiry;
	صحيح active;
	ثابت حرف *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
ساكن صحيح penalty_addr_cmp(بنية penalty *a, بنية penalty *b);
ساكن صحيح penalty_expiry_cmp(بنية penalty *a, بنية penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ساكن size_t npenalties4, npenalties6;

ساكن صحيح
srclimit_mask_addr(ثابت بنية xaddr *addr, صحيح bits, بنية xaddr *masked)
{
	بنية xaddr xmask;

	/* Mask address off address to desired size. */
	אם (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		החזר -1;
	}
	החזר 0;
}

ساكن صحيح
srclimit_peer_addr(صحيح sock, بنية xaddr *addr)
{
	بنية sockaddr_storage storage;
	socklen_t addrlen = حجم(storage);
	بنية sockaddr *sa = (بنية sockaddr *)&storage;

	אם (getpeername(sock, sa, &addrlen) != 0)
		החזר 1;	/* not remote socket? */
	אם (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		החזר 1;	/* unknown address family? */
	החזר 0;
}

فراغ
srclimit_init(صحيح max, صحيح persource, صحيح ipv4len, صحيح ipv6len,
    بنية per_source_penalty *penalty_conf, ثابت حرف *penalty_exempt_conf)
{
	صحيح i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	אם (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == عدم ?
	    عدم : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	אם (max_persource == INT_MAX)	/* no limit */
		החזר;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	אם (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, حجم(*children));
	עבור (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
صحيح
srclimit_check_allow(صحيح sock, صحيح id)
{
	بنية xaddr xa, xb;
	صحيح i, bits, first_unused, count = 0;
	حرف xas[NI_MAXHOST];

	אם (max_persource == INT_MAX)	/* no limit */
		החזר 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	אם (srclimit_peer_addr(sock, &xa) != 0)
		החזר 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	אם (srclimit_mask_addr(&xa, bits, &xb) != 0)
		החזר 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	עבור (i = 0; i < max_children; i++) {
		אם (children[i].id == -1) {
			אם (i < first_unused)
				first_unused = i;
		} אחרת אם (addr_cmp(&children[i].addr, &xb) == 0) {
			count++;
		}
	}
	אם (addr_ntop(&xa, xas, حجم(xas)) != 0) {
		debug3_f("addr ntop failed");
		החזר 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, count, max_persource);

	אם (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		החזר 0;
	}
	אם (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	אם (count >= max_persource)
		החזר 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, حجم(xb));
	החזר 1;
}

فراغ
srclimit_done(صحيح id)
{
	صحيح i;

	אם (max_persource == INT_MAX)	/* no limit */
		החזר;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	עבור (i = 0; i < max_children; i++) {
		אם (children[i].id == id) {
			children[i].id = -1;
			החזר;
		}
	}
}

ساكن صحيح
penalty_addr_cmp(بنية penalty *a, بنية penalty *b)
{
	החזר addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ساكن صحيح
penalty_expiry_cmp(بنية penalty *a, بنية penalty *b)
{
	אם (a->expiry != b->expiry)
		החזר a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	החזר addr_cmp(&a->addr, &b->addr);
}

ساكن فراغ
expire_penalties_from_tree(مزدوج now, ثابت حرف *t,
    بنية penalties_by_expiry *by_expiry,
    بنية penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	بنية penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		אם (penalty->expiry >= now)
			اكسر;
		אם (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		حرر(penalty);
		אם ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

ساكن فراغ
expire_penalties(مزدوج now)
{
	expire_penalties_from_tree(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_tree(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

ساكن فراغ
addr_masklen_ntop(بنية xaddr *addr, صحيح masklen, حرف *s, size_t slen)
{
	size_t o;

	אם (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		החזר;
	}
	אם ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

صحيح
srclimit_penalty_check_allow(صحيح sock, ثابت حرف **reason)
{
	بنية xaddr addr;
	بنية penalty find, *penalty;
	مزدوج now;
	صحيح bits, max_sources, overflow_mode;
	حرف addr_s[NI_MAXHOST];
	بنية penalties_by_addr *by_addr;
	size_t npenalties;

	אם (!penalty_cfg.enabled)
		החזר 1;
	אם (srclimit_peer_addr(sock, &addr) != 0)
		החזר 1;
	אם (penalty_exempt != عدم) {
		אם (addr_ntop(&addr, addr_s, حجم(addr_s)) != 0)
			החזר 1; /* shouldn't happen */
		אם (addr_match_list(addr_s, penalty_exempt) == 1) {
			החזר 1;
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
	אם (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		החזר 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, حجم(find));
	אם (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		החזר 1;
	אם ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == عدم)
		החזר 1; /* no penalty */
	אם (penalty->expiry < now) {
		expire_penalties(now);
		החזר 1; /* expired penalty */
	}
	אם (!penalty->active)
		החזר 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	החזר 0;
}

ساكن فراغ
srclimit_early_expire_penalties_from_tree(ثابت حرف *t,
    بنية penalties_by_expiry *by_expiry,
    بنية penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	بنية penalty *p = عدم;
	صحيح bits;
	حرف s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	כלעוד (*npenaltiesp > max_sources) {
		אם ((p = RB_MIN(penalties_by_expiry, by_expiry)) == عدم)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, حجم(s));
		debug3_f("%s overflow, remove %s", t, s);
		אם (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		حرر(p);
		(*npenaltiesp)--;
	}
}

ساكن فراغ
srclimit_early_expire_penalties(فراغ)
{
	srclimit_early_expire_penalties_from_tree("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_tree("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

فراغ
srclimit_penalise(بنية xaddr *addr, صحيح penalty_type)
{
	بنية xaddr masked;
	بنية penalty *penalty = عدم, *existing = عدم;
	مزدوج now;
	صحيح bits, max_sources = 0, overflow_mode;
	مزدوج penalty_secs;
	حرف addrnetmask[NI_MAXHOST + 4];
	ثابت حرف *reason = عدم, *t;
	size_t *npenaltiesp = عدم;
	بنية penalties_by_addr *by_addr = عدم;
	بنية penalties_by_expiry *by_expiry = عدم;

	אם (!penalty_cfg.enabled)
		החזר;
	אם (penalty_exempt != عدم) {
		אם (addr_ntop(addr, addrnetmask, حجم(addrnetmask)) != 0)
			החזר; /* shouldn't happen */
		אם (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			החזר;
		}
	}

	بدل (penalty_type) {
	حالة SRCLIMIT_PENALTY_NONE:
		החזר;
	حالة SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		اكسر;
	حالة SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		اكسر;
	حالة SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		اكسر;
	حالة SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		اكسر;
	حالة SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		اكسر;
	حالة SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		اكسر;
	افتراضي:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	אם (penalty_secs <= 0)
		החזר;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	אם (srclimit_mask_addr(addr, bits, &masked) != 0)
		החזר;
	addr_masklen_ntop(addr, bits, addrnetmask, حجم(addrnetmask));

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
	אם (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		החזר;
	}

	penalty = xcalloc(1, حجم(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	אם ((existing = RB_INSERT(penalties_by_addr, by_addr,
	    penalty)) == عدم) {
		/* penalty didn't previously exist */
		אם (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		אם (RB_INSERT(penalties_by_expiry, by_expiry, penalty) != عدم)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		אם (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		החזר;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	אם (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	אם (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	אם (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	حرر(penalty);
	penalty = عدم;
	/* Re-insert into expiry tree */
	אם (RB_INSERT(penalties_by_expiry, by_expiry, existing) != عدم)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ساكن فراغ
srclimit_penalty_info_for_tree(ثابت حرف *t,
    بنية penalties_by_expiry *by_expiry, size_t npenalties)
{
	بنية penalty *p = عدم;
	صحيح bits;
	حرف s[NI_MAXHOST + 4];
	مزدوج now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, حجم(s));
		אם (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		אחרת {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

فراغ
srclimit_penalty_info(فراغ)
{
	srclimit_penalty_info_for_tree("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_tree("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
