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

#شامل "includes.h"

#شامل <sys/socket.h>
#شامل <sys/types.h>
#شامل <sys/tree.h>

#شامل <limits.h>
#شامل <netdb.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "addr.h"
#شامل "canohost.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "srclimit.h"
#شامل "xmalloc.h"
#شامل "servconf.h"
#شامل "match.h"

ایستا صحیح max_children, max_persource, ipv4_masklen, ipv6_masklen;
ایستا ساختار per_source_penalty penalty_cfg;
ایستا نویسه *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ایستا ساختار child_info {
	صحیح id;
	ساختار xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ساختار penalty {
	ساختار xaddr addr;
	دوگانه expiry;
	صحیح active;
	ثابت نویسه *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
ایستا صحیح penalty_addr_cmp(ساختار penalty *a, ساختار penalty *b);
ایستا صحیح penalty_expiry_cmp(ساختار penalty *a, ساختار penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ایستا size_t npenalties4, npenalties6;

ایستا صحیح
srclimit_mask_addr(ثابت ساختار xaddr *addr, صحیح bits, ساختار xaddr *masked)
{
	ساختار xaddr xmask;

	/* Mask address off address to desired size. */
	اگر (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		بازگشت -1;
	}
	بازگشت 0;
}

ایستا صحیح
srclimit_peer_addr(صحیح sock, ساختار xaddr *addr)
{
	ساختار sockaddr_storage storage;
	socklen_t addrlen = اندازه(storage);
	ساختار sockaddr *sa = (ساختار sockaddr *)&storage;

	اگر (getpeername(sock, sa, &addrlen) != 0)
		بازگشت 1;	/* not remote socket? */
	اگر (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		بازگشت 1;	/* unknown address family? */
	بازگشت 0;
}

تهی
srclimit_init(صحیح max, صحیح persource, صحیح ipv4len, صحیح ipv6len,
    ساختار per_source_penalty *penalty_conf, ثابت نویسه *penalty_exempt_conf)
{
	صحیح i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	اگر (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == پوچ ?
	    پوچ : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	اگر (max_persource == INT_MAX)	/* no limit */
		بازگشت;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	اگر (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, اندازه(*children));
	برای (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
صحیح
srclimit_check_allow(صحیح sock, صحیح id)
{
	ساختار xaddr xa, xb;
	صحیح i, bits, first_unused, شمار = 0;
	نویسه xas[NI_MAXHOST];

	اگر (max_persource == INT_MAX)	/* no limit */
		بازگشت 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	اگر (srclimit_peer_addr(sock, &xa) != 0)
		بازگشت 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	اگر (srclimit_mask_addr(&xa, bits, &xb) != 0)
		بازگشت 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	برای (i = 0; i < max_children; i++) {
		اگر (children[i].id == -1) {
			اگر (i < first_unused)
				first_unused = i;
		} وگرنه اگر (addr_cmp(&children[i].addr, &xb) == 0) {
			شمار++;
		}
	}
	اگر (addr_ntop(&xa, xas, اندازه(xas)) != 0) {
		debug3_f("addr ntop failed");
		بازگشت 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, شمار, max_persource);

	اگر (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		بازگشت 0;
	}
	اگر (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	اگر (شمار >= max_persource)
		بازگشت 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, اندازه(xb));
	بازگشت 1;
}

تهی
srclimit_done(صحیح id)
{
	صحیح i;

	اگر (max_persource == INT_MAX)	/* no limit */
		بازگشت;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	برای (i = 0; i < max_children; i++) {
		اگر (children[i].id == id) {
			children[i].id = -1;
			بازگشت;
		}
	}
}

ایستا صحیح
penalty_addr_cmp(ساختار penalty *a, ساختار penalty *b)
{
	بازگشت addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ایستا صحیح
penalty_expiry_cmp(ساختار penalty *a, ساختار penalty *b)
{
	اگر (a->expiry != b->expiry)
		بازگشت a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	بازگشت addr_cmp(&a->addr, &b->addr);
}

ایستا تهی
expire_penalties_from_درخت(دوگانه now, ثابت نویسه *t,
    ساختار penalties_by_expiry *by_expiry,
    ساختار penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	ساختار penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		اگر (penalty->expiry >= now)
			بشکن;
		اگر (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		آزاد(penalty);
		اگر ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

ایستا تهی
expire_penalties(دوگانه now)
{
	expire_penalties_from_درخت(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_درخت(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

ایستا تهی
addr_masklen_ntop(ساختار xaddr *addr, صحیح masklen, نویسه *s, size_t slen)
{
	size_t o;

	اگر (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		بازگشت;
	}
	اگر ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

صحیح
srclimit_penalty_check_allow(صحیح sock, ثابت نویسه **reason)
{
	ساختار xaddr addr;
	ساختار penalty find, *penalty;
	دوگانه now;
	صحیح bits, max_sources, overflow_mode;
	نویسه addr_s[NI_MAXHOST];
	ساختار penalties_by_addr *by_addr;
	size_t npenalties;

	اگر (!penalty_cfg.enabled)
		بازگشت 1;
	اگر (srclimit_peer_addr(sock, &addr) != 0)
		بازگشت 1;
	اگر (penalty_exempt != پوچ) {
		اگر (addr_ntop(&addr, addr_s, اندازه(addr_s)) != 0)
			بازگشت 1; /* shouldn't happen */
		اگر (addr_match_list(addr_s, penalty_exempt) == 1) {
			بازگشت 1;
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
	اگر (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		بازگشت 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, اندازه(find));
	اگر (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		بازگشت 1;
	اگر ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == پوچ)
		بازگشت 1; /* no penalty */
	اگر (penalty->expiry < now) {
		expire_penalties(now);
		بازگشت 1; /* expired penalty */
	}
	اگر (!penalty->active)
		بازگشت 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	بازگشت 0;
}

ایستا تهی
srclimit_early_expire_penalties_from_درخت(ثابت نویسه *t,
    ساختار penalties_by_expiry *by_expiry,
    ساختار penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	ساختار penalty *p = پوچ;
	صحیح bits;
	نویسه s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	وقتی (*npenaltiesp > max_sources) {
		اگر ((p = RB_MIN(penalties_by_expiry, by_expiry)) == پوچ)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, اندازه(s));
		debug3_f("%s overflow, remove %s", t, s);
		اگر (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		آزاد(p);
		(*npenaltiesp)--;
	}
}

ایستا تهی
srclimit_early_expire_penalties(تهی)
{
	srclimit_early_expire_penalties_from_درخت("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_درخت("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

تهی
srclimit_penalise(ساختار xaddr *addr, صحیح penalty_type)
{
	ساختار xaddr masked;
	ساختار penalty *penalty = پوچ, *existing = پوچ;
	دوگانه now;
	صحیح bits, max_sources = 0, overflow_mode;
	دوگانه penalty_secs;
	نویسه addrnetmask[NI_MAXHOST + 4];
	ثابت نویسه *reason = پوچ, *t;
	size_t *npenaltiesp = پوچ;
	ساختار penalties_by_addr *by_addr = پوچ;
	ساختار penalties_by_expiry *by_expiry = پوچ;

	اگر (!penalty_cfg.enabled)
		بازگشت;
	اگر (penalty_exempt != پوچ) {
		اگر (addr_ntop(addr, addrnetmask, اندازه(addrnetmask)) != 0)
			بازگشت; /* shouldn't happen */
		اگر (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			بازگشت;
		}
	}

	انتخاب (penalty_type) {
	حالت SRCLIMIT_PENALTY_NONE:
		بازگشت;
	حالت SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		بشکن;
	حالت SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		بشکن;
	حالت SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		بشکن;
	حالت SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		بشکن;
	حالت SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		بشکن;
	حالت SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		بشکن;
	پیشفرض:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	اگر (penalty_secs <= 0)
		بازگشت;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	اگر (srclimit_mask_addr(addr, bits, &masked) != 0)
		بازگشت;
	addr_masklen_ntop(addr, bits, addrnetmask, اندازه(addrnetmask));

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
	اگر (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		بازگشت;
	}

	penalty = xcalloc(1, اندازه(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	اگر ((existing = RB_درج(penalties_by_addr, by_addr,
	    penalty)) == پوچ) {
		/* penalty didn't previously exist */
		اگر (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		اگر (RB_درج(penalties_by_expiry, by_expiry, penalty) != پوچ)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		اگر (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		بازگشت;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	اگر (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	اگر (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	اگر (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	آزاد(penalty);
	penalty = پوچ;
	/* Re-insert into expiry tree */
	اگر (RB_درج(penalties_by_expiry, by_expiry, existing) != پوچ)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ایستا تهی
srclimit_penalty_info_for_درخت(ثابت نویسه *t,
    ساختار penalties_by_expiry *by_expiry, size_t npenalties)
{
	ساختار penalty *p = پوچ;
	صحیح bits;
	نویسه s[NI_MAXHOST + 4];
	دوگانه now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, اندازه(s));
		اگر (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		وگرنه {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

تهی
srclimit_penalty_info(تهی)
{
	srclimit_penalty_info_for_درخت("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_درخت("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
