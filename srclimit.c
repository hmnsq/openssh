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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/tree.h>

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "addr.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "srclimit.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "match.h"

স্থির পূর্ণসংখ্যা max_children, max_persource, ipv4_masklen, ipv6_masklen;
স্থির কাঠামো per_source_penalty penalty_cfg;
স্থির অক্ষর *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
স্থির কাঠামো child_info {
	পূর্ণসংখ্যা id;
	কাঠামো xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
কাঠামো penalty {
	কাঠামো xaddr addr;
	দ্বিগুণ expiry;
	পূর্ণসংখ্যা active;
	ধ্রুবক অক্ষর *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
স্থির পূর্ণসংখ্যা penalty_addr_cmp(কাঠামো penalty *a, কাঠামো penalty *b);
স্থির পূর্ণসংখ্যা penalty_expiry_cmp(কাঠামো penalty *a, কাঠামো penalty *b);
RB_শীর্ষ(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_শীর্ষ(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
স্থির আকার_t npenalties4, npenalties6;

স্থির পূর্ণসংখ্যা
srclimit_mask_addr(ধ্রুবক কাঠামো xaddr *addr, পূর্ণসংখ্যা bits, কাঠামো xaddr *masked)
{
	কাঠামো xaddr xmask;

	/* Mask address off address to desired size. */
	যদি (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		ফেরত -1;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
srclimit_peer_addr(পূর্ণসংখ্যা sock, কাঠামো xaddr *addr)
{
	কাঠামো sockaddr_storage storage;
	socklen_t addrlen = আকার(storage);
	কাঠামো sockaddr *sa = (কাঠামো sockaddr *)&storage;

	যদি (getpeername(sock, sa, &addrlen) != 0)
		ফেরত 1;	/* not remote socket? */
	যদি (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		ফেরত 1;	/* unknown address family? */
	ফেরত 0;
}

শূন্য
srclimit_init(পূর্ণসংখ্যা max, পূর্ণসংখ্যা persource, পূর্ণসংখ্যা ipv4len, পূর্ণসংখ্যা ipv6len,
    কাঠামো per_source_penalty *penalty_conf, ধ্রুবক অক্ষর *penalty_exempt_conf)
{
	পূর্ণসংখ্যা i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	যদি (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ফাঁকা ?
	    ফাঁকা : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	যদি (max_persource == INT_MAX)	/* no limit */
		ফেরত;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	যদি (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, আকার(*children));
	জন্য (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
পূর্ণসংখ্যা
srclimit_check_allow(পূর্ণসংখ্যা sock, পূর্ণসংখ্যা id)
{
	কাঠামো xaddr xa, xb;
	পূর্ণসংখ্যা i, bits, first_unused, গুনতি = 0;
	অক্ষর xas[NI_MAXHOST];

	যদি (max_persource == INT_MAX)	/* no limit */
		ফেরত 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	যদি (srclimit_peer_addr(sock, &xa) != 0)
		ফেরত 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	যদি (srclimit_mask_addr(&xa, bits, &xb) != 0)
		ফেরত 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	জন্য (i = 0; i < max_children; i++) {
		যদি (children[i].id == -1) {
			যদি (i < first_unused)
				first_unused = i;
		} অন্যথা যদি (addr_cmp(&children[i].addr, &xb) == 0) {
			গুনতি++;
		}
	}
	যদি (addr_ntop(&xa, xas, আকার(xas)) != 0) {
		debug3_f("addr ntop failed");
		ফেরত 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, গুনতি, max_persource);

	যদি (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ফেরত 0;
	}
	যদি (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	যদি (গুনতি >= max_persource)
		ফেরত 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, আকার(xb));
	ফেরত 1;
}

শূন্য
srclimit_done(পূর্ণসংখ্যা id)
{
	পূর্ণসংখ্যা i;

	যদি (max_persource == INT_MAX)	/* no limit */
		ফেরত;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	জন্য (i = 0; i < max_children; i++) {
		যদি (children[i].id == id) {
			children[i].id = -1;
			ফেরত;
		}
	}
}

স্থির পূর্ণসংখ্যা
penalty_addr_cmp(কাঠামো penalty *a, কাঠামো penalty *b)
{
	ফেরত addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

স্থির পূর্ণসংখ্যা
penalty_expiry_cmp(কাঠামো penalty *a, কাঠামো penalty *b)
{
	যদি (a->expiry != b->expiry)
		ফেরত a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ফেরত addr_cmp(&a->addr, &b->addr);
}

স্থির শূন্য
expire_penalties_from_বৃক্ষ(দ্বিগুণ now, ধ্রুবক অক্ষর *t,
    কাঠামো penalties_by_expiry *by_expiry,
    কাঠামো penalties_by_addr *by_addr, আকার_t *npenaltiesp)
{
	কাঠামো penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		যদি (penalty->expiry >= now)
			বিরতি;
		যদি (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		মুক্ত(penalty);
		যদি ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

স্থির শূন্য
expire_penalties(দ্বিগুণ now)
{
	expire_penalties_from_বৃক্ষ(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_বৃক্ষ(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

স্থির শূন্য
addr_masklen_ntop(কাঠামো xaddr *addr, পূর্ণসংখ্যা masklen, অক্ষর *s, আকার_t slen)
{
	আকার_t o;

	যদি (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ফেরত;
	}
	যদি ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

পূর্ণসংখ্যা
srclimit_penalty_check_allow(পূর্ণসংখ্যা sock, ধ্রুবক অক্ষর **reason)
{
	কাঠামো xaddr addr;
	কাঠামো penalty find, *penalty;
	দ্বিগুণ now;
	পূর্ণসংখ্যা bits, max_sources, overflow_mode;
	অক্ষর addr_s[NI_MAXHOST];
	কাঠামো penalties_by_addr *by_addr;
	আকার_t npenalties;

	যদি (!penalty_cfg.enabled)
		ফেরত 1;
	যদি (srclimit_peer_addr(sock, &addr) != 0)
		ফেরত 1;
	যদি (penalty_exempt != ফাঁকা) {
		যদি (addr_ntop(&addr, addr_s, আকার(addr_s)) != 0)
			ফেরত 1; /* shouldn't happen */
		যদি (addr_match_list(addr_s, penalty_exempt) == 1) {
			ফেরত 1;
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
	যদি (npenalties >= (আকার_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		ফেরত 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, আকার(find));
	যদি (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		ফেরত 1;
	যদি ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == ফাঁকা)
		ফেরত 1; /* no penalty */
	যদি (penalty->expiry < now) {
		expire_penalties(now);
		ফেরত 1; /* expired penalty */
	}
	যদি (!penalty->active)
		ফেরত 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ফেরত 0;
}

স্থির শূন্য
srclimit_early_expire_penalties_from_বৃক্ষ(ধ্রুবক অক্ষর *t,
    কাঠামো penalties_by_expiry *by_expiry,
    কাঠামো penalties_by_addr *by_addr, আকার_t *npenaltiesp, আকার_t max_sources)
{
	কাঠামো penalty *p = ফাঁকা;
	পূর্ণসংখ্যা bits;
	অক্ষর s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	যখন (*npenaltiesp > max_sources) {
		যদি ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ফাঁকা)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, আকার(s));
		debug3_f("%s overflow, remove %s", t, s);
		যদি (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		মুক্ত(p);
		(*npenaltiesp)--;
	}
}

স্থির শূন্য
srclimit_early_expire_penalties(শূন্য)
{
	srclimit_early_expire_penalties_from_বৃক্ষ("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (আকার_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_বৃক্ষ("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (আকার_t)penalty_cfg.max_sources6);
}

শূন্য
srclimit_penalise(কাঠামো xaddr *addr, পূর্ণসংখ্যা penalty_type)
{
	কাঠামো xaddr masked;
	কাঠামো penalty *penalty = ফাঁকা, *existing = ফাঁকা;
	দ্বিগুণ now;
	পূর্ণসংখ্যা bits, max_sources = 0, overflow_mode;
	দ্বিগুণ penalty_secs;
	অক্ষর addrnetmask[NI_MAXHOST + 4];
	ধ্রুবক অক্ষর *reason = ফাঁকা, *t;
	আকার_t *npenaltiesp = ফাঁকা;
	কাঠামো penalties_by_addr *by_addr = ফাঁকা;
	কাঠামো penalties_by_expiry *by_expiry = ফাঁকা;

	যদি (!penalty_cfg.enabled)
		ফেরত;
	যদি (penalty_exempt != ফাঁকা) {
		যদি (addr_ntop(addr, addrnetmask, আকার(addrnetmask)) != 0)
			ফেরত; /* shouldn't happen */
		যদি (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ফেরত;
		}
	}

	নির্বাচন (penalty_type) {
	ক্ষেত্র SRCLIMIT_PENALTY_NONE:
		ফেরত;
	ক্ষেত্র SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		বিরতি;
	ক্ষেত্র SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		বিরতি;
	ক্ষেত্র SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		বিরতি;
	ক্ষেত্র SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		বিরতি;
	ক্ষেত্র SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		বিরতি;
	ক্ষেত্র SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		বিরতি;
	পূর্বনির্ধারিত:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	যদি (penalty_secs <= 0)
		ফেরত;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	যদি (srclimit_mask_addr(addr, bits, &masked) != 0)
		ফেরত;
	addr_masklen_ntop(addr, bits, addrnetmask, আকার(addrnetmask));

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
	যদি (*npenaltiesp >= (আকার_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ফেরত;
	}

	penalty = xcalloc(1, আকার(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	যদি ((existing = RB_ঢোকাও(penalties_by_addr, by_addr,
	    penalty)) == ফাঁকা) {
		/* penalty didn't previously exist */
		যদি (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		যদি (RB_ঢোকাও(penalties_by_expiry, by_expiry, penalty) != ফাঁকা)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		যদি (++(*npenaltiesp) > (আকার_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ফেরত;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	যদি (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	যদি (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	যদি (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	মুক্ত(penalty);
	penalty = ফাঁকা;
	/* Re-insert into expiry tree */
	যদি (RB_ঢোকাও(penalties_by_expiry, by_expiry, existing) != ফাঁকা)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

স্থির শূন্য
srclimit_penalty_info_for_বৃক্ষ(ধ্রুবক অক্ষর *t,
    কাঠামো penalties_by_expiry *by_expiry, আকার_t npenalties)
{
	কাঠামো penalty *p = ফাঁকা;
	পূর্ণসংখ্যা bits;
	অক্ষর s[NI_MAXHOST + 4];
	দ্বিগুণ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, আকার(s));
		যদি (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		অন্যথা {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

শূন্য
srclimit_penalty_info(শূন্য)
{
	srclimit_penalty_info_for_বৃক্ষ("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_বৃক্ষ("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
