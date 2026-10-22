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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/tree.h>

#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "addr.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "srclimit.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "match.h"

स्थिर पूर्णाङ्क max_children, max_persource, ipv4_masklen, ipv6_masklen;
स्थिर संरचना per_source_penalty penalty_cfg;
स्थिर वर्ण *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
स्थिर संरचना child_info {
	पूर्णाङ्क id;
	संरचना xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
संरचना penalty {
	संरचना xaddr addr;
	द्विगुण expiry;
	पूर्णाङ्क active;
	ध्रुव वर्ण *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
स्थिर पूर्णाङ्क penalty_addr_cmp(संरचना penalty *a, संरचना penalty *b);
स्थिर पूर्णाङ्क penalty_expiry_cmp(संरचना penalty *a, संरचना penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
स्थिर size_t npenalties4, npenalties6;

स्थिर पूर्णाङ्क
srclimit_mask_addr(ध्रुव संरचना xaddr *addr, पूर्णाङ्क bits, संरचना xaddr *masked)
{
	संरचना xaddr xmask;

	/* Mask address off address to desired size. */
	सचे (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
srclimit_peer_addr(पूर्णाङ्क sock, संरचना xaddr *addr)
{
	संरचना sockaddr_storage storage;
	socklen_t addrlen = परिमाण(storage);
	संरचना sockaddr *sa = (संरचना sockaddr *)&storage;

	सचे (getpeername(sock, sa, &addrlen) != 0)
		पटिनिवत्त 1;	/* not remote socket? */
	सचे (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		पटिनिवत्त 1;	/* unknown address family? */
	पटिनिवत्त 0;
}

शून्य
srclimit_init(पूर्णाङ्क max, पूर्णाङ्क persource, पूर्णाङ्क ipv4len, पूर्णाङ्क ipv6len,
    संरचना per_source_penalty *penalty_conf, ध्रुव वर्ण *penalty_exempt_conf)
{
	पूर्णाङ्क i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	सचे (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == रिक्त ?
	    रिक्त : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	सचे (max_persource == INT_MAX)	/* no limit */
		पटिनिवत्त;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	सचे (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, परिमाण(*children));
	अत्थाय (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
पूर्णाङ्क
srclimit_check_allow(पूर्णाङ्क sock, पूर्णाङ्क id)
{
	संरचना xaddr xa, xb;
	पूर्णाङ्क i, bits, first_unused, गणनम् = 0;
	वर्ण xas[NI_MAXHOST];

	सचे (max_persource == INT_MAX)	/* no limit */
		पटिनिवत्त 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	सचे (srclimit_peer_addr(sock, &xa) != 0)
		पटिनिवत्त 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	सचे (srclimit_mask_addr(&xa, bits, &xb) != 0)
		पटिनिवत्त 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	अत्थाय (i = 0; i < max_children; i++) {
		सचे (children[i].id == -1) {
			सचे (i < first_unused)
				first_unused = i;
		} अञ्ञथा सचे (addr_cmp(&children[i].addr, &xb) == 0) {
			गणनम्++;
		}
	}
	सचे (addr_ntop(&xa, xas, परिमाण(xas)) != 0) {
		debug3_f("addr ntop failed");
		पटिनिवत्त 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, गणनम्, max_persource);

	सचे (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		पटिनिवत्त 0;
	}
	सचे (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	सचे (गणनम् >= max_persource)
		पटिनिवत्त 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, परिमाण(xb));
	पटिनिवत्त 1;
}

शून्य
srclimit_done(पूर्णाङ्क id)
{
	पूर्णाङ्क i;

	सचे (max_persource == INT_MAX)	/* no limit */
		पटिनिवत्त;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	अत्थाय (i = 0; i < max_children; i++) {
		सचे (children[i].id == id) {
			children[i].id = -1;
			पटिनिवत्त;
		}
	}
}

स्थिर पूर्णाङ्क
penalty_addr_cmp(संरचना penalty *a, संरचना penalty *b)
{
	पटिनिवत्त addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

स्थिर पूर्णाङ्क
penalty_expiry_cmp(संरचना penalty *a, संरचना penalty *b)
{
	सचे (a->expiry != b->expiry)
		पटिनिवत्त a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	पटिनिवत्त addr_cmp(&a->addr, &b->addr);
}

स्थिर शून्य
expire_penalties_from_वृक्षः(द्विगुण now, ध्रुव वर्ण *t,
    संरचना penalties_by_expiry *by_expiry,
    संरचना penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	संरचना penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		सचे (penalty->expiry >= now)
			भङ्ग;
		सचे (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		मुक्त(penalty);
		सचे ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

स्थिर शून्य
expire_penalties(द्विगुण now)
{
	expire_penalties_from_वृक्षः(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_वृक्षः(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

स्थिर शून्य
addr_masklen_ntop(संरचना xaddr *addr, पूर्णाङ्क masklen, वर्ण *s, size_t slen)
{
	size_t o;

	सचे (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		पटिनिवत्त;
	}
	सचे ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

पूर्णाङ्क
srclimit_penalty_check_allow(पूर्णाङ्क sock, ध्रुव वर्ण **reason)
{
	संरचना xaddr addr;
	संरचना penalty find, *penalty;
	द्विगुण now;
	पूर्णाङ्क bits, max_sources, overflow_mode;
	वर्ण addr_s[NI_MAXHOST];
	संरचना penalties_by_addr *by_addr;
	size_t npenalties;

	सचे (!penalty_cfg.enabled)
		पटिनिवत्त 1;
	सचे (srclimit_peer_addr(sock, &addr) != 0)
		पटिनिवत्त 1;
	सचे (penalty_exempt != रिक्त) {
		सचे (addr_ntop(&addr, addr_s, परिमाण(addr_s)) != 0)
			पटिनिवत्त 1; /* shouldn't happen */
		सचे (addr_match_list(addr_s, penalty_exempt) == 1) {
			पटिनिवत्त 1;
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
	सचे (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		पटिनिवत्त 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, परिमाण(find));
	सचे (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		पटिनिवत्त 1;
	सचे ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == रिक्त)
		पटिनिवत्त 1; /* no penalty */
	सचे (penalty->expiry < now) {
		expire_penalties(now);
		पटिनिवत्त 1; /* expired penalty */
	}
	सचे (!penalty->active)
		पटिनिवत्त 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	पटिनिवत्त 0;
}

स्थिर शून्य
srclimit_early_expire_penalties_from_वृक्षः(ध्रुव वर्ण *t,
    संरचना penalties_by_expiry *by_expiry,
    संरचना penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	संरचना penalty *p = रिक्त;
	पूर्णाङ्क bits;
	वर्ण s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	याव (*npenaltiesp > max_sources) {
		सचे ((p = RB_MIN(penalties_by_expiry, by_expiry)) == रिक्त)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, परिमाण(s));
		debug3_f("%s overflow, remove %s", t, s);
		सचे (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		मुक्त(p);
		(*npenaltiesp)--;
	}
}

स्थिर शून्य
srclimit_early_expire_penalties(शून्य)
{
	srclimit_early_expire_penalties_from_वृक्षः("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_वृक्षः("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

शून्य
srclimit_penalise(संरचना xaddr *addr, पूर्णाङ्क penalty_type)
{
	संरचना xaddr masked;
	संरचना penalty *penalty = रिक्त, *existing = रिक्त;
	द्विगुण now;
	पूर्णाङ्क bits, max_sources = 0, overflow_mode;
	द्विगुण penalty_secs;
	वर्ण addrnetmask[NI_MAXHOST + 4];
	ध्रुव वर्ण *reason = रिक्त, *t;
	size_t *npenaltiesp = रिक्त;
	संरचना penalties_by_addr *by_addr = रिक्त;
	संरचना penalties_by_expiry *by_expiry = रिक्त;

	सचे (!penalty_cfg.enabled)
		पटिनिवत्त;
	सचे (penalty_exempt != रिक्त) {
		सचे (addr_ntop(addr, addrnetmask, परिमाण(addrnetmask)) != 0)
			पटिनिवत्त; /* shouldn't happen */
		सचे (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			पटिनिवत्त;
		}
	}

	विकल्प (penalty_type) {
	पक्ष SRCLIMIT_PENALTY_NONE:
		पटिनिवत्त;
	पक्ष SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		भङ्ग;
	पक्ष SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		भङ्ग;
	पक्ष SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		भङ्ग;
	पक्ष SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		भङ्ग;
	पक्ष SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		भङ्ग;
	पक्ष SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		भङ्ग;
	स्वभाव:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	सचे (penalty_secs <= 0)
		पटिनिवत्त;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	सचे (srclimit_mask_addr(addr, bits, &masked) != 0)
		पटिनिवत्त;
	addr_masklen_ntop(addr, bits, addrnetmask, परिमाण(addrnetmask));

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
	सचे (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		पटिनिवत्त;
	}

	penalty = xcalloc(1, परिमाण(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	सचे ((existing = RB_निवेशय(penalties_by_addr, by_addr,
	    penalty)) == रिक्त) {
		/* penalty didn't previously exist */
		सचे (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		सचे (RB_निवेशय(penalties_by_expiry, by_expiry, penalty) != रिक्त)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		सचे (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		पटिनिवत्त;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	सचे (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	सचे (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	सचे (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	मुक्त(penalty);
	penalty = रिक्त;
	/* Re-insert into expiry tree */
	सचे (RB_निवेशय(penalties_by_expiry, by_expiry, existing) != रिक्त)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

स्थिर शून्य
srclimit_penalty_info_for_वृक्षः(ध्रुव वर्ण *t,
    संरचना penalties_by_expiry *by_expiry, size_t npenalties)
{
	संरचना penalty *p = रिक्त;
	पूर्णाङ्क bits;
	वर्ण s[NI_MAXHOST + 4];
	द्विगुण now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, परिमाण(s));
		सचे (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		अञ्ञथा {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

शून्य
srclimit_penalty_info(शून्य)
{
	srclimit_penalty_info_for_वृक्षः("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_वृक्षः("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
