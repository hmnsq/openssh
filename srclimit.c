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
स्थिर माप_प्रकार npenalties4, npenalties6;

स्थिर पूर्णाङ्क
srclimit_mask_addr(ध्रुव संरचना xaddr *addr, पूर्णाङ्क bits, संरचना xaddr *masked)
{
	संरचना xaddr xmask;

	/* Mask address off address to desired size. */
	यदि (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		प्रत्यागम -1;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
srclimit_peer_addr(पूर्णाङ्क sock, संरचना xaddr *addr)
{
	संरचना sockaddr_storage storage;
	socklen_t addrlen = परिमाण(storage);
	संरचना sockaddr *sa = (संरचना sockaddr *)&storage;

	यदि (getpeername(sock, sa, &addrlen) != 0)
		प्रत्यागम 1;	/* not remote socket? */
	यदि (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		प्रत्यागम 1;	/* unknown address family? */
	प्रत्यागम 0;
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
	यदि (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == रिक्त ?
	    रिक्त : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	यदि (max_persource == पूर्णांक_उच्च)	/* no limit */
		प्रत्यागम;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	यदि (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, परिमाण(*children));
	प्रति (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
पूर्णाङ्क
srclimit_check_allow(पूर्णाङ्क sock, पूर्णाङ्क id)
{
	संरचना xaddr xa, xb;
	पूर्णाङ्क i, bits, first_unused, गिनती = 0;
	वर्ण xas[NI_MAXHOST];

	यदि (max_persource == पूर्णांक_उच्च)	/* no limit */
		प्रत्यागम 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	यदि (srclimit_peer_addr(sock, &xa) != 0)
		प्रत्यागम 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	यदि (srclimit_mask_addr(&xa, bits, &xb) != 0)
		प्रत्यागम 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	प्रति (i = 0; i < max_children; i++) {
		यदि (children[i].id == -1) {
			यदि (i < first_unused)
				first_unused = i;
		} अन्यथा यदि (addr_cmp(&children[i].addr, &xb) == 0) {
			गिनती++;
		}
	}
	यदि (addr_ntop(&xa, xas, परिमाण(xas)) != 0) {
		debug3_f("addr ntop failed");
		प्रत्यागम 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, गिनती, max_persource);

	यदि (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		प्रत्यागम 0;
	}
	यदि (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	यदि (गिनती >= max_persource)
		प्रत्यागम 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	स_नकल(&children[first_unused].addr, &xb, परिमाण(xb));
	प्रत्यागम 1;
}

शून्य
srclimit_done(पूर्णाङ्क id)
{
	पूर्णाङ्क i;

	यदि (max_persource == पूर्णांक_उच्च)	/* no limit */
		प्रत्यागम;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	प्रति (i = 0; i < max_children; i++) {
		यदि (children[i].id == id) {
			children[i].id = -1;
			प्रत्यागम;
		}
	}
}

स्थिर पूर्णाङ्क
penalty_addr_cmp(संरचना penalty *a, संरचना penalty *b)
{
	प्रत्यागम addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

स्थिर पूर्णाङ्क
penalty_expiry_cmp(संरचना penalty *a, संरचना penalty *b)
{
	यदि (a->expiry != b->expiry)
		प्रत्यागम a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	प्रत्यागम addr_cmp(&a->addr, &b->addr);
}

स्थिर शून्य
expire_penalties_from_वृक्ष(द्विगुण now, ध्रुव वर्ण *t,
    संरचना penalties_by_expiry *by_expiry,
    संरचना penalties_by_addr *by_addr, माप_प्रकार *npenaltiesp)
{
	संरचना penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		यदि (penalty->expiry >= now)
			भङ्ग;
		यदि (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		मुक्त(penalty);
		यदि ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

स्थिर शून्य
expire_penalties(द्विगुण now)
{
	expire_penalties_from_वृक्ष(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_वृक्ष(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

स्थिर शून्य
addr_masklen_ntop(संरचना xaddr *addr, पूर्णाङ्क masklen, वर्ण *s, माप_प्रकार slen)
{
	माप_प्रकार o;

	यदि (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		प्रत्यागम;
	}
	यदि ((o = म_माप(s)) < slen)
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
	माप_प्रकार npenalties;

	यदि (!penalty_cfg.enabled)
		प्रत्यागम 1;
	यदि (srclimit_peer_addr(sock, &addr) != 0)
		प्रत्यागम 1;
	यदि (penalty_exempt != रिक्त) {
		यदि (addr_ntop(&addr, addr_s, परिमाण(addr_s)) != 0)
			प्रत्यागम 1; /* shouldn't happen */
		यदि (addr_match_list(addr_s, penalty_exempt) == 1) {
			प्रत्यागम 1;
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
	यदि (npenalties >= (माप_प्रकार)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		प्रत्यागम 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	स_रखो(&find, 0, परिमाण(find));
	यदि (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		प्रत्यागम 1;
	यदि ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == रिक्त)
		प्रत्यागम 1; /* no penalty */
	यदि (penalty->expiry < now) {
		expire_penalties(now);
		प्रत्यागम 1; /* expired penalty */
	}
	यदि (!penalty->active)
		प्रत्यागम 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	प्रत्यागम 0;
}

स्थिर शून्य
srclimit_early_expire_penalties_from_वृक्ष(ध्रुव वर्ण *t,
    संरचना penalties_by_expiry *by_expiry,
    संरचना penalties_by_addr *by_addr, माप_प्रकार *npenaltiesp, माप_प्रकार max_sources)
{
	संरचना penalty *p = रिक्त;
	पूर्णाङ्क bits;
	वर्ण s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	यावत् (*npenaltiesp > max_sources) {
		यदि ((p = RB_MIN(penalties_by_expiry, by_expiry)) == रिक्त)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, परिमाण(s));
		debug3_f("%s overflow, remove %s", t, s);
		यदि (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		मुक्त(p);
		(*npenaltiesp)--;
	}
}

स्थिर शून्य
srclimit_early_expire_penalties(शून्य)
{
	srclimit_early_expire_penalties_from_वृक्ष("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (माप_प्रकार)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_वृक्ष("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (माप_प्रकार)penalty_cfg.max_sources6);
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
	माप_प्रकार *npenaltiesp = रिक्त;
	संरचना penalties_by_addr *by_addr = रिक्त;
	संरचना penalties_by_expiry *by_expiry = रिक्त;

	यदि (!penalty_cfg.enabled)
		प्रत्यागम;
	यदि (penalty_exempt != रिक्त) {
		यदि (addr_ntop(addr, addrnetmask, परिमाण(addrnetmask)) != 0)
			प्रत्यागम; /* shouldn't happen */
		यदि (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			प्रत्यागम;
		}
	}

	विकल्प (penalty_type) {
	पक्ष SRCLIMIT_PENALTY_NONE:
		प्रत्यागम;
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

	यदि (penalty_secs <= 0)
		प्रत्यागम;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	यदि (srclimit_mask_addr(addr, bits, &masked) != 0)
		प्रत्यागम;
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
	यदि (*npenaltiesp >= (माप_प्रकार)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		प्रत्यागम;
	}

	penalty = xcalloc(1, परिमाण(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	यदि ((existing = RB_जोड़ो(penalties_by_addr, by_addr,
	    penalty)) == रिक्त) {
		/* penalty didn't previously exist */
		यदि (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		यदि (RB_जोड़ो(penalties_by_expiry, by_expiry, penalty) != रिक्त)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		यदि (++(*npenaltiesp) > (माप_प्रकार)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		प्रत्यागम;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (दीर्घ दीर्घ)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	यदि (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	यदि (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	यदि (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	मुक्त(penalty);
	penalty = रिक्त;
	/* Re-insert into expiry tree */
	यदि (RB_जोड़ो(penalties_by_expiry, by_expiry, existing) != रिक्त)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

स्थिर शून्य
srclimit_penalty_info_for_वृक्ष(ध्रुव वर्ण *t,
    संरचना penalties_by_expiry *by_expiry, माप_प्रकार npenalties)
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
		यदि (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		अन्यथा {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

शून्य
srclimit_penalty_info(शून्य)
{
	srclimit_penalty_info_for_वृक्ष("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_वृक्ष("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
