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

स्थिर पूर्णांक max_children, max_persource, ipv4_masklen, ipv6_masklen;
स्थिर संरचना per_source_penalty penalty_cfg;
स्थिर अक्षर *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
स्थिर संरचना child_info {
	पूर्णांक id;
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
	पूर्णांक active;
	स्थिरांक अक्षर *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
स्थिर पूर्णांक penalty_addr_cmp(संरचना penalty *a, संरचना penalty *b);
स्थिर पूर्णांक penalty_expiry_cmp(संरचना penalty *a, संरचना penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
स्थिर माप_प्रकार npenalties4, npenalties6;

स्थिर पूर्णांक
srclimit_mask_addr(स्थिरांक संरचना xaddr *addr, पूर्णांक bits, संरचना xaddr *masked)
{
	संरचना xaddr xmask;

	/* Mask address off address to desired size. */
	जर (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		परत -1;
	}
	परत 0;
}

स्थिर पूर्णांक
srclimit_peer_addr(पूर्णांक sock, संरचना xaddr *addr)
{
	संरचना sockaddr_storage storage;
	socklen_t addrlen = आकार(storage);
	संरचना sockaddr *sa = (संरचना sockaddr *)&storage;

	जर (getpeername(sock, sa, &addrlen) != 0)
		परत 1;	/* not remote socket? */
	जर (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		परत 1;	/* unknown address family? */
	परत 0;
}

शून्य
srclimit_init(पूर्णांक max, पूर्णांक persource, पूर्णांक ipv4len, पूर्णांक ipv6len,
    संरचना per_source_penalty *penalty_conf, स्थिरांक अक्षर *penalty_exempt_conf)
{
	पूर्णांक i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	जर (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == रिक्त ?
	    रिक्त : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	जर (max_persource == पूर्णांक_उच्च)	/* no limit */
		परत;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	जर (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, आकार(*children));
	साठी (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
पूर्णांक
srclimit_check_allow(पूर्णांक sock, पूर्णांक id)
{
	संरचना xaddr xa, xb;
	पूर्णांक i, bits, first_unused, मोजणी = 0;
	अक्षर xas[NI_MAXHOST];

	जर (max_persource == पूर्णांक_उच्च)	/* no limit */
		परत 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	जर (srclimit_peer_addr(sock, &xa) != 0)
		परत 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	जर (srclimit_mask_addr(&xa, bits, &xb) != 0)
		परत 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	साठी (i = 0; i < max_children; i++) {
		जर (children[i].id == -1) {
			जर (i < first_unused)
				first_unused = i;
		} अन्यथा जर (addr_cmp(&children[i].addr, &xb) == 0) {
			मोजणी++;
		}
	}
	जर (addr_ntop(&xa, xas, आकार(xas)) != 0) {
		debug3_f("addr ntop failed");
		परत 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, मोजणी, max_persource);

	जर (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		परत 0;
	}
	जर (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	जर (मोजणी >= max_persource)
		परत 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	स_नकल(&children[first_unused].addr, &xb, आकार(xb));
	परत 1;
}

शून्य
srclimit_done(पूर्णांक id)
{
	पूर्णांक i;

	जर (max_persource == पूर्णांक_उच्च)	/* no limit */
		परत;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	साठी (i = 0; i < max_children; i++) {
		जर (children[i].id == id) {
			children[i].id = -1;
			परत;
		}
	}
}

स्थिर पूर्णांक
penalty_addr_cmp(संरचना penalty *a, संरचना penalty *b)
{
	परत addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

स्थिर पूर्णांक
penalty_expiry_cmp(संरचना penalty *a, संरचना penalty *b)
{
	जर (a->expiry != b->expiry)
		परत a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	परत addr_cmp(&a->addr, &b->addr);
}

स्थिर शून्य
expire_penalties_from_वृक्ष(द्विगुण now, स्थिरांक अक्षर *t,
    संरचना penalties_by_expiry *by_expiry,
    संरचना penalties_by_addr *by_addr, माप_प्रकार *npenaltiesp)
{
	संरचना penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		जर (penalty->expiry >= now)
			थांबा;
		जर (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		मुक्त(penalty);
		जर ((*npenaltiesp)-- == 0)
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
addr_masklen_ntop(संरचना xaddr *addr, पूर्णांक masklen, अक्षर *s, माप_प्रकार slen)
{
	माप_प्रकार o;

	जर (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		परत;
	}
	जर ((o = म_माप(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

पूर्णांक
srclimit_penalty_check_allow(पूर्णांक sock, स्थिरांक अक्षर **reason)
{
	संरचना xaddr addr;
	संरचना penalty find, *penalty;
	द्विगुण now;
	पूर्णांक bits, max_sources, overflow_mode;
	अक्षर addr_s[NI_MAXHOST];
	संरचना penalties_by_addr *by_addr;
	माप_प्रकार npenalties;

	जर (!penalty_cfg.enabled)
		परत 1;
	जर (srclimit_peer_addr(sock, &addr) != 0)
		परत 1;
	जर (penalty_exempt != रिक्त) {
		जर (addr_ntop(&addr, addr_s, आकार(addr_s)) != 0)
			परत 1; /* shouldn't happen */
		जर (addr_match_list(addr_s, penalty_exempt) == 1) {
			परत 1;
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
	जर (npenalties >= (माप_प्रकार)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		परत 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	स_रखो(&find, 0, आकार(find));
	जर (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		परत 1;
	जर ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == रिक्त)
		परत 1; /* no penalty */
	जर (penalty->expiry < now) {
		expire_penalties(now);
		परत 1; /* expired penalty */
	}
	जर (!penalty->active)
		परत 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	परत 0;
}

स्थिर शून्य
srclimit_early_expire_penalties_from_वृक्ष(स्थिरांक अक्षर *t,
    संरचना penalties_by_expiry *by_expiry,
    संरचना penalties_by_addr *by_addr, माप_प्रकार *npenaltiesp, माप_प्रकार max_sources)
{
	संरचना penalty *p = रिक्त;
	पूर्णांक bits;
	अक्षर s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	पर्यंत (*npenaltiesp > max_sources) {
		जर ((p = RB_MIN(penalties_by_expiry, by_expiry)) == रिक्त)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, आकार(s));
		debug3_f("%s overflow, remove %s", t, s);
		जर (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
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
srclimit_penalise(संरचना xaddr *addr, पूर्णांक penalty_type)
{
	संरचना xaddr masked;
	संरचना penalty *penalty = रिक्त, *existing = रिक्त;
	द्विगुण now;
	पूर्णांक bits, max_sources = 0, overflow_mode;
	द्विगुण penalty_secs;
	अक्षर addrnetmask[NI_MAXHOST + 4];
	स्थिरांक अक्षर *reason = रिक्त, *t;
	माप_प्रकार *npenaltiesp = रिक्त;
	संरचना penalties_by_addr *by_addr = रिक्त;
	संरचना penalties_by_expiry *by_expiry = रिक्त;

	जर (!penalty_cfg.enabled)
		परत;
	जर (penalty_exempt != रिक्त) {
		जर (addr_ntop(addr, addrnetmask, आकार(addrnetmask)) != 0)
			परत; /* shouldn't happen */
		जर (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			परत;
		}
	}

	निवड (penalty_type) {
	स्थिती SRCLIMIT_PENALTY_NONE:
		परत;
	स्थिती SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		थांबा;
	स्थिती SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		थांबा;
	स्थिती SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		थांबा;
	स्थिती SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		थांबा;
	स्थिती SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		थांबा;
	स्थिती SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		थांबा;
	पूर्वनिर्धारित:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	जर (penalty_secs <= 0)
		परत;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	जर (srclimit_mask_addr(addr, bits, &masked) != 0)
		परत;
	addr_masklen_ntop(addr, bits, addrnetmask, आकार(addrnetmask));

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
	जर (*npenaltiesp >= (माप_प्रकार)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		परत;
	}

	penalty = xcalloc(1, आकार(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	जर ((existing = RB_घाला(penalties_by_addr, by_addr,
	    penalty)) == रिक्त) {
		/* penalty didn't previously exist */
		जर (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		जर (RB_घाला(penalties_by_expiry, by_expiry, penalty) != रिक्त)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		जर (++(*npenaltiesp) > (माप_प्रकार)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		परत;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (दीर्घ दीर्घ)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	जर (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	जर (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	जर (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	मुक्त(penalty);
	penalty = रिक्त;
	/* Re-insert into expiry tree */
	जर (RB_घाला(penalties_by_expiry, by_expiry, existing) != रिक्त)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

स्थिर शून्य
srclimit_penalty_info_for_वृक्ष(स्थिरांक अक्षर *t,
    संरचना penalties_by_expiry *by_expiry, माप_प्रकार npenalties)
{
	संरचना penalty *p = रिक्त;
	पूर्णांक bits;
	अक्षर s[NI_MAXHOST + 4];
	द्विगुण now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, आकार(s));
		जर (p->expiry < now)
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
