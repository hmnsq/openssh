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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/tree.h>

#అన్తర్భావ <limits.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "addr.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "srclimit.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "match.h"

స్థిర పూర్ణాంకం max_children, max_persource, ipv4_masklen, ipv6_masklen;
స్థిర నిర్మాణం చొప్పున_ఆధారం_penalty penalty_cfg;
స్థిర అక్షరం *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
స్థిర నిర్మాణం బిడ్డ_info {
	పూర్ణాంకం id;
	నిర్మాణం xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
నిర్మాణం penalty {
	నిర్మాణం xaddr addr;
	ద్విగుణ expiry;
	పూర్ణాంకం చురుకైన;
	స్థిరరాశి అక్షరం *reason;
	RB_నమోదు(penalty) by_addr;
	RB_నమోదు(penalty) by_expiry;
};
స్థిర పూర్ణాంకం penalty_addr_cmp(నిర్మాణం penalty *a, నిర్మాణం penalty *b);
స్థిర పూర్ణాంకం penalty_expiry_cmp(నిర్మాణం penalty *a, నిర్మాణం penalty *b);
RB_తల(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_తల(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
స్థిర కొలత_t npenalties4, npenalties6;

స్థిర పూర్ణాంకం
srclimit_ముసుగు_addr(స్థిరరాశి నిర్మాణం xaddr *addr, పూర్ణాంకం బిట్లు, నిర్మాణం xaddr *masked)
{
	నిర్మాణం xaddr xmask;

	/* Mask address off address to desired size. */
	ఒకవేళ (addr_netmask(addr->af, బిట్లు, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, బిట్లు);
		తిరిగి -1;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
srclimit_peer_addr(పూర్ణాంకం sock, నిర్మాణం xaddr *addr)
{
	నిర్మాణం sockaddr_storage storage;
	socklen_t addrlen = పరిమాణం(storage);
	నిర్మాణం sockaddr *sa = (నిర్మాణం sockaddr *)&storage;

	ఒకవేళ (getpeername(sock, sa, &addrlen) != 0)
		తిరిగి 1;	/* not remote socket? */
	ఒకవేళ (addr_sa_గమ్యం_xaddr(sa, addrlen, addr) != 0)
		తిరిగి 1;	/* unknown address family? */
	తిరిగి 0;
}

శూన్య
srclimit_init(పూర్ణాంకం max, పూర్ణాంకం persource, పూర్ణాంకం ipv4len, పూర్ణాంకం ipv6len,
    నిర్మాణం చొప్పున_ఆధారం_penalty *penalty_conf, స్థిరరాశి అక్షరం *penalty_exempt_conf)
{
	పూర్ణాంకం i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ఒకవేళ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ఖాళీ ?
	    ఖాళీ : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ఒకవేళ (max_persource == గరిష్ఠ_పూర్ణాంకం)	/* no limit */
		తిరిగి;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ఒకవేళ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, పరిమాణం(*children));
	కొరకు (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
పూర్ణాంకం
srclimit_check_allow(పూర్ణాంకం sock, పూర్ణాంకం id)
{
	నిర్మాణం xaddr xa, xb;
	పూర్ణాంకం i, బిట్లు, మొదటి_వాడని, లెక్క = 0;
	అక్షరం xas[NI_MAXHOST];

	ఒకవేళ (max_persource == గరిష్ఠ_పూర్ణాంకం)	/* no limit */
		తిరిగి 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ఒకవేళ (srclimit_peer_addr(sock, &xa) != 0)
		తిరిగి 1;
	బిట్లు = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ఒకవేళ (srclimit_ముసుగు_addr(&xa, బిట్లు, &xb) != 0)
		తిరిగి 1;

	మొదటి_వాడని = max_children;
	/* Count matching entries and find first unused one. */
	కొరకు (i = 0; i < max_children; i++) {
		ఒకవేళ (children[i].id == -1) {
			ఒకవేళ (i < మొదటి_వాడని)
				మొదటి_వాడని = i;
		} లేకపోతే ఒకవేళ (addr_cmp(&children[i].addr, &xb) == 0) {
			లెక్క++;
		}
	}
	ఒకవేళ (addr_ntop(&xa, xas, పరిమాణం(xas)) != 0) {
		debug3_f("addr ntop failed");
		తిరిగి 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, బిట్లు, లెక్క, max_persource);

	ఒకవేళ (మొదటి_వాడని == max_children) { /* no free slot found */
		debug3_f("no free slot");
		తిరిగి 0;
	}
	ఒకవేళ (మొదటి_వాడని < 0 || మొదటి_వాడని >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ఒకవేళ (లెక్క >= max_persource)
		తిరిగి 0;

	/* Connection allowed, store masked address. */
	children[మొదటి_వాడని].id = id;
	జ్ఞాపకం_నకలు(&children[మొదటి_వాడని].addr, &xb, పరిమాణం(xb));
	తిరిగి 1;
}

శూన్య
srclimit_పూర్తి(పూర్ణాంకం id)
{
	పూర్ణాంకం i;

	ఒకవేళ (max_persource == గరిష్ఠ_పూర్ణాంకం)	/* no limit */
		తిరిగి;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	కొరకు (i = 0; i < max_children; i++) {
		ఒకవేళ (children[i].id == id) {
			children[i].id = -1;
			తిరిగి;
		}
	}
}

స్థిర పూర్ణాంకం
penalty_addr_cmp(నిర్మాణం penalty *a, నిర్మాణం penalty *b)
{
	తిరిగి addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

స్థిర పూర్ణాంకం
penalty_expiry_cmp(నిర్మాణం penalty *a, నిర్మాణం penalty *b)
{
	ఒకవేళ (a->expiry != b->expiry)
		తిరిగి a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	తిరిగి addr_cmp(&a->addr, &b->addr);
}

స్థిర శూన్య
expire_penalties_from_వృక్షం(ద్విగుణ now, స్థిరరాశి అక్షరం *t,
    నిర్మాణం penalties_by_expiry *by_expiry,
    నిర్మాణం penalties_by_addr *by_addr, కొలత_t *npenaltiesp)
{
	నిర్మాణం penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_సురక్షిత(penalty, penalties_by_expiry, by_expiry, tmp) {
		ఒకవేళ (penalty->expiry >= now)
			ఆపు;
		ఒకవేళ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		విడుదల(penalty);
		ఒకవేళ ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

స్థిర శూన్య
expire_penalties(ద్విగుణ now)
{
	expire_penalties_from_వృక్షం(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_వృక్షం(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

స్థిర శూన్య
addr_masklen_ntop(నిర్మాణం xaddr *addr, పూర్ణాంకం masklen, అక్షరం *s, కొలత_t slen)
{
	కొలత_t o;

	ఒకవేళ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		తిరిగి;
	}
	ఒకవేళ ((o = అక్షరశ్రేణి_పొడవు(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

పూర్ణాంకం
srclimit_penalty_check_allow(పూర్ణాంకం sock, స్థిరరాశి అక్షరం **reason)
{
	నిర్మాణం xaddr addr;
	నిర్మాణం penalty కనుగొను, *penalty;
	ద్విగుణ now;
	పూర్ణాంకం బిట్లు, max_sources, అధికప్రవాహం_బహుళకం;
	అక్షరం addr_s[NI_MAXHOST];
	నిర్మాణం penalties_by_addr *by_addr;
	కొలత_t npenalties;

	ఒకవేళ (!penalty_cfg.enabled)
		తిరిగి 1;
	ఒకవేళ (srclimit_peer_addr(sock, &addr) != 0)
		తిరిగి 1;
	ఒకవేళ (penalty_exempt != ఖాళీ) {
		ఒకవేళ (addr_ntop(&addr, addr_s, పరిమాణం(addr_s)) != 0)
			తిరిగి 1; /* shouldn't happen */
		ఒకవేళ (addr_సరిపోలిక_list(addr_s, penalty_exempt) == 1) {
			తిరిగి 1;
		}
	}
	now = monotime_double();
	expire_penalties(now);
	by_addr = addr.af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr.af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	అధికప్రవాహం_బహుళకం = addr.af == AF_INET ?
	    penalty_cfg.అధికప్రవాహం_బహుళకం : penalty_cfg.అధికప్రవాహం_mode6;
	npenalties = addr.af == AF_INET ?  npenalties4 : npenalties6;
	ఒకవేళ (npenalties >= (కొలత_t)max_sources &&
	    అధికప్రవాహం_బహుళకం == చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL) {
		*reason = "too many penalised addresses";
		తిరిగి 0;
	}
	బిట్లు = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&కనుగొను, 0, పరిమాణం(కనుగొను));
	ఒకవేళ (srclimit_ముసుగు_addr(&addr, బిట్లు, &కనుగొను.addr) != 0)
		తిరిగి 1;
	ఒకవేళ ((penalty = RB_కనుగొను(penalties_by_addr, by_addr, &కనుగొను)) == ఖాళీ)
		తిరిగి 1; /* no penalty */
	ఒకవేళ (penalty->expiry < now) {
		expire_penalties(now);
		తిరిగి 1; /* expired penalty */
	}
	ఒకవేళ (!penalty->చురుకైన)
		తిరిగి 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	తిరిగి 0;
}

స్థిర శూన్య
srclimit_early_expire_penalties_from_వృక్షం(స్థిరరాశి అక్షరం *t,
    నిర్మాణం penalties_by_expiry *by_expiry,
    నిర్మాణం penalties_by_addr *by_addr, కొలత_t *npenaltiesp, కొలత_t max_sources)
{
	నిర్మాణం penalty *p = ఖాళీ;
	పూర్ణాంకం బిట్లు;
	అక్షరం s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	అయితే (*npenaltiesp > max_sources) {
		ఒకవేళ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ఖాళీ)
			fatal_f("internal error: %s table corrupt (find)", t);
		బిట్లు = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, బిట్లు, s, పరిమాణం(s));
		debug3_f("%s overflow, remove %s", t, s);
		ఒకవేళ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		విడుదల(p);
		(*npenaltiesp)--;
	}
}

స్థిర శూన్య
srclimit_early_expire_penalties(శూన్య)
{
	srclimit_early_expire_penalties_from_వృక్షం("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (కొలత_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_వృక్షం("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (కొలత_t)penalty_cfg.max_sources6);
}

శూన్య
srclimit_penalise(నిర్మాణం xaddr *addr, పూర్ణాంకం penalty_type)
{
	నిర్మాణం xaddr masked;
	నిర్మాణం penalty *penalty = ఖాళీ, *existing = ఖాళీ;
	ద్విగుణ now;
	పూర్ణాంకం బిట్లు, max_sources = 0, అధికప్రవాహం_బహుళకం;
	ద్విగుణ penalty_secs;
	అక్షరం addrnetmask[NI_MAXHOST + 4];
	స్థిరరాశి అక్షరం *reason = ఖాళీ, *t;
	కొలత_t *npenaltiesp = ఖాళీ;
	నిర్మాణం penalties_by_addr *by_addr = ఖాళీ;
	నిర్మాణం penalties_by_expiry *by_expiry = ఖాళీ;

	ఒకవేళ (!penalty_cfg.enabled)
		తిరిగి;
	ఒకవేళ (penalty_exempt != ఖాళీ) {
		ఒకవేళ (addr_ntop(addr, addrnetmask, పరిమాణం(addrnetmask)) != 0)
			తిరిగి; /* shouldn't happen */
		ఒకవేళ (addr_సరిపోలిక_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			తిరిగి;
		}
	}

	ఎంపిక (penalty_type) {
	స్థితి SRCLIMIT_PENALTY_NONE:
		తిరిగి;
	స్థితి SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		ఆపు;
	స్థితి SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		ఆపు;
	స్థితి SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		ఆపు;
	స్థితి SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		ఆపు;
	స్థితి SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		ఆపు;
	స్థితి SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		ఆపు;
	అప్రమేయ:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	ఒకవేళ (penalty_secs <= 0)
		తిరిగి;

	బిట్లు = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ఒకవేళ (srclimit_ముసుగు_addr(addr, బిట్లు, &masked) != 0)
		తిరిగి;
	addr_masklen_ntop(addr, బిట్లు, addrnetmask, పరిమాణం(addrnetmask));

	now = monotime_double();
	expire_penalties(now);
	by_expiry = addr->af == AF_INET ?
	    &penalties_by_expiry4 : &penalties_by_expiry6;
	by_addr = addr->af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr->af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	అధికప్రవాహం_బహుళకం = addr->af == AF_INET ?
	    penalty_cfg.అధికప్రవాహం_బహుళకం : penalty_cfg.అధికప్రవాహం_mode6;
	npenaltiesp = addr->af == AF_INET ?  &npenalties4 : &npenalties6;
	t = addr->af == AF_INET ? "ipv4" : "ipv6";
	ఒకవేళ (*npenaltiesp >= (కొలత_t)max_sources &&
	    అధికప్రవాహం_బహుళకం == చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		తిరిగి;
	}

	penalty = xcalloc(1, పరిమాణం(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ఒకవేళ ((existing = RB_చొప్పించు(penalties_by_addr, by_addr,
	    penalty)) == ఖాళీ) {
		/* penalty didn't previously exist */
		ఒకవేళ (penalty_secs > penalty_cfg.penalty_min)
			penalty->చురుకైన = 1;
		ఒకవేళ (RB_చొప్పించు(penalties_by_expiry, by_expiry, penalty) != ఖాళీ)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->చురుకైన ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->చురుకైన ? "active" : "deferred",
		    penalty_secs, reason);
		ఒకవేళ (++(*npenaltiesp) > (కొలత_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		తిరిగి;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->చురుకైన ? "active" : "inactive", t,
	    addrnetmask, (దీర్ఘ దీర్ఘ)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ఒకవేళ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ఒకవేళ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ఒకవేళ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->చురుకైన) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->చురుకైన = 1;
	}
	existing->reason = penalty->reason;
	విడుదల(penalty);
	penalty = ఖాళీ;
	/* Re-insert into expiry tree */
	ఒకవేళ (RB_చొప్పించు(penalties_by_expiry, by_expiry, existing) != ఖాళీ)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

స్థిర శూన్య
srclimit_penalty_info_for_వృక్షం(స్థిరరాశి అక్షరం *t,
    నిర్మాణం penalties_by_expiry *by_expiry, కొలత_t npenalties)
{
	నిర్మాణం penalty *p = ఖాళీ;
	పూర్ణాంకం బిట్లు;
	అక్షరం s[NI_MAXHOST + 4];
	ద్విగుణ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		బిట్లు = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, బిట్లు, s, పరిమాణం(s));
		ఒకవేళ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		లేకపోతే {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

శూన్య
srclimit_penalty_info(శూన్య)
{
	srclimit_penalty_info_for_వృక్షం("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_వృక్షం("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
