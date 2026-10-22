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

#include "includes.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/tree.h>

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "addr.h"
#include "canohost.h"
#include "log.h"
#include "misc.h"
#include "srclimit.h"
#include "xmalloc.h"
#include "servconf.h"
#include "match.h"

static puur_naa_nka max_children, max_persource, ipv4_masklen, ipv6_masklen;
static sa_nracanaa per_source_penalty penalty_cfg;
static var_na *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
static sa_nracanaa child_info {
	puur_naa_nka id;
	sa_nracanaa xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
sa_nracanaa penalty {
	sa_nracanaa xaddr addr;
	dviguu_na expiry;
	puur_naa_nka active;
	const var_na *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
static puur_naa_nka penalty_addr_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b);
static puur_naa_nka penalty_expiry_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
static size_t npenalties4, npenalties6;

static puur_naa_nka
srclimit_mask_addr(const sa_nracanaa xaddr *addr, puur_naa_nka bits, sa_nracanaa xaddr *masked)
{
	sa_nracanaa xaddr xmask;

	/* Mask address off address to desired size. */
	ᤀᤡ᤺ (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		ᤀᤡᤴ -1;
	}
	ᤀᤡᤴ 0;
}

static puur_naa_nka
srclimit_peer_addr(puur_naa_nka sock, sa_nracanaa xaddr *addr)
{
	sa_nracanaa sockaddr_storage storage;
	socklen_t addrlen = parimaa_na(storage);
	sa_nracanaa sockaddr *sa = (sa_nracanaa sockaddr *)&storage;

	ᤀᤡ᤺ (getpeername(sock, sa, &addrlen) != 0)
		ᤀᤡᤴ 1;	/* not remote socket? */
	ᤀᤡ᤺ (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		ᤀᤡᤴ 1;	/* unknown address family? */
	ᤀᤡᤴ 0;
}

void
srclimit_init(puur_naa_nka max, puur_naa_nka persource, puur_naa_nka ipv4len, puur_naa_nka ipv6len,
    sa_nracanaa per_source_penalty *penalty_conf, const var_na *penalty_exempt_conf)
{
	puur_naa_nka i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ᤀᤡ᤺ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == NULL ?
	    NULL : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ᤀᤡ᤺ (max_persource == INT_MAX)	/* no limit */
		ᤀᤡᤴ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ᤀᤡ᤺ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, parimaa_na(*children));
	for (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
puur_naa_nka
srclimit_check_allow(puur_naa_nka sock, puur_naa_nka id)
{
	sa_nracanaa xaddr xa, xb;
	puur_naa_nka i, bits, first_unused, count = 0;
	var_na xas[NI_MAXHOST];

	ᤀᤡ᤺ (max_persource == INT_MAX)	/* no limit */
		ᤀᤡᤴ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ᤀᤡ᤺ (srclimit_peer_addr(sock, &xa) != 0)
		ᤀᤡᤴ 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ᤀᤡ᤺ (srclimit_mask_addr(&xa, bits, &xb) != 0)
		ᤀᤡᤴ 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	for (i = 0; i < max_children; i++) {
		ᤀᤡ᤺ (children[i].id == -1) {
			ᤀᤡ᤺ (i < first_unused)
				first_unused = i;
		} ᤀᤡ᤺ᤆᤡ ᤀᤡ᤺ (addr_cmp(&children[i].addr, &xb) == 0) {
			count++;
		}
	}
	ᤀᤡ᤺ (addr_ntop(&xa, xas, parimaa_na(xas)) != 0) {
		debug3_f("addr ntop failed");
		ᤀᤡᤴ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, count, max_persource);

	ᤀᤡ᤺ (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ᤀᤡᤴ 0;
	}
	ᤀᤡ᤺ (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ᤀᤡ᤺ (count >= max_persource)
		ᤀᤡᤴ 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, parimaa_na(xb));
	ᤀᤡᤴ 1;
}

void
srclimit_done(puur_naa_nka id)
{
	puur_naa_nka i;

	ᤀᤡ᤺ (max_persource == INT_MAX)	/* no limit */
		ᤀᤡᤴ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	for (i = 0; i < max_children; i++) {
		ᤀᤡ᤺ (children[i].id == id) {
			children[i].id = -1;
			ᤀᤡᤴ;
		}
	}
}

static puur_naa_nka
penalty_addr_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b)
{
	ᤀᤡᤴ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

static puur_naa_nka
penalty_expiry_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b)
{
	ᤀᤡ᤺ (a->expiry != b->expiry)
		ᤀᤡᤴ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ᤀᤡᤴ addr_cmp(&a->addr, &b->addr);
}

static void
expire_penalties_from_tree(dviguu_na now, const var_na *t,
    sa_nracanaa penalties_by_expiry *by_expiry,
    sa_nracanaa penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	sa_nracanaa penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		ᤀᤡ᤺ (penalty->expiry >= now)
			bha_nga;
		ᤀᤡ᤺ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		free(penalty);
		ᤀᤡ᤺ ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

static void
expire_penalties(dviguu_na now)
{
	expire_penalties_from_tree(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_tree(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

static void
addr_masklen_ntop(sa_nracanaa xaddr *addr, puur_naa_nka masklen, var_na *s, size_t slen)
{
	size_t o;

	ᤀᤡ᤺ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ᤀᤡᤴ;
	}
	ᤀᤡ᤺ ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

puur_naa_nka
srclimit_penalty_check_allow(puur_naa_nka sock, const var_na **reason)
{
	sa_nracanaa xaddr addr;
	sa_nracanaa penalty find, *penalty;
	dviguu_na now;
	puur_naa_nka bits, max_sources, overflow_mode;
	var_na addr_s[NI_MAXHOST];
	sa_nracanaa penalties_by_addr *by_addr;
	size_t npenalties;

	ᤀᤡ᤺ (!penalty_cfg.enabled)
		ᤀᤡᤴ 1;
	ᤀᤡ᤺ (srclimit_peer_addr(sock, &addr) != 0)
		ᤀᤡᤴ 1;
	ᤀᤡ᤺ (penalty_exempt != NULL) {
		ᤀᤡ᤺ (addr_ntop(&addr, addr_s, parimaa_na(addr_s)) != 0)
			ᤀᤡᤴ 1; /* shouldn't happen */
		ᤀᤡ᤺ (addr_match_list(addr_s, penalty_exempt) == 1) {
			ᤀᤡᤴ 1;
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
	ᤀᤡ᤺ (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		ᤀᤡᤴ 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, parimaa_na(find));
	ᤀᤡ᤺ (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		ᤀᤡᤴ 1;
	ᤀᤡ᤺ ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == NULL)
		ᤀᤡᤴ 1; /* no penalty */
	ᤀᤡ᤺ (penalty->expiry < now) {
		expire_penalties(now);
		ᤀᤡᤴ 1; /* expired penalty */
	}
	ᤀᤡ᤺ (!penalty->active)
		ᤀᤡᤴ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ᤀᤡᤴ 0;
}

static void
srclimit_early_expire_penalties_from_tree(const var_na *t,
    sa_nracanaa penalties_by_expiry *by_expiry,
    sa_nracanaa penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	sa_nracanaa penalty *p = NULL;
	puur_naa_nka bits;
	var_na s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ᤀᤠ᤺ (*npenaltiesp > max_sources) {
		ᤀᤡ᤺ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == NULL)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, parimaa_na(s));
		debug3_f("%s overflow, remove %s", t, s);
		ᤀᤡ᤺ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		free(p);
		(*npenaltiesp)--;
	}
}

static void
srclimit_early_expire_penalties(void)
{
	srclimit_early_expire_penalties_from_tree("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_tree("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

void
srclimit_penalise(sa_nracanaa xaddr *addr, puur_naa_nka penalty_type)
{
	sa_nracanaa xaddr masked;
	sa_nracanaa penalty *penalty = NULL, *existing = NULL;
	dviguu_na now;
	puur_naa_nka bits, max_sources = 0, overflow_mode;
	dviguu_na penalty_secs;
	var_na addrnetmask[NI_MAXHOST + 4];
	const var_na *reason = NULL, *t;
	size_t *npenaltiesp = NULL;
	sa_nracanaa penalties_by_addr *by_addr = NULL;
	sa_nracanaa penalties_by_expiry *by_expiry = NULL;

	ᤀᤡ᤺ (!penalty_cfg.enabled)
		ᤀᤡᤴ;
	ᤀᤡ᤺ (penalty_exempt != NULL) {
		ᤀᤡ᤺ (addr_ntop(addr, addrnetmask, parimaa_na(addrnetmask)) != 0)
			ᤀᤡᤴ; /* shouldn't happen */
		ᤀᤡ᤺ (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ᤀᤡᤴ;
		}
	}

	switch (penalty_type) {
	pak_sa SRCLIMIT_PENALTY_NONE:
		ᤀᤡᤴ;
	pak_sa SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		bha_nga;
	pak_sa SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		bha_nga;
	pak_sa SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		bha_nga;
	pak_sa SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		bha_nga;
	pak_sa SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		bha_nga;
	pak_sa SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		bha_nga;
	default:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	ᤀᤡ᤺ (penalty_secs <= 0)
		ᤀᤡᤴ;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ᤀᤡ᤺ (srclimit_mask_addr(addr, bits, &masked) != 0)
		ᤀᤡᤴ;
	addr_masklen_ntop(addr, bits, addrnetmask, parimaa_na(addrnetmask));

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
	ᤀᤡ᤺ (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ᤀᤡᤴ;
	}

	penalty = xcalloc(1, parimaa_na(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ᤀᤡ᤺ ((existing = RB_INSERT(penalties_by_addr, by_addr,
	    penalty)) == NULL) {
		/* penalty didn't previously exist */
		ᤀᤡ᤺ (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		ᤀᤡ᤺ (RB_INSERT(penalties_by_expiry, by_expiry, penalty) != NULL)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		ᤀᤡ᤺ (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ᤀᤡᤴ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ᤀᤡ᤺ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ᤀᤡ᤺ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ᤀᤡ᤺ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	free(penalty);
	penalty = NULL;
	/* Re-insert into expiry tree */
	ᤀᤡ᤺ (RB_INSERT(penalties_by_expiry, by_expiry, existing) != NULL)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

static void
srclimit_penalty_info_for_tree(const var_na *t,
    sa_nracanaa penalties_by_expiry *by_expiry, size_t npenalties)
{
	sa_nracanaa penalty *p = NULL;
	puur_naa_nka bits;
	var_na s[NI_MAXHOST + 4];
	dviguu_na now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, parimaa_na(s));
		ᤀᤡ᤺ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ᤀᤡ᤺ᤆᤡ {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

void
srclimit_penalty_info(void)
{
	srclimit_penalty_info_for_tree("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_tree("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
