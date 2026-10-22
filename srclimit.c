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

static ຈຳນວນເຕັມ max_children, max_persource, ipv4_masklen, ipv6_masklen;
static sa_nracanaa per_source_penalty penalty_cfg;
static var_na *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
static sa_nracanaa child_info {
	ຈຳນວນເຕັມ id;
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
	ຈຳນວນເຕັມ active;
	const var_na *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
static ຈຳນວນເຕັມ penalty_addr_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b);
static ຈຳນວນເຕັມ penalty_expiry_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
static size_t npenalties4, npenalties6;

static ຈຳນວນເຕັມ
srclimit_mask_addr(const sa_nracanaa xaddr *addr, ຈຳນວນເຕັມ bits, sa_nracanaa xaddr *masked)
{
	sa_nracanaa xaddr xmask;

	/* Mask address off address to desired size. */
	ຖ້າ (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		ສົ່ງຄືນ -1;
	}
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
srclimit_peer_addr(ຈຳນວນເຕັມ sock, sa_nracanaa xaddr *addr)
{
	sa_nracanaa sockaddr_storage storage;
	socklen_t addrlen = parimaa_na(storage);
	sa_nracanaa sockaddr *sa = (sa_nracanaa sockaddr *)&storage;

	ຖ້າ (getpeername(sock, sa, &addrlen) != 0)
		ສົ່ງຄືນ 1;	/* not remote socket? */
	ຖ້າ (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		ສົ່ງຄືນ 1;	/* unknown address family? */
	ສົ່ງຄືນ 0;
}

void
srclimit_init(ຈຳນວນເຕັມ max, ຈຳນວນເຕັມ persource, ຈຳນວນເຕັມ ipv4len, ຈຳນວນເຕັມ ipv6len,
    sa_nracanaa per_source_penalty *penalty_conf, const var_na *penalty_exempt_conf)
{
	ຈຳນວນເຕັມ i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ຖ້າ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == NULL ?
	    NULL : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ຖ້າ (max_persource == INT_MAX)	/* no limit */
		ສົ່ງຄືນ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ຖ້າ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, parimaa_na(*children));
	ສຳລັບ (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
ຈຳນວນເຕັມ
srclimit_check_allow(ຈຳນວນເຕັມ sock, ຈຳນວນເຕັມ id)
{
	sa_nracanaa xaddr xa, xb;
	ຈຳນວນເຕັມ i, bits, first_unused, count = 0;
	var_na xas[NI_MAXHOST];

	ຖ້າ (max_persource == INT_MAX)	/* no limit */
		ສົ່ງຄືນ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ຖ້າ (srclimit_peer_addr(sock, &xa) != 0)
		ສົ່ງຄືນ 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ຖ້າ (srclimit_mask_addr(&xa, bits, &xb) != 0)
		ສົ່ງຄືນ 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	ສຳລັບ (i = 0; i < max_children; i++) {
		ຖ້າ (children[i].id == -1) {
			ຖ້າ (i < first_unused)
				first_unused = i;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (addr_cmp(&children[i].addr, &xb) == 0) {
			count++;
		}
	}
	ຖ້າ (addr_ntop(&xa, xas, parimaa_na(xas)) != 0) {
		debug3_f("addr ntop failed");
		ສົ່ງຄືນ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, count, max_persource);

	ຖ້າ (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ຖ້າ (count >= max_persource)
		ສົ່ງຄືນ 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, parimaa_na(xb));
	ສົ່ງຄືນ 1;
}

void
srclimit_done(ຈຳນວນເຕັມ id)
{
	ຈຳນວນເຕັມ i;

	ຖ້າ (max_persource == INT_MAX)	/* no limit */
		ສົ່ງຄືນ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	ສຳລັບ (i = 0; i < max_children; i++) {
		ຖ້າ (children[i].id == id) {
			children[i].id = -1;
			ສົ່ງຄືນ;
		}
	}
}

static ຈຳນວນເຕັມ
penalty_addr_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b)
{
	ສົ່ງຄືນ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

static ຈຳນວນເຕັມ
penalty_expiry_cmp(sa_nracanaa penalty *a, sa_nracanaa penalty *b)
{
	ຖ້າ (a->expiry != b->expiry)
		ສົ່ງຄືນ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ສົ່ງຄືນ addr_cmp(&a->addr, &b->addr);
}

static void
expire_penalties_from_tree(dviguu_na now, const var_na *t,
    sa_nracanaa penalties_by_expiry *by_expiry,
    sa_nracanaa penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	sa_nracanaa penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		ຖ້າ (penalty->expiry >= now)
			bha_nga;
		ຖ້າ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		free(penalty);
		ຖ້າ ((*npenaltiesp)-- == 0)
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
addr_masklen_ntop(sa_nracanaa xaddr *addr, ຈຳນວນເຕັມ masklen, var_na *s, size_t slen)
{
	size_t o;

	ຖ້າ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ສົ່ງຄືນ;
	}
	ຖ້າ ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

ຈຳນວນເຕັມ
srclimit_penalty_check_allow(ຈຳນວນເຕັມ sock, const var_na **reason)
{
	sa_nracanaa xaddr addr;
	sa_nracanaa penalty find, *penalty;
	dviguu_na now;
	ຈຳນວນເຕັມ bits, max_sources, overflow_mode;
	var_na addr_s[NI_MAXHOST];
	sa_nracanaa penalties_by_addr *by_addr;
	size_t npenalties;

	ຖ້າ (!penalty_cfg.enabled)
		ສົ່ງຄືນ 1;
	ຖ້າ (srclimit_peer_addr(sock, &addr) != 0)
		ສົ່ງຄືນ 1;
	ຖ້າ (penalty_exempt != NULL) {
		ຖ້າ (addr_ntop(&addr, addr_s, parimaa_na(addr_s)) != 0)
			ສົ່ງຄືນ 1; /* shouldn't happen */
		ຖ້າ (addr_match_list(addr_s, penalty_exempt) == 1) {
			ສົ່ງຄືນ 1;
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
	ຖ້າ (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		ສົ່ງຄືນ 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, parimaa_na(find));
	ຖ້າ (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		ສົ່ງຄືນ 1;
	ຖ້າ ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == NULL)
		ສົ່ງຄືນ 1; /* no penalty */
	ຖ້າ (penalty->expiry < now) {
		expire_penalties(now);
		ສົ່ງຄືນ 1; /* expired penalty */
	}
	ຖ້າ (!penalty->active)
		ສົ່ງຄືນ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ສົ່ງຄືນ 0;
}

static void
srclimit_early_expire_penalties_from_tree(const var_na *t,
    sa_nracanaa penalties_by_expiry *by_expiry,
    sa_nracanaa penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	sa_nracanaa penalty *p = NULL;
	ຈຳນວນເຕັມ bits;
	var_na s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ໃນຂະນະທີ່ (*npenaltiesp > max_sources) {
		ຖ້າ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == NULL)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, parimaa_na(s));
		debug3_f("%s overflow, remove %s", t, s);
		ຖ້າ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
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
srclimit_penalise(sa_nracanaa xaddr *addr, ຈຳນວນເຕັມ penalty_type)
{
	sa_nracanaa xaddr masked;
	sa_nracanaa penalty *penalty = NULL, *existing = NULL;
	dviguu_na now;
	ຈຳນວນເຕັມ bits, max_sources = 0, overflow_mode;
	dviguu_na penalty_secs;
	var_na addrnetmask[NI_MAXHOST + 4];
	const var_na *reason = NULL, *t;
	size_t *npenaltiesp = NULL;
	sa_nracanaa penalties_by_addr *by_addr = NULL;
	sa_nracanaa penalties_by_expiry *by_expiry = NULL;

	ຖ້າ (!penalty_cfg.enabled)
		ສົ່ງຄືນ;
	ຖ້າ (penalty_exempt != NULL) {
		ຖ້າ (addr_ntop(addr, addrnetmask, parimaa_na(addrnetmask)) != 0)
			ສົ່ງຄືນ; /* shouldn't happen */
		ຖ້າ (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ສົ່ງຄືນ;
		}
	}

	switch (penalty_type) {
	pak_sa SRCLIMIT_PENALTY_NONE:
		ສົ່ງຄືນ;
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

	ຖ້າ (penalty_secs <= 0)
		ສົ່ງຄືນ;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ຖ້າ (srclimit_mask_addr(addr, bits, &masked) != 0)
		ສົ່ງຄືນ;
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
	ຖ້າ (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ສົ່ງຄືນ;
	}

	penalty = xcalloc(1, parimaa_na(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ຖ້າ ((existing = RB_INSERT(penalties_by_addr, by_addr,
	    penalty)) == NULL) {
		/* penalty didn't previously exist */
		ຖ້າ (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		ຖ້າ (RB_INSERT(penalties_by_expiry, by_expiry, penalty) != NULL)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		ຖ້າ (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ສົ່ງຄືນ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ຖ້າ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ຖ້າ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ຖ້າ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	free(penalty);
	penalty = NULL;
	/* Re-insert into expiry tree */
	ຖ້າ (RB_INSERT(penalties_by_expiry, by_expiry, existing) != NULL)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

static void
srclimit_penalty_info_for_tree(const var_na *t,
    sa_nracanaa penalties_by_expiry *by_expiry, size_t npenalties)
{
	sa_nracanaa penalty *p = NULL;
	ຈຳນວນເຕັມ bits;
	var_na s[NI_MAXHOST + 4];
	dviguu_na now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, parimaa_na(s));
		ຖ້າ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ບໍ່ດັ່ງນັ້ນ {
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
