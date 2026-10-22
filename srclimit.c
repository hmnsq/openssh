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

static ціле max_children, max_persource, ipv4_masklen, ipv6_masklen;
static struct per_source_penalty penalty_cfg;
static char *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
static struct child_info {
	ціле id;
	struct xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
struct penalty {
	struct xaddr addr;
	double expiry;
	ціле active;
	const char *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
static ціле penalty_addr_cmp(struct penalty *a, struct penalty *b);
static ціле penalty_expiry_cmp(struct penalty *a, struct penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
static size_t npenalties4, npenalties6;

static ціле
srclimit_mask_addr(const struct xaddr *addr, ціле bits, struct xaddr *masked)
{
	struct xaddr xmask;

	/* Mask address off address to desired size. */
	якщо (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		повернути -1;
	}
	повернути 0;
}

static ціле
srclimit_peer_addr(ціле sock, struct xaddr *addr)
{
	struct sockaddr_storage storage;
	socklen_t addrlen = sizeof(storage);
	struct sockaddr *sa = (struct sockaddr *)&storage;

	якщо (getpeername(sock, sa, &addrlen) != 0)
		повернути 1;	/* not remote socket? */
	якщо (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		повернути 1;	/* unknown address family? */
	повернути 0;
}

void
srclimit_init(ціле max, ціле persource, ціле ipv4len, ціле ipv6len,
    struct per_source_penalty *penalty_conf, const char *penalty_exempt_conf)
{
	ціле i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	якщо (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == NULL ?
	    NULL : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	якщо (max_persource == INT_MAX)	/* no limit */
		повернути;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	якщо (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, sizeof(*children));
	для (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
ціле
srclimit_check_allow(ціле sock, ціле id)
{
	struct xaddr xa, xb;
	ціле i, bits, first_unused, count = 0;
	char xas[NI_MAXHOST];

	якщо (max_persource == INT_MAX)	/* no limit */
		повернути 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	якщо (srclimit_peer_addr(sock, &xa) != 0)
		повернути 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	якщо (srclimit_mask_addr(&xa, bits, &xb) != 0)
		повернути 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	для (i = 0; i < max_children; i++) {
		якщо (children[i].id == -1) {
			якщо (i < first_unused)
				first_unused = i;
		} інакше якщо (addr_cmp(&children[i].addr, &xb) == 0) {
			count++;
		}
	}
	якщо (addr_ntop(&xa, xas, sizeof(xas)) != 0) {
		debug3_f("addr ntop failed");
		повернути 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, count, max_persource);

	якщо (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		повернути 0;
	}
	якщо (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	якщо (count >= max_persource)
		повернути 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, sizeof(xb));
	повернути 1;
}

void
srclimit_done(ціле id)
{
	ціле i;

	якщо (max_persource == INT_MAX)	/* no limit */
		повернути;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	для (i = 0; i < max_children; i++) {
		якщо (children[i].id == id) {
			children[i].id = -1;
			повернути;
		}
	}
}

static ціле
penalty_addr_cmp(struct penalty *a, struct penalty *b)
{
	повернути addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

static ціле
penalty_expiry_cmp(struct penalty *a, struct penalty *b)
{
	якщо (a->expiry != b->expiry)
		повернути a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	повернути addr_cmp(&a->addr, &b->addr);
}

static void
expire_penalties_from_tree(double now, const char *t,
    struct penalties_by_expiry *by_expiry,
    struct penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	struct penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		якщо (penalty->expiry >= now)
			break;
		якщо (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		free(penalty);
		якщо ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

static void
expire_penalties(double now)
{
	expire_penalties_from_tree(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_tree(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

static void
addr_masklen_ntop(struct xaddr *addr, ціле masklen, char *s, size_t slen)
{
	size_t o;

	якщо (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		повернути;
	}
	якщо ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

ціле
srclimit_penalty_check_allow(ціле sock, const char **reason)
{
	struct xaddr addr;
	struct penalty find, *penalty;
	double now;
	ціле bits, max_sources, overflow_mode;
	char addr_s[NI_MAXHOST];
	struct penalties_by_addr *by_addr;
	size_t npenalties;

	якщо (!penalty_cfg.enabled)
		повернути 1;
	якщо (srclimit_peer_addr(sock, &addr) != 0)
		повернути 1;
	якщо (penalty_exempt != NULL) {
		якщо (addr_ntop(&addr, addr_s, sizeof(addr_s)) != 0)
			повернути 1; /* shouldn't happen */
		якщо (addr_match_list(addr_s, penalty_exempt) == 1) {
			повернути 1;
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
	якщо (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		повернути 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, sizeof(find));
	якщо (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		повернути 1;
	якщо ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == NULL)
		повернути 1; /* no penalty */
	якщо (penalty->expiry < now) {
		expire_penalties(now);
		повернути 1; /* expired penalty */
	}
	якщо (!penalty->active)
		повернути 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	повернути 0;
}

static void
srclimit_early_expire_penalties_from_tree(const char *t,
    struct penalties_by_expiry *by_expiry,
    struct penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	struct penalty *p = NULL;
	ціле bits;
	char s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	поки (*npenaltiesp > max_sources) {
		якщо ((p = RB_MIN(penalties_by_expiry, by_expiry)) == NULL)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, sizeof(s));
		debug3_f("%s overflow, remove %s", t, s);
		якщо (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
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
srclimit_penalise(struct xaddr *addr, ціле penalty_type)
{
	struct xaddr masked;
	struct penalty *penalty = NULL, *existing = NULL;
	double now;
	ціле bits, max_sources = 0, overflow_mode;
	double penalty_secs;
	char addrnetmask[NI_MAXHOST + 4];
	const char *reason = NULL, *t;
	size_t *npenaltiesp = NULL;
	struct penalties_by_addr *by_addr = NULL;
	struct penalties_by_expiry *by_expiry = NULL;

	якщо (!penalty_cfg.enabled)
		повернути;
	якщо (penalty_exempt != NULL) {
		якщо (addr_ntop(addr, addrnetmask, sizeof(addrnetmask)) != 0)
			повернути; /* shouldn't happen */
		якщо (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			повернути;
		}
	}

	switch (penalty_type) {
	case SRCLIMIT_PENALTY_NONE:
		повернути;
	case SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		break;
	case SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		break;
	case SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		break;
	case SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		break;
	case SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		break;
	case SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		break;
	default:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	якщо (penalty_secs <= 0)
		повернути;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	якщо (srclimit_mask_addr(addr, bits, &masked) != 0)
		повернути;
	addr_masklen_ntop(addr, bits, addrnetmask, sizeof(addrnetmask));

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
	якщо (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		повернути;
	}

	penalty = xcalloc(1, sizeof(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	якщо ((existing = RB_INSERT(penalties_by_addr, by_addr,
	    penalty)) == NULL) {
		/* penalty didn't previously exist */
		якщо (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		якщо (RB_INSERT(penalties_by_expiry, by_expiry, penalty) != NULL)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		якщо (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		повернути;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	якщо (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	якщо (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	якщо (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	free(penalty);
	penalty = NULL;
	/* Re-insert into expiry tree */
	якщо (RB_INSERT(penalties_by_expiry, by_expiry, existing) != NULL)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

static void
srclimit_penalty_info_for_tree(const char *t,
    struct penalties_by_expiry *by_expiry, size_t npenalties)
{
	struct penalty *p = NULL;
	ціле bits;
	char s[NI_MAXHOST + 4];
	double now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, sizeof(s));
		якщо (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		інакше {
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
