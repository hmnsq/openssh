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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/tree.h>

#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "addr.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "srclimit.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "match.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ max_children, max_persource, ipv4_masklen, ipv6_masklen;
ಸ್ಥಿರ ಸಂರಚನಾ per_source_penalty penalty_cfg;
ಸ್ಥಿರ ವರ್ಣ *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ಸ್ಥಿರ ಸಂರಚನಾ child_info {
	ಪೂರ್ಣಾಙ್ಕ id;
	ಸಂರಚನಾ xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ಸಂರಚನಾ penalty {
	ಸಂರಚನಾ xaddr addr;
	ದ್ವಿಗುಣ expiry;
	ಪೂರ್ಣಾಙ್ಕ active;
	ಧ್ರುವ ವರ್ಣ *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ penalty_addr_cmp(ಸಂರಚನಾ penalty *a, ಸಂರಚನಾ penalty *b);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ penalty_expiry_cmp(ಸಂರಚನಾ penalty *a, ಸಂರಚನಾ penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ಸ್ಥಿರ size_t npenalties4, npenalties6;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
srclimit_mask_addr(ಧ್ರುವ ಸಂರಚನಾ xaddr *addr, ಪೂರ್ಣಾಙ್ಕ bits, ಸಂರಚನಾ xaddr *masked)
{
	ಸಂರಚನಾ xaddr xmask;

	/* Mask address off address to desired size. */
	ಯದಿ (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
srclimit_peer_addr(ಪೂರ್ಣಾಙ್ಕ sock, ಸಂರಚನಾ xaddr *addr)
{
	ಸಂರಚನಾ sockaddr_storage storage;
	socklen_t addrlen = ಪರಿಮಾಣ(storage);
	ಸಂರಚನಾ sockaddr *sa = (ಸಂರಚನಾ sockaddr *)&storage;

	ಯದಿ (getpeername(sock, sa, &addrlen) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;	/* not remote socket? */
	ಯದಿ (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;	/* unknown address family? */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
srclimit_init(ಪೂರ್ಣಾಙ್ಕ max, ಪೂರ್ಣಾಙ್ಕ persource, ಪೂರ್ಣಾಙ್ಕ ipv4len, ಪೂರ್ಣಾಙ್ಕ ipv6len,
    ಸಂರಚನಾ per_source_penalty *penalty_conf, ಧ್ರುವ ವರ್ಣ *penalty_exempt_conf)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ಯದಿ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ರಿಕ್ತ ?
	    ರಿಕ್ತ : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ಯದಿ (max_persource == INT_MAX)	/* no limit */
		ಪ್ರತ್ಯಾಗಮ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ಯದಿ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, ಪರಿಮಾಣ(*children));
	ಪ್ರತಿ (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
ಪೂರ್ಣಾಙ್ಕ
srclimit_check_allow(ಪೂರ್ಣಾಙ್ಕ sock, ಪೂರ್ಣಾಙ್ಕ id)
{
	ಸಂರಚನಾ xaddr xa, xb;
	ಪೂರ್ಣಾಙ್ಕ i, bits, first_unused, ಎಣಿಕೆ = 0;
	ವರ್ಣ xas[NI_MAXHOST];

	ಯದಿ (max_persource == INT_MAX)	/* no limit */
		ಪ್ರತ್ಯಾಗಮ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ಯದಿ (srclimit_peer_addr(sock, &xa) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ಯದಿ (srclimit_mask_addr(&xa, bits, &xb) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	ಪ್ರತಿ (i = 0; i < max_children; i++) {
		ಯದಿ (children[i].id == -1) {
			ಯದಿ (i < first_unused)
				first_unused = i;
		} ಅನ್ಯಥಾ ಯದಿ (addr_cmp(&children[i].addr, &xb) == 0) {
			ಎಣಿಕೆ++;
		}
	}
	ಯದಿ (addr_ntop(&xa, xas, ಪರಿಮಾಣ(xas)) != 0) {
		debug3_f("addr ntop failed");
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, ಎಣಿಕೆ, max_persource);

	ಯದಿ (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ಯದಿ (ಎಣಿಕೆ >= max_persource)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, ಪರಿಮಾಣ(xb));
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಶೂನ್ಯ
srclimit_done(ಪೂರ್ಣಾಙ್ಕ id)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (max_persource == INT_MAX)	/* no limit */
		ಪ್ರತ್ಯಾಗಮ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	ಪ್ರತಿ (i = 0; i < max_children; i++) {
		ಯದಿ (children[i].id == id) {
			children[i].id = -1;
			ಪ್ರತ್ಯಾಗಮ;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
penalty_addr_cmp(ಸಂರಚನಾ penalty *a, ಸಂರಚನಾ penalty *b)
{
	ಪ್ರತ್ಯಾಗಮ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
penalty_expiry_cmp(ಸಂರಚನಾ penalty *a, ಸಂರಚನಾ penalty *b)
{
	ಯದಿ (a->expiry != b->expiry)
		ಪ್ರತ್ಯಾಗಮ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ಪ್ರತ್ಯಾಗಮ addr_cmp(&a->addr, &b->addr);
}

ಸ್ಥಿರ ಶೂನ್ಯ
expire_penalties_from_ವೃಕ್ಷ(ದ್ವಿಗುಣ now, ಧ್ರುವ ವರ್ಣ *t,
    ಸಂರಚನಾ penalties_by_expiry *by_expiry,
    ಸಂರಚನಾ penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	ಸಂರಚನಾ penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		ಯದಿ (penalty->expiry >= now)
			ಭಙ್ಗ;
		ಯದಿ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		ಮುಕ್ತ(penalty);
		ಯದಿ ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
expire_penalties(ದ್ವಿಗುಣ now)
{
	expire_penalties_from_ವೃಕ್ಷ(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_ವೃಕ್ಷ(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

ಸ್ಥಿರ ಶೂನ್ಯ
addr_masklen_ntop(ಸಂರಚನಾ xaddr *addr, ಪೂರ್ಣಾಙ್ಕ masklen, ವರ್ಣ *s, size_t slen)
{
	size_t o;

	ಯದಿ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

ಪೂರ್ಣಾಙ್ಕ
srclimit_penalty_check_allow(ಪೂರ್ಣಾಙ್ಕ sock, ಧ್ರುವ ವರ್ಣ **reason)
{
	ಸಂರಚನಾ xaddr addr;
	ಸಂರಚನಾ penalty find, *penalty;
	ದ್ವಿಗುಣ now;
	ಪೂರ್ಣಾಙ್ಕ bits, max_sources, overflow_mode;
	ವರ್ಣ addr_s[NI_MAXHOST];
	ಸಂರಚನಾ penalties_by_addr *by_addr;
	size_t npenalties;

	ಯದಿ (!penalty_cfg.enabled)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (srclimit_peer_addr(sock, &addr) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (penalty_exempt != ರಿಕ್ತ) {
		ಯದಿ (addr_ntop(&addr, addr_s, ಪರಿಮಾಣ(addr_s)) != 0)
			ಪ್ರತ್ಯಾಗಮ 1; /* shouldn't happen */
		ಯದಿ (addr_match_list(addr_s, penalty_exempt) == 1) {
			ಪ್ರತ್ಯಾಗಮ 1;
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
	ಯದಿ (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, ಪರಿಮಾಣ(find));
	ಯದಿ (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1; /* no penalty */
	ಯದಿ (penalty->expiry < now) {
		expire_penalties(now);
		ಪ್ರತ್ಯಾಗಮ 1; /* expired penalty */
	}
	ಯದಿ (!penalty->active)
		ಪ್ರತ್ಯಾಗಮ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
srclimit_early_expire_penalties_from_ವೃಕ್ಷ(ಧ್ರುವ ವರ್ಣ *t,
    ಸಂರಚನಾ penalties_by_expiry *by_expiry,
    ಸಂರಚನಾ penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	ಸಂರಚನಾ penalty *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ bits;
	ವರ್ಣ s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ಯಾವತ್ (*npenaltiesp > max_sources) {
		ಯದಿ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ರಿಕ್ತ)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, ಪರಿಮಾಣ(s));
		debug3_f("%s overflow, remove %s", t, s);
		ಯದಿ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		ಮುಕ್ತ(p);
		(*npenaltiesp)--;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
srclimit_early_expire_penalties(ಶೂನ್ಯ)
{
	srclimit_early_expire_penalties_from_ವೃಕ್ಷ("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_ವೃಕ್ಷ("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

ಶೂನ್ಯ
srclimit_penalise(ಸಂರಚನಾ xaddr *addr, ಪೂರ್ಣಾಙ್ಕ penalty_type)
{
	ಸಂರಚನಾ xaddr masked;
	ಸಂರಚನಾ penalty *penalty = ರಿಕ್ತ, *existing = ರಿಕ್ತ;
	ದ್ವಿಗುಣ now;
	ಪೂರ್ಣಾಙ್ಕ bits, max_sources = 0, overflow_mode;
	ದ್ವಿಗುಣ penalty_secs;
	ವರ್ಣ addrnetmask[NI_MAXHOST + 4];
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ, *t;
	size_t *npenaltiesp = ರಿಕ್ತ;
	ಸಂರಚನಾ penalties_by_addr *by_addr = ರಿಕ್ತ;
	ಸಂರಚನಾ penalties_by_expiry *by_expiry = ರಿಕ್ತ;

	ಯದಿ (!penalty_cfg.enabled)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (penalty_exempt != ರಿಕ್ತ) {
		ಯದಿ (addr_ntop(addr, addrnetmask, ಪರಿಮಾಣ(addrnetmask)) != 0)
			ಪ್ರತ್ಯಾಗಮ; /* shouldn't happen */
		ಯದಿ (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ಪ್ರತ್ಯಾಗಮ;
		}
	}

	ವಿಕಲ್ಪ (penalty_type) {
	ಪಕ್ಷ SRCLIMIT_PENALTY_NONE:
		ಪ್ರತ್ಯಾಗಮ;
	ಪಕ್ಷ SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		ಭಙ್ಗ;
	ಪಕ್ಷ SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		ಭಙ್ಗ;
	ಪಕ್ಷ SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		ಭಙ್ಗ;
	ಪಕ್ಷ SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		ಭಙ್ಗ;
	ಪಕ್ಷ SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		ಭಙ್ಗ;
	ಪಕ್ಷ SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	ಯದಿ (penalty_secs <= 0)
		ಪ್ರತ್ಯಾಗಮ;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ಯದಿ (srclimit_mask_addr(addr, bits, &masked) != 0)
		ಪ್ರತ್ಯಾಗಮ;
	addr_masklen_ntop(addr, bits, addrnetmask, ಪರಿಮಾಣ(addrnetmask));

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
	ಯದಿ (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ಪ್ರತ್ಯಾಗಮ;
	}

	penalty = xcalloc(1, ಪರಿಮಾಣ(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ಯದಿ ((existing = RB_ಸೇರಿಸು(penalties_by_addr, by_addr,
	    penalty)) == ರಿಕ್ತ) {
		/* penalty didn't previously exist */
		ಯದಿ (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		ಯದಿ (RB_ಸೇರಿಸು(penalties_by_expiry, by_expiry, penalty) != ರಿಕ್ತ)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		ಯದಿ (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ಪ್ರತ್ಯಾಗಮ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ಯದಿ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ಯದಿ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ಯದಿ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	ಮುಕ್ತ(penalty);
	penalty = ರಿಕ್ತ;
	/* Re-insert into expiry tree */
	ಯದಿ (RB_ಸೇರಿಸು(penalties_by_expiry, by_expiry, existing) != ರಿಕ್ತ)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ಸ್ಥಿರ ಶೂನ್ಯ
srclimit_penalty_info_for_ವೃಕ್ಷ(ಧ್ರುವ ವರ್ಣ *t,
    ಸಂರಚನಾ penalties_by_expiry *by_expiry, size_t npenalties)
{
	ಸಂರಚನಾ penalty *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ bits;
	ವರ್ಣ s[NI_MAXHOST + 4];
	ದ್ವಿಗುಣ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, ಪರಿಮಾಣ(s));
		ಯದಿ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ಅನ್ಯಥಾ {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

ಶೂನ್ಯ
srclimit_penalty_info(ಶೂನ್ಯ)
{
	srclimit_penalty_info_for_ವೃಕ್ಷ("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_ವೃಕ್ಷ("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
