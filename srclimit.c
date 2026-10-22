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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ max_children, max_persource, ipv4_masklen, ipv6_masklen;
ಸ್ಥಿರ ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty penalty_cfg;
ಸ್ಥಿರ ಅಕ್ಷರ *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ಸ್ಥಿರ ರಚನೆ ಮಗು_info {
	ಪೂರ್ಣಾಂಕ id;
	ರಚನೆ xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ರಚನೆ penalty {
	ರಚನೆ xaddr addr;
	ದ್ವಿಗುಣ expiry;
	ಪೂರ್ಣಾಂಕ ಸಕ್ರಿಯ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason;
	RB_ನಮೂದು(penalty) by_addr;
	RB_ನಮೂದು(penalty) by_expiry;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ penalty_addr_cmp(ರಚನೆ penalty *a, ರಚನೆ penalty *b);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ penalty_expiry_cmp(ರಚನೆ penalty *a, ರಚನೆ penalty *b);
RB_ತಲೆ(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_ತಲೆ(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ಸ್ಥಿರ ಗಾತ್ರ_t npenalties4, npenalties6;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
srclimit_ಮುಖವಾಡ_addr(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *addr, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು, ರಚನೆ xaddr *masked)
{
	ರಚನೆ xaddr xmask;

	/* Mask address off address to desired size. */
	ಆದರೆ (addr_netmask(addr->af, ಬಿಟ್ಟುಗಳು, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, ಬಿಟ್ಟುಗಳು);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
srclimit_peer_addr(ಪೂರ್ಣಾಂಕ sock, ರಚನೆ xaddr *addr)
{
	ರಚನೆ sockaddr_storage storage;
	socklen_t addrlen = ಗಾತ್ರ(storage);
	ರಚನೆ sockaddr *sa = (ರಚನೆ sockaddr *)&storage;

	ಆದರೆ (getpeername(sock, sa, &addrlen) != 0)
		ಹಿಂತಿರುಗಿ 1;	/* not remote socket? */
	ಆದರೆ (addr_sa_ಗಮ್ಯ_xaddr(sa, addrlen, addr) != 0)
		ಹಿಂತಿರುಗಿ 1;	/* unknown address family? */
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
srclimit_init(ಪೂರ್ಣಾಂಕ max, ಪೂರ್ಣಾಂಕ persource, ಪೂರ್ಣಾಂಕ ipv4len, ಪೂರ್ಣಾಂಕ ipv6len,
    ರಚನೆ ಪ್ರತಿ_ಮೂಲ_penalty *penalty_conf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *penalty_exempt_conf)
{
	ಪೂರ್ಣಾಂಕ i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ಆದರೆ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ಖಾಲಿ ?
	    ಖಾಲಿ : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ಆದರೆ (max_persource == ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)	/* no limit */
		ಹಿಂತಿರುಗಿ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ಆದರೆ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, ಗಾತ್ರ(*children));
	ಗಾಗಿ (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
ಪೂರ್ಣಾಂಕ
srclimit_check_allow(ಪೂರ್ಣಾಂಕ sock, ಪೂರ್ಣಾಂಕ id)
{
	ರಚನೆ xaddr xa, xb;
	ಪೂರ್ಣಾಂಕ i, ಬಿಟ್ಟುಗಳು, ಮೊದಲ_ಬಳಸದ, ಎಣಿಕೆ_2 = 0;
	ಅಕ್ಷರ xas[NI_MAXHOST];

	ಆದರೆ (max_persource == ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)	/* no limit */
		ಹಿಂತಿರುಗಿ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ಆದರೆ (srclimit_peer_addr(sock, &xa) != 0)
		ಹಿಂತಿರುಗಿ 1;
	ಬಿಟ್ಟುಗಳು = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ಆದರೆ (srclimit_ಮುಖವಾಡ_addr(&xa, ಬಿಟ್ಟುಗಳು, &xb) != 0)
		ಹಿಂತಿರುಗಿ 1;

	ಮೊದಲ_ಬಳಸದ = max_children;
	/* Count matching entries and find first unused one. */
	ಗಾಗಿ (i = 0; i < max_children; i++) {
		ಆದರೆ (children[i].id == -1) {
			ಆದರೆ (i < ಮೊದಲ_ಬಳಸದ)
				ಮೊದಲ_ಬಳಸದ = i;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (addr_cmp(&children[i].addr, &xb) == 0) {
			ಎಣಿಕೆ_2++;
		}
	}
	ಆದರೆ (addr_ntop(&xa, xas, ಗಾತ್ರ(xas)) != 0) {
		debug3_f("addr ntop failed");
		ಹಿಂತಿರುಗಿ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, ಬಿಟ್ಟುಗಳು, ಎಣಿಕೆ_2, max_persource);

	ಆದರೆ (ಮೊದಲ_ಬಳಸದ == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (ಮೊದಲ_ಬಳಸದ < 0 || ಮೊದಲ_ಬಳಸದ >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ಆದರೆ (ಎಣಿಕೆ_2 >= max_persource)
		ಹಿಂತಿರುಗಿ 0;

	/* Connection allowed, store masked address. */
	children[ಮೊದಲ_ಬಳಸದ].id = id;
	ಸ್ಮರಣೆ_ನಕಲು(&children[ಮೊದಲ_ಬಳಸದ].addr, &xb, ಗಾತ್ರ(xb));
	ಹಿಂತಿರುಗಿ 1;
}

ಶೂನ್ಯ
srclimit_ಮುಗಿದ(ಪೂರ್ಣಾಂಕ id)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (max_persource == ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)	/* no limit */
		ಹಿಂತಿರುಗಿ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	ಗಾಗಿ (i = 0; i < max_children; i++) {
		ಆದರೆ (children[i].id == id) {
			children[i].id = -1;
			ಹಿಂತಿರುಗಿ;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
penalty_addr_cmp(ರಚನೆ penalty *a, ರಚನೆ penalty *b)
{
	ಹಿಂತಿರುಗಿ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
penalty_expiry_cmp(ರಚನೆ penalty *a, ರಚನೆ penalty *b)
{
	ಆದರೆ (a->expiry != b->expiry)
		ಹಿಂತಿರುಗಿ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ಹಿಂತಿರುಗಿ addr_cmp(&a->addr, &b->addr);
}

ಸ್ಥಿರ ಶೂನ್ಯ
expire_penalties_from_ವೃಕ್ಷ(ದ್ವಿಗುಣ now, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *t,
    ರಚನೆ penalties_by_expiry *by_expiry,
    ರಚನೆ penalties_by_addr *by_addr, ಗಾತ್ರ_t *npenaltiesp)
{
	ರಚನೆ penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_ಸುರಕ್ಷಿತ(penalty, penalties_by_expiry, by_expiry, tmp) {
		ಆದರೆ (penalty->expiry >= now)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		ಬಿಡುಗಡೆ(penalty);
		ಆದರೆ ((*npenaltiesp)-- == 0)
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
addr_masklen_ntop(ರಚನೆ xaddr *addr, ಪೂರ್ಣಾಂಕ masklen, ಅಕ್ಷರ *s, ಗಾತ್ರ_t slen)
{
	ಗಾತ್ರ_t o;

	ಆದರೆ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((o = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

ಪೂರ್ಣಾಂಕ
srclimit_penalty_check_allow(ಪೂರ್ಣಾಂಕ sock, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **reason)
{
	ರಚನೆ xaddr addr;
	ರಚನೆ penalty ಕಂಡುಹಿಡಿ, *penalty;
	ದ್ವಿಗುಣ now;
	ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು, max_sources, ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ;
	ಅಕ್ಷರ addr_s[NI_MAXHOST];
	ರಚನೆ penalties_by_addr *by_addr;
	ಗಾತ್ರ_t npenalties;

	ಆದರೆ (!penalty_cfg.enabled)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (srclimit_peer_addr(sock, &addr) != 0)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (penalty_exempt != ಖಾಲಿ) {
		ಆದರೆ (addr_ntop(&addr, addr_s, ಗಾತ್ರ(addr_s)) != 0)
			ಹಿಂತಿರುಗಿ 1; /* shouldn't happen */
		ಆದರೆ (addr_ಹೊಂದಿಕೆ_list(addr_s, penalty_exempt) == 1) {
			ಹಿಂತಿರುಗಿ 1;
		}
	}
	now = monotime_double();
	expire_penalties(now);
	by_addr = addr.af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr.af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ = addr.af == AF_INET ?
	    penalty_cfg.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ : penalty_cfg.ಅತಿಪ್ರವಾಹ_mode6;
	npenalties = addr.af == AF_INET ?  npenalties4 : npenalties6;
	ಆದರೆ (npenalties >= (ಗಾತ್ರ_t)max_sources &&
	    ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ == ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL) {
		*reason = "too many penalised addresses";
		ಹಿಂತಿರುಗಿ 0;
	}
	ಬಿಟ್ಟುಗಳು = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&ಕಂಡುಹಿಡಿ, 0, ಗಾತ್ರ(ಕಂಡುಹಿಡಿ));
	ಆದರೆ (srclimit_ಮುಖವಾಡ_addr(&addr, ಬಿಟ್ಟುಗಳು, &ಕಂಡುಹಿಡಿ.addr) != 0)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ ((penalty = RB_ಕಂಡುಹಿಡಿ(penalties_by_addr, by_addr, &ಕಂಡುಹಿಡಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1; /* no penalty */
	ಆದರೆ (penalty->expiry < now) {
		expire_penalties(now);
		ಹಿಂತಿರುಗಿ 1; /* expired penalty */
	}
	ಆದರೆ (!penalty->ಸಕ್ರಿಯ)
		ಹಿಂತಿರುಗಿ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
srclimit_early_expire_penalties_from_ವೃಕ್ಷ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *t,
    ರಚನೆ penalties_by_expiry *by_expiry,
    ರಚನೆ penalties_by_addr *by_addr, ಗಾತ್ರ_t *npenaltiesp, ಗಾತ್ರ_t max_sources)
{
	ರಚನೆ penalty *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು;
	ಅಕ್ಷರ s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ಆಗ (*npenaltiesp > max_sources) {
		ಆದರೆ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ಖಾಲಿ)
			fatal_f("internal error: %s table corrupt (find)", t);
		ಬಿಟ್ಟುಗಳು = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, ಬಿಟ್ಟುಗಳು, s, ಗಾತ್ರ(s));
		debug3_f("%s overflow, remove %s", t, s);
		ಆದರೆ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		ಬಿಡುಗಡೆ(p);
		(*npenaltiesp)--;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
srclimit_early_expire_penalties(ಶೂನ್ಯ)
{
	srclimit_early_expire_penalties_from_ವೃಕ್ಷ("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (ಗಾತ್ರ_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_ವೃಕ್ಷ("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (ಗಾತ್ರ_t)penalty_cfg.max_sources6);
}

ಶೂನ್ಯ
srclimit_penalise(ರಚನೆ xaddr *addr, ಪೂರ್ಣಾಂಕ penalty_type)
{
	ರಚನೆ xaddr masked;
	ರಚನೆ penalty *penalty = ಖಾಲಿ, *existing = ಖಾಲಿ;
	ದ್ವಿಗುಣ now;
	ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು, max_sources = 0, ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ;
	ದ್ವಿಗುಣ penalty_secs;
	ಅಕ್ಷರ addrnetmask[NI_MAXHOST + 4];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ, *t;
	ಗಾತ್ರ_t *npenaltiesp = ಖಾಲಿ;
	ರಚನೆ penalties_by_addr *by_addr = ಖಾಲಿ;
	ರಚನೆ penalties_by_expiry *by_expiry = ಖಾಲಿ;

	ಆದರೆ (!penalty_cfg.enabled)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (penalty_exempt != ಖಾಲಿ) {
		ಆದರೆ (addr_ntop(addr, addrnetmask, ಗಾತ್ರ(addrnetmask)) != 0)
			ಹಿಂತಿರುಗಿ; /* shouldn't happen */
		ಆದರೆ (addr_ಹೊಂದಿಕೆ_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ಹಿಂತಿರುಗಿ;
		}
	}

	ಆಯ್ಕೆ (penalty_type) {
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_NONE:
		ಹಿಂತಿರುಗಿ;
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	ಆದರೆ (penalty_secs <= 0)
		ಹಿಂತಿರುಗಿ;

	ಬಿಟ್ಟುಗಳು = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ಆದರೆ (srclimit_ಮುಖವಾಡ_addr(addr, ಬಿಟ್ಟುಗಳು, &masked) != 0)
		ಹಿಂತಿರುಗಿ;
	addr_masklen_ntop(addr, ಬಿಟ್ಟುಗಳು, addrnetmask, ಗಾತ್ರ(addrnetmask));

	now = monotime_double();
	expire_penalties(now);
	by_expiry = addr->af == AF_INET ?
	    &penalties_by_expiry4 : &penalties_by_expiry6;
	by_addr = addr->af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr->af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ = addr->af == AF_INET ?
	    penalty_cfg.ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ : penalty_cfg.ಅತಿಪ್ರವಾಹ_mode6;
	npenaltiesp = addr->af == AF_INET ?  &npenalties4 : &npenalties6;
	t = addr->af == AF_INET ? "ipv4" : "ipv6";
	ಆದರೆ (*npenaltiesp >= (ಗಾತ್ರ_t)max_sources &&
	    ಅತಿಪ್ರವಾಹ_ಬಹುಲಕ == ಪ್ರತಿ_ಮೂಲ_PENALTY_ಅತಿಪ್ರವಾಹ_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ಹಿಂತಿರುಗಿ;
	}

	penalty = xcalloc(1, ಗಾತ್ರ(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ಆದರೆ ((existing = RB_ಸೇರಿಸು(penalties_by_addr, by_addr,
	    penalty)) == ಖಾಲಿ) {
		/* penalty didn't previously exist */
		ಆದರೆ (penalty_secs > penalty_cfg.penalty_min)
			penalty->ಸಕ್ರಿಯ = 1;
		ಆದರೆ (RB_ಸೇರಿಸು(penalties_by_expiry, by_expiry, penalty) != ಖಾಲಿ)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->ಸಕ್ರಿಯ ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->ಸಕ್ರಿಯ ? "active" : "deferred",
		    penalty_secs, reason);
		ಆದರೆ (++(*npenaltiesp) > (ಗಾತ್ರ_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ಹಿಂತಿರುಗಿ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->ಸಕ್ರಿಯ ? "active" : "inactive", t,
	    addrnetmask, (ದೀರ್ಘ ದೀರ್ಘ)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ಆದರೆ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ಆದರೆ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ಆದರೆ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->ಸಕ್ರಿಯ) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->ಸಕ್ರಿಯ = 1;
	}
	existing->reason = penalty->reason;
	ಬಿಡುಗಡೆ(penalty);
	penalty = ಖಾಲಿ;
	/* Re-insert into expiry tree */
	ಆದರೆ (RB_ಸೇರಿಸು(penalties_by_expiry, by_expiry, existing) != ಖಾಲಿ)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ಸ್ಥಿರ ಶೂನ್ಯ
srclimit_penalty_info_for_ವೃಕ್ಷ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *t,
    ರಚನೆ penalties_by_expiry *by_expiry, ಗಾತ್ರ_t npenalties)
{
	ರಚನೆ penalty *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು;
	ಅಕ್ಷರ s[NI_MAXHOST + 4];
	ದ್ವಿಗುಣ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		ಬಿಟ್ಟುಗಳು = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, ಬಿಟ್ಟುಗಳು, s, ಗಾತ್ರ(s));
		ಆದರೆ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ಇಲ್ಲದಿದ್ದರೆ {
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
