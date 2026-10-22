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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/tree.h>

#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "addr.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "srclimit.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "match.h"

સ્થિર પૂર્ણાંક max_children, max_persource, ipv4_masklen, ipv6_masklen;
સ્થિર સંરચના per_source_penalty penalty_cfg;
સ્થિર અક્ષર *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
સ્થિર સંરચના child_info {
	પૂર્ણાંક id;
	સંરચના xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
સંરચના penalty {
	સંરચના xaddr addr;
	દ્વિગુણ expiry;
	પૂર્ણાંક active;
	અચલ અક્ષર *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
સ્થિર પૂર્ણાંક penalty_addr_cmp(સંરચના penalty *a, સંરચના penalty *b);
સ્થિર પૂર્ણાંક penalty_expiry_cmp(સંરચના penalty *a, સંરચના penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
સ્થિર size_t npenalties4, npenalties6;

સ્થિર પૂર્ણાંક
srclimit_mask_addr(અચલ સંરચના xaddr *addr, પૂર્ણાંક bits, સંરચના xaddr *masked)
{
	સંરચના xaddr xmask;

	/* Mask address off address to desired size. */
	જો (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		પાછા -1;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
srclimit_peer_addr(પૂર્ણાંક sock, સંરચના xaddr *addr)
{
	સંરચના sockaddr_storage storage;
	socklen_t addrlen = કદ(storage);
	સંરચના sockaddr *sa = (સંરચના sockaddr *)&storage;

	જો (getpeername(sock, sa, &addrlen) != 0)
		પાછા 1;	/* not remote socket? */
	જો (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		પાછા 1;	/* unknown address family? */
	પાછા 0;
}

શૂન્ય
srclimit_init(પૂર્ણાંક max, પૂર્ણાંક persource, પૂર્ણાંક ipv4len, પૂર્ણાંક ipv6len,
    સંરચના per_source_penalty *penalty_conf, અચલ અક્ષર *penalty_exempt_conf)
{
	પૂર્ણાંક i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	જો (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ખાલી ?
	    ખાલી : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	જો (max_persource == INT_MAX)	/* no limit */
		પાછા;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	જો (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, કદ(*children));
	માટે (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
પૂર્ણાંક
srclimit_check_allow(પૂર્ણાંક sock, પૂર્ણાંક id)
{
	સંરચના xaddr xa, xb;
	પૂર્ણાંક i, bits, first_unused, ગણતરી = 0;
	અક્ષર xas[NI_MAXHOST];

	જો (max_persource == INT_MAX)	/* no limit */
		પાછા 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	જો (srclimit_peer_addr(sock, &xa) != 0)
		પાછા 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	જો (srclimit_mask_addr(&xa, bits, &xb) != 0)
		પાછા 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	માટે (i = 0; i < max_children; i++) {
		જો (children[i].id == -1) {
			જો (i < first_unused)
				first_unused = i;
		} નહીંતર જો (addr_cmp(&children[i].addr, &xb) == 0) {
			ગણતરી++;
		}
	}
	જો (addr_ntop(&xa, xas, કદ(xas)) != 0) {
		debug3_f("addr ntop failed");
		પાછા 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, ગણતરી, max_persource);

	જો (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		પાછા 0;
	}
	જો (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	જો (ગણતરી >= max_persource)
		પાછા 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, કદ(xb));
	પાછા 1;
}

શૂન્ય
srclimit_done(પૂર્ણાંક id)
{
	પૂર્ણાંક i;

	જો (max_persource == INT_MAX)	/* no limit */
		પાછા;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	માટે (i = 0; i < max_children; i++) {
		જો (children[i].id == id) {
			children[i].id = -1;
			પાછા;
		}
	}
}

સ્થિર પૂર્ણાંક
penalty_addr_cmp(સંરચના penalty *a, સંરચના penalty *b)
{
	પાછા addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

સ્થિર પૂર્ણાંક
penalty_expiry_cmp(સંરચના penalty *a, સંરચના penalty *b)
{
	જો (a->expiry != b->expiry)
		પાછા a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	પાછા addr_cmp(&a->addr, &b->addr);
}

સ્થિર શૂન્ય
expire_penalties_from_વૃક્ષ(દ્વિગુણ now, અચલ અક્ષર *t,
    સંરચના penalties_by_expiry *by_expiry,
    સંરચના penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	સંરચના penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		જો (penalty->expiry >= now)
			તોડો;
		જો (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		મુક્ત(penalty);
		જો ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

સ્થિર શૂન્ય
expire_penalties(દ્વિગુણ now)
{
	expire_penalties_from_વૃક્ષ(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_વૃક્ષ(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

સ્થિર શૂન્ય
addr_masklen_ntop(સંરચના xaddr *addr, પૂર્ણાંક masklen, અક્ષર *s, size_t slen)
{
	size_t o;

	જો (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		પાછા;
	}
	જો ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

પૂર્ણાંક
srclimit_penalty_check_allow(પૂર્ણાંક sock, અચલ અક્ષર **reason)
{
	સંરચના xaddr addr;
	સંરચના penalty find, *penalty;
	દ્વિગુણ now;
	પૂર્ણાંક bits, max_sources, overflow_mode;
	અક્ષર addr_s[NI_MAXHOST];
	સંરચના penalties_by_addr *by_addr;
	size_t npenalties;

	જો (!penalty_cfg.enabled)
		પાછા 1;
	જો (srclimit_peer_addr(sock, &addr) != 0)
		પાછા 1;
	જો (penalty_exempt != ખાલી) {
		જો (addr_ntop(&addr, addr_s, કદ(addr_s)) != 0)
			પાછા 1; /* shouldn't happen */
		જો (addr_match_list(addr_s, penalty_exempt) == 1) {
			પાછા 1;
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
	જો (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		પાછા 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, કદ(find));
	જો (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		પાછા 1;
	જો ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == ખાલી)
		પાછા 1; /* no penalty */
	જો (penalty->expiry < now) {
		expire_penalties(now);
		પાછા 1; /* expired penalty */
	}
	જો (!penalty->active)
		પાછા 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	પાછા 0;
}

સ્થિર શૂન્ય
srclimit_early_expire_penalties_from_વૃક્ષ(અચલ અક્ષર *t,
    સંરચના penalties_by_expiry *by_expiry,
    સંરચના penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	સંરચના penalty *p = ખાલી;
	પૂર્ણાંક bits;
	અક્ષર s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	જ્યારે (*npenaltiesp > max_sources) {
		જો ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ખાલી)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, કદ(s));
		debug3_f("%s overflow, remove %s", t, s);
		જો (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		મુક્ત(p);
		(*npenaltiesp)--;
	}
}

સ્થિર શૂન્ય
srclimit_early_expire_penalties(શૂન્ય)
{
	srclimit_early_expire_penalties_from_વૃક્ષ("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_વૃક્ષ("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

શૂન્ય
srclimit_penalise(સંરચના xaddr *addr, પૂર્ણાંક penalty_type)
{
	સંરચના xaddr masked;
	સંરચના penalty *penalty = ખાલી, *existing = ખાલી;
	દ્વિગુણ now;
	પૂર્ણાંક bits, max_sources = 0, overflow_mode;
	દ્વિગુણ penalty_secs;
	અક્ષર addrnetmask[NI_MAXHOST + 4];
	અચલ અક્ષર *reason = ખાલી, *t;
	size_t *npenaltiesp = ખાલી;
	સંરચના penalties_by_addr *by_addr = ખાલી;
	સંરચના penalties_by_expiry *by_expiry = ખાલી;

	જો (!penalty_cfg.enabled)
		પાછા;
	જો (penalty_exempt != ખાલી) {
		જો (addr_ntop(addr, addrnetmask, કદ(addrnetmask)) != 0)
			પાછા; /* shouldn't happen */
		જો (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			પાછા;
		}
	}

	પસંદગી (penalty_type) {
	સ્થિતિ SRCLIMIT_PENALTY_NONE:
		પાછા;
	સ્થિતિ SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		તોડો;
	સ્થિતિ SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		તોડો;
	સ્થિતિ SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		તોડો;
	સ્થિતિ SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		તોડો;
	સ્થિતિ SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		તોડો;
	સ્થિતિ SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		તોડો;
	મૂળભૂત:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	જો (penalty_secs <= 0)
		પાછા;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	જો (srclimit_mask_addr(addr, bits, &masked) != 0)
		પાછા;
	addr_masklen_ntop(addr, bits, addrnetmask, કદ(addrnetmask));

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
	જો (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		પાછા;
	}

	penalty = xcalloc(1, કદ(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	જો ((existing = RB_ઉમેરો(penalties_by_addr, by_addr,
	    penalty)) == ખાલી) {
		/* penalty didn't previously exist */
		જો (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		જો (RB_ઉમેરો(penalties_by_expiry, by_expiry, penalty) != ખાલી)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		જો (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		પાછા;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	જો (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	જો (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	જો (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	મુક્ત(penalty);
	penalty = ખાલી;
	/* Re-insert into expiry tree */
	જો (RB_ઉમેરો(penalties_by_expiry, by_expiry, existing) != ખાલી)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

સ્થિર શૂન્ય
srclimit_penalty_info_for_વૃક્ષ(અચલ અક્ષર *t,
    સંરચના penalties_by_expiry *by_expiry, size_t npenalties)
{
	સંરચના penalty *p = ખાલી;
	પૂર્ણાંક bits;
	અક્ષર s[NI_MAXHOST + 4];
	દ્વિગુણ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, કદ(s));
		જો (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		નહીંતર {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

શૂન્ય
srclimit_penalty_info(શૂન્ય)
{
	srclimit_penalty_info_for_વૃક્ષ("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_વૃક્ષ("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
