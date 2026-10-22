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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/tree.h>

#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "addr.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "srclimit.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "match.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ max_children, max_persource, ipv4_masklen, ipv6_masklen;
സ്ഥിതം ഘടന per_source_penalty penalty_cfg;
സ്ഥിതം അക്ഷരം *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
സ്ഥിതം ഘടന child_info {
	പൂർണ്ണസംഖ്യ id;
	ഘടന xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ഘടന penalty {
	ഘടന xaddr addr;
	ഇരട്ട expiry;
	പൂർണ്ണസംഖ്യ active;
	സ്ഥിരം അക്ഷരം *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
സ്ഥിതം പൂർണ്ണസംഖ്യ penalty_addr_cmp(ഘടന penalty *a, ഘടന penalty *b);
സ്ഥിതം പൂർണ്ണസംഖ്യ penalty_expiry_cmp(ഘടന penalty *a, ഘടന penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
സ്ഥിതം size_t npenalties4, npenalties6;

സ്ഥിതം പൂർണ്ണസംഖ്യ
srclimit_mask_addr(സ്ഥിരം ഘടന xaddr *addr, പൂർണ്ണസംഖ്യ bits, ഘടന xaddr *masked)
{
	ഘടന xaddr xmask;

	/* Mask address off address to desired size. */
	എങ്കിൽ (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		തിരികെ -1;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
srclimit_peer_addr(പൂർണ്ണസംഖ്യ sock, ഘടന xaddr *addr)
{
	ഘടന sockaddr_storage storage;
	socklen_t addrlen = വലുപ്പം(storage);
	ഘടന sockaddr *sa = (ഘടന sockaddr *)&storage;

	എങ്കിൽ (getpeername(sock, sa, &addrlen) != 0)
		തിരികെ 1;	/* not remote socket? */
	എങ്കിൽ (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		തിരികെ 1;	/* unknown address family? */
	തിരികെ 0;
}

ശൂന്യം
srclimit_init(പൂർണ്ണസംഖ്യ max, പൂർണ്ണസംഖ്യ persource, പൂർണ്ണസംഖ്യ ipv4len, പൂർണ്ണസംഖ്യ ipv6len,
    ഘടന per_source_penalty *penalty_conf, സ്ഥിരം അക്ഷരം *penalty_exempt_conf)
{
	പൂർണ്ണസംഖ്യ i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	എങ്കിൽ (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ശൂന്യ ?
	    ശൂന്യ : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	എങ്കിൽ (max_persource == INT_MAX)	/* no limit */
		തിരികെ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	എങ്കിൽ (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, വലുപ്പം(*children));
	വേണ്ടി (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
പൂർണ്ണസംഖ്യ
srclimit_check_allow(പൂർണ്ണസംഖ്യ sock, പൂർണ്ണസംഖ്യ id)
{
	ഘടന xaddr xa, xb;
	പൂർണ്ണസംഖ്യ i, bits, first_unused, എണ്ണം = 0;
	അക്ഷരം xas[NI_MAXHOST];

	എങ്കിൽ (max_persource == INT_MAX)	/* no limit */
		തിരികെ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	എങ്കിൽ (srclimit_peer_addr(sock, &xa) != 0)
		തിരികെ 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	എങ്കിൽ (srclimit_mask_addr(&xa, bits, &xb) != 0)
		തിരികെ 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	വേണ്ടി (i = 0; i < max_children; i++) {
		എങ്കിൽ (children[i].id == -1) {
			എങ്കിൽ (i < first_unused)
				first_unused = i;
		} അല്ലെങ്കിൽ എങ്കിൽ (addr_cmp(&children[i].addr, &xb) == 0) {
			എണ്ണം++;
		}
	}
	എങ്കിൽ (addr_ntop(&xa, xas, വലുപ്പം(xas)) != 0) {
		debug3_f("addr ntop failed");
		തിരികെ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, എണ്ണം, max_persource);

	എങ്കിൽ (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		തിരികെ 0;
	}
	എങ്കിൽ (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	എങ്കിൽ (എണ്ണം >= max_persource)
		തിരികെ 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, വലുപ്പം(xb));
	തിരികെ 1;
}

ശൂന്യം
srclimit_done(പൂർണ്ണസംഖ്യ id)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (max_persource == INT_MAX)	/* no limit */
		തിരികെ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	വേണ്ടി (i = 0; i < max_children; i++) {
		എങ്കിൽ (children[i].id == id) {
			children[i].id = -1;
			തിരികെ;
		}
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
penalty_addr_cmp(ഘടന penalty *a, ഘടന penalty *b)
{
	തിരികെ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
penalty_expiry_cmp(ഘടന penalty *a, ഘടന penalty *b)
{
	എങ്കിൽ (a->expiry != b->expiry)
		തിരികെ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	തിരികെ addr_cmp(&a->addr, &b->addr);
}

സ്ഥിതം ശൂന്യം
expire_penalties_from_വൃക്ഷം(ഇരട്ട now, സ്ഥിരം അക്ഷരം *t,
    ഘടന penalties_by_expiry *by_expiry,
    ഘടന penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	ഘടന penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		എങ്കിൽ (penalty->expiry >= now)
			നിർത്തുക;
		എങ്കിൽ (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		സ്വതന്ത്രം(penalty);
		എങ്കിൽ ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

സ്ഥിതം ശൂന്യം
expire_penalties(ഇരട്ട now)
{
	expire_penalties_from_വൃക്ഷം(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_വൃക്ഷം(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

സ്ഥിതം ശൂന്യം
addr_masklen_ntop(ഘടന xaddr *addr, പൂർണ്ണസംഖ്യ masklen, അക്ഷരം *s, size_t slen)
{
	size_t o;

	എങ്കിൽ (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		തിരികെ;
	}
	എങ്കിൽ ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

പൂർണ്ണസംഖ്യ
srclimit_penalty_check_allow(പൂർണ്ണസംഖ്യ sock, സ്ഥിരം അക്ഷരം **reason)
{
	ഘടന xaddr addr;
	ഘടന penalty find, *penalty;
	ഇരട്ട now;
	പൂർണ്ണസംഖ്യ bits, max_sources, overflow_mode;
	അക്ഷരം addr_s[NI_MAXHOST];
	ഘടന penalties_by_addr *by_addr;
	size_t npenalties;

	എങ്കിൽ (!penalty_cfg.enabled)
		തിരികെ 1;
	എങ്കിൽ (srclimit_peer_addr(sock, &addr) != 0)
		തിരികെ 1;
	എങ്കിൽ (penalty_exempt != ശൂന്യ) {
		എങ്കിൽ (addr_ntop(&addr, addr_s, വലുപ്പം(addr_s)) != 0)
			തിരികെ 1; /* shouldn't happen */
		എങ്കിൽ (addr_match_list(addr_s, penalty_exempt) == 1) {
			തിരികെ 1;
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
	എങ്കിൽ (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		തിരികെ 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, വലുപ്പം(find));
	എങ്കിൽ (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		തിരികെ 1;
	എങ്കിൽ ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == ശൂന്യ)
		തിരികെ 1; /* no penalty */
	എങ്കിൽ (penalty->expiry < now) {
		expire_penalties(now);
		തിരികെ 1; /* expired penalty */
	}
	എങ്കിൽ (!penalty->active)
		തിരികെ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
srclimit_early_expire_penalties_from_വൃക്ഷം(സ്ഥിരം അക്ഷരം *t,
    ഘടന penalties_by_expiry *by_expiry,
    ഘടന penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	ഘടന penalty *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ bits;
	അക്ഷരം s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ആകുമ്പോൾ (*npenaltiesp > max_sources) {
		എങ്കിൽ ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ശൂന്യ)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, വലുപ്പം(s));
		debug3_f("%s overflow, remove %s", t, s);
		എങ്കിൽ (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		സ്വതന്ത്രം(p);
		(*npenaltiesp)--;
	}
}

സ്ഥിതം ശൂന്യം
srclimit_early_expire_penalties(ശൂന്യം)
{
	srclimit_early_expire_penalties_from_വൃക്ഷം("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_വൃക്ഷം("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

ശൂന്യം
srclimit_penalise(ഘടന xaddr *addr, പൂർണ്ണസംഖ്യ penalty_type)
{
	ഘടന xaddr masked;
	ഘടന penalty *penalty = ശൂന്യ, *existing = ശൂന്യ;
	ഇരട്ട now;
	പൂർണ്ണസംഖ്യ bits, max_sources = 0, overflow_mode;
	ഇരട്ട penalty_secs;
	അക്ഷരം addrnetmask[NI_MAXHOST + 4];
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ, *t;
	size_t *npenaltiesp = ശൂന്യ;
	ഘടന penalties_by_addr *by_addr = ശൂന്യ;
	ഘടന penalties_by_expiry *by_expiry = ശൂന്യ;

	എങ്കിൽ (!penalty_cfg.enabled)
		തിരികെ;
	എങ്കിൽ (penalty_exempt != ശൂന്യ) {
		എങ്കിൽ (addr_ntop(addr, addrnetmask, വലുപ്പം(addrnetmask)) != 0)
			തിരികെ; /* shouldn't happen */
		എങ്കിൽ (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			തിരികെ;
		}
	}

	തിരഞ്ഞെടുപ്പ് (penalty_type) {
	അവസ്ഥ SRCLIMIT_PENALTY_NONE:
		തിരികെ;
	അവസ്ഥ SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		നിർത്തുക;
	അവസ്ഥ SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		നിർത്തുക;
	അവസ്ഥ SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		നിർത്തുക;
	അവസ്ഥ SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		നിർത്തുക;
	അവസ്ഥ SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		നിർത്തുക;
	അവസ്ഥ SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	എങ്കിൽ (penalty_secs <= 0)
		തിരികെ;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	എങ്കിൽ (srclimit_mask_addr(addr, bits, &masked) != 0)
		തിരികെ;
	addr_masklen_ntop(addr, bits, addrnetmask, വലുപ്പം(addrnetmask));

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
	എങ്കിൽ (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		തിരികെ;
	}

	penalty = xcalloc(1, വലുപ്പം(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	എങ്കിൽ ((existing = RB_തിരുകുക(penalties_by_addr, by_addr,
	    penalty)) == ശൂന്യ) {
		/* penalty didn't previously exist */
		എങ്കിൽ (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		എങ്കിൽ (RB_തിരുകുക(penalties_by_expiry, by_expiry, penalty) != ശൂന്യ)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		എങ്കിൽ (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		തിരികെ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	എങ്കിൽ (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	എങ്കിൽ (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	എങ്കിൽ (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	സ്വതന്ത്രം(penalty);
	penalty = ശൂന്യ;
	/* Re-insert into expiry tree */
	എങ്കിൽ (RB_തിരുകുക(penalties_by_expiry, by_expiry, existing) != ശൂന്യ)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

സ്ഥിതം ശൂന്യം
srclimit_penalty_info_for_വൃക്ഷം(സ്ഥിരം അക്ഷരം *t,
    ഘടന penalties_by_expiry *by_expiry, size_t npenalties)
{
	ഘടന penalty *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ bits;
	അക്ഷരം s[NI_MAXHOST + 4];
	ഇരട്ട now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, വലുപ്പം(s));
		എങ്കിൽ (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		അല്ലെങ്കിൽ {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

ശൂന്യം
srclimit_penalty_info(ശൂന്യം)
{
	srclimit_penalty_info_for_വൃക്ഷം("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_വൃക്ഷം("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
