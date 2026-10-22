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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/tree.h>

#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "addr.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "srclimit.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "match.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା max_children, max_persource, ipv4_masklen, ipv6_masklen;
ସ୍ଥିର ସଂରଚନା per_source_penalty penalty_cfg;
ସ୍ଥିର ଅକ୍ଷର *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ସ୍ଥିର ସଂରଚନା child_info {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା id;
	ସଂରଚନା xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ସଂରଚନା penalty {
	ସଂରଚନା xaddr addr;
	ଦ୍ୱିଗୁଣ expiry;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା active;
	ଅଚଳ ଅକ୍ଷର *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା penalty_addr_cmp(ସଂରଚନା penalty *a, ସଂରଚନା penalty *b);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା penalty_expiry_cmp(ସଂରଚନା penalty *a, ସଂରଚନା penalty *b);
RB_HEAD(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_HEAD(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ସ୍ଥିର size_t npenalties4, npenalties6;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
srclimit_mask_addr(ଅଚଳ ସଂରଚନା xaddr *addr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits, ସଂରଚନା xaddr *masked)
{
	ସଂରଚନା xaddr xmask;

	/* Mask address off address to desired size. */
	ଯଦି (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
srclimit_peer_addr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ସଂରଚନା xaddr *addr)
{
	ସଂରଚନା sockaddr_storage storage;
	socklen_t addrlen = ଆକାର(storage);
	ସଂରଚନା sockaddr *sa = (ସଂରଚନା sockaddr *)&storage;

	ଯଦି (getpeername(sock, sa, &addrlen) != 0)
		ଫେରନ୍ତୁ 1;	/* not remote socket? */
	ଯଦି (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		ଫେରନ୍ତୁ 1;	/* unknown address family? */
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
srclimit_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା max, ପୂର୍ଣ୍ଣସଂଖ୍ୟା persource, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ipv4len, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ipv6len,
    ସଂରଚନା per_source_penalty *penalty_conf, ଅଚଳ ଅକ୍ଷର *penalty_exempt_conf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	ଯଦି (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == ଖାଲି ?
	    ଖାଲି : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	ଯଦି (max_persource == INT_MAX)	/* no limit */
		ଫେରନ୍ତୁ;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	ଯଦି (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, ଆକାର(*children));
	ପାଇଁ (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
srclimit_check_allow(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	ସଂରଚନା xaddr xa, xb;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, bits, first_unused, ଗଣନା_2 = 0;
	ଅକ୍ଷର xas[NI_MAXHOST];

	ଯଦି (max_persource == INT_MAX)	/* no limit */
		ଫେରନ୍ତୁ 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	ଯଦି (srclimit_peer_addr(sock, &xa) != 0)
		ଫେରନ୍ତୁ 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ଯଦି (srclimit_mask_addr(&xa, bits, &xb) != 0)
		ଫେରନ୍ତୁ 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	ପାଇଁ (i = 0; i < max_children; i++) {
		ଯଦି (children[i].id == -1) {
			ଯଦି (i < first_unused)
				first_unused = i;
		} ଅନ୍ୟଥା ଯଦି (addr_cmp(&children[i].addr, &xb) == 0) {
			ଗଣନା_2++;
		}
	}
	ଯଦି (addr_ntop(&xa, xas, ଆକାର(xas)) != 0) {
		debug3_f("addr ntop failed");
		ଫେରନ୍ତୁ 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, ଗଣନା_2, max_persource);

	ଯଦି (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	ଯଦି (ଗଣନା_2 >= max_persource)
		ଫେରନ୍ତୁ 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	memcpy(&children[first_unused].addr, &xb, ଆକାର(xb));
	ଫେରନ୍ତୁ 1;
}

ଶୂନ୍ୟ
srclimit_done(ପୂର୍ଣ୍ଣସଂଖ୍ୟା id)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (max_persource == INT_MAX)	/* no limit */
		ଫେରନ୍ତୁ;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	ପାଇଁ (i = 0; i < max_children; i++) {
		ଯଦି (children[i].id == id) {
			children[i].id = -1;
			ଫେରନ୍ତୁ;
		}
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
penalty_addr_cmp(ସଂରଚନା penalty *a, ସଂରଚନା penalty *b)
{
	ଫେରନ୍ତୁ addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
penalty_expiry_cmp(ସଂରଚନା penalty *a, ସଂରଚନା penalty *b)
{
	ଯଦି (a->expiry != b->expiry)
		ଫେରନ୍ତୁ a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	ଫେରନ୍ତୁ addr_cmp(&a->addr, &b->addr);
}

ସ୍ଥିର ଶୂନ୍ୟ
expire_penalties_from_ବୃକ୍ଷ(ଦ୍ୱିଗୁଣ now, ଅଚଳ ଅକ୍ଷର *t,
    ସଂରଚନା penalties_by_expiry *by_expiry,
    ସଂରଚନା penalties_by_addr *by_addr, size_t *npenaltiesp)
{
	ସଂରଚନା penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		ଯଦି (penalty->expiry >= now)
			ଭାଙ୍ଗ;
		ଯଦି (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		ମୁକ୍ତ(penalty);
		ଯଦି ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
expire_penalties(ଦ୍ୱିଗୁଣ now)
{
	expire_penalties_from_ବୃକ୍ଷ(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_ବୃକ୍ଷ(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

ସ୍ଥିର ଶୂନ୍ୟ
addr_masklen_ntop(ସଂରଚନା xaddr *addr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା masklen, ଅକ୍ଷର *s, size_t slen)
{
	size_t o;

	ଯଦି (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
srclimit_penalty_check_allow(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, ଅଚଳ ଅକ୍ଷର **reason)
{
	ସଂରଚନା xaddr addr;
	ସଂରଚନା penalty find, *penalty;
	ଦ୍ୱିଗୁଣ now;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits, max_sources, overflow_mode;
	ଅକ୍ଷର addr_s[NI_MAXHOST];
	ସଂରଚନା penalties_by_addr *by_addr;
	size_t npenalties;

	ଯଦି (!penalty_cfg.enabled)
		ଫେରନ୍ତୁ 1;
	ଯଦି (srclimit_peer_addr(sock, &addr) != 0)
		ଫେରନ୍ତୁ 1;
	ଯଦି (penalty_exempt != ଖାଲି) {
		ଯଦି (addr_ntop(&addr, addr_s, ଆକାର(addr_s)) != 0)
			ଫେରନ୍ତୁ 1; /* shouldn't happen */
		ଯଦି (addr_match_list(addr_s, penalty_exempt) == 1) {
			ଫେରନ୍ତୁ 1;
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
	ଯଦି (npenalties >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		ଫେରନ୍ତୁ 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, ଆକାର(find));
	ଯଦି (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		ଫେରନ୍ତୁ 1;
	ଯଦି ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == ଖାଲି)
		ଫେରନ୍ତୁ 1; /* no penalty */
	ଯଦି (penalty->expiry < now) {
		expire_penalties(now);
		ଫେରନ୍ତୁ 1; /* expired penalty */
	}
	ଯଦି (!penalty->active)
		ଫେରନ୍ତୁ 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
srclimit_early_expire_penalties_from_ବୃକ୍ଷ(ଅଚଳ ଅକ୍ଷର *t,
    ସଂରଚନା penalties_by_expiry *by_expiry,
    ସଂରଚନା penalties_by_addr *by_addr, size_t *npenaltiesp, size_t max_sources)
{
	ସଂରଚନା penalty *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits;
	ଅକ୍ଷର s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	ଯେତେବେଳେ (*npenaltiesp > max_sources) {
		ଯଦି ((p = RB_MIN(penalties_by_expiry, by_expiry)) == ଖାଲି)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, ଆକାର(s));
		debug3_f("%s overflow, remove %s", t, s);
		ଯଦି (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		ମୁକ୍ତ(p);
		(*npenaltiesp)--;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
srclimit_early_expire_penalties(ଶୂନ୍ୟ)
{
	srclimit_early_expire_penalties_from_ବୃକ୍ଷ("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (size_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_ବୃକ୍ଷ("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (size_t)penalty_cfg.max_sources6);
}

ଶୂନ୍ୟ
srclimit_penalise(ସଂରଚନା xaddr *addr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା penalty_type)
{
	ସଂରଚନା xaddr masked;
	ସଂରଚନା penalty *penalty = ଖାଲି, *existing = ଖାଲି;
	ଦ୍ୱିଗୁଣ now;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits, max_sources = 0, overflow_mode;
	ଦ୍ୱିଗୁଣ penalty_secs;
	ଅକ୍ଷର addrnetmask[NI_MAXHOST + 4];
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି, *t;
	size_t *npenaltiesp = ଖାଲି;
	ସଂରଚନା penalties_by_addr *by_addr = ଖାଲି;
	ସଂରଚନା penalties_by_expiry *by_expiry = ଖାଲି;

	ଯଦି (!penalty_cfg.enabled)
		ଫେରନ୍ତୁ;
	ଯଦି (penalty_exempt != ଖାଲି) {
		ଯଦି (addr_ntop(addr, addrnetmask, ଆକାର(addrnetmask)) != 0)
			ଫେରନ୍ତୁ; /* shouldn't happen */
		ଯଦି (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			ଫେରନ୍ତୁ;
		}
	}

	ବାଛ (penalty_type) {
	ସ୍ଥିତି SRCLIMIT_PENALTY_NONE:
		ଫେରନ୍ତୁ;
	ସ୍ଥିତି SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	ଯଦି (penalty_secs <= 0)
		ଫେରନ୍ତୁ;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	ଯଦି (srclimit_mask_addr(addr, bits, &masked) != 0)
		ଫେରନ୍ତୁ;
	addr_masklen_ntop(addr, bits, addrnetmask, ଆକାର(addrnetmask));

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
	ଯଦି (*npenaltiesp >= (size_t)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		ଫେରନ୍ତୁ;
	}

	penalty = xcalloc(1, ଆକାର(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	ଯଦି ((existing = RB_ଭର୍ତ୍ତି(penalties_by_addr, by_addr,
	    penalty)) == ଖାଲି) {
		/* penalty didn't previously exist */
		ଯଦି (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		ଯଦି (RB_ଭର୍ତ୍ତି(penalties_by_expiry, by_expiry, penalty) != ଖାଲି)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		ଯଦି (++(*npenaltiesp) > (size_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		ଫେରନ୍ତୁ;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (long long)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	ଯଦି (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	ଯଦି (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	ଯଦି (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	ମୁକ୍ତ(penalty);
	penalty = ଖାଲି;
	/* Re-insert into expiry tree */
	ଯଦି (RB_ଭର୍ତ୍ତି(penalties_by_expiry, by_expiry, existing) != ଖାଲି)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ସ୍ଥିର ଶୂନ୍ୟ
srclimit_penalty_info_for_ବୃକ୍ଷ(ଅଚଳ ଅକ୍ଷର *t,
    ସଂରଚନା penalties_by_expiry *by_expiry, size_t npenalties)
{
	ସଂରଚନା penalty *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits;
	ଅକ୍ଷର s[NI_MAXHOST + 4];
	ଦ୍ୱିଗୁଣ now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, ଆକାର(s));
		ଯଦି (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ଅନ୍ୟଥା {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

ଶୂନ୍ୟ
srclimit_penalty_info(ଶୂନ୍ୟ)
{
	srclimit_penalty_info_for_ବୃକ୍ଷ("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_ବୃକ୍ଷ("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
