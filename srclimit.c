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

#شامل "includes.h"

#شامل <sys/socket.h>
#شامل <sys/types.h>
#شامل <sys/tree.h>

#شامل <limits.h>
#شامل <netdb.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "addr.h"
#شامل "canohost.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "srclimit.h"
#شامل "xmalloc.h"
#شامل "servconf.h"
#شامل "match.h"

ساکن صحیح max_children, max_persource, ipv4_masklen, ipv6_masklen;
ساکن ساخت فی_ماخذ_penalty penalty_cfg;
ساکن حرف *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
ساکن ساخت بچہ_info {
	صحیح id;
	ساخت xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
ساخت penalty {
	ساخت xaddr addr;
	دوہرا expiry;
	صحیح فعال;
	ثابت حرف *reason;
	RB_اندراج(penalty) by_addr;
	RB_اندراج(penalty) by_expiry;
};
ساکن صحیح penalty_addr_cmp(ساخت penalty *a, ساخت penalty *b);
ساکن صحیح penalty_expiry_cmp(ساخت penalty *a, ساخت penalty *b);
RB_سر(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_سر(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
ساکن سائز_t npenalties4, npenalties6;

ساکن صحیح
srclimit_نقاب_addr(ثابت ساخت xaddr *addr, صحیح بٹ, ساخت xaddr *masked)
{
	ساخت xaddr xmask;

	/* Mask address off address to desired size. */
	اگر (addr_netmask(addr->af, بٹ, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, بٹ);
		واپس -1;
	}
	واپس 0;
}

ساکن صحیح
srclimit_peer_addr(صحیح sock, ساخت xaddr *addr)
{
	ساخت sockaddr_storage storage;
	socklen_t addrlen = حجم(storage);
	ساخت sockaddr *sa = (ساخت sockaddr *)&storage;

	اگر (getpeername(sock, sa, &addrlen) != 0)
		واپس 1;	/* not remote socket? */
	اگر (addr_sa_مقصد_xaddr(sa, addrlen, addr) != 0)
		واپس 1;	/* unknown address family? */
	واپس 0;
}

خالی
srclimit_init(صحیح max, صحیح persource, صحیح ipv4len, صحیح ipv6len,
    ساخت فی_ماخذ_penalty *penalty_conf, ثابت حرف *penalty_exempt_conf)
{
	صحیح i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	اگر (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == تہی ?
	    تہی : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	اگر (max_persource == زیادہ_سے_زیادہ_عدد)	/* no limit */
		واپس;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	اگر (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, حجم(*children));
	برائے (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
صحیح
srclimit_check_allow(صحیح sock, صحیح id)
{
	ساخت xaddr xa, xb;
	صحیح i, بٹ, پہلا_غیر_مستعمل, گنتی = 0;
	حرف xas[NI_MAXHOST];

	اگر (max_persource == زیادہ_سے_زیادہ_عدد)	/* no limit */
		واپس 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	اگر (srclimit_peer_addr(sock, &xa) != 0)
		واپس 1;
	بٹ = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	اگر (srclimit_نقاب_addr(&xa, بٹ, &xb) != 0)
		واپس 1;

	پہلا_غیر_مستعمل = max_children;
	/* Count matching entries and find first unused one. */
	برائے (i = 0; i < max_children; i++) {
		اگر (children[i].id == -1) {
			اگر (i < پہلا_غیر_مستعمل)
				پہلا_غیر_مستعمل = i;
		} ورنہ اگر (addr_cmp(&children[i].addr, &xb) == 0) {
			گنتی++;
		}
	}
	اگر (addr_ntop(&xa, xas, حجم(xas)) != 0) {
		debug3_f("addr ntop failed");
		واپس 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, بٹ, گنتی, max_persource);

	اگر (پہلا_غیر_مستعمل == max_children) { /* no free slot found */
		debug3_f("no free slot");
		واپس 0;
	}
	اگر (پہلا_غیر_مستعمل < 0 || پہلا_غیر_مستعمل >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	اگر (گنتی >= max_persource)
		واپس 0;

	/* Connection allowed, store masked address. */
	children[پہلا_غیر_مستعمل].id = id;
	حافظہ_نقل(&children[پہلا_غیر_مستعمل].addr, &xb, حجم(xb));
	واپس 1;
}

خالی
srclimit_مکمل(صحیح id)
{
	صحیح i;

	اگر (max_persource == زیادہ_سے_زیادہ_عدد)	/* no limit */
		واپس;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	برائے (i = 0; i < max_children; i++) {
		اگر (children[i].id == id) {
			children[i].id = -1;
			واپس;
		}
	}
}

ساکن صحیح
penalty_addr_cmp(ساخت penalty *a, ساخت penalty *b)
{
	واپس addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

ساکن صحیح
penalty_expiry_cmp(ساخت penalty *a, ساخت penalty *b)
{
	اگر (a->expiry != b->expiry)
		واپس a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	واپس addr_cmp(&a->addr, &b->addr);
}

ساکن خالی
expire_penalties_from_درخت(دوہرا now, ثابت حرف *t,
    ساخت penalties_by_expiry *by_expiry,
    ساخت penalties_by_addr *by_addr, سائز_t *npenaltiesp)
{
	ساخت penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_محفوظ(penalty, penalties_by_expiry, by_expiry, tmp) {
		اگر (penalty->expiry >= now)
			توڑو;
		اگر (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		آزاد(penalty);
		اگر ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

ساکن خالی
expire_penalties(دوہرا now)
{
	expire_penalties_from_درخت(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_درخت(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

ساکن خالی
addr_masklen_ntop(ساخت xaddr *addr, صحیح masklen, حرف *s, سائز_t slen)
{
	سائز_t o;

	اگر (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		واپس;
	}
	اگر ((o = لڑی_لمبائی(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

صحیح
srclimit_penalty_check_allow(صحیح sock, ثابت حرف **reason)
{
	ساخت xaddr addr;
	ساخت penalty ڈھونڈو, *penalty;
	دوہرا now;
	صحیح بٹ, max_sources, حد_سے_تجاوز_منوال;
	حرف addr_s[NI_MAXHOST];
	ساخت penalties_by_addr *by_addr;
	سائز_t npenalties;

	اگر (!penalty_cfg.enabled)
		واپس 1;
	اگر (srclimit_peer_addr(sock, &addr) != 0)
		واپس 1;
	اگر (penalty_exempt != تہی) {
		اگر (addr_ntop(&addr, addr_s, حجم(addr_s)) != 0)
			واپس 1; /* shouldn't happen */
		اگر (addr_مطابقت_list(addr_s, penalty_exempt) == 1) {
			واپس 1;
		}
	}
	now = monotime_double();
	expire_penalties(now);
	by_addr = addr.af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr.af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	حد_سے_تجاوز_منوال = addr.af == AF_INET ?
	    penalty_cfg.حد_سے_تجاوز_منوال : penalty_cfg.حد_سے_تجاوز_mode6;
	npenalties = addr.af == AF_INET ?  npenalties4 : npenalties6;
	اگر (npenalties >= (سائز_t)max_sources &&
	    حد_سے_تجاوز_منوال == فی_ماخذ_PENALTY_حد_سے_تجاوز_DENY_ALL) {
		*reason = "too many penalised addresses";
		واپس 0;
	}
	بٹ = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&ڈھونڈو, 0, حجم(ڈھونڈو));
	اگر (srclimit_نقاب_addr(&addr, بٹ, &ڈھونڈو.addr) != 0)
		واپس 1;
	اگر ((penalty = RB_ڈھونڈو(penalties_by_addr, by_addr, &ڈھونڈو)) == تہی)
		واپس 1; /* no penalty */
	اگر (penalty->expiry < now) {
		expire_penalties(now);
		واپس 1; /* expired penalty */
	}
	اگر (!penalty->فعال)
		واپس 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	واپس 0;
}

ساکن خالی
srclimit_early_expire_penalties_from_درخت(ثابت حرف *t,
    ساخت penalties_by_expiry *by_expiry,
    ساخت penalties_by_addr *by_addr, سائز_t *npenaltiesp, سائز_t max_sources)
{
	ساخت penalty *p = تہی;
	صحیح بٹ;
	حرف s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	جب (*npenaltiesp > max_sources) {
		اگر ((p = RB_MIN(penalties_by_expiry, by_expiry)) == تہی)
			fatal_f("internal error: %s table corrupt (find)", t);
		بٹ = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, بٹ, s, حجم(s));
		debug3_f("%s overflow, remove %s", t, s);
		اگر (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		آزاد(p);
		(*npenaltiesp)--;
	}
}

ساکن خالی
srclimit_early_expire_penalties(خالی)
{
	srclimit_early_expire_penalties_from_درخت("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (سائز_t)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_درخت("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (سائز_t)penalty_cfg.max_sources6);
}

خالی
srclimit_penalise(ساخت xaddr *addr, صحیح penalty_type)
{
	ساخت xaddr masked;
	ساخت penalty *penalty = تہی, *existing = تہی;
	دوہرا now;
	صحیح بٹ, max_sources = 0, حد_سے_تجاوز_منوال;
	دوہرا penalty_secs;
	حرف addrnetmask[NI_MAXHOST + 4];
	ثابت حرف *reason = تہی, *t;
	سائز_t *npenaltiesp = تہی;
	ساخت penalties_by_addr *by_addr = تہی;
	ساخت penalties_by_expiry *by_expiry = تہی;

	اگر (!penalty_cfg.enabled)
		واپس;
	اگر (penalty_exempt != تہی) {
		اگر (addr_ntop(addr, addrnetmask, حجم(addrnetmask)) != 0)
			واپس; /* shouldn't happen */
		اگر (addr_مطابقت_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			واپس;
		}
	}

	انتخاب (penalty_type) {
	حالت SRCLIMIT_PENALTY_NONE:
		واپس;
	حالت SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		توڑو;
	حالت SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		توڑو;
	حالت SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		توڑو;
	حالت SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		توڑو;
	حالت SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		توڑو;
	حالت SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		توڑو;
	طےشدہ:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	اگر (penalty_secs <= 0)
		واپس;

	بٹ = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	اگر (srclimit_نقاب_addr(addr, بٹ, &masked) != 0)
		واپس;
	addr_masklen_ntop(addr, بٹ, addrnetmask, حجم(addrnetmask));

	now = monotime_double();
	expire_penalties(now);
	by_expiry = addr->af == AF_INET ?
	    &penalties_by_expiry4 : &penalties_by_expiry6;
	by_addr = addr->af == AF_INET ?
	    &penalties_by_addr4 : &penalties_by_addr6;
	max_sources = addr->af == AF_INET ?
	    penalty_cfg.max_sources4 : penalty_cfg.max_sources6;
	حد_سے_تجاوز_منوال = addr->af == AF_INET ?
	    penalty_cfg.حد_سے_تجاوز_منوال : penalty_cfg.حد_سے_تجاوز_mode6;
	npenaltiesp = addr->af == AF_INET ?  &npenalties4 : &npenalties6;
	t = addr->af == AF_INET ? "ipv4" : "ipv6";
	اگر (*npenaltiesp >= (سائز_t)max_sources &&
	    حد_سے_تجاوز_منوال == فی_ماخذ_PENALTY_حد_سے_تجاوز_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		واپس;
	}

	penalty = xcalloc(1, حجم(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	اگر ((existing = RB_داخل_کرو(penalties_by_addr, by_addr,
	    penalty)) == تہی) {
		/* penalty didn't previously exist */
		اگر (penalty_secs > penalty_cfg.penalty_min)
			penalty->فعال = 1;
		اگر (RB_داخل_کرو(penalties_by_expiry, by_expiry, penalty) != تہی)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->فعال ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->فعال ? "active" : "deferred",
		    penalty_secs, reason);
		اگر (++(*npenaltiesp) > (سائز_t)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		واپس;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->فعال ? "active" : "inactive", t,
	    addrnetmask, (طویل طویل)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	اگر (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	اگر (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	اگر (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->فعال) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->فعال = 1;
	}
	existing->reason = penalty->reason;
	آزاد(penalty);
	penalty = تہی;
	/* Re-insert into expiry tree */
	اگر (RB_داخل_کرو(penalties_by_expiry, by_expiry, existing) != تہی)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

ساکن خالی
srclimit_penalty_info_for_درخت(ثابت حرف *t,
    ساخت penalties_by_expiry *by_expiry, سائز_t npenalties)
{
	ساخت penalty *p = تہی;
	صحیح بٹ;
	حرف s[NI_MAXHOST + 4];
	دوہرا now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		بٹ = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, بٹ, s, حجم(s));
		اگر (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		ورنہ {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

خالی
srclimit_penalty_info(خالی)
{
	srclimit_penalty_info_for_درخت("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_درخت("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
