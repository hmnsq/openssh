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

#समावेश "includes.h"

#समावेश <sys/socket.h>
#समावेश <sys/types.h>
#समावेश <sys/tree.h>

#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdlib.h>

#समावेश "addr.h"
#समावेश "canohost.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "srclimit.h"
#समावेश "xmalloc.h"
#समावेश "servconf.h"
#समावेश "match.h"

अटल पूर्णांक max_children, max_persource, ipv4_masklen, ipv6_masklen;
अटल काष्ठा per_source_penalty penalty_cfg;
अटल अक्षर *penalty_exempt;

/* Per connection state, used to enforce unauthenticated connection limit. */
अटल काष्ठा child_info {
	पूर्णांक id;
	काष्ठा xaddr addr;
} *children;

/*
 * Penalised addresses, active entries here prohibit connections until expired.
 * Entries become active when more than penalty_min seconds of penalty are
 * outstanding.
 */
काष्ठा penalty {
	काष्ठा xaddr addr;
	द्विगुन expiry;
	पूर्णांक active;
	स्थिर अक्षर *reason;
	RB_ENTRY(penalty) by_addr;
	RB_ENTRY(penalty) by_expiry;
};
अटल पूर्णांक penalty_addr_cmp(काष्ठा penalty *a, काष्ठा penalty *b);
अटल पूर्णांक penalty_expiry_cmp(काष्ठा penalty *a, काष्ठा penalty *b);
RB_शीर्ष(penalties_by_addr, penalty) penalties_by_addr4, penalties_by_addr6;
RB_शीर्ष(penalties_by_expiry, penalty) penalties_by_expiry4, penalties_by_expiry6;
RB_GENERATE_STATIC(penalties_by_addr, penalty, by_addr, penalty_addr_cmp)
RB_GENERATE_STATIC(penalties_by_expiry, penalty, by_expiry, penalty_expiry_cmp)
अटल माप_प्रकार npenalties4, npenalties6;

अटल पूर्णांक
srclimit_mask_addr(स्थिर काष्ठा xaddr *addr, पूर्णांक bits, काष्ठा xaddr *masked)
{
	काष्ठा xaddr xmask;

	/* Mask address off address to desired size. */
	अगर (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		वापस -1;
	}
	वापस 0;
}

अटल पूर्णांक
srclimit_peer_addr(पूर्णांक sock, काष्ठा xaddr *addr)
{
	काष्ठा sockaddr_storage storage;
	socklen_t addrlen = माप(storage);
	काष्ठा sockaddr *sa = (काष्ठा sockaddr *)&storage;

	अगर (getpeername(sock, sa, &addrlen) != 0)
		वापस 1;	/* not remote socket? */
	अगर (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		वापस 1;	/* unknown address family? */
	वापस 0;
}

व्योम
srclimit_init(पूर्णांक max, पूर्णांक persource, पूर्णांक ipv4len, पूर्णांक ipv6len,
    काष्ठा per_source_penalty *penalty_conf, स्थिर अक्षर *penalty_exempt_conf)
{
	पूर्णांक i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_cfg = *penalty_conf;
	अगर (penalty_cfg.max_sources4 < 0 || penalty_cfg.max_sources6 < 0)
		fatal_f("invalid max_sources"); /* shouldn't happen */
	penalty_exempt = penalty_exempt_conf == शून्य ?
	    शून्य : xstrdup(penalty_exempt_conf);
	RB_INIT(&penalties_by_addr4);
	RB_INIT(&penalties_by_expiry4);
	RB_INIT(&penalties_by_addr6);
	RB_INIT(&penalties_by_expiry6);
	अगर (max_persource == पूर्णांक_उच्च)	/* no limit */
		वापस;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	अगर (max <= 0)
		fatal_f("invalid number of sockets: %d", max);
	children = xcalloc(max_children, माप(*children));
	क्रम (i = 0; i < max_children; i++)
		children[i].id = -1;
}

/* returns 1 if connection allowed, 0 if not allowed. */
पूर्णांक
srclimit_check_allow(पूर्णांक sock, पूर्णांक id)
{
	काष्ठा xaddr xa, xb;
	पूर्णांक i, bits, first_unused, गिनती = 0;
	अक्षर xas[NI_MAXHOST];

	अगर (max_persource == पूर्णांक_उच्च)	/* no limit */
		वापस 1;

	debug_f("sock %d id %d limit %d", sock, id, max_persource);
	अगर (srclimit_peer_addr(sock, &xa) != 0)
		वापस 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	अगर (srclimit_mask_addr(&xa, bits, &xb) != 0)
		वापस 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	क्रम (i = 0; i < max_children; i++) {
		अगर (children[i].id == -1) {
			अगर (i < first_unused)
				first_unused = i;
		} अन्यथा अगर (addr_cmp(&children[i].addr, &xb) == 0) {
			गिनती++;
		}
	}
	अगर (addr_ntop(&xa, xas, माप(xas)) != 0) {
		debug3_f("addr ntop failed");
		वापस 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, गिनती, max_persource);

	अगर (first_unused == max_children) { /* no free slot found */
		debug3_f("no free slot");
		वापस 0;
	}
	अगर (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	अगर (गिनती >= max_persource)
		वापस 0;

	/* Connection allowed, store masked address. */
	children[first_unused].id = id;
	स_नकल(&children[first_unused].addr, &xb, माप(xb));
	वापस 1;
}

व्योम
srclimit_done(पूर्णांक id)
{
	पूर्णांक i;

	अगर (max_persource == पूर्णांक_उच्च)	/* no limit */
		वापस;

	debug_f("id %d", id);
	/* Clear corresponding state entry. */
	क्रम (i = 0; i < max_children; i++) {
		अगर (children[i].id == id) {
			children[i].id = -1;
			वापस;
		}
	}
}

अटल पूर्णांक
penalty_addr_cmp(काष्ठा penalty *a, काष्ठा penalty *b)
{
	वापस addr_cmp(&a->addr, &b->addr);
	/* Addresses must be unique in by_addr, so no need to tiebreak */
}

अटल पूर्णांक
penalty_expiry_cmp(काष्ठा penalty *a, काष्ठा penalty *b)
{
	अगर (a->expiry != b->expiry)
		वापस a->expiry < b->expiry ? -1 : 1;
	/* Tiebreak on addresses */
	वापस addr_cmp(&a->addr, &b->addr);
}

अटल व्योम
expire_penalties_from_वृक्ष(द्विगुन now, स्थिर अक्षर *t,
    काष्ठा penalties_by_expiry *by_expiry,
    काष्ठा penalties_by_addr *by_addr, माप_प्रकार *npenaltiesp)
{
	काष्ठा penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties_by_expiry, by_expiry, tmp) {
		अगर (penalty->expiry >= now)
			अवरोध;
		अगर (RB_REMOVE(penalties_by_expiry, by_expiry,
		    penalty) != penalty ||
		    RB_REMOVE(penalties_by_addr, by_addr,
		    penalty) != penalty)
			fatal_f("internal error: %s penalty table corrupt", t);
		मुक्त(penalty);
		अगर ((*npenaltiesp)-- == 0)
			fatal_f("internal error: %s npenalties underflow", t);
	}
}

अटल व्योम
expire_penalties(द्विगुन now)
{
	expire_penalties_from_वृक्ष(now, "ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4);
	expire_penalties_from_वृक्ष(now, "ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6);
}

अटल व्योम
addr_masklen_ntop(काष्ठा xaddr *addr, पूर्णांक masklen, अक्षर *s, माप_प्रकार slen)
{
	माप_प्रकार o;

	अगर (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		वापस;
	}
	अगर ((o = म_माप(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

पूर्णांक
srclimit_penalty_check_allow(पूर्णांक sock, स्थिर अक्षर **reason)
{
	काष्ठा xaddr addr;
	काष्ठा penalty find, *penalty;
	द्विगुन now;
	पूर्णांक bits, max_sources, overflow_mode;
	अक्षर addr_s[NI_MAXHOST];
	काष्ठा penalties_by_addr *by_addr;
	माप_प्रकार npenalties;

	अगर (!penalty_cfg.enabled)
		वापस 1;
	अगर (srclimit_peer_addr(sock, &addr) != 0)
		वापस 1;
	अगर (penalty_exempt != शून्य) {
		अगर (addr_ntop(&addr, addr_s, माप(addr_s)) != 0)
			वापस 1; /* shouldn't happen */
		अगर (addr_match_list(addr_s, penalty_exempt) == 1) {
			वापस 1;
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
	अगर (npenalties >= (माप_प्रकार)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		*reason = "too many penalised addresses";
		वापस 0;
	}
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	स_रखो(&find, 0, माप(find));
	अगर (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		वापस 1;
	अगर ((penalty = RB_FIND(penalties_by_addr, by_addr, &find)) == शून्य)
		वापस 1; /* no penalty */
	अगर (penalty->expiry < now) {
		expire_penalties(now);
		वापस 1; /* expired penalty */
	}
	अगर (!penalty->active)
		वापस 1; /* Penalty hasn't hit activation threshold yet */
	*reason = penalty->reason;
	वापस 0;
}

अटल व्योम
srclimit_early_expire_penalties_from_वृक्ष(स्थिर अक्षर *t,
    काष्ठा penalties_by_expiry *by_expiry,
    काष्ठा penalties_by_addr *by_addr, माप_प्रकार *npenaltiesp, माप_प्रकार max_sources)
{
	काष्ठा penalty *p = शून्य;
	पूर्णांक bits;
	अक्षर s[NI_MAXHOST + 4];

	/* Delete the soonest-to-expire penalties. */
	जबतक (*npenaltiesp > max_sources) {
		अगर ((p = RB_MIN(penalties_by_expiry, by_expiry)) == शून्य)
			fatal_f("internal error: %s table corrupt (find)", t);
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, माप(s));
		debug3_f("%s overflow, remove %s", t, s);
		अगर (RB_REMOVE(penalties_by_expiry, by_expiry, p) != p ||
		    RB_REMOVE(penalties_by_addr, by_addr, p) != p)
			fatal_f("internal error: %s table corrupt (remove)", t);
		मुक्त(p);
		(*npenaltiesp)--;
	}
}

अटल व्योम
srclimit_early_expire_penalties(व्योम)
{
	srclimit_early_expire_penalties_from_वृक्ष("ipv4",
	    &penalties_by_expiry4, &penalties_by_addr4, &npenalties4,
	    (माप_प्रकार)penalty_cfg.max_sources4);
	srclimit_early_expire_penalties_from_वृक्ष("ipv6",
	    &penalties_by_expiry6, &penalties_by_addr6, &npenalties6,
	    (माप_प्रकार)penalty_cfg.max_sources6);
}

व्योम
srclimit_penalise(काष्ठा xaddr *addr, पूर्णांक penalty_type)
{
	काष्ठा xaddr masked;
	काष्ठा penalty *penalty = शून्य, *existing = शून्य;
	द्विगुन now;
	पूर्णांक bits, max_sources = 0, overflow_mode;
	द्विगुन penalty_secs;
	अक्षर addrnetmask[NI_MAXHOST + 4];
	स्थिर अक्षर *reason = शून्य, *t;
	माप_प्रकार *npenaltiesp = शून्य;
	काष्ठा penalties_by_addr *by_addr = शून्य;
	काष्ठा penalties_by_expiry *by_expiry = शून्य;

	अगर (!penalty_cfg.enabled)
		वापस;
	अगर (penalty_exempt != शून्य) {
		अगर (addr_ntop(addr, addrnetmask, माप(addrnetmask)) != 0)
			वापस; /* shouldn't happen */
		अगर (addr_match_list(addrnetmask, penalty_exempt) == 1) {
			debug3_f("address %s is exempt", addrnetmask);
			वापस;
		}
	}

	चयन (penalty_type) {
	हाल SRCLIMIT_PENALTY_NONE:
		वापस;
	हाल SRCLIMIT_PENALTY_CRASH:
		penalty_secs = penalty_cfg.penalty_crash;
		reason = "penalty: caused crash";
		अवरोध;
	हाल SRCLIMIT_PENALTY_AUTHFAIL:
		penalty_secs = penalty_cfg.penalty_authfail;
		reason = "penalty: failed authentication";
		अवरोध;
	हाल SRCLIMIT_PENALTY_NOAUTH:
		penalty_secs = penalty_cfg.penalty_noauth;
		reason = "penalty: connections without attempting authentication";
		अवरोध;
	हाल SRCLIMIT_PENALTY_INVALIDUSER:
		penalty_secs = penalty_cfg.penalty_invaliduser;
		reason = "penalty: attempted authentication by invalid user";
		अवरोध;
	हाल SRCLIMIT_PENALTY_REFUSECONNECTION:
		penalty_secs = penalty_cfg.penalty_refuseconnection;
		reason = "penalty: connection prohibited by RefuseConnection";
		अवरोध;
	हाल SRCLIMIT_PENALTY_GRACE_EXCEEDED:
		penalty_secs = penalty_cfg.penalty_grace;
		reason = "penalty: exceeded LoginGraceTime";
		अवरोध;
	शेष:
		fatal_f("internal error: unknown penalty %d", penalty_type);
	}

	अगर (penalty_secs <= 0)
		वापस;

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	अगर (srclimit_mask_addr(addr, bits, &masked) != 0)
		वापस;
	addr_masklen_ntop(addr, bits, addrnetmask, माप(addrnetmask));

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
	अगर (*npenaltiesp >= (माप_प्रकार)max_sources &&
	    overflow_mode == PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL) {
		verbose_f("%s penalty table full, cannot penalise %s for %s", t,
		    addrnetmask, reason);
		वापस;
	}

	penalty = xcalloc(1, माप(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = reason;
	अगर ((existing = RB_जोड़ो(penalties_by_addr, by_addr,
	    penalty)) == शून्य) {
		/* penalty didn't previously exist */
		अगर (penalty_secs > penalty_cfg.penalty_min)
			penalty->active = 1;
		अगर (RB_जोड़ो(penalties_by_expiry, by_expiry, penalty) != शून्य)
			fatal_f("internal error: %s penalty tables corrupt", t);
		do_log2_f(penalty->active ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_VERBOSE,
		    "%s: new %s %s penalty of %.3f seconds for %s", t,
		    addrnetmask, penalty->active ? "active" : "deferred",
		    penalty_secs, reason);
		अगर (++(*npenaltiesp) > (माप_प्रकार)max_sources)
			srclimit_early_expire_penalties(); /* permissive */
		वापस;
	}
	debug_f("%s penalty for %s %s already exists, %lld seconds remaining",
	    existing->active ? "active" : "inactive", t,
	    addrnetmask, (दीर्घ दीर्घ)(existing->expiry - now));
	/* Expiry information is about to change, remove from tree */
	अगर (RB_REMOVE(penalties_by_expiry, by_expiry, existing) != existing)
		fatal_f("internal error: %s penalty table corrupt (remove)", t);
	/* An entry already existed. Accumulate penalty up to maximum */
	existing->expiry += penalty_secs;
	अगर (existing->expiry - now > penalty_cfg.penalty_max)
		existing->expiry = now + penalty_cfg.penalty_max;
	अगर (existing->expiry - now > penalty_cfg.penalty_min &&
	    !existing->active) {
		logit_f("%s: activating %s penalty of %.3f seconds for %s",
		    addrnetmask, t, existing->expiry - now, reason);
		existing->active = 1;
	}
	existing->reason = penalty->reason;
	मुक्त(penalty);
	penalty = शून्य;
	/* Re-insert into expiry tree */
	अगर (RB_जोड़ो(penalties_by_expiry, by_expiry, existing) != शून्य)
		fatal_f("internal error: %s penalty table corrupt (insert)", t);
}

अटल व्योम
srclimit_penalty_info_for_वृक्ष(स्थिर अक्षर *t,
    काष्ठा penalties_by_expiry *by_expiry, माप_प्रकार npenalties)
{
	काष्ठा penalty *p = शून्य;
	पूर्णांक bits;
	अक्षर s[NI_MAXHOST + 4];
	द्विगुन now;

	now = monotime_double();
	logit("%zu active %s penalties", npenalties, t);
	RB_FOREACH(p, penalties_by_expiry, by_expiry) {
		bits = p->addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
		addr_masklen_ntop(&p->addr, bits, s, माप(s));
		अगर (p->expiry < now)
			logit("client %s %s (expired)", s, p->reason);
		अन्यथा {
			logit("client %s %s (%.3f secs left)", s, p->reason,
			   p->expiry - now);
		}
	}
}

व्योम
srclimit_penalty_info(व्योम)
{
	srclimit_penalty_info_for_वृक्ष("ipv4",
	    &penalties_by_expiry4, npenalties4);
	srclimit_penalty_info_for_वृक्ष("ipv6",
	    &penalties_by_expiry6, npenalties6);
}
