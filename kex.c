/* $OpenBSD: kex.c,v 1.196 2026/09/22 00:24:47 dtucker Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>
#endif

#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "version.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

/* prototype */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା kex_choose_conf(ସଂରଚନା ssh *, uint32_t seq);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା kex_ନିବେଶ_newkeys(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ proposal_names[PROPOSAL_MAX] = {
	"KEX algorithms",
	"host key algorithms",
	"ciphers ctos",
	"ciphers stoc",
	"MACs ctos",
	"MACs stoc",
	"compression ctos",
	"compression stoc",
	"languages ctos",
	"languages stoc",
};

/*
 * Fill out a proposal array with dynamically allocated values, which may
 * be modified as required for compatibility reasons.
 * Any of the options may be NULL, in which case the default is used.
 * Array contents must be freed by calling kex_proposal_free_entries.
 */
ଶୂନ୍ୟ
kex_proposal_populate_entries(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *prop[PROPOSAL_MAX],
    ଅଚଳ ଅକ୍ଷର *kexalgos, ଅଚଳ ଅକ୍ଷର *ciphers, ଅଚଳ ଅକ୍ଷର *macs,
    ଅଚଳ ଅକ୍ଷର *comp, ଅଚଳ ଅକ୍ଷର *hkalgs)
{
	ଅଚଳ ଅକ୍ଷର *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ଅଚଳ ଅକ୍ଷର *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅଚଳ ଅକ୍ଷର **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	ଅକ୍ଷର *cp;

	ଯଦି (prop == ଖାଲି)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ଯଦି (kexalgos == ଖାଲି)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ଯଦି ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ଖାଲି)
		fatal_f("kex_names_cat");

	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ବାଛ(i) {
		ସ୍ଥିତି PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି PROPOSAL_ENC_ALGS_CTOS:
		ସ୍ଥିତି PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି PROPOSAL_MAC_ALGS_CTOS:
		ସ୍ଥିତି PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି PROPOSAL_COMP_ALGS_CTOS:
		ସ୍ଥିତି PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି PROPOSAL_SERVER_HOST_ଚାବି_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	ମୁକ୍ତ(cp);
}

ଶୂନ୍ୟ
kex_proposal_free_entries(ଅକ୍ଷର *prop[PROPOSAL_MAX])
{
	u_int i;

	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(prop[i]);
}

/* put algorithm proposal into buffer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_prop2buf(ସଂରଚନା sshbuf *b, ଅକ୍ଷର *proposal[PROPOSAL_MAX])
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	ପାଇଁ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ଯଦି ((r = sshbuf_put_u8(b, 0)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଯଦି ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

/* parse buffer and return algorithm proposal */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_buf2prop(ସଂରଚନା sshbuf *raw, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *first_kex_follows, ଅକ୍ଷର ***propp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	u_char v;
	u_int i;
	ଅକ୍ଷର **proposal = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*propp = ଖାଲି;
	ଯଦି ((proposal = calloc(PROPOSAL_MAX, ଆକାର(ଅକ୍ଷର *))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((b = sshbuf_fromb(raw)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		ଯାଅ out;
	}
	/* extract kex init proposal strings */
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଯଦି ((r = sshbuf_get_cstring(b, &(proposal[i]), ଖାଲି)) != 0) {
			error_fr(r, "parse proposal %u", i);
			ଯାଅ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ଯଦି ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		ଯାଅ out;
	}
	ଯଦି (first_kex_follows != ଖାଲି)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	ଯଦି (r != 0 && proposal != ଖାଲି)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ଶୂନ୍ୟ
kex_prop_free(ଅକ୍ଷର **proposal)
{
	u_int i;

	ଯଦି (proposal == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(proposal[i]);
	ମୁକ୍ତ(proposal);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_protocol_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* If in strict mode, any unexpected message is an error */
	ଯଦି ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
kex_reset_dispatch(ସଂରଚନା ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_ସନ୍ଦେଶ_TRANSPORT_MIN,
	    SSH2_ସନ୍ଦେଶ_TRANSPORT_MAX, &kex_protocol_error);
}

ଶୂନ୍ୟ
kex_set_server_sig_algs(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *allowed_algs)
{
	ଅକ୍ଷର *alg, *oalgs, *algs, *sigalgs;
	ଅଚଳ ଅକ୍ଷର *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ଯଦି ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ଖାଲି)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	ମୁକ୍ତ(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ଖାଲି;
	ପାଇଁ ((alg = strsep(&algs, ",")); alg != ଖାଲି && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ଯଦି ((sigalg = sshkey_sigalg_by_name(alg)) == ଖାଲି)
			ଜାରି;
		ଯଦି (!kex_has_any_alg(sigalg, sigalgs))
			ଜାରି;
		/* Don't add an algorithm twice. */
		ଯଦି (ssh->kex->server_sig_algs != ଖାଲି &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			ଜାରି;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	ମୁକ୍ତ(oalgs);
	ମୁକ୍ତ(sigalgs);
	ଯଦି (ssh->kex->server_sig_algs == ଖାଲି)
		ssh->kex->server_sig_algs = xstrdup("");
}

ଶୂନ୍ୟ
kex_set_warn_weak_crypto(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା warn_weak_crypto)
{
	ଯଦି (ssh != ଖାଲି && ssh->kex != ଖାଲି)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

ଶୂନ୍ୟ
kex_check_warn_weak_crypto(ସଂରଚନା ssh *ssh)
{
	ଅକ୍ଷର remote_id[512];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rekeyed = 0;

	ଯଦି (ssh == ଖାଲି || ssh->kex == ଖାଲି || ssh->kex->name == ଖାଲି ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ଫେରନ୍ତୁ;
	ଯଦି (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ଫେରନ୍ତୁ;
	}

	ଯଦି (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ଯଦି (!rekeyed && !ssh->kex->server)
		ଫେରନ୍ତୁ; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, ଆକାର(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_compose_ext_info_server(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ssh->kex->server_sig_algs == ଖାଲି &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u32(m, 4)) != 0 ||
	    (r = sshbuf_put_cstring(m, "server-sig-algs")) != 0 ||
	    (r = sshbuf_put_cstring(m, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshbuf_put_cstring(m,
	    "publickey-hostbound@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0 ||
	    (r = sshbuf_put_cstring(m, "ping@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0 ||
	    (r = sshbuf_put_cstring(m, "agent-forward")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_compose_ext_info_client(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *m)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_maybe_send_ext_info(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *m = ଖାଲି;

	ଯଦି ((ssh->kex->flags & KEX_INITIAL) == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ଫେରନ୍ତୁ 0;

	/* Compose EXT_INFO packet. */
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		ଯାଅ fail;
	ଯଦି (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		ଯାଅ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ଯାଅ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_server_update_ext_info(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		ଫେରନ୍ତୁ 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_send_newkeys(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	kex_reset_dispatch(ssh);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_NEWKEYS, &kex_ନିବେଶ_newkeys);
	ଯଦି ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ଫେରନ୍ତୁ 0;
}

/* Check whether an ext_info value contains the expected version string */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ext_info_check_ver(ସଂରଚନା kex *kex, ଅଚଳ ଅକ୍ଷର *name,
    ଅଚଳ u_char *val, size_t len, ଅଚଳ ଅକ୍ଷର *want_ver, u_int flag)
{
	ଯଦି (memchr(val, '\0', len) != ଖାଲି) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ଯଦି (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	ଅନ୍ୟଥା
		debug_f("unsupported version of %s extension", name);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ext_info_client_parse(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *name,
    ଅଚଳ u_char *ମୂଲ୍ୟ, size_t vlen)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ଯଦି (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ଯଦି (memchr(ମୂଲ୍ୟ, '\0', vlen) != ଖାଲି) {
			error_f("nul byte in %s", name);
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, ମୂଲ୍ୟ);
		ମୁକ୍ତ(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ଅଚଳ ଅକ୍ଷର *)ମୂଲ୍ୟ);
	} ଅନ୍ୟଥା ଯଦି (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ଯଦି ((r = kex_ext_info_check_ver(ssh->kex, name, ମୂଲ୍ୟ, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ଫେରନ୍ତୁ r;
		}
	} ଅନ୍ୟଥା ଯଦି (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ଯଦି ((r = kex_ext_info_check_ver(ssh->kex, name, ମୂଲ୍ୟ, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ଫେରନ୍ତୁ r;
		}
	} ଅନ୍ୟଥା ଯଦି (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ଯଦି ((r = kex_ext_info_check_ver(ssh->kex, name, ମୂଲ୍ୟ, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ଫେରନ୍ତୁ r;
		}
	} ଅନ୍ୟଥା
		debug_f("%s (unrecognised)", name);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ext_info_server_parse(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *name,
    ଅଚଳ u_char *ମୂଲ୍ୟ, size_t vlen)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ଯଦି ((r = kex_ext_info_check_ver(ssh->kex, name, ମୂଲ୍ୟ, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			ଫେରନ୍ତୁ r;
		}
	} ଅନ୍ୟଥା
		debug_f("%s (unrecognised)", name);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ନିବେଶ_ext_info(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	ଅକ୍ଷର *name;
	u_char *val;
	size_t vlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("SSH2_MSG_EXT_INFO received");
	ଯଦି (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ଫେରନ୍ତୁ dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, &kex_protocol_error);
	ଯଦି ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ଫେରନ୍ତୁ dispatch_protocol_error(type, seq, ssh);
	}
	ପାଇଁ (i = 0; i < ninfo; i++) {
		ଯଦି ((r = sshpkt_get_cstring(ssh, &name, ଖାଲି)) != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			ମୁକ୍ତ(name);
			ଫେରନ୍ତୁ r;
		}
		debug3_f("extension %s", name);
		ଯଦି (kex->server) {
			ଯଦି ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ଫେରନ୍ତୁ r;
		} ଅନ୍ୟଥା {
			ଯଦି ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ଫେରନ୍ତୁ r;
		}
		ମୁକ୍ତ(name);
		ମୁକ୍ତ(val);
	}
	ଫେରନ୍ତୁ sshpkt_get_end(ssh);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ନିବେଶ_newkeys(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, initial = (kex->flags & KEX_INITIAL) != 0;
	ଅକ୍ଷର *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ଯଦି (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, &kex_ନିବେଶ_ext_info);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEXINIT, &kex_ନିବେଶ_kexinit);
	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ଯଦି ((r = kex_buf2prop(kex->my, ଖାଲି, &prop)) != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ଖାଲି) {
			error_f("match_filter_denylist failed");
			ଯାଅ fail;
		}
		ମୁକ୍ତ(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ଯଦି ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			ମୁକ୍ତ(prop);
			ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		ମୁକ୍ତ(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_send_kexinit(ସଂରଚନା ssh *ssh)
{
	u_char *cookie;
	ସଂରଚନା kex *kex = ssh->kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (kex == ଖାଲି) {
		error_f("no kex");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଯଦି (kex->flags & KEX_INIT_SENT)
		ଫେରନ୍ତୁ 0;
	kex->done = 0;

	/* generate a random cookie */
	ଯଦି (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଯଦି ((cookie = sshbuf_mutable_ptr(kex->my)) == ଖାଲି) {
		error_f("buffer error");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ଫେରନ୍ତୁ r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ନିବେଶ_kexinit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ଅଚଳ u_char *ptr;
	u_int i;
	size_t dlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("SSH2_MSG_KEXINIT received");
	ଯଦି (kex == ଖାଲି) {
		error_f("no kex");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ମୁକ୍ତ(kex->name);
	kex->name = ଖାଲି;
	ଯଦି ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ଯଦି ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ଫେରନ୍ତୁ r;

	/* discard packet */
	ପାଇଁ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ଯଦି ((r = sshpkt_get_u8(ssh, ଖାଲି)) != 0) {
			error_fr(r, "discard cookie");
			ଫେରନ୍ତୁ r;
		}
	}
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଯଦି ((r = sshpkt_get_string(ssh, ଖାଲି, ଖାଲି)) != 0) {
			error_fr(r, "discard proposal");
			ଫେରନ୍ତୁ r;
		}
	}
	/*
	 * XXX RFC4253 sec 7: "each side MAY guess" - currently no supported
	 * KEX method has the server move first, but a server might be using
	 * a custom method or one that we otherwise don't support. We should
	 * be prepared to remember first_kex_follows here so we can eat a
	 * packet later.
	 * XXX2 - RFC4253 is kind of ambiguous on what first_kex_follows means
	 * for cases where the server *doesn't* go first. I guess we should
	 * ignore it when it is set for these cases, which is what we do now.
	 */
	ଯଦି ((r = sshpkt_get_u8(ssh, ଖାଲି)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ଖାଲି)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			ଫେରନ୍ତୁ r;

	ଯଦି (!(kex->flags & KEX_INIT_SENT))
		ଯଦି ((r = kex_send_kexinit(ssh)) != 0)
			ଫେରନ୍ତୁ r;
	ଯଦି ((r = kex_choose_conf(ssh, seq)) != 0)
		ଫେରନ୍ତୁ r;

	ଯଦି (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ଖାଲି)
		ଫେରନ୍ତୁ (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
}

ସଂରଚନା kex *
kex_new(ଶୂନ୍ୟ)
{
	ସଂରଚନା kex *kex;

	ଯଦି ((kex = calloc(1, ଆକାର(*kex))) == ଖାଲି ||
	    (kex->peer = sshbuf_new()) == ଖାଲି ||
	    (kex->my = sshbuf_new()) == ଖାଲି ||
	    (kex->client_version = sshbuf_new()) == ଖାଲି ||
	    (kex->server_version = sshbuf_new()) == ଖାଲି ||
	    (kex->session_id = sshbuf_new()) == ଖାଲି) {
		kex_free(kex);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ kex;
}

ଶୂନ୍ୟ
kex_free_newkeys(ସଂରଚନା newkeys *newkeys)
{
	ଯଦି (newkeys == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (newkeys->enc.ଚାବି) {
		explicit_bzero(newkeys->enc.ଚାବି, newkeys->enc.ଚାବି_len);
		ମୁକ୍ତ(newkeys->enc.ଚାବି);
		newkeys->enc.ଚାବି = ଖାଲି;
	}
	ଯଦି (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		ମୁକ୍ତ(newkeys->enc.iv);
		newkeys->enc.iv = ଖାଲି;
	}
	ମୁକ୍ତ(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, ଆକାର(newkeys->enc));
	ମୁକ୍ତ(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, ଆକାର(newkeys->comp));
	mac_clear(&newkeys->mac);
	ଯଦି (newkeys->mac.ଚାବି) {
		explicit_bzero(newkeys->mac.ଚାବି, newkeys->mac.ଚାବି_len);
		ମୁକ୍ତ(newkeys->mac.ଚାବି);
		newkeys->mac.ଚାବି = ଖାଲି;
	}
	ମୁକ୍ତ(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, ଆକାର(newkeys->mac));
	freezero(newkeys, ଆକାର(*newkeys));
}

ଶୂନ୍ୟ
kex_free(ସଂରଚନା kex *kex)
{
	u_int mode;

	ଯଦି (kex == ଖାଲି)
		ଫେରନ୍ତୁ;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_ଚାବି_free(kex->ec_client_ଚାବି);
#endif /* WITH_OPENSSL */
	ପାଇଁ (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = ଖାଲି;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	ମୁକ୍ତ(kex->failed_choice);
	ମୁକ୍ତ(kex->hostkey_alg);
	ମୁକ୍ତ(kex->name);
	ମୁକ୍ତ(kex->server_sig_algs);
	ମୁକ୍ତ(kex);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ready(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *proposal[PROPOSAL_MAX])
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ଫେରନ୍ତୁ r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEXINIT, &kex_ନିବେଶ_kexinit);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_setup(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *proposal[PROPOSAL_MAX])
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = kex_ready(ssh, proposal)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ଖାଲି;
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_start_rekex(ସଂରଚନା ssh *ssh)
{
	ଯଦି (ssh->kex == ଖାଲି) {
		error_f("no kex");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଯଦି (ssh->kex->done == 0) {
		error_f("requested twice");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	ଫେରନ୍ତୁ kex_send_kexinit(ssh);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
choose_enc(ସଂରଚନା sshenc *enc, ଅକ୍ଷର *client, ଅକ୍ଷର *server)
{
	ଅକ୍ଷର *name = match_list(client, server, ଖାଲି);

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_NO_CIPHER_ALG_MATCH;
	ଯଦି ((enc->cipher = cipher_by_name(name)) == ଖାଲି) {
		error_f("unsupported cipher %s", name);
		ମୁକ୍ତ(name);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ଖାଲି;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->ଚାବି = ଖାଲି;
	enc->ଚାବି_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
choose_mac(ସଂରଚନା ssh *ssh, ସଂରଚନା sshmac *mac, ଅକ୍ଷର *client, ଅକ୍ଷର *server)
{
	ଅକ୍ଷର *name = match_list(client, server, ଖାଲି);

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_NO_MAC_ALG_MATCH;
	ଯଦି (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		ମୁକ୍ତ(name);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->ଚାବି = ଖାଲି;
	mac->enabled = 0;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
choose_comp(ସଂରଚନା sshcomp *comp, ଅକ୍ଷର *client, ଅକ୍ଷର *server)
{
	ଅକ୍ଷର *name = match_list(client, server, ଖାଲି);

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	ଯଦି (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} ଅନ୍ୟଥା
#endif	/* WITH_ZLIB */
	ଯଦି (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} ଅନ୍ୟଥା {
		error_f("unsupported compression scheme %s", name);
		ମୁକ୍ତ(name);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
choose_kex(ସଂରଚନା kex *k, ଅକ୍ଷର *client, ଅକ୍ଷର *server)
{
	k->name = match_list(client, server, ଖାଲି);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ଯଦି (k->name == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_NO_KEX_ALG_MATCH;
	ଯଦି (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
choose_hostkeyalg(ସଂରଚନା kex *k, ଅକ୍ଷର *client, ଅକ୍ଷର *server)
{
	ମୁକ୍ତ(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, ଖାଲି);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ଯଦି (k->hostkey_alg == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ଯଦି (k->hostkey_type == ଚାବି_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
proposals_match(ଅକ୍ଷର *my[PROPOSAL_MAX], ଅକ୍ଷର *peer[PROPOSAL_MAX])
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_ଚାବି_ALGS, -1
	};
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା *idx;
	ଅକ୍ଷର *p;

	ପାଇଁ (idx = &check[0]; *idx != -1; idx++) {
		ଯଦି ((p = strchr(my[*idx], ',')) != ଖାଲି)
			*p = '\0';
		ଯଦି ((p = strchr(peer[*idx], ',')) != ଖାଲି)
			*p = '\0';
		ଯଦି (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ଫେରନ୍ତୁ (0);
		}
	}
	debug2("proposals match");
	ଫେରନ୍ତୁ (1);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kexalgs_contains(ଅକ୍ଷର **peer, ଅଚଳ ଅକ୍ଷର *ext)
{
	ଫେରନ୍ତୁ kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_choose_conf(ସଂରଚନା ssh *ssh, uint32_t seq)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ସଂରଚନା newkeys *newkeys;
	ଅକ୍ଷର **my = ଖାଲି, **peer = ଖାଲି;
	ଅକ୍ଷର **cprop, **sprop;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ଯଦି ((r = kex_buf2prop(kex->my, ଖାଲି, &my)) != 0)
		ଯାଅ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ଯଦି ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		ଯାଅ out;

	ଯଦି (kex->server) {
		cprop=peer;
		sprop=my;
	} ଅନ୍ୟଥା {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ଯଦି ((kex->flags & KEX_INITIAL) != 0) {
		ଯଦି (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} ଅନ୍ୟଥା {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ଯଦି (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ଯଦି (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ଯଦି (kex->server && (kex->flags & KEX_INITIAL)) {
		ଯଦି (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ଚାବି_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ଯଦି (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ଚାବି_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ଯଦି ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ଖାଲି;
		ଯାଅ out;
	}
	ଯଦି ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_ଚାବି_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_ଚାବି_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_ଚାବି_ALGS];
		peer[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = ଖାଲି;
		ଯାଅ out;
	}
	ପାଇଁ (mode = 0; mode < MODE_MAX; mode++) {
		ଯଦି ((newkeys = calloc(1, ଆକାର(*newkeys))) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ଯଦି ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ଖାଲି;
			ଯାଅ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ଯଦି (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ଖାଲି;
			ଯାଅ out;
		}
		ଯଦି ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ଖାଲି;
			ଯାଅ out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	ପାଇଁ (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.ଚାବି_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.ଚାବି_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.ଚାବି_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	ଯଦି (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
derive_ଚାବି(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, u_int need, u_char *hash, u_int hashlen,
    ଅଚଳ ସଂରଚନା sshbuf *shared_secret, u_char **keyp)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ସଂରଚନା ssh_digest_ctx *hashctx = ଖାଲି;
	ଅକ୍ଷର c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((digest = calloc(1, ROUNDUP(need, mdsz))) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ଯଦି ((hashctx = ssh_digest_start(kex->hash_alg)) == ଖାଲି ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		ଯାଅ out;
	}
	ssh_digest_free(hashctx);
	hashctx = ଖାଲି;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	ପାଇଁ (have = mdsz; need > have; have += mdsz) {
		ଯଦି ((hashctx = ssh_digest_start(kex->hash_alg)) == ଖାଲି ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		ssh_digest_free(hashctx);
		hashctx = ଖାଲି;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = ଖାଲି;
	r = 0;
 out:
	ମୁକ୍ତ(digest);
	ssh_digest_free(hashctx);
	ଫେରନ୍ତୁ r;
}

#define NKEYS	6
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_derive_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା ssh *ssh, u_char *hash, u_int hashlen,
    ଅଚଳ ସଂରଚନା sshbuf *shared_secret)
{
	ସଂରଚନା kex *kex = ssh->kex;
	u_char *ଚାବିଗୁଡ଼ିକ[NKEYS];
	u_int i, j, mode, ctos;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* save initial hash as session id */
	ଯଦି ((kex->flags & KEX_INITIAL) != 0) {
		ଯଦି (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
		}
		ଯଦି ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ଫେରନ୍ତୁ r;
	} ଅନ୍ୟଥା ଯଦି (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ପାଇଁ (i = 0; i < NKEYS; i++) {
		ଯଦି ((r = derive_ଚାବି(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &ଚାବିଗୁଡ଼ିକ[i])) != 0) {
			ପାଇଁ (j = 0; j < i; j++)
				ମୁକ୍ତ(ଚାବିଗୁଡ଼ିକ[j]);
			ଫେରନ୍ତୁ r;
		}
	}
	ପାଇଁ (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = ଚାବିଗୁଡ଼ିକ[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.ଚାବି = ଚାବିଗୁଡ଼ିକ[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.ଚାବି = ଚାବିଗୁଡ଼ିକ[ctos ? 4 : 5];
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_load_hostkey(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey **prvp, ସଂରଚନା sshkey **pubp)
{
	ସଂରଚନା kex *kex = ssh->kex;

	*pubp = ଖାଲି;
	*prvp = ଖାଲି;
	ଯଦି (kex->load_host_public_ଚାବି == ଖାଲି ||
	    kex->load_host_private_ଚାବି == ଖାଲି) {
		error_f("missing hostkey loader");
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_ଚାବି(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_ଚାବି(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ଯଦି (*pubp == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_NO_HOSTKEY_LOADED;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_verify_host_ଚାବି(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey *server_host_ଚାବି)
{
	ସଂରଚନା kex *kex = ssh->kex;

	ଯଦି (kex->verify_host_ଚାବି == ଖାଲି) {
		error_f("missing hostkey verifier");
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	ଯଦି (server_host_ଚାବି->type != kex->hostkey_type ||
	    (kex->hostkey_type == ଚାବି_ECDSA &&
	    server_host_ଚାବି->ecdsa_nid != kex->hostkey_nid))
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_MISMATCH;
	ଯଦି (kex->verify_host_ଚାବି(server_host_ଚାବି, ssh) == -1)
		ଫେରନ୍ତୁ  SSH_ERR_SIGNATURE_INVALID;
	ଫେରନ୍ତୁ 0;
}

#ଯଦି defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ଶୂନ୍ୟ
dump_digest(ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ, ଅଚଳ u_char *digest, ପୂର୍ଣ୍ଣସଂଖ୍ୟା len)
{
	fprintf(stderr, "%s\n", ସନ୍ଦେଶ);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ସ୍ଥିର ଶୂନ୍ୟ
send_error(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *ସନ୍ଦେଶ)
{
	ଅକ୍ଷର *crnl = "\r\n";

	ଯଦି (!ssh->kex->server)
		ଫେରନ୍ତୁ;

	ଯଦି (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    ସନ୍ଦେଶ, strlen(ସନ୍ଦେଶ)) != strlen(ସନ୍ଦେଶ) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_exchange_identification(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout_ms,
    ଅଚଳ ଅକ୍ଷର *version_addendum)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, expect_nl;
	u_char c;
	ସଂରଚନା sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	ସଂରଚନା sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	ଅକ୍ଷର *our_version_string = ଖାଲି, *peer_version_string = ଖାଲି;
	ଅକ୍ଷର *cp, *remote_version = ଖାଲି;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	ଯଦି (version_addendum != ଖାଲି && *version_addendum == '\0')
		version_addendum = ଖାଲି;
	ଯଦି ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == ଖାଲି ? "" : " ",
	    version_addendum == ଖାଲି ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		ଯାଅ out;
	}

	ଯଦି (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		ଯାଅ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	ଯଦି (our_version_string == ଖାଲି) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	ପାଇଁ (n = 0; ; n++) {
		ଯଦି (n >= SSH_MAX_PRE_BANNER_ଧାଡ଼ିଗୁଡ଼ିକ) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_ଧାଡ଼ିଗୁଡ଼ିକ);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		ପାଇଁ (;;) {
			ଯଦି (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, ଖାଲି);
				ଯଦି (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					ଯାଅ out;
				} ଅନ୍ୟଥା ଯଦି (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					ଯାଅ out;
				}
			}

			len = atomicio(ପଠ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			ଯଦି (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				ଯାଅ out;
			} ଅନ୍ୟଥା ଯଦି (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				ଯାଅ out;
			}
			ଯଦି (c == '\r') {
				expect_nl = 1;
				ଜାରି;
			}
			ଯଦି (c == '\n')
				ଭାଙ୍ଗ;
			ଯଦି (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				ଯାଅ invalid;
			}
			ଯଦି ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				ଯାଅ out;
			}
			ଯଦି (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				ଯାଅ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ଯଦି (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			ଭାଙ୍ଗ;
		/* If not, then just log the line and continue */
		ଯଦି ((cp = sshbuf_dup_string(peer_version)) == ଖାଲି) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		/* Do not accept lines before the SSH ident from a client */
		ଯଦି (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			ମୁକ୍ତ(cp);
			ଯାଅ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		ମୁକ୍ତ(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	ଯଦି (peer_version_string == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ଯଦି ((remote_version = calloc(1, sshbuf_len(peer_version))) == ଖାଲି) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ଯଦି (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	ବାଛ (remote_major) {
	ସ୍ଥିତି 2:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 1:
		ଯଦି (remote_minor != 99)
			mismatch = 1;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		mismatch = 1;
		ଭାଙ୍ଗ;
	}
	ଯଦି (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		ଯାଅ out;
	}

	ଯଦି (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ଯାଅ out;
	}
	ଯଦି (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(our_version_string);
	ମୁକ୍ତ(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	ଯଦି (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ଫେରନ୍ତୁ r;
}

