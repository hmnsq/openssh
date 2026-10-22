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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/dh.h>
#అయితే_ముగింపు

#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "version.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "myproposal.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "xmalloc.h"

/* prototype */
స్థిర పూర్ణాంకం kex_ఎంచుకో_conf(నిర్మాణం ssh *, uint32_t seq);
స్థిర పూర్ణాంకం kex_ఆదానం_newkeys(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి proposal_పేర్లు[PROPOSAL_MAX] = {
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
శూన్య
kex_proposal_populate_entries(నిర్మాణం ssh *ssh, అక్షరం *prop[PROPOSAL_MAX],
    స్థిరరాశి అక్షరం *kexalgos, స్థిరరాశి అక్షరం *ciphers, స్థిరరాశి అక్షరం *macs,
    స్థిరరాశి అక్షరం *comp, స్థిరరాశి అక్షరం *hkalgs)
{
	స్థిరరాశి అక్షరం *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	స్థిరరాశి అక్షరం *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	స్థిరరాశి అక్షరం **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	అక్షరం *cp;

	ఒకవేళ (prop == ఖాళీ)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ఒకవేళ (kexalgos == ఖాళీ)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ఒకవేళ ((cp = kex_పేర్లు_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ఖాళీ)
		fatal_f("kex_names_cat");

	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		ఎంపిక(i) {
		స్థితి PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			ఆపు;
		స్థితి PROPOSAL_ENC_ALGS_CTOS:
		స్థితి PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			ఆపు;
		స్థితి PROPOSAL_MAC_ALGS_CTOS:
		స్థితి PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			ఆపు;
		స్థితి PROPOSAL_COMP_ALGS_CTOS:
		స్థితి PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			ఆపు;
		స్థితి PROPOSAL_SERVER_HOST_కీలకం_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			ఆపు;
		అప్రమేయ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	విడుదల(cp);
}

శూన్య
kex_proposal_free_entries(అక్షరం *prop[PROPOSAL_MAX])
{
	u_int i;

	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(prop[i]);
}

/* put algorithm proposal into buffer */
పూర్ణాంకం
kex_prop2buf(నిర్మాణం sshbuf *b, అక్షరం *proposal[PROPOSAL_MAX])
{
	u_int i;
	పూర్ణాంకం r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	కొరకు (i = 0; i < KEX_COOKIE_LEN; i++) {
		ఒకవేళ ((r = sshbuf_put_u8(b, 0)) != 0)
			తిరిగి r;
	}
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		తిరిగి r;
	తిరిగి 0;
}

/* parse buffer and return algorithm proposal */
పూర్ణాంకం
kex_buf2prop(నిర్మాణం sshbuf *raw, పూర్ణాంకం *మొదటి_kex_follows, అక్షరం ***propp)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	u_char v;
	u_int i;
	అక్షరం **proposal = ఖాళీ;
	పూర్ణాంకం r;

	*propp = ఖాళీ;
	ఒకవేళ ((proposal = సున్నా_జ్ఞాపకం_ఇవ్వు(PROPOSAL_MAX, పరిమాణం(అక్షరం *))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((b = sshbuf_fromb(raw)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		వెళ్ళు బహిర్గతం;
	}
	/* extract kex init proposal strings */
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		ఒకవేళ ((r = sshbuf_get_cstring(b, &(proposal[i]), ఖాళీ)) != 0) {
			error_fr(r, "parse proposal %u", i);
			వెళ్ళు బహిర్గతం;
		}
		debug2("%s: %s", proposal_పేర్లు[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ఒకవేళ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (మొదటి_kex_follows != ఖాళీ)
		*మొదటి_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 బహిర్గతం:
	ఒకవేళ (r != 0 && proposal != ఖాళీ)
		kex_prop_free(proposal);
	sshbuf_free(b);
	తిరిగి r;
}

శూన్య
kex_prop_free(అక్షరం **proposal)
{
	u_int i;

	ఒకవేళ (proposal == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(proposal[i]);
	విడుదల(proposal);
}

పూర్ణాంకం
kex_protocol_error(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	/* If in strict mode, any unexpected message is an error */
	ఒకవేళ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర శూన్య
kex_reset_dispatch(నిర్మాణం ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_సందేశం_TRANSPORT_MIN,
	    SSH2_సందేశం_TRANSPORT_MAX, &kex_protocol_error);
}

శూన్య
kex_సమితి_server_sig_algs(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *allowed_algs)
{
	అక్షరం *alg, *oalgs, *algs, *sigalgs;
	స్థిరరాశి అక్షరం *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ఒకవేళ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ఖాళీ)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	విడుదల(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ఖాళీ;
	కొరకు ((alg = strsep(&algs, ",")); alg != ఖాళీ && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ఒకవేళ ((sigalg = sshkey_sigalg_by_name(alg)) == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (!kex_has_any_alg(sigalg, sigalgs))
			కొనసాగు;
		/* Don't add an algorithm twice. */
		ఒకవేళ (ssh->kex->server_sig_algs != ఖాళీ &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			కొనసాగు;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	విడుదల(oalgs);
	విడుదల(sigalgs);
	ఒకవేళ (ssh->kex->server_sig_algs == ఖాళీ)
		ssh->kex->server_sig_algs = xstrdup("");
}

శూన్య
kex_సమితి_warn_weak_crypto(నిర్మాణం ssh *ssh, పూర్ణాంకం warn_weak_crypto)
{
	ఒకవేళ (ssh != ఖాళీ && ssh->kex != ఖాళీ)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

శూన్య
kex_check_warn_weak_crypto(నిర్మాణం ssh *ssh)
{
	అక్షరం remote_id[512];
	పూర్ణాంకం rekeyed = 0;

	ఒకవేళ (ssh == ఖాళీ || ssh->kex == ఖాళీ || ssh->kex->name == ఖాళీ ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		తిరిగి;
	ఒకవేళ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		తిరిగి;
	}

	ఒకవేళ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ఒకవేళ (!rekeyed && !ssh->kex->server)
		తిరిగి; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, పరిమాణం(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

స్థిర పూర్ణాంకం
kex_compose_ext_info_server(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;

	ఒకవేళ (ssh->kex->server_sig_algs == ఖాళీ &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
kex_compose_ext_info_client(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *m)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	తిరిగి r;
}

స్థిర పూర్ణాంకం
kex_maybe_send_ext_info(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;
	నిర్మాణం sshbuf *m = ఖాళీ;

	ఒకవేళ ((ssh->kex->flags & KEX_INITIAL) == 0)
		తిరిగి 0;
	ఒకవేళ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		తిరిగి 0;

	/* Compose EXT_INFO packet. */
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		వెళ్ళు fail;
	ఒకవేళ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		వెళ్ళు fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		వెళ్ళు fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	తిరిగి r;
}

పూర్ణాంకం
kex_server_update_ext_info(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	ఒకవేళ ((ssh->kex->flags & KEX_HAS_EXT_INFO_లోపల_AUTH) == 0)
		తిరిగి 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		తిరిగి r;
	}
	తిరిగి 0;
}

పూర్ణాంకం
kex_send_newkeys(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	kex_reset_dispatch(ssh);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		తిరిగి r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_NEWKEYS, &kex_ఆదానం_newkeys);
	ఒకవేళ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		తిరిగి r;
	debug("expecting SSH2_MSG_NEWKEYS");
	తిరిగి 0;
}

/* Check whether an ext_info value contains the expected version string */
స్థిర పూర్ణాంకం
kex_ext_info_check_ver(నిర్మాణం kex *kex, స్థిరరాశి అక్షరం *name,
    స్థిరరాశి u_char *val, కొలత_t len, స్థిరరాశి అక్షరం *want_ver, u_int flag)
{
	ఒకవేళ (memchr(val, '\0', len) != ఖాళీ) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ఒకవేళ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	లేకపోతే
		debug_f("unsupported version of %s extension", name);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
kex_ext_info_client_parse(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *name,
    స్థిరరాశి u_char *విలువ, కొలత_t vlen)
{
	పూర్ణాంకం r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ఒకవేళ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ఒకవేళ (memchr(విలువ, '\0', vlen) != ఖాళీ) {
			error_f("nul byte in %s", name);
			తిరిగి SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, విలువ);
		విడుదల(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((స్థిరరాశి అక్షరం *)విలువ);
	} లేకపోతే ఒకవేళ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ఒకవేళ ((r = kex_ext_info_check_ver(ssh->kex, name, విలువ, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			తిరిగి r;
		}
	} లేకపోతే ఒకవేళ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ఒకవేళ ((r = kex_ext_info_check_ver(ssh->kex, name, విలువ, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			తిరిగి r;
		}
	} లేకపోతే ఒకవేళ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ఒకవేళ ((r = kex_ext_info_check_ver(ssh->kex, name, విలువ, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			తిరిగి r;
		}
	} లేకపోతే
		debug_f("%s (unrecognised)", name);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
kex_ext_info_server_parse(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *name,
    స్థిరరాశి u_char *విలువ, కొలత_t vlen)
{
	పూర్ణాంకం r;

	ఒకవేళ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ఒకవేళ ((r = kex_ext_info_check_ver(ssh->kex, name, విలువ, vlen,
		    "0", KEX_HAS_EXT_INFO_లోపల_AUTH)) != 0) {
			తిరిగి r;
		}
	} లేకపోతే
		debug_f("%s (unrecognised)", name);
	తిరిగి 0;
}

పూర్ణాంకం
kex_ఆదానం_ext_info(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	స్థిరరాశి పూర్ణాంకం max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	అక్షరం *name;
	u_char *val;
	కొలత_t vlen;
	పూర్ణాంకం r;

	debug("SSH2_MSG_EXT_INFO received");
	ఒకవేళ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		తిరిగి dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, &kex_protocol_error);
	ఒకవేళ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		తిరిగి r;
	ఒకవేళ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		తిరిగి dispatch_protocol_error(type, seq, ssh);
	}
	కొరకు (i = 0; i < ninfo; i++) {
		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &name, ఖాళీ)) != 0)
			తిరిగి r;
		ఒకవేళ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			విడుదల(name);
			తిరిగి r;
		}
		debug3_f("extension %s", name);
		ఒకవేళ (kex->server) {
			ఒకవేళ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				తిరిగి r;
		} లేకపోతే {
			ఒకవేళ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				తిరిగి r;
		}
		విడుదల(name);
		విడుదల(val);
	}
	తిరిగి sshpkt_get_చివర(ssh);
}

స్థిర పూర్ణాంకం
kex_ఆదానం_newkeys(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	పూర్ణాంకం r, initial = (kex->flags & KEX_INITIAL) != 0;
	అక్షరం *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ఒకవేళ (kex->ext_info_c && initial)
		ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, &kex_ఆదానం_ext_info);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEXINIT, &kex_ఆదానం_kexinit);
	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = ssh_సమితి_newkeys(ssh, బహుళకం_లోపల)) != 0)
		తిరిగి r;
	ఒకవేళ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ఒకవేళ ((r = kex_buf2prop(kex->my, ఖాళీ, &prop)) != 0)
			తిరిగి r;
		ఒకవేళ ((cp = సరిపోలిక_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ఖాళీ) {
			error_f("match_filter_denylist failed");
			వెళ్ళు fail;
		}
		విడుదల(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ఒకవేళ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			విడుదల(prop);
			తిరిగి SSH_ERR_అంతర్గత_ERROR;
		}
		kex_proposal_free_entries(prop);
		విడుదల(prop);
	}
	kex->పూర్తి = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_పంపిన|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	తిరిగి 0;
}

పూర్ణాంకం
kex_send_kexinit(నిర్మాణం ssh *ssh)
{
	u_char *cookie;
	నిర్మాణం kex *kex = ssh->kex;
	పూర్ణాంకం r;

	ఒకవేళ (kex == ఖాళీ) {
		error_f("no kex");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	ఒకవేళ (kex->flags & KEX_INIT_పంపిన)
		తిరిగి 0;
	kex->పూర్తి = 0;

	/* generate a random cookie */
	ఒకవేళ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	ఒకవేళ ((cookie = sshbuf_mutable_ptr(kex->my)) == ఖాళీ) {
		error_f("buffer error");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		తిరిగి r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_పంపిన;
	తిరిగి 0;
}

పూర్ణాంకం
kex_ఆదానం_kexinit(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	స్థిరరాశి u_char *ptr;
	u_int i;
	కొలత_t dlen;
	పూర్ణాంకం r;

	debug("SSH2_MSG_KEXINIT received");
	ఒకవేళ (kex == ఖాళీ) {
		error_f("no kex");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	విడుదల(kex->name);
	kex->name = ఖాళీ;
	ఒకవేళ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ఒకవేళ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		తిరిగి r;

	/* discard packet */
	కొరకు (i = 0; i < KEX_COOKIE_LEN; i++) {
		ఒకవేళ ((r = sshpkt_get_u8(ssh, ఖాళీ)) != 0) {
			error_fr(r, "discard cookie");
			తిరిగి r;
		}
	}
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		ఒకవేళ ((r = sshpkt_get_string(ssh, ఖాళీ, ఖాళీ)) != 0) {
			error_fr(r, "discard proposal");
			తిరిగి r;
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
	ఒకవేళ ((r = sshpkt_get_u8(ssh, ఖాళీ)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ఖాళీ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_చివర(ssh)) != 0)
			తిరిగి r;

	ఒకవేళ (!(kex->flags & KEX_INIT_పంపిన))
		ఒకవేళ ((r = kex_send_kexinit(ssh)) != 0)
			తిరిగి r;
	ఒకవేళ ((r = kex_ఎంచుకో_conf(ssh, seq)) != 0)
		తిరిగి r;

	ఒకవేళ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ఖాళీ)
		తిరిగి (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	తిరిగి SSH_ERR_అంతర్గత_ERROR;
}

నిర్మాణం kex *
kex_new(శూన్య)
{
	నిర్మాణం kex *kex;

	ఒకవేళ ((kex = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*kex))) == ఖాళీ ||
	    (kex->peer = sshbuf_new()) == ఖాళీ ||
	    (kex->my = sshbuf_new()) == ఖాళీ ||
	    (kex->client_సంస్కరణ = sshbuf_new()) == ఖాళీ ||
	    (kex->server_సంస్కరణ = sshbuf_new()) == ఖాళీ ||
	    (kex->session_id = sshbuf_new()) == ఖాళీ) {
		kex_free(kex);
		తిరిగి ఖాళీ;
	}
	తిరిగి kex;
}

శూన్య
kex_free_newkeys(నిర్మాణం newkeys *newkeys)
{
	ఒకవేళ (newkeys == ఖాళీ)
		తిరిగి;
	ఒకవేళ (newkeys->enc.కీలకం) {
		explicit_bzero(newkeys->enc.కీలకం, newkeys->enc.కీలకం_len);
		విడుదల(newkeys->enc.కీలకం);
		newkeys->enc.కీలకం = ఖాళీ;
	}
	ఒకవేళ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		విడుదల(newkeys->enc.iv);
		newkeys->enc.iv = ఖాళీ;
	}
	విడుదల(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, పరిమాణం(newkeys->enc));
	విడుదల(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, పరిమాణం(newkeys->comp));
	mac_clear(&newkeys->mac);
	ఒకవేళ (newkeys->mac.కీలకం) {
		explicit_bzero(newkeys->mac.కీలకం, newkeys->mac.కీలకం_len);
		విడుదల(newkeys->mac.కీలకం);
		newkeys->mac.కీలకం = ఖాళీ;
	}
	విడుదల(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, పరిమాణం(newkeys->mac));
	freezero(newkeys, పరిమాణం(*newkeys));
}

శూన్య
kex_free(నిర్మాణం kex *kex)
{
	u_int బహుళకం;

	ఒకవేళ (kex == ఖాళీ)
		తిరిగి;

#నిర్వచితమైతే WITH_OPENSSL
	DH_free(kex->dh);
	EC_కీలకం_free(kex->ec_client_కీలకం);
#అయితే_ముగింపు /* WITH_OPENSSL */
	కొరకు (బహుళకం = 0; బహుళకం < బహుళకం_MAX; బహుళకం++) {
		kex_free_newkeys(kex->newkeys[బహుళకం]);
		kex->newkeys[బహుళకం] = ఖాళీ;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_సంస్కరణ);
	sshbuf_free(kex->server_సంస్కరణ);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	విడుదల(kex->failed_choice);
	విడుదల(kex->hostkey_alg);
	విడుదల(kex->name);
	విడుదల(kex->server_sig_algs);
	విడుదల(kex);
}

పూర్ణాంకం
kex_ready(నిర్మాణం ssh *ssh, అక్షరం *proposal[PROPOSAL_MAX])
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		తిరిగి r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEXINIT, &kex_ఆదానం_kexinit);
	తిరిగి 0;
}

పూర్ణాంకం
kex_అమరిక(నిర్మాణం ssh *ssh, అక్షరం *proposal[PROPOSAL_MAX])
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = kex_ready(ssh, proposal)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ఖాళీ;
		తిరిగి r;
	}
	తిరిగి 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
పూర్ణాంకం
kex_ప్రారంభం_rekex(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (ssh->kex == ఖాళీ) {
		error_f("no kex");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	ఒకవేళ (ssh->kex->పూర్తి == 0) {
		error_f("requested twice");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	ssh->kex->పూర్తి = 0;
	తిరిగి kex_send_kexinit(ssh);
}

స్థిర పూర్ణాంకం
ఎంచుకో_enc(నిర్మాణం sshenc *enc, అక్షరం *client, అక్షరం *server)
{
	అక్షరం *name = సరిపోలిక_list(client, server, ఖాళీ);

	ఒకవేళ (name == ఖాళీ)
		తిరిగి SSH_ERR_NO_CIPHER_ALG_సరిపోలిక;
	ఒకవేళ ((enc->cipher = cipher_by_name(name)) == ఖాళీ) {
		error_f("unsupported cipher %s", name);
		విడుదల(name);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ఖాళీ;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->కీలకం = ఖాళీ;
	enc->కీలకం_len = cipher_keylen(enc->cipher);
	enc->ఖండం_కొలత = cipher_blocksize(enc->cipher);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఎంచుకో_mac(నిర్మాణం ssh *ssh, నిర్మాణం sshmac *mac, అక్షరం *client, అక్షరం *server)
{
	అక్షరం *name = సరిపోలిక_list(client, server, ఖాళీ);

	ఒకవేళ (name == ఖాళీ)
		తిరిగి SSH_ERR_NO_MAC_ALG_సరిపోలిక;
	ఒకవేళ (mac_అమరిక(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		విడుదల(name);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	mac->name = name;
	mac->కీలకం = ఖాళీ;
	mac->enabled = 0;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఎంచుకో_comp(నిర్మాణం sshcomp *comp, అక్షరం *client, అక్షరం *server)
{
	అక్షరం *name = సరిపోలిక_list(client, server, ఖాళీ);

	ఒకవేళ (name == ఖాళీ)
		తిరిగి SSH_ERR_NO_COMPRESS_ALG_సరిపోలిక;
#నిర్వచితమైతే WITH_ZLIB
	ఒకవేళ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} లేకపోతే
#అయితే_ముగింపు	/* WITH_ZLIB */
	ఒకవేళ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} లేకపోతే {
		error_f("unsupported compression scheme %s", name);
		విడుదల(name);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	comp->name = name;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఎంచుకో_kex(నిర్మాణం kex *k, అక్షరం *client, అక్షరం *server)
{
	k->name = సరిపోలిక_list(client, server, ఖాళీ);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ఒకవేళ (k->name == ఖాళీ)
		తిరిగి SSH_ERR_NO_KEX_ALG_సరిపోలిక;
	ఒకవేళ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఎంచుకో_hostkeyalg(నిర్మాణం kex *k, అక్షరం *client, అక్షరం *server)
{
	విడుదల(k->hostkey_alg);
	k->hostkey_alg = సరిపోలిక_list(client, server, ఖాళీ);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ఒకవేళ (k->hostkey_alg == ఖాళీ)
		తిరిగి SSH_ERR_NO_HOSTKEY_ALG_సరిపోలిక;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ఒకవేళ (k->hostkey_type == కీలకం_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
proposals_సరిపోలిక(అక్షరం *my[PROPOSAL_MAX], అక్షరం *peer[PROPOSAL_MAX])
{
	స్థిర పూర్ణాంకం check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_కీలకం_ALGS, -1
	};
	పూర్ణాంకం *idx;
	అక్షరం *p;

	కొరకు (idx = &check[0]; *idx != -1; idx++) {
		ఒకవేళ ((p = strchr(my[*idx], ',')) != ఖాళీ)
			*p = '\0';
		ఒకవేళ ((p = strchr(peer[*idx], ',')) != ఖాళీ)
			*p = '\0';
		ఒకవేళ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			తిరిగి (0);
		}
	}
	debug2("proposals match");
	తిరిగి (1);
}

స్థిర పూర్ణాంకం
kexalgs_కలిగియుంది(అక్షరం **peer, స్థిరరాశి అక్షరం *ext)
{
	తిరిగి kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

స్థిర పూర్ణాంకం
kex_ఎంచుకో_conf(నిర్మాణం ssh *ssh, uint32_t seq)
{
	నిర్మాణం kex *kex = ssh->kex;
	నిర్మాణం newkeys *newkeys;
	అక్షరం **my = ఖాళీ, **peer = ఖాళీ;
	అక్షరం **cprop, **sprop;
	పూర్ణాంకం nenc, nmac, ncomp;
	u_int బహుళకం, ctos, need, dh_need, authlen;
	పూర్ణాంకం r, మొదటి_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ఒకవేళ ((r = kex_buf2prop(kex->my, ఖాళీ, &my)) != 0)
		వెళ్ళు బహిర్గతం;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ఒకవేళ ((r = kex_buf2prop(kex->peer, &మొదటి_kex_follows, &peer)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (kex->server) {
		cprop=peer;
		sprop=my;
	} లేకపోతే {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ఒకవేళ ((kex->flags & KEX_INITIAL) != 0) {
		ఒకవేళ (kex->server) {
			kex->ext_info_c = kexalgs_కలిగియుంది(peer, "ext-info-c");
			kex->kex_strict = kexalgs_కలిగియుంది(peer,
			    "kex-strict-c-v00@openssh.com");
		} లేకపోతే {
			kex->ext_info_s = kexalgs_కలిగియుంది(peer, "ext-info-s");
			kex->kex_strict = kexalgs_కలిగియుంది(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ఒకవేళ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ఒకవేళ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ఒకవేళ (kex->server && (kex->flags & KEX_INITIAL)) {
		ఒకవేళ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_కీలకం_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ఒకవేళ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_కీలకం_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ఒకవేళ ((r = ఎంచుకో_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ఖాళీ;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ఎంచుకో_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_కీలకం_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_కీలకం_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_కీలకం_ALGS];
		peer[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = ఖాళీ;
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (బహుళకం = 0; బహుళకం < బహుళకం_MAX; బహుళకం++) {
		ఒకవేళ ((newkeys = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*newkeys))) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		kex->newkeys[బహుళకం] = newkeys;
		ctos = (!kex->server && బహుళకం == బహుళకం_బహిర్గతం) ||
		    (kex->server && బహుళకం == బహుళకం_లోపల);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ఒకవేళ ((r = ఎంచుకో_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ఖాళీ;
			వెళ్ళు బహిర్గతం;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ఒకవేళ (authlen == 0 &&
		    (r = ఎంచుకో_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ఖాళీ;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = ఎంచుకో_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ఖాళీ;
			వెళ్ళు బహిర్గతం;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	కొరకు (బహుళకం = 0; బహుళకం < బహుళకం_MAX; బహుళకం++) {
		newkeys = kex->newkeys[బహుళకం];
		need = గరిష్ఠ(need, newkeys->enc.కీలకం_len);
		need = గరిష్ఠ(need, newkeys->enc.ఖండం_కొలత);
		need = గరిష్ఠ(need, newkeys->enc.iv_len);
		need = గరిష్ఠ(need, newkeys->mac.కీలకం_len);
		dh_need = గరిష్ఠ(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = గరిష్ఠ(dh_need, newkeys->enc.ఖండం_కొలత);
		dh_need = గరిష్ఠ(dh_need, newkeys->enc.iv_len);
		dh_need = గరిష్ఠ(dh_need, newkeys->mac.కీలకం_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	ఒకవేళ (మొదటి_kex_follows && !proposals_సరిపోలిక(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 బహిర్గతం:
	kex_prop_free(my);
	kex_prop_free(peer);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
derive_కీలకం(నిర్మాణం ssh *ssh, పూర్ణాంకం id, u_int need, u_char *hash, u_int hashlen,
    స్థిరరాశి నిర్మాణం sshbuf *shared_secret, u_char **keyp)
{
	నిర్మాణం kex *kex = ssh->kex;
	నిర్మాణం ssh_digest_ctx *hashctx = ఖాళీ;
	అక్షరం c = id;
	u_int have;
	కొలత_t mdsz;
	u_char *digest;
	పూర్ణాంకం r;

	ఒకవేళ ((mdsz = ssh_digest_బైట్లు(kex->hash_alg)) == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((digest = సున్నా_జ్ఞాపకం_ఇవ్వు(1, ROUNDUP(need, mdsz))) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ఒకవేళ ((hashctx = ssh_digest_ప్రారంభం(kex->hash_alg)) == ఖాళీ ||
	    ssh_digest_update_బఫరు(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_బఫరు(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		వెళ్ళు బహిర్గతం;
	}
	ssh_digest_free(hashctx);
	hashctx = ఖాళీ;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	కొరకు (have = mdsz; need > have; have += mdsz) {
		ఒకవేళ ((hashctx = ssh_digest_ప్రారంభం(kex->hash_alg)) == ఖాళీ ||
		    ssh_digest_update_బఫరు(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ssh_digest_free(hashctx);
		hashctx = ఖాళీ;
	}
#నిర్వచితమైతే DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#అయితే_ముగింపు
	*keyp = digest;
	digest = ఖాళీ;
	r = 0;
 బహిర్గతం:
	విడుదల(digest);
	ssh_digest_free(hashctx);
	తిరిగి r;
}

#నిర్వచించు NKEYS	6
పూర్ణాంకం
kex_derive_కీలకాలు(నిర్మాణం ssh *ssh, u_char *hash, u_int hashlen,
    స్థిరరాశి నిర్మాణం sshbuf *shared_secret)
{
	నిర్మాణం kex *kex = ssh->kex;
	u_char *కీలకాలు[NKEYS];
	u_int i, j, బహుళకం, ctos;
	పూర్ణాంకం r;

	/* save initial hash as session id */
	ఒకవేళ ((kex->flags & KEX_INITIAL) != 0) {
		ఒకవేళ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			తిరిగి SSH_ERR_అంతర్గత_ERROR;
		}
		ఒకవేళ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			తిరిగి r;
	} లేకపోతే ఒకవేళ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	కొరకు (i = 0; i < NKEYS; i++) {
		ఒకవేళ ((r = derive_కీలకం(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &కీలకాలు[i])) != 0) {
			కొరకు (j = 0; j < i; j++)
				విడుదల(కీలకాలు[j]);
			తిరిగి r;
		}
	}
	కొరకు (బహుళకం = 0; బహుళకం < బహుళకం_MAX; బహుళకం++) {
		ctos = (!kex->server && బహుళకం == బహుళకం_బహిర్గతం) ||
		    (kex->server && బహుళకం == బహుళకం_లోపల);
		kex->newkeys[బహుళకం]->enc.iv  = కీలకాలు[ctos ? 0 : 1];
		kex->newkeys[బహుళకం]->enc.కీలకం = కీలకాలు[ctos ? 2 : 3];
		kex->newkeys[బహుళకం]->mac.కీలకం = కీలకాలు[ctos ? 4 : 5];
	}
	తిరిగి 0;
}

పూర్ణాంకం
kex_ఎక్కించు_hostkey(నిర్మాణం ssh *ssh, నిర్మాణం sshkey **prvp, నిర్మాణం sshkey **pubp)
{
	నిర్మాణం kex *kex = ssh->kex;

	*pubp = ఖాళీ;
	*prvp = ఖాళీ;
	ఒకవేళ (kex->ఎక్కించు_host_ప్రజా_కీలకం == ఖాళీ ||
	    kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం == ఖాళీ) {
		error_f("missing hostkey loader");
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	*pubp = kex->ఎక్కించు_host_ప్రజా_కీలకం(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ఒకవేళ (*pubp == ఖాళీ)
		తిరిగి SSH_ERR_NO_HOSTKEY_LOADED;
	తిరిగి 0;
}

పూర్ణాంకం
kex_verify_host_కీలకం(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *server_host_కీలకం)
{
	నిర్మాణం kex *kex = ssh->kex;

	ఒకవేళ (kex->verify_host_కీలకం == ఖాళీ) {
		error_f("missing hostkey verifier");
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	ఒకవేళ (server_host_కీలకం->type != kex->hostkey_type ||
	    (kex->hostkey_type == కీలకం_ECDSA &&
	    server_host_కీలకం->ecdsa_nid != kex->hostkey_nid))
		తిరిగి SSH_ERR_కీలకం_TYPE_MISMATCH;
	ఒకవేళ (kex->verify_host_కీలకం(server_host_కీలకం, ssh) == -1)
		తిరిగి  SSH_ERR_SIGNATURE_INVALID;
	తిరిగి 0;
}

#ఒకవేళ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
శూన్య
dump_digest(స్థిరరాశి అక్షరం *సందేశం, స్థిరరాశి u_char *digest, పూర్ణాంకం len)
{
	fprintf(stderr, "%s\n", సందేశం);
	sshbuf_dump_దత్తాంశం(digest, len, stderr);
}
#అయితే_ముగింపు

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
స్థిర శూన్య
send_error(నిర్మాణం ssh *ssh, అక్షరం *సందేశం)
{
	అక్షరం *crnl = "\r\n";

	ఒకవేళ (!ssh->kex->server)
		తిరిగి;

	ఒకవేళ (atomicio(vwrite, ssh_packet_get_connection_బహిర్గతం(ssh),
	    సందేశం, అక్షరశ్రేణి_పొడవు(సందేశం)) != అక్షరశ్రేణి_పొడవు(సందేశం) ||
	    atomicio(vwrite, ssh_packet_get_connection_బహిర్గతం(ssh),
	    crnl, అక్షరశ్రేణి_పొడవు(crnl)) != అక్షరశ్రేణి_పొడవు(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
పూర్ణాంకం
kex_exchange_identification(నిర్మాణం ssh *ssh, పూర్ణాంకం timeout_ms,
    స్థిరరాశి అక్షరం *సంస్కరణ_addendum)
{
	పూర్ణాంకం remote_major, remote_minor, mismatch, oerrno = 0;
	కొలత_t len, n;
	పూర్ణాంకం r, expect_nl;
	u_char c;
	నిర్మాణం sshbuf *our_సంస్కరణ = ssh->kex->server ?
	    ssh->kex->server_సంస్కరణ : ssh->kex->client_సంస్కరణ;
	నిర్మాణం sshbuf *peer_సంస్కరణ = ssh->kex->server ?
	    ssh->kex->client_సంస్కరణ : ssh->kex->server_సంస్కరణ;
	అక్షరం *our_సంస్కరణ_string = ఖాళీ, *peer_సంస్కరణ_string = ఖాళీ;
	అక్షరం *cp, *remote_సంస్కరణ = ఖాళీ;

	/* Prepare and send our banner */
	sshbuf_reset(our_సంస్కరణ);
	ఒకవేళ (సంస్కరణ_addendum != ఖాళీ && *సంస్కరణ_addendum == '\0')
		సంస్కరణ_addendum = ఖాళీ;
	ఒకవేళ ((r = sshbuf_putf(our_సంస్కరణ, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_సంస్కరణ,
	    సంస్కరణ_addendum == ఖాళీ ? "" : " ",
	    సంస్కరణ_addendum == ఖాళీ ? "" : సంస్కరణ_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (atomicio(vwrite, ssh_packet_get_connection_బహిర్గతం(ssh),
	    sshbuf_mutable_ptr(our_సంస్కరణ),
	    sshbuf_len(our_సంస్కరణ)) != sshbuf_len(our_సంస్కరణ)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_consume_చివర(our_సంస్కరణ, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		వెళ్ళు బహిర్గతం;
	}
	our_సంస్కరణ_string = sshbuf_dup_string(our_సంస్కరణ);
	ఒకవేళ (our_సంస్కరణ_string == ఖాళీ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	debug("Local version string %.100s", our_సంస్కరణ_string);

	/* Read other side's version identification. */
	కొరకు (n = 0; ; n++) {
		ఒకవేళ (n >= SSH_MAX_PRE_BANNER_పంక్తులు) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_పంక్తులు);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		sshbuf_reset(peer_సంస్కరణ);
		expect_nl = 0;
		కొరకు (;;) {
			ఒకవేళ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_లోపల(ssh),
				    &timeout_ms, ఖాళీ);
				ఒకవేళ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					వెళ్ళు బహిర్గతం;
				} లేకపోతే ఒకవేళ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					వెళ్ళు బహిర్గతం;
				}
			}

			len = atomicio(పఠ, ssh_packet_get_connection_లోపల(ssh),
			    &c, 1);
			ఒకవేళ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				వెళ్ళు బహిర్గతం;
			} లేకపోతే ఒకవేళ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (c == '\r') {
				expect_nl = 1;
				కొనసాగు;
			}
			ఒకవేళ (c == '\n')
				ఆపు;
			ఒకవేళ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				వెళ్ళు invalid;
			}
			ఒకవేళ ((r = sshbuf_put_u8(peer_సంస్కరణ, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (sshbuf_len(peer_సంస్కరణ) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				వెళ్ళు invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ఒకవేళ (sshbuf_len(peer_సంస్కరణ) > 4 &&
		    memcmp(sshbuf_ptr(peer_సంస్కరణ), "SSH-", 4) == 0)
			ఆపు;
		/* If not, then just log the line and continue */
		ఒకవేళ ((cp = sshbuf_dup_string(peer_సంస్కరణ)) == ఖాళీ) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		/* Do not accept lines before the SSH ident from a client */
		ఒకవేళ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			విడుదల(cp);
			వెళ్ళు invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		విడుదల(cp);
	}
	peer_సంస్కరణ_string = sshbuf_dup_string(peer_సంస్కరణ);
	ఒకవేళ (peer_సంస్కరణ_string == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ఒకవేళ ((remote_సంస్కరణ = సున్నా_జ్ఞాపకం_ఇవ్వు(1, sshbuf_len(peer_సంస్కరణ))) == ఖాళీ) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ఒకవేళ (అక్షరశ్రేణి_చదువు(peer_సంస్కరణ_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_సంస్కరణ) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_సంస్కరణ_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_సంస్కరణ);
	compat_banner(ssh, remote_సంస్కరణ);

	mismatch = 0;
	ఎంపిక (remote_major) {
	స్థితి 2:
		ఆపు;
	స్థితి 1:
		ఒకవేళ (remote_minor != 99)
			mismatch = 1;
		ఆపు;
	అప్రమేయ:
		mismatch = 1;
		ఆపు;
	}
	ఒకవేళ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_సంస్కరణ;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
		    peer_సంస్కరణ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
		    peer_సంస్కరణ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(our_సంస్కరణ_string);
	విడుదల(peer_సంస్కరణ_string);
	ssh->remote_సంస్కరణ = remote_సంస్కరణ;  /* transferred */
	ఒకవేళ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	తిరిగి r;
}

