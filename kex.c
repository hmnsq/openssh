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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#endif

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

/* prototype */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ kex_choose_conf(ಸಂರಚನಾ ssh *, uint32_t seq);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ kex_ಒಳಹರಿವು_newkeys(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ proposal_names[PROPOSAL_MAX] = {
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
ಶೂನ್ಯ
kex_proposal_populate_entries(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *prop[PROPOSAL_MAX],
    ಧ್ರುವ ವರ್ಣ *kexalgos, ಧ್ರುವ ವರ್ಣ *ciphers, ಧ್ರುವ ವರ್ಣ *macs,
    ಧ್ರುವ ವರ್ಣ *comp, ಧ್ರುವ ವರ್ಣ *hkalgs)
{
	ಧ್ರುವ ವರ್ಣ *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ಧ್ರುವ ವರ್ಣ *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ಧ್ರುವ ವರ್ಣ **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	ವರ್ಣ *cp;

	ಯದಿ (prop == ರಿಕ್ತ)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ಯದಿ (kexalgos == ರಿಕ್ತ)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ಯದಿ ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ರಿಕ್ತ)
		fatal_f("kex_names_cat");

	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ವಿಕಲ್ಪ(i) {
		ಪಕ್ಷ PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			ಭಙ್ಗ;
		ಪಕ್ಷ PROPOSAL_ENC_ALGS_CTOS:
		ಪಕ್ಷ PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			ಭಙ್ಗ;
		ಪಕ್ಷ PROPOSAL_MAC_ALGS_CTOS:
		ಪಕ್ಷ PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			ಭಙ್ಗ;
		ಪಕ್ಷ PROPOSAL_COMP_ALGS_CTOS:
		ಪಕ್ಷ PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			ಭಙ್ಗ;
		ಪಕ್ಷ PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	ಮುಕ್ತ(cp);
}

ಶೂನ್ಯ
kex_proposal_free_entries(ವರ್ಣ *prop[PROPOSAL_MAX])
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(prop[i]);
}

/* put algorithm proposal into buffer */
ಪೂರ್ಣಾಙ್ಕ
kex_prop2buf(ಸಂರಚನಾ sshbuf *b, ವರ್ಣ *proposal[PROPOSAL_MAX])
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	ಪ್ರತಿ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ಯದಿ ((r = sshbuf_put_u8(b, 0)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* parse buffer and return algorithm proposal */
ಪೂರ್ಣಾಙ್ಕ
kex_buf2prop(ಸಂರಚನಾ sshbuf *raw, ಪೂರ್ಣಾಙ್ಕ *first_kex_follows, ವರ್ಣ ***propp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	u_char v;
	u_int i;
	ವರ್ಣ **proposal = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*propp = ರಿಕ್ತ;
	ಯದಿ ((proposal = calloc(PROPOSAL_MAX, ಪರಿಮಾಣ(ವರ್ಣ *))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((b = sshbuf_fromb(raw)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		ಗಚ್ಛ out;
	}
	/* extract kex init proposal strings */
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಯದಿ ((r = sshbuf_get_cstring(b, &(proposal[i]), ರಿಕ್ತ)) != 0) {
			error_fr(r, "parse proposal %u", i);
			ಗಚ್ಛ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ಯದಿ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		ಗಚ್ಛ out;
	}
	ಯದಿ (first_kex_follows != ರಿಕ್ತ)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	ಯದಿ (r != 0 && proposal != ರಿಕ್ತ)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಶೂನ್ಯ
kex_prop_free(ವರ್ಣ **proposal)
{
	u_int i;

	ಯದಿ (proposal == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(proposal[i]);
	ಮುಕ್ತ(proposal);
}

ಪೂರ್ಣಾಙ್ಕ
kex_protocol_error(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	/* If in strict mode, any unexpected message is an error */
	ಯದಿ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
kex_reset_dispatch(ಸಂರಚನಾ ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_ಸಂದೇಶ_TRANSPORT_MIN,
	    SSH2_ಸಂದೇಶ_TRANSPORT_MAX, &kex_protocol_error);
}

ಶೂನ್ಯ
kex_set_server_sig_algs(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *allowed_algs)
{
	ವರ್ಣ *alg, *oalgs, *algs, *sigalgs;
	ಧ್ರುವ ವರ್ಣ *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ಯದಿ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ರಿಕ್ತ)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	ಮುಕ್ತ(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ರಿಕ್ತ;
	ಪ್ರತಿ ((alg = strsep(&algs, ",")); alg != ರಿಕ್ತ && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ಯದಿ ((sigalg = sshkey_sigalg_by_name(alg)) == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (!kex_has_any_alg(sigalg, sigalgs))
			ಅನುವರ್ತ;
		/* Don't add an algorithm twice. */
		ಯದಿ (ssh->kex->server_sig_algs != ರಿಕ್ತ &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			ಅನುವರ್ತ;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	ಮುಕ್ತ(oalgs);
	ಮುಕ್ತ(sigalgs);
	ಯದಿ (ssh->kex->server_sig_algs == ರಿಕ್ತ)
		ssh->kex->server_sig_algs = xstrdup("");
}

ಶೂನ್ಯ
kex_set_warn_weak_crypto(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ warn_weak_crypto)
{
	ಯದಿ (ssh != ರಿಕ್ತ && ssh->kex != ರಿಕ್ತ)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

ಶೂನ್ಯ
kex_check_warn_weak_crypto(ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ remote_id[512];
	ಪೂರ್ಣಾಙ್ಕ rekeyed = 0;

	ಯದಿ (ssh == ರಿಕ್ತ || ssh->kex == ರಿಕ್ತ || ssh->kex->name == ರಿಕ್ತ ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ಯದಿ (!rekeyed && !ssh->kex->server)
		ಪ್ರತ್ಯಾಗಮ; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, ಪರಿಮಾಣ(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_compose_ext_info_server(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ssh->kex->server_sig_algs == ರಿಕ್ತ &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_compose_ext_info_client(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *m)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_maybe_send_ext_info(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *m = ರಿಕ್ತ;

	ಯದಿ ((ssh->kex->flags & KEX_INITIAL) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Compose EXT_INFO packet. */
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		ಗಚ್ಛ fail;
	ಯದಿ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		ಗಚ್ಛ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ಗಚ್ಛ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_server_update_ext_info(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_send_newkeys(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	kex_reset_dispatch(ssh);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_NEWKEYS, &kex_ಒಳಹರಿವು_newkeys);
	ಯದಿ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Check whether an ext_info value contains the expected version string */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_ext_info_check_ver(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ವರ್ಣ *name,
    ಧ್ರುವ u_char *val, size_t len, ಧ್ರುವ ವರ್ಣ *want_ver, u_int flag)
{
	ಯದಿ (memchr(val, '\0', len) != ರಿಕ್ತ) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ಯದಿ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	ಅನ್ಯಥಾ
		debug_f("unsupported version of %s extension", name);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_ext_info_client_parse(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *name,
    ಧ್ರುವ u_char *ಮೌಲ್ಯ, size_t vlen)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ಯದಿ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ಯದಿ (memchr(ಮೌಲ್ಯ, '\0', vlen) != ರಿಕ್ತ) {
			error_f("nul byte in %s", name);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, ಮೌಲ್ಯ);
		ಮುಕ್ತ(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ಧ್ರುವ ವರ್ಣ *)ಮೌಲ್ಯ);
	} ಅನ್ಯಥಾ ಯದಿ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ಯದಿ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ಪ್ರತ್ಯಾಗಮ r;
		}
	} ಅನ್ಯಥಾ ಯದಿ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ಯದಿ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ಪ್ರತ್ಯಾಗಮ r;
		}
	} ಅನ್ಯಥಾ ಯದಿ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ಯದಿ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ಪ್ರತ್ಯಾಗಮ r;
		}
	} ಅನ್ಯಥಾ
		debug_f("%s (unrecognised)", name);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_ext_info_server_parse(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *name,
    ಧ್ರುವ u_char *ಮೌಲ್ಯ, size_t vlen)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ಯದಿ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			ಪ್ರತ್ಯಾಗಮ r;
		}
	} ಅನ್ಯಥಾ
		debug_f("%s (unrecognised)", name);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_ಒಳಹರಿವು_ext_info(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	ವರ್ಣ *name;
	u_char *val;
	size_t vlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("SSH2_MSG_EXT_INFO received");
	ಯದಿ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ಪ್ರತ್ಯಾಗಮ dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &kex_protocol_error);
	ಯದಿ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ಪ್ರತ್ಯಾಗಮ dispatch_protocol_error(type, seq, ssh);
	}
	ಪ್ರತಿ (i = 0; i < ninfo; i++) {
		ಯದಿ ((r = sshpkt_get_cstring(ssh, &name, ರಿಕ್ತ)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			ಮುಕ್ತ(name);
			ಪ್ರತ್ಯಾಗಮ r;
		}
		debug3_f("extension %s", name);
		ಯದಿ (kex->server) {
			ಯದಿ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ಪ್ರತ್ಯಾಗಮ r;
		} ಅನ್ಯಥಾ {
			ಯದಿ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ಪ್ರತ್ಯಾಗಮ r;
		}
		ಮುಕ್ತ(name);
		ಮುಕ್ತ(val);
	}
	ಪ್ರತ್ಯಾಗಮ sshpkt_get_end(ssh);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_ಒಳಹರಿವು_newkeys(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಙ್ಕ r, initial = (kex->flags & KEX_INITIAL) != 0;
	ವರ್ಣ *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ಯದಿ (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);
	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ಯದಿ ((r = kex_buf2prop(kex->my, ರಿಕ್ತ, &prop)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ರಿಕ್ತ) {
			error_f("match_filter_denylist failed");
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ಯದಿ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			ಮುಕ್ತ(prop);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		ಮುಕ್ತ(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_send_kexinit(ಸಂರಚನಾ ssh *ssh)
{
	u_char *cookie;
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (kex == ರಿಕ್ತ) {
		error_f("no kex");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಯದಿ (kex->flags & KEX_INIT_SENT)
		ಪ್ರತ್ಯಾಗಮ 0;
	kex->done = 0;

	/* generate a random cookie */
	ಯದಿ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಯದಿ ((cookie = sshbuf_mutable_ptr(kex->my)) == ರಿಕ್ತ) {
		error_f("buffer error");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_ಒಳಹರಿವು_kexinit(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಧ್ರುವ u_char *ptr;
	u_int i;
	size_t dlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("SSH2_MSG_KEXINIT received");
	ಯದಿ (kex == ರಿಕ್ತ) {
		error_f("no kex");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಮುಕ್ತ(kex->name);
	kex->name = ರಿಕ್ತ;
	ಯದಿ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ಯದಿ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* discard packet */
	ಪ್ರತಿ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ಯದಿ ((r = sshpkt_get_u8(ssh, ರಿಕ್ತ)) != 0) {
			error_fr(r, "discard cookie");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಯದಿ ((r = sshpkt_get_string(ssh, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) {
			error_fr(r, "discard proposal");
			ಪ್ರತ್ಯಾಗಮ r;
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
	ಯದಿ ((r = sshpkt_get_u8(ssh, ರಿಕ್ತ)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ರಿಕ್ತ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;

	ಯದಿ (!(kex->flags & KEX_INIT_SENT))
		ಯದಿ ((r = kex_send_kexinit(ssh)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = kex_choose_conf(ssh, seq)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಯದಿ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
}

ಸಂರಚನಾ kex *
kex_new(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ kex *kex;

	ಯದಿ ((kex = calloc(1, ಪರಿಮಾಣ(*kex))) == ರಿಕ್ತ ||
	    (kex->peer = sshbuf_new()) == ರಿಕ್ತ ||
	    (kex->my = sshbuf_new()) == ರಿಕ್ತ ||
	    (kex->client_version = sshbuf_new()) == ರಿಕ್ತ ||
	    (kex->server_version = sshbuf_new()) == ರಿಕ್ತ ||
	    (kex->session_id = sshbuf_new()) == ರಿಕ್ತ) {
		kex_free(kex);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ kex;
}

ಶೂನ್ಯ
kex_free_newkeys(ಸಂರಚನಾ newkeys *newkeys)
{
	ಯದಿ (newkeys == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (newkeys->enc.ಕೀಲಿ) {
		explicit_bzero(newkeys->enc.ಕೀಲಿ, newkeys->enc.ಕೀಲಿ_len);
		ಮುಕ್ತ(newkeys->enc.ಕೀಲಿ);
		newkeys->enc.ಕೀಲಿ = ರಿಕ್ತ;
	}
	ಯದಿ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		ಮುಕ್ತ(newkeys->enc.iv);
		newkeys->enc.iv = ರಿಕ್ತ;
	}
	ಮುಕ್ತ(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, ಪರಿಮಾಣ(newkeys->enc));
	ಮುಕ್ತ(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, ಪರಿಮಾಣ(newkeys->comp));
	mac_clear(&newkeys->mac);
	ಯದಿ (newkeys->mac.ಕೀಲಿ) {
		explicit_bzero(newkeys->mac.ಕೀಲಿ, newkeys->mac.ಕೀಲಿ_len);
		ಮುಕ್ತ(newkeys->mac.ಕೀಲಿ);
		newkeys->mac.ಕೀಲಿ = ರಿಕ್ತ;
	}
	ಮುಕ್ತ(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, ಪರಿಮಾಣ(newkeys->mac));
	freezero(newkeys, ಪರಿಮಾಣ(*newkeys));
}

ಶೂನ್ಯ
kex_free(ಸಂರಚನಾ kex *kex)
{
	u_int mode;

	ಯದಿ (kex == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_ಕೀಲಿ_free(kex->ec_client_ಕೀಲಿ);
#endif /* WITH_OPENSSL */
	ಪ್ರತಿ (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = ರಿಕ್ತ;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	ಮುಕ್ತ(kex->failed_choice);
	ಮುಕ್ತ(kex->hostkey_alg);
	ಮುಕ್ತ(kex->name);
	ಮುಕ್ತ(kex->server_sig_algs);
	ಮುಕ್ತ(kex);
}

ಪೂರ್ಣಾಙ್ಕ
kex_ready(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *proposal[PROPOSAL_MAX])
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_setup(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *proposal[PROPOSAL_MAX])
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = kex_ready(ssh, proposal)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
ಪೂರ್ಣಾಙ್ಕ
kex_start_rekex(ಸಂರಚನಾ ssh *ssh)
{
	ಯದಿ (ssh->kex == ರಿಕ್ತ) {
		error_f("no kex");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಯದಿ (ssh->kex->done == 0) {
		error_f("requested twice");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	ಪ್ರತ್ಯಾಗಮ kex_send_kexinit(ssh);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
choose_enc(ಸಂರಚನಾ sshenc *enc, ವರ್ಣ *client, ವರ್ಣ *server)
{
	ವರ್ಣ *name = match_list(client, server, ರಿಕ್ತ);

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_CIPHER_ALG_MATCH;
	ಯದಿ ((enc->cipher = cipher_by_name(name)) == ರಿಕ್ತ) {
		error_f("unsupported cipher %s", name);
		ಮುಕ್ತ(name);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ರಿಕ್ತ;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->ಕೀಲಿ = ರಿಕ್ತ;
	enc->ಕೀಲಿ_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
choose_mac(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshmac *mac, ವರ್ಣ *client, ವರ್ಣ *server)
{
	ವರ್ಣ *name = match_list(client, server, ರಿಕ್ತ);

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_MAC_ALG_MATCH;
	ಯದಿ (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		ಮುಕ್ತ(name);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->ಕೀಲಿ = ರಿಕ್ತ;
	mac->enabled = 0;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
choose_comp(ಸಂರಚನಾ sshcomp *comp, ವರ್ಣ *client, ವರ್ಣ *server)
{
	ವರ್ಣ *name = match_list(client, server, ರಿಕ್ತ);

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	ಯದಿ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} ಅನ್ಯಥಾ
#endif	/* WITH_ZLIB */
	ಯದಿ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} ಅನ್ಯಥಾ {
		error_f("unsupported compression scheme %s", name);
		ಮುಕ್ತ(name);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
choose_kex(ಸಂರಚನಾ kex *k, ವರ್ಣ *client, ವರ್ಣ *server)
{
	k->name = match_list(client, server, ರಿಕ್ತ);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ಯದಿ (k->name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_KEX_ALG_MATCH;
	ಯದಿ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
choose_hostkeyalg(ಸಂರಚನಾ kex *k, ವರ್ಣ *client, ವರ್ಣ *server)
{
	ಮುಕ್ತ(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, ರಿಕ್ತ);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ಯದಿ (k->hostkey_alg == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ಯದಿ (k->hostkey_type == ಕೀಲಿ_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
proposals_match(ವರ್ಣ *my[PROPOSAL_MAX], ವರ್ಣ *peer[PROPOSAL_MAX])
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS, -1
	};
	ಪೂರ್ಣಾಙ್ಕ *idx;
	ವರ್ಣ *p;

	ಪ್ರತಿ (idx = &check[0]; *idx != -1; idx++) {
		ಯದಿ ((p = strchr(my[*idx], ',')) != ರಿಕ್ತ)
			*p = '\0';
		ಯದಿ ((p = strchr(peer[*idx], ',')) != ರಿಕ್ತ)
			*p = '\0';
		ಯದಿ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ಪ್ರತ್ಯಾಗಮ (0);
		}
	}
	debug2("proposals match");
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kexalgs_contains(ವರ್ಣ **peer, ಧ್ರುವ ವರ್ಣ *ext)
{
	ಪ್ರತ್ಯಾಗಮ kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_choose_conf(ಸಂರಚನಾ ssh *ssh, uint32_t seq)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಸಂರಚನಾ newkeys *newkeys;
	ವರ್ಣ **my = ರಿಕ್ತ, **peer = ರಿಕ್ತ;
	ವರ್ಣ **cprop, **sprop;
	ಪೂರ್ಣಾಙ್ಕ nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	ಪೂರ್ಣಾಙ್ಕ r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ಯದಿ ((r = kex_buf2prop(kex->my, ರಿಕ್ತ, &my)) != 0)
		ಗಚ್ಛ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ಯದಿ ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (kex->server) {
		cprop=peer;
		sprop=my;
	} ಅನ್ಯಥಾ {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ಯದಿ ((kex->flags & KEX_INITIAL) != 0) {
		ಯದಿ (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} ಅನ್ಯಥಾ {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ಯದಿ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ಯದಿ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ಯದಿ (kex->server && (kex->flags & KEX_INITIAL)) {
		ಯದಿ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ಯದಿ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ಯದಿ ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ರಿಕ್ತ;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS];
		peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = ರಿಕ್ತ;
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (mode = 0; mode < MODE_MAX; mode++) {
		ಯದಿ ((newkeys = calloc(1, ಪರಿಮಾಣ(*newkeys))) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ಯದಿ ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ರಿಕ್ತ;
			ಗಚ್ಛ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ಯದಿ (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ರಿಕ್ತ;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ರಿಕ್ತ;
			ಗಚ್ಛ out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	ಪ್ರತಿ (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.ಕೀಲಿ_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.ಕೀಲಿ_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.ಕೀಲಿ_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	ಯದಿ (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
derive_ಕೀಲಿ(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, u_int need, u_char *hash, u_int hashlen,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *shared_secret, u_char **keyp)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಸಂರಚನಾ ssh_digest_ctx *hashctx = ರಿಕ್ತ;
	ವರ್ಣ c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((digest = calloc(1, ROUNDUP(need, mdsz))) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ಯದಿ ((hashctx = ssh_digest_start(kex->hash_alg)) == ರಿಕ್ತ ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		ಗಚ್ಛ out;
	}
	ssh_digest_free(hashctx);
	hashctx = ರಿಕ್ತ;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	ಪ್ರತಿ (have = mdsz; need > have; have += mdsz) {
		ಯದಿ ((hashctx = ssh_digest_start(kex->hash_alg)) == ರಿಕ್ತ ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		ssh_digest_free(hashctx);
		hashctx = ರಿಕ್ತ;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = ರಿಕ್ತ;
	r = 0;
 out:
	ಮುಕ್ತ(digest);
	ssh_digest_free(hashctx);
	ಪ್ರತ್ಯಾಗಮ r;
}

#define NKEYS	6
ಪೂರ್ಣಾಙ್ಕ
kex_derive_ಕೀಲಿಗಳು(ಸಂರಚನಾ ssh *ssh, u_char *hash, u_int hashlen,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *shared_secret)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	u_char *ಕೀಲಿಗಳು[NKEYS];
	u_int i, j, mode, ctos;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* save initial hash as session id */
	ಯದಿ ((kex->flags & KEX_INITIAL) != 0) {
		ಯದಿ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
		}
		ಯದಿ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	} ಅನ್ಯಥಾ ಯದಿ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತಿ (i = 0; i < NKEYS; i++) {
		ಯದಿ ((r = derive_ಕೀಲಿ(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &ಕೀಲಿಗಳು[i])) != 0) {
			ಪ್ರತಿ (j = 0; j < i; j++)
				ಮುಕ್ತ(ಕೀಲಿಗಳು[j]);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತಿ (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = ಕೀಲಿಗಳು[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.ಕೀಲಿ = ಕೀಲಿಗಳು[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.ಕೀಲಿ = ಕೀಲಿಗಳು[ctos ? 4 : 5];
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_load_hostkey(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey **prvp, ಸಂರಚನಾ sshkey **pubp)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;

	*pubp = ರಿಕ್ತ;
	*prvp = ರಿಕ್ತ;
	ಯದಿ (kex->load_host_public_ಕೀಲಿ == ರಿಕ್ತ ||
	    kex->load_host_private_ಕೀಲಿ == ರಿಕ್ತ) {
		error_f("missing hostkey loader");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_ಕೀಲಿ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_ಕೀಲಿ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ಯದಿ (*pubp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_HOSTKEY_LOADED;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_verify_host_ಕೀಲಿ(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *server_host_ಕೀಲಿ)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;

	ಯದಿ (kex->verify_host_ಕೀಲಿ == ರಿಕ್ತ) {
		error_f("missing hostkey verifier");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	ಯದಿ (server_host_ಕೀಲಿ->type != kex->hostkey_type ||
	    (kex->hostkey_type == ಕೀಲಿ_ECDSA &&
	    server_host_ಕೀಲಿ->ecdsa_nid != kex->hostkey_nid))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
	ಯದಿ (kex->verify_host_ಕೀಲಿ(server_host_ಕೀಲಿ, ssh) == -1)
		ಪ್ರತ್ಯಾಗಮ  SSH_ERR_SIGNATURE_INVALID;
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ಯದಿ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ಶೂನ್ಯ
dump_digest(ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ, ಧ್ರುವ u_char *digest, ಪೂರ್ಣಾಙ್ಕ len)
{
	fprintf(stderr, "%s\n", ಸಂದೇಶ);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
send_error(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *ಸಂದೇಶ)
{
	ವರ್ಣ *crnl = "\r\n";

	ಯದಿ (!ssh->kex->server)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    ಸಂದೇಶ, strlen(ಸಂದೇಶ)) != strlen(ಸಂದೇಶ) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
kex_exchange_identification(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ timeout_ms,
    ಧ್ರುವ ವರ್ಣ *version_addendum)
{
	ಪೂರ್ಣಾಙ್ಕ remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	ಪೂರ್ಣಾಙ್ಕ r, expect_nl;
	u_char c;
	ಸಂರಚನಾ sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	ಸಂರಚನಾ sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	ವರ್ಣ *our_version_string = ರಿಕ್ತ, *peer_version_string = ರಿಕ್ತ;
	ವರ್ಣ *cp, *remote_version = ರಿಕ್ತ;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	ಯದಿ (version_addendum != ರಿಕ್ತ && *version_addendum == '\0')
		version_addendum = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == ರಿಕ್ತ ? "" : " ",
	    version_addendum == ರಿಕ್ತ ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		ಗಚ್ಛ out;
	}

	ಯದಿ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		ಗಚ್ಛ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	ಯದಿ (our_version_string == ರಿಕ್ತ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	ಪ್ರತಿ (n = 0; ; n++) {
		ಯದಿ (n >= SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		ಪ್ರತಿ (;;) {
			ಯದಿ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, ರಿಕ್ತ);
				ಯದಿ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					ಗಚ್ಛ out;
				} ಅನ್ಯಥಾ ಯದಿ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					ಗಚ್ಛ out;
				}
			}

			len = atomicio(ಪಠ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			ಯದಿ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				ಗಚ್ಛ out;
			} ಅನ್ಯಥಾ ಯದಿ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				ಗಚ್ಛ out;
			}
			ಯದಿ (c == '\r') {
				expect_nl = 1;
				ಅನುವರ್ತ;
			}
			ಯದಿ (c == '\n')
				ಭಙ್ಗ;
			ಯದಿ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				ಗಚ್ಛ invalid;
			}
			ಯದಿ ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				ಗಚ್ಛ out;
			}
			ಯದಿ (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				ಗಚ್ಛ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ಯದಿ (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			ಭಙ್ಗ;
		/* If not, then just log the line and continue */
		ಯದಿ ((cp = sshbuf_dup_string(peer_version)) == ರಿಕ್ತ) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		/* Do not accept lines before the SSH ident from a client */
		ಯದಿ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			ಮುಕ್ತ(cp);
			ಗಚ್ಛ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		ಮುಕ್ತ(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	ಯದಿ (peer_version_string == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ಯದಿ ((remote_version = calloc(1, sshbuf_len(peer_version))) == ರಿಕ್ತ) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ಯದಿ (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	ವಿಕಲ್ಪ (remote_major) {
	ಪಕ್ಷ 2:
		ಭಙ್ಗ;
	ಪಕ್ಷ 1:
		ಯದಿ (remote_minor != 99)
			mismatch = 1;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		mismatch = 1;
		ಭಙ್ಗ;
	}
	ಯದಿ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		ಗಚ್ಛ out;
	}

	ಯದಿ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ಗಚ್ಛ out;
	}
	ಯದಿ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(our_version_string);
	ಮುಕ್ತ(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	ಯದಿ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

