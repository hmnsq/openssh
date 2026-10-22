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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#ಆದರೆ_ಅಂತ್ಯ

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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ kex_ಆರಿಸು_conf(ರಚನೆ ssh *, uint32_t seq);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ kex_ಒಳಹರಿವು_newkeys(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ proposal_ಹೆಸರುಗಳು[PROPOSAL_MAX] = {
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
kex_proposal_populate_entries(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *prop[PROPOSAL_MAX],
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kexalgos, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ciphers, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *macs,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hkalgs)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	ಅಕ್ಷರ *cp;

	ಆದರೆ (prop == ಖಾಲಿ)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ಆದರೆ (kexalgos == ಖಾಲಿ)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ಆದರೆ ((cp = kex_ಹೆಸರುಗಳು_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ಖಾಲಿ)
		fatal_f("kex_names_cat");

	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಆಯ್ಕೆ(i) {
		ಸ್ಥಿತಿ PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ PROPOSAL_ENC_ALGS_CTOS:
		ಸ್ಥಿತಿ PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ PROPOSAL_MAC_ALGS_CTOS:
		ಸ್ಥಿತಿ PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ PROPOSAL_COMP_ALGS_CTOS:
		ಸ್ಥಿತಿ PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	ಬಿಡುಗಡೆ(cp);
}

ಶೂನ್ಯ
kex_proposal_free_entries(ಅಕ್ಷರ *prop[PROPOSAL_MAX])
{
	u_int i;

	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(prop[i]);
}

/* put algorithm proposal into buffer */
ಪೂರ್ಣಾಂಕ
kex_prop2buf(ರಚನೆ sshbuf *b, ಅಕ್ಷರ *proposal[PROPOSAL_MAX])
{
	u_int i;
	ಪೂರ್ಣಾಂಕ r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	ಗಾಗಿ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ಆದರೆ ((r = sshbuf_put_u8(b, 0)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

/* parse buffer and return algorithm proposal */
ಪೂರ್ಣಾಂಕ
kex_buf2prop(ರಚನೆ sshbuf *raw, ಪೂರ್ಣಾಂಕ *ಮೊದಲ_kex_follows, ಅಕ್ಷರ ***propp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	u_char v;
	u_int i;
	ಅಕ್ಷರ **proposal = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*propp = ಖಾಲಿ;
	ಆದರೆ ((proposal = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(PROPOSAL_MAX, ಗಾತ್ರ(ಅಕ್ಷರ *))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((b = sshbuf_fromb(raw)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* extract kex init proposal strings */
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಆದರೆ ((r = sshbuf_get_cstring(b, &(proposal[i]), ಖಾಲಿ)) != 0) {
			error_fr(r, "parse proposal %u", i);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug2("%s: %s", proposal_ಹೆಸರುಗಳು[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ಆದರೆ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ಮೊದಲ_kex_follows != ಖಾಲಿ)
		*ಮೊದಲ_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 ಹೊರಹೋಗು:
	ಆದರೆ (r != 0 && proposal != ಖಾಲಿ)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಶೂನ್ಯ
kex_prop_free(ಅಕ್ಷರ **proposal)
{
	u_int i;

	ಆದರೆ (proposal == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(proposal[i]);
	ಬಿಡುಗಡೆ(proposal);
}

ಪೂರ್ಣಾಂಕ
kex_protocol_error(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	/* If in strict mode, any unexpected message is an error */
	ಆದರೆ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
kex_reset_dispatch(ರಚನೆ ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_ಸಂದೇಶ_TRANSPORT_MIN,
	    SSH2_ಸಂದೇಶ_TRANSPORT_MAX, &kex_protocol_error);
}

ಶೂನ್ಯ
kex_ಗಣ_server_sig_algs(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowed_algs)
{
	ಅಕ್ಷರ *alg, *oalgs, *algs, *sigalgs;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ಆದರೆ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ಖಾಲಿ)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	ಬಿಡುಗಡೆ(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ಖಾಲಿ;
	ಗಾಗಿ ((alg = strsep(&algs, ",")); alg != ಖಾಲಿ && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ಆದರೆ ((sigalg = sshkey_sigalg_by_name(alg)) == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (!kex_has_any_alg(sigalg, sigalgs))
			ಮುಂದುವರಿ;
		/* Don't add an algorithm twice. */
		ಆದರೆ (ssh->kex->server_sig_algs != ಖಾಲಿ &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			ಮುಂದುವರಿ;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	ಬಿಡುಗಡೆ(oalgs);
	ಬಿಡುಗಡೆ(sigalgs);
	ಆದರೆ (ssh->kex->server_sig_algs == ಖಾಲಿ)
		ssh->kex->server_sig_algs = xstrdup("");
}

ಶೂನ್ಯ
kex_ಗಣ_warn_weak_crypto(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ warn_weak_crypto)
{
	ಆದರೆ (ssh != ಖಾಲಿ && ssh->kex != ಖಾಲಿ)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

ಶೂನ್ಯ
kex_check_warn_weak_crypto(ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ remote_id[512];
	ಪೂರ್ಣಾಂಕ rekeyed = 0;

	ಆದರೆ (ssh == ಖಾಲಿ || ssh->kex == ಖಾಲಿ || ssh->kex->name == ಖಾಲಿ ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ಆದರೆ (!rekeyed && !ssh->kex->server)
		ಹಿಂತಿರುಗಿ; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, ಗಾತ್ರ(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_compose_ext_info_server(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh->kex->server_sig_algs == ಖಾಲಿ &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_compose_ext_info_client(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *m)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_maybe_send_ext_info(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *m = ಖಾಲಿ;

	ಆದರೆ ((ssh->kex->flags & KEX_INITIAL) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ಹಿಂತಿರುಗಿ 0;

	/* Compose EXT_INFO packet. */
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		ಹೋಗು fail;
	ಆದರೆ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		ಹೋಗು fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ಹೋಗು fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_server_update_ext_info(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((ssh->kex->flags & KEX_HAS_EXT_INFO_ಒಳ_AUTH) == 0)
		ಹಿಂತಿರುಗಿ 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_send_newkeys(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	kex_reset_dispatch(ssh);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_NEWKEYS, &kex_ಒಳಹರಿವು_newkeys);
	ಆದರೆ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ಹಿಂತಿರುಗಿ 0;
}

/* Check whether an ext_info value contains the expected version string */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_ext_info_check_ver(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name,
    ಸ್ಥಿರಾಂಕ u_char *val, ಗಾತ್ರ_t len, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *want_ver, u_int flag)
{
	ಆದರೆ (memchr(val, '\0', len) != ಖಾಲಿ) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ಆದರೆ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	ಇಲ್ಲದಿದ್ದರೆ
		debug_f("unsupported version of %s extension", name);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_ext_info_client_parse(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name,
    ಸ್ಥಿರಾಂಕ u_char *ಮೌಲ್ಯ, ಗಾತ್ರ_t vlen)
{
	ಪೂರ್ಣಾಂಕ r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ಆದರೆ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ಆದರೆ (memchr(ಮೌಲ್ಯ, '\0', vlen) != ಖಾಲಿ) {
			error_f("nul byte in %s", name);
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, ಮೌಲ್ಯ);
		ಬಿಡುಗಡೆ(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)ಮೌಲ್ಯ);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ಆದರೆ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ಹಿಂತಿರುಗಿ r;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ಆದರೆ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ಹಿಂತಿರುಗಿ r;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ಆದರೆ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ಹಿಂತಿರುಗಿ r;
		}
	} ಇಲ್ಲದಿದ್ದರೆ
		debug_f("%s (unrecognised)", name);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_ext_info_server_parse(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name,
    ಸ್ಥಿರಾಂಕ u_char *ಮೌಲ್ಯ, ಗಾತ್ರ_t vlen)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ಆದರೆ ((r = kex_ext_info_check_ver(ssh->kex, name, ಮೌಲ್ಯ, vlen,
		    "0", KEX_HAS_EXT_INFO_ಒಳ_AUTH)) != 0) {
			ಹಿಂತಿರುಗಿ r;
		}
	} ಇಲ್ಲದಿದ್ದರೆ
		debug_f("%s (unrecognised)", name);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_ಒಳಹರಿವು_ext_info(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	ಅಕ್ಷರ *name;
	u_char *val;
	ಗಾತ್ರ_t vlen;
	ಪೂರ್ಣಾಂಕ r;

	debug("SSH2_MSG_EXT_INFO received");
	ಆದರೆ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ಹಿಂತಿರುಗಿ dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &kex_protocol_error);
	ಆದರೆ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ಹಿಂತಿರುಗಿ dispatch_protocol_error(type, seq, ssh);
	}
	ಗಾಗಿ (i = 0; i < ninfo; i++) {
		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &name, ಖಾಲಿ)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			ಬಿಡುಗಡೆ(name);
			ಹಿಂತಿರುಗಿ r;
		}
		debug3_f("extension %s", name);
		ಆದರೆ (kex->server) {
			ಆದರೆ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ಹಿಂತಿರುಗಿ r;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ಹಿಂತಿರುಗಿ r;
		}
		ಬಿಡುಗಡೆ(name);
		ಬಿಡುಗಡೆ(val);
	}
	ಹಿಂತಿರುಗಿ sshpkt_get_ಕೊನೆ(ssh);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_ಒಳಹರಿವು_newkeys(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಂಕ r, initial = (kex->flags & KEX_INITIAL) != 0;
	ಅಕ್ಷರ *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ಆದರೆ (kex->ext_info_c && initial)
		ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, &kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);
	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = ssh_ಗಣ_newkeys(ssh, ಬಹುಲಕ_ಒಳ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ಆದರೆ ((r = kex_buf2prop(kex->my, ಖಾಲಿ, &prop)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((cp = ಹೊಂದಿಕೆ_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ಖಾಲಿ) {
			error_f("match_filter_denylist failed");
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ಆದರೆ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			ಬಿಡುಗಡೆ(prop);
			ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
		}
		kex_proposal_free_entries(prop);
		ಬಿಡುಗಡೆ(prop);
	}
	kex->ಮುಗಿದ = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_ಕಳುಹಿಸಿದ|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_send_kexinit(ರಚನೆ ssh *ssh)
{
	u_char *cookie;
	ರಚನೆ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (kex == ಖಾಲಿ) {
		error_f("no kex");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಆದರೆ (kex->flags & KEX_INIT_ಕಳುಹಿಸಿದ)
		ಹಿಂತಿರುಗಿ 0;
	kex->ಮುಗಿದ = 0;

	/* generate a random cookie */
	ಆದರೆ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಆದರೆ ((cookie = sshbuf_mutable_ptr(kex->my)) == ಖಾಲಿ) {
		error_f("buffer error");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ಹಿಂತಿರುಗಿ r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_ಕಳುಹಿಸಿದ;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_ಒಳಹರಿವು_kexinit(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಸ್ಥಿರಾಂಕ u_char *ptr;
	u_int i;
	ಗಾತ್ರ_t dlen;
	ಪೂರ್ಣಾಂಕ r;

	debug("SSH2_MSG_KEXINIT received");
	ಆದರೆ (kex == ಖಾಲಿ) {
		error_f("no kex");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಬಿಡುಗಡೆ(kex->name);
	kex->name = ಖಾಲಿ;
	ಆದರೆ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ಆದರೆ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* discard packet */
	ಗಾಗಿ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ಆದರೆ ((r = sshpkt_get_u8(ssh, ಖಾಲಿ)) != 0) {
			error_fr(r, "discard cookie");
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಆದರೆ ((r = sshpkt_get_string(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0) {
			error_fr(r, "discard proposal");
			ಹಿಂತಿರುಗಿ r;
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
	ಆದರೆ ((r = sshpkt_get_u8(ssh, ಖಾಲಿ)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ಖಾಲಿ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
			ಹಿಂತಿರುಗಿ r;

	ಆದರೆ (!(kex->flags & KEX_INIT_ಕಳುಹಿಸಿದ))
		ಆದರೆ ((r = kex_send_kexinit(ssh)) != 0)
			ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = kex_ಆರಿಸು_conf(ssh, seq)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಆದರೆ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
}

ರಚನೆ kex *
kex_new(ಶೂನ್ಯ)
{
	ರಚನೆ kex *kex;

	ಆದರೆ ((kex = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*kex))) == ಖಾಲಿ ||
	    (kex->peer = sshbuf_new()) == ಖಾಲಿ ||
	    (kex->my = sshbuf_new()) == ಖಾಲಿ ||
	    (kex->client_ಆವೃತ್ತಿ = sshbuf_new()) == ಖಾಲಿ ||
	    (kex->server_ಆವೃತ್ತಿ = sshbuf_new()) == ಖಾಲಿ ||
	    (kex->session_id = sshbuf_new()) == ಖಾಲಿ) {
		kex_free(kex);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ kex;
}

ಶೂನ್ಯ
kex_free_newkeys(ರಚನೆ newkeys *newkeys)
{
	ಆದರೆ (newkeys == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (newkeys->enc.ಕೀಲಿ) {
		explicit_bzero(newkeys->enc.ಕೀಲಿ, newkeys->enc.ಕೀಲಿ_len);
		ಬಿಡುಗಡೆ(newkeys->enc.ಕೀಲಿ);
		newkeys->enc.ಕೀಲಿ = ಖಾಲಿ;
	}
	ಆದರೆ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		ಬಿಡುಗಡೆ(newkeys->enc.iv);
		newkeys->enc.iv = ಖಾಲಿ;
	}
	ಬಿಡುಗಡೆ(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, ಗಾತ್ರ(newkeys->enc));
	ಬಿಡುಗಡೆ(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, ಗಾತ್ರ(newkeys->comp));
	mac_clear(&newkeys->mac);
	ಆದರೆ (newkeys->mac.ಕೀಲಿ) {
		explicit_bzero(newkeys->mac.ಕೀಲಿ, newkeys->mac.ಕೀಲಿ_len);
		ಬಿಡುಗಡೆ(newkeys->mac.ಕೀಲಿ);
		newkeys->mac.ಕೀಲಿ = ಖಾಲಿ;
	}
	ಬಿಡುಗಡೆ(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, ಗಾತ್ರ(newkeys->mac));
	freezero(newkeys, ಗಾತ್ರ(*newkeys));
}

ಶೂನ್ಯ
kex_free(ರಚನೆ kex *kex)
{
	u_int ಬಹುಲಕ;

	ಆದರೆ (kex == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	DH_free(kex->dh);
	EC_ಕೀಲಿ_free(kex->ec_client_ಕೀಲಿ);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಗಾಗಿ (ಬಹುಲಕ = 0; ಬಹುಲಕ < ಬಹುಲಕ_MAX; ಬಹುಲಕ++) {
		kex_free_newkeys(kex->newkeys[ಬಹುಲಕ]);
		kex->newkeys[ಬಹುಲಕ] = ಖಾಲಿ;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_ಆವೃತ್ತಿ);
	sshbuf_free(kex->server_ಆವೃತ್ತಿ);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	ಬಿಡುಗಡೆ(kex->failed_choice);
	ಬಿಡುಗಡೆ(kex->hostkey_alg);
	ಬಿಡುಗಡೆ(kex->name);
	ಬಿಡುಗಡೆ(kex->server_sig_algs);
	ಬಿಡುಗಡೆ(kex);
}

ಪೂರ್ಣಾಂಕ
kex_ready(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *proposal[PROPOSAL_MAX])
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEXINIT, &kex_ಒಳಹರಿವು_kexinit);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_ಸಿದ್ಧತೆ(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *proposal[PROPOSAL_MAX])
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = kex_ready(ssh, proposal)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
ಪೂರ್ಣಾಂಕ
kex_ಆರಂಭ_rekex(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (ssh->kex == ಖಾಲಿ) {
		error_f("no kex");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಆದರೆ (ssh->kex->ಮುಗಿದ == 0) {
		error_f("requested twice");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ssh->kex->ಮುಗಿದ = 0;
	ಹಿಂತಿರುಗಿ kex_send_kexinit(ssh);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಿಸು_enc(ರಚನೆ sshenc *enc, ಅಕ್ಷರ *client, ಅಕ್ಷರ *server)
{
	ಅಕ್ಷರ *name = ಹೊಂದಿಕೆ_list(client, server, ಖಾಲಿ);

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_CIPHER_ALG_ಹೊಂದಿಕೆ;
	ಆದರೆ ((enc->cipher = cipher_by_name(name)) == ಖಾಲಿ) {
		error_f("unsupported cipher %s", name);
		ಬಿಡುಗಡೆ(name);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ಖಾಲಿ;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->ಕೀಲಿ = ಖಾಲಿ;
	enc->ಕೀಲಿ_len = cipher_keylen(enc->cipher);
	enc->ಖಂಡ_ಗಾತ್ರ = cipher_blocksize(enc->cipher);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಿಸು_mac(ರಚನೆ ssh *ssh, ರಚನೆ sshmac *mac, ಅಕ್ಷರ *client, ಅಕ್ಷರ *server)
{
	ಅಕ್ಷರ *name = ಹೊಂದಿಕೆ_list(client, server, ಖಾಲಿ);

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_MAC_ALG_ಹೊಂದಿಕೆ;
	ಆದರೆ (mac_ಸಿದ್ಧತೆ(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		ಬಿಡುಗಡೆ(name);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	mac->name = name;
	mac->ಕೀಲಿ = ಖಾಲಿ;
	mac->enabled = 0;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಿಸು_comp(ರಚನೆ sshcomp *comp, ಅಕ್ಷರ *client, ಅಕ್ಷರ *server)
{
	ಅಕ್ಷರ *name = ಹೊಂದಿಕೆ_list(client, server, ಖಾಲಿ);

	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_COMPRESS_ALG_ಹೊಂದಿಕೆ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	ಆದರೆ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} ಇಲ್ಲದಿದ್ದರೆ
#ಆದರೆ_ಅಂತ್ಯ	/* WITH_ZLIB */
	ಆದರೆ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} ಇಲ್ಲದಿದ್ದರೆ {
		error_f("unsupported compression scheme %s", name);
		ಬಿಡುಗಡೆ(name);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	comp->name = name;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಿಸು_kex(ರಚನೆ kex *k, ಅಕ್ಷರ *client, ಅಕ್ಷರ *server)
{
	k->name = ಹೊಂದಿಕೆ_list(client, server, ಖಾಲಿ);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ಆದರೆ (k->name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_KEX_ALG_ಹೊಂದಿಕೆ;
	ಆದರೆ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಿಸು_hostkeyalg(ರಚನೆ kex *k, ಅಕ್ಷರ *client, ಅಕ್ಷರ *server)
{
	ಬಿಡುಗಡೆ(k->hostkey_alg);
	k->hostkey_alg = ಹೊಂದಿಕೆ_list(client, server, ಖಾಲಿ);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ಆದರೆ (k->hostkey_alg == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_HOSTKEY_ALG_ಹೊಂದಿಕೆ;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ಆದರೆ (k->hostkey_type == ಕೀಲಿ_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
proposals_ಹೊಂದಿಕೆ(ಅಕ್ಷರ *my[PROPOSAL_MAX], ಅಕ್ಷರ *peer[PROPOSAL_MAX])
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS, -1
	};
	ಪೂರ್ಣಾಂಕ *idx;
	ಅಕ್ಷರ *p;

	ಗಾಗಿ (idx = &check[0]; *idx != -1; idx++) {
		ಆದರೆ ((p = strchr(my[*idx], ',')) != ಖಾಲಿ)
			*p = '\0';
		ಆದರೆ ((p = strchr(peer[*idx], ',')) != ಖಾಲಿ)
			*p = '\0';
		ಆದರೆ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ಹಿಂತಿರುಗಿ (0);
		}
	}
	debug2("proposals match");
	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kexalgs_ಒಳಗೊಂಡಿದೆ(ಅಕ್ಷರ **peer, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ext)
{
	ಹಿಂತಿರುಗಿ kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_ಆರಿಸು_conf(ರಚನೆ ssh *ssh, uint32_t seq)
{
	ರಚನೆ kex *kex = ssh->kex;
	ರಚನೆ newkeys *newkeys;
	ಅಕ್ಷರ **my = ಖಾಲಿ, **peer = ಖಾಲಿ;
	ಅಕ್ಷರ **cprop, **sprop;
	ಪೂರ್ಣಾಂಕ nenc, nmac, ncomp;
	u_int ಬಹುಲಕ, ctos, need, dh_need, authlen;
	ಪೂರ್ಣಾಂಕ r, ಮೊದಲ_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ಆದರೆ ((r = kex_buf2prop(kex->my, ಖಾಲಿ, &my)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ಆದರೆ ((r = kex_buf2prop(kex->peer, &ಮೊದಲ_kex_follows, &peer)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (kex->server) {
		cprop=peer;
		sprop=my;
	} ಇಲ್ಲದಿದ್ದರೆ {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ಆದರೆ ((kex->flags & KEX_INITIAL) != 0) {
		ಆದರೆ (kex->server) {
			kex->ext_info_c = kexalgs_ಒಳಗೊಂಡಿದೆ(peer, "ext-info-c");
			kex->kex_strict = kexalgs_ಒಳಗೊಂಡಿದೆ(peer,
			    "kex-strict-c-v00@openssh.com");
		} ಇಲ್ಲದಿದ್ದರೆ {
			kex->ext_info_s = kexalgs_ಒಳಗೊಂಡಿದೆ(peer, "ext-info-s");
			kex->kex_strict = kexalgs_ಒಳಗೊಂಡಿದೆ(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ಆದರೆ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ಆದರೆ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ಆದರೆ (kex->server && (kex->flags & KEX_INITIAL)) {
		ಆದರೆ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ಆದರೆ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ಆದರೆ ((r = ಆರಿಸು_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ಖಾಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ಆರಿಸು_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS];
		peer[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = ಖಾಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (ಬಹುಲಕ = 0; ಬಹುಲಕ < ಬಹುಲಕ_MAX; ಬಹುಲಕ++) {
		ಆದರೆ ((newkeys = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*newkeys))) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		kex->newkeys[ಬಹುಲಕ] = newkeys;
		ctos = (!kex->server && ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು) ||
		    (kex->server && ಬಹುಲಕ == ಬಹುಲಕ_ಒಳ);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ಆದರೆ ((r = ಆರಿಸು_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ಖಾಲಿ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ಆದರೆ (authlen == 0 &&
		    (r = ಆರಿಸು_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ಖಾಲಿ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = ಆರಿಸು_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ಖಾಲಿ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	ಗಾಗಿ (ಬಹುಲಕ = 0; ಬಹುಲಕ < ಬಹುಲಕ_MAX; ಬಹುಲಕ++) {
		newkeys = kex->newkeys[ಬಹುಲಕ];
		need = ಗರಿಷ್ಠ(need, newkeys->enc.ಕೀಲಿ_len);
		need = ಗರಿಷ್ಠ(need, newkeys->enc.ಖಂಡ_ಗಾತ್ರ);
		need = ಗರಿಷ್ಠ(need, newkeys->enc.iv_len);
		need = ಗರಿಷ್ಠ(need, newkeys->mac.ಕೀಲಿ_len);
		dh_need = ಗರಿಷ್ಠ(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = ಗರಿಷ್ಠ(dh_need, newkeys->enc.ಖಂಡ_ಗಾತ್ರ);
		dh_need = ಗರಿಷ್ಠ(dh_need, newkeys->enc.iv_len);
		dh_need = ಗರಿಷ್ಠ(dh_need, newkeys->mac.ಕೀಲಿ_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	ಆದರೆ (ಮೊದಲ_kex_follows && !proposals_ಹೊಂದಿಕೆ(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 ಹೊರಹೋಗು:
	kex_prop_free(my);
	kex_prop_free(peer);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
derive_ಕೀಲಿ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, u_int need, u_char *hash, u_int hashlen,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *shared_secret, u_char **keyp)
{
	ರಚನೆ kex *kex = ssh->kex;
	ರಚನೆ ssh_digest_ctx *hashctx = ಖಾಲಿ;
	ಅಕ್ಷರ c = id;
	u_int have;
	ಗಾತ್ರ_t mdsz;
	u_char *digest;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((mdsz = ssh_digest_ಬೈಟುಗಳು(kex->hash_alg)) == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((digest = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ROUNDUP(need, mdsz))) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ಆದರೆ ((hashctx = ssh_digest_ಆರಂಭ(kex->hash_alg)) == ಖಾಲಿ ||
	    ssh_digest_update_ಬಫರ್(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_ಬಫರ್(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ssh_digest_free(hashctx);
	hashctx = ಖಾಲಿ;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	ಗಾಗಿ (have = mdsz; need > have; have += mdsz) {
		ಆದರೆ ((hashctx = ssh_digest_ಆರಂಭ(kex->hash_alg)) == ಖಾಲಿ ||
		    ssh_digest_update_ಬಫರ್(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ssh_digest_free(hashctx);
		hashctx = ಖಾಲಿ;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#ಆದರೆ_ಅಂತ್ಯ
	*keyp = digest;
	digest = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(digest);
	ssh_digest_free(hashctx);
	ಹಿಂತಿರುಗಿ r;
}

#ವ್ಯಾಖ್ಯಾನಿಸು NKEYS	6
ಪೂರ್ಣಾಂಕ
kex_derive_ಕೀಲಿಗಳು(ರಚನೆ ssh *ssh, u_char *hash, u_int hashlen,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *shared_secret)
{
	ರಚನೆ kex *kex = ssh->kex;
	u_char *ಕೀಲಿಗಳು[NKEYS];
	u_int i, j, ಬಹುಲಕ, ctos;
	ಪೂರ್ಣಾಂಕ r;

	/* save initial hash as session id */
	ಆದರೆ ((kex->flags & KEX_INITIAL) != 0) {
		ಆದರೆ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
		}
		ಆದರೆ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ಹಿಂತಿರುಗಿ r;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಗಾಗಿ (i = 0; i < NKEYS; i++) {
		ಆದರೆ ((r = derive_ಕೀಲಿ(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &ಕೀಲಿಗಳು[i])) != 0) {
			ಗಾಗಿ (j = 0; j < i; j++)
				ಬಿಡುಗಡೆ(ಕೀಲಿಗಳು[j]);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಗಾಗಿ (ಬಹುಲಕ = 0; ಬಹುಲಕ < ಬಹುಲಕ_MAX; ಬಹುಲಕ++) {
		ctos = (!kex->server && ಬಹುಲಕ == ಬಹುಲಕ_ಹೊರಹೋಗು) ||
		    (kex->server && ಬಹುಲಕ == ಬಹುಲಕ_ಒಳ);
		kex->newkeys[ಬಹುಲಕ]->enc.iv  = ಕೀಲಿಗಳು[ctos ? 0 : 1];
		kex->newkeys[ಬಹುಲಕ]->enc.ಕೀಲಿ = ಕೀಲಿಗಳು[ctos ? 2 : 3];
		kex->newkeys[ಬಹುಲಕ]->mac.ಕೀಲಿ = ಕೀಲಿಗಳು[ctos ? 4 : 5];
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_ತುಂಬು_hostkey(ರಚನೆ ssh *ssh, ರಚನೆ sshkey **prvp, ರಚನೆ sshkey **pubp)
{
	ರಚನೆ kex *kex = ssh->kex;

	*pubp = ಖಾಲಿ;
	*prvp = ಖಾಲಿ;
	ಆದರೆ (kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ == ಖಾಲಿ ||
	    kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ == ಖಾಲಿ) {
		error_f("missing hostkey loader");
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	*pubp = kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ಆದರೆ (*pubp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_HOSTKEY_LOADED;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_verify_host_ಕೀಲಿ(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *server_host_ಕೀಲಿ)
{
	ರಚನೆ kex *kex = ssh->kex;

	ಆದರೆ (kex->verify_host_ಕೀಲಿ == ಖಾಲಿ) {
		error_f("missing hostkey verifier");
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	ಆದರೆ (server_host_ಕೀಲಿ->type != kex->hostkey_type ||
	    (kex->hostkey_type == ಕೀಲಿ_ECDSA &&
	    server_host_ಕೀಲಿ->ecdsa_nid != kex->hostkey_nid))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
	ಆದರೆ (kex->verify_host_ಕೀಲಿ(server_host_ಕೀಲಿ, ssh) == -1)
		ಹಿಂತಿರುಗಿ  SSH_ERR_SIGNATURE_INVALID;
	ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ಶೂನ್ಯ
dump_digest(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ, ಸ್ಥಿರಾಂಕ u_char *digest, ಪೂರ್ಣಾಂಕ len)
{
	fprintf(stderr, "%s\n", ಸಂದೇಶ);
	sshbuf_dump_ದತ್ತಾಂಶ(digest, len, stderr);
}
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
send_error(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *ಸಂದೇಶ)
{
	ಅಕ್ಷರ *crnl = "\r\n";

	ಆದರೆ (!ssh->kex->server)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ (atomicio(vwrite, ssh_packet_get_connection_ಹೊರಹೋಗು(ssh),
	    ಸಂದೇಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ)) != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ) ||
	    atomicio(vwrite, ssh_packet_get_connection_ಹೊರಹೋಗು(ssh),
	    crnl, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(crnl)) != ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
ಪೂರ್ಣಾಂಕ
kex_exchange_identification(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ timeout_ms,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಆವೃತ್ತಿ_addendum)
{
	ಪೂರ್ಣಾಂಕ remote_major, remote_minor, mismatch, oerrno = 0;
	ಗಾತ್ರ_t len, n;
	ಪೂರ್ಣಾಂಕ r, expect_nl;
	u_char c;
	ರಚನೆ sshbuf *our_ಆವೃತ್ತಿ = ssh->kex->server ?
	    ssh->kex->server_ಆವೃತ್ತಿ : ssh->kex->client_ಆವೃತ್ತಿ;
	ರಚನೆ sshbuf *peer_ಆವೃತ್ತಿ = ssh->kex->server ?
	    ssh->kex->client_ಆವೃತ್ತಿ : ssh->kex->server_ಆವೃತ್ತಿ;
	ಅಕ್ಷರ *our_ಆವೃತ್ತಿ_string = ಖಾಲಿ, *peer_ಆವೃತ್ತಿ_string = ಖಾಲಿ;
	ಅಕ್ಷರ *cp, *remote_ಆವೃತ್ತಿ = ಖಾಲಿ;

	/* Prepare and send our banner */
	sshbuf_reset(our_ಆವೃತ್ತಿ);
	ಆದರೆ (ಆವೃತ್ತಿ_addendum != ಖಾಲಿ && *ಆವೃತ್ತಿ_addendum == '\0')
		ಆವೃತ್ತಿ_addendum = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_putf(our_ಆವೃತ್ತಿ, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_ಆವೃತ್ತಿ,
	    ಆವೃತ್ತಿ_addendum == ಖಾಲಿ ? "" : " ",
	    ಆವೃತ್ತಿ_addendum == ಖಾಲಿ ? "" : ಆವೃತ್ತಿ_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (atomicio(vwrite, ssh_packet_get_connection_ಹೊರಹೋಗು(ssh),
	    sshbuf_mutable_ptr(our_ಆವೃತ್ತಿ),
	    sshbuf_len(our_ಆವೃತ್ತಿ)) != sshbuf_len(our_ಆವೃತ್ತಿ)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(our_ಆವೃತ್ತಿ, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	our_ಆವೃತ್ತಿ_string = sshbuf_dup_string(our_ಆವೃತ್ತಿ);
	ಆದರೆ (our_ಆವೃತ್ತಿ_string == ಖಾಲಿ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug("Local version string %.100s", our_ಆವೃತ್ತಿ_string);

	/* Read other side's version identification. */
	ಗಾಗಿ (n = 0; ; n++) {
		ಆದರೆ (n >= SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		sshbuf_reset(peer_ಆವೃತ್ತಿ);
		expect_nl = 0;
		ಗಾಗಿ (;;) {
			ಆದರೆ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_ಒಳ(ssh),
				    &timeout_ms, ಖಾಲಿ);
				ಆದರೆ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					ಹೋಗು ಹೊರಹೋಗು;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}

			len = atomicio(ಪಠ, ssh_packet_get_connection_ಒಳ(ssh),
			    &c, 1);
			ಆದರೆ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				ಹೋಗು ಹೊರಹೋಗು;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (c == '\r') {
				expect_nl = 1;
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (c == '\n')
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				ಹೋಗು invalid;
			}
			ಆದರೆ ((r = sshbuf_put_u8(peer_ಆವೃತ್ತಿ, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (sshbuf_len(peer_ಆವೃತ್ತಿ) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				ಹೋಗು invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ಆದರೆ (sshbuf_len(peer_ಆವೃತ್ತಿ) > 4 &&
		    memcmp(sshbuf_ptr(peer_ಆವೃತ್ತಿ), "SSH-", 4) == 0)
			ನಿಲ್ಲಿಸು;
		/* If not, then just log the line and continue */
		ಆದರೆ ((cp = sshbuf_dup_string(peer_ಆವೃತ್ತಿ)) == ಖಾಲಿ) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Do not accept lines before the SSH ident from a client */
		ಆದರೆ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			ಬಿಡುಗಡೆ(cp);
			ಹೋಗು invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		ಬಿಡುಗಡೆ(cp);
	}
	peer_ಆವೃತ್ತಿ_string = sshbuf_dup_string(peer_ಆವೃತ್ತಿ);
	ಆದರೆ (peer_ಆವೃತ್ತಿ_string == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ಆದರೆ ((remote_ಆವೃತ್ತಿ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, sshbuf_len(peer_ಆವೃತ್ತಿ))) == ಖಾಲಿ) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(peer_ಆವೃತ್ತಿ_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_ಆವೃತ್ತಿ) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_ಆವೃತ್ತಿ_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_ಆವೃತ್ತಿ);
	compat_banner(ssh, remote_ಆವೃತ್ತಿ);

	mismatch = 0;
	ಆಯ್ಕೆ (remote_major) {
	ಸ್ಥಿತಿ 2:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 1:
		ಆದರೆ (remote_minor != 99)
			mismatch = 1;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		mismatch = 1;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_ಆವೃತ್ತಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
		    peer_ಆವೃತ್ತಿ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
		    peer_ಆವೃತ್ತಿ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(our_ಆವೃತ್ತಿ_string);
	ಬಿಡುಗಡೆ(peer_ಆವೃತ್ತಿ_string);
	ssh->remote_ಆವೃತ್ತಿ = remote_ಆವೃತ್ತಿ;  /* transferred */
	ಆದರೆ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

