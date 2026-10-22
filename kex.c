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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

/* prototype */
ਸਥਿਰ ਪੂਰਨ kex_ਚੁਣੋ_conf(ਬਣਤਰ ssh *, uint32_t seq);
ਸਥਿਰ ਪੂਰਨ kex_ਨਿਵੇਸ਼_newkeys(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ proposal_ਨਾਂ[PROPOSAL_MAX] = {
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
ਖਾਲੀ
kex_proposal_populate_entries(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *prop[PROPOSAL_MAX],
    ਅਚਲ ਅੱਖਰ *kexalgos, ਅਚਲ ਅੱਖਰ *ciphers, ਅਚਲ ਅੱਖਰ *macs,
    ਅਚਲ ਅੱਖਰ *comp, ਅਚਲ ਅੱਖਰ *hkalgs)
{
	ਅਚਲ ਅੱਖਰ *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ਅਚਲ ਅੱਖਰ *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅਚਲ ਅੱਖਰ **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	ਅੱਖਰ *cp;

	ਜੇ (prop == ਨਿਰਾ)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ਜੇ (kexalgos == ਨਿਰਾ)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ਜੇ ((cp = kex_ਨਾਂ_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ਨਿਰਾ)
		fatal_f("kex_names_cat");

	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਚੋਣ(i) {
		ਹਾਲਤ PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			ਰੋਕੋ;
		ਹਾਲਤ PROPOSAL_ENC_ALGS_CTOS:
		ਹਾਲਤ PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			ਰੋਕੋ;
		ਹਾਲਤ PROPOSAL_MAC_ALGS_CTOS:
		ਹਾਲਤ PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			ਰੋਕੋ;
		ਹਾਲਤ PROPOSAL_COMP_ALGS_CTOS:
		ਹਾਲਤ PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			ਰੋਕੋ;
		ਹਾਲਤ PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			ਰੋਕੋ;
		ਮੂਲ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	ਮੁਕਤ(cp);
}

ਖਾਲੀ
kex_proposal_free_entries(ਅੱਖਰ *prop[PROPOSAL_MAX])
{
	u_int i;

	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(prop[i]);
}

/* put algorithm proposal into buffer */
ਪੂਰਨ
kex_prop2buf(ਬਣਤਰ sshbuf *b, ਅੱਖਰ *proposal[PROPOSAL_MAX])
{
	u_int i;
	ਪੂਰਨ r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	ਲਈ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ਜੇ ((r = sshbuf_put_u8(b, 0)) != 0)
			ਵਾਪਸ r;
	}
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਜੇ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

/* parse buffer and return algorithm proposal */
ਪੂਰਨ
kex_buf2prop(ਬਣਤਰ sshbuf *raw, ਪੂਰਨ *ਪਹਿਲਾ_kex_follows, ਅੱਖਰ ***propp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	u_char v;
	u_int i;
	ਅੱਖਰ **proposal = ਨਿਰਾ;
	ਪੂਰਨ r;

	*propp = ਨਿਰਾ;
	ਜੇ ((proposal = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(PROPOSAL_MAX, ਆਕਾਰ(ਅੱਖਰ *))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((b = sshbuf_fromb(raw)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* extract kex init proposal strings */
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਜੇ ((r = sshbuf_get_cstring(b, &(proposal[i]), ਨਿਰਾ)) != 0) {
			error_fr(r, "parse proposal %u", i);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug2("%s: %s", proposal_ਨਾਂ[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ਜੇ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ਪਹਿਲਾ_kex_follows != ਨਿਰਾ)
		*ਪਹਿਲਾ_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 ਬਾਹਰਲਾ:
	ਜੇ (r != 0 && proposal != ਨਿਰਾ)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਖਾਲੀ
kex_prop_free(ਅੱਖਰ **proposal)
{
	u_int i;

	ਜੇ (proposal == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(proposal[i]);
	ਮੁਕਤ(proposal);
}

ਪੂਰਨ
kex_protocol_error(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	/* If in strict mode, any unexpected message is an error */
	ਜੇ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
kex_reset_dispatch(ਬਣਤਰ ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_ਸੁਨੇਹਾ_TRANSPORT_MIN,
	    SSH2_ਸੁਨੇਹਾ_TRANSPORT_MAX, &kex_protocol_error);
}

ਖਾਲੀ
kex_ਸੈੱਟ_server_sig_algs(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *allowed_algs)
{
	ਅੱਖਰ *alg, *oalgs, *algs, *sigalgs;
	ਅਚਲ ਅੱਖਰ *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ਜੇ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ਨਿਰਾ)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	ਮੁਕਤ(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ਨਿਰਾ;
	ਲਈ ((alg = strsep(&algs, ",")); alg != ਨਿਰਾ && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ਜੇ ((sigalg = sshkey_sigalg_by_name(alg)) == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (!kex_has_any_alg(sigalg, sigalgs))
			ਜਾਰੀ;
		/* Don't add an algorithm twice. */
		ਜੇ (ssh->kex->server_sig_algs != ਨਿਰਾ &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			ਜਾਰੀ;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	ਮੁਕਤ(oalgs);
	ਮੁਕਤ(sigalgs);
	ਜੇ (ssh->kex->server_sig_algs == ਨਿਰਾ)
		ssh->kex->server_sig_algs = xstrdup("");
}

ਖਾਲੀ
kex_ਸੈੱਟ_warn_weak_crypto(ਬਣਤਰ ssh *ssh, ਪੂਰਨ warn_weak_crypto)
{
	ਜੇ (ssh != ਨਿਰਾ && ssh->kex != ਨਿਰਾ)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

ਖਾਲੀ
kex_check_warn_weak_crypto(ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ remote_id[512];
	ਪੂਰਨ rekeyed = 0;

	ਜੇ (ssh == ਨਿਰਾ || ssh->kex == ਨਿਰਾ || ssh->kex->name == ਨਿਰਾ ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ਵਾਪਸ;
	ਜੇ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ਵਾਪਸ;
	}

	ਜੇ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ਜੇ (!rekeyed && !ssh->kex->server)
		ਵਾਪਸ; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, ਆਕਾਰ(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ਸਥਿਰ ਪੂਰਨ
kex_compose_ext_info_server(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;

	ਜੇ (ssh->kex->server_sig_algs == ਨਿਰਾ &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
kex_compose_ext_info_client(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *m)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
kex_maybe_send_ext_info(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *m = ਨਿਰਾ;

	ਜੇ ((ssh->kex->flags & KEX_INITIAL) == 0)
		ਵਾਪਸ 0;
	ਜੇ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ਵਾਪਸ 0;

	/* Compose EXT_INFO packet. */
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		ਜਾਓ fail;
	ਜੇ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		ਜਾਓ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ਜਾਓ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_server_update_ext_info(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	ਜੇ ((ssh->kex->flags & KEX_HAS_EXT_INFO_ਵਿੱਚ_AUTH) == 0)
		ਵਾਪਸ 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_send_newkeys(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	kex_reset_dispatch(ssh);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਵਾਪਸ r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_NEWKEYS, &kex_ਨਿਵੇਸ਼_newkeys);
	ਜੇ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ਵਾਪਸ r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ਵਾਪਸ 0;
}

/* Check whether an ext_info value contains the expected version string */
ਸਥਿਰ ਪੂਰਨ
kex_ext_info_check_ver(ਬਣਤਰ kex *kex, ਅਚਲ ਅੱਖਰ *name,
    ਅਚਲ u_char *val, ਮਾਪ_t len, ਅਚਲ ਅੱਖਰ *want_ver, u_int flag)
{
	ਜੇ (memchr(val, '\0', len) != ਨਿਰਾ) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ਜੇ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	ਨਹੀਂਤਾਂ
		debug_f("unsupported version of %s extension", name);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
kex_ext_info_client_parse(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *name,
    ਅਚਲ u_char *ਮੁੱਲ, ਮਾਪ_t vlen)
{
	ਪੂਰਨ r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ਜੇ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ਜੇ (memchr(ਮੁੱਲ, '\0', vlen) != ਨਿਰਾ) {
			error_f("nul byte in %s", name);
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, ਮੁੱਲ);
		ਮੁਕਤ(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ਅਚਲ ਅੱਖਰ *)ਮੁੱਲ);
	} ਨਹੀਂਤਾਂ ਜੇ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ਜੇ ((r = kex_ext_info_check_ver(ssh->kex, name, ਮੁੱਲ, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ਵਾਪਸ r;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ਜੇ ((r = kex_ext_info_check_ver(ssh->kex, name, ਮੁੱਲ, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ਵਾਪਸ r;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ਜੇ ((r = kex_ext_info_check_ver(ssh->kex, name, ਮੁੱਲ, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ਵਾਪਸ r;
		}
	} ਨਹੀਂਤਾਂ
		debug_f("%s (unrecognised)", name);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
kex_ext_info_server_parse(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *name,
    ਅਚਲ u_char *ਮੁੱਲ, ਮਾਪ_t vlen)
{
	ਪੂਰਨ r;

	ਜੇ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ਜੇ ((r = kex_ext_info_check_ver(ssh->kex, name, ਮੁੱਲ, vlen,
		    "0", KEX_HAS_EXT_INFO_ਵਿੱਚ_AUTH)) != 0) {
			ਵਾਪਸ r;
		}
	} ਨਹੀਂਤਾਂ
		debug_f("%s (unrecognised)", name);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_ਨਿਵੇਸ਼_ext_info(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਅਚਲ ਪੂਰਨ max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	ਅੱਖਰ *name;
	u_char *val;
	ਮਾਪ_t vlen;
	ਪੂਰਨ r;

	debug("SSH2_MSG_EXT_INFO received");
	ਜੇ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ਵਾਪਸ dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, &kex_protocol_error);
	ਜੇ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ਵਾਪਸ r;
	ਜੇ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ਵਾਪਸ dispatch_protocol_error(type, seq, ssh);
	}
	ਲਈ (i = 0; i < ninfo; i++) {
		ਜੇ ((r = sshpkt_get_cstring(ssh, &name, ਨਿਰਾ)) != 0)
			ਵਾਪਸ r;
		ਜੇ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			ਮੁਕਤ(name);
			ਵਾਪਸ r;
		}
		debug3_f("extension %s", name);
		ਜੇ (kex->server) {
			ਜੇ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ਵਾਪਸ r;
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ਵਾਪਸ r;
		}
		ਮੁਕਤ(name);
		ਮੁਕਤ(val);
	}
	ਵਾਪਸ sshpkt_get_ਸਿਰਾ(ssh);
}

ਸਥਿਰ ਪੂਰਨ
kex_ਨਿਵੇਸ਼_newkeys(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਪੂਰਨ r, initial = (kex->flags & KEX_INITIAL) != 0;
	ਅੱਖਰ *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ਜੇ (kex->ext_info_c && initial)
		ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, &kex_ਨਿਵੇਸ਼_ext_info);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEXINIT, &kex_ਨਿਵੇਸ਼_kexinit);
	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = ssh_ਸੈੱਟ_newkeys(ssh, ਬਹੁਲਕ_ਵਿੱਚ)) != 0)
		ਵਾਪਸ r;
	ਜੇ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ਜੇ ((r = kex_buf2prop(kex->my, ਨਿਰਾ, &prop)) != 0)
			ਵਾਪਸ r;
		ਜੇ ((cp = ਮੇਲ_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ਨਿਰਾ) {
			error_f("match_filter_denylist failed");
			ਜਾਓ fail;
		}
		ਮੁਕਤ(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ਜੇ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			ਮੁਕਤ(prop);
			ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		}
		kex_proposal_free_entries(prop);
		ਮੁਕਤ(prop);
	}
	kex->ਪੂਰਾ = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_ਭੇਜਿਆ|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_send_kexinit(ਬਣਤਰ ssh *ssh)
{
	u_char *cookie;
	ਬਣਤਰ kex *kex = ssh->kex;
	ਪੂਰਨ r;

	ਜੇ (kex == ਨਿਰਾ) {
		error_f("no kex");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਜੇ (kex->flags & KEX_INIT_ਭੇਜਿਆ)
		ਵਾਪਸ 0;
	kex->ਪੂਰਾ = 0;

	/* generate a random cookie */
	ਜੇ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਜੇ ((cookie = sshbuf_mutable_ptr(kex->my)) == ਨਿਰਾ) {
		error_f("buffer error");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ਵਾਪਸ r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_ਭੇਜਿਆ;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_ਨਿਵੇਸ਼_kexinit(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਅਚਲ u_char *ptr;
	u_int i;
	ਮਾਪ_t dlen;
	ਪੂਰਨ r;

	debug("SSH2_MSG_KEXINIT received");
	ਜੇ (kex == ਨਿਰਾ) {
		error_f("no kex");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਮੁਕਤ(kex->name);
	kex->name = ਨਿਰਾ;
	ਜੇ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ਜੇ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ਵਾਪਸ r;

	/* discard packet */
	ਲਈ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ਜੇ ((r = sshpkt_get_u8(ssh, ਨਿਰਾ)) != 0) {
			error_fr(r, "discard cookie");
			ਵਾਪਸ r;
		}
	}
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਜੇ ((r = sshpkt_get_string(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0) {
			error_fr(r, "discard proposal");
			ਵਾਪਸ r;
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
	ਜੇ ((r = sshpkt_get_u8(ssh, ਨਿਰਾ)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ਨਿਰਾ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
			ਵਾਪਸ r;

	ਜੇ (!(kex->flags & KEX_INIT_ਭੇਜਿਆ))
		ਜੇ ((r = kex_send_kexinit(ssh)) != 0)
			ਵਾਪਸ r;
	ਜੇ ((r = kex_ਚੁਣੋ_conf(ssh, seq)) != 0)
		ਵਾਪਸ r;

	ਜੇ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ਨਿਰਾ)
		ਵਾਪਸ (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
}

ਬਣਤਰ kex *
kex_new(ਖਾਲੀ)
{
	ਬਣਤਰ kex *kex;

	ਜੇ ((kex = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*kex))) == ਨਿਰਾ ||
	    (kex->peer = sshbuf_new()) == ਨਿਰਾ ||
	    (kex->my = sshbuf_new()) == ਨਿਰਾ ||
	    (kex->client_ਸੰਸਕਰਣ = sshbuf_new()) == ਨਿਰਾ ||
	    (kex->server_ਸੰਸਕਰਣ = sshbuf_new()) == ਨਿਰਾ ||
	    (kex->session_id = sshbuf_new()) == ਨਿਰਾ) {
		kex_free(kex);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ kex;
}

ਖਾਲੀ
kex_free_newkeys(ਬਣਤਰ newkeys *newkeys)
{
	ਜੇ (newkeys == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (newkeys->enc.ਕੁੰਜੀ) {
		explicit_bzero(newkeys->enc.ਕੁੰਜੀ, newkeys->enc.ਕੁੰਜੀ_len);
		ਮੁਕਤ(newkeys->enc.ਕੁੰਜੀ);
		newkeys->enc.ਕੁੰਜੀ = ਨਿਰਾ;
	}
	ਜੇ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		ਮੁਕਤ(newkeys->enc.iv);
		newkeys->enc.iv = ਨਿਰਾ;
	}
	ਮੁਕਤ(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, ਆਕਾਰ(newkeys->enc));
	ਮੁਕਤ(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, ਆਕਾਰ(newkeys->comp));
	mac_clear(&newkeys->mac);
	ਜੇ (newkeys->mac.ਕੁੰਜੀ) {
		explicit_bzero(newkeys->mac.ਕੁੰਜੀ, newkeys->mac.ਕੁੰਜੀ_len);
		ਮੁਕਤ(newkeys->mac.ਕੁੰਜੀ);
		newkeys->mac.ਕੁੰਜੀ = ਨਿਰਾ;
	}
	ਮੁਕਤ(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, ਆਕਾਰ(newkeys->mac));
	freezero(newkeys, ਆਕਾਰ(*newkeys));
}

ਖਾਲੀ
kex_free(ਬਣਤਰ kex *kex)
{
	u_int ਬਹੁਲਕ;

	ਜੇ (kex == ਨਿਰਾ)
		ਵਾਪਸ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	DH_free(kex->dh);
	EC_ਕੁੰਜੀ_free(kex->ec_client_ਕੁੰਜੀ);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਲਈ (ਬਹੁਲਕ = 0; ਬਹੁਲਕ < ਬਹੁਲਕ_MAX; ਬਹੁਲਕ++) {
		kex_free_newkeys(kex->newkeys[ਬਹੁਲਕ]);
		kex->newkeys[ਬਹੁਲਕ] = ਨਿਰਾ;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_ਸੰਸਕਰਣ);
	sshbuf_free(kex->server_ਸੰਸਕਰਣ);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	ਮੁਕਤ(kex->failed_choice);
	ਮੁਕਤ(kex->hostkey_alg);
	ਮੁਕਤ(kex->name);
	ਮੁਕਤ(kex->server_sig_algs);
	ਮੁਕਤ(kex);
}

ਪੂਰਨ
kex_ready(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *proposal[PROPOSAL_MAX])
{
	ਪੂਰਨ r;

	ਜੇ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ਵਾਪਸ r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEXINIT, &kex_ਨਿਵੇਸ਼_kexinit);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_ਤਿਆਰੀ(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *proposal[PROPOSAL_MAX])
{
	ਪੂਰਨ r;

	ਜੇ ((r = kex_ready(ssh, proposal)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ਨਿਰਾ;
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
ਪੂਰਨ
kex_ਸ਼ੁਰੂ_rekex(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (ssh->kex == ਨਿਰਾ) {
		error_f("no kex");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਜੇ (ssh->kex->ਪੂਰਾ == 0) {
		error_f("requested twice");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ssh->kex->ਪੂਰਾ = 0;
	ਵਾਪਸ kex_send_kexinit(ssh);
}

ਸਥਿਰ ਪੂਰਨ
ਚੁਣੋ_enc(ਬਣਤਰ sshenc *enc, ਅੱਖਰ *client, ਅੱਖਰ *server)
{
	ਅੱਖਰ *name = ਮੇਲ_list(client, server, ਨਿਰਾ);

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_NO_CIPHER_ALG_ਮੇਲ;
	ਜੇ ((enc->cipher = cipher_by_name(name)) == ਨਿਰਾ) {
		error_f("unsupported cipher %s", name);
		ਮੁਕਤ(name);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ਨਿਰਾ;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->ਕੁੰਜੀ = ਨਿਰਾ;
	enc->ਕੁੰਜੀ_len = cipher_keylen(enc->cipher);
	enc->ਖੰਡ_ਮਾਪ = cipher_blocksize(enc->cipher);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਚੁਣੋ_mac(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshmac *mac, ਅੱਖਰ *client, ਅੱਖਰ *server)
{
	ਅੱਖਰ *name = ਮੇਲ_list(client, server, ਨਿਰਾ);

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_NO_MAC_ALG_ਮੇਲ;
	ਜੇ (mac_ਤਿਆਰੀ(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		ਮੁਕਤ(name);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	mac->name = name;
	mac->ਕੁੰਜੀ = ਨਿਰਾ;
	mac->enabled = 0;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਚੁਣੋ_comp(ਬਣਤਰ sshcomp *comp, ਅੱਖਰ *client, ਅੱਖਰ *server)
{
	ਅੱਖਰ *name = ਮੇਲ_list(client, server, ਨਿਰਾ);

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_NO_COMPRESS_ALG_ਮੇਲ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	ਜੇ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} ਨਹੀਂਤਾਂ
#ਜੇ_ਅੰਤ	/* WITH_ZLIB */
	ਜੇ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} ਨਹੀਂਤਾਂ {
		error_f("unsupported compression scheme %s", name);
		ਮੁਕਤ(name);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	comp->name = name;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਚੁਣੋ_kex(ਬਣਤਰ kex *k, ਅੱਖਰ *client, ਅੱਖਰ *server)
{
	k->name = ਮੇਲ_list(client, server, ਨਿਰਾ);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ਜੇ (k->name == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_NO_KEX_ALG_ਮੇਲ;
	ਜੇ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਚੁਣੋ_hostkeyalg(ਬਣਤਰ kex *k, ਅੱਖਰ *client, ਅੱਖਰ *server)
{
	ਮੁਕਤ(k->hostkey_alg);
	k->hostkey_alg = ਮੇਲ_list(client, server, ਨਿਰਾ);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ਜੇ (k->hostkey_alg == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_NO_HOSTKEY_ALG_ਮੇਲ;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ਜੇ (k->hostkey_type == ਕੁੰਜੀ_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
proposals_ਮੇਲ(ਅੱਖਰ *my[PROPOSAL_MAX], ਅੱਖਰ *peer[PROPOSAL_MAX])
{
	ਸਥਿਰ ਪੂਰਨ check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS, -1
	};
	ਪੂਰਨ *idx;
	ਅੱਖਰ *p;

	ਲਈ (idx = &check[0]; *idx != -1; idx++) {
		ਜੇ ((p = strchr(my[*idx], ',')) != ਨਿਰਾ)
			*p = '\0';
		ਜੇ ((p = strchr(peer[*idx], ',')) != ਨਿਰਾ)
			*p = '\0';
		ਜੇ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ਵਾਪਸ (0);
		}
	}
	debug2("proposals match");
	ਵਾਪਸ (1);
}

ਸਥਿਰ ਪੂਰਨ
kexalgs_ਸ਼ਾਮਲ_ਹੈ(ਅੱਖਰ **peer, ਅਚਲ ਅੱਖਰ *ext)
{
	ਵਾਪਸ kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ਸਥਿਰ ਪੂਰਨ
kex_ਚੁਣੋ_conf(ਬਣਤਰ ssh *ssh, uint32_t seq)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਬਣਤਰ newkeys *newkeys;
	ਅੱਖਰ **my = ਨਿਰਾ, **peer = ਨਿਰਾ;
	ਅੱਖਰ **cprop, **sprop;
	ਪੂਰਨ nenc, nmac, ncomp;
	u_int ਬਹੁਲਕ, ctos, need, dh_need, authlen;
	ਪੂਰਨ r, ਪਹਿਲਾ_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ਜੇ ((r = kex_buf2prop(kex->my, ਨਿਰਾ, &my)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ਜੇ ((r = kex_buf2prop(kex->peer, &ਪਹਿਲਾ_kex_follows, &peer)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (kex->server) {
		cprop=peer;
		sprop=my;
	} ਨਹੀਂਤਾਂ {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ਜੇ ((kex->flags & KEX_INITIAL) != 0) {
		ਜੇ (kex->server) {
			kex->ext_info_c = kexalgs_ਸ਼ਾਮਲ_ਹੈ(peer, "ext-info-c");
			kex->kex_strict = kexalgs_ਸ਼ਾਮਲ_ਹੈ(peer,
			    "kex-strict-c-v00@openssh.com");
		} ਨਹੀਂਤਾਂ {
			kex->ext_info_s = kexalgs_ਸ਼ਾਮਲ_ਹੈ(peer, "ext-info-s");
			kex->kex_strict = kexalgs_ਸ਼ਾਮਲ_ਹੈ(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ਜੇ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ਜੇ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ਜੇ (kex->server && (kex->flags & KEX_INITIAL)) {
		ਜੇ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ਜੇ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ਜੇ ((r = ਚੁਣੋ_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ਨਿਰਾ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ਚੁਣੋ_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS];
		peer[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = ਨਿਰਾ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (ਬਹੁਲਕ = 0; ਬਹੁਲਕ < ਬਹੁਲਕ_MAX; ਬਹੁਲਕ++) {
		ਜੇ ((newkeys = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*newkeys))) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		kex->newkeys[ਬਹੁਲਕ] = newkeys;
		ctos = (!kex->server && ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ) ||
		    (kex->server && ਬਹੁਲਕ == ਬਹੁਲਕ_ਵਿੱਚ);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ਜੇ ((r = ਚੁਣੋ_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ਨਿਰਾ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ਜੇ (authlen == 0 &&
		    (r = ਚੁਣੋ_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ਨਿਰਾ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = ਚੁਣੋ_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ਨਿਰਾ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	ਲਈ (ਬਹੁਲਕ = 0; ਬਹੁਲਕ < ਬਹੁਲਕ_MAX; ਬਹੁਲਕ++) {
		newkeys = kex->newkeys[ਬਹੁਲਕ];
		need = ਵੱਧ_ਤੋਂ_ਵੱਧ(need, newkeys->enc.ਕੁੰਜੀ_len);
		need = ਵੱਧ_ਤੋਂ_ਵੱਧ(need, newkeys->enc.ਖੰਡ_ਮਾਪ);
		need = ਵੱਧ_ਤੋਂ_ਵੱਧ(need, newkeys->enc.iv_len);
		need = ਵੱਧ_ਤੋਂ_ਵੱਧ(need, newkeys->mac.ਕੁੰਜੀ_len);
		dh_need = ਵੱਧ_ਤੋਂ_ਵੱਧ(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = ਵੱਧ_ਤੋਂ_ਵੱਧ(dh_need, newkeys->enc.ਖੰਡ_ਮਾਪ);
		dh_need = ਵੱਧ_ਤੋਂ_ਵੱਧ(dh_need, newkeys->enc.iv_len);
		dh_need = ਵੱਧ_ਤੋਂ_ਵੱਧ(dh_need, newkeys->mac.ਕੁੰਜੀ_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	ਜੇ (ਪਹਿਲਾ_kex_follows && !proposals_ਮੇਲ(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 ਬਾਹਰਲਾ:
	kex_prop_free(my);
	kex_prop_free(peer);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
derive_ਕੁੰਜੀ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, u_int need, u_char *hash, u_int hashlen,
    ਅਚਲ ਬਣਤਰ sshbuf *shared_secret, u_char **keyp)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਬਣਤਰ ssh_digest_ctx *hashctx = ਨਿਰਾ;
	ਅੱਖਰ c = id;
	u_int have;
	ਮਾਪ_t mdsz;
	u_char *digest;
	ਪੂਰਨ r;

	ਜੇ ((mdsz = ssh_digest_ਬਾਈਟਾਂ(kex->hash_alg)) == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((digest = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ROUNDUP(need, mdsz))) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ਜੇ ((hashctx = ssh_digest_ਸ਼ੁਰੂ(kex->hash_alg)) == ਨਿਰਾ ||
	    ssh_digest_update_ਬਫਰ(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_ਬਫਰ(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ssh_digest_free(hashctx);
	hashctx = ਨਿਰਾ;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	ਲਈ (have = mdsz; need > have; have += mdsz) {
		ਜੇ ((hashctx = ssh_digest_ਸ਼ੁਰੂ(kex->hash_alg)) == ਨਿਰਾ ||
		    ssh_digest_update_ਬਫਰ(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ssh_digest_free(hashctx);
		hashctx = ਨਿਰਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#ਜੇ_ਅੰਤ
	*keyp = digest;
	digest = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(digest);
	ssh_digest_free(hashctx);
	ਵਾਪਸ r;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NKEYS	6
ਪੂਰਨ
kex_derive_ਕੁੰਜੀਆਂ(ਬਣਤਰ ssh *ssh, u_char *hash, u_int hashlen,
    ਅਚਲ ਬਣਤਰ sshbuf *shared_secret)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	u_char *ਕੁੰਜੀਆਂ[NKEYS];
	u_int i, j, ਬਹੁਲਕ, ctos;
	ਪੂਰਨ r;

	/* save initial hash as session id */
	ਜੇ ((kex->flags & KEX_INITIAL) != 0) {
		ਜੇ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		}
		ਜੇ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ਵਾਪਸ r;
	} ਨਹੀਂਤਾਂ ਜੇ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਲਈ (i = 0; i < NKEYS; i++) {
		ਜੇ ((r = derive_ਕੁੰਜੀ(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &ਕੁੰਜੀਆਂ[i])) != 0) {
			ਲਈ (j = 0; j < i; j++)
				ਮੁਕਤ(ਕੁੰਜੀਆਂ[j]);
			ਵਾਪਸ r;
		}
	}
	ਲਈ (ਬਹੁਲਕ = 0; ਬਹੁਲਕ < ਬਹੁਲਕ_MAX; ਬਹੁਲਕ++) {
		ctos = (!kex->server && ਬਹੁਲਕ == ਬਹੁਲਕ_ਬਾਹਰਲਾ) ||
		    (kex->server && ਬਹੁਲਕ == ਬਹੁਲਕ_ਵਿੱਚ);
		kex->newkeys[ਬਹੁਲਕ]->enc.iv  = ਕੁੰਜੀਆਂ[ctos ? 0 : 1];
		kex->newkeys[ਬਹੁਲਕ]->enc.ਕੁੰਜੀ = ਕੁੰਜੀਆਂ[ctos ? 2 : 3];
		kex->newkeys[ਬਹੁਲਕ]->mac.ਕੁੰਜੀ = ਕੁੰਜੀਆਂ[ctos ? 4 : 5];
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_ਲੱਦੋ_hostkey(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey **prvp, ਬਣਤਰ sshkey **pubp)
{
	ਬਣਤਰ kex *kex = ssh->kex;

	*pubp = ਨਿਰਾ;
	*prvp = ਨਿਰਾ;
	ਜੇ (kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ == ਨਿਰਾ ||
	    kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ == ਨਿਰਾ) {
		error_f("missing hostkey loader");
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	*pubp = kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ਜੇ (*pubp == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_NO_HOSTKEY_LOADED;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_verify_host_ਕੁੰਜੀ(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *server_host_ਕੁੰਜੀ)
{
	ਬਣਤਰ kex *kex = ssh->kex;

	ਜੇ (kex->verify_host_ਕੁੰਜੀ == ਨਿਰਾ) {
		error_f("missing hostkey verifier");
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	ਜੇ (server_host_ਕੁੰਜੀ->type != kex->hostkey_type ||
	    (kex->hostkey_type == ਕੁੰਜੀ_ECDSA &&
	    server_host_ਕੁੰਜੀ->ecdsa_nid != kex->hostkey_nid))
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
	ਜੇ (kex->verify_host_ਕੁੰਜੀ(server_host_ਕੁੰਜੀ, ssh) == -1)
		ਵਾਪਸ  SSH_ERR_SIGNATURE_INVALID;
	ਵਾਪਸ 0;
}

#ਜੇ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ਖਾਲੀ
dump_digest(ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ, ਅਚਲ u_char *digest, ਪੂਰਨ len)
{
	fprintf(stderr, "%s\n", ਸੁਨੇਹਾ);
	sshbuf_dump_ਅੰਕੜੇ(digest, len, stderr);
}
#ਜੇ_ਅੰਤ

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ਸਥਿਰ ਖਾਲੀ
send_error(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	ਅੱਖਰ *crnl = "\r\n";

	ਜੇ (!ssh->kex->server)
		ਵਾਪਸ;

	ਜੇ (atomicio(vwrite, ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh),
	    ਸੁਨੇਹਾ, ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ)) != ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ) ||
	    atomicio(vwrite, ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh),
	    crnl, ਲੜੀ_ਲੰਬਾਈ(crnl)) != ਲੜੀ_ਲੰਬਾਈ(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
ਪੂਰਨ
kex_exchange_identification(ਬਣਤਰ ssh *ssh, ਪੂਰਨ timeout_ms,
    ਅਚਲ ਅੱਖਰ *ਸੰਸਕਰਣ_addendum)
{
	ਪੂਰਨ remote_major, remote_minor, mismatch, oerrno = 0;
	ਮਾਪ_t len, n;
	ਪੂਰਨ r, expect_nl;
	u_char c;
	ਬਣਤਰ sshbuf *our_ਸੰਸਕਰਣ = ssh->kex->server ?
	    ssh->kex->server_ਸੰਸਕਰਣ : ssh->kex->client_ਸੰਸਕਰਣ;
	ਬਣਤਰ sshbuf *peer_ਸੰਸਕਰਣ = ssh->kex->server ?
	    ssh->kex->client_ਸੰਸਕਰਣ : ssh->kex->server_ਸੰਸਕਰਣ;
	ਅੱਖਰ *our_ਸੰਸਕਰਣ_string = ਨਿਰਾ, *peer_ਸੰਸਕਰਣ_string = ਨਿਰਾ;
	ਅੱਖਰ *cp, *remote_ਸੰਸਕਰਣ = ਨਿਰਾ;

	/* Prepare and send our banner */
	sshbuf_reset(our_ਸੰਸਕਰਣ);
	ਜੇ (ਸੰਸਕਰਣ_addendum != ਨਿਰਾ && *ਸੰਸਕਰਣ_addendum == '\0')
		ਸੰਸਕਰਣ_addendum = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_putf(our_ਸੰਸਕਰਣ, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_ਸੰਸਕਰਣ,
	    ਸੰਸਕਰਣ_addendum == ਨਿਰਾ ? "" : " ",
	    ਸੰਸਕਰਣ_addendum == ਨਿਰਾ ? "" : ਸੰਸਕਰਣ_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (atomicio(vwrite, ssh_packet_get_connection_ਬਾਹਰਲਾ(ssh),
	    sshbuf_mutable_ptr(our_ਸੰਸਕਰਣ),
	    sshbuf_len(our_ਸੰਸਕਰਣ)) != sshbuf_len(our_ਸੰਸਕਰਣ)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(our_ਸੰਸਕਰਣ, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	our_ਸੰਸਕਰਣ_string = sshbuf_dup_string(our_ਸੰਸਕਰਣ);
	ਜੇ (our_ਸੰਸਕਰਣ_string == ਨਿਰਾ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug("Local version string %.100s", our_ਸੰਸਕਰਣ_string);

	/* Read other side's version identification. */
	ਲਈ (n = 0; ; n++) {
		ਜੇ (n >= SSH_MAX_PRE_BANNER_ਸਤਰਾਂ) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_ਸਤਰਾਂ);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		sshbuf_reset(peer_ਸੰਸਕਰਣ);
		expect_nl = 0;
		ਲਈ (;;) {
			ਜੇ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_ਵਿੱਚ(ssh),
				    &timeout_ms, ਨਿਰਾ);
				ਜੇ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					ਜਾਓ ਬਾਹਰਲਾ;
				} ਨਹੀਂਤਾਂ ਜੇ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}

			len = atomicio(ਪਠ, ssh_packet_get_connection_ਵਿੱਚ(ssh),
			    &c, 1);
			ਜੇ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				ਜਾਓ ਬਾਹਰਲਾ;
			} ਨਹੀਂਤਾਂ ਜੇ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (c == '\r') {
				expect_nl = 1;
				ਜਾਰੀ;
			}
			ਜੇ (c == '\n')
				ਰੋਕੋ;
			ਜੇ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				ਜਾਓ invalid;
			}
			ਜੇ ((r = sshbuf_put_u8(peer_ਸੰਸਕਰਣ, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (sshbuf_len(peer_ਸੰਸਕਰਣ) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				ਜਾਓ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ਜੇ (sshbuf_len(peer_ਸੰਸਕਰਣ) > 4 &&
		    memcmp(sshbuf_ptr(peer_ਸੰਸਕਰਣ), "SSH-", 4) == 0)
			ਰੋਕੋ;
		/* If not, then just log the line and continue */
		ਜੇ ((cp = sshbuf_dup_string(peer_ਸੰਸਕਰਣ)) == ਨਿਰਾ) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Do not accept lines before the SSH ident from a client */
		ਜੇ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			ਮੁਕਤ(cp);
			ਜਾਓ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		ਮੁਕਤ(cp);
	}
	peer_ਸੰਸਕਰਣ_string = sshbuf_dup_string(peer_ਸੰਸਕਰਣ);
	ਜੇ (peer_ਸੰਸਕਰਣ_string == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ਜੇ ((remote_ਸੰਸਕਰਣ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, sshbuf_len(peer_ਸੰਸਕਰਣ))) == ਨਿਰਾ) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(peer_ਸੰਸਕਰਣ_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_ਸੰਸਕਰਣ) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_ਸੰਸਕਰਣ_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_ਸੰਸਕਰਣ);
	compat_banner(ssh, remote_ਸੰਸਕਰਣ);

	mismatch = 0;
	ਚੋਣ (remote_major) {
	ਹਾਲਤ 2:
		ਰੋਕੋ;
	ਹਾਲਤ 1:
		ਜੇ (remote_minor != 99)
			mismatch = 1;
		ਰੋਕੋ;
	ਮੂਲ:
		mismatch = 1;
		ਰੋਕੋ;
	}
	ਜੇ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_ਸੰਸਕਰਣ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
		    peer_ਸੰਸਕਰਣ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
		    peer_ਸੰਸਕਰਣ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(our_ਸੰਸਕਰਣ_string);
	ਮੁਕਤ(peer_ਸੰਸਕਰਣ_string);
	ssh->remote_ਸੰਸਕਰਣ = remote_ਸੰਸਕਰਣ;  /* transferred */
	ਜੇ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ਵਾਪਸ r;
}

