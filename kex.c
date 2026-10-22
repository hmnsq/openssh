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

#include "includes.h"

#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/crypto.h>
#include <openssl/dh.h>
#endif

#include "ssh.h"
#include "ssh2.h"
#include "atomicio.h"
#include "version.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "sshkey.h"
#include "kex.h"
#include "log.h"
#include "mac.h"
#include "match.h"
#include "misc.h"
#include "dispatch.h"
#include "myproposal.h"

#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"
#include "xmalloc.h"

/* prototype */
static จำนวนเต็ม kex_choose_conf(sa_nracanaa ssh *, uint32_t seq);
static จำนวนเต็ม kex_input_newkeys(จำนวนเต็ม, uint32_t, sa_nracanaa ssh *);

static const var_na * const proposal_names[PROPOSAL_MAX] = {
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
void
kex_proposal_populate_entries(sa_nracanaa ssh *ssh, var_na *prop[PROPOSAL_MAX],
    const var_na *kexalgos, const var_na *ciphers, const var_na *macs,
    const var_na *comp, const var_na *hkalgs)
{
	const var_na *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	const var_na *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	const var_na **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	var_na *cp;

	ถ้า (prop == NULL)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ถ้า (kexalgos == NULL)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ถ้า ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == NULL)
		fatal_f("kex_names_cat");

	สำหรับ (i = 0; i < PROPOSAL_MAX; i++) {
		switch(i) {
		pak_sa PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			bha_nga;
		pak_sa PROPOSAL_ENC_ALGS_CTOS:
		pak_sa PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			bha_nga;
		pak_sa PROPOSAL_MAC_ALGS_CTOS:
		pak_sa PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			bha_nga;
		pak_sa PROPOSAL_COMP_ALGS_CTOS:
		pak_sa PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			bha_nga;
		pak_sa PROPOSAL_SERVER_HOST_KEY_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			bha_nga;
		default:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	free(cp);
}

void
kex_proposal_free_entries(var_na *prop[PROPOSAL_MAX])
{
	u_int i;

	สำหรับ (i = 0; i < PROPOSAL_MAX; i++)
		free(prop[i]);
}

/* put algorithm proposal into buffer */
จำนวนเต็ม
kex_prop2buf(sa_nracanaa sshbuf *b, var_na *proposal[PROPOSAL_MAX])
{
	u_int i;
	จำนวนเต็ม r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	สำหรับ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ถ้า ((r = sshbuf_put_u8(b, 0)) != 0)
			คืน r;
	}
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++) {
		ถ้า ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			คืน r;
	}
	ถ้า ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		คืน r;
	คืน 0;
}

/* parse buffer and return algorithm proposal */
จำนวนเต็ม
kex_buf2prop(sa_nracanaa sshbuf *raw, จำนวนเต็ม *first_kex_follows, var_na ***propp)
{
	sa_nracanaa sshbuf *b = NULL;
	u_char v;
	u_int i;
	var_na **proposal = NULL;
	จำนวนเต็ม r;

	*propp = NULL;
	ถ้า ((proposal = calloc(PROPOSAL_MAX, parimaa_na(var_na *))) == NULL)
		คืน SSH_ERR_ALLOC_FAIL;
	ถ้า ((b = sshbuf_fromb(raw)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ถ้า ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		goto out;
	}
	/* extract kex init proposal strings */
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++) {
		ถ้า ((r = sshbuf_get_cstring(b, &(proposal[i]), NULL)) != 0) {
			error_fr(r, "parse proposal %u", i);
			goto out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ถ้า ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		goto out;
	}
	ถ้า (first_kex_follows != NULL)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	ถ้า (r != 0 && proposal != NULL)
		kex_prop_free(proposal);
	sshbuf_free(b);
	คืน r;
}

void
kex_prop_free(var_na **proposal)
{
	u_int i;

	ถ้า (proposal == NULL)
		คืน;
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	free(proposal);
}

จำนวนเต็ม
kex_protocol_error(จำนวนเต็ม type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	จำนวนเต็ม r;

	/* If in strict mode, any unexpected message is an error */
	ถ้า ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ถ้า ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		คืน r;
	คืน 0;
}

static void
kex_reset_dispatch(sa_nracanaa ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_MSG_TRANSPORT_MIN,
	    SSH2_MSG_TRANSPORT_MAX, &kex_protocol_error);
}

void
kex_set_server_sig_algs(sa_nracanaa ssh *ssh, const var_na *allowed_algs)
{
	var_na *alg, *oalgs, *algs, *sigalgs;
	const var_na *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ถ้า ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == NULL)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	free(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = NULL;
	สำหรับ ((alg = strsep(&algs, ",")); alg != NULL && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ถ้า ((sigalg = sshkey_sigalg_by_name(alg)) == NULL)
			continue;
		ถ้า (!kex_has_any_alg(sigalg, sigalgs))
			continue;
		/* Don't add an algorithm twice. */
		ถ้า (ssh->kex->server_sig_algs != NULL &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			continue;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	free(oalgs);
	free(sigalgs);
	ถ้า (ssh->kex->server_sig_algs == NULL)
		ssh->kex->server_sig_algs = xstrdup("");
}

void
kex_set_warn_weak_crypto(sa_nracanaa ssh *ssh, จำนวนเต็ม warn_weak_crypto)
{
	ถ้า (ssh != NULL && ssh->kex != NULL)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

void
kex_check_warn_weak_crypto(sa_nracanaa ssh *ssh)
{
	var_na remote_id[512];
	จำนวนเต็ม rekeyed = 0;

	ถ้า (ssh == NULL || ssh->kex == NULL || ssh->kex->name == NULL ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		คืน;
	ถ้า (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		คืน;
	}

	ถ้า (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ถ้า (!rekeyed && !ssh->kex->server)
		คืน; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, parimaa_na(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

static จำนวนเต็ม
kex_compose_ext_info_server(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *m)
{
	จำนวนเต็ม r;

	ถ้า (ssh->kex->server_sig_algs == NULL &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == NULL)
		คืน SSH_ERR_ALLOC_FAIL;
	ถ้า ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		คืน r;
	}
	คืน 0;
}

static จำนวนเต็ม
kex_compose_ext_info_client(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *m)
{
	จำนวนเต็ม r;

	ถ้า ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		goto out;
	}
	/* success */
	r = 0;
 out:
	คืน r;
}

static จำนวนเต็ม
kex_maybe_send_ext_info(sa_nracanaa ssh *ssh)
{
	จำนวนเต็ม r;
	sa_nracanaa sshbuf *m = NULL;

	ถ้า ((ssh->kex->flags & KEX_INITIAL) == 0)
		คืน 0;
	ถ้า (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		คืน 0;

	/* Compose EXT_INFO packet. */
	ถ้า ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	ถ้า (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		goto fail;
	ถ้า (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		goto fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ถ้า ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		goto fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	คืน r;
}

จำนวนเต็ม
kex_server_update_ext_info(sa_nracanaa ssh *ssh)
{
	จำนวนเต็ม r;

	ถ้า ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		คืน 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ถ้า ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		คืน r;
	}
	คืน 0;
}

จำนวนเต็ม
kex_send_newkeys(sa_nracanaa ssh *ssh)
{
	จำนวนเต็ม r;

	kex_reset_dispatch(ssh);
	ถ้า ((r = sshpkt_start(ssh, SSH2_MSG_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		คืน r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_input_newkeys);
	ถ้า ((r = kex_maybe_send_ext_info(ssh)) != 0)
		คืน r;
	debug("expecting SSH2_MSG_NEWKEYS");
	คืน 0;
}

/* Check whether an ext_info value contains the expected version string */
static จำนวนเต็ม
kex_ext_info_check_ver(sa_nracanaa kex *kex, const var_na *name,
    const u_char *val, size_t len, const var_na *want_ver, u_int flag)
{
	ถ้า (memchr(val, '\0', len) != NULL) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		คืน SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ถ้า (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	มิฉะนั้น
		debug_f("unsupported version of %s extension", name);
	คืน 0;
}

static จำนวนเต็ม
kex_ext_info_client_parse(sa_nracanaa ssh *ssh, const var_na *name,
    const u_char *value, size_t vlen)
{
	จำนวนเต็ม r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ถ้า (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ถ้า (memchr(value, '\0', vlen) != NULL) {
			error_f("nul byte in %s", name);
			คืน SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, value);
		free(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((const var_na *)value);
	} มิฉะนั้น ถ้า (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ถ้า ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			คืน r;
		}
	} มิฉะนั้น ถ้า (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ถ้า ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			คืน r;
		}
	} มิฉะนั้น ถ้า (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ถ้า ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			คืน r;
		}
	} มิฉะนั้น
		debug_f("%s (unrecognised)", name);

	คืน 0;
}

static จำนวนเต็ม
kex_ext_info_server_parse(sa_nracanaa ssh *ssh, const var_na *name,
    const u_char *value, size_t vlen)
{
	จำนวนเต็ม r;

	ถ้า (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ถ้า ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			คืน r;
		}
	} มิฉะนั้น
		debug_f("%s (unrecognised)", name);
	คืน 0;
}

จำนวนเต็ม
kex_input_ext_info(จำนวนเต็ม type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	const จำนวนเต็ม max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	var_na *name;
	u_char *val;
	size_t vlen;
	จำนวนเต็ม r;

	debug("SSH2_MSG_EXT_INFO received");
	ถ้า (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		คืน dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_protocol_error);
	ถ้า ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		คืน r;
	ถ้า (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		คืน dispatch_protocol_error(type, seq, ssh);
	}
	สำหรับ (i = 0; i < ninfo; i++) {
		ถ้า ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0)
			คืน r;
		ถ้า ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			free(name);
			คืน r;
		}
		debug3_f("extension %s", name);
		ถ้า (kex->server) {
			ถ้า ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				คืน r;
		} มิฉะนั้น {
			ถ้า ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				คืน r;
		}
		free(name);
		free(val);
	}
	คืน sshpkt_get_end(ssh);
}

static จำนวนเต็ม
kex_input_newkeys(จำนวนเต็ม type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	จำนวนเต็ม r, initial = (kex->flags & KEX_INITIAL) != 0;
	var_na *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ถ้า (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	ถ้า ((r = sshpkt_get_end(ssh)) != 0)
		คืน r;
	ถ้า ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		คืน r;
	ถ้า (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ถ้า ((r = kex_buf2prop(kex->my, NULL, &prop)) != 0)
			คืน r;
		ถ้า ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == NULL) {
			error_f("match_filter_denylist failed");
			goto fail;
		}
		free(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ถ้า ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			free(prop);
			คืน SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		free(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	คืน 0;
}

จำนวนเต็ม
kex_send_kexinit(sa_nracanaa ssh *ssh)
{
	u_char *cookie;
	sa_nracanaa kex *kex = ssh->kex;
	จำนวนเต็ม r;

	ถ้า (kex == NULL) {
		error_f("no kex");
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	ถ้า (kex->flags & KEX_INIT_SENT)
		คืน 0;
	kex->done = 0;

	/* generate a random cookie */
	ถ้า (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		คืน SSH_ERR_INVALID_FORMAT;
	}
	ถ้า ((cookie = sshbuf_mutable_ptr(kex->my)) == NULL) {
		error_f("buffer error");
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ถ้า ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		คืน r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	คืน 0;
}

จำนวนเต็ม
kex_input_kexinit(จำนวนเต็ม type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	const u_char *ptr;
	u_int i;
	size_t dlen;
	จำนวนเต็ม r;

	debug("SSH2_MSG_KEXINIT received");
	ถ้า (kex == NULL) {
		error_f("no kex");
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	free(kex->name);
	kex->name = NULL;
	ถ้า ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ถ้า ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		คืน r;

	/* discard packet */
	สำหรับ (i = 0; i < KEX_COOKIE_LEN; i++) {
		ถ้า ((r = sshpkt_get_u8(ssh, NULL)) != 0) {
			error_fr(r, "discard cookie");
			คืน r;
		}
	}
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++) {
		ถ้า ((r = sshpkt_get_string(ssh, NULL, NULL)) != 0) {
			error_fr(r, "discard proposal");
			คืน r;
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
	ถ้า ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			คืน r;

	ถ้า (!(kex->flags & KEX_INIT_SENT))
		ถ้า ((r = kex_send_kexinit(ssh)) != 0)
			คืน r;
	ถ้า ((r = kex_choose_conf(ssh, seq)) != 0)
		คืน r;

	ถ้า (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != NULL)
		คืน (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	คืน SSH_ERR_INTERNAL_ERROR;
}

sa_nracanaa kex *
kex_new(void)
{
	sa_nracanaa kex *kex;

	ถ้า ((kex = calloc(1, parimaa_na(*kex))) == NULL ||
	    (kex->peer = sshbuf_new()) == NULL ||
	    (kex->my = sshbuf_new()) == NULL ||
	    (kex->client_version = sshbuf_new()) == NULL ||
	    (kex->server_version = sshbuf_new()) == NULL ||
	    (kex->session_id = sshbuf_new()) == NULL) {
		kex_free(kex);
		คืน NULL;
	}
	คืน kex;
}

void
kex_free_newkeys(sa_nracanaa newkeys *newkeys)
{
	ถ้า (newkeys == NULL)
		คืน;
	ถ้า (newkeys->enc.key) {
		explicit_bzero(newkeys->enc.key, newkeys->enc.key_len);
		free(newkeys->enc.key);
		newkeys->enc.key = NULL;
	}
	ถ้า (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		free(newkeys->enc.iv);
		newkeys->enc.iv = NULL;
	}
	free(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, parimaa_na(newkeys->enc));
	free(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, parimaa_na(newkeys->comp));
	mac_clear(&newkeys->mac);
	ถ้า (newkeys->mac.key) {
		explicit_bzero(newkeys->mac.key, newkeys->mac.key_len);
		free(newkeys->mac.key);
		newkeys->mac.key = NULL;
	}
	free(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, parimaa_na(newkeys->mac));
	freezero(newkeys, parimaa_na(*newkeys));
}

void
kex_free(sa_nracanaa kex *kex)
{
	u_int mode;

	ถ้า (kex == NULL)
		คืน;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_KEY_free(kex->ec_client_key);
#endif /* WITH_OPENSSL */
	สำหรับ (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = NULL;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	free(kex->failed_choice);
	free(kex->hostkey_alg);
	free(kex->name);
	free(kex->server_sig_algs);
	free(kex);
}

จำนวนเต็ม
kex_ready(sa_nracanaa ssh *ssh, var_na *proposal[PROPOSAL_MAX])
{
	จำนวนเต็ม r;

	ถ้า ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		คืน r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	คืน 0;
}

จำนวนเต็ม
kex_setup(sa_nracanaa ssh *ssh, var_na *proposal[PROPOSAL_MAX])
{
	จำนวนเต็ม r;

	ถ้า ((r = kex_ready(ssh, proposal)) != 0)
		คืน r;
	ถ้า ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = NULL;
		คืน r;
	}
	คืน 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
จำนวนเต็ม
kex_start_rekex(sa_nracanaa ssh *ssh)
{
	ถ้า (ssh->kex == NULL) {
		error_f("no kex");
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	ถ้า (ssh->kex->done == 0) {
		error_f("requested twice");
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	คืน kex_send_kexinit(ssh);
}

static จำนวนเต็ม
choose_enc(sa_nracanaa sshenc *enc, var_na *client, var_na *server)
{
	var_na *name = match_list(client, server, NULL);

	ถ้า (name == NULL)
		คืน SSH_ERR_NO_CIPHER_ALG_MATCH;
	ถ้า ((enc->cipher = cipher_by_name(name)) == NULL) {
		error_f("unsupported cipher %s", name);
		free(name);
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = NULL;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->key = NULL;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	คืน 0;
}

static จำนวนเต็ม
choose_mac(sa_nracanaa ssh *ssh, sa_nracanaa sshmac *mac, var_na *client, var_na *server)
{
	var_na *name = match_list(client, server, NULL);

	ถ้า (name == NULL)
		คืน SSH_ERR_NO_MAC_ALG_MATCH;
	ถ้า (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		free(name);
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->key = NULL;
	mac->enabled = 0;
	คืน 0;
}

static จำนวนเต็ม
choose_comp(sa_nracanaa sshcomp *comp, var_na *client, var_na *server)
{
	var_na *name = match_list(client, server, NULL);

	ถ้า (name == NULL)
		คืน SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	ถ้า (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} มิฉะนั้น
#endif	/* WITH_ZLIB */
	ถ้า (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} มิฉะนั้น {
		error_f("unsupported compression scheme %s", name);
		free(name);
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	คืน 0;
}

static จำนวนเต็ม
choose_kex(sa_nracanaa kex *k, var_na *client, var_na *server)
{
	k->name = match_list(client, server, NULL);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ถ้า (k->name == NULL)
		คืน SSH_ERR_NO_KEX_ALG_MATCH;
	ถ้า (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	คืน 0;
}

static จำนวนเต็ม
choose_hostkeyalg(sa_nracanaa kex *k, var_na *client, var_na *server)
{
	free(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, NULL);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ถ้า (k->hostkey_alg == NULL)
		คืน SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ถ้า (k->hostkey_type == KEY_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	คืน 0;
}

static จำนวนเต็ม
proposals_match(var_na *my[PROPOSAL_MAX], var_na *peer[PROPOSAL_MAX])
{
	static จำนวนเต็ม check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	จำนวนเต็ม *idx;
	var_na *p;

	สำหรับ (idx = &check[0]; *idx != -1; idx++) {
		ถ้า ((p = strchr(my[*idx], ',')) != NULL)
			*p = '\0';
		ถ้า ((p = strchr(peer[*idx], ',')) != NULL)
			*p = '\0';
		ถ้า (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			คืน (0);
		}
	}
	debug2("proposals match");
	คืน (1);
}

static จำนวนเต็ม
kexalgs_contains(var_na **peer, const var_na *ext)
{
	คืน kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

static จำนวนเต็ม
kex_choose_conf(sa_nracanaa ssh *ssh, uint32_t seq)
{
	sa_nracanaa kex *kex = ssh->kex;
	sa_nracanaa newkeys *newkeys;
	var_na **my = NULL, **peer = NULL;
	var_na **cprop, **sprop;
	จำนวนเต็ม nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	จำนวนเต็ม r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ถ้า ((r = kex_buf2prop(kex->my, NULL, &my)) != 0)
		goto out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ถ้า ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		goto out;

	ถ้า (kex->server) {
		cprop=peer;
		sprop=my;
	} มิฉะนั้น {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ถ้า ((kex->flags & KEX_INITIAL) != 0) {
		ถ้า (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} มิฉะนั้น {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ถ้า (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ถ้า (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ถ้า (kex->server && (kex->flags & KEX_INITIAL)) {
		ถ้า (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ถ้า (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ถ้า ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = NULL;
		goto out;
	}
	ถ้า ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_KEY_ALGS];
		peer[PROPOSAL_SERVER_HOST_KEY_ALGS] = NULL;
		goto out;
	}
	สำหรับ (mode = 0; mode < MODE_MAX; mode++) {
		ถ้า ((newkeys = calloc(1, parimaa_na(*newkeys))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ถ้า ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = NULL;
			goto out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ถ้า (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = NULL;
			goto out;
		}
		ถ้า ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = NULL;
			goto out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	สำหรับ (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.key_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.key_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.key_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	ถ้า (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	คืน r;
}

static จำนวนเต็ม
derive_key(sa_nracanaa ssh *ssh, จำนวนเต็ม id, u_int need, u_char *hash, u_int hashlen,
    const sa_nracanaa sshbuf *shared_secret, u_char **keyp)
{
	sa_nracanaa kex *kex = ssh->kex;
	sa_nracanaa ssh_digest_ctx *hashctx = NULL;
	var_na c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	จำนวนเต็ม r;

	ถ้า ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		คืน SSH_ERR_INVALID_ARGUMENT;
	ถ้า ((digest = calloc(1, ROUNDUP(need, mdsz))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ถ้า ((hashctx = ssh_digest_start(kex->hash_alg)) == NULL ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		goto out;
	}
	ssh_digest_free(hashctx);
	hashctx = NULL;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	สำหรับ (have = mdsz; need > have; have += mdsz) {
		ถ้า ((hashctx = ssh_digest_start(kex->hash_alg)) == NULL ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		ssh_digest_free(hashctx);
		hashctx = NULL;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = NULL;
	r = 0;
 out:
	free(digest);
	ssh_digest_free(hashctx);
	คืน r;
}

#define NKEYS	6
จำนวนเต็ม
kex_derive_keys(sa_nracanaa ssh *ssh, u_char *hash, u_int hashlen,
    const sa_nracanaa sshbuf *shared_secret)
{
	sa_nracanaa kex *kex = ssh->kex;
	u_char *keys[NKEYS];
	u_int i, j, mode, ctos;
	จำนวนเต็ม r;

	/* save initial hash as session id */
	ถ้า ((kex->flags & KEX_INITIAL) != 0) {
		ถ้า (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			คืน SSH_ERR_INTERNAL_ERROR;
		}
		ถ้า ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			คืน r;
	} มิฉะนั้น ถ้า (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	สำหรับ (i = 0; i < NKEYS; i++) {
		ถ้า ((r = derive_key(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &keys[i])) != 0) {
			สำหรับ (j = 0; j < i; j++)
				free(keys[j]);
			คืน r;
		}
	}
	สำหรับ (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.key = keys[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
	คืน 0;
}

จำนวนเต็ม
kex_load_hostkey(sa_nracanaa ssh *ssh, sa_nracanaa sshkey **prvp, sa_nracanaa sshkey **pubp)
{
	sa_nracanaa kex *kex = ssh->kex;

	*pubp = NULL;
	*prvp = NULL;
	ถ้า (kex->load_host_public_key == NULL ||
	    kex->load_host_private_key == NULL) {
		error_f("missing hostkey loader");
		คืน SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ถ้า (*pubp == NULL)
		คืน SSH_ERR_NO_HOSTKEY_LOADED;
	คืน 0;
}

จำนวนเต็ม
kex_verify_host_key(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *server_host_key)
{
	sa_nracanaa kex *kex = ssh->kex;

	ถ้า (kex->verify_host_key == NULL) {
		error_f("missing hostkey verifier");
		คืน SSH_ERR_INVALID_ARGUMENT;
	}
	ถ้า (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid))
		คืน SSH_ERR_KEY_TYPE_MISMATCH;
	ถ้า (kex->verify_host_key(server_host_key, ssh) == -1)
		คืน  SSH_ERR_SIGNATURE_INVALID;
	คืน 0;
}

#ถ้า defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void
dump_digest(const var_na *msg, const u_char *digest, จำนวนเต็ม len)
{
	fprintf(stderr, "%s\n", msg);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
static void
send_error(sa_nracanaa ssh *ssh, var_na *msg)
{
	var_na *crnl = "\r\n";

	ถ้า (!ssh->kex->server)
		คืน;

	ถ้า (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    msg, strlen(msg)) != strlen(msg) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
จำนวนเต็ม
kex_exchange_identification(sa_nracanaa ssh *ssh, จำนวนเต็ม timeout_ms,
    const var_na *version_addendum)
{
	จำนวนเต็ม remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	จำนวนเต็ม r, expect_nl;
	u_char c;
	sa_nracanaa sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	sa_nracanaa sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	var_na *our_version_string = NULL, *peer_version_string = NULL;
	var_na *cp, *remote_version = NULL;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	ถ้า (version_addendum != NULL && *version_addendum == '\0')
		version_addendum = NULL;
	ถ้า ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == NULL ? "" : " ",
	    version_addendum == NULL ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		goto out;
	}

	ถ้า (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	ถ้า ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		goto out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	ถ้า (our_version_string == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	สำหรับ (n = 0; ; n++) {
		ถ้า (n >= SSH_MAX_PRE_BANNER_LINES) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_LINES);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		สำหรับ (;;) {
			ถ้า (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, NULL);
				ถ้า (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					goto out;
				} มิฉะนั้น ถ้า (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					goto out;
				}
			}

			len = atomicio(read, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			ถ้า (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				goto out;
			} มิฉะนั้น ถ้า (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			ถ้า (c == '\r') {
				expect_nl = 1;
				continue;
			}
			ถ้า (c == '\n')
				bha_nga;
			ถ้า (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				goto invalid;
			}
			ถ้า ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				goto out;
			}
			ถ้า (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				goto invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ถ้า (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			bha_nga;
		/* If not, then just log the line and continue */
		ถ้า ((cp = sshbuf_dup_string(peer_version)) == NULL) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		/* Do not accept lines before the SSH ident from a client */
		ถ้า (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			free(cp);
			goto invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		free(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	ถ้า (peer_version_string == NULL)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ถ้า ((remote_version = calloc(1, sshbuf_len(peer_version))) == NULL) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ถ้า (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	switch (remote_major) {
	pak_sa 2:
		bha_nga;
	pak_sa 1:
		ถ้า (remote_minor != 99)
			mismatch = 1;
		bha_nga;
	default:
		mismatch = 1;
		bha_nga;
	}
	ถ้า (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		goto out;
	}

	ถ้า (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		goto out;
	}
	ถ้า (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(our_version_string);
	free(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	ถ้า (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	คืน r;
}

