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
static ကိန်းပြည့် kex_choose_conf(sa_nracanaa ssh *, uint32_t seq);
static ကိန်းပြည့် kex_input_newkeys(ကိန်းပြည့်, uint32_t, sa_nracanaa ssh *);

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

	အကယ်၍ (prop == NULL)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	အကယ်၍ (kexalgos == NULL)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	အကယ်၍ ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == NULL)
		fatal_f("kex_names_cat");

	အတွက် (i = 0; i < PROPOSAL_MAX; i++) {
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

	အတွက် (i = 0; i < PROPOSAL_MAX; i++)
		free(prop[i]);
}

/* put algorithm proposal into buffer */
ကိန်းပြည့်
kex_prop2buf(sa_nracanaa sshbuf *b, var_na *proposal[PROPOSAL_MAX])
{
	u_int i;
	ကိန်းပြည့် r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	အတွက် (i = 0; i < KEX_COOKIE_LEN; i++) {
		အကယ်၍ ((r = sshbuf_put_u8(b, 0)) != 0)
			ပြန်ပေး r;
	}
	အတွက် (i = 0; i < PROPOSAL_MAX; i++) {
		အကယ်၍ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ပြန်ပေး r;
	}
	အကယ်၍ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ပြန်ပေး r;
	ပြန်ပေး 0;
}

/* parse buffer and return algorithm proposal */
ကိန်းပြည့်
kex_buf2prop(sa_nracanaa sshbuf *raw, ကိန်းပြည့် *first_kex_follows, var_na ***propp)
{
	sa_nracanaa sshbuf *b = NULL;
	u_char v;
	u_int i;
	var_na **proposal = NULL;
	ကိန်းပြည့် r;

	*propp = NULL;
	အကယ်၍ ((proposal = calloc(PROPOSAL_MAX, parimaa_na(var_na *))) == NULL)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	အကယ်၍ ((b = sshbuf_fromb(raw)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		goto out;
	}
	/* extract kex init proposal strings */
	အတွက် (i = 0; i < PROPOSAL_MAX; i++) {
		အကယ်၍ ((r = sshbuf_get_cstring(b, &(proposal[i]), NULL)) != 0) {
			error_fr(r, "parse proposal %u", i);
			goto out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	အကယ်၍ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		goto out;
	}
	အကယ်၍ (first_kex_follows != NULL)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	အကယ်၍ (r != 0 && proposal != NULL)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ပြန်ပေး r;
}

void
kex_prop_free(var_na **proposal)
{
	u_int i;

	အကယ်၍ (proposal == NULL)
		ပြန်ပေး;
	အတွက် (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	free(proposal);
}

ကိန်းပြည့်
kex_protocol_error(ကိန်းပြည့် type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	ကိန်းပြည့် r;

	/* If in strict mode, any unexpected message is an error */
	အကယ်၍ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ပြန်ပေး r;
	ပြန်ပေး 0;
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
	အကယ်၍ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == NULL)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	free(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = NULL;
	အတွက် ((alg = strsep(&algs, ",")); alg != NULL && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		အကယ်၍ ((sigalg = sshkey_sigalg_by_name(alg)) == NULL)
			continue;
		အကယ်၍ (!kex_has_any_alg(sigalg, sigalgs))
			continue;
		/* Don't add an algorithm twice. */
		အကယ်၍ (ssh->kex->server_sig_algs != NULL &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			continue;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	free(oalgs);
	free(sigalgs);
	အကယ်၍ (ssh->kex->server_sig_algs == NULL)
		ssh->kex->server_sig_algs = xstrdup("");
}

void
kex_set_warn_weak_crypto(sa_nracanaa ssh *ssh, ကိန်းပြည့် warn_weak_crypto)
{
	အကယ်၍ (ssh != NULL && ssh->kex != NULL)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

void
kex_check_warn_weak_crypto(sa_nracanaa ssh *ssh)
{
	var_na remote_id[512];
	ကိန်းပြည့် rekeyed = 0;

	အကယ်၍ (ssh == NULL || ssh->kex == NULL || ssh->kex->name == NULL ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ပြန်ပေး;
	အကယ်၍ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ပြန်ပေး;
	}

	အကယ်၍ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	အကယ်၍ (!rekeyed && !ssh->kex->server)
		ပြန်ပေး; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, parimaa_na(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

static ကိန်းပြည့်
kex_compose_ext_info_server(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *m)
{
	ကိန်းပြည့် r;

	အကယ်၍ (ssh->kex->server_sig_algs == NULL &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == NULL)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	အကယ်၍ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		ပြန်ပေး r;
	}
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
kex_compose_ext_info_client(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *m)
{
	ကိန်းပြည့် r;

	အကယ်၍ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		goto out;
	}
	/* success */
	r = 0;
 out:
	ပြန်ပေး r;
}

static ကိန်းပြည့်
kex_maybe_send_ext_info(sa_nracanaa ssh *ssh)
{
	ကိန်းပြည့် r;
	sa_nracanaa sshbuf *m = NULL;

	အကယ်၍ ((ssh->kex->flags & KEX_INITIAL) == 0)
		ပြန်ပေး 0;
	အကယ်၍ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ပြန်ပေး 0;

	/* Compose EXT_INFO packet. */
	အကယ်၍ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	အကယ်၍ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		goto fail;
	အကယ်၍ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		goto fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		goto fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ပြန်ပေး r;
}

ကိန်းပြည့်
kex_server_update_ext_info(sa_nracanaa ssh *ssh)
{
	ကိန်းပြည့် r;

	အကယ်၍ ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		ပြန်ပေး 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ပြန်ပေး r;
	}
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_send_newkeys(sa_nracanaa ssh *ssh)
{
	ကိန်းပြည့် r;

	kex_reset_dispatch(ssh);
	အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ပြန်ပေး r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_input_newkeys);
	အကယ်၍ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ပြန်ပေး r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ပြန်ပေး 0;
}

/* Check whether an ext_info value contains the expected version string */
static ကိန်းပြည့်
kex_ext_info_check_ver(sa_nracanaa kex *kex, const var_na *name,
    const u_char *val, size_t len, const var_na *want_ver, u_int flag)
{
	အကယ်၍ (memchr(val, '\0', len) != NULL) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	အကယ်၍ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	မဟုတ်ပါက
		debug_f("unsupported version of %s extension", name);
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
kex_ext_info_client_parse(sa_nracanaa ssh *ssh, const var_na *name,
    const u_char *value, size_t vlen)
{
	ကိန်းပြည့် r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	အကယ်၍ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		အကယ်၍ (memchr(value, '\0', vlen) != NULL) {
			error_f("nul byte in %s", name);
			ပြန်ပေး SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, value);
		free(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((const var_na *)value);
	} မဟုတ်ပါက အကယ်၍ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		အကယ်၍ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ပြန်ပေး r;
		}
	} မဟုတ်ပါက အကယ်၍ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		အကယ်၍ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ပြန်ပေး r;
		}
	} မဟုတ်ပါက အကယ်၍ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		အကယ်၍ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ပြန်ပေး r;
		}
	} မဟုတ်ပါက
		debug_f("%s (unrecognised)", name);

	ပြန်ပေး 0;
}

static ကိန်းပြည့်
kex_ext_info_server_parse(sa_nracanaa ssh *ssh, const var_na *name,
    const u_char *value, size_t vlen)
{
	ကိန်းပြည့် r;

	အကယ်၍ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		အကယ်၍ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			ပြန်ပေး r;
		}
	} မဟုတ်ပါက
		debug_f("%s (unrecognised)", name);
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_input_ext_info(ကိန်းပြည့် type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	const ကိန်းပြည့် max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	var_na *name;
	u_char *val;
	size_t vlen;
	ကိန်းပြည့် r;

	debug("SSH2_MSG_EXT_INFO received");
	အကယ်၍ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ပြန်ပေး dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_protocol_error);
	အကယ်၍ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ပြန်ပေး r;
	အကယ်၍ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ပြန်ပေး dispatch_protocol_error(type, seq, ssh);
	}
	အတွက် (i = 0; i < ninfo; i++) {
		အကယ်၍ ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0)
			ပြန်ပေး r;
		အကယ်၍ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			free(name);
			ပြန်ပေး r;
		}
		debug3_f("extension %s", name);
		အကယ်၍ (kex->server) {
			အကယ်၍ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ပြန်ပေး r;
		} မဟုတ်ပါက {
			အကယ်၍ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ပြန်ပေး r;
		}
		free(name);
		free(val);
	}
	ပြန်ပေး sshpkt_get_end(ssh);
}

static ကိန်းပြည့်
kex_input_newkeys(ကိန်းပြည့် type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	ကိန်းပြည့် r, initial = (kex->flags & KEX_INITIAL) != 0;
	var_na *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	အကယ်၍ (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	အကယ်၍ ((r = sshpkt_get_end(ssh)) != 0)
		ပြန်ပေး r;
	အကယ်၍ ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		ပြန်ပေး r;
	အကယ်၍ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		အကယ်၍ ((r = kex_buf2prop(kex->my, NULL, &prop)) != 0)
			ပြန်ပေး r;
		အကယ်၍ ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == NULL) {
			error_f("match_filter_denylist failed");
			goto fail;
		}
		free(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		အကယ်၍ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			free(prop);
			ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		free(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_send_kexinit(sa_nracanaa ssh *ssh)
{
	u_char *cookie;
	sa_nracanaa kex *kex = ssh->kex;
	ကိန်းပြည့် r;

	အကယ်၍ (kex == NULL) {
		error_f("no kex");
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	အကယ်၍ (kex->flags & KEX_INIT_SENT)
		ပြန်ပေး 0;
	kex->done = 0;

	/* generate a random cookie */
	အကယ်၍ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	}
	အကယ်၍ ((cookie = sshbuf_mutable_ptr(kex->my)) == NULL) {
		error_f("buffer error");
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	အကယ်၍ ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ပြန်ပေး r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_input_kexinit(ကိန်းပြည့် type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	const u_char *ptr;
	u_int i;
	size_t dlen;
	ကိန်းပြည့် r;

	debug("SSH2_MSG_KEXINIT received");
	အကယ်၍ (kex == NULL) {
		error_f("no kex");
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	free(kex->name);
	kex->name = NULL;
	အကယ်၍ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	အကယ်၍ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ပြန်ပေး r;

	/* discard packet */
	အတွက် (i = 0; i < KEX_COOKIE_LEN; i++) {
		အကယ်၍ ((r = sshpkt_get_u8(ssh, NULL)) != 0) {
			error_fr(r, "discard cookie");
			ပြန်ပေး r;
		}
	}
	အတွက် (i = 0; i < PROPOSAL_MAX; i++) {
		အကယ်၍ ((r = sshpkt_get_string(ssh, NULL, NULL)) != 0) {
			error_fr(r, "discard proposal");
			ပြန်ပေး r;
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
	အကယ်၍ ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			ပြန်ပေး r;

	အကယ်၍ (!(kex->flags & KEX_INIT_SENT))
		အကယ်၍ ((r = kex_send_kexinit(ssh)) != 0)
			ပြန်ပေး r;
	အကယ်၍ ((r = kex_choose_conf(ssh, seq)) != 0)
		ပြန်ပေး r;

	အကယ်၍ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != NULL)
		ပြန်ပေး (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
}

sa_nracanaa kex *
kex_new(void)
{
	sa_nracanaa kex *kex;

	အကယ်၍ ((kex = calloc(1, parimaa_na(*kex))) == NULL ||
	    (kex->peer = sshbuf_new()) == NULL ||
	    (kex->my = sshbuf_new()) == NULL ||
	    (kex->client_version = sshbuf_new()) == NULL ||
	    (kex->server_version = sshbuf_new()) == NULL ||
	    (kex->session_id = sshbuf_new()) == NULL) {
		kex_free(kex);
		ပြန်ပေး NULL;
	}
	ပြန်ပေး kex;
}

void
kex_free_newkeys(sa_nracanaa newkeys *newkeys)
{
	အကယ်၍ (newkeys == NULL)
		ပြန်ပေး;
	အကယ်၍ (newkeys->enc.key) {
		explicit_bzero(newkeys->enc.key, newkeys->enc.key_len);
		free(newkeys->enc.key);
		newkeys->enc.key = NULL;
	}
	အကယ်၍ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		free(newkeys->enc.iv);
		newkeys->enc.iv = NULL;
	}
	free(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, parimaa_na(newkeys->enc));
	free(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, parimaa_na(newkeys->comp));
	mac_clear(&newkeys->mac);
	အကယ်၍ (newkeys->mac.key) {
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

	အကယ်၍ (kex == NULL)
		ပြန်ပေး;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_KEY_free(kex->ec_client_key);
#endif /* WITH_OPENSSL */
	အတွက် (mode = 0; mode < MODE_MAX; mode++) {
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

ကိန်းပြည့်
kex_ready(sa_nracanaa ssh *ssh, var_na *proposal[PROPOSAL_MAX])
{
	ကိန်းပြည့် r;

	အကယ်၍ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ပြန်ပေး r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_setup(sa_nracanaa ssh *ssh, var_na *proposal[PROPOSAL_MAX])
{
	ကိန်းပြည့် r;

	အကယ်၍ ((r = kex_ready(ssh, proposal)) != 0)
		ပြန်ပေး r;
	အကယ်၍ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = NULL;
		ပြန်ပေး r;
	}
	ပြန်ပေး 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
ကိန်းပြည့်
kex_start_rekex(sa_nracanaa ssh *ssh)
{
	အကယ်၍ (ssh->kex == NULL) {
		error_f("no kex");
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	အကယ်၍ (ssh->kex->done == 0) {
		error_f("requested twice");
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	ပြန်ပေး kex_send_kexinit(ssh);
}

static ကိန်းပြည့်
choose_enc(sa_nracanaa sshenc *enc, var_na *client, var_na *server)
{
	var_na *name = match_list(client, server, NULL);

	အကယ်၍ (name == NULL)
		ပြန်ပေး SSH_ERR_NO_CIPHER_ALG_MATCH;
	အကယ်၍ ((enc->cipher = cipher_by_name(name)) == NULL) {
		error_f("unsupported cipher %s", name);
		free(name);
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = NULL;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->key = NULL;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
choose_mac(sa_nracanaa ssh *ssh, sa_nracanaa sshmac *mac, var_na *client, var_na *server)
{
	var_na *name = match_list(client, server, NULL);

	အကယ်၍ (name == NULL)
		ပြန်ပေး SSH_ERR_NO_MAC_ALG_MATCH;
	အကယ်၍ (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		free(name);
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->key = NULL;
	mac->enabled = 0;
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
choose_comp(sa_nracanaa sshcomp *comp, var_na *client, var_na *server)
{
	var_na *name = match_list(client, server, NULL);

	အကယ်၍ (name == NULL)
		ပြန်ပေး SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	အကယ်၍ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} မဟုတ်ပါက
#endif	/* WITH_ZLIB */
	အကယ်၍ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} မဟုတ်ပါက {
		error_f("unsupported compression scheme %s", name);
		free(name);
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
choose_kex(sa_nracanaa kex *k, var_na *client, var_na *server)
{
	k->name = match_list(client, server, NULL);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	အကယ်၍ (k->name == NULL)
		ပြန်ပေး SSH_ERR_NO_KEX_ALG_MATCH;
	အကယ်၍ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
choose_hostkeyalg(sa_nracanaa kex *k, var_na *client, var_na *server)
{
	free(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, NULL);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	အကယ်၍ (k->hostkey_alg == NULL)
		ပြန်ပေး SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	အကယ်၍ (k->hostkey_type == KEY_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ပြန်ပေး 0;
}

static ကိန်းပြည့်
proposals_match(var_na *my[PROPOSAL_MAX], var_na *peer[PROPOSAL_MAX])
{
	static ကိန်းပြည့် check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	ကိန်းပြည့် *idx;
	var_na *p;

	အတွက် (idx = &check[0]; *idx != -1; idx++) {
		အကယ်၍ ((p = strchr(my[*idx], ',')) != NULL)
			*p = '\0';
		အကယ်၍ ((p = strchr(peer[*idx], ',')) != NULL)
			*p = '\0';
		အကယ်၍ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ပြန်ပေး (0);
		}
	}
	debug2("proposals match");
	ပြန်ပေး (1);
}

static ကိန်းပြည့်
kexalgs_contains(var_na **peer, const var_na *ext)
{
	ပြန်ပေး kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

static ကိန်းပြည့်
kex_choose_conf(sa_nracanaa ssh *ssh, uint32_t seq)
{
	sa_nracanaa kex *kex = ssh->kex;
	sa_nracanaa newkeys *newkeys;
	var_na **my = NULL, **peer = NULL;
	var_na **cprop, **sprop;
	ကိန်းပြည့် nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	ကိန်းပြည့် r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	အကယ်၍ ((r = kex_buf2prop(kex->my, NULL, &my)) != 0)
		goto out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	အကယ်၍ ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		goto out;

	အကယ်၍ (kex->server) {
		cprop=peer;
		sprop=my;
	} မဟုတ်ပါက {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	အကယ်၍ ((kex->flags & KEX_INITIAL) != 0) {
		အကယ်၍ (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} မဟုတ်ပါက {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		အကယ်၍ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			အကယ်၍ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	အကယ်၍ (kex->server && (kex->flags & KEX_INITIAL)) {
		အကယ်၍ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		အကယ်၍ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	အကယ်၍ ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = NULL;
		goto out;
	}
	အကယ်၍ ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_KEY_ALGS];
		peer[PROPOSAL_SERVER_HOST_KEY_ALGS] = NULL;
		goto out;
	}
	အတွက် (mode = 0; mode < MODE_MAX; mode++) {
		အကယ်၍ ((newkeys = calloc(1, parimaa_na(*newkeys))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		အကယ်၍ ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = NULL;
			goto out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		အကယ်၍ (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = NULL;
			goto out;
		}
		အကယ်၍ ((r = choose_comp(&newkeys->comp, cprop[ncomp],
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
	အတွက် (mode = 0; mode < MODE_MAX; mode++) {
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
	အကယ်၍ (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	ပြန်ပေး r;
}

static ကိန်းပြည့်
derive_key(sa_nracanaa ssh *ssh, ကိန်းပြည့် id, u_int need, u_char *hash, u_int hashlen,
    const sa_nracanaa sshbuf *shared_secret, u_char **keyp)
{
	sa_nracanaa kex *kex = ssh->kex;
	sa_nracanaa ssh_digest_ctx *hashctx = NULL;
	var_na c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	ကိန်းပြည့် r;

	အကယ်၍ ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	အကယ်၍ ((digest = calloc(1, ROUNDUP(need, mdsz))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	အကယ်၍ ((hashctx = ssh_digest_start(kex->hash_alg)) == NULL ||
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
	အတွက် (have = mdsz; need > have; have += mdsz) {
		အကယ်၍ ((hashctx = ssh_digest_start(kex->hash_alg)) == NULL ||
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
	ပြန်ပေး r;
}

#define NKEYS	6
ကိန်းပြည့်
kex_derive_keys(sa_nracanaa ssh *ssh, u_char *hash, u_int hashlen,
    const sa_nracanaa sshbuf *shared_secret)
{
	sa_nracanaa kex *kex = ssh->kex;
	u_char *keys[NKEYS];
	u_int i, j, mode, ctos;
	ကိန်းပြည့် r;

	/* save initial hash as session id */
	အကယ်၍ ((kex->flags & KEX_INITIAL) != 0) {
		အကယ်၍ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
		}
		အကယ်၍ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ပြန်ပေး r;
	} မဟုတ်ပါက အကယ်၍ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	}
	အတွက် (i = 0; i < NKEYS; i++) {
		အကယ်၍ ((r = derive_key(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &keys[i])) != 0) {
			အတွက် (j = 0; j < i; j++)
				free(keys[j]);
			ပြန်ပေး r;
		}
	}
	အတွက် (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.key = keys[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_load_hostkey(sa_nracanaa ssh *ssh, sa_nracanaa sshkey **prvp, sa_nracanaa sshkey **pubp)
{
	sa_nracanaa kex *kex = ssh->kex;

	*pubp = NULL;
	*prvp = NULL;
	အကယ်၍ (kex->load_host_public_key == NULL ||
	    kex->load_host_private_key == NULL) {
		error_f("missing hostkey loader");
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	အကယ်၍ (*pubp == NULL)
		ပြန်ပေး SSH_ERR_NO_HOSTKEY_LOADED;
	ပြန်ပေး 0;
}

ကိန်းပြည့်
kex_verify_host_key(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *server_host_key)
{
	sa_nracanaa kex *kex = ssh->kex;

	အကယ်၍ (kex->verify_host_key == NULL) {
		error_f("missing hostkey verifier");
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	}
	အကယ်၍ (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid))
		ပြန်ပေး SSH_ERR_KEY_TYPE_MISMATCH;
	အကယ်၍ (kex->verify_host_key(server_host_key, ssh) == -1)
		ပြန်ပေး  SSH_ERR_SIGNATURE_INVALID;
	ပြန်ပေး 0;
}

#အကယ်၍ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void
dump_digest(const var_na *msg, const u_char *digest, ကိန်းပြည့် len)
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

	အကယ်၍ (!ssh->kex->server)
		ပြန်ပေး;

	အကယ်၍ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
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
ကိန်းပြည့်
kex_exchange_identification(sa_nracanaa ssh *ssh, ကိန်းပြည့် timeout_ms,
    const var_na *version_addendum)
{
	ကိန်းပြည့် remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	ကိန်းပြည့် r, expect_nl;
	u_char c;
	sa_nracanaa sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	sa_nracanaa sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	var_na *our_version_string = NULL, *peer_version_string = NULL;
	var_na *cp, *remote_version = NULL;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	အကယ်၍ (version_addendum != NULL && *version_addendum == '\0')
		version_addendum = NULL;
	အကယ်၍ ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == NULL ? "" : " ",
	    version_addendum == NULL ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		goto out;
	}

	အကယ်၍ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	အကယ်၍ ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		goto out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	အကယ်၍ (our_version_string == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	အတွက် (n = 0; ; n++) {
		အကယ်၍ (n >= SSH_MAX_PRE_BANNER_LINES) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_LINES);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		အတွက် (;;) {
			အကယ်၍ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, NULL);
				အကယ်၍ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					goto out;
				} မဟုတ်ပါက အကယ်၍ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					goto out;
				}
			}

			len = atomicio(read, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			အကယ်၍ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				goto out;
			} မဟုတ်ပါက အကယ်၍ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			အကယ်၍ (c == '\r') {
				expect_nl = 1;
				continue;
			}
			အကယ်၍ (c == '\n')
				bha_nga;
			အကယ်၍ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				goto invalid;
			}
			အကယ်၍ ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				goto out;
			}
			အကယ်၍ (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				goto invalid;
			}
		}
		/* Is this an actual protocol banner? */
		အကယ်၍ (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			bha_nga;
		/* If not, then just log the line and continue */
		အကယ်၍ ((cp = sshbuf_dup_string(peer_version)) == NULL) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		/* Do not accept lines before the SSH ident from a client */
		အကယ်၍ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			free(cp);
			goto invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		free(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	အကယ်၍ (peer_version_string == NULL)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	အကယ်၍ ((remote_version = calloc(1, sshbuf_len(peer_version))) == NULL) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	အကယ်၍ (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
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
		အကယ်၍ (remote_minor != 99)
			mismatch = 1;
		bha_nga;
	default:
		mismatch = 1;
		bha_nga;
	}
	အကယ်၍ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		goto out;
	}

	အကယ်၍ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		goto out;
	}
	အကယ်၍ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
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
	အကယ်၍ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ပြန်ပေး r;
}

