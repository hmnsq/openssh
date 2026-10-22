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
static 整数 kex_choose_conf(struct ssh *, uint32_t seq);
static 整数 kex_input_newkeys(整数, uint32_t, struct ssh *);

static const char * const proposal_names[PROPOSAL_MAX] = {
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
kex_proposal_populate_entries(struct ssh *ssh, char *prop[PROPOSAL_MAX],
    const char *kexalgos, const char *ciphers, const char *macs,
    const char *comp, const char *hkalgs)
{
	const char *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	const char *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	const char **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	char *cp;

	もし (prop == NULL)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	もし (kexalgos == NULL)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	もし ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == NULL)
		fatal_f("kex_names_cat");

	ために (i = 0; i < PROPOSAL_MAX; i++) {
		switch(i) {
		case PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			break;
		case PROPOSAL_ENC_ALGS_CTOS:
		case PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			break;
		case PROPOSAL_MAC_ALGS_CTOS:
		case PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			break;
		case PROPOSAL_COMP_ALGS_CTOS:
		case PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			break;
		case PROPOSAL_SERVER_HOST_KEY_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			break;
		default:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	free(cp);
}

void
kex_proposal_free_entries(char *prop[PROPOSAL_MAX])
{
	u_int i;

	ために (i = 0; i < PROPOSAL_MAX; i++)
		free(prop[i]);
}

/* put algorithm proposal into buffer */
整数
kex_prop2buf(struct sshbuf *b, char *proposal[PROPOSAL_MAX])
{
	u_int i;
	整数 r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	ために (i = 0; i < KEX_COOKIE_LEN; i++) {
		もし ((r = sshbuf_put_u8(b, 0)) != 0)
			戻る r;
	}
	ために (i = 0; i < PROPOSAL_MAX; i++) {
		もし ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			戻る r;
	}
	もし ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		戻る r;
	戻る 0;
}

/* parse buffer and return algorithm proposal */
整数
kex_buf2prop(struct sshbuf *raw, 整数 *first_kex_follows, char ***propp)
{
	struct sshbuf *b = NULL;
	u_char v;
	u_int i;
	char **proposal = NULL;
	整数 r;

	*propp = NULL;
	もし ((proposal = calloc(PROPOSAL_MAX, sizeof(char *))) == NULL)
		戻る SSH_ERR_ALLOC_FAIL;
	もし ((b = sshbuf_fromb(raw)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	もし ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		goto out;
	}
	/* extract kex init proposal strings */
	ために (i = 0; i < PROPOSAL_MAX; i++) {
		もし ((r = sshbuf_get_cstring(b, &(proposal[i]), NULL)) != 0) {
			error_fr(r, "parse proposal %u", i);
			goto out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	もし ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		goto out;
	}
	もし (first_kex_follows != NULL)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	もし (r != 0 && proposal != NULL)
		kex_prop_free(proposal);
	sshbuf_free(b);
	戻る r;
}

void
kex_prop_free(char **proposal)
{
	u_int i;

	もし (proposal == NULL)
		戻る;
	ために (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	free(proposal);
}

整数
kex_protocol_error(整数 type, uint32_t seq, struct ssh *ssh)
{
	整数 r;

	/* If in strict mode, any unexpected message is an error */
	もし ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	もし ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		戻る r;
	戻る 0;
}

static void
kex_reset_dispatch(struct ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_MSG_TRANSPORT_MIN,
	    SSH2_MSG_TRANSPORT_MAX, &kex_protocol_error);
}

void
kex_set_server_sig_algs(struct ssh *ssh, const char *allowed_algs)
{
	char *alg, *oalgs, *algs, *sigalgs;
	const char *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	もし ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == NULL)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	free(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = NULL;
	ために ((alg = strsep(&algs, ",")); alg != NULL && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		もし ((sigalg = sshkey_sigalg_by_name(alg)) == NULL)
			continue;
		もし (!kex_has_any_alg(sigalg, sigalgs))
			continue;
		/* Don't add an algorithm twice. */
		もし (ssh->kex->server_sig_algs != NULL &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			continue;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	free(oalgs);
	free(sigalgs);
	もし (ssh->kex->server_sig_algs == NULL)
		ssh->kex->server_sig_algs = xstrdup("");
}

void
kex_set_warn_weak_crypto(struct ssh *ssh, 整数 warn_weak_crypto)
{
	もし (ssh != NULL && ssh->kex != NULL)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

void
kex_check_warn_weak_crypto(struct ssh *ssh)
{
	char remote_id[512];
	整数 rekeyed = 0;

	もし (ssh == NULL || ssh->kex == NULL || ssh->kex->name == NULL ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		戻る;
	もし (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		戻る;
	}

	もし (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	もし (!rekeyed && !ssh->kex->server)
		戻る; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, sizeof(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

static 整数
kex_compose_ext_info_server(struct ssh *ssh, struct sshbuf *m)
{
	整数 r;

	もし (ssh->kex->server_sig_algs == NULL &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == NULL)
		戻る SSH_ERR_ALLOC_FAIL;
	もし ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		戻る r;
	}
	戻る 0;
}

static 整数
kex_compose_ext_info_client(struct ssh *ssh, struct sshbuf *m)
{
	整数 r;

	もし ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		goto out;
	}
	/* success */
	r = 0;
 out:
	戻る r;
}

static 整数
kex_maybe_send_ext_info(struct ssh *ssh)
{
	整数 r;
	struct sshbuf *m = NULL;

	もし ((ssh->kex->flags & KEX_INITIAL) == 0)
		戻る 0;
	もし (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		戻る 0;

	/* Compose EXT_INFO packet. */
	もし ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	もし (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		goto fail;
	もし (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		goto fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	もし ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		goto fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	戻る r;
}

整数
kex_server_update_ext_info(struct ssh *ssh)
{
	整数 r;

	もし ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		戻る 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	もし ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		戻る r;
	}
	戻る 0;
}

整数
kex_send_newkeys(struct ssh *ssh)
{
	整数 r;

	kex_reset_dispatch(ssh);
	もし ((r = sshpkt_start(ssh, SSH2_MSG_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		戻る r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_input_newkeys);
	もし ((r = kex_maybe_send_ext_info(ssh)) != 0)
		戻る r;
	debug("expecting SSH2_MSG_NEWKEYS");
	戻る 0;
}

/* Check whether an ext_info value contains the expected version string */
static 整数
kex_ext_info_check_ver(struct kex *kex, const char *name,
    const u_char *val, size_t len, const char *want_ver, u_int flag)
{
	もし (memchr(val, '\0', len) != NULL) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		戻る SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	もし (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	否则
		debug_f("unsupported version of %s extension", name);
	戻る 0;
}

static 整数
kex_ext_info_client_parse(struct ssh *ssh, const char *name,
    const u_char *value, size_t vlen)
{
	整数 r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	もし (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		もし (memchr(value, '\0', vlen) != NULL) {
			error_f("nul byte in %s", name);
			戻る SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, value);
		free(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((const char *)value);
	} 否则 もし (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		もし ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			戻る r;
		}
	} 否则 もし (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		もし ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			戻る r;
		}
	} 否则 もし (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		もし ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			戻る r;
		}
	} 否则
		debug_f("%s (unrecognised)", name);

	戻る 0;
}

static 整数
kex_ext_info_server_parse(struct ssh *ssh, const char *name,
    const u_char *value, size_t vlen)
{
	整数 r;

	もし (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		もし ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			戻る r;
		}
	} 否则
		debug_f("%s (unrecognised)", name);
	戻る 0;
}

整数
kex_input_ext_info(整数 type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	const 整数 max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	char *name;
	u_char *val;
	size_t vlen;
	整数 r;

	debug("SSH2_MSG_EXT_INFO received");
	もし (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		戻る dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_protocol_error);
	もし ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		戻る r;
	もし (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		戻る dispatch_protocol_error(type, seq, ssh);
	}
	ために (i = 0; i < ninfo; i++) {
		もし ((r = sshpkt_get_cstring(ssh, &name, NULL)) != 0)
			戻る r;
		もし ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			free(name);
			戻る r;
		}
		debug3_f("extension %s", name);
		もし (kex->server) {
			もし ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				戻る r;
		} 否则 {
			もし ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				戻る r;
		}
		free(name);
		free(val);
	}
	戻る sshpkt_get_end(ssh);
}

static 整数
kex_input_newkeys(整数 type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	整数 r, initial = (kex->flags & KEX_INITIAL) != 0;
	char *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	もし (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	もし ((r = sshpkt_get_end(ssh)) != 0)
		戻る r;
	もし ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		戻る r;
	もし (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		もし ((r = kex_buf2prop(kex->my, NULL, &prop)) != 0)
			戻る r;
		もし ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == NULL) {
			error_f("match_filter_denylist failed");
			goto fail;
		}
		free(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		もし ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			free(prop);
			戻る SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		free(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	戻る 0;
}

整数
kex_send_kexinit(struct ssh *ssh)
{
	u_char *cookie;
	struct kex *kex = ssh->kex;
	整数 r;

	もし (kex == NULL) {
		error_f("no kex");
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	もし (kex->flags & KEX_INIT_SENT)
		戻る 0;
	kex->done = 0;

	/* generate a random cookie */
	もし (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		戻る SSH_ERR_INVALID_FORMAT;
	}
	もし ((cookie = sshbuf_mutable_ptr(kex->my)) == NULL) {
		error_f("buffer error");
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	もし ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		戻る r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	戻る 0;
}

整数
kex_input_kexinit(整数 type, uint32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	const u_char *ptr;
	u_int i;
	size_t dlen;
	整数 r;

	debug("SSH2_MSG_KEXINIT received");
	もし (kex == NULL) {
		error_f("no kex");
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	free(kex->name);
	kex->name = NULL;
	もし ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	もし ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		戻る r;

	/* discard packet */
	ために (i = 0; i < KEX_COOKIE_LEN; i++) {
		もし ((r = sshpkt_get_u8(ssh, NULL)) != 0) {
			error_fr(r, "discard cookie");
			戻る r;
		}
	}
	ために (i = 0; i < PROPOSAL_MAX; i++) {
		もし ((r = sshpkt_get_string(ssh, NULL, NULL)) != 0) {
			error_fr(r, "discard proposal");
			戻る r;
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
	もし ((r = sshpkt_get_u8(ssh, NULL)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, NULL)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			戻る r;

	もし (!(kex->flags & KEX_INIT_SENT))
		もし ((r = kex_send_kexinit(ssh)) != 0)
			戻る r;
	もし ((r = kex_choose_conf(ssh, seq)) != 0)
		戻る r;

	もし (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != NULL)
		戻る (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	戻る SSH_ERR_INTERNAL_ERROR;
}

struct kex *
kex_new(void)
{
	struct kex *kex;

	もし ((kex = calloc(1, sizeof(*kex))) == NULL ||
	    (kex->peer = sshbuf_new()) == NULL ||
	    (kex->my = sshbuf_new()) == NULL ||
	    (kex->client_version = sshbuf_new()) == NULL ||
	    (kex->server_version = sshbuf_new()) == NULL ||
	    (kex->session_id = sshbuf_new()) == NULL) {
		kex_free(kex);
		戻る NULL;
	}
	戻る kex;
}

void
kex_free_newkeys(struct newkeys *newkeys)
{
	もし (newkeys == NULL)
		戻る;
	もし (newkeys->enc.key) {
		explicit_bzero(newkeys->enc.key, newkeys->enc.key_len);
		free(newkeys->enc.key);
		newkeys->enc.key = NULL;
	}
	もし (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		free(newkeys->enc.iv);
		newkeys->enc.iv = NULL;
	}
	free(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, sizeof(newkeys->enc));
	free(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, sizeof(newkeys->comp));
	mac_clear(&newkeys->mac);
	もし (newkeys->mac.key) {
		explicit_bzero(newkeys->mac.key, newkeys->mac.key_len);
		free(newkeys->mac.key);
		newkeys->mac.key = NULL;
	}
	free(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, sizeof(newkeys->mac));
	freezero(newkeys, sizeof(*newkeys));
}

void
kex_free(struct kex *kex)
{
	u_int mode;

	もし (kex == NULL)
		戻る;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_KEY_free(kex->ec_client_key);
#endif /* WITH_OPENSSL */
	ために (mode = 0; mode < MODE_MAX; mode++) {
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

整数
kex_ready(struct ssh *ssh, char *proposal[PROPOSAL_MAX])
{
	整数 r;

	もし ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		戻る r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	戻る 0;
}

整数
kex_setup(struct ssh *ssh, char *proposal[PROPOSAL_MAX])
{
	整数 r;

	もし ((r = kex_ready(ssh, proposal)) != 0)
		戻る r;
	もし ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = NULL;
		戻る r;
	}
	戻る 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
整数
kex_start_rekex(struct ssh *ssh)
{
	もし (ssh->kex == NULL) {
		error_f("no kex");
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	もし (ssh->kex->done == 0) {
		error_f("requested twice");
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	戻る kex_send_kexinit(ssh);
}

static 整数
choose_enc(struct sshenc *enc, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	もし (name == NULL)
		戻る SSH_ERR_NO_CIPHER_ALG_MATCH;
	もし ((enc->cipher = cipher_by_name(name)) == NULL) {
		error_f("unsupported cipher %s", name);
		free(name);
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = NULL;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->key = NULL;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	戻る 0;
}

static 整数
choose_mac(struct ssh *ssh, struct sshmac *mac, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	もし (name == NULL)
		戻る SSH_ERR_NO_MAC_ALG_MATCH;
	もし (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		free(name);
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->key = NULL;
	mac->enabled = 0;
	戻る 0;
}

static 整数
choose_comp(struct sshcomp *comp, char *client, char *server)
{
	char *name = match_list(client, server, NULL);

	もし (name == NULL)
		戻る SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	もし (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} 否则
#endif	/* WITH_ZLIB */
	もし (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} 否则 {
		error_f("unsupported compression scheme %s", name);
		free(name);
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	戻る 0;
}

static 整数
choose_kex(struct kex *k, char *client, char *server)
{
	k->name = match_list(client, server, NULL);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	もし (k->name == NULL)
		戻る SSH_ERR_NO_KEX_ALG_MATCH;
	もし (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	戻る 0;
}

static 整数
choose_hostkeyalg(struct kex *k, char *client, char *server)
{
	free(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, NULL);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	もし (k->hostkey_alg == NULL)
		戻る SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	もし (k->hostkey_type == KEY_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	戻る 0;
}

static 整数
proposals_match(char *my[PROPOSAL_MAX], char *peer[PROPOSAL_MAX])
{
	static 整数 check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	整数 *idx;
	char *p;

	ために (idx = &check[0]; *idx != -1; idx++) {
		もし ((p = strchr(my[*idx], ',')) != NULL)
			*p = '\0';
		もし ((p = strchr(peer[*idx], ',')) != NULL)
			*p = '\0';
		もし (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			戻る (0);
		}
	}
	debug2("proposals match");
	戻る (1);
}

static 整数
kexalgs_contains(char **peer, const char *ext)
{
	戻る kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

static 整数
kex_choose_conf(struct ssh *ssh, uint32_t seq)
{
	struct kex *kex = ssh->kex;
	struct newkeys *newkeys;
	char **my = NULL, **peer = NULL;
	char **cprop, **sprop;
	整数 nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	整数 r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	もし ((r = kex_buf2prop(kex->my, NULL, &my)) != 0)
		goto out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	もし ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		goto out;

	もし (kex->server) {
		cprop=peer;
		sprop=my;
	} 否则 {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	もし ((kex->flags & KEX_INITIAL) != 0) {
		もし (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} 否则 {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		もし (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			もし (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	もし (kex->server && (kex->flags & KEX_INITIAL)) {
		もし (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		もし (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	もし ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = NULL;
		goto out;
	}
	もし ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_KEY_ALGS];
		peer[PROPOSAL_SERVER_HOST_KEY_ALGS] = NULL;
		goto out;
	}
	ために (mode = 0; mode < MODE_MAX; mode++) {
		もし ((newkeys = calloc(1, sizeof(*newkeys))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		もし ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = NULL;
			goto out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		もし (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = NULL;
			goto out;
		}
		もし ((r = choose_comp(&newkeys->comp, cprop[ncomp],
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
	ために (mode = 0; mode < MODE_MAX; mode++) {
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
	もし (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	戻る r;
}

static 整数
derive_key(struct ssh *ssh, 整数 id, u_int need, u_char *hash, u_int hashlen,
    const struct sshbuf *shared_secret, u_char **keyp)
{
	struct kex *kex = ssh->kex;
	struct ssh_digest_ctx *hashctx = NULL;
	char c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	整数 r;

	もし ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		戻る SSH_ERR_INVALID_ARGUMENT;
	もし ((digest = calloc(1, ROUNDUP(need, mdsz))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	もし ((hashctx = ssh_digest_start(kex->hash_alg)) == NULL ||
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
	ために (have = mdsz; need > have; have += mdsz) {
		もし ((hashctx = ssh_digest_start(kex->hash_alg)) == NULL ||
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
	戻る r;
}

#define NKEYS	6
整数
kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen,
    const struct sshbuf *shared_secret)
{
	struct kex *kex = ssh->kex;
	u_char *keys[NKEYS];
	u_int i, j, mode, ctos;
	整数 r;

	/* save initial hash as session id */
	もし ((kex->flags & KEX_INITIAL) != 0) {
		もし (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			戻る SSH_ERR_INTERNAL_ERROR;
		}
		もし ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			戻る r;
	} 否则 もし (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		戻る SSH_ERR_INTERNAL_ERROR;
	}
	ために (i = 0; i < NKEYS; i++) {
		もし ((r = derive_key(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &keys[i])) != 0) {
			ために (j = 0; j < i; j++)
				free(keys[j]);
			戻る r;
		}
	}
	ために (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.key = keys[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
	戻る 0;
}

整数
kex_load_hostkey(struct ssh *ssh, struct sshkey **prvp, struct sshkey **pubp)
{
	struct kex *kex = ssh->kex;

	*pubp = NULL;
	*prvp = NULL;
	もし (kex->load_host_public_key == NULL ||
	    kex->load_host_private_key == NULL) {
		error_f("missing hostkey loader");
		戻る SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	もし (*pubp == NULL)
		戻る SSH_ERR_NO_HOSTKEY_LOADED;
	戻る 0;
}

整数
kex_verify_host_key(struct ssh *ssh, struct sshkey *server_host_key)
{
	struct kex *kex = ssh->kex;

	もし (kex->verify_host_key == NULL) {
		error_f("missing hostkey verifier");
		戻る SSH_ERR_INVALID_ARGUMENT;
	}
	もし (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid))
		戻る SSH_ERR_KEY_TYPE_MISMATCH;
	もし (kex->verify_host_key(server_host_key, ssh) == -1)
		戻る  SSH_ERR_SIGNATURE_INVALID;
	戻る 0;
}

#もし defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void
dump_digest(const char *msg, const u_char *digest, 整数 len)
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
send_error(struct ssh *ssh, char *msg)
{
	char *crnl = "\r\n";

	もし (!ssh->kex->server)
		戻る;

	もし (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
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
整数
kex_exchange_identification(struct ssh *ssh, 整数 timeout_ms,
    const char *version_addendum)
{
	整数 remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	整数 r, expect_nl;
	u_char c;
	struct sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	struct sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	char *our_version_string = NULL, *peer_version_string = NULL;
	char *cp, *remote_version = NULL;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	もし (version_addendum != NULL && *version_addendum == '\0')
		version_addendum = NULL;
	もし ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == NULL ? "" : " ",
	    version_addendum == NULL ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		goto out;
	}

	もし (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	もし ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		goto out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	もし (our_version_string == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	ために (n = 0; ; n++) {
		もし (n >= SSH_MAX_PRE_BANNER_LINES) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_LINES);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		ために (;;) {
			もし (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, NULL);
				もし (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					goto out;
				} 否则 もし (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					goto out;
				}
			}

			len = atomicio(read, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			もし (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				goto out;
			} 否则 もし (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				goto out;
			}
			もし (c == '\r') {
				expect_nl = 1;
				continue;
			}
			もし (c == '\n')
				break;
			もし (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				goto invalid;
			}
			もし ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				goto out;
			}
			もし (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				goto invalid;
			}
		}
		/* Is this an actual protocol banner? */
		もし (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			break;
		/* If not, then just log the line and continue */
		もし ((cp = sshbuf_dup_string(peer_version)) == NULL) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		/* Do not accept lines before the SSH ident from a client */
		もし (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			free(cp);
			goto invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		free(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	もし (peer_version_string == NULL)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	もし ((remote_version = calloc(1, sshbuf_len(peer_version))) == NULL) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	もし (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
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
	case 2:
		break;
	case 1:
		もし (remote_minor != 99)
			mismatch = 1;
		break;
	default:
		mismatch = 1;
		break;
	}
	もし (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		goto out;
	}

	もし (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		goto out;
	}
	もし (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
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
	もし (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	戻る r;
}

