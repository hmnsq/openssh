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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/crypto.h>
#ضمن <openssl/dh.h>
#endif

#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "atomicio.h"
#ضمن "version.h"
#ضمن "packet.h"
#ضمن "compat.h"
#ضمن "cipher.h"
#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "log.h"
#ضمن "mac.h"
#ضمن "match.h"
#ضمن "misc.h"
#ضمن "dispatch.h"
#ضمن "myproposal.h"

#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"
#ضمن "xmalloc.h"

/* prototype */
ساكن صحيح kex_choose_conf(بنية ssh *, uint32_t seq);
ساكن صحيح kex_input_newkeys(صحيح, uint32_t, بنية ssh *);

ساكن ثابت حرف * ثابت proposal_names[PROPOSAL_MAX] = {
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
فراغ
kex_proposal_populate_entries(بنية ssh *ssh, حرف *prop[PROPOSAL_MAX],
    ثابت حرف *kexalgos, ثابت حرف *ciphers, ثابت حرف *macs,
    ثابت حرف *comp, ثابت حرف *hkalgs)
{
	ثابت حرف *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ثابت حرف *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ثابت حرف **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	حرف *cp;

	ܐܢ (prop == عدم)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	ܐܢ (kexalgos == عدم)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	ܐܢ ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == عدم)
		fatal_f("kex_names_cat");

	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		بدل(i) {
		حالة PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			اكسر;
		حالة PROPOSAL_ENC_ALGS_CTOS:
		حالة PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			اكسر;
		حالة PROPOSAL_MAC_ALGS_CTOS:
		حالة PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			اكسر;
		حالة PROPOSAL_COMP_ALGS_CTOS:
		حالة PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			اكسر;
		حالة PROPOSAL_SERVER_HOST_KEY_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			اكسر;
		افتراضي:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	حرر(cp);
}

فراغ
kex_proposal_free_entries(حرف *prop[PROPOSAL_MAX])
{
	u_int i;

	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(prop[i]);
}

/* put algorithm proposal into buffer */
صحيح
kex_prop2buf(بنية sshbuf *b, حرف *proposal[PROPOSAL_MAX])
{
	u_int i;
	صحيح r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	لكل (i = 0; i < KEX_COOKIE_LEN; i++) {
		ܐܢ ((r = sshbuf_put_u8(b, 0)) != 0)
			ܦܢܐ r;
	}
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ܐܢ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ܦܢܐ r;
	}
	ܐܢ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ܦܢܐ r;
	ܦܢܐ 0;
}

/* parse buffer and return algorithm proposal */
صحيح
kex_buf2prop(بنية sshbuf *raw, صحيح *first_kex_follows, حرف ***propp)
{
	بنية sshbuf *b = عدم;
	u_char v;
	u_int i;
	حرف **proposal = عدم;
	صحيح r;

	*propp = عدم;
	ܐܢ ((proposal = calloc(PROPOSAL_MAX, حجم(حرف *))) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	ܐܢ ((b = sshbuf_fromb(raw)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	ܐܢ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		اذهب out;
	}
	/* extract kex init proposal strings */
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ܐܢ ((r = sshbuf_get_cstring(b, &(proposal[i]), عدم)) != 0) {
			error_fr(r, "parse proposal %u", i);
			اذهب out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	ܐܢ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		اذهب out;
	}
	ܐܢ (first_kex_follows != عدم)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	ܐܢ (r != 0 && proposal != عدم)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ܦܢܐ r;
}

فراغ
kex_prop_free(حرف **proposal)
{
	u_int i;

	ܐܢ (proposal == عدم)
		ܦܢܐ;
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	حرر(proposal);
}

صحيح
kex_protocol_error(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح r;

	/* If in strict mode, any unexpected message is an error */
	ܐܢ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	ܐܢ ((r = sshpkt_start(ssh, SSH2_MSG_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ܦܢܐ r;
	ܦܢܐ 0;
}

ساكن فراغ
kex_reset_dispatch(بنية ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_MSG_TRANSPORT_MIN,
	    SSH2_MSG_TRANSPORT_MAX, &kex_protocol_error);
}

فراغ
kex_set_server_sig_algs(بنية ssh *ssh, ثابت حرف *allowed_algs)
{
	حرف *alg, *oalgs, *algs, *sigalgs;
	ثابت حرف *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	ܐܢ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == عدم)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	حرر(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = عدم;
	لكل ((alg = strsep(&algs, ",")); alg != عدم && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		ܐܢ ((sigalg = sshkey_sigalg_by_name(alg)) == عدم)
			استمر;
		ܐܢ (!kex_has_any_alg(sigalg, sigalgs))
			استمر;
		/* Don't add an algorithm twice. */
		ܐܢ (ssh->kex->server_sig_algs != عدم &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			استمر;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	حرر(oalgs);
	حرر(sigalgs);
	ܐܢ (ssh->kex->server_sig_algs == عدم)
		ssh->kex->server_sig_algs = xstrdup("");
}

فراغ
kex_set_warn_weak_crypto(بنية ssh *ssh, صحيح warn_weak_crypto)
{
	ܐܢ (ssh != عدم && ssh->kex != عدم)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

فراغ
kex_check_warn_weak_crypto(بنية ssh *ssh)
{
	حرف remote_id[512];
	صحيح rekeyed = 0;

	ܐܢ (ssh == عدم || ssh->kex == عدم || ssh->kex->name == عدم ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ܦܢܐ;
	ܐܢ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ܦܢܐ;
	}

	ܐܢ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	ܐܢ (!rekeyed && !ssh->kex->server)
		ܦܢܐ; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ساكن صحيح
kex_compose_ext_info_server(بنية ssh *ssh, بنية sshbuf *m)
{
	صحيح r;

	ܐܢ (ssh->kex->server_sig_algs == عدم &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	ܐܢ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		ܦܢܐ r;
	}
	ܦܢܐ 0;
}

ساكن صحيح
kex_compose_ext_info_client(بنية ssh *ssh, بنية sshbuf *m)
{
	صحيح r;

	ܐܢ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	ܦܢܐ r;
}

ساكن صحيح
kex_maybe_send_ext_info(بنية ssh *ssh)
{
	صحيح r;
	بنية sshbuf *m = عدم;

	ܐܢ ((ssh->kex->flags & KEX_INITIAL) == 0)
		ܦܢܐ 0;
	ܐܢ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ܦܢܐ 0;

	/* Compose EXT_INFO packet. */
	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	ܐܢ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		اذهب fail;
	ܐܢ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		اذهب fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	ܐܢ ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		اذهب fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ܦܢܐ r;
}

صحيح
kex_server_update_ext_info(بنية ssh *ssh)
{
	صحيح r;

	ܐܢ ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		ܦܢܐ 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	ܐܢ ((r = sshpkt_start(ssh, SSH2_MSG_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ܦܢܐ r;
	}
	ܦܢܐ 0;
}

صحيح
kex_send_newkeys(بنية ssh *ssh)
{
	صحيح r;

	kex_reset_dispatch(ssh);
	ܐܢ ((r = sshpkt_start(ssh, SSH2_MSG_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ܦܢܐ r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_input_newkeys);
	ܐܢ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ܦܢܐ r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ܦܢܐ 0;
}

/* Check whether an ext_info value contains the expected version string */
ساكن صحيح
kex_ext_info_check_ver(بنية kex *kex, ثابت حرف *name,
    ثابت u_char *val, size_t len, ثابت حرف *want_ver, u_int flag)
{
	ܐܢ (memchr(val, '\0', len) != عدم) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ܦܢܐ SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	ܐܢ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	ܐܚܪܢܐ
		debug_f("unsupported version of %s extension", name);
	ܦܢܐ 0;
}

ساكن صحيح
kex_ext_info_client_parse(بنية ssh *ssh, ثابت حرف *name,
    ثابت u_char *value, size_t vlen)
{
	صحيح r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	ܐܢ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		ܐܢ (memchr(value, '\0', vlen) != عدم) {
			error_f("nul byte in %s", name);
			ܦܢܐ SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, value);
		حرر(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ثابت حرف *)value);
	} ܐܚܪܢܐ ܐܢ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		ܐܢ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ܦܢܐ r;
		}
	} ܐܚܪܢܐ ܐܢ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		ܐܢ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ܦܢܐ r;
		}
	} ܐܚܪܢܐ ܐܢ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		ܐܢ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ܦܢܐ r;
		}
	} ܐܚܪܢܐ
		debug_f("%s (unrecognised)", name);

	ܦܢܐ 0;
}

ساكن صحيح
kex_ext_info_server_parse(بنية ssh *ssh, ثابت حرف *name,
    ثابت u_char *value, size_t vlen)
{
	صحيح r;

	ܐܢ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		ܐܢ ((r = kex_ext_info_check_ver(ssh->kex, name, value, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			ܦܢܐ r;
		}
	} ܐܚܪܢܐ
		debug_f("%s (unrecognised)", name);
	ܦܢܐ 0;
}

صحيح
kex_input_ext_info(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	ثابت صحيح max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	حرف *name;
	u_char *val;
	size_t vlen;
	صحيح r;

	debug("SSH2_MSG_EXT_INFO received");
	ܐܢ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ܦܢܐ dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_protocol_error);
	ܐܢ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ܦܢܐ r;
	ܐܢ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ܦܢܐ dispatch_protocol_error(type, seq, ssh);
	}
	لكل (i = 0; i < ninfo; i++) {
		ܐܢ ((r = sshpkt_get_cstring(ssh, &name, عدم)) != 0)
			ܦܢܐ r;
		ܐܢ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			حرر(name);
			ܦܢܐ r;
		}
		debug3_f("extension %s", name);
		ܐܢ (kex->server) {
			ܐܢ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ܦܢܐ r;
		} ܐܚܪܢܐ {
			ܐܢ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ܦܢܐ r;
		}
		حرر(name);
		حرر(val);
	}
	ܦܢܐ sshpkt_get_end(ssh);
}

ساكن صحيح
kex_input_newkeys(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r, initial = (kex->flags & KEX_INITIAL) != 0;
	حرف *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	ܐܢ (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_MSG_EXT_INFO, &kex_input_ext_info);
	ssh_dispatch_set(ssh, SSH2_MSG_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	ܐܢ ((r = sshpkt_get_end(ssh)) != 0)
		ܦܢܐ r;
	ܐܢ ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		ܦܢܐ r;
	ܐܢ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		ܐܢ ((r = kex_buf2prop(kex->my, عدم, &prop)) != 0)
			ܦܢܐ r;
		ܐܢ ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == عدم) {
			error_f("match_filter_denylist failed");
			اذهب fail;
		}
		حرر(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		ܐܢ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			حرر(prop);
			ܦܢܐ SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		حرر(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ܦܢܐ 0;
}

صحيح
kex_send_kexinit(بنية ssh *ssh)
{
	u_char *cookie;
	بنية kex *kex = ssh->kex;
	صحيح r;

	ܐܢ (kex == عدم) {
		error_f("no kex");
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	ܐܢ (kex->flags & KEX_INIT_SENT)
		ܦܢܐ 0;
	kex->done = 0;

	/* generate a random cookie */
	ܐܢ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ܦܢܐ SSH_ERR_INVALID_FORMAT;
	}
	ܐܢ ((cookie = sshbuf_mutable_ptr(kex->my)) == عدم) {
		error_f("buffer error");
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	ܐܢ ((r = sshpkt_start(ssh, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ܦܢܐ r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	ܦܢܐ 0;
}

صحيح
kex_input_kexinit(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	ثابت u_char *ptr;
	u_int i;
	size_t dlen;
	صحيح r;

	debug("SSH2_MSG_KEXINIT received");
	ܐܢ (kex == عدم) {
		error_f("no kex");
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	حرر(kex->name);
	kex->name = عدم;
	ܐܢ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	ܐܢ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ܦܢܐ r;

	/* discard packet */
	لكل (i = 0; i < KEX_COOKIE_LEN; i++) {
		ܐܢ ((r = sshpkt_get_u8(ssh, عدم)) != 0) {
			error_fr(r, "discard cookie");
			ܦܢܐ r;
		}
	}
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ܐܢ ((r = sshpkt_get_string(ssh, عدم, عدم)) != 0) {
			error_fr(r, "discard proposal");
			ܦܢܐ r;
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
	ܐܢ ((r = sshpkt_get_u8(ssh, عدم)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			ܦܢܐ r;

	ܐܢ (!(kex->flags & KEX_INIT_SENT))
		ܐܢ ((r = kex_send_kexinit(ssh)) != 0)
			ܦܢܐ r;
	ܐܢ ((r = kex_choose_conf(ssh, seq)) != 0)
		ܦܢܐ r;

	ܐܢ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != عدم)
		ܦܢܐ (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ܦܢܐ SSH_ERR_INTERNAL_ERROR;
}

بنية kex *
kex_new(فراغ)
{
	بنية kex *kex;

	ܐܢ ((kex = calloc(1, حجم(*kex))) == عدم ||
	    (kex->peer = sshbuf_new()) == عدم ||
	    (kex->my = sshbuf_new()) == عدم ||
	    (kex->client_version = sshbuf_new()) == عدم ||
	    (kex->server_version = sshbuf_new()) == عدم ||
	    (kex->session_id = sshbuf_new()) == عدم) {
		kex_free(kex);
		ܦܢܐ عدم;
	}
	ܦܢܐ kex;
}

فراغ
kex_free_newkeys(بنية newkeys *newkeys)
{
	ܐܢ (newkeys == عدم)
		ܦܢܐ;
	ܐܢ (newkeys->enc.key) {
		explicit_bzero(newkeys->enc.key, newkeys->enc.key_len);
		حرر(newkeys->enc.key);
		newkeys->enc.key = عدم;
	}
	ܐܢ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		حرر(newkeys->enc.iv);
		newkeys->enc.iv = عدم;
	}
	حرر(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, حجم(newkeys->enc));
	حرر(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, حجم(newkeys->comp));
	mac_clear(&newkeys->mac);
	ܐܢ (newkeys->mac.key) {
		explicit_bzero(newkeys->mac.key, newkeys->mac.key_len);
		حرر(newkeys->mac.key);
		newkeys->mac.key = عدم;
	}
	حرر(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, حجم(newkeys->mac));
	freezero(newkeys, حجم(*newkeys));
}

فراغ
kex_free(بنية kex *kex)
{
	u_int mode;

	ܐܢ (kex == عدم)
		ܦܢܐ;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_KEY_free(kex->ec_client_key);
#endif /* WITH_OPENSSL */
	لكل (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = عدم;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	حرر(kex->failed_choice);
	حرر(kex->hostkey_alg);
	حرر(kex->name);
	حرر(kex->server_sig_algs);
	حرر(kex);
}

صحيح
kex_ready(بنية ssh *ssh, حرف *proposal[PROPOSAL_MAX])
{
	صحيح r;

	ܐܢ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ܦܢܐ r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit);
	ܦܢܐ 0;
}

صحيح
kex_setup(بنية ssh *ssh, حرف *proposal[PROPOSAL_MAX])
{
	صحيح r;

	ܐܢ ((r = kex_ready(ssh, proposal)) != 0)
		ܦܢܐ r;
	ܐܢ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = عدم;
		ܦܢܐ r;
	}
	ܦܢܐ 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
صحيح
kex_start_rekex(بنية ssh *ssh)
{
	ܐܢ (ssh->kex == عدم) {
		error_f("no kex");
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	ܐܢ (ssh->kex->done == 0) {
		error_f("requested twice");
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	ܦܢܐ kex_send_kexinit(ssh);
}

ساكن صحيح
choose_enc(بنية sshenc *enc, حرف *client, حرف *server)
{
	حرف *name = match_list(client, server, عدم);

	ܐܢ (name == عدم)
		ܦܢܐ SSH_ERR_NO_CIPHER_ALG_MATCH;
	ܐܢ ((enc->cipher = cipher_by_name(name)) == عدم) {
		error_f("unsupported cipher %s", name);
		حرر(name);
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = عدم;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->key = عدم;
	enc->key_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	ܦܢܐ 0;
}

ساكن صحيح
choose_mac(بنية ssh *ssh, بنية sshmac *mac, حرف *client, حرف *server)
{
	حرف *name = match_list(client, server, عدم);

	ܐܢ (name == عدم)
		ܦܢܐ SSH_ERR_NO_MAC_ALG_MATCH;
	ܐܢ (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		حرر(name);
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->key = عدم;
	mac->enabled = 0;
	ܦܢܐ 0;
}

ساكن صحيح
choose_comp(بنية sshcomp *comp, حرف *client, حرف *server)
{
	حرف *name = match_list(client, server, عدم);

	ܐܢ (name == عدم)
		ܦܢܐ SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	ܐܢ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} ܐܚܪܢܐ
#endif	/* WITH_ZLIB */
	ܐܢ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} ܐܚܪܢܐ {
		error_f("unsupported compression scheme %s", name);
		حرر(name);
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	ܦܢܐ 0;
}

ساكن صحيح
choose_kex(بنية kex *k, حرف *client, حرف *server)
{
	k->name = match_list(client, server, عدم);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	ܐܢ (k->name == عدم)
		ܦܢܐ SSH_ERR_NO_KEX_ALG_MATCH;
	ܐܢ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ܦܢܐ 0;
}

ساكن صحيح
choose_hostkeyalg(بنية kex *k, حرف *client, حرف *server)
{
	حرر(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, عدم);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	ܐܢ (k->hostkey_alg == عدم)
		ܦܢܐ SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	ܐܢ (k->hostkey_type == KEY_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ܦܢܐ 0;
}

ساكن صحيح
proposals_match(حرف *my[PROPOSAL_MAX], حرف *peer[PROPOSAL_MAX])
{
	ساكن صحيح check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_KEY_ALGS, -1
	};
	صحيح *idx;
	حرف *p;

	لكل (idx = &check[0]; *idx != -1; idx++) {
		ܐܢ ((p = strchr(my[*idx], ',')) != عدم)
			*p = '\0';
		ܐܢ ((p = strchr(peer[*idx], ',')) != عدم)
			*p = '\0';
		ܐܢ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ܦܢܐ (0);
		}
	}
	debug2("proposals match");
	ܦܢܐ (1);
}

ساكن صحيح
kexalgs_contains(حرف **peer, ثابت حرف *ext)
{
	ܦܢܐ kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ساكن صحيح
kex_choose_conf(بنية ssh *ssh, uint32_t seq)
{
	بنية kex *kex = ssh->kex;
	بنية newkeys *newkeys;
	حرف **my = عدم, **peer = عدم;
	حرف **cprop, **sprop;
	صحيح nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	صحيح r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	ܐܢ ((r = kex_buf2prop(kex->my, عدم, &my)) != 0)
		اذهب out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	ܐܢ ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		اذهب out;

	ܐܢ (kex->server) {
		cprop=peer;
		sprop=my;
	} ܐܚܪܢܐ {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	ܐܢ ((kex->flags & KEX_INITIAL) != 0) {
		ܐܢ (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} ܐܚܪܢܐ {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		ܐܢ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			ܐܢ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	ܐܢ (kex->server && (kex->flags & KEX_INITIAL)) {
		ܐܢ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		ܐܢ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_KEY_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	ܐܢ ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = عدم;
		اذهب out;
	}
	ܐܢ ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_KEY_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_KEY_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_KEY_ALGS];
		peer[PROPOSAL_SERVER_HOST_KEY_ALGS] = عدم;
		اذهب out;
	}
	لكل (mode = 0; mode < MODE_MAX; mode++) {
		ܐܢ ((newkeys = calloc(1, حجم(*newkeys))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		ܐܢ ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = عدم;
			اذهب out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		ܐܢ (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = عدم;
			اذهب out;
		}
		ܐܢ ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = عدم;
			اذهب out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	لكل (mode = 0; mode < MODE_MAX; mode++) {
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
	ܐܢ (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	ܦܢܐ r;
}

ساكن صحيح
derive_key(بنية ssh *ssh, صحيح id, u_int need, u_char *hash, u_int hashlen,
    ثابت بنية sshbuf *shared_secret, u_char **keyp)
{
	بنية kex *kex = ssh->kex;
	بنية ssh_digest_ctx *hashctx = عدم;
	حرف c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	صحيح r;

	ܐܢ ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	ܐܢ ((digest = calloc(1, ROUNDUP(need, mdsz))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	ܐܢ ((hashctx = ssh_digest_start(kex->hash_alg)) == عدم ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		اذهب out;
	}
	ssh_digest_free(hashctx);
	hashctx = عدم;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	لكل (have = mdsz; need > have; have += mdsz) {
		ܐܢ ((hashctx = ssh_digest_start(kex->hash_alg)) == عدم ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		ssh_digest_free(hashctx);
		hashctx = عدم;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = عدم;
	r = 0;
 out:
	حرر(digest);
	ssh_digest_free(hashctx);
	ܦܢܐ r;
}

#define NKEYS	6
صحيح
kex_derive_keys(بنية ssh *ssh, u_char *hash, u_int hashlen,
    ثابت بنية sshbuf *shared_secret)
{
	بنية kex *kex = ssh->kex;
	u_char *keys[NKEYS];
	u_int i, j, mode, ctos;
	صحيح r;

	/* save initial hash as session id */
	ܐܢ ((kex->flags & KEX_INITIAL) != 0) {
		ܐܢ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ܦܢܐ SSH_ERR_INTERNAL_ERROR;
		}
		ܐܢ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ܦܢܐ r;
	} ܐܚܪܢܐ ܐܢ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	لكل (i = 0; i < NKEYS; i++) {
		ܐܢ ((r = derive_key(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &keys[i])) != 0) {
			لكل (j = 0; j < i; j++)
				حرر(keys[j]);
			ܦܢܐ r;
		}
	}
	لكل (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = keys[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.key = keys[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.key = keys[ctos ? 4 : 5];
	}
	ܦܢܐ 0;
}

صحيح
kex_load_hostkey(بنية ssh *ssh, بنية sshkey **prvp, بنية sshkey **pubp)
{
	بنية kex *kex = ssh->kex;

	*pubp = عدم;
	*prvp = عدم;
	ܐܢ (kex->load_host_public_key == عدم ||
	    kex->load_host_private_key == عدم) {
		error_f("missing hostkey loader");
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	ܐܢ (*pubp == عدم)
		ܦܢܐ SSH_ERR_NO_HOSTKEY_LOADED;
	ܦܢܐ 0;
}

صحيح
kex_verify_host_key(بنية ssh *ssh, بنية sshkey *server_host_key)
{
	بنية kex *kex = ssh->kex;

	ܐܢ (kex->verify_host_key == عدم) {
		error_f("missing hostkey verifier");
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	}
	ܐܢ (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid))
		ܦܢܐ SSH_ERR_KEY_TYPE_MISMATCH;
	ܐܢ (kex->verify_host_key(server_host_key, ssh) == -1)
		ܦܢܐ  SSH_ERR_SIGNATURE_INVALID;
	ܦܢܐ 0;
}

#ܐܢ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
فراغ
dump_digest(ثابت حرف *msg, ثابت u_char *digest, صحيح len)
{
	fprintf(stderr, "%s\n", msg);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ساكن فراغ
send_error(بنية ssh *ssh, حرف *msg)
{
	حرف *crnl = "\r\n";

	ܐܢ (!ssh->kex->server)
		ܦܢܐ;

	ܐܢ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
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
صحيح
kex_exchange_identification(بنية ssh *ssh, صحيح timeout_ms,
    ثابت حرف *version_addendum)
{
	صحيح remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	صحيح r, expect_nl;
	u_char c;
	بنية sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	بنية sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	حرف *our_version_string = عدم, *peer_version_string = عدم;
	حرف *cp, *remote_version = عدم;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	ܐܢ (version_addendum != عدم && *version_addendum == '\0')
		version_addendum = عدم;
	ܐܢ ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == عدم ? "" : " ",
	    version_addendum == عدم ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		اذهب out;
	}

	ܐܢ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب out;
	}
	ܐܢ ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		اذهب out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	ܐܢ (our_version_string == عدم) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	لكل (n = 0; ; n++) {
		ܐܢ (n >= SSH_MAX_PRE_BANNER_LINES) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_LINES);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		لكل (;;) {
			ܐܢ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, عدم);
				ܐܢ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					اذهب out;
				} ܐܚܪܢܐ ܐܢ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					اذهب out;
				}
			}

			len = atomicio(اقرأ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			ܐܢ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				اذهب out;
			} ܐܚܪܢܐ ܐܢ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب out;
			}
			ܐܢ (c == '\r') {
				expect_nl = 1;
				استمر;
			}
			ܐܢ (c == '\n')
				اكسر;
			ܐܢ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				اذهب invalid;
			}
			ܐܢ ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				اذهب out;
			}
			ܐܢ (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				اذهب invalid;
			}
		}
		/* Is this an actual protocol banner? */
		ܐܢ (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			اكسر;
		/* If not, then just log the line and continue */
		ܐܢ ((cp = sshbuf_dup_string(peer_version)) == عدم) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		/* Do not accept lines before the SSH ident from a client */
		ܐܢ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			حرر(cp);
			اذهب invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		حرر(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	ܐܢ (peer_version_string == عدم)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	ܐܢ ((remote_version = calloc(1, sshbuf_len(peer_version))) == عدم) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ܐܢ (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	بدل (remote_major) {
	حالة 2:
		اكسر;
	حالة 1:
		ܐܢ (remote_minor != 99)
			mismatch = 1;
		اكسر;
	افتراضي:
		mismatch = 1;
		اكسر;
	}
	ܐܢ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		اذهب out;
	}

	ܐܢ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		اذهب out;
	}
	ܐܢ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(our_version_string);
	حرر(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	ܐܢ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ܦܢܐ r;
}

