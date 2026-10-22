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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <errno.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#ifdef WITH_OPENSSL
#شامل <openssl/crypto.h>
#شامل <openssl/dh.h>
#endif

#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "atomicio.h"
#شامل "version.h"
#شامل "packet.h"
#شامل "compat.h"
#شامل "cipher.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "log.h"
#شامل "mac.h"
#شامل "match.h"
#شامل "misc.h"
#شامل "dispatch.h"
#شامل "myproposal.h"

#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "xmalloc.h"

/* prototype */
ایستا صحیح kex_choose_conf(ساختار ssh *, uint32_t seq);
ایستا صحیح kex_درون_داد_newkeys(صحیح, uint32_t, ساختار ssh *);

ایستا ثابت نویسه * ثابت proposal_names[PROPOSAL_MAX] = {
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
تهی
kex_proposal_populate_entries(ساختار ssh *ssh, نویسه *prop[PROPOSAL_MAX],
    ثابت نویسه *kexalgos, ثابت نویسه *ciphers, ثابت نویسه *macs,
    ثابت نویسه *comp, ثابت نویسه *hkalgs)
{
	ثابت نویسه *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ثابت نویسه *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ثابت نویسه **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	نویسه *cp;

	اگر (prop == پوچ)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	اگر (kexalgos == پوچ)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	اگر ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == پوچ)
		fatal_f("kex_names_cat");

	برای (i = 0; i < PROPOSAL_MAX; i++) {
		انتخاب(i) {
		حالت PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			بشکن;
		حالت PROPOSAL_ENC_ALGS_CTOS:
		حالت PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			بشکن;
		حالت PROPOSAL_MAC_ALGS_CTOS:
		حالت PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			بشکن;
		حالت PROPOSAL_COMP_ALGS_CTOS:
		حالت PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			بشکن;
		حالت PROPOSAL_SERVER_HOST_کلید_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			بشکن;
		پیشفرض:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	آزاد(cp);
}

تهی
kex_proposal_free_entries(نویسه *prop[PROPOSAL_MAX])
{
	u_int i;

	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(prop[i]);
}

/* put algorithm proposal into buffer */
صحیح
kex_prop2buf(ساختار sshbuf *b, نویسه *proposal[PROPOSAL_MAX])
{
	u_int i;
	صحیح r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	برای (i = 0; i < KEX_COOKIE_LEN; i++) {
		اگر ((r = sshbuf_put_u8(b, 0)) != 0)
			بازگشت r;
	}
	برای (i = 0; i < PROPOSAL_MAX; i++) {
		اگر ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			بازگشت r;
	}
	اگر ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		بازگشت r;
	بازگشت 0;
}

/* parse buffer and return algorithm proposal */
صحیح
kex_buf2prop(ساختار sshbuf *raw, صحیح *first_kex_follows, نویسه ***propp)
{
	ساختار sshbuf *b = پوچ;
	u_char v;
	u_int i;
	نویسه **proposal = پوچ;
	صحیح r;

	*propp = پوچ;
	اگر ((proposal = calloc(PROPOSAL_MAX, اندازه(نویسه *))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((b = sshbuf_fromb(raw)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		برو out;
	}
	/* extract kex init proposal strings */
	برای (i = 0; i < PROPOSAL_MAX; i++) {
		اگر ((r = sshbuf_get_cstring(b, &(proposal[i]), پوچ)) != 0) {
			error_fr(r, "parse proposal %u", i);
			برو out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	اگر ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		برو out;
	}
	اگر (first_kex_follows != پوچ)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	اگر (r != 0 && proposal != پوچ)
		kex_prop_free(proposal);
	sshbuf_free(b);
	بازگشت r;
}

تهی
kex_prop_free(نویسه **proposal)
{
	u_int i;

	اگر (proposal == پوچ)
		بازگشت;
	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	آزاد(proposal);
}

صحیح
kex_protocol_error(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	صحیح r;

	/* If in strict mode, any unexpected message is an error */
	اگر ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا تهی
kex_reset_dispatch(ساختار ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_پیام_TRANSPORT_MIN,
	    SSH2_پیام_TRANSPORT_MAX, &kex_protocol_error);
}

تهی
kex_set_server_sig_algs(ساختار ssh *ssh, ثابت نویسه *allowed_algs)
{
	نویسه *alg, *oalgs, *algs, *sigalgs;
	ثابت نویسه *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	اگر ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == پوچ)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	آزاد(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = پوچ;
	برای ((alg = strsep(&algs, ",")); alg != پوچ && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		اگر ((sigalg = sshkey_sigalg_by_name(alg)) == پوچ)
			ادامه;
		اگر (!kex_has_any_alg(sigalg, sigalgs))
			ادامه;
		/* Don't add an algorithm twice. */
		اگر (ssh->kex->server_sig_algs != پوچ &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			ادامه;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	آزاد(oalgs);
	آزاد(sigalgs);
	اگر (ssh->kex->server_sig_algs == پوچ)
		ssh->kex->server_sig_algs = xstrdup("");
}

تهی
kex_set_warn_weak_crypto(ساختار ssh *ssh, صحیح warn_weak_crypto)
{
	اگر (ssh != پوچ && ssh->kex != پوچ)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

تهی
kex_check_warn_weak_crypto(ساختار ssh *ssh)
{
	نویسه remote_id[512];
	صحیح rekeyed = 0;

	اگر (ssh == پوچ || ssh->kex == پوچ || ssh->kex->name == پوچ ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		بازگشت;
	اگر (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		بازگشت;
	}

	اگر (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	اگر (!rekeyed && !ssh->kex->server)
		بازگشت; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, اندازه(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ایستا صحیح
kex_compose_ext_info_server(ساختار ssh *ssh, ساختار sshbuf *m)
{
	صحیح r;

	اگر (ssh->kex->server_sig_algs == پوچ &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
kex_compose_ext_info_client(ساختار ssh *ssh, ساختار sshbuf *m)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		برو out;
	}
	/* success */
	r = 0;
 out:
	بازگشت r;
}

ایستا صحیح
kex_maybe_send_ext_info(ساختار ssh *ssh)
{
	صحیح r;
	ساختار sshbuf *m = پوچ;

	اگر ((ssh->kex->flags & KEX_INITIAL) == 0)
		بازگشت 0;
	اگر (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		بازگشت 0;

	/* Compose EXT_INFO packet. */
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		برو fail;
	اگر (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		برو fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		برو fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	بازگشت r;
}

صحیح
kex_server_update_ext_info(ساختار ssh *ssh)
{
	صحیح r;

	اگر ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		بازگشت 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		بازگشت r;
	}
	بازگشت 0;
}

صحیح
kex_send_newkeys(ساختار ssh *ssh)
{
	صحیح r;

	kex_reset_dispatch(ssh);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		بازگشت r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_پیام_NEWKEYS, &kex_درون_داد_newkeys);
	اگر ((r = kex_maybe_send_ext_info(ssh)) != 0)
		بازگشت r;
	debug("expecting SSH2_MSG_NEWKEYS");
	بازگشت 0;
}

/* Check whether an ext_info value contains the expected version string */
ایستا صحیح
kex_ext_info_check_ver(ساختار kex *kex, ثابت نویسه *name,
    ثابت u_char *val, size_t len, ثابت نویسه *want_ver, u_int flag)
{
	اگر (memchr(val, '\0', len) != پوچ) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	اگر (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	وگرنه
		debug_f("unsupported version of %s extension", name);
	بازگشت 0;
}

ایستا صحیح
kex_ext_info_client_parse(ساختار ssh *ssh, ثابت نویسه *name,
    ثابت u_char *مقدار, size_t vlen)
{
	صحیح r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	اگر (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		اگر (memchr(مقدار, '\0', vlen) != پوچ) {
			error_f("nul byte in %s", name);
			بازگشت SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, مقدار);
		آزاد(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ثابت نویسه *)مقدار);
	} وگرنه اگر (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			بازگشت r;
		}
	} وگرنه اگر (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			بازگشت r;
		}
	} وگرنه اگر (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			بازگشت r;
		}
	} وگرنه
		debug_f("%s (unrecognised)", name);

	بازگشت 0;
}

ایستا صحیح
kex_ext_info_server_parse(ساختار ssh *ssh, ثابت نویسه *name,
    ثابت u_char *مقدار, size_t vlen)
{
	صحیح r;

	اگر (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			بازگشت r;
		}
	} وگرنه
		debug_f("%s (unrecognised)", name);
	بازگشت 0;
}

صحیح
kex_درون_داد_ext_info(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	ثابت صحیح max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	نویسه *name;
	u_char *val;
	size_t vlen;
	صحیح r;

	debug("SSH2_MSG_EXT_INFO received");
	اگر (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		بازگشت dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, &kex_protocol_error);
	اگر ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		بازگشت r;
	اگر (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		بازگشت dispatch_protocol_error(type, seq, ssh);
	}
	برای (i = 0; i < ninfo; i++) {
		اگر ((r = sshpkt_get_cstring(ssh, &name, پوچ)) != 0)
			بازگشت r;
		اگر ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			آزاد(name);
			بازگشت r;
		}
		debug3_f("extension %s", name);
		اگر (kex->server) {
			اگر ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				بازگشت r;
		} وگرنه {
			اگر ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				بازگشت r;
		}
		آزاد(name);
		آزاد(val);
	}
	بازگشت sshpkt_get_end(ssh);
}

ایستا صحیح
kex_درون_داد_newkeys(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	صحیح r, initial = (kex->flags & KEX_INITIAL) != 0;
	نویسه *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	اگر (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, &kex_درون_داد_ext_info);
	ssh_dispatch_set(ssh, SSH2_پیام_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_پیام_KEXINIT, &kex_درون_داد_kexinit);
	اگر ((r = sshpkt_get_end(ssh)) != 0)
		بازگشت r;
	اگر ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		بازگشت r;
	اگر (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		اگر ((r = kex_buf2prop(kex->my, پوچ, &prop)) != 0)
			بازگشت r;
		اگر ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == پوچ) {
			error_f("match_filter_denylist failed");
			برو fail;
		}
		آزاد(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		اگر ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			آزاد(prop);
			بازگشت SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		آزاد(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	بازگشت 0;
}

صحیح
kex_send_kexinit(ساختار ssh *ssh)
{
	u_char *cookie;
	ساختار kex *kex = ssh->kex;
	صحیح r;

	اگر (kex == پوچ) {
		error_f("no kex");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	اگر (kex->flags & KEX_INIT_SENT)
		بازگشت 0;
	kex->done = 0;

	/* generate a random cookie */
	اگر (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	اگر ((cookie = sshbuf_mutable_ptr(kex->my)) == پوچ) {
		error_f("buffer error");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		بازگشت r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	بازگشت 0;
}

صحیح
kex_درون_داد_kexinit(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	ثابت u_char *ptr;
	u_int i;
	size_t dlen;
	صحیح r;

	debug("SSH2_MSG_KEXINIT received");
	اگر (kex == پوچ) {
		error_f("no kex");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	آزاد(kex->name);
	kex->name = پوچ;
	اگر ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_پیام_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	اگر ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		بازگشت r;

	/* discard packet */
	برای (i = 0; i < KEX_COOKIE_LEN; i++) {
		اگر ((r = sshpkt_get_u8(ssh, پوچ)) != 0) {
			error_fr(r, "discard cookie");
			بازگشت r;
		}
	}
	برای (i = 0; i < PROPOSAL_MAX; i++) {
		اگر ((r = sshpkt_get_string(ssh, پوچ, پوچ)) != 0) {
			error_fr(r, "discard proposal");
			بازگشت r;
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
	اگر ((r = sshpkt_get_u8(ssh, پوچ)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, پوچ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			بازگشت r;

	اگر (!(kex->flags & KEX_INIT_SENT))
		اگر ((r = kex_send_kexinit(ssh)) != 0)
			بازگشت r;
	اگر ((r = kex_choose_conf(ssh, seq)) != 0)
		بازگشت r;

	اگر (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != پوچ)
		بازگشت (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	بازگشت SSH_ERR_INTERNAL_ERROR;
}

ساختار kex *
kex_new(تهی)
{
	ساختار kex *kex;

	اگر ((kex = calloc(1, اندازه(*kex))) == پوچ ||
	    (kex->peer = sshbuf_new()) == پوچ ||
	    (kex->my = sshbuf_new()) == پوچ ||
	    (kex->client_version = sshbuf_new()) == پوچ ||
	    (kex->server_version = sshbuf_new()) == پوچ ||
	    (kex->session_id = sshbuf_new()) == پوچ) {
		kex_free(kex);
		بازگشت پوچ;
	}
	بازگشت kex;
}

تهی
kex_free_newkeys(ساختار newkeys *newkeys)
{
	اگر (newkeys == پوچ)
		بازگشت;
	اگر (newkeys->enc.کلید) {
		explicit_bzero(newkeys->enc.کلید, newkeys->enc.کلید_len);
		آزاد(newkeys->enc.کلید);
		newkeys->enc.کلید = پوچ;
	}
	اگر (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		آزاد(newkeys->enc.iv);
		newkeys->enc.iv = پوچ;
	}
	آزاد(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, اندازه(newkeys->enc));
	آزاد(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, اندازه(newkeys->comp));
	mac_clear(&newkeys->mac);
	اگر (newkeys->mac.کلید) {
		explicit_bzero(newkeys->mac.کلید, newkeys->mac.کلید_len);
		آزاد(newkeys->mac.کلید);
		newkeys->mac.کلید = پوچ;
	}
	آزاد(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, اندازه(newkeys->mac));
	freezero(newkeys, اندازه(*newkeys));
}

تهی
kex_free(ساختار kex *kex)
{
	u_int mode;

	اگر (kex == پوچ)
		بازگشت;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_کلید_free(kex->ec_client_کلید);
#endif /* WITH_OPENSSL */
	برای (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = پوچ;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	آزاد(kex->failed_choice);
	آزاد(kex->hostkey_alg);
	آزاد(kex->name);
	آزاد(kex->server_sig_algs);
	آزاد(kex);
}

صحیح
kex_ready(ساختار ssh *ssh, نویسه *proposal[PROPOSAL_MAX])
{
	صحیح r;

	اگر ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		بازگشت r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_پیام_KEXINIT, &kex_درون_داد_kexinit);
	بازگشت 0;
}

صحیح
kex_setup(ساختار ssh *ssh, نویسه *proposal[PROPOSAL_MAX])
{
	صحیح r;

	اگر ((r = kex_ready(ssh, proposal)) != 0)
		بازگشت r;
	اگر ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = پوچ;
		بازگشت r;
	}
	بازگشت 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
صحیح
kex_start_rekex(ساختار ssh *ssh)
{
	اگر (ssh->kex == پوچ) {
		error_f("no kex");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	اگر (ssh->kex->done == 0) {
		error_f("requested twice");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	بازگشت kex_send_kexinit(ssh);
}

ایستا صحیح
choose_enc(ساختار sshenc *enc, نویسه *client, نویسه *server)
{
	نویسه *name = match_list(client, server, پوچ);

	اگر (name == پوچ)
		بازگشت SSH_ERR_NO_CIPHER_ALG_MATCH;
	اگر ((enc->cipher = cipher_by_name(name)) == پوچ) {
		error_f("unsupported cipher %s", name);
		آزاد(name);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = پوچ;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->کلید = پوچ;
	enc->کلید_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	بازگشت 0;
}

ایستا صحیح
choose_mac(ساختار ssh *ssh, ساختار sshmac *mac, نویسه *client, نویسه *server)
{
	نویسه *name = match_list(client, server, پوچ);

	اگر (name == پوچ)
		بازگشت SSH_ERR_NO_MAC_ALG_MATCH;
	اگر (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		آزاد(name);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->کلید = پوچ;
	mac->enabled = 0;
	بازگشت 0;
}

ایستا صحیح
choose_comp(ساختار sshcomp *comp, نویسه *client, نویسه *server)
{
	نویسه *name = match_list(client, server, پوچ);

	اگر (name == پوچ)
		بازگشت SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	اگر (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} وگرنه
#endif	/* WITH_ZLIB */
	اگر (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} وگرنه {
		error_f("unsupported compression scheme %s", name);
		آزاد(name);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	بازگشت 0;
}

ایستا صحیح
choose_kex(ساختار kex *k, نویسه *client, نویسه *server)
{
	k->name = match_list(client, server, پوچ);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	اگر (k->name == پوچ)
		بازگشت SSH_ERR_NO_KEX_ALG_MATCH;
	اگر (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	بازگشت 0;
}

ایستا صحیح
choose_hostkeyalg(ساختار kex *k, نویسه *client, نویسه *server)
{
	آزاد(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, پوچ);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	اگر (k->hostkey_alg == پوچ)
		بازگشت SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	اگر (k->hostkey_type == کلید_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	بازگشت 0;
}

ایستا صحیح
proposals_match(نویسه *my[PROPOSAL_MAX], نویسه *peer[PROPOSAL_MAX])
{
	ایستا صحیح check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_کلید_ALGS, -1
	};
	صحیح *idx;
	نویسه *p;

	برای (idx = &check[0]; *idx != -1; idx++) {
		اگر ((p = strchr(my[*idx], ',')) != پوچ)
			*p = '\0';
		اگر ((p = strchr(peer[*idx], ',')) != پوچ)
			*p = '\0';
		اگر (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			بازگشت (0);
		}
	}
	debug2("proposals match");
	بازگشت (1);
}

ایستا صحیح
kexalgs_contains(نویسه **peer, ثابت نویسه *ext)
{
	بازگشت kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ایستا صحیح
kex_choose_conf(ساختار ssh *ssh, uint32_t seq)
{
	ساختار kex *kex = ssh->kex;
	ساختار newkeys *newkeys;
	نویسه **my = پوچ, **peer = پوچ;
	نویسه **cprop, **sprop;
	صحیح nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	صحیح r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	اگر ((r = kex_buf2prop(kex->my, پوچ, &my)) != 0)
		برو out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	اگر ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		برو out;

	اگر (kex->server) {
		cprop=peer;
		sprop=my;
	} وگرنه {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} وگرنه {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		اگر (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			اگر (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	اگر (kex->server && (kex->flags & KEX_INITIAL)) {
		اگر (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_کلید_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		اگر (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_کلید_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	اگر ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = پوچ;
		برو out;
	}
	اگر ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_کلید_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_کلید_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_کلید_ALGS];
		peer[PROPOSAL_SERVER_HOST_کلید_ALGS] = پوچ;
		برو out;
	}
	برای (mode = 0; mode < MODE_MAX; mode++) {
		اگر ((newkeys = calloc(1, اندازه(*newkeys))) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		اگر ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = پوچ;
			برو out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		اگر (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = پوچ;
			برو out;
		}
		اگر ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = پوچ;
			برو out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	برای (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.کلید_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.کلید_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.کلید_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	اگر (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	بازگشت r;
}

ایستا صحیح
derive_کلید(ساختار ssh *ssh, صحیح id, u_int need, u_char *hash, u_int hashlen,
    ثابت ساختار sshbuf *shared_secret, u_char **keyp)
{
	ساختار kex *kex = ssh->kex;
	ساختار ssh_digest_ctx *hashctx = پوچ;
	نویسه c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	صحیح r;

	اگر ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((digest = calloc(1, ROUNDUP(need, mdsz))) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	اگر ((hashctx = ssh_digest_start(kex->hash_alg)) == پوچ ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		برو out;
	}
	ssh_digest_free(hashctx);
	hashctx = پوچ;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	برای (have = mdsz; need > have; have += mdsz) {
		اگر ((hashctx = ssh_digest_start(kex->hash_alg)) == پوچ ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		ssh_digest_free(hashctx);
		hashctx = پوچ;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = پوچ;
	r = 0;
 out:
	آزاد(digest);
	ssh_digest_free(hashctx);
	بازگشت r;
}

#define NKEYS	6
صحیح
kex_derive_کلیدها(ساختار ssh *ssh, u_char *hash, u_int hashlen,
    ثابت ساختار sshbuf *shared_secret)
{
	ساختار kex *kex = ssh->kex;
	u_char *کلیدها[NKEYS];
	u_int i, j, mode, ctos;
	صحیح r;

	/* save initial hash as session id */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			بازگشت SSH_ERR_INTERNAL_ERROR;
		}
		اگر ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			بازگشت r;
	} وگرنه اگر (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	برای (i = 0; i < NKEYS; i++) {
		اگر ((r = derive_کلید(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &کلیدها[i])) != 0) {
			برای (j = 0; j < i; j++)
				آزاد(کلیدها[j]);
			بازگشت r;
		}
	}
	برای (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = کلیدها[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.کلید = کلیدها[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.کلید = کلیدها[ctos ? 4 : 5];
	}
	بازگشت 0;
}

صحیح
kex_load_hostkey(ساختار ssh *ssh, ساختار sshkey **prvp, ساختار sshkey **pubp)
{
	ساختار kex *kex = ssh->kex;

	*pubp = پوچ;
	*prvp = پوچ;
	اگر (kex->load_host_public_کلید == پوچ ||
	    kex->load_host_private_کلید == پوچ) {
		error_f("missing hostkey loader");
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_کلید(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_کلید(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	اگر (*pubp == پوچ)
		بازگشت SSH_ERR_NO_HOSTKEY_LOADED;
	بازگشت 0;
}

صحیح
kex_verify_host_کلید(ساختار ssh *ssh, ساختار sshkey *server_host_کلید)
{
	ساختار kex *kex = ssh->kex;

	اگر (kex->verify_host_کلید == پوچ) {
		error_f("missing hostkey verifier");
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	اگر (server_host_کلید->type != kex->hostkey_type ||
	    (kex->hostkey_type == کلید_ECDSA &&
	    server_host_کلید->ecdsa_nid != kex->hostkey_nid))
		بازگشت SSH_ERR_کلید_TYPE_MISMATCH;
	اگر (kex->verify_host_کلید(server_host_کلید, ssh) == -1)
		بازگشت  SSH_ERR_SIGNATURE_INVALID;
	بازگشت 0;
}

#اگر defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
تهی
dump_digest(ثابت نویسه *پیام, ثابت u_char *digest, صحیح len)
{
	fprintf(stderr, "%s\n", پیام);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ایستا تهی
send_error(ساختار ssh *ssh, نویسه *پیام)
{
	نویسه *crnl = "\r\n";

	اگر (!ssh->kex->server)
		بازگشت;

	اگر (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    پیام, strlen(پیام)) != strlen(پیام) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
صحیح
kex_exchange_identification(ساختار ssh *ssh, صحیح timeout_ms,
    ثابت نویسه *version_addendum)
{
	صحیح remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	صحیح r, expect_nl;
	u_char c;
	ساختار sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	ساختار sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	نویسه *our_version_string = پوچ, *peer_version_string = پوچ;
	نویسه *cp, *remote_version = پوچ;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	اگر (version_addendum != پوچ && *version_addendum == '\0')
		version_addendum = پوچ;
	اگر ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == پوچ ? "" : " ",
	    version_addendum == پوچ ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		برو out;
	}

	اگر (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		برو out;
	}
	اگر ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		برو out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	اگر (our_version_string == پوچ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	برای (n = 0; ; n++) {
		اگر (n >= SSH_MAX_PRE_BANNER_سطرها) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_سطرها);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		برای (;;) {
			اگر (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, پوچ);
				اگر (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					برو out;
				} وگرنه اگر (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					برو out;
				}
			}

			len = atomicio(اقرأ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			اگر (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				برو out;
			} وگرنه اگر (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				برو out;
			}
			اگر (c == '\r') {
				expect_nl = 1;
				ادامه;
			}
			اگر (c == '\n')
				بشکن;
			اگر (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				برو invalid;
			}
			اگر ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				برو out;
			}
			اگر (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				برو invalid;
			}
		}
		/* Is this an actual protocol banner? */
		اگر (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			بشکن;
		/* If not, then just log the line and continue */
		اگر ((cp = sshbuf_dup_string(peer_version)) == پوچ) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		/* Do not accept lines before the SSH ident from a client */
		اگر (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			آزاد(cp);
			برو invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		آزاد(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	اگر (peer_version_string == پوچ)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	اگر ((remote_version = calloc(1, sshbuf_len(peer_version))) == پوچ) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	اگر (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	انتخاب (remote_major) {
	حالت 2:
		بشکن;
	حالت 1:
		اگر (remote_minor != 99)
			mismatch = 1;
		بشکن;
	پیشفرض:
		mismatch = 1;
		بشکن;
	}
	اگر (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		برو out;
	}

	اگر (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		برو out;
	}
	اگر (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		برو out;
	}
	/* success */
	r = 0;
 out:
	آزاد(our_version_string);
	آزاد(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	اگر (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	بازگشت r;
}

