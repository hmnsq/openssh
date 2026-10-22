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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/crypto.h>
#شامل <openssl/dh.h>
#اگر_ختم

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
ساکن صحیح kex_انتخاب_conf(ساخت ssh *, uint32_t seq);
ساکن صحیح kex_داخلہ_newkeys(صحیح, uint32_t, ساخت ssh *);

ساکن ثابت حرف * ثابت proposal_نام[PROPOSAL_MAX] = {
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
خالی
kex_proposal_populate_entries(ساخت ssh *ssh, حرف *prop[PROPOSAL_MAX],
    ثابت حرف *kexalgos, ثابت حرف *ciphers, ثابت حرف *macs,
    ثابت حرف *comp, ثابت حرف *hkalgs)
{
	ثابت حرف *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ثابت حرف *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ثابت حرف **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	حرف *cp;

	اگر (prop == تہی)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	اگر (kexalgos == تہی)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	اگر ((cp = kex_نام_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == تہی)
		fatal_f("kex_names_cat");

	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		انتخاب(i) {
		حالت PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			توڑو;
		حالت PROPOSAL_ENC_ALGS_CTOS:
		حالت PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			توڑو;
		حالت PROPOSAL_MAC_ALGS_CTOS:
		حالت PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			توڑو;
		حالت PROPOSAL_COMP_ALGS_CTOS:
		حالت PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			توڑو;
		حالت PROPOSAL_SERVER_HOST_کلید_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			توڑو;
		طےشدہ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	آزاد(cp);
}

خالی
kex_proposal_free_entries(حرف *prop[PROPOSAL_MAX])
{
	u_int i;

	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(prop[i]);
}

/* put algorithm proposal into buffer */
صحیح
kex_prop2buf(ساخت sshbuf *b, حرف *proposal[PROPOSAL_MAX])
{
	u_int i;
	صحیح r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	برائے (i = 0; i < KEX_COOKIE_LEN; i++) {
		اگر ((r = sshbuf_put_u8(b, 0)) != 0)
			واپس r;
	}
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		اگر ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			واپس r;
	}
	اگر ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		واپس r;
	واپس 0;
}

/* parse buffer and return algorithm proposal */
صحیح
kex_buf2prop(ساخت sshbuf *raw, صحیح *پہلا_kex_follows, حرف ***propp)
{
	ساخت sshbuf *b = تہی;
	u_char v;
	u_int i;
	حرف **proposal = تہی;
	صحیح r;

	*propp = تہی;
	اگر ((proposal = صفر_حافظہ_دو(PROPOSAL_MAX, حجم(حرف *))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((b = sshbuf_fromb(raw)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		جاؤ برآمد;
	}
	/* extract kex init proposal strings */
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		اگر ((r = sshbuf_get_cstring(b, &(proposal[i]), تہی)) != 0) {
			error_fr(r, "parse proposal %u", i);
			جاؤ برآمد;
		}
		debug2("%s: %s", proposal_نام[i], proposal[i]);
	}
	/* first kex follows / reserved */
	اگر ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		جاؤ برآمد;
	}
	اگر (پہلا_kex_follows != تہی)
		*پہلا_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 برآمد:
	اگر (r != 0 && proposal != تہی)
		kex_prop_free(proposal);
	sshbuf_free(b);
	واپس r;
}

خالی
kex_prop_free(حرف **proposal)
{
	u_int i;

	اگر (proposal == تہی)
		واپس;
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	آزاد(proposal);
}

صحیح
kex_protocol_error(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	صحیح r;

	/* If in strict mode, any unexpected message is an error */
	اگر ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		واپس r;
	واپس 0;
}

ساکن خالی
kex_reset_dispatch(ساخت ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_پیغام_TRANSPORT_MIN,
	    SSH2_پیغام_TRANSPORT_MAX, &kex_protocol_error);
}

خالی
kex_سیٹ_server_sig_algs(ساخت ssh *ssh, ثابت حرف *allowed_algs)
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
	اگر ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == تہی)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	آزاد(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = تہی;
	برائے ((alg = strsep(&algs, ",")); alg != تہی && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		اگر ((sigalg = sshkey_sigalg_by_name(alg)) == تہی)
			جاری;
		اگر (!kex_has_any_alg(sigalg, sigalgs))
			جاری;
		/* Don't add an algorithm twice. */
		اگر (ssh->kex->server_sig_algs != تہی &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			جاری;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	آزاد(oalgs);
	آزاد(sigalgs);
	اگر (ssh->kex->server_sig_algs == تہی)
		ssh->kex->server_sig_algs = xstrdup("");
}

خالی
kex_سیٹ_warn_weak_crypto(ساخت ssh *ssh, صحیح warn_weak_crypto)
{
	اگر (ssh != تہی && ssh->kex != تہی)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

خالی
kex_check_warn_weak_crypto(ساخت ssh *ssh)
{
	حرف remote_id[512];
	صحیح rekeyed = 0;

	اگر (ssh == تہی || ssh->kex == تہی || ssh->kex->name == تہی ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		واپس;
	اگر (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		واپس;
	}

	اگر (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	اگر (!rekeyed && !ssh->kex->server)
		واپس; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, حجم(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

ساکن صحیح
kex_compose_ext_info_server(ساخت ssh *ssh, ساخت sshbuf *m)
{
	صحیح r;

	اگر (ssh->kex->server_sig_algs == تہی &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
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
		واپس r;
	}
	واپس 0;
}

ساکن صحیح
kex_compose_ext_info_client(ساخت ssh *ssh, ساخت sshbuf *m)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	واپس r;
}

ساکن صحیح
kex_maybe_send_ext_info(ساخت ssh *ssh)
{
	صحیح r;
	ساخت sshbuf *m = تہی;

	اگر ((ssh->kex->flags & KEX_INITIAL) == 0)
		واپس 0;
	اگر (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		واپس 0;

	/* Compose EXT_INFO packet. */
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		جاؤ fail;
	اگر (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		جاؤ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		جاؤ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	واپس r;
}

صحیح
kex_server_update_ext_info(ساخت ssh *ssh)
{
	صحیح r;

	اگر ((ssh->kex->flags & KEX_HAS_EXT_INFO_اندر_AUTH) == 0)
		واپس 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		واپس r;
	}
	واپس 0;
}

صحیح
kex_send_newkeys(ساخت ssh *ssh)
{
	صحیح r;

	kex_reset_dispatch(ssh);
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		واپس r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_NEWKEYS, &kex_داخلہ_newkeys);
	اگر ((r = kex_maybe_send_ext_info(ssh)) != 0)
		واپس r;
	debug("expecting SSH2_MSG_NEWKEYS");
	واپس 0;
}

/* Check whether an ext_info value contains the expected version string */
ساکن صحیح
kex_ext_info_check_ver(ساخت kex *kex, ثابت حرف *name,
    ثابت u_char *val, سائز_t len, ثابت حرف *want_ver, u_int flag)
{
	اگر (memchr(val, '\0', len) != تہی) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	اگر (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	ورنہ
		debug_f("unsupported version of %s extension", name);
	واپس 0;
}

ساکن صحیح
kex_ext_info_client_parse(ساخت ssh *ssh, ثابت حرف *name,
    ثابت u_char *قدر, سائز_t vlen)
{
	صحیح r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	اگر (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		اگر (memchr(قدر, '\0', vlen) != تہی) {
			error_f("nul byte in %s", name);
			واپس SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, قدر);
		آزاد(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ثابت حرف *)قدر);
	} ورنہ اگر (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, قدر, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			واپس r;
		}
	} ورنہ اگر (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, قدر, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			واپس r;
		}
	} ورنہ اگر (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, قدر, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			واپس r;
		}
	} ورنہ
		debug_f("%s (unrecognised)", name);

	واپس 0;
}

ساکن صحیح
kex_ext_info_server_parse(ساخت ssh *ssh, ثابت حرف *name,
    ثابت u_char *قدر, سائز_t vlen)
{
	صحیح r;

	اگر (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		اگر ((r = kex_ext_info_check_ver(ssh->kex, name, قدر, vlen,
		    "0", KEX_HAS_EXT_INFO_اندر_AUTH)) != 0) {
			واپس r;
		}
	} ورنہ
		debug_f("%s (unrecognised)", name);
	واپس 0;
}

صحیح
kex_داخلہ_ext_info(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	ثابت صحیح max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	حرف *name;
	u_char *val;
	سائز_t vlen;
	صحیح r;

	debug("SSH2_MSG_EXT_INFO received");
	اگر (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		واپس dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, &kex_protocol_error);
	اگر ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		واپس r;
	اگر (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		واپس dispatch_protocol_error(type, seq, ssh);
	}
	برائے (i = 0; i < ninfo; i++) {
		اگر ((r = sshpkt_get_cstring(ssh, &name, تہی)) != 0)
			واپس r;
		اگر ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			آزاد(name);
			واپس r;
		}
		debug3_f("extension %s", name);
		اگر (kex->server) {
			اگر ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				واپس r;
		} ورنہ {
			اگر ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				واپس r;
		}
		آزاد(name);
		آزاد(val);
	}
	واپس sshpkt_get_انتہا(ssh);
}

ساکن صحیح
kex_داخلہ_newkeys(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	صحیح r, initial = (kex->flags & KEX_INITIAL) != 0;
	حرف *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	اگر (kex->ext_info_c && initial)
		ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, &kex_داخلہ_ext_info);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEXINIT, &kex_داخلہ_kexinit);
	اگر ((r = sshpkt_get_انتہا(ssh)) != 0)
		واپس r;
	اگر ((r = ssh_سیٹ_newkeys(ssh, منوال_اندر)) != 0)
		واپس r;
	اگر (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		اگر ((r = kex_buf2prop(kex->my, تہی, &prop)) != 0)
			واپس r;
		اگر ((cp = مطابقت_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == تہی) {
			error_f("match_filter_denylist failed");
			جاؤ fail;
		}
		آزاد(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		اگر ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			آزاد(prop);
			واپس SSH_ERR_اندرونی_ERROR;
		}
		kex_proposal_free_entries(prop);
		آزاد(prop);
	}
	kex->مکمل = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_بھیجا|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	واپس 0;
}

صحیح
kex_send_kexinit(ساخت ssh *ssh)
{
	u_char *cookie;
	ساخت kex *kex = ssh->kex;
	صحیح r;

	اگر (kex == تہی) {
		error_f("no kex");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	اگر (kex->flags & KEX_INIT_بھیجا)
		واپس 0;
	kex->مکمل = 0;

	/* generate a random cookie */
	اگر (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	اگر ((cookie = sshbuf_mutable_ptr(kex->my)) == تہی) {
		error_f("buffer error");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		واپس r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_بھیجا;
	واپس 0;
}

صحیح
kex_داخلہ_kexinit(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	ثابت u_char *ptr;
	u_int i;
	سائز_t dlen;
	صحیح r;

	debug("SSH2_MSG_KEXINIT received");
	اگر (kex == تہی) {
		error_f("no kex");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	آزاد(kex->name);
	kex->name = تہی;
	اگر ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	اگر ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		واپس r;

	/* discard packet */
	برائے (i = 0; i < KEX_COOKIE_LEN; i++) {
		اگر ((r = sshpkt_get_u8(ssh, تہی)) != 0) {
			error_fr(r, "discard cookie");
			واپس r;
		}
	}
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		اگر ((r = sshpkt_get_string(ssh, تہی, تہی)) != 0) {
			error_fr(r, "discard proposal");
			واپس r;
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
	اگر ((r = sshpkt_get_u8(ssh, تہی)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, تہی)) != 0 ||	/* reserved */
	    (r = sshpkt_get_انتہا(ssh)) != 0)
			واپس r;

	اگر (!(kex->flags & KEX_INIT_بھیجا))
		اگر ((r = kex_send_kexinit(ssh)) != 0)
			واپس r;
	اگر ((r = kex_انتخاب_conf(ssh, seq)) != 0)
		واپس r;

	اگر (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != تہی)
		واپس (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	واپس SSH_ERR_اندرونی_ERROR;
}

ساخت kex *
kex_new(خالی)
{
	ساخت kex *kex;

	اگر ((kex = صفر_حافظہ_دو(1, حجم(*kex))) == تہی ||
	    (kex->peer = sshbuf_new()) == تہی ||
	    (kex->my = sshbuf_new()) == تہی ||
	    (kex->client_نسخہ = sshbuf_new()) == تہی ||
	    (kex->server_نسخہ = sshbuf_new()) == تہی ||
	    (kex->session_id = sshbuf_new()) == تہی) {
		kex_free(kex);
		واپس تہی;
	}
	واپس kex;
}

خالی
kex_free_newkeys(ساخت newkeys *newkeys)
{
	اگر (newkeys == تہی)
		واپس;
	اگر (newkeys->enc.کلید) {
		explicit_bzero(newkeys->enc.کلید, newkeys->enc.کلید_len);
		آزاد(newkeys->enc.کلید);
		newkeys->enc.کلید = تہی;
	}
	اگر (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		آزاد(newkeys->enc.iv);
		newkeys->enc.iv = تہی;
	}
	آزاد(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, حجم(newkeys->enc));
	آزاد(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, حجم(newkeys->comp));
	mac_clear(&newkeys->mac);
	اگر (newkeys->mac.کلید) {
		explicit_bzero(newkeys->mac.کلید, newkeys->mac.کلید_len);
		آزاد(newkeys->mac.کلید);
		newkeys->mac.کلید = تہی;
	}
	آزاد(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, حجم(newkeys->mac));
	freezero(newkeys, حجم(*newkeys));
}

خالی
kex_free(ساخت kex *kex)
{
	u_int منوال;

	اگر (kex == تہی)
		واپس;

#اگر_تعریف_شدہ WITH_OPENSSL
	DH_free(kex->dh);
	EC_کلید_free(kex->ec_client_کلید);
#اگر_ختم /* WITH_OPENSSL */
	برائے (منوال = 0; منوال < منوال_MAX; منوال++) {
		kex_free_newkeys(kex->newkeys[منوال]);
		kex->newkeys[منوال] = تہی;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_نسخہ);
	sshbuf_free(kex->server_نسخہ);
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
kex_ready(ساخت ssh *ssh, حرف *proposal[PROPOSAL_MAX])
{
	صحیح r;

	اگر ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		واپس r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEXINIT, &kex_داخلہ_kexinit);
	واپس 0;
}

صحیح
kex_تیاری(ساخت ssh *ssh, حرف *proposal[PROPOSAL_MAX])
{
	صحیح r;

	اگر ((r = kex_ready(ssh, proposal)) != 0)
		واپس r;
	اگر ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = تہی;
		واپس r;
	}
	واپس 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
صحیح
kex_آغاز_rekex(ساخت ssh *ssh)
{
	اگر (ssh->kex == تہی) {
		error_f("no kex");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	اگر (ssh->kex->مکمل == 0) {
		error_f("requested twice");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	ssh->kex->مکمل = 0;
	واپس kex_send_kexinit(ssh);
}

ساکن صحیح
انتخاب_enc(ساخت sshenc *enc, حرف *client, حرف *server)
{
	حرف *name = مطابقت_list(client, server, تہی);

	اگر (name == تہی)
		واپس SSH_ERR_NO_CIPHER_ALG_مطابقت;
	اگر ((enc->cipher = cipher_by_name(name)) == تہی) {
		error_f("unsupported cipher %s", name);
		آزاد(name);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = تہی;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->کلید = تہی;
	enc->کلید_len = cipher_keylen(enc->cipher);
	enc->بلاک_سائز = cipher_blocksize(enc->cipher);
	واپس 0;
}

ساکن صحیح
انتخاب_mac(ساخت ssh *ssh, ساخت sshmac *mac, حرف *client, حرف *server)
{
	حرف *name = مطابقت_list(client, server, تہی);

	اگر (name == تہی)
		واپس SSH_ERR_NO_MAC_ALG_مطابقت;
	اگر (mac_تیاری(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		آزاد(name);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	mac->name = name;
	mac->کلید = تہی;
	mac->enabled = 0;
	واپس 0;
}

ساکن صحیح
انتخاب_comp(ساخت sshcomp *comp, حرف *client, حرف *server)
{
	حرف *name = مطابقت_list(client, server, تہی);

	اگر (name == تہی)
		واپس SSH_ERR_NO_COMPRESS_ALG_مطابقت;
#اگر_تعریف_شدہ WITH_ZLIB
	اگر (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} ورنہ
#اگر_ختم	/* WITH_ZLIB */
	اگر (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} ورنہ {
		error_f("unsupported compression scheme %s", name);
		آزاد(name);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	comp->name = name;
	واپس 0;
}

ساکن صحیح
انتخاب_kex(ساخت kex *k, حرف *client, حرف *server)
{
	k->name = مطابقت_list(client, server, تہی);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	اگر (k->name == تہی)
		واپس SSH_ERR_NO_KEX_ALG_مطابقت;
	اگر (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	واپس 0;
}

ساکن صحیح
انتخاب_hostkeyalg(ساخت kex *k, حرف *client, حرف *server)
{
	آزاد(k->hostkey_alg);
	k->hostkey_alg = مطابقت_list(client, server, تہی);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	اگر (k->hostkey_alg == تہی)
		واپس SSH_ERR_NO_HOSTKEY_ALG_مطابقت;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	اگر (k->hostkey_type == کلید_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	واپس 0;
}

ساکن صحیح
proposals_مطابقت(حرف *my[PROPOSAL_MAX], حرف *peer[PROPOSAL_MAX])
{
	ساکن صحیح check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_کلید_ALGS, -1
	};
	صحیح *idx;
	حرف *p;

	برائے (idx = &check[0]; *idx != -1; idx++) {
		اگر ((p = strchr(my[*idx], ',')) != تہی)
			*p = '\0';
		اگر ((p = strchr(peer[*idx], ',')) != تہی)
			*p = '\0';
		اگر (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			واپس (0);
		}
	}
	debug2("proposals match");
	واپس (1);
}

ساکن صحیح
kexalgs_شامل_ہے(حرف **peer, ثابت حرف *ext)
{
	واپس kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ساکن صحیح
kex_انتخاب_conf(ساخت ssh *ssh, uint32_t seq)
{
	ساخت kex *kex = ssh->kex;
	ساخت newkeys *newkeys;
	حرف **my = تہی, **peer = تہی;
	حرف **cprop, **sprop;
	صحیح nenc, nmac, ncomp;
	u_int منوال, ctos, need, dh_need, authlen;
	صحیح r, پہلا_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	اگر ((r = kex_buf2prop(kex->my, تہی, &my)) != 0)
		جاؤ برآمد;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	اگر ((r = kex_buf2prop(kex->peer, &پہلا_kex_follows, &peer)) != 0)
		جاؤ برآمد;

	اگر (kex->server) {
		cprop=peer;
		sprop=my;
	} ورنہ {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (kex->server) {
			kex->ext_info_c = kexalgs_شامل_ہے(peer, "ext-info-c");
			kex->kex_strict = kexalgs_شامل_ہے(peer,
			    "kex-strict-c-v00@openssh.com");
		} ورنہ {
			kex->ext_info_s = kexalgs_شامل_ہے(peer, "ext-info-s");
			kex->kex_strict = kexalgs_شامل_ہے(peer,
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
	اگر ((r = انتخاب_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = تہی;
		جاؤ برآمد;
	}
	اگر ((r = انتخاب_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_کلید_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_کلید_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_کلید_ALGS];
		peer[PROPOSAL_SERVER_HOST_کلید_ALGS] = تہی;
		جاؤ برآمد;
	}
	برائے (منوال = 0; منوال < منوال_MAX; منوال++) {
		اگر ((newkeys = صفر_حافظہ_دو(1, حجم(*newkeys))) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		kex->newkeys[منوال] = newkeys;
		ctos = (!kex->server && منوال == منوال_برآمد) ||
		    (kex->server && منوال == منوال_اندر);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		اگر ((r = انتخاب_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = تہی;
			جاؤ برآمد;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		اگر (authlen == 0 &&
		    (r = انتخاب_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = تہی;
			جاؤ برآمد;
		}
		اگر ((r = انتخاب_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = تہی;
			جاؤ برآمد;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	برائے (منوال = 0; منوال < منوال_MAX; منوال++) {
		newkeys = kex->newkeys[منوال];
		need = زیادہ_سے_زیادہ(need, newkeys->enc.کلید_len);
		need = زیادہ_سے_زیادہ(need, newkeys->enc.بلاک_سائز);
		need = زیادہ_سے_زیادہ(need, newkeys->enc.iv_len);
		need = زیادہ_سے_زیادہ(need, newkeys->mac.کلید_len);
		dh_need = زیادہ_سے_زیادہ(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = زیادہ_سے_زیادہ(dh_need, newkeys->enc.بلاک_سائز);
		dh_need = زیادہ_سے_زیادہ(dh_need, newkeys->enc.iv_len);
		dh_need = زیادہ_سے_زیادہ(dh_need, newkeys->mac.کلید_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	اگر (پہلا_kex_follows && !proposals_مطابقت(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 برآمد:
	kex_prop_free(my);
	kex_prop_free(peer);
	واپس r;
}

ساکن صحیح
derive_کلید(ساخت ssh *ssh, صحیح id, u_int need, u_char *hash, u_int hashlen,
    ثابت ساخت sshbuf *shared_secret, u_char **keyp)
{
	ساخت kex *kex = ssh->kex;
	ساخت ssh_digest_ctx *hashctx = تہی;
	حرف c = id;
	u_int have;
	سائز_t mdsz;
	u_char *digest;
	صحیح r;

	اگر ((mdsz = ssh_digest_بائٹیں(kex->hash_alg)) == 0)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((digest = صفر_حافظہ_دو(1, ROUNDUP(need, mdsz))) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	اگر ((hashctx = ssh_digest_آغاز(kex->hash_alg)) == تہی ||
	    ssh_digest_update_بفر(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_بفر(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		جاؤ برآمد;
	}
	ssh_digest_free(hashctx);
	hashctx = تہی;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	برائے (have = mdsz; need > have; have += mdsz) {
		اگر ((hashctx = ssh_digest_آغاز(kex->hash_alg)) == تہی ||
		    ssh_digest_update_بفر(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		ssh_digest_free(hashctx);
		hashctx = تہی;
	}
#اگر_تعریف_شدہ DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#اگر_ختم
	*keyp = digest;
	digest = تہی;
	r = 0;
 برآمد:
	آزاد(digest);
	ssh_digest_free(hashctx);
	واپس r;
}

#تعریف_کرو NKEYS	6
صحیح
kex_derive_کلیدیں(ساخت ssh *ssh, u_char *hash, u_int hashlen,
    ثابت ساخت sshbuf *shared_secret)
{
	ساخت kex *kex = ssh->kex;
	u_char *کلیدیں[NKEYS];
	u_int i, j, منوال, ctos;
	صحیح r;

	/* save initial hash as session id */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			واپس SSH_ERR_اندرونی_ERROR;
		}
		اگر ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			واپس r;
	} ورنہ اگر (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	برائے (i = 0; i < NKEYS; i++) {
		اگر ((r = derive_کلید(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &کلیدیں[i])) != 0) {
			برائے (j = 0; j < i; j++)
				آزاد(کلیدیں[j]);
			واپس r;
		}
	}
	برائے (منوال = 0; منوال < منوال_MAX; منوال++) {
		ctos = (!kex->server && منوال == منوال_برآمد) ||
		    (kex->server && منوال == منوال_اندر);
		kex->newkeys[منوال]->enc.iv  = کلیدیں[ctos ? 0 : 1];
		kex->newkeys[منوال]->enc.کلید = کلیدیں[ctos ? 2 : 3];
		kex->newkeys[منوال]->mac.کلید = کلیدیں[ctos ? 4 : 5];
	}
	واپس 0;
}

صحیح
kex_بھرو_hostkey(ساخت ssh *ssh, ساخت sshkey **prvp, ساخت sshkey **pubp)
{
	ساخت kex *kex = ssh->kex;

	*pubp = تہی;
	*prvp = تہی;
	اگر (kex->بھرو_host_عوامی_کلید == تہی ||
	    kex->بھرو_host_نجی_کلید == تہی) {
		error_f("missing hostkey loader");
		واپس SSH_ERR_INVALID_دلیل;
	}
	*pubp = kex->بھرو_host_عوامی_کلید(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->بھرو_host_نجی_کلید(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	اگر (*pubp == تہی)
		واپس SSH_ERR_NO_HOSTKEY_LOADED;
	واپس 0;
}

صحیح
kex_verify_host_کلید(ساخت ssh *ssh, ساخت sshkey *server_host_کلید)
{
	ساخت kex *kex = ssh->kex;

	اگر (kex->verify_host_کلید == تہی) {
		error_f("missing hostkey verifier");
		واپس SSH_ERR_INVALID_دلیل;
	}
	اگر (server_host_کلید->type != kex->hostkey_type ||
	    (kex->hostkey_type == کلید_ECDSA &&
	    server_host_کلید->ecdsa_nid != kex->hostkey_nid))
		واپس SSH_ERR_کلید_TYPE_MISMATCH;
	اگر (kex->verify_host_کلید(server_host_کلید, ssh) == -1)
		واپس  SSH_ERR_SIGNATURE_INVALID;
	واپس 0;
}

#اگر defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
خالی
dump_digest(ثابت حرف *پیغام, ثابت u_char *digest, صحیح len)
{
	fprintf(stderr, "%s\n", پیغام);
	sshbuf_dump_ڈیٹا(digest, len, stderr);
}
#اگر_ختم

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ساکن خالی
send_error(ساخت ssh *ssh, حرف *پیغام)
{
	حرف *crnl = "\r\n";

	اگر (!ssh->kex->server)
		واپس;

	اگر (atomicio(vwrite, ssh_packet_get_connection_برآمد(ssh),
	    پیغام, لڑی_لمبائی(پیغام)) != لڑی_لمبائی(پیغام) ||
	    atomicio(vwrite, ssh_packet_get_connection_برآمد(ssh),
	    crnl, لڑی_لمبائی(crnl)) != لڑی_لمبائی(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
صحیح
kex_exchange_identification(ساخت ssh *ssh, صحیح timeout_ms,
    ثابت حرف *نسخہ_addendum)
{
	صحیح remote_major, remote_minor, mismatch, oerrno = 0;
	سائز_t len, n;
	صحیح r, expect_nl;
	u_char c;
	ساخت sshbuf *our_نسخہ = ssh->kex->server ?
	    ssh->kex->server_نسخہ : ssh->kex->client_نسخہ;
	ساخت sshbuf *peer_نسخہ = ssh->kex->server ?
	    ssh->kex->client_نسخہ : ssh->kex->server_نسخہ;
	حرف *our_نسخہ_string = تہی, *peer_نسخہ_string = تہی;
	حرف *cp, *remote_نسخہ = تہی;

	/* Prepare and send our banner */
	sshbuf_reset(our_نسخہ);
	اگر (نسخہ_addendum != تہی && *نسخہ_addendum == '\0')
		نسخہ_addendum = تہی;
	اگر ((r = sshbuf_putf(our_نسخہ, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_نسخہ,
	    نسخہ_addendum == تہی ? "" : " ",
	    نسخہ_addendum == تہی ? "" : نسخہ_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		جاؤ برآمد;
	}

	اگر (atomicio(vwrite, ssh_packet_get_connection_برآمد(ssh),
	    sshbuf_mutable_ptr(our_نسخہ),
	    sshbuf_len(our_نسخہ)) != sshbuf_len(our_نسخہ)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_consume_انتہا(our_نسخہ, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		جاؤ برآمد;
	}
	our_نسخہ_string = sshbuf_dup_string(our_نسخہ);
	اگر (our_نسخہ_string == تہی) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	debug("Local version string %.100s", our_نسخہ_string);

	/* Read other side's version identification. */
	برائے (n = 0; ; n++) {
		اگر (n >= SSH_MAX_PRE_BANNER_سطریں) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_سطریں);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		sshbuf_reset(peer_نسخہ);
		expect_nl = 0;
		برائے (;;) {
			اگر (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_اندر(ssh),
				    &timeout_ms, تہی);
				اگر (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					جاؤ برآمد;
				} ورنہ اگر (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					جاؤ برآمد;
				}
			}

			len = atomicio(اقرأ, ssh_packet_get_connection_اندر(ssh),
			    &c, 1);
			اگر (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				جاؤ برآمد;
			} ورنہ اگر (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				جاؤ برآمد;
			}
			اگر (c == '\r') {
				expect_nl = 1;
				جاری;
			}
			اگر (c == '\n')
				توڑو;
			اگر (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				جاؤ invalid;
			}
			اگر ((r = sshbuf_put_u8(peer_نسخہ, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				جاؤ برآمد;
			}
			اگر (sshbuf_len(peer_نسخہ) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				جاؤ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		اگر (sshbuf_len(peer_نسخہ) > 4 &&
		    memcmp(sshbuf_ptr(peer_نسخہ), "SSH-", 4) == 0)
			توڑو;
		/* If not, then just log the line and continue */
		اگر ((cp = sshbuf_dup_string(peer_نسخہ)) == تہی) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		/* Do not accept lines before the SSH ident from a client */
		اگر (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			آزاد(cp);
			جاؤ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		آزاد(cp);
	}
	peer_نسخہ_string = sshbuf_dup_string(peer_نسخہ);
	اگر (peer_نسخہ_string == تہی)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	اگر ((remote_نسخہ = صفر_حافظہ_دو(1, sshbuf_len(peer_نسخہ))) == تہی) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	اگر (لڑی_سے_پڑھو(peer_نسخہ_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_نسخہ) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_نسخہ_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_نسخہ);
	compat_banner(ssh, remote_نسخہ);

	mismatch = 0;
	انتخاب (remote_major) {
	حالت 2:
		توڑو;
	حالت 1:
		اگر (remote_minor != 99)
			mismatch = 1;
		توڑو;
	طےشدہ:
		mismatch = 1;
		توڑو;
	}
	اگر (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_نسخہ;
		جاؤ برآمد;
	}

	اگر (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    peer_نسخہ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		جاؤ برآمد;
	}
	اگر (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورٹ(ssh),
		    peer_نسخہ_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(our_نسخہ_string);
	آزاد(peer_نسخہ_string);
	ssh->remote_نسخہ = remote_نسخہ;  /* transferred */
	اگر (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	واپس r;
}

