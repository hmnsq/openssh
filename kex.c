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

#اگر_تعریف_شده WITH_OPENSSL
#ضمن <openssl/crypto.h>
#ضمن <openssl/dh.h>
#پایان_اگر

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
ساكن صحيح kex_انتخاب_conf(بنية ssh *, uint32_t seq);
ساكن صحيح kex_درون_داد_newkeys(صحيح, uint32_t, بنية ssh *);

ساكن ثابت حرف * ثابت proposal_نامها[PROPOSAL_MAX] = {
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

	إذا (prop == عدم)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	إذا (kexalgos == عدم)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	إذا ((cp = kex_نامها_cat(kexalgos, ssh->kex->server ?
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
		حالة PROPOSAL_SERVER_HOST_کلید_ALGS:
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
		إذا ((r = sshbuf_put_u8(b, 0)) != 0)
			أرجع r;
	}
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		إذا ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		أرجع r;
	أرجع 0;
}

/* parse buffer and return algorithm proposal */
صحيح
kex_buf2prop(بنية sshbuf *raw, صحيح *اولی_kex_follows, حرف ***propp)
{
	بنية sshbuf *b = عدم;
	u_char v;
	u_int i;
	حرف **proposal = عدم;
	صحيح r;

	*propp = عدم;
	إذا ((proposal = حافظه_صفر_بده(PROPOSAL_MAX, حجم(حرف *))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((b = sshbuf_fromb(raw)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		اذهب بیرون;
	}
	/* extract kex init proposal strings */
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		إذا ((r = sshbuf_get_cstring(b, &(proposal[i]), عدم)) != 0) {
			error_fr(r, "parse proposal %u", i);
			اذهب بیرون;
		}
		debug2("%s: %s", proposal_نامها[i], proposal[i]);
	}
	/* first kex follows / reserved */
	إذا ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		اذهب بیرون;
	}
	إذا (اولی_kex_follows != عدم)
		*اولی_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 بیرون:
	إذا (r != 0 && proposal != عدم)
		kex_prop_free(proposal);
	sshbuf_free(b);
	أرجع r;
}

فراغ
kex_prop_free(حرف **proposal)
{
	u_int i;

	إذا (proposal == عدم)
		أرجع;
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	حرر(proposal);
}

صحيح
kex_protocol_error(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	صحيح r;

	/* If in strict mode, any unexpected message is an error */
	إذا ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن فراغ
kex_reset_dispatch(بنية ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_پیام_TRANSPORT_MIN,
	    SSH2_پیام_TRANSPORT_MAX, &kex_protocol_error);
}

فراغ
kex_مجموعه_server_sig_algs(بنية ssh *ssh, ثابت حرف *allowed_algs)
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
	إذا ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == عدم)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	حرر(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = عدم;
	لكل ((alg = strsep(&algs, ",")); alg != عدم && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		إذا ((sigalg = sshkey_sigalg_by_name(alg)) == عدم)
			استمر;
		إذا (!kex_has_any_alg(sigalg, sigalgs))
			استمر;
		/* Don't add an algorithm twice. */
		إذا (ssh->kex->server_sig_algs != عدم &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			استمر;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	حرر(oalgs);
	حرر(sigalgs);
	إذا (ssh->kex->server_sig_algs == عدم)
		ssh->kex->server_sig_algs = xstrdup("");
}

فراغ
kex_مجموعه_warn_weak_crypto(بنية ssh *ssh, صحيح warn_weak_crypto)
{
	إذا (ssh != عدم && ssh->kex != عدم)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

فراغ
kex_check_warn_weak_crypto(بنية ssh *ssh)
{
	حرف remote_id[512];
	صحيح rekeyed = 0;

	إذا (ssh == عدم || ssh->kex == عدم || ssh->kex->name == عدم ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		أرجع;
	إذا (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		أرجع;
	}

	إذا (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	إذا (!rekeyed && !ssh->kex->server)
		أرجع; /* client logs initial KEX warning separately */

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

	إذا (ssh->kex->server_sig_algs == عدم &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
kex_compose_ext_info_client(بنية ssh *ssh, بنية sshbuf *m)
{
	صحيح r;

	إذا ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		اذهب بیرون;
	}
	/* success */
	r = 0;
 بیرون:
	أرجع r;
}

ساكن صحيح
kex_maybe_send_ext_info(بنية ssh *ssh)
{
	صحيح r;
	بنية sshbuf *m = عدم;

	إذا ((ssh->kex->flags & KEX_INITIAL) == 0)
		أرجع 0;
	إذا (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		أرجع 0;

	/* Compose EXT_INFO packet. */
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		اذهب fail;
	إذا (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		اذهب fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		اذهب fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	أرجع r;
}

صحيح
kex_server_update_ext_info(بنية ssh *ssh)
{
	صحيح r;

	إذا ((ssh->kex->flags & KEX_HAS_EXT_INFO_درون_AUTH) == 0)
		أرجع 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		أرجع r;
	}
	أرجع 0;
}

صحيح
kex_send_newkeys(بنية ssh *ssh)
{
	صحيح r;

	kex_reset_dispatch(ssh);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_NEWKEYS, &kex_درون_داد_newkeys);
	إذا ((r = kex_maybe_send_ext_info(ssh)) != 0)
		أرجع r;
	debug("expecting SSH2_MSG_NEWKEYS");
	أرجع 0;
}

/* Check whether an ext_info value contains the expected version string */
ساكن صحيح
kex_ext_info_check_ver(بنية kex *kex, ثابت حرف *name,
    ثابت u_char *val, اندازه_t len, ثابت حرف *want_ver, u_int flag)
{
	إذا (memchr(val, '\0', len) != عدم) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	إذا (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	وإلا
		debug_f("unsupported version of %s extension", name);
	أرجع 0;
}

ساكن صحيح
kex_ext_info_client_parse(بنية ssh *ssh, ثابت حرف *name,
    ثابت u_char *مقدار, اندازه_t vlen)
{
	صحيح r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	إذا (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		إذا (memchr(مقدار, '\0', vlen) != عدم) {
			error_f("nul byte in %s", name);
			أرجع SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, مقدار);
		حرر(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ثابت حرف *)مقدار);
	} وإلا إذا (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		إذا ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			أرجع r;
		}
	} وإلا إذا (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		إذا ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			أرجع r;
		}
	} وإلا إذا (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		إذا ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			أرجع r;
		}
	} وإلا
		debug_f("%s (unrecognised)", name);

	أرجع 0;
}

ساكن صحيح
kex_ext_info_server_parse(بنية ssh *ssh, ثابت حرف *name,
    ثابت u_char *مقدار, اندازه_t vlen)
{
	صحيح r;

	إذا (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		إذا ((r = kex_ext_info_check_ver(ssh->kex, name, مقدار, vlen,
		    "0", KEX_HAS_EXT_INFO_درون_AUTH)) != 0) {
			أرجع r;
		}
	} وإلا
		debug_f("%s (unrecognised)", name);
	أرجع 0;
}

صحيح
kex_درون_داد_ext_info(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	ثابت صحيح max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	حرف *name;
	u_char *val;
	اندازه_t vlen;
	صحيح r;

	debug("SSH2_MSG_EXT_INFO received");
	إذا (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		أرجع dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_EXT_INFO, &kex_protocol_error);
	إذا ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		أرجع r;
	إذا (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		أرجع dispatch_protocol_error(type, seq, ssh);
	}
	لكل (i = 0; i < ninfo; i++) {
		إذا ((r = sshpkt_get_cstring(ssh, &name, عدم)) != 0)
			أرجع r;
		إذا ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			حرر(name);
			أرجع r;
		}
		debug3_f("extension %s", name);
		إذا (kex->server) {
			إذا ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				أرجع r;
		} وإلا {
			إذا ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				أرجع r;
		}
		حرر(name);
		حرر(val);
	}
	أرجع sshpkt_get_انتها(ssh);
}

ساكن صحيح
kex_درون_داد_newkeys(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r, initial = (kex->flags & KEX_INITIAL) != 0;
	حرف *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	إذا (kex->ext_info_c && initial)
		ssh_dispatch_مجموعه(ssh, SSH2_پیام_EXT_INFO, &kex_درون_داد_ext_info);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEXINIT, &kex_درون_داد_kexinit);
	إذا ((r = sshpkt_get_انتها(ssh)) != 0)
		أرجع r;
	إذا ((r = ssh_مجموعه_newkeys(ssh, نما_درون)) != 0)
		أرجع r;
	إذا (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		إذا ((r = kex_buf2prop(kex->my, عدم, &prop)) != 0)
			أرجع r;
		إذا ((cp = تطابق_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == عدم) {
			error_f("match_filter_denylist failed");
			اذهب fail;
		}
		حرر(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		إذا ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			حرر(prop);
			أرجع SSH_ERR_داخلی_ERROR;
		}
		kex_proposal_free_entries(prop);
		حرر(prop);
	}
	kex->انجامشده = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_فرستاده|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	أرجع 0;
}

صحيح
kex_send_kexinit(بنية ssh *ssh)
{
	u_char *cookie;
	بنية kex *kex = ssh->kex;
	صحيح r;

	إذا (kex == عدم) {
		error_f("no kex");
		أرجع SSH_ERR_داخلی_ERROR;
	}
	إذا (kex->flags & KEX_INIT_فرستاده)
		أرجع 0;
	kex->انجامشده = 0;

	/* generate a random cookie */
	إذا (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	إذا ((cookie = sshbuf_mutable_ptr(kex->my)) == عدم) {
		error_f("buffer error");
		أرجع SSH_ERR_داخلی_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		أرجع r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_فرستاده;
	أرجع 0;
}

صحيح
kex_درون_داد_kexinit(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	ثابت u_char *ptr;
	u_int i;
	اندازه_t dlen;
	صحيح r;

	debug("SSH2_MSG_KEXINIT received");
	إذا (kex == عدم) {
		error_f("no kex");
		أرجع SSH_ERR_داخلی_ERROR;
	}
	حرر(kex->name);
	kex->name = عدم;
	إذا ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	إذا ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		أرجع r;

	/* discard packet */
	لكل (i = 0; i < KEX_COOKIE_LEN; i++) {
		إذا ((r = sshpkt_get_u8(ssh, عدم)) != 0) {
			error_fr(r, "discard cookie");
			أرجع r;
		}
	}
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		إذا ((r = sshpkt_get_string(ssh, عدم, عدم)) != 0) {
			error_fr(r, "discard proposal");
			أرجع r;
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
	إذا ((r = sshpkt_get_u8(ssh, عدم)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, عدم)) != 0 ||	/* reserved */
	    (r = sshpkt_get_انتها(ssh)) != 0)
			أرجع r;

	إذا (!(kex->flags & KEX_INIT_فرستاده))
		إذا ((r = kex_send_kexinit(ssh)) != 0)
			أرجع r;
	إذا ((r = kex_انتخاب_conf(ssh, seq)) != 0)
		أرجع r;

	إذا (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != عدم)
		أرجع (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	أرجع SSH_ERR_داخلی_ERROR;
}

بنية kex *
kex_new(فراغ)
{
	بنية kex *kex;

	إذا ((kex = حافظه_صفر_بده(1, حجم(*kex))) == عدم ||
	    (kex->peer = sshbuf_new()) == عدم ||
	    (kex->my = sshbuf_new()) == عدم ||
	    (kex->client_نسخه = sshbuf_new()) == عدم ||
	    (kex->server_نسخه = sshbuf_new()) == عدم ||
	    (kex->session_id = sshbuf_new()) == عدم) {
		kex_free(kex);
		أرجع عدم;
	}
	أرجع kex;
}

فراغ
kex_free_newkeys(بنية newkeys *newkeys)
{
	إذا (newkeys == عدم)
		أرجع;
	إذا (newkeys->enc.کلید) {
		explicit_bzero(newkeys->enc.کلید, newkeys->enc.کلید_len);
		حرر(newkeys->enc.کلید);
		newkeys->enc.کلید = عدم;
	}
	إذا (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		حرر(newkeys->enc.iv);
		newkeys->enc.iv = عدم;
	}
	حرر(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, حجم(newkeys->enc));
	حرر(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, حجم(newkeys->comp));
	mac_clear(&newkeys->mac);
	إذا (newkeys->mac.کلید) {
		explicit_bzero(newkeys->mac.کلید, newkeys->mac.کلید_len);
		حرر(newkeys->mac.کلید);
		newkeys->mac.کلید = عدم;
	}
	حرر(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, حجم(newkeys->mac));
	freezero(newkeys, حجم(*newkeys));
}

فراغ
kex_free(بنية kex *kex)
{
	u_int نما;

	إذا (kex == عدم)
		أرجع;

#اگر_تعریف_شده WITH_OPENSSL
	DH_free(kex->dh);
	EC_کلید_free(kex->ec_client_کلید);
#پایان_اگر /* WITH_OPENSSL */
	لكل (نما = 0; نما < نما_MAX; نما++) {
		kex_free_newkeys(kex->newkeys[نما]);
		kex->newkeys[نما] = عدم;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_نسخه);
	sshbuf_free(kex->server_نسخه);
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

	إذا ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		أرجع r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEXINIT, &kex_درون_داد_kexinit);
	أرجع 0;
}

صحيح
kex_راهاندازی(بنية ssh *ssh, حرف *proposal[PROPOSAL_MAX])
{
	صحيح r;

	إذا ((r = kex_ready(ssh, proposal)) != 0)
		أرجع r;
	إذا ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = عدم;
		أرجع r;
	}
	أرجع 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
صحيح
kex_شروع_rekex(بنية ssh *ssh)
{
	إذا (ssh->kex == عدم) {
		error_f("no kex");
		أرجع SSH_ERR_داخلی_ERROR;
	}
	إذا (ssh->kex->انجامشده == 0) {
		error_f("requested twice");
		أرجع SSH_ERR_داخلی_ERROR;
	}
	ssh->kex->انجامشده = 0;
	أرجع kex_send_kexinit(ssh);
}

ساكن صحيح
انتخاب_enc(بنية sshenc *enc, حرف *client, حرف *server)
{
	حرف *name = تطابق_list(client, server, عدم);

	إذا (name == عدم)
		أرجع SSH_ERR_NO_CIPHER_ALG_تطابق;
	إذا ((enc->cipher = cipher_by_name(name)) == عدم) {
		error_f("unsupported cipher %s", name);
		حرر(name);
		أرجع SSH_ERR_داخلی_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = عدم;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->کلید = عدم;
	enc->کلید_len = cipher_keylen(enc->cipher);
	enc->بلوک_اندازه = cipher_blocksize(enc->cipher);
	أرجع 0;
}

ساكن صحيح
انتخاب_mac(بنية ssh *ssh, بنية sshmac *mac, حرف *client, حرف *server)
{
	حرف *name = تطابق_list(client, server, عدم);

	إذا (name == عدم)
		أرجع SSH_ERR_NO_MAC_ALG_تطابق;
	إذا (mac_راهاندازی(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		حرر(name);
		أرجع SSH_ERR_داخلی_ERROR;
	}
	mac->name = name;
	mac->کلید = عدم;
	mac->enabled = 0;
	أرجع 0;
}

ساكن صحيح
انتخاب_comp(بنية sshcomp *comp, حرف *client, حرف *server)
{
	حرف *name = تطابق_list(client, server, عدم);

	إذا (name == عدم)
		أرجع SSH_ERR_NO_COMPRESS_ALG_تطابق;
#اگر_تعریف_شده WITH_ZLIB
	إذا (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} وإلا
#پایان_اگر	/* WITH_ZLIB */
	إذا (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} وإلا {
		error_f("unsupported compression scheme %s", name);
		حرر(name);
		أرجع SSH_ERR_داخلی_ERROR;
	}
	comp->name = name;
	أرجع 0;
}

ساكن صحيح
انتخاب_kex(بنية kex *k, حرف *client, حرف *server)
{
	k->name = تطابق_list(client, server, عدم);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	إذا (k->name == عدم)
		أرجع SSH_ERR_NO_KEX_ALG_تطابق;
	إذا (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		أرجع SSH_ERR_داخلی_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	أرجع 0;
}

ساكن صحيح
انتخاب_hostkeyalg(بنية kex *k, حرف *client, حرف *server)
{
	حرر(k->hostkey_alg);
	k->hostkey_alg = تطابق_list(client, server, عدم);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	إذا (k->hostkey_alg == عدم)
		أرجع SSH_ERR_NO_HOSTKEY_ALG_تطابق;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	إذا (k->hostkey_type == کلید_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		أرجع SSH_ERR_داخلی_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	أرجع 0;
}

ساكن صحيح
proposals_تطابق(حرف *my[PROPOSAL_MAX], حرف *peer[PROPOSAL_MAX])
{
	ساكن صحيح check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_کلید_ALGS, -1
	};
	صحيح *idx;
	حرف *p;

	لكل (idx = &check[0]; *idx != -1; idx++) {
		إذا ((p = strchr(my[*idx], ',')) != عدم)
			*p = '\0';
		إذا ((p = strchr(peer[*idx], ',')) != عدم)
			*p = '\0';
		إذا (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			أرجع (0);
		}
	}
	debug2("proposals match");
	أرجع (1);
}

ساكن صحيح
kexalgs_شامل_است(حرف **peer, ثابت حرف *ext)
{
	أرجع kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

ساكن صحيح
kex_انتخاب_conf(بنية ssh *ssh, uint32_t seq)
{
	بنية kex *kex = ssh->kex;
	بنية newkeys *newkeys;
	حرف **my = عدم, **peer = عدم;
	حرف **cprop, **sprop;
	صحيح nenc, nmac, ncomp;
	u_int نما, ctos, need, dh_need, authlen;
	صحيح r, اولی_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	إذا ((r = kex_buf2prop(kex->my, عدم, &my)) != 0)
		اذهب بیرون;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	إذا ((r = kex_buf2prop(kex->peer, &اولی_kex_follows, &peer)) != 0)
		اذهب بیرون;

	إذا (kex->server) {
		cprop=peer;
		sprop=my;
	} وإلا {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	إذا ((kex->flags & KEX_INITIAL) != 0) {
		إذا (kex->server) {
			kex->ext_info_c = kexalgs_شامل_است(peer, "ext-info-c");
			kex->kex_strict = kexalgs_شامل_است(peer,
			    "kex-strict-c-v00@openssh.com");
		} وإلا {
			kex->ext_info_s = kexalgs_شامل_است(peer, "ext-info-s");
			kex->kex_strict = kexalgs_شامل_است(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		إذا (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			إذا (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	إذا (kex->server && (kex->flags & KEX_INITIAL)) {
		إذا (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_کلید_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		إذا (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_کلید_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	إذا ((r = انتخاب_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = عدم;
		اذهب بیرون;
	}
	إذا ((r = انتخاب_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_کلید_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_کلید_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_کلید_ALGS];
		peer[PROPOSAL_SERVER_HOST_کلید_ALGS] = عدم;
		اذهب بیرون;
	}
	لكل (نما = 0; نما < نما_MAX; نما++) {
		إذا ((newkeys = حافظه_صفر_بده(1, حجم(*newkeys))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		kex->newkeys[نما] = newkeys;
		ctos = (!kex->server && نما == نما_بیرون) ||
		    (kex->server && نما == نما_درون);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		إذا ((r = انتخاب_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = عدم;
			اذهب بیرون;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		إذا (authlen == 0 &&
		    (r = انتخاب_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = عدم;
			اذهب بیرون;
		}
		إذا ((r = انتخاب_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = عدم;
			اذهب بیرون;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	لكل (نما = 0; نما < نما_MAX; نما++) {
		newkeys = kex->newkeys[نما];
		need = بیشینه(need, newkeys->enc.کلید_len);
		need = بیشینه(need, newkeys->enc.بلوک_اندازه);
		need = بیشینه(need, newkeys->enc.iv_len);
		need = بیشینه(need, newkeys->mac.کلید_len);
		dh_need = بیشینه(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = بیشینه(dh_need, newkeys->enc.بلوک_اندازه);
		dh_need = بیشینه(dh_need, newkeys->enc.iv_len);
		dh_need = بیشینه(dh_need, newkeys->mac.کلید_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	إذا (اولی_kex_follows && !proposals_تطابق(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 بیرون:
	kex_prop_free(my);
	kex_prop_free(peer);
	أرجع r;
}

ساكن صحيح
derive_کلید(بنية ssh *ssh, صحيح id, u_int need, u_char *hash, u_int hashlen,
    ثابت بنية sshbuf *shared_secret, u_char **keyp)
{
	بنية kex *kex = ssh->kex;
	بنية ssh_digest_ctx *hashctx = عدم;
	حرف c = id;
	u_int have;
	اندازه_t mdsz;
	u_char *digest;
	صحيح r;

	إذا ((mdsz = ssh_digest_بایتها(kex->hash_alg)) == 0)
		أرجع SSH_ERR_INVALID_آرگومان;
	إذا ((digest = حافظه_صفر_بده(1, ROUNDUP(need, mdsz))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	إذا ((hashctx = ssh_digest_شروع(kex->hash_alg)) == عدم ||
	    ssh_digest_update_میانگیر(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_میانگیر(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		اذهب بیرون;
	}
	ssh_digest_free(hashctx);
	hashctx = عدم;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	لكل (have = mdsz; need > have; have += mdsz) {
		إذا ((hashctx = ssh_digest_شروع(kex->hash_alg)) == عدم ||
		    ssh_digest_update_میانگیر(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بیرون;
		}
		ssh_digest_free(hashctx);
		hashctx = عدم;
	}
#اگر_تعریف_شده DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#پایان_اگر
	*keyp = digest;
	digest = عدم;
	r = 0;
 بیرون:
	حرر(digest);
	ssh_digest_free(hashctx);
	أرجع r;
}

#تعریف_کن NKEYS	6
صحيح
kex_derive_کلیدها(بنية ssh *ssh, u_char *hash, u_int hashlen,
    ثابت بنية sshbuf *shared_secret)
{
	بنية kex *kex = ssh->kex;
	u_char *کلیدها[NKEYS];
	u_int i, j, نما, ctos;
	صحيح r;

	/* save initial hash as session id */
	إذا ((kex->flags & KEX_INITIAL) != 0) {
		إذا (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			أرجع SSH_ERR_داخلی_ERROR;
		}
		إذا ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			أرجع r;
	} وإلا إذا (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		أرجع SSH_ERR_داخلی_ERROR;
	}
	لكل (i = 0; i < NKEYS; i++) {
		إذا ((r = derive_کلید(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &کلیدها[i])) != 0) {
			لكل (j = 0; j < i; j++)
				حرر(کلیدها[j]);
			أرجع r;
		}
	}
	لكل (نما = 0; نما < نما_MAX; نما++) {
		ctos = (!kex->server && نما == نما_بیرون) ||
		    (kex->server && نما == نما_درون);
		kex->newkeys[نما]->enc.iv  = کلیدها[ctos ? 0 : 1];
		kex->newkeys[نما]->enc.کلید = کلیدها[ctos ? 2 : 3];
		kex->newkeys[نما]->mac.کلید = کلیدها[ctos ? 4 : 5];
	}
	أرجع 0;
}

صحيح
kex_بارگیری_hostkey(بنية ssh *ssh, بنية sshkey **prvp, بنية sshkey **pubp)
{
	بنية kex *kex = ssh->kex;

	*pubp = عدم;
	*prvp = عدم;
	إذا (kex->بارگیری_host_عمومی_کلید == عدم ||
	    kex->بارگیری_host_خصوصی_کلید == عدم) {
		error_f("missing hostkey loader");
		أرجع SSH_ERR_INVALID_آرگومان;
	}
	*pubp = kex->بارگیری_host_عمومی_کلید(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->بارگیری_host_خصوصی_کلید(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	إذا (*pubp == عدم)
		أرجع SSH_ERR_NO_HOSTKEY_LOADED;
	أرجع 0;
}

صحيح
kex_verify_host_کلید(بنية ssh *ssh, بنية sshkey *server_host_کلید)
{
	بنية kex *kex = ssh->kex;

	إذا (kex->verify_host_کلید == عدم) {
		error_f("missing hostkey verifier");
		أرجع SSH_ERR_INVALID_آرگومان;
	}
	إذا (server_host_کلید->type != kex->hostkey_type ||
	    (kex->hostkey_type == کلید_ECDSA &&
	    server_host_کلید->ecdsa_nid != kex->hostkey_nid))
		أرجع SSH_ERR_کلید_TYPE_MISMATCH;
	إذا (kex->verify_host_کلید(server_host_کلید, ssh) == -1)
		أرجع  SSH_ERR_SIGNATURE_INVALID;
	أرجع 0;
}

#إذا defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
فراغ
dump_digest(ثابت حرف *پیام, ثابت u_char *digest, صحيح len)
{
	fprintf(stderr, "%s\n", پیام);
	sshbuf_dump_داده(digest, len, stderr);
}
#پایان_اگر

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
ساكن فراغ
send_error(بنية ssh *ssh, حرف *پیام)
{
	حرف *crnl = "\r\n";

	إذا (!ssh->kex->server)
		أرجع;

	إذا (atomicio(vwrite, ssh_packet_get_connection_بیرون(ssh),
	    پیام, طول_رشته(پیام)) != طول_رشته(پیام) ||
	    atomicio(vwrite, ssh_packet_get_connection_بیرون(ssh),
	    crnl, طول_رشته(crnl)) != طول_رشته(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
صحيح
kex_exchange_identification(بنية ssh *ssh, صحيح timeout_ms,
    ثابت حرف *نسخه_addendum)
{
	صحيح remote_major, remote_minor, mismatch, oerrno = 0;
	اندازه_t len, n;
	صحيح r, expect_nl;
	u_char c;
	بنية sshbuf *our_نسخه = ssh->kex->server ?
	    ssh->kex->server_نسخه : ssh->kex->client_نسخه;
	بنية sshbuf *peer_نسخه = ssh->kex->server ?
	    ssh->kex->client_نسخه : ssh->kex->server_نسخه;
	حرف *our_نسخه_string = عدم, *peer_نسخه_string = عدم;
	حرف *cp, *remote_نسخه = عدم;

	/* Prepare and send our banner */
	sshbuf_reset(our_نسخه);
	إذا (نسخه_addendum != عدم && *نسخه_addendum == '\0')
		نسخه_addendum = عدم;
	إذا ((r = sshbuf_putf(our_نسخه, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_نسخه,
	    نسخه_addendum == عدم ? "" : " ",
	    نسخه_addendum == عدم ? "" : نسخه_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		اذهب بیرون;
	}

	إذا (atomicio(vwrite, ssh_packet_get_connection_بیرون(ssh),
	    sshbuf_mutable_ptr(our_نسخه),
	    sshbuf_len(our_نسخه)) != sshbuf_len(our_نسخه)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_consume_انتها(our_نسخه, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		اذهب بیرون;
	}
	our_نسخه_string = sshbuf_dup_string(our_نسخه);
	إذا (our_نسخه_string == عدم) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	debug("Local version string %.100s", our_نسخه_string);

	/* Read other side's version identification. */
	لكل (n = 0; ; n++) {
		إذا (n >= SSH_MAX_PRE_BANNER_سطرها) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_سطرها);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
		sshbuf_reset(peer_نسخه);
		expect_nl = 0;
		لكل (;;) {
			إذا (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_درون(ssh),
				    &timeout_ms, عدم);
				إذا (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					اذهب بیرون;
				} وإلا إذا (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					اذهب بیرون;
				}
			}

			len = atomicio(اقرأ, ssh_packet_get_connection_درون(ssh),
			    &c, 1);
			إذا (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				اذهب بیرون;
			} وإلا إذا (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				اذهب بیرون;
			}
			إذا (c == '\r') {
				expect_nl = 1;
				استمر;
			}
			إذا (c == '\n')
				اكسر;
			إذا (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				اذهب invalid;
			}
			إذا ((r = sshbuf_put_u8(peer_نسخه, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				اذهب بیرون;
			}
			إذا (sshbuf_len(peer_نسخه) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				اذهب invalid;
			}
		}
		/* Is this an actual protocol banner? */
		إذا (sshbuf_len(peer_نسخه) > 4 &&
		    memcmp(sshbuf_ptr(peer_نسخه), "SSH-", 4) == 0)
			اكسر;
		/* If not, then just log the line and continue */
		إذا ((cp = sshbuf_dup_string(peer_نسخه)) == عدم) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		/* Do not accept lines before the SSH ident from a client */
		إذا (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			حرر(cp);
			اذهب invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		حرر(cp);
	}
	peer_نسخه_string = sshbuf_dup_string(peer_نسخه);
	إذا (peer_نسخه_string == عدم)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	إذا ((remote_نسخه = حافظه_صفر_بده(1, sshbuf_len(peer_نسخه))) == عدم) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	إذا (از_رشته_بخوان(peer_نسخه_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_نسخه) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_نسخه_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_نسخه);
	compat_banner(ssh, remote_نسخه);

	mismatch = 0;
	بدل (remote_major) {
	حالة 2:
		اكسر;
	حالة 1:
		إذا (remote_minor != 99)
			mismatch = 1;
		اكسر;
	افتراضي:
		mismatch = 1;
		اكسر;
	}
	إذا (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_نسخه;
		اذهب بیرون;
	}

	إذا (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh),
		    peer_نسخه_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		اذهب بیرون;
	}
	إذا (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_پورت(ssh),
		    peer_نسخه_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		اذهب بیرون;
	}
	/* success */
	r = 0;
 بیرون:
	حرر(our_نسخه_string);
	حرر(peer_نسخه_string);
	ssh->remote_نسخه = remote_نسخه;  /* transferred */
	إذا (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	أرجع r;
}

