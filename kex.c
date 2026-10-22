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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/dh.h>
#endif

#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "version.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "myproposal.h"

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "xmalloc.h"

/* prototype */
স্থির পূর্ণসংখ্যা kex_choose_conf(কাঠামো ssh *, uint32_t seq);
স্থির পূর্ণসংখ্যা kex_প্রবেশ_newkeys(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

স্থির ধ্রুবক অক্ষর * ধ্রুবক proposal_names[PROPOSAL_MAX] = {
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
শূন্য
kex_proposal_populate_entries(কাঠামো ssh *ssh, অক্ষর *prop[PROPOSAL_MAX],
    ধ্রুবক অক্ষর *kexalgos, ধ্রুবক অক্ষর *ciphers, ধ্রুবক অক্ষর *macs,
    ধ্রুবক অক্ষর *comp, ধ্রুবক অক্ষর *hkalgs)
{
	ধ্রুবক অক্ষর *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ধ্রুবক অক্ষর *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ধ্রুবক অক্ষর **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	অক্ষর *cp;

	যদি (prop == ফাঁকা)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	যদি (kexalgos == ফাঁকা)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	যদি ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ফাঁকা)
		fatal_f("kex_names_cat");

	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		নির্বাচন(i) {
		ক্ষেত্র PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			বিরতি;
		ক্ষেত্র PROPOSAL_ENC_ALGS_CTOS:
		ক্ষেত্র PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			বিরতি;
		ক্ষেত্র PROPOSAL_MAC_ALGS_CTOS:
		ক্ষেত্র PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			বিরতি;
		ক্ষেত্র PROPOSAL_COMP_ALGS_CTOS:
		ক্ষেত্র PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			বিরতি;
		ক্ষেত্র PROPOSAL_SERVER_HOST_চাবি_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			বিরতি;
		পূর্বনির্ধারিত:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	মুক্ত(cp);
}

শূন্য
kex_proposal_free_entries(অক্ষর *prop[PROPOSAL_MAX])
{
	u_int i;

	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(prop[i]);
}

/* put algorithm proposal into buffer */
পূর্ণসংখ্যা
kex_prop2buf(কাঠামো sshbuf *b, অক্ষর *proposal[PROPOSAL_MAX])
{
	u_int i;
	পূর্ণসংখ্যা r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	জন্য (i = 0; i < KEX_COOKIE_LEN; i++) {
		যদি ((r = sshbuf_put_u8(b, 0)) != 0)
			ফেরত r;
	}
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		যদি ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ফেরত r;
	}
	যদি ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ফেরত r;
	ফেরত 0;
}

/* parse buffer and return algorithm proposal */
পূর্ণসংখ্যা
kex_buf2prop(কাঠামো sshbuf *raw, পূর্ণসংখ্যা *first_kex_follows, অক্ষর ***propp)
{
	কাঠামো sshbuf *b = ফাঁকা;
	u_char v;
	u_int i;
	অক্ষর **proposal = ফাঁকা;
	পূর্ণসংখ্যা r;

	*propp = ফাঁকা;
	যদি ((proposal = calloc(PROPOSAL_MAX, আকার(অক্ষর *))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((b = sshbuf_fromb(raw)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		যাও out;
	}
	/* extract kex init proposal strings */
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		যদি ((r = sshbuf_get_cstring(b, &(proposal[i]), ফাঁকা)) != 0) {
			error_fr(r, "parse proposal %u", i);
			যাও out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	যদি ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		যাও out;
	}
	যদি (first_kex_follows != ফাঁকা)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	যদি (r != 0 && proposal != ফাঁকা)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ফেরত r;
}

শূন্য
kex_prop_free(অক্ষর **proposal)
{
	u_int i;

	যদি (proposal == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	মুক্ত(proposal);
}

পূর্ণসংখ্যা
kex_protocol_error(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	/* If in strict mode, any unexpected message is an error */
	যদি ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ফেরত r;
	ফেরত 0;
}

স্থির শূন্য
kex_reset_dispatch(কাঠামো ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_বার্তা_TRANSPORT_MIN,
	    SSH2_বার্তা_TRANSPORT_MAX, &kex_protocol_error);
}

শূন্য
kex_set_server_sig_algs(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *allowed_algs)
{
	অক্ষর *alg, *oalgs, *algs, *sigalgs;
	ধ্রুবক অক্ষর *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	যদি ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ফাঁকা)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	মুক্ত(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ফাঁকা;
	জন্য ((alg = strsep(&algs, ",")); alg != ফাঁকা && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		যদি ((sigalg = sshkey_sigalg_by_name(alg)) == ফাঁকা)
			চালু;
		যদি (!kex_has_any_alg(sigalg, sigalgs))
			চালু;
		/* Don't add an algorithm twice. */
		যদি (ssh->kex->server_sig_algs != ফাঁকা &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			চালু;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	মুক্ত(oalgs);
	মুক্ত(sigalgs);
	যদি (ssh->kex->server_sig_algs == ফাঁকা)
		ssh->kex->server_sig_algs = xstrdup("");
}

শূন্য
kex_set_warn_weak_crypto(কাঠামো ssh *ssh, পূর্ণসংখ্যা warn_weak_crypto)
{
	যদি (ssh != ফাঁকা && ssh->kex != ফাঁকা)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

শূন্য
kex_check_warn_weak_crypto(কাঠামো ssh *ssh)
{
	অক্ষর remote_id[512];
	পূর্ণসংখ্যা rekeyed = 0;

	যদি (ssh == ফাঁকা || ssh->kex == ফাঁকা || ssh->kex->name == ফাঁকা ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ফেরত;
	যদি (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ফেরত;
	}

	যদি (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	যদি (!rekeyed && !ssh->kex->server)
		ফেরত; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, আকার(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

স্থির পূর্ণসংখ্যা
kex_compose_ext_info_server(কাঠামো ssh *ssh, কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r;

	যদি (ssh->kex->server_sig_algs == ফাঁকা &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
kex_compose_ext_info_client(কাঠামো ssh *ssh, কাঠামো sshbuf *m)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		যাও out;
	}
	/* success */
	r = 0;
 out:
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
kex_maybe_send_ext_info(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;
	কাঠামো sshbuf *m = ফাঁকা;

	যদি ((ssh->kex->flags & KEX_INITIAL) == 0)
		ফেরত 0;
	যদি (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ফেরত 0;

	/* Compose EXT_INFO packet. */
	যদি ((m = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		যাও fail;
	যদি (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		যাও fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		যাও fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_server_update_ext_info(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	যদি ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		ফেরত 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ফেরত r;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_send_newkeys(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;

	kex_reset_dispatch(ssh);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ফেরত r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_বার্তা_NEWKEYS, &kex_প্রবেশ_newkeys);
	যদি ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ফেরত r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ফেরত 0;
}

/* Check whether an ext_info value contains the expected version string */
স্থির পূর্ণসংখ্যা
kex_ext_info_check_ver(কাঠামো kex *kex, ধ্রুবক অক্ষর *name,
    ধ্রুবক u_char *val, আকার_t len, ধ্রুবক অক্ষর *want_ver, u_int flag)
{
	যদি (memchr(val, '\0', len) != ফাঁকা) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	যদি (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	অন্যথা
		debug_f("unsupported version of %s extension", name);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
kex_ext_info_client_parse(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *name,
    ধ্রুবক u_char *মান, আকার_t vlen)
{
	পূর্ণসংখ্যা r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	যদি (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		যদি (memchr(মান, '\0', vlen) != ফাঁকা) {
			error_f("nul byte in %s", name);
			ফেরত SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, মান);
		মুক্ত(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ধ্রুবক অক্ষর *)মান);
	} অন্যথা যদি (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ফেরত r;
		}
	} অন্যথা যদি (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ফেরত r;
		}
	} অন্যথা যদি (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ফেরত r;
		}
	} অন্যথা
		debug_f("%s (unrecognised)", name);

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
kex_ext_info_server_parse(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *name,
    ধ্রুবক u_char *মান, আকার_t vlen)
{
	পূর্ণসংখ্যা r;

	যদি (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			ফেরত r;
		}
	} অন্যথা
		debug_f("%s (unrecognised)", name);
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_প্রবেশ_ext_info(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	ধ্রুবক পূর্ণসংখ্যা max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	অক্ষর *name;
	u_char *val;
	আকার_t vlen;
	পূর্ণসংখ্যা r;

	debug("SSH2_MSG_EXT_INFO received");
	যদি (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ফেরত dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, &kex_protocol_error);
	যদি ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ফেরত r;
	যদি (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ফেরত dispatch_protocol_error(type, seq, ssh);
	}
	জন্য (i = 0; i < ninfo; i++) {
		যদি ((r = sshpkt_get_cstring(ssh, &name, ফাঁকা)) != 0)
			ফেরত r;
		যদি ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			মুক্ত(name);
			ফেরত r;
		}
		debug3_f("extension %s", name);
		যদি (kex->server) {
			যদি ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ফেরত r;
		} অন্যথা {
			যদি ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ফেরত r;
		}
		মুক্ত(name);
		মুক্ত(val);
	}
	ফেরত sshpkt_get_end(ssh);
}

স্থির পূর্ণসংখ্যা
kex_প্রবেশ_newkeys(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	পূর্ণসংখ্যা r, initial = (kex->flags & KEX_INITIAL) != 0;
	অক্ষর *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	যদি (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, &kex_প্রবেশ_ext_info);
	ssh_dispatch_set(ssh, SSH2_বার্তা_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEXINIT, &kex_প্রবেশ_kexinit);
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		ফেরত r;
	যদি ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		ফেরত r;
	যদি (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		যদি ((r = kex_buf2prop(kex->my, ফাঁকা, &prop)) != 0)
			ফেরত r;
		যদি ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ফাঁকা) {
			error_f("match_filter_denylist failed");
			যাও fail;
		}
		মুক্ত(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		যদি ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			মুক্ত(prop);
			ফেরত SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		মুক্ত(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_send_kexinit(কাঠামো ssh *ssh)
{
	u_char *cookie;
	কাঠামো kex *kex = ssh->kex;
	পূর্ণসংখ্যা r;

	যদি (kex == ফাঁকা) {
		error_f("no kex");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	যদি (kex->flags & KEX_INIT_SENT)
		ফেরত 0;
	kex->done = 0;

	/* generate a random cookie */
	যদি (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	যদি ((cookie = sshbuf_mutable_ptr(kex->my)) == ফাঁকা) {
		error_f("buffer error");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ফেরত r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_প্রবেশ_kexinit(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	ধ্রুবক u_char *ptr;
	u_int i;
	আকার_t dlen;
	পূর্ণসংখ্যা r;

	debug("SSH2_MSG_KEXINIT received");
	যদি (kex == ফাঁকা) {
		error_f("no kex");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	মুক্ত(kex->name);
	kex->name = ফাঁকা;
	যদি ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	যদি ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ফেরত r;

	/* discard packet */
	জন্য (i = 0; i < KEX_COOKIE_LEN; i++) {
		যদি ((r = sshpkt_get_u8(ssh, ফাঁকা)) != 0) {
			error_fr(r, "discard cookie");
			ফেরত r;
		}
	}
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		যদি ((r = sshpkt_get_string(ssh, ফাঁকা, ফাঁকা)) != 0) {
			error_fr(r, "discard proposal");
			ফেরত r;
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
	যদি ((r = sshpkt_get_u8(ssh, ফাঁকা)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ফাঁকা)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			ফেরত r;

	যদি (!(kex->flags & KEX_INIT_SENT))
		যদি ((r = kex_send_kexinit(ssh)) != 0)
			ফেরত r;
	যদি ((r = kex_choose_conf(ssh, seq)) != 0)
		ফেরত r;

	যদি (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ফাঁকা)
		ফেরত (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ফেরত SSH_ERR_INTERNAL_ERROR;
}

কাঠামো kex *
kex_new(শূন্য)
{
	কাঠামো kex *kex;

	যদি ((kex = calloc(1, আকার(*kex))) == ফাঁকা ||
	    (kex->peer = sshbuf_new()) == ফাঁকা ||
	    (kex->my = sshbuf_new()) == ফাঁকা ||
	    (kex->client_version = sshbuf_new()) == ফাঁকা ||
	    (kex->server_version = sshbuf_new()) == ফাঁকা ||
	    (kex->session_id = sshbuf_new()) == ফাঁকা) {
		kex_free(kex);
		ফেরত ফাঁকা;
	}
	ফেরত kex;
}

শূন্য
kex_free_newkeys(কাঠামো newkeys *newkeys)
{
	যদি (newkeys == ফাঁকা)
		ফেরত;
	যদি (newkeys->enc.চাবি) {
		explicit_bzero(newkeys->enc.চাবি, newkeys->enc.চাবি_len);
		মুক্ত(newkeys->enc.চাবি);
		newkeys->enc.চাবি = ফাঁকা;
	}
	যদি (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		মুক্ত(newkeys->enc.iv);
		newkeys->enc.iv = ফাঁকা;
	}
	মুক্ত(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, আকার(newkeys->enc));
	মুক্ত(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, আকার(newkeys->comp));
	mac_clear(&newkeys->mac);
	যদি (newkeys->mac.চাবি) {
		explicit_bzero(newkeys->mac.চাবি, newkeys->mac.চাবি_len);
		মুক্ত(newkeys->mac.চাবি);
		newkeys->mac.চাবি = ফাঁকা;
	}
	মুক্ত(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, আকার(newkeys->mac));
	freezero(newkeys, আকার(*newkeys));
}

শূন্য
kex_free(কাঠামো kex *kex)
{
	u_int mode;

	যদি (kex == ফাঁকা)
		ফেরত;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_চাবি_free(kex->ec_client_চাবি);
#endif /* WITH_OPENSSL */
	জন্য (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = ফাঁকা;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	মুক্ত(kex->failed_choice);
	মুক্ত(kex->hostkey_alg);
	মুক্ত(kex->name);
	মুক্ত(kex->server_sig_algs);
	মুক্ত(kex);
}

পূর্ণসংখ্যা
kex_ready(কাঠামো ssh *ssh, অক্ষর *proposal[PROPOSAL_MAX])
{
	পূর্ণসংখ্যা r;

	যদি ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ফেরত r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEXINIT, &kex_প্রবেশ_kexinit);
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_setup(কাঠামো ssh *ssh, অক্ষর *proposal[PROPOSAL_MAX])
{
	পূর্ণসংখ্যা r;

	যদি ((r = kex_ready(ssh, proposal)) != 0)
		ফেরত r;
	যদি ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ফাঁকা;
		ফেরত r;
	}
	ফেরত 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
পূর্ণসংখ্যা
kex_start_rekex(কাঠামো ssh *ssh)
{
	যদি (ssh->kex == ফাঁকা) {
		error_f("no kex");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	যদি (ssh->kex->done == 0) {
		error_f("requested twice");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	ফেরত kex_send_kexinit(ssh);
}

স্থির পূর্ণসংখ্যা
choose_enc(কাঠামো sshenc *enc, অক্ষর *client, অক্ষর *server)
{
	অক্ষর *name = match_list(client, server, ফাঁকা);

	যদি (name == ফাঁকা)
		ফেরত SSH_ERR_NO_CIPHER_ALG_MATCH;
	যদি ((enc->cipher = cipher_by_name(name)) == ফাঁকা) {
		error_f("unsupported cipher %s", name);
		মুক্ত(name);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ফাঁকা;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->চাবি = ফাঁকা;
	enc->চাবি_len = cipher_keylen(enc->cipher);
	enc->block_আকার = cipher_blocksize(enc->cipher);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
choose_mac(কাঠামো ssh *ssh, কাঠামো sshmac *mac, অক্ষর *client, অক্ষর *server)
{
	অক্ষর *name = match_list(client, server, ফাঁকা);

	যদি (name == ফাঁকা)
		ফেরত SSH_ERR_NO_MAC_ALG_MATCH;
	যদি (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		মুক্ত(name);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->চাবি = ফাঁকা;
	mac->enabled = 0;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
choose_comp(কাঠামো sshcomp *comp, অক্ষর *client, অক্ষর *server)
{
	অক্ষর *name = match_list(client, server, ফাঁকা);

	যদি (name == ফাঁকা)
		ফেরত SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	যদি (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} অন্যথা
#endif	/* WITH_ZLIB */
	যদি (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} অন্যথা {
		error_f("unsupported compression scheme %s", name);
		মুক্ত(name);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
choose_kex(কাঠামো kex *k, অক্ষর *client, অক্ষর *server)
{
	k->name = match_list(client, server, ফাঁকা);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	যদি (k->name == ফাঁকা)
		ফেরত SSH_ERR_NO_KEX_ALG_MATCH;
	যদি (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
choose_hostkeyalg(কাঠামো kex *k, অক্ষর *client, অক্ষর *server)
{
	মুক্ত(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, ফাঁকা);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	যদি (k->hostkey_alg == ফাঁকা)
		ফেরত SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	যদি (k->hostkey_type == চাবি_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
proposals_match(অক্ষর *my[PROPOSAL_MAX], অক্ষর *peer[PROPOSAL_MAX])
{
	স্থির পূর্ণসংখ্যা check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_চাবি_ALGS, -1
	};
	পূর্ণসংখ্যা *idx;
	অক্ষর *p;

	জন্য (idx = &check[0]; *idx != -1; idx++) {
		যদি ((p = strchr(my[*idx], ',')) != ফাঁকা)
			*p = '\0';
		যদি ((p = strchr(peer[*idx], ',')) != ফাঁকা)
			*p = '\0';
		যদি (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ফেরত (0);
		}
	}
	debug2("proposals match");
	ফেরত (1);
}

স্থির পূর্ণসংখ্যা
kexalgs_contains(অক্ষর **peer, ধ্রুবক অক্ষর *ext)
{
	ফেরত kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

স্থির পূর্ণসংখ্যা
kex_choose_conf(কাঠামো ssh *ssh, uint32_t seq)
{
	কাঠামো kex *kex = ssh->kex;
	কাঠামো newkeys *newkeys;
	অক্ষর **my = ফাঁকা, **peer = ফাঁকা;
	অক্ষর **cprop, **sprop;
	পূর্ণসংখ্যা nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	পূর্ণসংখ্যা r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	যদি ((r = kex_buf2prop(kex->my, ফাঁকা, &my)) != 0)
		যাও out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	যদি ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		যাও out;

	যদি (kex->server) {
		cprop=peer;
		sprop=my;
	} অন্যথা {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	যদি ((kex->flags & KEX_INITIAL) != 0) {
		যদি (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} অন্যথা {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		যদি (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			যদি (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	যদি (kex->server && (kex->flags & KEX_INITIAL)) {
		যদি (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_চাবি_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		যদি (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_চাবি_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	যদি ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ফাঁকা;
		যাও out;
	}
	যদি ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_চাবি_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_চাবি_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_চাবি_ALGS];
		peer[PROPOSAL_SERVER_HOST_চাবি_ALGS] = ফাঁকা;
		যাও out;
	}
	জন্য (mode = 0; mode < MODE_MAX; mode++) {
		যদি ((newkeys = calloc(1, আকার(*newkeys))) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		যদি ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ফাঁকা;
			যাও out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		যদি (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ফাঁকা;
			যাও out;
		}
		যদি ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ফাঁকা;
			যাও out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	জন্য (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.চাবি_len);
		need = MAXIMUM(need, newkeys->enc.block_আকার);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.চাবি_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_আকার);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.চাবি_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	যদি (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
derive_চাবি(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, u_int need, u_char *hash, u_int hashlen,
    ধ্রুবক কাঠামো sshbuf *shared_secret, u_char **keyp)
{
	কাঠামো kex *kex = ssh->kex;
	কাঠামো ssh_digest_ctx *hashctx = ফাঁকা;
	অক্ষর c = id;
	u_int have;
	আকার_t mdsz;
	u_char *digest;
	পূর্ণসংখ্যা r;

	যদি ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((digest = calloc(1, ROUNDUP(need, mdsz))) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	যদি ((hashctx = ssh_digest_start(kex->hash_alg)) == ফাঁকা ||
	    ssh_digest_update_বাফার(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_বাফার(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		যাও out;
	}
	ssh_digest_free(hashctx);
	hashctx = ফাঁকা;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	জন্য (have = mdsz; need > have; have += mdsz) {
		যদি ((hashctx = ssh_digest_start(kex->hash_alg)) == ফাঁকা ||
		    ssh_digest_update_বাফার(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		ssh_digest_free(hashctx);
		hashctx = ফাঁকা;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = ফাঁকা;
	r = 0;
 out:
	মুক্ত(digest);
	ssh_digest_free(hashctx);
	ফেরত r;
}

#define NKEYS	6
পূর্ণসংখ্যা
kex_derive_চাবিগুলি(কাঠামো ssh *ssh, u_char *hash, u_int hashlen,
    ধ্রুবক কাঠামো sshbuf *shared_secret)
{
	কাঠামো kex *kex = ssh->kex;
	u_char *চাবিগুলি[NKEYS];
	u_int i, j, mode, ctos;
	পূর্ণসংখ্যা r;

	/* save initial hash as session id */
	যদি ((kex->flags & KEX_INITIAL) != 0) {
		যদি (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ফেরত SSH_ERR_INTERNAL_ERROR;
		}
		যদি ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ফেরত r;
	} অন্যথা যদি (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	জন্য (i = 0; i < NKEYS; i++) {
		যদি ((r = derive_চাবি(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &চাবিগুলি[i])) != 0) {
			জন্য (j = 0; j < i; j++)
				মুক্ত(চাবিগুলি[j]);
			ফেরত r;
		}
	}
	জন্য (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = চাবিগুলি[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.চাবি = চাবিগুলি[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.চাবি = চাবিগুলি[ctos ? 4 : 5];
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_load_hostkey(কাঠামো ssh *ssh, কাঠামো sshkey **prvp, কাঠামো sshkey **pubp)
{
	কাঠামো kex *kex = ssh->kex;

	*pubp = ফাঁকা;
	*prvp = ফাঁকা;
	যদি (kex->load_host_public_চাবি == ফাঁকা ||
	    kex->load_host_private_চাবি == ফাঁকা) {
		error_f("missing hostkey loader");
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_চাবি(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_চাবি(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	যদি (*pubp == ফাঁকা)
		ফেরত SSH_ERR_NO_HOSTKEY_LOADED;
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_verify_host_চাবি(কাঠামো ssh *ssh, কাঠামো sshkey *server_host_চাবি)
{
	কাঠামো kex *kex = ssh->kex;

	যদি (kex->verify_host_চাবি == ফাঁকা) {
		error_f("missing hostkey verifier");
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (server_host_চাবি->type != kex->hostkey_type ||
	    (kex->hostkey_type == চাবি_ECDSA &&
	    server_host_চাবি->ecdsa_nid != kex->hostkey_nid))
		ফেরত SSH_ERR_চাবি_TYPE_MISMATCH;
	যদি (kex->verify_host_চাবি(server_host_চাবি, ssh) == -1)
		ফেরত  SSH_ERR_SIGNATURE_INVALID;
	ফেরত 0;
}

#যদি defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
শূন্য
dump_digest(ধ্রুবক অক্ষর *বার্তা, ধ্রুবক u_char *digest, পূর্ণসংখ্যা len)
{
	fprintf(stderr, "%s\n", বার্তা);
	sshbuf_dump_তথ্য(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
স্থির শূন্য
send_error(কাঠামো ssh *ssh, অক্ষর *বার্তা)
{
	অক্ষর *crnl = "\r\n";

	যদি (!ssh->kex->server)
		ফেরত;

	যদি (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    বার্তা, strlen(বার্তা)) != strlen(বার্তা) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
পূর্ণসংখ্যা
kex_exchange_identification(কাঠামো ssh *ssh, পূর্ণসংখ্যা timeout_ms,
    ধ্রুবক অক্ষর *version_addendum)
{
	পূর্ণসংখ্যা remote_major, remote_minor, mismatch, oerrno = 0;
	আকার_t len, n;
	পূর্ণসংখ্যা r, expect_nl;
	u_char c;
	কাঠামো sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	কাঠামো sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	অক্ষর *our_version_string = ফাঁকা, *peer_version_string = ফাঁকা;
	অক্ষর *cp, *remote_version = ফাঁকা;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	যদি (version_addendum != ফাঁকা && *version_addendum == '\0')
		version_addendum = ফাঁকা;
	যদি ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == ফাঁকা ? "" : " ",
	    version_addendum == ফাঁকা ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		যাও out;
	}

	যদি (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		যাও out;
	}
	যদি ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		যাও out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	যদি (our_version_string == ফাঁকা) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	জন্য (n = 0; ; n++) {
		যদি (n >= SSH_MAX_PRE_BANNER_সারিগুলি) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_সারিগুলি);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		জন্য (;;) {
			যদি (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, ফাঁকা);
				যদি (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					যাও out;
				} অন্যথা যদি (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					যাও out;
				}
			}

			len = atomicio(পঠ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			যদি (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				যাও out;
			} অন্যথা যদি (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				যাও out;
			}
			যদি (c == '\r') {
				expect_nl = 1;
				চালু;
			}
			যদি (c == '\n')
				বিরতি;
			যদি (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				যাও invalid;
			}
			যদি ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				যাও out;
			}
			যদি (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				যাও invalid;
			}
		}
		/* Is this an actual protocol banner? */
		যদি (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			বিরতি;
		/* If not, then just log the line and continue */
		যদি ((cp = sshbuf_dup_string(peer_version)) == ফাঁকা) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		/* Do not accept lines before the SSH ident from a client */
		যদি (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			মুক্ত(cp);
			যাও invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		মুক্ত(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	যদি (peer_version_string == ফাঁকা)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	যদি ((remote_version = calloc(1, sshbuf_len(peer_version))) == ফাঁকা) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	যদি (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	নির্বাচন (remote_major) {
	ক্ষেত্র 2:
		বিরতি;
	ক্ষেত্র 1:
		যদি (remote_minor != 99)
			mismatch = 1;
		বিরতি;
	পূর্বনির্ধারিত:
		mismatch = 1;
		বিরতি;
	}
	যদি (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		যাও out;
	}

	যদি (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		যাও out;
	}
	যদি (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		যাও out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(our_version_string);
	মুক্ত(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	যদি (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ফেরত r;
}

