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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/crypto.h>
#অন্তর্ভাৱ <openssl/dh.h>
#endif

#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "atomicio.h"
#অন্তর্ভাৱ "version.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "compat.h"
#অন্তর্ভাৱ "cipher.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "mac.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "myproposal.h"

#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "xmalloc.h"

/* prototype */
স্থির পূর্ণাঙ্ক kex_choose_conf(সংরচনা ssh *, uint32_t seq);
স্থির পূর্ণাঙ্ক kex_প্ৰবেশ_newkeys(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);

স্থির ধ্রুৱ ৱর্ণ * ধ্রুৱ proposal_names[PROPOSAL_MAX] = {
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
kex_proposal_populate_entries(সংরচনা ssh *ssh, ৱর্ণ *prop[PROPOSAL_MAX],
    ধ্রুৱ ৱর্ণ *kexalgos, ধ্রুৱ ৱর্ণ *ciphers, ধ্রুৱ ৱর্ণ *macs,
    ধ্রুৱ ৱর্ণ *comp, ধ্রুৱ ৱর্ণ *hkalgs)
{
	ধ্রুৱ ৱর্ণ *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ধ্রুৱ ৱর্ণ *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ধ্রুৱ ৱর্ণ **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	ৱর্ণ *cp;

	যদি (prop == রিক্ত)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	যদি (kexalgos == রিক্ত)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	যদি ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == রিক্ত)
		fatal_f("kex_names_cat");

	বাবে (i = 0; i < PROPOSAL_MAX; i++) {
		ৱিকল্প(i) {
		পক্ষ PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			ভঙ্গ;
		পক্ষ PROPOSAL_ENC_ALGS_CTOS:
		পক্ষ PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			ভঙ্গ;
		পক্ষ PROPOSAL_MAC_ALGS_CTOS:
		পক্ষ PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			ভঙ্গ;
		পক্ষ PROPOSAL_COMP_ALGS_CTOS:
		পক্ষ PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			ভঙ্গ;
		পক্ষ PROPOSAL_SERVER_HOST_চাবি_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			ভঙ্গ;
		স্ৱভাৱ:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	মুক্ত(cp);
}

শূন্য
kex_proposal_free_entries(ৱর্ণ *prop[PROPOSAL_MAX])
{
	u_int i;

	বাবে (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(prop[i]);
}

/* put algorithm proposal into buffer */
পূর্ণাঙ্ক
kex_prop2buf(সংরচনা sshbuf *b, ৱর্ণ *proposal[PROPOSAL_MAX])
{
	u_int i;
	পূর্ণাঙ্ক r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	বাবে (i = 0; i < KEX_COOKIE_LEN; i++) {
		যদি ((r = sshbuf_put_u8(b, 0)) != 0)
			ঘূৰাই r;
	}
	বাবে (i = 0; i < PROPOSAL_MAX; i++) {
		যদি ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			ঘূৰাই r;
	}
	যদি ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		ঘূৰাই r;
	ঘূৰাই 0;
}

/* parse buffer and return algorithm proposal */
পূর্ণাঙ্ক
kex_buf2prop(সংরচনা sshbuf *raw, পূর্ণাঙ্ক *first_kex_follows, ৱর্ণ ***propp)
{
	সংরচনা sshbuf *b = রিক্ত;
	u_char v;
	u_int i;
	ৱর্ণ **proposal = রিক্ত;
	পূর্ণাঙ্ক r;

	*propp = রিক্ত;
	যদি ((proposal = calloc(PROPOSAL_MAX, পরিমাণ(ৱর্ণ *))) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((b = sshbuf_fromb(raw)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		গচ্ছ out;
	}
	/* extract kex init proposal strings */
	বাবে (i = 0; i < PROPOSAL_MAX; i++) {
		যদি ((r = sshbuf_get_cstring(b, &(proposal[i]), রিক্ত)) != 0) {
			error_fr(r, "parse proposal %u", i);
			গচ্ছ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	যদি ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		গচ্ছ out;
	}
	যদি (first_kex_follows != রিক্ত)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	যদি (r != 0 && proposal != রিক্ত)
		kex_prop_free(proposal);
	sshbuf_free(b);
	ঘূৰাই r;
}

শূন্য
kex_prop_free(ৱর্ণ **proposal)
{
	u_int i;

	যদি (proposal == রিক্ত)
		ঘূৰাই;
	বাবে (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	মুক্ত(proposal);
}

পূর্ণাঙ্ক
kex_protocol_error(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	/* If in strict mode, any unexpected message is an error */
	যদি ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ঘূৰাই r;
	ঘূৰাই 0;
}

স্থির শূন্য
kex_reset_dispatch(সংরচনা ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_বাৰ্তা_TRANSPORT_MIN,
	    SSH2_বাৰ্তা_TRANSPORT_MAX, &kex_protocol_error);
}

শূন্য
kex_set_server_sig_algs(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *allowed_algs)
{
	ৱর্ণ *alg, *oalgs, *algs, *sigalgs;
	ধ্রুৱ ৱর্ণ *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	যদি ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == রিক্ত)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	মুক্ত(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = রিক্ত;
	বাবে ((alg = strsep(&algs, ",")); alg != রিক্ত && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		যদি ((sigalg = sshkey_sigalg_by_name(alg)) == রিক্ত)
			অনুৱর্ত;
		যদি (!kex_has_any_alg(sigalg, sigalgs))
			অনুৱর্ত;
		/* Don't add an algorithm twice. */
		যদি (ssh->kex->server_sig_algs != রিক্ত &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			অনুৱর্ত;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	মুক্ত(oalgs);
	মুক্ত(sigalgs);
	যদি (ssh->kex->server_sig_algs == রিক্ত)
		ssh->kex->server_sig_algs = xstrdup("");
}

শূন্য
kex_set_warn_weak_crypto(সংরচনা ssh *ssh, পূর্ণাঙ্ক warn_weak_crypto)
{
	যদি (ssh != রিক্ত && ssh->kex != রিক্ত)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

শূন্য
kex_check_warn_weak_crypto(সংরচনা ssh *ssh)
{
	ৱর্ণ remote_id[512];
	পূর্ণাঙ্ক rekeyed = 0;

	যদি (ssh == রিক্ত || ssh->kex == রিক্ত || ssh->kex->name == রিক্ত ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		ঘূৰাই;
	যদি (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		ঘূৰাই;
	}

	যদি (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	যদি (!rekeyed && !ssh->kex->server)
		ঘূৰাই; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, পরিমাণ(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

স্থির পূর্ণাঙ্ক
kex_compose_ext_info_server(সংরচনা ssh *ssh, সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;

	যদি (ssh->kex->server_sig_algs == রিক্ত &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
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
		ঘূৰাই r;
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
kex_compose_ext_info_client(সংরচনা ssh *ssh, সংরচনা sshbuf *m)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
kex_maybe_send_ext_info(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *m = রিক্ত;

	যদি ((ssh->kex->flags & KEX_INITIAL) == 0)
		ঘূৰাই 0;
	যদি (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		ঘূৰাই 0;

	/* Compose EXT_INFO packet. */
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		গচ্ছ fail;
	যদি (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		গচ্ছ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		গচ্ছ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	ঘূৰাই r;
}

পূর্ণাঙ্ক
kex_server_update_ext_info(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	যদি ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		ঘূৰাই 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		ঘূৰাই r;
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_send_newkeys(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;

	kex_reset_dispatch(ssh);
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ঘূৰাই r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_NEWKEYS, &kex_প্ৰবেশ_newkeys);
	যদি ((r = kex_maybe_send_ext_info(ssh)) != 0)
		ঘূৰাই r;
	debug("expecting SSH2_MSG_NEWKEYS");
	ঘূৰাই 0;
}

/* Check whether an ext_info value contains the expected version string */
স্থির পূর্ণাঙ্ক
kex_ext_info_check_ver(সংরচনা kex *kex, ধ্রুৱ ৱর্ণ *name,
    ধ্রুৱ u_char *val, size_t len, ধ্রুৱ ৱর্ণ *want_ver, u_int flag)
{
	যদি (memchr(val, '\0', len) != রিক্ত) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	যদি (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	অন্যথা
		debug_f("unsupported version of %s extension", name);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
kex_ext_info_client_parse(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *name,
    ধ্রুৱ u_char *মান, size_t vlen)
{
	পূর্ণাঙ্ক r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	যদি (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		যদি (memchr(মান, '\0', vlen) != রিক্ত) {
			error_f("nul byte in %s", name);
			ঘূৰাই SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, মান);
		মুক্ত(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ধ্রুৱ ৱর্ণ *)মান);
	} অন্যথা যদি (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			ঘূৰাই r;
		}
	} অন্যথা যদি (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			ঘূৰাই r;
		}
	} অন্যথা যদি (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			ঘূৰাই r;
		}
	} অন্যথা
		debug_f("%s (unrecognised)", name);

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
kex_ext_info_server_parse(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *name,
    ধ্রুৱ u_char *মান, size_t vlen)
{
	পূর্ণাঙ্ক r;

	যদি (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		যদি ((r = kex_ext_info_check_ver(ssh->kex, name, মান, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			ঘূৰাই r;
		}
	} অন্যথা
		debug_f("%s (unrecognised)", name);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_প্ৰবেশ_ext_info(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	ধ্রুৱ পূর্ণাঙ্ক max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	ৱর্ণ *name;
	u_char *val;
	size_t vlen;
	পূর্ণাঙ্ক r;

	debug("SSH2_MSG_EXT_INFO received");
	যদি (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		ঘূৰাই dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_EXT_INFO, &kex_protocol_error);
	যদি ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		ঘূৰাই r;
	যদি (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		ঘূৰাই dispatch_protocol_error(type, seq, ssh);
	}
	বাবে (i = 0; i < ninfo; i++) {
		যদি ((r = sshpkt_get_cstring(ssh, &name, রিক্ত)) != 0)
			ঘূৰাই r;
		যদি ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			মুক্ত(name);
			ঘূৰাই r;
		}
		debug3_f("extension %s", name);
		যদি (kex->server) {
			যদি ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				ঘূৰাই r;
		} অন্যথা {
			যদি ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				ঘূৰাই r;
		}
		মুক্ত(name);
		মুক্ত(val);
	}
	ঘূৰাই sshpkt_get_end(ssh);
}

স্থির পূর্ণাঙ্ক
kex_প্ৰবেশ_newkeys(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	পূর্ণাঙ্ক r, initial = (kex->flags & KEX_INITIAL) != 0;
	ৱর্ণ *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	যদি (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_বাৰ্তা_EXT_INFO, &kex_প্ৰবেশ_ext_info);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEXINIT, &kex_প্ৰবেশ_kexinit);
	যদি ((r = sshpkt_get_end(ssh)) != 0)
		ঘূৰাই r;
	যদি ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		ঘূৰাই r;
	যদি (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		যদি ((r = kex_buf2prop(kex->my, রিক্ত, &prop)) != 0)
			ঘূৰাই r;
		যদি ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == রিক্ত) {
			error_f("match_filter_denylist failed");
			গচ্ছ fail;
		}
		মুক্ত(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		যদি ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			মুক্ত(prop);
			ঘূৰাই SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		মুক্ত(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_send_kexinit(সংরচনা ssh *ssh)
{
	u_char *cookie;
	সংরচনা kex *kex = ssh->kex;
	পূর্ণাঙ্ক r;

	যদি (kex == রিক্ত) {
		error_f("no kex");
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	যদি (kex->flags & KEX_INIT_SENT)
		ঘূৰাই 0;
	kex->done = 0;

	/* generate a random cookie */
	যদি (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	}
	যদি ((cookie = sshbuf_mutable_ptr(kex->my)) == রিক্ত) {
		error_f("buffer error");
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		ঘূৰাই r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_প্ৰবেশ_kexinit(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	ধ্রুৱ u_char *ptr;
	u_int i;
	size_t dlen;
	পূর্ণাঙ্ক r;

	debug("SSH2_MSG_KEXINIT received");
	যদি (kex == রিক্ত) {
		error_f("no kex");
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	মুক্ত(kex->name);
	kex->name = রিক্ত;
	যদি ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	যদি ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		ঘূৰাই r;

	/* discard packet */
	বাবে (i = 0; i < KEX_COOKIE_LEN; i++) {
		যদি ((r = sshpkt_get_u8(ssh, রিক্ত)) != 0) {
			error_fr(r, "discard cookie");
			ঘূৰাই r;
		}
	}
	বাবে (i = 0; i < PROPOSAL_MAX; i++) {
		যদি ((r = sshpkt_get_string(ssh, রিক্ত, রিক্ত)) != 0) {
			error_fr(r, "discard proposal");
			ঘূৰাই r;
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
	যদি ((r = sshpkt_get_u8(ssh, রিক্ত)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, রিক্ত)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			ঘূৰাই r;

	যদি (!(kex->flags & KEX_INIT_SENT))
		যদি ((r = kex_send_kexinit(ssh)) != 0)
			ঘূৰাই r;
	যদি ((r = kex_choose_conf(ssh, seq)) != 0)
		ঘূৰাই r;

	যদি (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != রিক্ত)
		ঘূৰাই (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	ঘূৰাই SSH_ERR_INTERNAL_ERROR;
}

সংরচনা kex *
kex_new(শূন্য)
{
	সংরচনা kex *kex;

	যদি ((kex = calloc(1, পরিমাণ(*kex))) == রিক্ত ||
	    (kex->peer = sshbuf_new()) == রিক্ত ||
	    (kex->my = sshbuf_new()) == রিক্ত ||
	    (kex->client_version = sshbuf_new()) == রিক্ত ||
	    (kex->server_version = sshbuf_new()) == রিক্ত ||
	    (kex->session_id = sshbuf_new()) == রিক্ত) {
		kex_free(kex);
		ঘূৰাই রিক্ত;
	}
	ঘূৰাই kex;
}

শূন্য
kex_free_newkeys(সংরচনা newkeys *newkeys)
{
	যদি (newkeys == রিক্ত)
		ঘূৰাই;
	যদি (newkeys->enc.চাবি) {
		explicit_bzero(newkeys->enc.চাবি, newkeys->enc.চাবি_len);
		মুক্ত(newkeys->enc.চাবি);
		newkeys->enc.চাবি = রিক্ত;
	}
	যদি (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		মুক্ত(newkeys->enc.iv);
		newkeys->enc.iv = রিক্ত;
	}
	মুক্ত(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, পরিমাণ(newkeys->enc));
	মুক্ত(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, পরিমাণ(newkeys->comp));
	mac_clear(&newkeys->mac);
	যদি (newkeys->mac.চাবি) {
		explicit_bzero(newkeys->mac.চাবি, newkeys->mac.চাবি_len);
		মুক্ত(newkeys->mac.চাবি);
		newkeys->mac.চাবি = রিক্ত;
	}
	মুক্ত(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, পরিমাণ(newkeys->mac));
	freezero(newkeys, পরিমাণ(*newkeys));
}

শূন্য
kex_free(সংরচনা kex *kex)
{
	u_int mode;

	যদি (kex == রিক্ত)
		ঘূৰাই;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_চাবি_free(kex->ec_client_চাবি);
#endif /* WITH_OPENSSL */
	বাবে (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = রিক্ত;
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

পূর্ণাঙ্ক
kex_ready(সংরচনা ssh *ssh, ৱর্ণ *proposal[PROPOSAL_MAX])
{
	পূর্ণাঙ্ক r;

	যদি ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		ঘূৰাই r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEXINIT, &kex_প্ৰবেশ_kexinit);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_setup(সংরচনা ssh *ssh, ৱর্ণ *proposal[PROPOSAL_MAX])
{
	পূর্ণাঙ্ক r;

	যদি ((r = kex_ready(ssh, proposal)) != 0)
		ঘূৰাই r;
	যদি ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = রিক্ত;
		ঘূৰাই r;
	}
	ঘূৰাই 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
পূর্ণাঙ্ক
kex_start_rekex(সংরচনা ssh *ssh)
{
	যদি (ssh->kex == রিক্ত) {
		error_f("no kex");
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	যদি (ssh->kex->done == 0) {
		error_f("requested twice");
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	ঘূৰাই kex_send_kexinit(ssh);
}

স্থির পূর্ণাঙ্ক
choose_enc(সংরচনা sshenc *enc, ৱর্ণ *client, ৱর্ণ *server)
{
	ৱর্ণ *name = match_list(client, server, রিক্ত);

	যদি (name == রিক্ত)
		ঘূৰাই SSH_ERR_NO_CIPHER_ALG_MATCH;
	যদি ((enc->cipher = cipher_by_name(name)) == রিক্ত) {
		error_f("unsupported cipher %s", name);
		মুক্ত(name);
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = রিক্ত;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->চাবি = রিক্ত;
	enc->চাবি_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
choose_mac(সংরচনা ssh *ssh, সংরচনা sshmac *mac, ৱর্ণ *client, ৱর্ণ *server)
{
	ৱর্ণ *name = match_list(client, server, রিক্ত);

	যদি (name == রিক্ত)
		ঘূৰাই SSH_ERR_NO_MAC_ALG_MATCH;
	যদি (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		মুক্ত(name);
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->চাবি = রিক্ত;
	mac->enabled = 0;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
choose_comp(সংরচনা sshcomp *comp, ৱর্ণ *client, ৱর্ণ *server)
{
	ৱর্ণ *name = match_list(client, server, রিক্ত);

	যদি (name == রিক্ত)
		ঘূৰাই SSH_ERR_NO_COMPRESS_ALG_MATCH;
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
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
choose_kex(সংরচনা kex *k, ৱর্ণ *client, ৱর্ণ *server)
{
	k->name = match_list(client, server, রিক্ত);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	যদি (k->name == রিক্ত)
		ঘূৰাই SSH_ERR_NO_KEX_ALG_MATCH;
	যদি (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
choose_hostkeyalg(সংরচনা kex *k, ৱর্ণ *client, ৱর্ণ *server)
{
	মুক্ত(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, রিক্ত);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	যদি (k->hostkey_alg == রিক্ত)
		ঘূৰাই SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	যদি (k->hostkey_type == চাবি_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
proposals_match(ৱর্ণ *my[PROPOSAL_MAX], ৱর্ণ *peer[PROPOSAL_MAX])
{
	স্থির পূর্ণাঙ্ক check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_চাবি_ALGS, -1
	};
	পূর্ণাঙ্ক *idx;
	ৱর্ণ *p;

	বাবে (idx = &check[0]; *idx != -1; idx++) {
		যদি ((p = strchr(my[*idx], ',')) != রিক্ত)
			*p = '\0';
		যদি ((p = strchr(peer[*idx], ',')) != রিক্ত)
			*p = '\0';
		যদি (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			ঘূৰাই (0);
		}
	}
	debug2("proposals match");
	ঘূৰাই (1);
}

স্থির পূর্ণাঙ্ক
kexalgs_contains(ৱর্ণ **peer, ধ্রুৱ ৱর্ণ *ext)
{
	ঘূৰাই kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

স্থির পূর্ণাঙ্ক
kex_choose_conf(সংরচনা ssh *ssh, uint32_t seq)
{
	সংরচনা kex *kex = ssh->kex;
	সংরচনা newkeys *newkeys;
	ৱর্ণ **my = রিক্ত, **peer = রিক্ত;
	ৱর্ণ **cprop, **sprop;
	পূর্ণাঙ্ক nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	পূর্ণাঙ্ক r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	যদি ((r = kex_buf2prop(kex->my, রিক্ত, &my)) != 0)
		গচ্ছ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	যদি ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		গচ্ছ out;

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
		peer[PROPOSAL_KEX_ALGS] = রিক্ত;
		গচ্ছ out;
	}
	যদি ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_চাবি_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_চাবি_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_চাবি_ALGS];
		peer[PROPOSAL_SERVER_HOST_চাবি_ALGS] = রিক্ত;
		গচ্ছ out;
	}
	বাবে (mode = 0; mode < MODE_MAX; mode++) {
		যদি ((newkeys = calloc(1, পরিমাণ(*newkeys))) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
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
			peer[nenc] = রিক্ত;
			গচ্ছ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		যদি (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = রিক্ত;
			গচ্ছ out;
		}
		যদি ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = রিক্ত;
			গচ্ছ out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	বাবে (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.চাবি_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.চাবি_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
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
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
derive_চাবি(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, u_int need, u_char *hash, u_int hashlen,
    ধ্রুৱ সংরচনা sshbuf *shared_secret, u_char **keyp)
{
	সংরচনা kex *kex = ssh->kex;
	সংরচনা ssh_digest_ctx *hashctx = রিক্ত;
	ৱর্ণ c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	পূর্ণাঙ্ক r;

	যদি ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি ((digest = calloc(1, ROUNDUP(need, mdsz))) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	যদি ((hashctx = ssh_digest_start(kex->hash_alg)) == রিক্ত ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		গচ্ছ out;
	}
	ssh_digest_free(hashctx);
	hashctx = রিক্ত;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	বাবে (have = mdsz; need > have; have += mdsz) {
		যদি ((hashctx = ssh_digest_start(kex->hash_alg)) == রিক্ত ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		ssh_digest_free(hashctx);
		hashctx = রিক্ত;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = রিক্ত;
	r = 0;
 out:
	মুক্ত(digest);
	ssh_digest_free(hashctx);
	ঘূৰাই r;
}

#define NKEYS	6
পূর্ণাঙ্ক
kex_derive_চাবিগুলি(সংরচনা ssh *ssh, u_char *hash, u_int hashlen,
    ধ্রুৱ সংরচনা sshbuf *shared_secret)
{
	সংরচনা kex *kex = ssh->kex;
	u_char *চাবিগুলি[NKEYS];
	u_int i, j, mode, ctos;
	পূর্ণাঙ্ক r;

	/* save initial hash as session id */
	যদি ((kex->flags & KEX_INITIAL) != 0) {
		যদি (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			ঘূৰাই SSH_ERR_INTERNAL_ERROR;
		}
		যদি ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			ঘূৰাই r;
	} অন্যথা যদি (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	বাবে (i = 0; i < NKEYS; i++) {
		যদি ((r = derive_চাবি(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &চাবিগুলি[i])) != 0) {
			বাবে (j = 0; j < i; j++)
				মুক্ত(চাবিগুলি[j]);
			ঘূৰাই r;
		}
	}
	বাবে (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = চাবিগুলি[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.চাবি = চাবিগুলি[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.চাবি = চাবিগুলি[ctos ? 4 : 5];
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_load_hostkey(সংরচনা ssh *ssh, সংরচনা sshkey **prvp, সংরচনা sshkey **pubp)
{
	সংরচনা kex *kex = ssh->kex;

	*pubp = রিক্ত;
	*prvp = রিক্ত;
	যদি (kex->load_host_public_চাবি == রিক্ত ||
	    kex->load_host_private_চাবি == রিক্ত) {
		error_f("missing hostkey loader");
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_চাবি(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_চাবি(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	যদি (*pubp == রিক্ত)
		ঘূৰাই SSH_ERR_NO_HOSTKEY_LOADED;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
kex_verify_host_চাবি(সংরচনা ssh *ssh, সংরচনা sshkey *server_host_চাবি)
{
	সংরচনা kex *kex = ssh->kex;

	যদি (kex->verify_host_চাবি == রিক্ত) {
		error_f("missing hostkey verifier");
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (server_host_চাবি->type != kex->hostkey_type ||
	    (kex->hostkey_type == চাবি_ECDSA &&
	    server_host_চাবি->ecdsa_nid != kex->hostkey_nid))
		ঘূৰাই SSH_ERR_চাবি_TYPE_MISMATCH;
	যদি (kex->verify_host_চাবি(server_host_চাবি, ssh) == -1)
		ঘূৰাই  SSH_ERR_SIGNATURE_INVALID;
	ঘূৰাই 0;
}

#যদি defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
শূন্য
dump_digest(ধ্রুৱ ৱর্ণ *বাৰ্তা, ধ্রুৱ u_char *digest, পূর্ণাঙ্ক len)
{
	fprintf(stderr, "%s\n", বাৰ্তা);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
স্থির শূন্য
send_error(সংরচনা ssh *ssh, ৱর্ণ *বাৰ্তা)
{
	ৱর্ণ *crnl = "\r\n";

	যদি (!ssh->kex->server)
		ঘূৰাই;

	যদি (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    বাৰ্তা, strlen(বাৰ্তা)) != strlen(বাৰ্তা) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
পূর্ণাঙ্ক
kex_exchange_identification(সংরচনা ssh *ssh, পূর্ণাঙ্ক timeout_ms,
    ধ্রুৱ ৱর্ণ *version_addendum)
{
	পূর্ণাঙ্ক remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	পূর্ণাঙ্ক r, expect_nl;
	u_char c;
	সংরচনা sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	সংরচনা sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	ৱর্ণ *our_version_string = রিক্ত, *peer_version_string = রিক্ত;
	ৱর্ণ *cp, *remote_version = রিক্ত;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	যদি (version_addendum != রিক্ত && *version_addendum == '\0')
		version_addendum = রিক্ত;
	যদি ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == রিক্ত ? "" : " ",
	    version_addendum == রিক্ত ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		গচ্ছ out;
	}

	যদি (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		গচ্ছ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	যদি (our_version_string == রিক্ত) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	বাবে (n = 0; ; n++) {
		যদি (n >= SSH_MAX_PRE_BANNER_সাৰিগুলি) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_সাৰিগুলি);
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		বাবে (;;) {
			যদি (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, রিক্ত);
				যদি (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					গচ্ছ out;
				} অন্যথা যদি (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					গচ্ছ out;
				}
			}

			len = atomicio(পঠ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			যদি (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				গচ্ছ out;
			} অন্যথা যদি (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				গচ্ছ out;
			}
			যদি (c == '\r') {
				expect_nl = 1;
				অনুৱর্ত;
			}
			যদি (c == '\n')
				ভঙ্গ;
			যদি (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				গচ্ছ invalid;
			}
			যদি ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				গচ্ছ out;
			}
			যদি (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				গচ্ছ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		যদি (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			ভঙ্গ;
		/* If not, then just log the line and continue */
		যদি ((cp = sshbuf_dup_string(peer_version)) == রিক্ত) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		/* Do not accept lines before the SSH ident from a client */
		যদি (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			মুক্ত(cp);
			গচ্ছ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		মুক্ত(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	যদি (peer_version_string == রিক্ত)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	যদি ((remote_version = calloc(1, sshbuf_len(peer_version))) == রিক্ত) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
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
		গচ্ছ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	ৱিকল্প (remote_major) {
	পক্ষ 2:
		ভঙ্গ;
	পক্ষ 1:
		যদি (remote_minor != 99)
			mismatch = 1;
		ভঙ্গ;
	স্ৱভাৱ:
		mismatch = 1;
		ভঙ্গ;
	}
	যদি (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		গচ্ছ out;
	}

	যদি (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		গচ্ছ out;
	}
	যদি (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(our_version_string);
	মুক্ত(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	যদি (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	ঘূৰাই r;
}

