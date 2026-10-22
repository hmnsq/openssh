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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/dh.h>
#endif

#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "version.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "myproposal.h"

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "xmalloc.h"

/* prototype */
நிலையான முழு kex_choose_conf(கட்டமைப்பு ssh *, uint32_t seq);
நிலையான முழு kex_உள்ளீடு_newkeys(முழு, uint32_t, கட்டமைப்பு ssh *);

நிலையான மாறிலி எழுத்து * மாறிலி proposal_names[PROPOSAL_MAX] = {
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
வெறுமை
kex_proposal_populate_entries(கட்டமைப்பு ssh *ssh, எழுத்து *prop[PROPOSAL_MAX],
    மாறிலி எழுத்து *kexalgos, மாறிலி எழுத்து *ciphers, மாறிலி எழுத்து *macs,
    மாறிலி எழுத்து *comp, மாறிலி எழுத்து *hkalgs)
{
	மாறிலி எழுத்து *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	மாறிலி எழுத்து *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	மாறிலி எழுத்து **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	எழுத்து *cp;

	எனில் (prop == வெற்று)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	எனில் (kexalgos == வெற்று)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	எனில் ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == வெற்று)
		fatal_f("kex_names_cat");

	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		தேர்வு(i) {
		நிலை PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			நிறுத்து;
		நிலை PROPOSAL_ENC_ALGS_CTOS:
		நிலை PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			நிறுத்து;
		நிலை PROPOSAL_MAC_ALGS_CTOS:
		நிலை PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			நிறுத்து;
		நிலை PROPOSAL_COMP_ALGS_CTOS:
		நிலை PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			நிறுத்து;
		நிலை PROPOSAL_SERVER_HOST_சாவி_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			நிறுத்து;
		இயல்பு:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	விடுவி(cp);
}

வெறுமை
kex_proposal_free_entries(எழுத்து *prop[PROPOSAL_MAX])
{
	u_int i;

	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(prop[i]);
}

/* put algorithm proposal into buffer */
முழு
kex_prop2buf(கட்டமைப்பு sshbuf *b, எழுத்து *proposal[PROPOSAL_MAX])
{
	u_int i;
	முழு r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	க்கு (i = 0; i < KEX_COOKIE_LEN; i++) {
		எனில் ((r = sshbuf_put_u8(b, 0)) != 0)
			திரும்பு r;
	}
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		எனில் ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		திரும்பு r;
	திரும்பு 0;
}

/* parse buffer and return algorithm proposal */
முழு
kex_buf2prop(கட்டமைப்பு sshbuf *raw, முழு *first_kex_follows, எழுத்து ***propp)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	u_char v;
	u_int i;
	எழுத்து **proposal = வெற்று;
	முழு r;

	*propp = வெற்று;
	எனில் ((proposal = calloc(PROPOSAL_MAX, அளவு(எழுத்து *))) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((b = sshbuf_fromb(raw)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		செல் out;
	}
	/* extract kex init proposal strings */
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		எனில் ((r = sshbuf_get_cstring(b, &(proposal[i]), வெற்று)) != 0) {
			error_fr(r, "parse proposal %u", i);
			செல் out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	எனில் ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		செல் out;
	}
	எனில் (first_kex_follows != வெற்று)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	எனில் (r != 0 && proposal != வெற்று)
		kex_prop_free(proposal);
	sshbuf_free(b);
	திரும்பு r;
}

வெறுமை
kex_prop_free(எழுத்து **proposal)
{
	u_int i;

	எனில் (proposal == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(proposal[i]);
	விடுவி(proposal);
}

முழு
kex_protocol_error(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	முழு r;

	/* If in strict mode, any unexpected message is an error */
	எனில் ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான வெறுமை
kex_reset_dispatch(கட்டமைப்பு ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_செய்தி_TRANSPORT_MIN,
	    SSH2_செய்தி_TRANSPORT_MAX, &kex_protocol_error);
}

வெறுமை
kex_set_server_sig_algs(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *allowed_algs)
{
	எழுத்து *alg, *oalgs, *algs, *sigalgs;
	மாறிலி எழுத்து *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	எனில் ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == வெற்று)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	விடுவி(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = வெற்று;
	க்கு ((alg = strsep(&algs, ",")); alg != வெற்று && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		எனில் ((sigalg = sshkey_sigalg_by_name(alg)) == வெற்று)
			தொடர்;
		எனில் (!kex_has_any_alg(sigalg, sigalgs))
			தொடர்;
		/* Don't add an algorithm twice. */
		எனில் (ssh->kex->server_sig_algs != வெற்று &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			தொடர்;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	விடுவி(oalgs);
	விடுவி(sigalgs);
	எனில் (ssh->kex->server_sig_algs == வெற்று)
		ssh->kex->server_sig_algs = xstrdup("");
}

வெறுமை
kex_set_warn_weak_crypto(கட்டமைப்பு ssh *ssh, முழு warn_weak_crypto)
{
	எனில் (ssh != வெற்று && ssh->kex != வெற்று)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

வெறுமை
kex_check_warn_weak_crypto(கட்டமைப்பு ssh *ssh)
{
	எழுத்து remote_id[512];
	முழு rekeyed = 0;

	எனில் (ssh == வெற்று || ssh->kex == வெற்று || ssh->kex->name == வெற்று ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		திரும்பு;
	எனில் (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		திரும்பு;
	}

	எனில் (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	எனில் (!rekeyed && !ssh->kex->server)
		திரும்பு; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, அளவு(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

நிலையான முழு
kex_compose_ext_info_server(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *m)
{
	முழு r;

	எனில் (ssh->kex->server_sig_algs == வெற்று &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
kex_compose_ext_info_client(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *m)
{
	முழு r;

	எனில் ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		செல் out;
	}
	/* success */
	r = 0;
 out:
	திரும்பு r;
}

நிலையான முழு
kex_maybe_send_ext_info(கட்டமைப்பு ssh *ssh)
{
	முழு r;
	கட்டமைப்பு sshbuf *m = வெற்று;

	எனில் ((ssh->kex->flags & KEX_INITIAL) == 0)
		திரும்பு 0;
	எனில் (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		திரும்பு 0;

	/* Compose EXT_INFO packet. */
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		செல் fail;
	எனில் (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		செல் fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		செல் fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	திரும்பு r;
}

முழு
kex_server_update_ext_info(கட்டமைப்பு ssh *ssh)
{
	முழு r;

	எனில் ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		திரும்பு 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		திரும்பு r;
	}
	திரும்பு 0;
}

முழு
kex_send_newkeys(கட்டமைப்பு ssh *ssh)
{
	முழு r;

	kex_reset_dispatch(ssh);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		திரும்பு r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_செய்தி_NEWKEYS, &kex_உள்ளீடு_newkeys);
	எனில் ((r = kex_maybe_send_ext_info(ssh)) != 0)
		திரும்பு r;
	debug("expecting SSH2_MSG_NEWKEYS");
	திரும்பு 0;
}

/* Check whether an ext_info value contains the expected version string */
நிலையான முழு
kex_ext_info_check_ver(கட்டமைப்பு kex *kex, மாறிலி எழுத்து *name,
    மாறிலி u_char *val, size_t len, மாறிலி எழுத்து *want_ver, u_int flag)
{
	எனில் (memchr(val, '\0', len) != வெற்று) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	எனில் (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	இல்லையெனில்
		debug_f("unsupported version of %s extension", name);
	திரும்பு 0;
}

நிலையான முழு
kex_ext_info_client_parse(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *name,
    மாறிலி u_char *மதிப்பு, size_t vlen)
{
	முழு r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	எனில் (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		எனில் (memchr(மதிப்பு, '\0', vlen) != வெற்று) {
			error_f("nul byte in %s", name);
			திரும்பு SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, மதிப்பு);
		விடுவி(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((மாறிலி எழுத்து *)மதிப்பு);
	} இல்லையெனில் எனில் (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		எனில் ((r = kex_ext_info_check_ver(ssh->kex, name, மதிப்பு, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			திரும்பு r;
		}
	} இல்லையெனில் எனில் (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		எனில் ((r = kex_ext_info_check_ver(ssh->kex, name, மதிப்பு, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			திரும்பு r;
		}
	} இல்லையெனில் எனில் (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		எனில் ((r = kex_ext_info_check_ver(ssh->kex, name, மதிப்பு, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			திரும்பு r;
		}
	} இல்லையெனில்
		debug_f("%s (unrecognised)", name);

	திரும்பு 0;
}

நிலையான முழு
kex_ext_info_server_parse(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *name,
    மாறிலி u_char *மதிப்பு, size_t vlen)
{
	முழு r;

	எனில் (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		எனில் ((r = kex_ext_info_check_ver(ssh->kex, name, மதிப்பு, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			திரும்பு r;
		}
	} இல்லையெனில்
		debug_f("%s (unrecognised)", name);
	திரும்பு 0;
}

முழு
kex_உள்ளீடு_ext_info(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	மாறிலி முழு max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	எழுத்து *name;
	u_char *val;
	size_t vlen;
	முழு r;

	debug("SSH2_MSG_EXT_INFO received");
	எனில் (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		திரும்பு dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, &kex_protocol_error);
	எனில் ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		திரும்பு r;
	எனில் (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		திரும்பு dispatch_protocol_error(type, seq, ssh);
	}
	க்கு (i = 0; i < ninfo; i++) {
		எனில் ((r = sshpkt_get_cstring(ssh, &name, வெற்று)) != 0)
			திரும்பு r;
		எனில் ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			விடுவி(name);
			திரும்பு r;
		}
		debug3_f("extension %s", name);
		எனில் (kex->server) {
			எனில் ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				திரும்பு r;
		} இல்லையெனில் {
			எனில் ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				திரும்பு r;
		}
		விடுவி(name);
		விடுவி(val);
	}
	திரும்பு sshpkt_get_end(ssh);
}

நிலையான முழு
kex_உள்ளீடு_newkeys(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	முழு r, initial = (kex->flags & KEX_INITIAL) != 0;
	எழுத்து *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	எனில் (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, &kex_உள்ளீடு_ext_info);
	ssh_dispatch_set(ssh, SSH2_செய்தி_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEXINIT, &kex_உள்ளீடு_kexinit);
	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		திரும்பு r;
	எனில் ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		திரும்பு r;
	எனில் (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		எனில் ((r = kex_buf2prop(kex->my, வெற்று, &prop)) != 0)
			திரும்பு r;
		எனில் ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == வெற்று) {
			error_f("match_filter_denylist failed");
			செல் fail;
		}
		விடுவி(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		எனில் ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			விடுவி(prop);
			திரும்பு SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		விடுவி(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	திரும்பு 0;
}

முழு
kex_send_kexinit(கட்டமைப்பு ssh *ssh)
{
	u_char *cookie;
	கட்டமைப்பு kex *kex = ssh->kex;
	முழு r;

	எனில் (kex == வெற்று) {
		error_f("no kex");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	எனில் (kex->flags & KEX_INIT_SENT)
		திரும்பு 0;
	kex->done = 0;

	/* generate a random cookie */
	எனில் (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	எனில் ((cookie = sshbuf_mutable_ptr(kex->my)) == வெற்று) {
		error_f("buffer error");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		திரும்பு r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	திரும்பு 0;
}

முழு
kex_உள்ளீடு_kexinit(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	மாறிலி u_char *ptr;
	u_int i;
	size_t dlen;
	முழு r;

	debug("SSH2_MSG_KEXINIT received");
	எனில் (kex == வெற்று) {
		error_f("no kex");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	விடுவி(kex->name);
	kex->name = வெற்று;
	எனில் ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	எனில் ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		திரும்பு r;

	/* discard packet */
	க்கு (i = 0; i < KEX_COOKIE_LEN; i++) {
		எனில் ((r = sshpkt_get_u8(ssh, வெற்று)) != 0) {
			error_fr(r, "discard cookie");
			திரும்பு r;
		}
	}
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		எனில் ((r = sshpkt_get_string(ssh, வெற்று, வெற்று)) != 0) {
			error_fr(r, "discard proposal");
			திரும்பு r;
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
	எனில் ((r = sshpkt_get_u8(ssh, வெற்று)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, வெற்று)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			திரும்பு r;

	எனில் (!(kex->flags & KEX_INIT_SENT))
		எனில் ((r = kex_send_kexinit(ssh)) != 0)
			திரும்பு r;
	எனில் ((r = kex_choose_conf(ssh, seq)) != 0)
		திரும்பு r;

	எனில் (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != வெற்று)
		திரும்பு (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	திரும்பு SSH_ERR_INTERNAL_ERROR;
}

கட்டமைப்பு kex *
kex_new(வெறுமை)
{
	கட்டமைப்பு kex *kex;

	எனில் ((kex = calloc(1, அளவு(*kex))) == வெற்று ||
	    (kex->peer = sshbuf_new()) == வெற்று ||
	    (kex->my = sshbuf_new()) == வெற்று ||
	    (kex->client_version = sshbuf_new()) == வெற்று ||
	    (kex->server_version = sshbuf_new()) == வெற்று ||
	    (kex->session_id = sshbuf_new()) == வெற்று) {
		kex_free(kex);
		திரும்பு வெற்று;
	}
	திரும்பு kex;
}

வெறுமை
kex_free_newkeys(கட்டமைப்பு newkeys *newkeys)
{
	எனில் (newkeys == வெற்று)
		திரும்பு;
	எனில் (newkeys->enc.சாவி) {
		explicit_bzero(newkeys->enc.சாவி, newkeys->enc.சாவி_len);
		விடுவி(newkeys->enc.சாவி);
		newkeys->enc.சாவி = வெற்று;
	}
	எனில் (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		விடுவி(newkeys->enc.iv);
		newkeys->enc.iv = வெற்று;
	}
	விடுவி(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, அளவு(newkeys->enc));
	விடுவி(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, அளவு(newkeys->comp));
	mac_clear(&newkeys->mac);
	எனில் (newkeys->mac.சாவி) {
		explicit_bzero(newkeys->mac.சாவி, newkeys->mac.சாவி_len);
		விடுவி(newkeys->mac.சாவி);
		newkeys->mac.சாவி = வெற்று;
	}
	விடுவி(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, அளவு(newkeys->mac));
	freezero(newkeys, அளவு(*newkeys));
}

வெறுமை
kex_free(கட்டமைப்பு kex *kex)
{
	u_int mode;

	எனில் (kex == வெற்று)
		திரும்பு;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_சாவி_free(kex->ec_client_சாவி);
#endif /* WITH_OPENSSL */
	க்கு (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = வெற்று;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	விடுவி(kex->failed_choice);
	விடுவி(kex->hostkey_alg);
	விடுவி(kex->name);
	விடுவி(kex->server_sig_algs);
	விடுவி(kex);
}

முழு
kex_ready(கட்டமைப்பு ssh *ssh, எழுத்து *proposal[PROPOSAL_MAX])
{
	முழு r;

	எனில் ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		திரும்பு r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEXINIT, &kex_உள்ளீடு_kexinit);
	திரும்பு 0;
}

முழு
kex_setup(கட்டமைப்பு ssh *ssh, எழுத்து *proposal[PROPOSAL_MAX])
{
	முழு r;

	எனில் ((r = kex_ready(ssh, proposal)) != 0)
		திரும்பு r;
	எனில் ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = வெற்று;
		திரும்பு r;
	}
	திரும்பு 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
முழு
kex_start_rekex(கட்டமைப்பு ssh *ssh)
{
	எனில் (ssh->kex == வெற்று) {
		error_f("no kex");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	எனில் (ssh->kex->done == 0) {
		error_f("requested twice");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	திரும்பு kex_send_kexinit(ssh);
}

நிலையான முழு
choose_enc(கட்டமைப்பு sshenc *enc, எழுத்து *client, எழுத்து *server)
{
	எழுத்து *name = match_list(client, server, வெற்று);

	எனில் (name == வெற்று)
		திரும்பு SSH_ERR_NO_CIPHER_ALG_MATCH;
	எனில் ((enc->cipher = cipher_by_name(name)) == வெற்று) {
		error_f("unsupported cipher %s", name);
		விடுவி(name);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = வெற்று;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->சாவி = வெற்று;
	enc->சாவி_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	திரும்பு 0;
}

நிலையான முழு
choose_mac(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshmac *mac, எழுத்து *client, எழுத்து *server)
{
	எழுத்து *name = match_list(client, server, வெற்று);

	எனில் (name == வெற்று)
		திரும்பு SSH_ERR_NO_MAC_ALG_MATCH;
	எனில் (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		விடுவி(name);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->சாவி = வெற்று;
	mac->enabled = 0;
	திரும்பு 0;
}

நிலையான முழு
choose_comp(கட்டமைப்பு sshcomp *comp, எழுத்து *client, எழுத்து *server)
{
	எழுத்து *name = match_list(client, server, வெற்று);

	எனில் (name == வெற்று)
		திரும்பு SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	எனில் (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} இல்லையெனில்
#endif	/* WITH_ZLIB */
	எனில் (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} இல்லையெனில் {
		error_f("unsupported compression scheme %s", name);
		விடுவி(name);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	திரும்பு 0;
}

நிலையான முழு
choose_kex(கட்டமைப்பு kex *k, எழுத்து *client, எழுத்து *server)
{
	k->name = match_list(client, server, வெற்று);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	எனில் (k->name == வெற்று)
		திரும்பு SSH_ERR_NO_KEX_ALG_MATCH;
	எனில் (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	திரும்பு 0;
}

நிலையான முழு
choose_hostkeyalg(கட்டமைப்பு kex *k, எழுத்து *client, எழுத்து *server)
{
	விடுவி(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, வெற்று);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	எனில் (k->hostkey_alg == வெற்று)
		திரும்பு SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	எனில் (k->hostkey_type == சாவி_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	திரும்பு 0;
}

நிலையான முழு
proposals_match(எழுத்து *my[PROPOSAL_MAX], எழுத்து *peer[PROPOSAL_MAX])
{
	நிலையான முழு check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_சாவி_ALGS, -1
	};
	முழு *idx;
	எழுத்து *p;

	க்கு (idx = &check[0]; *idx != -1; idx++) {
		எனில் ((p = strchr(my[*idx], ',')) != வெற்று)
			*p = '\0';
		எனில் ((p = strchr(peer[*idx], ',')) != வெற்று)
			*p = '\0';
		எனில் (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			திரும்பு (0);
		}
	}
	debug2("proposals match");
	திரும்பு (1);
}

நிலையான முழு
kexalgs_contains(எழுத்து **peer, மாறிலி எழுத்து *ext)
{
	திரும்பு kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

நிலையான முழு
kex_choose_conf(கட்டமைப்பு ssh *ssh, uint32_t seq)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	கட்டமைப்பு newkeys *newkeys;
	எழுத்து **my = வெற்று, **peer = வெற்று;
	எழுத்து **cprop, **sprop;
	முழு nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	முழு r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	எனில் ((r = kex_buf2prop(kex->my, வெற்று, &my)) != 0)
		செல் out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	எனில் ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		செல் out;

	எனில் (kex->server) {
		cprop=peer;
		sprop=my;
	} இல்லையெனில் {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	எனில் ((kex->flags & KEX_INITIAL) != 0) {
		எனில் (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} இல்லையெனில் {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		எனில் (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			எனில் (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	எனில் (kex->server && (kex->flags & KEX_INITIAL)) {
		எனில் (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_சாவி_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		எனில் (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_சாவி_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	எனில் ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = வெற்று;
		செல் out;
	}
	எனில் ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_சாவி_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_சாவி_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_சாவி_ALGS];
		peer[PROPOSAL_SERVER_HOST_சாவி_ALGS] = வெற்று;
		செல் out;
	}
	க்கு (mode = 0; mode < MODE_MAX; mode++) {
		எனில் ((newkeys = calloc(1, அளவு(*newkeys))) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		எனில் ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = வெற்று;
			செல் out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		எனில் (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = வெற்று;
			செல் out;
		}
		எனில் ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = வெற்று;
			செல் out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	க்கு (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.சாவி_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.சாவி_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.சாவி_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	எனில் (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	திரும்பு r;
}

நிலையான முழு
derive_சாவி(கட்டமைப்பு ssh *ssh, முழு id, u_int need, u_char *hash, u_int hashlen,
    மாறிலி கட்டமைப்பு sshbuf *shared_secret, u_char **keyp)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	கட்டமைப்பு ssh_digest_ctx *hashctx = வெற்று;
	எழுத்து c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	முழு r;

	எனில் ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((digest = calloc(1, ROUNDUP(need, mdsz))) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	எனில் ((hashctx = ssh_digest_start(kex->hash_alg)) == வெற்று ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		செல் out;
	}
	ssh_digest_free(hashctx);
	hashctx = வெற்று;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	க்கு (have = mdsz; need > have; have += mdsz) {
		எனில் ((hashctx = ssh_digest_start(kex->hash_alg)) == வெற்று ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		ssh_digest_free(hashctx);
		hashctx = வெற்று;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = வெற்று;
	r = 0;
 out:
	விடுவி(digest);
	ssh_digest_free(hashctx);
	திரும்பு r;
}

#define NKEYS	6
முழு
kex_derive_சாவிகள்(கட்டமைப்பு ssh *ssh, u_char *hash, u_int hashlen,
    மாறிலி கட்டமைப்பு sshbuf *shared_secret)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	u_char *சாவிகள்[NKEYS];
	u_int i, j, mode, ctos;
	முழு r;

	/* save initial hash as session id */
	எனில் ((kex->flags & KEX_INITIAL) != 0) {
		எனில் (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			திரும்பு SSH_ERR_INTERNAL_ERROR;
		}
		எனில் ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			திரும்பு r;
	} இல்லையெனில் எனில் (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	க்கு (i = 0; i < NKEYS; i++) {
		எனில் ((r = derive_சாவி(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &சாவிகள்[i])) != 0) {
			க்கு (j = 0; j < i; j++)
				விடுவி(சாவிகள்[j]);
			திரும்பு r;
		}
	}
	க்கு (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = சாவிகள்[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.சாவி = சாவிகள்[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.சாவி = சாவிகள்[ctos ? 4 : 5];
	}
	திரும்பு 0;
}

முழு
kex_load_hostkey(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey **prvp, கட்டமைப்பு sshkey **pubp)
{
	கட்டமைப்பு kex *kex = ssh->kex;

	*pubp = வெற்று;
	*prvp = வெற்று;
	எனில் (kex->load_host_public_சாவி == வெற்று ||
	    kex->load_host_private_சாவி == வெற்று) {
		error_f("missing hostkey loader");
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_சாவி(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_சாவி(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	எனில் (*pubp == வெற்று)
		திரும்பு SSH_ERR_NO_HOSTKEY_LOADED;
	திரும்பு 0;
}

முழு
kex_verify_host_சாவி(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *server_host_சாவி)
{
	கட்டமைப்பு kex *kex = ssh->kex;

	எனில் (kex->verify_host_சாவி == வெற்று) {
		error_f("missing hostkey verifier");
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	எனில் (server_host_சாவி->type != kex->hostkey_type ||
	    (kex->hostkey_type == சாவி_ECDSA &&
	    server_host_சாவி->ecdsa_nid != kex->hostkey_nid))
		திரும்பு SSH_ERR_சாவி_TYPE_MISMATCH;
	எனில் (kex->verify_host_சாவி(server_host_சாவி, ssh) == -1)
		திரும்பு  SSH_ERR_SIGNATURE_INVALID;
	திரும்பு 0;
}

#எனில் defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
வெறுமை
dump_digest(மாறிலி எழுத்து *செய்தி, மாறிலி u_char *digest, முழு len)
{
	fprintf(stderr, "%s\n", செய்தி);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
நிலையான வெறுமை
send_error(கட்டமைப்பு ssh *ssh, எழுத்து *செய்தி)
{
	எழுத்து *crnl = "\r\n";

	எனில் (!ssh->kex->server)
		திரும்பு;

	எனில் (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    செய்தி, strlen(செய்தி)) != strlen(செய்தி) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
முழு
kex_exchange_identification(கட்டமைப்பு ssh *ssh, முழு timeout_ms,
    மாறிலி எழுத்து *version_addendum)
{
	முழு remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	முழு r, expect_nl;
	u_char c;
	கட்டமைப்பு sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	கட்டமைப்பு sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	எழுத்து *our_version_string = வெற்று, *peer_version_string = வெற்று;
	எழுத்து *cp, *remote_version = வெற்று;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	எனில் (version_addendum != வெற்று && *version_addendum == '\0')
		version_addendum = வெற்று;
	எனில் ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == வெற்று ? "" : " ",
	    version_addendum == வெற்று ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		செல் out;
	}

	எனில் (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		செல் out;
	}
	எனில் ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		செல் out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	எனில் (our_version_string == வெற்று) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	க்கு (n = 0; ; n++) {
		எனில் (n >= SSH_MAX_PRE_BANNER_வரிகள்) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_வரிகள்);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		க்கு (;;) {
			எனில் (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, வெற்று);
				எனில் (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					செல் out;
				} இல்லையெனில் எனில் (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					செல் out;
				}
			}

			len = atomicio(பட, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			எனில் (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				செல் out;
			} இல்லையெனில் எனில் (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				செல் out;
			}
			எனில் (c == '\r') {
				expect_nl = 1;
				தொடர்;
			}
			எனில் (c == '\n')
				நிறுத்து;
			எனில் (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				செல் invalid;
			}
			எனில் ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				செல் out;
			}
			எனில் (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				செல் invalid;
			}
		}
		/* Is this an actual protocol banner? */
		எனில் (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			நிறுத்து;
		/* If not, then just log the line and continue */
		எனில் ((cp = sshbuf_dup_string(peer_version)) == வெற்று) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		/* Do not accept lines before the SSH ident from a client */
		எனில் (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			விடுவி(cp);
			செல் invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		விடுவி(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	எனில் (peer_version_string == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	எனில் ((remote_version = calloc(1, sshbuf_len(peer_version))) == வெற்று) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	எனில் (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	தேர்வு (remote_major) {
	நிலை 2:
		நிறுத்து;
	நிலை 1:
		எனில் (remote_minor != 99)
			mismatch = 1;
		நிறுத்து;
	இயல்பு:
		mismatch = 1;
		நிறுத்து;
	}
	எனில் (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		செல் out;
	}

	எனில் (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		செல் out;
	}
	எனில் (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		செல் out;
	}
	/* success */
	r = 0;
 out:
	விடுவி(our_version_string);
	விடுவி(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	எனில் (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	திரும்பு r;
}

