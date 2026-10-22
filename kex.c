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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/dh.h>
#endif

#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "version.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "myproposal.h"

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "xmalloc.h"

/* prototype */
സ്ഥിതം പൂർണ്ണസംഖ്യ kex_choose_conf(ഘടന ssh *, uint32_t seq);
സ്ഥിതം പൂർണ്ണസംഖ്യ kex_നിവേശം_newkeys(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം proposal_names[PROPOSAL_MAX] = {
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
ശൂന്യം
kex_proposal_populate_entries(ഘടന ssh *ssh, അക്ഷരം *prop[PROPOSAL_MAX],
    സ്ഥിരം അക്ഷരം *kexalgos, സ്ഥിരം അക്ഷരം *ciphers, സ്ഥിരം അക്ഷരം *macs,
    സ്ഥിരം അക്ഷരം *comp, സ്ഥിരം അക്ഷരം *hkalgs)
{
	സ്ഥിരം അക്ഷരം *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	സ്ഥിരം അക്ഷരം *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	സ്ഥിരം അക്ഷരം **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	അക്ഷരം *cp;

	എങ്കിൽ (prop == ശൂന്യ)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	എങ്കിൽ (kexalgos == ശൂന്യ)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	എങ്കിൽ ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ശൂന്യ)
		fatal_f("kex_names_cat");

	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		തിരഞ്ഞെടുപ്പ്(i) {
		അവസ്ഥ PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			നിർത്തുക;
		അവസ്ഥ PROPOSAL_ENC_ALGS_CTOS:
		അവസ്ഥ PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			നിർത്തുക;
		അവസ്ഥ PROPOSAL_MAC_ALGS_CTOS:
		അവസ്ഥ PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			നിർത്തുക;
		അവസ്ഥ PROPOSAL_COMP_ALGS_CTOS:
		അവസ്ഥ PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			നിർത്തുക;
		അവസ്ഥ PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	സ്വതന്ത്രം(cp);
}

ശൂന്യം
kex_proposal_free_entries(അക്ഷരം *prop[PROPOSAL_MAX])
{
	u_int i;

	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(prop[i]);
}

/* put algorithm proposal into buffer */
പൂർണ്ണസംഖ്യ
kex_prop2buf(ഘടന sshbuf *b, അക്ഷരം *proposal[PROPOSAL_MAX])
{
	u_int i;
	പൂർണ്ണസംഖ്യ r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	വേണ്ടി (i = 0; i < KEX_COOKIE_LEN; i++) {
		എങ്കിൽ ((r = sshbuf_put_u8(b, 0)) != 0)
			തിരികെ r;
	}
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		തിരികെ r;
	തിരികെ 0;
}

/* parse buffer and return algorithm proposal */
പൂർണ്ണസംഖ്യ
kex_buf2prop(ഘടന sshbuf *raw, പൂർണ്ണസംഖ്യ *first_kex_follows, അക്ഷരം ***propp)
{
	ഘടന sshbuf *b = ശൂന്യ;
	u_char v;
	u_int i;
	അക്ഷരം **proposal = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*propp = ശൂന്യ;
	എങ്കിൽ ((proposal = calloc(PROPOSAL_MAX, വലുപ്പം(അക്ഷരം *))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((b = sshbuf_fromb(raw)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		പോകുക out;
	}
	/* extract kex init proposal strings */
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		എങ്കിൽ ((r = sshbuf_get_cstring(b, &(proposal[i]), ശൂന്യ)) != 0) {
			error_fr(r, "parse proposal %u", i);
			പോകുക out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	എങ്കിൽ ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		പോകുക out;
	}
	എങ്കിൽ (first_kex_follows != ശൂന്യ)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	എങ്കിൽ (r != 0 && proposal != ശൂന്യ)
		kex_prop_free(proposal);
	sshbuf_free(b);
	തിരികെ r;
}

ശൂന്യം
kex_prop_free(അക്ഷരം **proposal)
{
	u_int i;

	എങ്കിൽ (proposal == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(proposal[i]);
	സ്വതന്ത്രം(proposal);
}

പൂർണ്ണസംഖ്യ
kex_protocol_error(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	/* If in strict mode, any unexpected message is an error */
	എങ്കിൽ ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
kex_reset_dispatch(ഘടന ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_സന്ദേശം_TRANSPORT_MIN,
	    SSH2_സന്ദേശം_TRANSPORT_MAX, &kex_protocol_error);
}

ശൂന്യം
kex_set_server_sig_algs(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *allowed_algs)
{
	അക്ഷരം *alg, *oalgs, *algs, *sigalgs;
	സ്ഥിരം അക്ഷരം *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	എങ്കിൽ ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ശൂന്യ)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	സ്വതന്ത്രം(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ശൂന്യ;
	വേണ്ടി ((alg = strsep(&algs, ",")); alg != ശൂന്യ && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		എങ്കിൽ ((sigalg = sshkey_sigalg_by_name(alg)) == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (!kex_has_any_alg(sigalg, sigalgs))
			തുടരുക;
		/* Don't add an algorithm twice. */
		എങ്കിൽ (ssh->kex->server_sig_algs != ശൂന്യ &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			തുടരുക;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	സ്വതന്ത്രം(oalgs);
	സ്വതന്ത്രം(sigalgs);
	എങ്കിൽ (ssh->kex->server_sig_algs == ശൂന്യ)
		ssh->kex->server_sig_algs = xstrdup("");
}

ശൂന്യം
kex_set_warn_weak_crypto(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ warn_weak_crypto)
{
	എങ്കിൽ (ssh != ശൂന്യ && ssh->kex != ശൂന്യ)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

ശൂന്യം
kex_check_warn_weak_crypto(ഘടന ssh *ssh)
{
	അക്ഷരം remote_id[512];
	പൂർണ്ണസംഖ്യ rekeyed = 0;

	എങ്കിൽ (ssh == ശൂന്യ || ssh->kex == ശൂന്യ || ssh->kex->name == ശൂന്യ ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		തിരികെ;
	എങ്കിൽ (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		തിരികെ;
	}

	എങ്കിൽ (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	എങ്കിൽ (!rekeyed && !ssh->kex->server)
		തിരികെ; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, വലുപ്പം(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_compose_ext_info_server(ഘടന ssh *ssh, ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ssh->kex->server_sig_algs == ശൂന്യ &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_compose_ext_info_client(ഘടന ssh *ssh, ഘടന sshbuf *m)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_maybe_send_ext_info(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *m = ശൂന്യ;

	എങ്കിൽ ((ssh->kex->flags & KEX_INITIAL) == 0)
		തിരികെ 0;
	എങ്കിൽ (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		തിരികെ 0;

	/* Compose EXT_INFO packet. */
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		പോകുക fail;
	എങ്കിൽ (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		പോകുക fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		പോകുക fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_server_update_ext_info(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		തിരികെ 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		തിരികെ r;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_send_newkeys(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	kex_reset_dispatch(ssh);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		തിരികെ r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_NEWKEYS, &kex_നിവേശം_newkeys);
	എങ്കിൽ ((r = kex_maybe_send_ext_info(ssh)) != 0)
		തിരികെ r;
	debug("expecting SSH2_MSG_NEWKEYS");
	തിരികെ 0;
}

/* Check whether an ext_info value contains the expected version string */
സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_ext_info_check_ver(ഘടന kex *kex, സ്ഥിരം അക്ഷരം *name,
    സ്ഥിരം u_char *val, size_t len, സ്ഥിരം അക്ഷരം *want_ver, u_int flag)
{
	എങ്കിൽ (memchr(val, '\0', len) != ശൂന്യ) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	എങ്കിൽ (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	അല്ലെങ്കിൽ
		debug_f("unsupported version of %s extension", name);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_ext_info_client_parse(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *name,
    സ്ഥിരം u_char *മൂല്യം, size_t vlen)
{
	പൂർണ്ണസംഖ്യ r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	എങ്കിൽ (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		എങ്കിൽ (memchr(മൂല്യം, '\0', vlen) != ശൂന്യ) {
			error_f("nul byte in %s", name);
			തിരികെ SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, മൂല്യം);
		സ്വതന്ത്രം(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((സ്ഥിരം അക്ഷരം *)മൂല്യം);
	} അല്ലെങ്കിൽ എങ്കിൽ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		എങ്കിൽ ((r = kex_ext_info_check_ver(ssh->kex, name, മൂല്യം, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			തിരികെ r;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		എങ്കിൽ ((r = kex_ext_info_check_ver(ssh->kex, name, മൂല്യം, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			തിരികെ r;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		എങ്കിൽ ((r = kex_ext_info_check_ver(ssh->kex, name, മൂല്യം, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			തിരികെ r;
		}
	} അല്ലെങ്കിൽ
		debug_f("%s (unrecognised)", name);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_ext_info_server_parse(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *name,
    സ്ഥിരം u_char *മൂല്യം, size_t vlen)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		എങ്കിൽ ((r = kex_ext_info_check_ver(ssh->kex, name, മൂല്യം, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			തിരികെ r;
		}
	} അല്ലെങ്കിൽ
		debug_f("%s (unrecognised)", name);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_നിവേശം_ext_info(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	സ്ഥിരം പൂർണ്ണസംഖ്യ max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	അക്ഷരം *name;
	u_char *val;
	size_t vlen;
	പൂർണ്ണസംഖ്യ r;

	debug("SSH2_MSG_EXT_INFO received");
	എങ്കിൽ (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		തിരികെ dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, &kex_protocol_error);
	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		തിരികെ r;
	എങ്കിൽ (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		തിരികെ dispatch_protocol_error(type, seq, ssh);
	}
	വേണ്ടി (i = 0; i < ninfo; i++) {
		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &name, ശൂന്യ)) != 0)
			തിരികെ r;
		എങ്കിൽ ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			സ്വതന്ത്രം(name);
			തിരികെ r;
		}
		debug3_f("extension %s", name);
		എങ്കിൽ (kex->server) {
			എങ്കിൽ ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				തിരികെ r;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				തിരികെ r;
		}
		സ്വതന്ത്രം(name);
		സ്വതന്ത്രം(val);
	}
	തിരികെ sshpkt_get_end(ssh);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_നിവേശം_newkeys(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	പൂർണ്ണസംഖ്യ r, initial = (kex->flags & KEX_INITIAL) != 0;
	അക്ഷരം *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	എങ്കിൽ (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, &kex_നിവേശം_ext_info);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEXINIT, &kex_നിവേശം_kexinit);
	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		തിരികെ r;
	എങ്കിൽ (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		എങ്കിൽ ((r = kex_buf2prop(kex->my, ശൂന്യ, &prop)) != 0)
			തിരികെ r;
		എങ്കിൽ ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ശൂന്യ) {
			error_f("match_filter_denylist failed");
			പോകുക fail;
		}
		സ്വതന്ത്രം(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		എങ്കിൽ ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			സ്വതന്ത്രം(prop);
			തിരികെ SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		സ്വതന്ത്രം(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_send_kexinit(ഘടന ssh *ssh)
{
	u_char *cookie;
	ഘടന kex *kex = ssh->kex;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (kex == ശൂന്യ) {
		error_f("no kex");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	എങ്കിൽ (kex->flags & KEX_INIT_SENT)
		തിരികെ 0;
	kex->done = 0;

	/* generate a random cookie */
	എങ്കിൽ (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	എങ്കിൽ ((cookie = sshbuf_mutable_ptr(kex->my)) == ശൂന്യ) {
		error_f("buffer error");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		തിരികെ r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_നിവേശം_kexinit(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	സ്ഥിരം u_char *ptr;
	u_int i;
	size_t dlen;
	പൂർണ്ണസംഖ്യ r;

	debug("SSH2_MSG_KEXINIT received");
	എങ്കിൽ (kex == ശൂന്യ) {
		error_f("no kex");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	സ്വതന്ത്രം(kex->name);
	kex->name = ശൂന്യ;
	എങ്കിൽ ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	എങ്കിൽ ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		തിരികെ r;

	/* discard packet */
	വേണ്ടി (i = 0; i < KEX_COOKIE_LEN; i++) {
		എങ്കിൽ ((r = sshpkt_get_u8(ssh, ശൂന്യ)) != 0) {
			error_fr(r, "discard cookie");
			തിരികെ r;
		}
	}
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		എങ്കിൽ ((r = sshpkt_get_string(ssh, ശൂന്യ, ശൂന്യ)) != 0) {
			error_fr(r, "discard proposal");
			തിരികെ r;
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
	എങ്കിൽ ((r = sshpkt_get_u8(ssh, ശൂന്യ)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ശൂന്യ)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			തിരികെ r;

	എങ്കിൽ (!(kex->flags & KEX_INIT_SENT))
		എങ്കിൽ ((r = kex_send_kexinit(ssh)) != 0)
			തിരികെ r;
	എങ്കിൽ ((r = kex_choose_conf(ssh, seq)) != 0)
		തിരികെ r;

	എങ്കിൽ (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ശൂന്യ)
		തിരികെ (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	തിരികെ SSH_ERR_INTERNAL_ERROR;
}

ഘടന kex *
kex_new(ശൂന്യം)
{
	ഘടന kex *kex;

	എങ്കിൽ ((kex = calloc(1, വലുപ്പം(*kex))) == ശൂന്യ ||
	    (kex->peer = sshbuf_new()) == ശൂന്യ ||
	    (kex->my = sshbuf_new()) == ശൂന്യ ||
	    (kex->client_version = sshbuf_new()) == ശൂന്യ ||
	    (kex->server_version = sshbuf_new()) == ശൂന്യ ||
	    (kex->session_id = sshbuf_new()) == ശൂന്യ) {
		kex_free(kex);
		തിരികെ ശൂന്യ;
	}
	തിരികെ kex;
}

ശൂന്യം
kex_free_newkeys(ഘടന newkeys *newkeys)
{
	എങ്കിൽ (newkeys == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (newkeys->enc.താക്കോൽ) {
		explicit_bzero(newkeys->enc.താക്കോൽ, newkeys->enc.താക്കോൽ_len);
		സ്വതന്ത്രം(newkeys->enc.താക്കോൽ);
		newkeys->enc.താക്കോൽ = ശൂന്യ;
	}
	എങ്കിൽ (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		സ്വതന്ത്രം(newkeys->enc.iv);
		newkeys->enc.iv = ശൂന്യ;
	}
	സ്വതന്ത്രം(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, വലുപ്പം(newkeys->enc));
	സ്വതന്ത്രം(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, വലുപ്പം(newkeys->comp));
	mac_clear(&newkeys->mac);
	എങ്കിൽ (newkeys->mac.താക്കോൽ) {
		explicit_bzero(newkeys->mac.താക്കോൽ, newkeys->mac.താക്കോൽ_len);
		സ്വതന്ത്രം(newkeys->mac.താക്കോൽ);
		newkeys->mac.താക്കോൽ = ശൂന്യ;
	}
	സ്വതന്ത്രം(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, വലുപ്പം(newkeys->mac));
	freezero(newkeys, വലുപ്പം(*newkeys));
}

ശൂന്യം
kex_free(ഘടന kex *kex)
{
	u_int mode;

	എങ്കിൽ (kex == ശൂന്യ)
		തിരികെ;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_താക്കോൽ_free(kex->ec_client_താക്കോൽ);
#endif /* WITH_OPENSSL */
	വേണ്ടി (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = ശൂന്യ;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	സ്വതന്ത്രം(kex->failed_choice);
	സ്വതന്ത്രം(kex->hostkey_alg);
	സ്വതന്ത്രം(kex->name);
	സ്വതന്ത്രം(kex->server_sig_algs);
	സ്വതന്ത്രം(kex);
}

പൂർണ്ണസംഖ്യ
kex_ready(ഘടന ssh *ssh, അക്ഷരം *proposal[PROPOSAL_MAX])
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		തിരികെ r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEXINIT, &kex_നിവേശം_kexinit);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_setup(ഘടന ssh *ssh, അക്ഷരം *proposal[PROPOSAL_MAX])
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = kex_ready(ssh, proposal)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ശൂന്യ;
		തിരികെ r;
	}
	തിരികെ 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
പൂർണ്ണസംഖ്യ
kex_start_rekex(ഘടന ssh *ssh)
{
	എങ്കിൽ (ssh->kex == ശൂന്യ) {
		error_f("no kex");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	എങ്കിൽ (ssh->kex->done == 0) {
		error_f("requested twice");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	തിരികെ kex_send_kexinit(ssh);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
choose_enc(ഘടന sshenc *enc, അക്ഷരം *client, അക്ഷരം *server)
{
	അക്ഷരം *name = match_list(client, server, ശൂന്യ);

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ SSH_ERR_NO_CIPHER_ALG_MATCH;
	എങ്കിൽ ((enc->cipher = cipher_by_name(name)) == ശൂന്യ) {
		error_f("unsupported cipher %s", name);
		സ്വതന്ത്രം(name);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ശൂന്യ;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->താക്കോൽ = ശൂന്യ;
	enc->താക്കോൽ_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
choose_mac(ഘടന ssh *ssh, ഘടന sshmac *mac, അക്ഷരം *client, അക്ഷരം *server)
{
	അക്ഷരം *name = match_list(client, server, ശൂന്യ);

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ SSH_ERR_NO_MAC_ALG_MATCH;
	എങ്കിൽ (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		സ്വതന്ത്രം(name);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->താക്കോൽ = ശൂന്യ;
	mac->enabled = 0;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
choose_comp(ഘടന sshcomp *comp, അക്ഷരം *client, അക്ഷരം *server)
{
	അക്ഷരം *name = match_list(client, server, ശൂന്യ);

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	എങ്കിൽ (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} അല്ലെങ്കിൽ
#endif	/* WITH_ZLIB */
	എങ്കിൽ (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} അല്ലെങ്കിൽ {
		error_f("unsupported compression scheme %s", name);
		സ്വതന്ത്രം(name);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
choose_kex(ഘടന kex *k, അക്ഷരം *client, അക്ഷരം *server)
{
	k->name = match_list(client, server, ശൂന്യ);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	എങ്കിൽ (k->name == ശൂന്യ)
		തിരികെ SSH_ERR_NO_KEX_ALG_MATCH;
	എങ്കിൽ (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
choose_hostkeyalg(ഘടന kex *k, അക്ഷരം *client, അക്ഷരം *server)
{
	സ്വതന്ത്രം(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, ശൂന്യ);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	എങ്കിൽ (k->hostkey_alg == ശൂന്യ)
		തിരികെ SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	എങ്കിൽ (k->hostkey_type == താക്കോൽ_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
proposals_match(അക്ഷരം *my[PROPOSAL_MAX], അക്ഷരം *peer[PROPOSAL_MAX])
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS, -1
	};
	പൂർണ്ണസംഖ്യ *idx;
	അക്ഷരം *p;

	വേണ്ടി (idx = &check[0]; *idx != -1; idx++) {
		എങ്കിൽ ((p = strchr(my[*idx], ',')) != ശൂന്യ)
			*p = '\0';
		എങ്കിൽ ((p = strchr(peer[*idx], ',')) != ശൂന്യ)
			*p = '\0';
		എങ്കിൽ (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			തിരികെ (0);
		}
	}
	debug2("proposals match");
	തിരികെ (1);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kexalgs_contains(അക്ഷരം **peer, സ്ഥിരം അക്ഷരം *ext)
{
	തിരികെ kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_choose_conf(ഘടന ssh *ssh, uint32_t seq)
{
	ഘടന kex *kex = ssh->kex;
	ഘടന newkeys *newkeys;
	അക്ഷരം **my = ശൂന്യ, **peer = ശൂന്യ;
	അക്ഷരം **cprop, **sprop;
	പൂർണ്ണസംഖ്യ nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	പൂർണ്ണസംഖ്യ r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	എങ്കിൽ ((r = kex_buf2prop(kex->my, ശൂന്യ, &my)) != 0)
		പോകുക out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	എങ്കിൽ ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		പോകുക out;

	എങ്കിൽ (kex->server) {
		cprop=peer;
		sprop=my;
	} അല്ലെങ്കിൽ {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	എങ്കിൽ ((kex->flags & KEX_INITIAL) != 0) {
		എങ്കിൽ (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} അല്ലെങ്കിൽ {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		എങ്കിൽ (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			എങ്കിൽ (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	എങ്കിൽ (kex->server && (kex->flags & KEX_INITIAL)) {
		എങ്കിൽ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		എങ്കിൽ (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	എങ്കിൽ ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ശൂന്യ;
		പോകുക out;
	}
	എങ്കിൽ ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS];
		peer[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = ശൂന്യ;
		പോകുക out;
	}
	വേണ്ടി (mode = 0; mode < MODE_MAX; mode++) {
		എങ്കിൽ ((newkeys = calloc(1, വലുപ്പം(*newkeys))) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		എങ്കിൽ ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ശൂന്യ;
			പോകുക out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		എങ്കിൽ (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ശൂന്യ;
			പോകുക out;
		}
		എങ്കിൽ ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ശൂന്യ;
			പോകുക out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	വേണ്ടി (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.താക്കോൽ_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.താക്കോൽ_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.താക്കോൽ_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	എങ്കിൽ (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
derive_താക്കോൽ(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, u_int need, u_char *hash, u_int hashlen,
    സ്ഥിരം ഘടന sshbuf *shared_secret, u_char **keyp)
{
	ഘടന kex *kex = ssh->kex;
	ഘടന ssh_digest_ctx *hashctx = ശൂന്യ;
	അക്ഷരം c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((digest = calloc(1, ROUNDUP(need, mdsz))) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	എങ്കിൽ ((hashctx = ssh_digest_start(kex->hash_alg)) == ശൂന്യ ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		പോകുക out;
	}
	ssh_digest_free(hashctx);
	hashctx = ശൂന്യ;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	വേണ്ടി (have = mdsz; need > have; have += mdsz) {
		എങ്കിൽ ((hashctx = ssh_digest_start(kex->hash_alg)) == ശൂന്യ ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		ssh_digest_free(hashctx);
		hashctx = ശൂന്യ;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = ശൂന്യ;
	r = 0;
 out:
	സ്വതന്ത്രം(digest);
	ssh_digest_free(hashctx);
	തിരികെ r;
}

#define NKEYS	6
പൂർണ്ണസംഖ്യ
kex_derive_താക്കോലുകൾ(ഘടന ssh *ssh, u_char *hash, u_int hashlen,
    സ്ഥിരം ഘടന sshbuf *shared_secret)
{
	ഘടന kex *kex = ssh->kex;
	u_char *താക്കോലുകൾ[NKEYS];
	u_int i, j, mode, ctos;
	പൂർണ്ണസംഖ്യ r;

	/* save initial hash as session id */
	എങ്കിൽ ((kex->flags & KEX_INITIAL) != 0) {
		എങ്കിൽ (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			തിരികെ SSH_ERR_INTERNAL_ERROR;
		}
		എങ്കിൽ ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			തിരികെ r;
	} അല്ലെങ്കിൽ എങ്കിൽ (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	വേണ്ടി (i = 0; i < NKEYS; i++) {
		എങ്കിൽ ((r = derive_താക്കോൽ(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &താക്കോലുകൾ[i])) != 0) {
			വേണ്ടി (j = 0; j < i; j++)
				സ്വതന്ത്രം(താക്കോലുകൾ[j]);
			തിരികെ r;
		}
	}
	വേണ്ടി (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = താക്കോലുകൾ[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.താക്കോൽ = താക്കോലുകൾ[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.താക്കോൽ = താക്കോലുകൾ[ctos ? 4 : 5];
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_load_hostkey(ഘടന ssh *ssh, ഘടന sshkey **prvp, ഘടന sshkey **pubp)
{
	ഘടന kex *kex = ssh->kex;

	*pubp = ശൂന്യ;
	*prvp = ശൂന്യ;
	എങ്കിൽ (kex->load_host_public_താക്കോൽ == ശൂന്യ ||
	    kex->load_host_private_താക്കോൽ == ശൂന്യ) {
		error_f("missing hostkey loader");
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_താക്കോൽ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_താക്കോൽ(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	എങ്കിൽ (*pubp == ശൂന്യ)
		തിരികെ SSH_ERR_NO_HOSTKEY_LOADED;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_verify_host_താക്കോൽ(ഘടന ssh *ssh, ഘടന sshkey *server_host_താക്കോൽ)
{
	ഘടന kex *kex = ssh->kex;

	എങ്കിൽ (kex->verify_host_താക്കോൽ == ശൂന്യ) {
		error_f("missing hostkey verifier");
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	എങ്കിൽ (server_host_താക്കോൽ->type != kex->hostkey_type ||
	    (kex->hostkey_type == താക്കോൽ_ECDSA &&
	    server_host_താക്കോൽ->ecdsa_nid != kex->hostkey_nid))
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
	എങ്കിൽ (kex->verify_host_താക്കോൽ(server_host_താക്കോൽ, ssh) == -1)
		തിരികെ  SSH_ERR_SIGNATURE_INVALID;
	തിരികെ 0;
}

#എങ്കിൽ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ശൂന്യം
dump_digest(സ്ഥിരം അക്ഷരം *സന്ദേശം, സ്ഥിരം u_char *digest, പൂർണ്ണസംഖ്യ len)
{
	fprintf(stderr, "%s\n", സന്ദേശം);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
സ്ഥിതം ശൂന്യം
send_error(ഘടന ssh *ssh, അക്ഷരം *സന്ദേശം)
{
	അക്ഷരം *crnl = "\r\n";

	എങ്കിൽ (!ssh->kex->server)
		തിരികെ;

	എങ്കിൽ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    സന്ദേശം, strlen(സന്ദേശം)) != strlen(സന്ദേശം) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
പൂർണ്ണസംഖ്യ
kex_exchange_identification(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ timeout_ms,
    സ്ഥിരം അക്ഷരം *version_addendum)
{
	പൂർണ്ണസംഖ്യ remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	പൂർണ്ണസംഖ്യ r, expect_nl;
	u_char c;
	ഘടന sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	ഘടന sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	അക്ഷരം *our_version_string = ശൂന്യ, *peer_version_string = ശൂന്യ;
	അക്ഷരം *cp, *remote_version = ശൂന്യ;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	എങ്കിൽ (version_addendum != ശൂന്യ && *version_addendum == '\0')
		version_addendum = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == ശൂന്യ ? "" : " ",
	    version_addendum == ശൂന്യ ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		പോകുക out;
	}

	എങ്കിൽ (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		പോകുക out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	എങ്കിൽ (our_version_string == ശൂന്യ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	വേണ്ടി (n = 0; ; n++) {
		എങ്കിൽ (n >= SSH_MAX_PRE_BANNER_വരികൾ) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_വരികൾ);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		വേണ്ടി (;;) {
			എങ്കിൽ (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, ശൂന്യ);
				എങ്കിൽ (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					പോകുക out;
				} അല്ലെങ്കിൽ എങ്കിൽ (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					പോകുക out;
				}
			}

			len = atomicio(പഠ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			എങ്കിൽ (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				പോകുക out;
			} അല്ലെങ്കിൽ എങ്കിൽ (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				പോകുക out;
			}
			എങ്കിൽ (c == '\r') {
				expect_nl = 1;
				തുടരുക;
			}
			എങ്കിൽ (c == '\n')
				നിർത്തുക;
			എങ്കിൽ (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				പോകുക invalid;
			}
			എങ്കിൽ ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				പോകുക out;
			}
			എങ്കിൽ (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				പോകുക invalid;
			}
		}
		/* Is this an actual protocol banner? */
		എങ്കിൽ (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			നിർത്തുക;
		/* If not, then just log the line and continue */
		എങ്കിൽ ((cp = sshbuf_dup_string(peer_version)) == ശൂന്യ) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		/* Do not accept lines before the SSH ident from a client */
		എങ്കിൽ (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			സ്വതന്ത്രം(cp);
			പോകുക invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		സ്വതന്ത്രം(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	എങ്കിൽ (peer_version_string == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	എങ്കിൽ ((remote_version = calloc(1, sshbuf_len(peer_version))) == ശൂന്യ) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	എങ്കിൽ (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	തിരഞ്ഞെടുപ്പ് (remote_major) {
	അവസ്ഥ 2:
		നിർത്തുക;
	അവസ്ഥ 1:
		എങ്കിൽ (remote_minor != 99)
			mismatch = 1;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		mismatch = 1;
		നിർത്തുക;
	}
	എങ്കിൽ (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		പോകുക out;
	}

	എങ്കിൽ (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		പോകുക out;
	}
	എങ്കിൽ (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(our_version_string);
	സ്വതന്ത്രം(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	എങ്കിൽ (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	തിരികെ r;
}

