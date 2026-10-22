/* $OpenBSD: sshconnect2.c,v 1.395 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਜੇ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ਅਨ੍ਤਰ੍ਭਾਵ <vis.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshconnect.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "msg.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ

/* import */
ਬਾਹਰੀ Options options;

/*
 * SSH2 key exchange
 */

ਸਥਿਰ ਅੱਖਰ *xxx_host;
ਸਥਿਰ ਬਣਤਰ sockaddr_storage xxx_hostaddr;
ਸਥਿਰ ਅਚਲ ਬਣਤਰ ssh_conn_info *xxx_conn_info;
ਸਥਿਰ ਪੂਰਨ ਕੁੰਜੀ_type_allowed(ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *);

ਸਥਿਰ ਪੂਰਨ
verify_host_ਕੁੰਜੀ_callback(ਬਣਤਰ sshkey *hostkey, ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(hostkey,
	    options.required_rsa_ਮਾਪ)) != 0)
		fatal_r(r, "Bad server host key");
	ਜੇ (!ਕੁੰਜੀ_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	ਜੇ (verify_host_ਕੁੰਜੀ(xxx_host, (ਬਣਤਰ sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	ਵਾਪਸ 0;
}

/* Returns the first item from a comma-separated algorithm list */
ਸਥਿਰ ਅੱਖਰ *
ਪਹਿਲਾ_alg(ਅਚਲ ਅੱਖਰ *algs)
{
	ਅੱਖਰ *ret, *cp;

	ret = xstrdup(algs);
	ਜੇ ((cp = strchr(ret, ',')) != ਨਿਰਾ)
		*cp = '\0';
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅੱਖਰ *
ਕ੍ਰਮ_hostkeyalgs(ਅੱਖਰ *host, ਬਣਤਰ sockaddr *hostaddr, u_short ਪੋਰਟ,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਅੱਖਰ *oavail = ਨਿਰਾ, *avail = ਨਿਰਾ, *ਪਹਿਲਾ = ਨਿਰਾ, *ਆਖਰੀ = ਨਿਰਾ;
	ਅੱਖਰ *alg = ਨਿਰਾ, *hostname = ਨਿਰਾ, *ret = ਨਿਰਾ, *ਉੱਤਮ = ਨਿਰਾ;
	ਮਾਪ_t maxlen;
	ਬਣਤਰ hostkeys *hostkeys = ਨਿਰਾ;
	ਪੂਰਨ ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, ਪੋਰਟ, &hostname, ਨਿਰਾ);
	hostkeys = init_hostkeys();
	ਲਈ (i = 0; i < options.ਅੰਕ_user_hostfiles; i++)
		ਲੱਦੋ_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	ਲਈ (i = 0; i < options.ਅੰਕ_system_hostfiles; i++) {
		ਲੱਦੋ_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	ਜੇ (options.ਗਿਆਤ_hosts_command != ਨਿਰਾ) {
		ਲੱਦੋ_hostkeys_command(hostkeys, options.ਗਿਆਤ_hosts_command,
		    "ORDER", cinfo, ਨਿਰਾ, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	ਉੱਤਮ = ਪਹਿਲਾ_alg(options.hostkeyalgorithms);
	ਜੇ (lookup_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(ਉੱਤਮ)),
	    sshkey_ecdsa_nid_from_name(ਉੱਤਮ), ਨਿਰਾ)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", ਉੱਤਮ);
		ret = xstrdup(options.hostkeyalgorithms);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = ਲੜੀ_ਲੰਬਾਈ(avail) + 1;
	ਪਹਿਲਾ = xmalloc(maxlen);
	ਆਖਰੀ = xmalloc(maxlen);
	*ਪਹਿਲਾ = *ਆਖਰੀ = '\0';

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ALG_APPEND(ਮੰਜ਼ਿਲ, from) \
	ਕਰੋ { \
		ਜੇ (*ਮੰਜ਼ਿਲ != '\0') \
			strlcat(ਮੰਜ਼ਿਲ, ",", maxlen); \
		strlcat(ਮੰਜ਼ਿਲ, from, maxlen); \
	} ਜਦੋਂ (0)

	ਜਦੋਂ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ਜੇ ((ktype = sshkey_type_from_name(alg)) == ਕੁੰਜੀ_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		ਜੇ (sshkey_type_is_cert(ktype) &&
		    lookup_marker_ਵਿੱਚ_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(ਪਹਿਲਾ, alg);
			ਜਾਰੀ;
		}
		/* If the key appears in known_hosts then prefer it */
		ਜੇ (lookup_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ਨਿਰਾ)) {
			ALG_APPEND(ਪਹਿਲਾ, alg);
			ਜਾਰੀ;
		}
		/* Otherwise, put it last */
		ALG_APPEND(ਆਖਰੀ, alg);
	}
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ALG_APPEND
	xasprintf(&ret, "%s%s%s", ਪਹਿਲਾ,
	    (*ਪਹਿਲਾ == '\0' || *ਆਖਰੀ == '\0') ? "" : ",", ਆਖਰੀ);
	ਜੇ (*ਪਹਿਲਾ != '\0')
		debug3_f("prefer hostkeyalgs: %s", ਪਹਿਲਾ);
	ਨਹੀਂਤਾਂ
		debug3_f("no algorithms matched; accept original");
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਉੱਤਮ);
	ਮੁਕਤ(ਪਹਿਲਾ);
	ਮੁਕਤ(ਆਖਰੀ);
	ਮੁਕਤ(hostname);
	ਮੁਕਤ(oavail);
	free_hostkeys(hostkeys);

	ਵਾਪਸ ret;
}

ਖਾਲੀ
ssh_kex2(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *host, ਬਣਤਰ sockaddr_storage *hostaddr,
    u_short ਪੋਰਟ, ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਅੱਖਰ *myproposal[PROPOSAL_MAX];
	ਅੱਖਰ *all_ਕੁੰਜੀ, *hkalgs = ਨਿਰਾ;
	ਪੂਰਨ r, use_ਗਿਆਤ_hosts_ਕ੍ਰਮ = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_ਸੈੱਟ_rekey_limits(ssh, options.rekey_ਹੱਦਬੰਦੀ,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	ਜੇ (options.hostkeyalgorithms == ਨਿਰਾ ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_ਗਿਆਤ_hosts_ਕ੍ਰਮ = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_ਕੁੰਜੀ = sshkey_alg_list(0, 0, 1, ',');
	ਜੇ ((r = kex_assemble_ਨਾਂ(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_ਕੁੰਜੀ)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	ਮੁਕਤ(all_ਕੁੰਜੀ);

	ਜੇ (use_ਗਿਆਤ_hosts_ਕ੍ਰਮ) {
		hkalgs = ਕ੍ਰਮ_hostkeyalgs(host, (ਬਣਤਰ sockaddr *)hostaddr,
		    ਪੋਰਟ, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	ਮੁਕਤ(hkalgs);

	/* start key exchange */
	ਜੇ ((r = kex_ਤਿਆਰੀ(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#ਜੇ_ਅੰਤ
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_ਕੁੰਜੀ=&verify_host_ਕੁੰਜੀ_callback;

	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ssh, DISPATCH_ਖੰਡ, &ssh->kex->ਪੂਰਾ);
	kex_proposal_free_entries(myproposal);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#ਜੇ_ਅੰਤ
}

/*
 * Authenticate user
 */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ cauthctxt Authctxt;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ cauthmethod Authmethod;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 ਪਛਾਣ_ਤੱਤ;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ idlist Idlist;

ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 {
	TAILQ_ENTRY(ਪਛਾਣ_ਤੱਤ_2) ਅਗਲਾ;
	ਪੂਰਨ	agent_fd;		/* >=0 if agent supports key */
	ਬਣਤਰ sshkey	*ਕੁੰਜੀ;		/* public/private key */
	ਅੱਖਰ	*filename;		/* comment for agent-only keys */
	ਪੂਰਨ	tried;
	ਪੂਰਨ	isprivate;		/* key points to the private key */
	ਪੂਰਨ	userprovided;
};
TAILQ_HEAD(idlist, ਪਛਾਣ_ਤੱਤ_2);

ਬਣਤਰ cauthctxt {
	ਅਚਲ ਅੱਖਰ *server_user;
	ਅਚਲ ਅੱਖਰ *local_user;
	ਅਚਲ ਅੱਖਰ *host;
	ਅਚਲ ਅੱਖਰ *service;
	ਬਣਤਰ cauthmethod *ਵਿਧੀ;
	sig_atomic_t success;
	ਅੱਖਰ *authlist;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	/* gssapi */
	gss_OID_ਸੈੱਟ gss_supported_mechs;
	u_int mech_tried;
#ਜੇ_ਅੰਤ
	/* pubkey */
	ਬਣਤਰ idlist ਕੁੰਜੀਆਂ;
	ਪੂਰਨ agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	ਅੱਖਰ *oktypes, *ktypes;
	ਅਚਲ ਅੱਖਰ *ਸਰਗਰਮ_ktype;
	/* kbd-interactive */
	ਪੂਰਨ info_req_ਵੇਖਿਆ;
	ਪੂਰਨ attempt_kbdint;
	/* password */
	ਪੂਰਨ attempt_passwd;
	/* generic */
	ਖਾਲੀ *methoddata;
};

ਬਣਤਰ cauthmethod {
	ਅੱਖਰ	*name;		/* string to compare against server's list */
	ਪੂਰਨ	(*userauth)(ਬਣਤਰ ssh *ssh);
	ਖਾਲੀ	(*cleanup)(ਬਣਤਰ ssh *ssh);
	ਪੂਰਨ	*enabled;	/* flag in option struct that enables method */
	ਪੂਰਨ	*batch_flag;	/* flag in option struct that disables method */
};

ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_service_accept(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_success(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_failure(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_banner(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_error(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_info_req(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_pk_ok(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_userauth_passwd_changereq(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

ਸਥਿਰ ਪੂਰਨ userauth_none(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ userauth_pubkey(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ userauth_passwd(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ userauth_kbdint(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ userauth_hostbased(ਬਣਤਰ ssh *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਸਥਿਰ ਪੂਰਨ userauth_gssapi(ਬਣਤਰ ssh *);
ਸਥਿਰ ਖਾਲੀ userauth_gssapi_cleanup(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_response(ਪੂਰਨ type, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_token(ਪੂਰਨ type, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_error(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_gssapi_errtok(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
#ਜੇ_ਅੰਤ

ਖਾਲੀ	userauth(ਬਣਤਰ ssh *, ਅੱਖਰ *);

ਸਥਿਰ ਖਾਲੀ pubkey_cleanup(ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ sign_and_send_pubkey(ਬਣਤਰ ssh *ssh, ਪਛਾਣ_ਤੱਤ *);
ਸਥਿਰ ਖਾਲੀ pubkey_prepare(ਬਣਤਰ ssh *, Authctxt *);
ਸਥਿਰ ਖਾਲੀ pubkey_reset(Authctxt *);
ਸਥਿਰ ਬਣਤਰ sshkey *ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ_file(ਪਛਾਣ_ਤੱਤ *);

ਸਥਿਰ Authmethod *authmethod_get(ਅੱਖਰ *authlist);
ਸਥਿਰ Authmethod *authmethod_lookup(ਅਚਲ ਅੱਖਰ *name);
ਸਥਿਰ ਅੱਖਰ *authmethods_get(ਖਾਲੀ);

Authmethod authmethods[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ਨਿਰਾ},
#ਜੇ_ਅੰਤ
	{"hostbased",
		userauth_hostbased,
		ਨਿਰਾ,
		&options.hostbased_authentication,
		ਨਿਰਾ},
	{"publickey",
		userauth_pubkey,
		ਨਿਰਾ,
		&options.pubkey_authentication,
		ਨਿਰਾ},
	{"keyboard-interactive",
		userauth_kbdint,
		ਨਿਰਾ,
		&options.kbd_interactive_authentication,
		&options.batch_ਬਹੁਲਕ},
	{"password",
		userauth_passwd,
		ਨਿਰਾ,
		&options.password_authentication,
		&options.batch_ਬਹੁਲਕ},
	{"none",
		userauth_none,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਨਿਰਾ},
	{ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ}
};

ਖਾਲੀ
ssh_userauth2(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *local_user,
    ਅਚਲ ਅੱਖਰ *server_user, ਅੱਖਰ *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	ਪੂਰਨ r;

	ਜੇ (options.preferred_authentications == ਨਿਰਾ)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, ਆਕਾਰ(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.ਵਿਧੀ = authmethod_lookup("none");
	authctxt.authlist = ਨਿਰਾ;
	authctxt.methoddata = ਨਿਰਾ;
	authctxt.sensitive = sensitive;
	authctxt.ਸਰਗਰਮ_ktype = authctxt.oktypes = authctxt.ktypes = ਨਿਰਾ;
	authctxt.info_req_ਵੇਖਿਆ = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#ਜੇ GSSAPI
	authctxt.gss_supported_mechs = ਨਿਰਾ;
	authctxt.mech_tried = 0;
#ਜੇ_ਅੰਤ
	authctxt.agent_fd = -1;
	ਜੇ (authctxt.ਵਿਧੀ == ਨਿਰਾ)
		fatal_f("internal error: cannot send userauth none request");

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &ਨਿਵੇਸ਼_userauth_error);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, kex_ਨਿਵੇਸ਼_ext_info);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_SERVICE_ACCEPT, &ਨਿਵੇਸ਼_userauth_service_accept);
	ssh_dispatch_ਲੜੀਵਾਰ_fatal(ssh, DISPATCH_ਖੰਡ, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	ਜੇ (authctxt.gss_supported_mechs != ਨਿਰਾ) {
		u_int ms;

		gss_release_oid_ਸੈੱਟ(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ਨਿਰਾ;
	}
#ਜੇ_ਅੰਤ
	ssh->authctxt = ਨਿਰਾ;

	ssh_dispatch_range(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_MIN, SSH2_ਸੁਨੇਹਾ_USERAUTH_MAX, ਨਿਰਾ);

	ਜੇ (!authctxt.success)
		fatal("Authentication failed.");
	ਜੇ (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh),
		    authctxt.ਵਿਧੀ->name);
	} ਨਹੀਂਤਾਂ {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.ਵਿਧੀ->name);
	}
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_service_accept(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;

	ਜੇ (ssh_packet_ਬਚਿਆ(ssh) > 0) {
		ਅੱਖਰ *ਜਵਾਬ;

		ਜੇ ((r = sshpkt_get_cstring(ssh, &ਜਵਾਬ, ਨਿਰਾ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		debug2("service_accept: %s", ਜਵਾਬ);
		ਮੁਕਤ(ਜਵਾਬ);
	} ਨਹੀਂਤਾਂ {
		debug2("buggy server: service_accept w/o service");
	}
	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_ਨਿਵੇਸ਼_ext_info : &ਨਿਵੇਸ਼_userauth_error);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS, &ਨਿਵੇਸ਼_userauth_success);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_FAILURE, &ਨਿਵੇਸ਼_userauth_failure);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_BANNER, &ਨਿਵੇਸ਼_userauth_banner);
	r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਖਾਲੀ
userauth(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ਜੇ (authctxt->ਵਿਧੀ != ਨਿਰਾ && authctxt->ਵਿਧੀ->cleanup != ਨਿਰਾ)
		authctxt->ਵਿਧੀ->cleanup(ssh);

	ਮੁਕਤ(authctxt->methoddata);
	authctxt->methoddata = ਨਿਰਾ;
	ਜੇ (authlist == ਨਿਰਾ) {
		authlist = authctxt->authlist;
	} ਨਹੀਂਤਾਂ {
		ਮੁਕਤ(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	ਲਈ (;;) {
		Authmethod *ਵਿਧੀ = authmethod_get(authlist);
		ਜੇ (ਵਿਧੀ == ਨਿਰਾ)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->ਵਿਧੀ = ਵਿਧੀ;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_ਪ੍ਰਤੀ_ਵਿਧੀ_MIN,
		    SSH2_ਸੁਨੇਹਾ_USERAUTH_ਪ੍ਰਤੀ_ਵਿਧੀ_MAX, ਨਿਰਾ);

		/* and try new method */
		ਜੇ (ਵਿਧੀ->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", ਵਿਧੀ->name);
			ਰੋਕੋ;
		} ਨਹੀਂਤਾਂ {
			debug2("we did not send a packet, disable method");
			ਵਿਧੀ->enabled = ਨਿਰਾ;
		}
	}
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_error(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_banner(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	debug3_f("entering");
	ਜੇ ((r = sshpkt_get_cstring(ssh, &ਸੁਨੇਹਾ, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", ਸੁਨੇਹਾ);
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਸੁਨੇਹਾ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_success(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal_f("no authentication context");
	ਮੁਕਤ(authctxt->authlist);
	authctxt->authlist = ਨਿਰਾ;
	ਜੇ (authctxt->ਵਿਧੀ != ਨਿਰਾ && authctxt->ਵਿਧੀ->cleanup != ਨਿਰਾ)
		authctxt->ਵਿਧੀ->cleanup(ssh);
	ਮੁਕਤ(authctxt->methoddata);
	authctxt->methoddata = ਨਿਰਾ;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, dispatch_protocol_error);
	ਵਾਪਸ 0;
}

#ਜੇ 0
ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_success_unexpected(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->ਵਿਧੀ->name);
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_failure(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਅੱਖਰ *authlist = ਨਿਰਾ;
	u_char partial;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_userauth_failure: no authentication context");

	ਜੇ (sshpkt_get_cstring(ssh, &authlist, ਨਿਰਾ) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_ਸਿਰਾ(ssh) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->ਵਿਧੀ->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(authlist);
	ਵਾਪਸ 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ਸਥਿਰ ਅੱਖਰ *
format_ਪਛਾਣ_ਤੱਤ(ਪਛਾਣ_ਤੱਤ *id)
{
	ਅੱਖਰ *fp = ਨਿਰਾ, *ret = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *note = "";

	ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ) {
		fp = sshkey_fingerprint(id->ਕੁੰਜੀ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	ਜੇ (id->ਕੁੰਜੀ) {
		ਜੇ ((id->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		ਨਹੀਂਤਾਂ ਜੇ (sshkey_is_sk(id->ਕੁੰਜੀ))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->ਕੁੰਜੀ ? sshkey_type(id->ਕੁੰਜੀ) : "", id->ਕੁੰਜੀ ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	ਮੁਕਤ(fp);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_pk_ok(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *keyblob = ਨਿਰਾ;
	ਪਛਾਣ_ਤੱਤ *id = ਨਿਰਾ;
	ਪੂਰਨ pktype, ਮਿਲਿਆ = 0, ਭੇਜਿਆ = 0;
	ਅੱਖਰ *pkalg = ਨਿਰਾ, *fp = ਨਿਰਾ, *ident = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal_f("no authentication context");

	ਜੇ ((r = sshpkt_get_cstring(ssh, &pkalg, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਪੂਰਾ;

	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((pktype = sshkey_type_from_name(pkalg)) == ਕੁੰਜੀ_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਪੂਰਾ;
	}
	/* inner key type should match signature type */
	ਜੇ ((r = sshkey_fromb_allowlist(keyblob, &ਕੁੰਜੀ, pkalg, ਨਿਰਾ)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (ਕੁੰਜੀ->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    ਕੁੰਜੀ->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਪੂਰਾ;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_ਉਲਟ(id, &authctxt->ਕੁੰਜੀਆਂ, idlist, ਅਗਲਾ) {
		ਜੇ (sshkey_equal(ਕੁੰਜੀ, id->ਕੁੰਜੀ)) {
			ਮਿਲਿਆ = 1;
			ਰੋਕੋ;
		}
	}
	ਜੇ (!ਮਿਲਿਆ || id == ਨਿਰਾ) {
		fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(ਕੁੰਜੀ), fp == ਨਿਰਾ ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਪੂਰਾ;
	}
	ident = format_ਪਛਾਣ_ਤੱਤ(id);
	debug("Server accepts key: %s", ident);
	ਭੇਜਿਆ = sign_and_send_pubkey(ssh, id);
	r = 0;
 ਪੂਰਾ:
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(keyblob);
	ਮੁਕਤ(ident);
	ਮੁਕਤ(fp);
	ਮੁਕਤ(pkalg);

	/* try another method if we did not send a packet */
	ਜੇ (r == 0 && ਭੇਜਿਆ == 0)
		userauth(ssh, ਨਿਰਾ);
	ਵਾਪਸ r;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
ਸਥਿਰ ਪੂਰਨ
userauth_gssapi(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ਨਿਰਾ;
	OM_uint32 min;
	ਪੂਰਨ r, ok = 0;
	gss_OID mech = ਨਿਰਾ;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	ਜੇ (authctxt->gss_supported_mechs == ਨਿਰਾ)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	ਜਦੋਂ (authctxt->mech_tried < authctxt->gss_supported_mechs->ਗਿਣਤੀ_2 &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		ਜੇ (mech->ਲੰਮਾਈ < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} ਨਹੀਂਤਾਂ {
			authctxt->mech_tried++;
		}
	}

	ਜੇ (!ok || mech == ਨਿਰਾ)
		ਵਾਪਸ 0;

	authctxt->methoddata=(ਖਾਲੀ *)gssctxt;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->ਲੰਮਾਈ) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->ਲੰਮਾਈ)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->ਲੰਮਾਈ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_RESPONSE, &ਨਿਵੇਸ਼_gssapi_response);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN, &ਨਿਵੇਸ਼_gssapi_token);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERROR, &ਨਿਵੇਸ਼_gssapi_error);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK, &ਨਿਵੇਸ਼_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
userauth_gssapi_cleanup(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ਨਿਰਾ;
}

ਸਥਿਰ OM_uint32
process_gssapi_token(ਬਣਤਰ ssh *ssh, gss_ਬਫਰ_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_ਬਫਰ_desc send_tok = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	gss_ਬਫਰ_desc mic = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	gss_ਬਫਰ_desc gssbuf;
	OM_uint32 ਸਥਿਤੀ, ms, flags;
	ਪੂਰਨ r;

	ਸਥਿਤੀ = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	ਜੇ (send_tok.ਲੰਮਾਈ > 0) {
		u_char type = GSS_ERROR(ਸਥਿਤੀ) ?
		    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_TOKEN;

		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.ਮੁੱਲ,
		    send_tok.ਲੰਮਾਈ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_ਬਫਰ(&ms, &send_tok);
	}

	ਜੇ (ਸਥਿਤੀ == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		ਜੇ (!(flags & GSS_C_INTEG_FLAG)) {
			ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
			    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} ਨਹੀਂਤਾਂ {
			ਬਣਤਰ sshbuf *b;

			ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			ਜੇ ((gssbuf.ਮੁੱਲ = sshbuf_mutable_ptr(b)) == ਨਿਰਾ)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.ਲੰਮਾਈ = sshbuf_len(b);

			ਸਥਿਤੀ = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			ਜੇ (!GSS_ERROR(ਸਥਿਤੀ)) {
				ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh,
				    SSH2_ਸੁਨੇਹਾ_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.ਮੁੱਲ,
				    mic.ਲੰਮਾਈ)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_ਬਫਰ(&ms, &mic);
		}
	}

	ਵਾਪਸ ਸਥਿਤੀ;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_response(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ਮਾਪ_t oidlen;
	u_char *oidv = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	ਜੇ ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		ਜਾਓ ਪੂਰਾ;

	ਜੇ (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ਨਿਰਾ);
		ਜਾਓ ok;
	}

	ਜੇ (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਪੂਰਾ;

	ਜੇ (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_ਬਫਰ))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ਨਿਰਾ);
		ਜਾਓ ok;
	}
 ok:
	r = 0;
 ਪੂਰਾ:
	ਮੁਕਤ(oidv);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_token(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_ਬਫਰ_desc recv_tok;
	u_char *p = ਨਿਰਾ;
	ਮਾਪ_t len;
	OM_uint32 ਸਥਿਤੀ;
	ਪੂਰਨ r;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_gssapi_response: no authentication context");

	ਜੇ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	recv_tok.ਮੁੱਲ = p;
	recv_tok.ਲੰਮਾਈ = len;
	ਸਥਿਤੀ = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	ਜੇ (GSS_ERROR(ਸਥਿਤੀ)) {
		userauth(ssh, ਨਿਰਾ);
		/* ok */
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(p);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_errtok(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_ਬਫਰ_desc send_tok = GSS_C_ਖਾਲੀ_ਥਾਵਾਂ_ਬਫਰ;
	gss_ਬਫਰ_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ਨਿਰਾ;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	ਜੇ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0) {
		ਮੁਕਤ(p);
		ਵਾਪਸ r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.ਮੁੱਲ = p;
	recv_tok.ਲੰਮਾਈ = len;
	(ਖਾਲੀ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ਨਿਰਾ);
	ਮੁਕਤ(p);
	gss_release_ਬਫਰ(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_gssapi_error(ਪੂਰਨ type, uint32_t plen, ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਅੱਖਰ *lang = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_get_u32(ssh, ਨਿਰਾ)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ਨਿਰਾ)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = sshpkt_get_ਸਿਰਾ(ssh);
	debug("Server GSSAPI Error:\n%s", ਸੁਨੇਹਾ);
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਸੁਨੇਹਾ);
	ਮੁਕਤ(lang);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* GSSAPI */

ਸਥਿਰ ਪੂਰਨ
userauth_none(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਪੂਰਨ r;

	/* initial userauth request */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
userauth_passwd(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਅੱਖਰ *password, *prompt = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *host = options.host_ਕੁੰਜੀ_alias ?  options.host_ਕੁੰਜੀ_alias :
	    authctxt->host;
	ਪੂਰਨ r;

	ਜੇ (authctxt->attempt_passwd++ >= options.ਸੰਖਿਆ_ਦਾ_password_prompts)
		ਵਾਪਸ 0;

	ਜੇ (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_ਜੋੜੋ_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ਮੁਕਤ(prompt);
	ਜੇ (password != ਨਿਰਾ)
		freezero(password, ਲੜੀ_ਲੰਬਾਈ(password));

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_PASSWD_CHANGEREQ,
	    &ਨਿਵੇਸ਼_userauth_passwd_changereq);

	ਵਾਪਸ 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_passwd_changereq(ਪੂਰਨ type, uint32_t seqnr, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਅੱਖਰ *info = ਨਿਰਾ, *lang = ਨਿਰਾ, *password = ਨਿਰਾ, *retype = ਨਿਰਾ;
	ਅੱਖਰ prompt[256];
	ਅਚਲ ਅੱਖਰ *host;
	ਪੂਰਨ r, addnl;
	ਮਾਪ_t len;

	debug2("input_userauth_passwd_changereq");

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_ਕੁੰਜੀ_alias ? options.host_ਕੁੰਜੀ_alias : authctxt->host;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &info, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((len = ਲੜੀ_ਲੰਬਾਈ(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		ਜਾਓ ਬਾਹਰਲਾ;

	snprintf(prompt, ਆਕਾਰ(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ਜੇ ((r = sshpkt_put_cstring(ssh, password)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	freezero(password, ਲੜੀ_ਲੰਬਾਈ(password));
	password = ਨਿਰਾ;
	ਜਦੋਂ (password == ਨਿਰਾ) {
		snprintf(prompt, ਆਕਾਰ(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		ਜੇ (password == ਨਿਰਾ) {
			/* bail out */
			r = 0;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		snprintf(prompt, ਆਕਾਰ(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		ਜੇ (strcmp(password, retype) != 0) {
			freezero(password, ਲੜੀ_ਲੰਬਾਈ(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ਨਿਰਾ;
		}
		freezero(retype, ਲੜੀ_ਲੰਬਾਈ(retype));
	}
	ਜੇ ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_ਜੋੜੋ_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_PASSWD_CHANGEREQ,
	    &ਨਿਵੇਸ਼_userauth_passwd_changereq);
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (password)
		freezero(password, ਲੜੀ_ਲੰਬਾਈ(password));
	ਮੁਕਤ(info);
	ਮੁਕਤ(lang);
	ਵਾਪਸ r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ਸਥਿਰ ਅੱਖਰ *
ਕੁੰਜੀ_sig_algorithm(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ *allowed, *oallowed, *cp, *tmp, *alg = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	ਜੇ (ssh == ਨਿਰਾ || ssh->kex->server_sig_algs == ਨਿਰਾ ||
	    (ਕੁੰਜੀ->type != ਕੁੰਜੀ_RSA && ਕੁੰਜੀ->type != ਕੁੰਜੀ_RSA_CERT) ||
	    (ਕੁੰਜੀ->type == ਕੁੰਜੀ_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		ਵਾਪਸ ਮੇਲ_list(sshkey_ssh_name(ਕੁੰਜੀ),
		    options.pubkey_accepted_algos, ਨਿਰਾ);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	ਜੇ (ਕੁੰਜੀ->type == ਕੁੰਜੀ_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	ਜਦੋਂ ((cp = strsep(&allowed, ",")) != ਨਿਰਾ) {
		ਜੇ (sshkey_type_from_name(cp) != ਕੁੰਜੀ->type)
			ਜਾਰੀ;
		tmp = ਮੇਲ_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ਨਿਰਾ);
		ਜੇ (tmp != ਨਿਰਾ)
			alg = xstrdup(cp);
		ਮੁਕਤ(tmp);
		ਜੇ (alg != ਨਿਰਾ)
			ਰੋਕੋ;
	}
	ਮੁਕਤ(oallowed);
	ਵਾਪਸ alg;
}

ਸਥਿਰ ਪੂਰਨ
ਪਛਾਣ_ਤੱਤ_sign(ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 *id, u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen, u_int compat, ਅਚਲ ਅੱਖਰ *alg)
{
	ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ = ਨਿਰਾ, *prv = ਨਿਰਾ;
	ਪੂਰਨ is_agent = 0, retried = 0, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ notifier_ctx *notifier = ਨਿਰਾ;
	ਅੱਖਰ *fp = ਨਿਰਾ, *pin = ਨਿਰਾ, *prompt = ਨਿਰਾ;

	*sigp = ਨਿਰਾ;
	*lenp = 0;

	/* The agent supports this key. */
	ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ && id->agent_fd != -1) {
		ਵਾਪਸ ssh_agent_sign(id->agent_fd, id->ਕੁੰਜੀ, sigp, lenp,
		    ਅੰਕੜੇ, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ &&
	    (id->isprivate || (id->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT))) {
		sign_ਕੁੰਜੀ = id->ਕੁੰਜੀ;
		is_agent = 1;
	} ਨਹੀਂਤਾਂ {
		/* Load the private key from the file. */
		ਜੇ ((prv = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ_file(id)) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
		ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ && !sshkey_equal_ਜਨਤਕ(prv, id->ਕੁੰਜੀ)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		sign_ਕੁੰਜੀ = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	ਜੇ (!is_agent && sshkey_is_sk(sign_ਕੁੰਜੀ) &&
	    (sign_ਕੁੰਜੀ->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		ਜੇ ((fp = sshkey_fingerprint(sign_ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ)
			fatal_f("fingerprint failed");
		notifier = notify_ਸ਼ੁਰੂ(options.batch_ਬਹੁਲਕ,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_ਕੁੰਜੀ), fp);
		ਮੁਕਤ(fp);
	}
	ਜੇ ((r = sshkey_sign(sign_ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ਜੇ (!retried && pin == ਨਿਰਾ && !is_agent &&
		    sshkey_is_sk(sign_ਕੁੰਜੀ) &&
		    r == SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ਨਿਰਾ);
			notifier = ਨਿਰਾ;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_ਕੁੰਜੀ), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			ਜਾਓ retry_pin;
		}
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ && (id->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(prompt);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ਨਿਰਾ);
	sshkey_free(prv);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
id_filename_matches(ਪਛਾਣ_ਤੱਤ *id, ਪਛਾਣ_ਤੱਤ *ਨਿੱਜੀ_id)
{
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ suffixes[] = { ".pub", "-cert.pub", ਨਿਰਾ };
	ਮਾਪ_t len = ਲੜੀ_ਲੰਬਾਈ(id->filename), plen = ਲੜੀ_ਲੰਬਾਈ(ਨਿੱਜੀ_id->filename);
	ਮਾਪ_t i, slen;

	ਜੇ (strcmp(id->filename, ਨਿੱਜੀ_id->filename) == 0)
		ਵਾਪਸ 1;
	ਲਈ (i = 0; suffixes[i]; i++) {
		slen = ਲੜੀ_ਲੰਬਾਈ(suffixes[i]);
		ਜੇ (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, ਨਿੱਜੀ_id->filename, plen) == 0)
			ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
sign_and_send_pubkey(ਬਣਤਰ ssh *ssh, ਪਛਾਣ_ਤੱਤ *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪਛਾਣ_ਤੱਤ *ਨਿੱਜੀ_id, *sign_id = ਨਿਰਾ;
	u_char *signature = ਨਿਰਾ;
	ਮਾਪ_t slen = 0, skip = 0;
	ਪੂਰਨ r, fallback_sigtype, ਭੇਜਿਆ = 0;
	ਅੱਖਰ *alg = ਨਿਰਾ, *fp = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *loc = "", *ਵਿਧੀ = "publickey";
	ਪੂਰਨ hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	ਜੇ ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		ਵਿਧੀ = "publickey-hostbound-v00@openssh.com";
	}

	ਜੇ ((fp = sshkey_fingerprint(id->ਕੁੰਜੀ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ)
		ਵਾਪਸ 0;

	debug3_f("using %s with %s %s", ਵਿਧੀ, sshkey_type(id->ਕੁੰਜੀ), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	ਜੇ (id->agent_fd == -1 && sshkey_is_cert(id->ਕੁੰਜੀ)) {
		TAILQ_FOREACH(ਨਿੱਜੀ_id, &authctxt->ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
			ਜੇ (sshkey_equal_ਜਨਤਕ(id->ਕੁੰਜੀ, ਨਿੱਜੀ_id->ਕੁੰਜੀ) &&
			    id->ਕੁੰਜੀ->type != ਨਿੱਜੀ_id->ਕੁੰਜੀ->type) {
				sign_id = ਨਿੱਜੀ_id;
				ਰੋਕੋ;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		ਜੇ (sign_id == ਨਿਰਾ &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(ਨਿੱਜੀ_id, &authctxt->ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
				ਜੇ (ਨਿੱਜੀ_id->ਕੁੰਜੀ == ਨਿਰਾ &&
				    id_filename_matches(id, ਨਿੱਜੀ_id)) {
					sign_id = ਨਿੱਜੀ_id;
					ਰੋਕੋ;
				}
			}
		}
		ਜੇ (sign_id != ਨਿਰਾ) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} ਨਹੀਂਤਾਂ {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	ਜੇ (sign_id == ਨਿਰਾ)
		sign_id = id;

	/* assemble and sign data */
	ਲਈ (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		ਮੁਕਤ(alg);
		slen = 0;
		signature = ਨਿਰਾ;
		ਜੇ ((alg = ਕੁੰਜੀ_sig_algorithm(fallback_sigtype ? ਨਿਰਾ : ssh,
		    id->ਕੁੰਜੀ)) == ਨਿਰਾ) {
			error_f("no mutual signature supported");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
			fatal_f("sshbuf_new failed");
		ਜੇ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		ਜੇ ((r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, ਵਿਧੀ)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->ਕੁੰਜੀ, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		ਜੇ (hostbound) {
			ਜੇ (ssh->kex->initial_hostkey == ਨਿਰਾ) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			ਜੇ ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", ਵਿਧੀ);
		}
		/* generate signature */
		r = ਪਛਾਣ_ਤੱਤ_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		ਜੇ (r == 0)
			ਰੋਕੋ;
		ਨਹੀਂਤਾਂ ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ)
			ਜਾਓ ਬਾਹਰਲਾ; /* soft failure */
		ਨਹੀਂਤਾਂ ਜੇ (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			ਜੇ (sign_id->agent_fd != -1)
				loc = "agent ";
			ਨਹੀਂਤਾਂ ਜੇ (sign_id->ਕੁੰਜੀ != ਨਿਰਾ &&
			    (sign_id->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->ਕੁੰਜੀ), fp);
			ਜਾਰੀ;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->ਕੁੰਜੀ), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (slen == 0 || signature == ਨਿਰਾ) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	ਜੇ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
	/* skip session id and packet type */
	ਜੇ ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	ਭੇਜਿਆ = 1;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(fp);
	ਮੁਕਤ(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	ਵਾਪਸ ਭੇਜਿਆ;
}

ਸਥਿਰ ਪੂਰਨ
send_pubkey_test(ਬਣਤਰ ssh *ssh, ਪਛਾਣ_ਤੱਤ *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ਨਿਰਾ;
	ਅੱਖਰ *alg = ਨਿਰਾ;
	ਮਾਪ_t bloblen;
	u_int have_sig = 0;
	ਪੂਰਨ ਭੇਜਿਆ = 0, r;

	ਜੇ ((alg = ਕੁੰਜੀ_sig_algorithm(ssh, id->ਕੁੰਜੀ)) == ਨਿਰਾ) {
		debug_f("no mutual signature algorithm");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_blob(id->ਕੁੰਜੀ, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_PK_OK, &ਨਿਵੇਸ਼_userauth_pk_ok);

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ਭੇਜਿਆ = 1;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(alg);
	ਮੁਕਤ(blob);
	ਵਾਪਸ ਭੇਜਿਆ;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ_file(ਪਛਾਣ_ਤੱਤ *id)
{
	ਬਣਤਰ sshkey *ਨਿਜੀ = ਨਿਰਾ;
	ਅੱਖਰ prompt[300], *passphrase, *comment;
	ਪੂਰਨ r, quit = 0, i;
	ਬਣਤਰ stat st;

	ਜੇ (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	snprintf(prompt, ਆਕਾਰ prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	ਲਈ (i = 0; i <= options.ਸੰਖਿਆ_ਦਾ_password_prompts; i++) {
		ਜੇ (i == 0)
			passphrase = "";
		ਨਹੀਂਤਾਂ {
			passphrase = read_passphrase(prompt, 0);
			ਜੇ (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				ਮੁਕਤ(passphrase);
				ਰੋਕੋ;
			}
		}
		ਚੋਣ ((r = sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type(ਕੁੰਜੀ_UNSPEC, id->filename,
		    passphrase, &ਨਿਜੀ, &comment))) {
		ਹਾਲਤ 0:
			ਰੋਕੋ;
		ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE:
			ਜੇ (options.batch_ਬਹੁਲਕ) {
				quit = 1;
				ਰੋਕੋ;
			}
			ਜੇ (i != 0)
				debug2("bad passphrase given, try again...");
			ਰੋਕੋ;
		ਹਾਲਤ SSH_ERR_SYSTEM_ERROR:
			ਜੇ (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				ਰੋਕੋ;
			}
			/* FALLTHROUGH */
		ਮੂਲ:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			ਰੋਕੋ;
		}
		ਜੇ (ਨਿਜੀ != ਨਿਰਾ && sshkey_is_sk(ਨਿਜੀ) &&
		    options.sk_provider == ਨਿਰਾ) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(ਨਿਜੀ);
			ਨਿਜੀ = ਨਿਰਾ;
			quit = 1;
		}
		ਜੇ (!quit && (r = sshkey_check_rsa_ਲੰਮਾਈ(ਨਿਜੀ,
		    options.required_rsa_ਮਾਪ)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(ਨਿਜੀ);
			ਨਿਜੀ = ਨਿਰਾ;
			quit = 1;
		}
		ਜੇ (!quit && ਨਿਜੀ != ਨਿਰਾ && id->agent_fd == -1 &&
		    !(id->ਕੁੰਜੀ && id->isprivate))
			maybe_ਜੋੜੋ_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_agent(id->filename, ਨਿਜੀ, comment,
			    passphrase);
		ਜੇ (i > 0)
			freezero(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase));
		ਮੁਕਤ(comment);
		ਜੇ (ਨਿਜੀ != ਨਿਰਾ || quit)
			ਰੋਕੋ;
	}
	ਵਾਪਸ ਨਿਜੀ;
}

ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_type_allowed(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *allowlist)
{
	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(sshkey_ssh_name(ਕੁੰਜੀ), allowlist, 0) == 1)
		ਵਾਪਸ 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	ਚੋਣ (ਕੁੰਜੀ->type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-512", allowlist, 0) == 1)
			ਵਾਪਸ 1;
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-256", allowlist, 0) == 1)
			ਵਾਪਸ 1;
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ਵਾਪਸ 1;
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ਵਾਪਸ 1;
		ਰੋਕੋ;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_type_allowed_by_config(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਵਾਪਸ ਕੁੰਜੀ_type_allowed(ਕੁੰਜੀ, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ਸਥਿਰ ਪੂਰਨ
get_agent_identities(ਬਣਤਰ ssh *ssh, ਪੂਰਨ *agent_fdp,
    ਬਣਤਰ ssh_identitylist **idlistp)
{
	ਪੂਰਨ r, agent_fd;
	ਬਣਤਰ ssh_identitylist *idlist;

	ਜੇ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ਜੇ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ਵਾਪਸ r;
	}
	ਜੇ (ssh != ਨਿਰਾ && ssh->kex != ਨਿਰਾ) {
		ਜੇ ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		ਨਹੀਂਤਾਂ
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	ਜੇ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		ਵਾਪਸ r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	ਵਾਪਸ 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
cert_has_option(ਬਣਤਰ sshbuf *oblob, ਅਚਲ ਅੱਖਰ *ਨਿਸ਼ਾਨਾ)
{
	ਬਣਤਰ sshbuf *c = ਨਿਰਾ, *ਅੰਕੜੇ = ਨਿਰਾ;
	ਅੱਖਰ *name = ਨਿਰਾ;
	ਪੂਰਨ r, ਮਿਲਿਆ = 0;

	ਜੇ (oblob == ਨਿਰਾ || (c = sshbuf_fromb(oblob)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜਦੋਂ (sshbuf_len(c) > 0) {
		sshbuf_free(ਅੰਕੜੇ);
		ਅੰਕੜੇ = ਨਿਰਾ;
		ਮੁਕਤ(name);
		name = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_cstring(c, &name, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_froms(c, &ਅੰਕੜੇ)) != 0)
			ਰੋਕੋ;
		ਜੇ (strcmp(name, ਨਿਸ਼ਾਨਾ) == 0) {
			ਮਿਲਿਆ = 1;
			ਰੋਕੋ;
		}
	}
	sshbuf_free(ਅੰਕੜੇ);
	ਮੁਕਤ(name);
	sshbuf_free(c);
	ਵਾਪਸ ਮਿਲਿਆ;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_ID_ਤਰਜੀਹ 3
ਸਥਿਰ ਪੂਰਨ
ਪਛਾਣ_ਤੱਤ_prioritise(ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 *id)
{
	ਜੇ (id == ਨਿਰਾ || id->ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ 3;
	ਜੇ (!sshkey_is_cert(id->ਕੁੰਜੀ) || id->ਕੁੰਜੀ->cert == ਨਿਰਾ)
		ਵਾਪਸ 3;
	ਜੇ (sshkey_is_sk(id->ਕੁੰਜੀ) &&
	    cert_has_option(id->ਕੁੰਜੀ->cert->critical, "verify-required"))
		ਵਾਪਸ 2;
	ਜੇ (sshkey_is_sk(id->ਕੁੰਜੀ) &&
	    cert_has_option(id->ਕੁੰਜੀ->cert->extensions, "no-touch-required"))
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
ਕ੍ਰਮ_identities_by_prio(ਬਣਤਰ idlist *list)
{
	ਬਣਤਰ idlist prio[MAX_ID_ਤਰਜੀਹ + 1], sorted;
	ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 *id, *tmp, *dummy;
	ਪੂਰਨ p;

	ਲਈ (p = 0; p <= MAX_ID_ਤਰਜੀਹ; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(id, list, ਅਗਲਾ, tmp) {
		ਜੇ (id->userprovided)
			ਜਾਰੀ;
		dummy = xcalloc(1, ਆਕਾਰ(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, ਅਗਲਾ);
		TAILQ_REMOVE(list, id, ਅਗਲਾ);
		p = ਪਛਾਣ_ਤੱਤ_prioritise(id);
		ਜੇ (p < 0 || p > MAX_ID_ਤਰਜੀਹ)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, ਅਗਲਾ);
	}
	ਲਈ (p = 0; p <= MAX_ID_ਤਰਜੀਹ; p++)
		TAILQ_CONCAT(&sorted, &prio[p], ਅਗਲਾ);

	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(id, list, ਅਗਲਾ, tmp) {
		ਜੇ (id->userprovided != -1)
			ਜਾਰੀ;
		ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, ਅਗਲਾ);
		TAILQ_INSERT_BEFORE(id, s, ਅਗਲਾ);
		TAILQ_REMOVE(list, id, ਅਗਲਾ);
		ਮੁਕਤ(id);
	}
}

/*
 * try keys in the following order:
 *	1. certificates listed in the config file
 *	2. agent keys that are found in the config file
 *	3. other agent keys
 *	4. PKCS#11 keys that are found in the config file
 *	5. keys that are only listed in the config file
 */
ਸਥਿਰ ਖਾਲੀ
pubkey_prepare(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
{
	ਬਣਤਰ ਪਛਾਣ_ਤੱਤ_2 *id, *id2, *tmp;
	ਬਣਤਰ idlist agent, files, certs, agent_ਕੁੰਜੀਆਂ, *preferred;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	ਪੂਰਨ disallowed, agent_fd = -1, i, r, ਮਿਲਿਆ;
	ਮਾਪ_t j;
	ਬਣਤਰ ssh_identitylist *idlist;
	ਅੱਖਰ *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_ਕੁੰਜੀਆਂ); /* keys supported by the agent */
	preferred = &authctxt->ਕੁੰਜੀਆਂ;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	ਲਈ (i = 0; i < options.ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files; i++) {
		ਕੁੰਜੀ = options.ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[i];
		ਜੇ (ਕੁੰਜੀ && ਕੁੰਜੀ->cert &&
		    ਕੁੰਜੀ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.ਪਛਾਣ_ਤੱਤ_files[i]);
			ਜਾਰੀ;
		}
		ਜੇ (ਕੁੰਜੀ && sshkey_is_sk(ਕੁੰਜੀ) && options.sk_provider == ਨਿਰਾ) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.ਪਛਾਣ_ਤੱਤ_files[i]);
			ਜਾਰੀ;
		}
		options.ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
		id = xcalloc(1, ਆਕਾਰ(*id));
		id->agent_fd = -1;
		id->ਕੁੰਜੀ = ਕੁੰਜੀ;
		id->filename = xstrdup(options.ਪਛਾਣ_ਤੱਤ_files[i]);
		id->userprovided = options.ਪਛਾਣ_ਤੱਤ_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, ਅਗਲਾ);
	}

	/* list of certificates specified by user */
	ਲਈ (i = 0; i < options.ਅੰਕ_certificate_files; i++) {
		ਕੁੰਜੀ = options.certificates[i];
		ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ) || ਕੁੰਜੀ->cert == ਨਿਰਾ ||
		    ਕੁੰਜੀ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.ਪਛਾਣ_ਤੱਤ_files[i]);
			ਜਾਰੀ;
		}
		ਜੇ (ਕੁੰਜੀ && sshkey_is_sk(ਕੁੰਜੀ) && options.sk_provider == ਨਿਰਾ) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.ਪਛਾਣ_ਤੱਤ_files[i]);
			ਜਾਰੀ;
		}
		id = xcalloc(1, ਆਕਾਰ(*id));
		id->agent_fd = -1;
		id->ਕੁੰਜੀ = ਕੁੰਜੀ;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, ਅਗਲਾ);
	}
	ਕ੍ਰਮ_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, ਅਗਲਾ);

	/* list of keys supported by the agent */
	ਜੇ ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		ਲਈ (j = 0; j < idlist->nkeys; j++) {
			ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(idlist->ਕੁੰਜੀਆਂ[j],
			    options.required_rsa_ਮਾਪ)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->ਕੁੰਜੀਆਂ[j]));
				ਜਾਰੀ;
			}
			ਮਿਲਿਆ = 0;
			TAILQ_FOREACH(id, &files, ਅਗਲਾ) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				ਜੇ (sshkey_equal(idlist->ਕੁੰਜੀਆਂ[j], id->ਕੁੰਜੀ)) {
					TAILQ_REMOVE(&files, id, ਅਗਲਾ);
					TAILQ_INSERT_TAIL(&agent_ਕੁੰਜੀਆਂ, id, ਅਗਲਾ);
					id->agent_fd = agent_fd;
					ਮਿਲਿਆ = 1;
					ਰੋਕੋ;
				}
			}
			ਜੇ (!ਮਿਲਿਆ && !options.identities_only) {
				id = xcalloc(1, ਆਕਾਰ(*id));
				/* XXX "steals" key/comment from idlist */
				id->ਕੁੰਜੀ = idlist->ਕੁੰਜੀਆਂ[j];
				id->filename = idlist->comments[j];
				idlist->ਕੁੰਜੀਆਂ[j] = ਨਿਰਾ;
				idlist->comments[j] = ਨਿਰਾ;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, ਅਗਲਾ);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_ਕੁੰਜੀਆਂ, &agent, ਅਗਲਾ);
		ਕ੍ਰਮ_identities_by_prio(&agent_ਕੁੰਜੀਆਂ);
		TAILQ_CONCAT(preferred, &agent_ਕੁੰਜੀਆਂ, ਅਗਲਾ);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(id, &files, ਅਗਲਾ, tmp) {
		ਜੇ (id->ਕੁੰਜੀ == ਨਿਰਾ || (id->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) == 0)
			ਜਾਰੀ;
		ਮਿਲਿਆ = 0;
		TAILQ_FOREACH(id2, &files, ਅਗਲਾ) {
			ਜੇ (id2->ਕੁੰਜੀ == ਨਿਰਾ ||
			    (id2->ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) != 0)
				ਜਾਰੀ;
			ਜੇ (sshkey_equal(id->ਕੁੰਜੀ, id2->ਕੁੰਜੀ)) {
				TAILQ_REMOVE(&files, id, ਅਗਲਾ);
				TAILQ_INSERT_TAIL(preferred, id, ਅਗਲਾ);
				ਮਿਲਿਆ = 1;
				ਰੋਕੋ;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		ਜੇ (!ਮਿਲਿਆ && options.identities_only) {
			TAILQ_REMOVE(&files, id, ਅਗਲਾ);
			freezero(id, ਆਕਾਰ(*id));
		}
	}
	ਕ੍ਰਮ_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, ਅਗਲਾ);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(id, preferred, ਅਗਲਾ, id2) {
		disallowed = 0;
		cp = ਨਿਰਾ;
		ਜੇ (id->ਕੁੰਜੀ == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (!ਕੁੰਜੀ_type_allowed_by_config(id->ਕੁੰਜੀ)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->ਕੁੰਜੀ), id->filename);
			disallowed = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (ssh != ਨਿਰਾ && ssh->kex != ਨਿਰਾ &&
		    ssh->kex->server_sig_algs != ਨਿਰਾ &&
		    (cp = ਕੁੰਜੀ_sig_algorithm(ssh, id->ਕੁੰਜੀ)) == ਨਿਰਾ) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->ਕੁੰਜੀ), id->filename);
			disallowed = 1;
		}
		ਮੁਕਤ(cp);
		ਜੇ (!disallowed)
			ਜਾਰੀ;
		/* remove key */
		TAILQ_REMOVE(preferred, id, ਅਗਲਾ);
		sshkey_free(id->ਕੁੰਜੀ);
		ਮੁਕਤ(id->filename);
		freezero(id, ਆਕਾਰ(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(id, preferred, ਅਗਲਾ, id2) {
		ident = format_ਪਛਾਣ_ਤੱਤ(id);
		debug("Will attempt key: %s", ident);
		ਮੁਕਤ(ident);
	}
	debug2_f("done");
}

ਸਥਿਰ ਖਾਲੀ
pubkey_cleanup(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਪਛਾਣ_ਤੱਤ *id;

	ਜੇ (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	ਲਈ (id = TAILQ_FIRST(&authctxt->ਕੁੰਜੀਆਂ); id;
	    id = TAILQ_FIRST(&authctxt->ਕੁੰਜੀਆਂ)) {
		TAILQ_REMOVE(&authctxt->ਕੁੰਜੀਆਂ, id, ਅਗਲਾ);
		sshkey_free(id->ਕੁੰਜੀ);
		ਮੁਕਤ(id->filename);
		ਮੁਕਤ(id);
	}
}

ਖਾਲੀ
pubkey_dump(ਬਣਤਰ ssh *ssh)
{
	Authctxt authctxt;
	ਪਛਾਣ_ਤੱਤ *id;
	ਅੱਖਰ *ident;

	memset(&authctxt, 0, ਆਕਾਰ(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
		ident = format_ਪਛਾਣ_ਤੱਤ(id);
		fprintf(stdout, "%s\n", ident);
		ਮੁਕਤ(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
pubkey_reset(Authctxt *authctxt)
{
	ਪਛਾਣ_ਤੱਤ *id;

	TAILQ_FOREACH(id, &authctxt->ਕੁੰਜੀਆਂ, ਅਗਲਾ)
		id->tried = 0;
}

ਸਥਿਰ ਪੂਰਨ
userauth_pubkey(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਪਛਾਣ_ਤੱਤ *id;
	ਪੂਰਨ ਭੇਜਿਆ = 0;
	ਅੱਖਰ *ident;
	ਸਥਿਰ ਪੂਰਨ prepared;

	ਜੇ (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	ਜਦੋਂ ((id = TAILQ_FIRST(&authctxt->ਕੁੰਜੀਆਂ))) {
		ਜੇ (id->tried++)
			ਵਾਪਸ (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->ਕੁੰਜੀਆਂ, id, ਅਗਲਾ);
		TAILQ_INSERT_TAIL(&authctxt->ਕੁੰਜੀਆਂ, id, ਅਗਲਾ);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ) {
			ident = format_ਪਛਾਣ_ਤੱਤ(id);
			debug("Offering public key: %s", ident);
			ਮੁਕਤ(ident);
			ਭੇਜਿਆ = send_pubkey_test(ssh, id);
		} ਨਹੀਂਤਾਂ {
			debug("Trying private key: %s", id->filename);
			id->ਕੁੰਜੀ = ਲੱਦੋ_ਪਛਾਣ_ਤੱਤ_file(id);
			ਜੇ (id->ਕੁੰਜੀ != ਨਿਰਾ) {
				id->isprivate = 1;
				ਭੇਜਿਆ = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->ਕੁੰਜੀ);
				id->ਕੁੰਜੀ = ਨਿਰਾ;
				id->isprivate = 0;
			}
		}
		ਜੇ (ਭੇਜਿਆ)
			ਵਾਪਸ (ਭੇਜਿਆ);
	}
	ਵਾਪਸ (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ਸਥਿਰ ਪੂਰਨ
userauth_kbdint(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਪੂਰਨ r;

	ਜੇ (authctxt->attempt_kbdint++ >= options.ਸੰਖਿਆ_ਦਾ_password_prompts)
		ਵਾਪਸ 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	ਜੇ (authctxt->attempt_kbdint > 1 && !authctxt->info_req_ਵੇਖਿਆ) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_REQUEST, ਨਿਰਾ);
		ਵਾਪਸ 0;
	}

	debug2("userauth_kbdint");
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_REQUEST, &ਨਿਵੇਸ਼_userauth_info_req);
	ਵਾਪਸ 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_userauth_info_req(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ਅੱਖਰ *name = ਨਿਰਾ, *inst = ਨਿਰਾ, *lang = ਨਿਰਾ, *prompt = ਨਿਰਾ;
	ਅੱਖਰ *display_prompt = ਨਿਰਾ, *response = ਨਿਰਾ;
	u_char echo = 0;
	u_int ਅੰਕ_prompts, i;
	ਪੂਰਨ r, addnl;
	ਮਾਪ_t len;

	debug2_f("entering");

	ਜੇ (authctxt == ਨਿਰਾ)
		fatal_f("no authentication context");

	authctxt->info_req_ਵੇਖਿਆ = 1;

	ਜੇ ((r = sshpkt_get_cstring(ssh, &name, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((len = ਲੜੀ_ਲੰਬਾਈ(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	ਜੇ ((len = ਲੜੀ_ਲੰਬਾਈ(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	ਜੇ ((r = sshpkt_get_u32(ssh, &ਅੰਕ_prompts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, ਅੰਕ_prompts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	debug2_f("num_prompts %d", ਅੰਕ_prompts);
	ਲਈ (i = 0; i < ਅੰਕ_prompts; i++) {
		ਜੇ ((r = sshpkt_get_cstring(ssh, &prompt, ਨਿਰਾ)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (asmprintf(&display_prompt, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, ਨਿਰਾ, "(%s@%s) %s",
		    authctxt->server_user, options.host_ਕੁੰਜੀ_alias ?
		    options.host_ਕੁੰਜੀ_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		ਜੇ ((r = sshpkt_put_cstring(ssh, response)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		freezero(response, ਲੜੀ_ਲੰਬਾਈ(response));
		ਮੁਕਤ(prompt);
		ਮੁਕਤ(display_prompt);
		display_prompt = response = prompt = ਨਿਰਾ;
	}
	/* done with parsing incoming message. */
	ਜੇ ((r = sshpkt_get_ਸਿਰਾ(ssh)) != 0 ||
	    (r = sshpkt_ਜੋੜੋ_padding(ssh, 64)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = sshpkt_send(ssh);
 ਬਾਹਰਲਾ:
	ਜੇ (response)
		freezero(response, ਲੜੀ_ਲੰਬਾਈ(response));
	ਮੁਕਤ(prompt);
	ਮੁਕਤ(display_prompt);
	ਮੁਕਤ(name);
	ਮੁਕਤ(inst);
	ਮੁਕਤ(lang);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_keysign(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen)
{
	ਬਣਤਰ sshbuf *b;
	ਬਣਤਰ stat st;
	pid_t pid;
	ਪੂਰਨ r, ਮੰਜ਼ਿਲ[2], from[2], ਸਥਿਤੀ;
	ਪੂਰਨ sock = ssh_packet_get_connection_ਵਿੱਚ(ssh);
	u_char rversion = 0, ਸੰਸਕਰਣ = 2;
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);

	*sigp = ਨਿਰਾ;
	*lenp = 0;

	ਜੇ (stat(ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (pipe(ਮੰਜ਼ਿਲ) == -1) {
		error_f("pipe: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	ਜੇ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ਵਾਪਸ -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ਜੇ (pid == 0) {
		close(from[0]);
		ਜੇ (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(ਮੰਜ਼ਿਲ[1]);
		ਜੇ (dup2(ਮੰਜ਼ਿਲ[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(ਮੰਜ਼ਿਲ[0]);

		ਜੇ (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		ਜੇ (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (ਲੰਮਾ)getpid(), ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN);
		execl(ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN, ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN, (ਅੱਖਰ *)ਨਿਰਾ);
		fatal_f("exec(%s): %s", ਰਸਤਾ_SSH_ਕੁੰਜੀ_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(ਮੰਜ਼ਿਲ[0]);
	sock = STDERR_FILENO + 1;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	ਜੇ ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, ਅੰਕੜੇ, datalen)) != 0)
		fatal_fr(r, "buffer error");
	ਜੇ (ssh_ਸੁਨੇਹਾ_send(ਮੰਜ਼ਿਲ[1], ਸੰਸਕਰਣ, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_ਸੁਨੇਹਾ_recv(from[0], b);
	close(from[0]);
	close(ਮੰਜ਼ਿਲ[1]);
	ਜੇ (r < 0) {
		error_f("no reply");
		ਜਾਓ fail;
	}

	errno = 0;
	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno != EINTR) {
			error_f("waitpid %ld: %s", (ਲੰਮਾ)pid, strerror(errno));
			ਜਾਓ fail;
		}
	}
	ਜੇ (!WIFEXITED(ਸਥਿਤੀ)) {
		error_f("exited abnormally");
		ਜਾਓ fail;
	}
	ਜੇ (WEXITSTATUS(ਸਥਿਤੀ) != 0) {
		error_f("exited with status %d", WEXITSTATUS(ਸਥਿਤੀ));
		ਜਾਓ fail;
	}
	ਜੇ ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		ਜਾਓ fail;
	}
	ਜੇ (rversion != ਸੰਸਕਰਣ) {
		error_f("bad version");
		ਜਾਓ fail;
	}
	ਜੇ ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		ਵਾਪਸ -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
userauth_hostbased(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਬਣਤਰ sshkey *ਨਿਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	u_char *sig = ਨਿਰਾ, *keyblob = ਨਿਰਾ;
	ਅੱਖਰ *fp = ਨਿਰਾ, *chost = ਨਿਰਾ, *lname = ਨਿਰਾ;
	ਮਾਪ_t siglen = 0, keylen = 0;
	ਪੂਰਨ i, r, success = 0;

	ਜੇ (authctxt->ktypes == ਨਿਰਾ) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	ਲਈ (;;) {
		ਜੇ (authctxt->ਸਰਗਰਮ_ktype == ਨਿਰਾ)
			authctxt->ਸਰਗਰਮ_ktype = strsep(&authctxt->ktypes, ",");
		ਜੇ (authctxt->ਸਰਗਰਮ_ktype == ਨਿਰਾ ||
		    *authctxt->ਸਰਗਰਮ_ktype == '\0')
			ਰੋਕੋ;
		debug3_f("trying key type %s", authctxt->ਸਰਗਰਮ_ktype);

		/* check for a useful key */
		ਨਿਜੀ = ਨਿਰਾ;
		ਲਈ (i = 0; i < authctxt->sensitive->nkeys; i++) {
			ਜੇ (authctxt->sensitive->ਕੁੰਜੀਆਂ[i] == ਨਿਰਾ ||
			    authctxt->sensitive->ਕੁੰਜੀਆਂ[i]->type == ਕੁੰਜੀ_UNSPEC)
				ਜਾਰੀ;
			ਜੇ (!sshkey_ਮੇਲ_keyname_ਮੰਜ਼ਿਲ_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->ਕੁੰਜੀਆਂ[i]),
			    authctxt->ਸਰਗਰਮ_ktype))
				ਜਾਰੀ;
			/* we take and free the key */
			ਨਿਜੀ = authctxt->sensitive->ਕੁੰਜੀਆਂ[i];
			authctxt->sensitive->ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
			ਰੋਕੋ;
		}
		/* Found one */
		ਜੇ (ਨਿਜੀ != ਨਿਰਾ)
			ਰੋਕੋ;
		/* No more keys of this type; advance */
		authctxt->ਸਰਗਰਮ_ktype = ਨਿਰਾ;
	}
	ਜੇ (ਨਿਜੀ == ਨਿਰਾ) {
		ਮੁਕਤ(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ਨਿਰਾ;
		authctxt->ਸਰਗਰਮ_ktype = ਨਿਰਾ;
		debug("No more client hostkeys for hostbased authentication.");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((fp = sshkey_fingerprint(ਨਿਜੀ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		error_f("sshkey_fingerprint failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(ਨਿਜੀ), fp, authctxt->ਸਰਗਰਮ_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_ਵਿੱਚ(ssh));
	ਜੇ (lname == ਨਿਰਾ) {
		error_f("cannot get local ipaddr/name");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		error_f("sshbuf_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_blob(ਨਿਜੀ, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->ਸਰਗਰਮ_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((r = ssh_keysign(ssh, ਨਿਜੀ, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(ਨਿਜੀ), fp);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਵਿਧੀ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ਸਰਗਰਮ_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	success = 1;

 ਬਾਹਰਲਾ:
	ਜੇ (sig != ਨਿਰਾ)
		freezero(sig, siglen);
	ਮੁਕਤ(keyblob);
	ਮੁਕਤ(lname);
	ਮੁਕਤ(fp);
	ਮੁਕਤ(chost);
	sshkey_free(ਨਿਜੀ);
	sshbuf_free(b);

	ਵਾਪਸ success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ਸਥਿਰ ਪੂਰਨ
authmethod_is_enabled(Authmethod *ਵਿਧੀ)
{
	ਜੇ (ਵਿਧੀ == ਨਿਰਾ)
		ਵਾਪਸ 0;
	/* return false if options indicate this method is disabled */
	ਜੇ  (ਵਿਧੀ->enabled == ਨਿਰਾ || *ਵਿਧੀ->enabled == 0)
		ਵਾਪਸ 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	ਜੇ  (ਵਿਧੀ->batch_flag != ਨਿਰਾ && *ਵਿਧੀ->batch_flag != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ Authmethod *
authmethod_lookup(ਅਚਲ ਅੱਖਰ *name)
{
	Authmethod *ਵਿਧੀ = ਨਿਰਾ;
	ਜੇ (name != ਨਿਰਾ)
		ਲਈ (ਵਿਧੀ = authmethods; ਵਿਧੀ->name != ਨਿਰਾ; ਵਿਧੀ++)
			ਜੇ (strcmp(name, ਵਿਧੀ->name) == 0)
				ਵਾਪਸ ਵਿਧੀ;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	ਵਾਪਸ ਨਿਰਾ;
}

/* XXX internal state */
ਸਥਿਰ Authmethod *current = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *supported = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *preferred = ਨਿਰਾ;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ਸਥਿਰ Authmethod *
authmethod_get(ਅੱਖਰ *authlist)
{
	ਅੱਖਰ *name = ਨਿਰਾ;
	u_int ਅਗਲਾ;

	/* Use a suitable default if we're passed a nil list.  */
	ਜੇ (authlist == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(authlist) == 0)
		authlist = options.preferred_authentications;

	ਜੇ (supported == ਨਿਰਾ || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		ਮੁਕਤ(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (current != ਨਿਰਾ && authmethod_is_enabled(current))
		ਵਾਪਸ current;

	ਲਈ (;;) {
		ਜੇ ((name = ਮੇਲ_list(preferred, supported, &ਅਗਲਾ)) == ਨਿਰਾ) {
			debug("No more authentication methods to try.");
			current = ਨਿਰਾ;
			ਵਾਪਸ ਨਿਰਾ;
		}
		preferred += ਅਗਲਾ;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		ਜੇ ((current = authmethod_lookup(name)) != ਨਿਰਾ &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			ਮੁਕਤ(name);
			ਵਾਪਸ current;
		}
		ਮੁਕਤ(name);
	}
}

ਸਥਿਰ ਅੱਖਰ *
authmethods_get(ਖਾਲੀ)
{
	Authmethod *ਵਿਧੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b;
	ਅੱਖਰ *list;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਲਈ (ਵਿਧੀ = authmethods; ਵਿਧੀ->name != ਨਿਰਾ; ਵਿਧੀ++) {
		ਜੇ (authmethod_is_enabled(ਵਿਧੀ)) {
			ਜੇ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", ਵਿਧੀ->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	ਜੇ ((list = sshbuf_dup_string(b)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ਵਾਪਸ list;
}
