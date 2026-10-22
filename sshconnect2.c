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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଯଦି defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ଅନ୍ତର୍ଭାଵ <vis.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshconnect.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "msg.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"

#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif

/* import */
ବାହ୍ୟ Options options;

/*
 * SSH2 key exchange
 */

ସ୍ଥିର ଅକ୍ଷର *xxx_host;
ସ୍ଥିର ସଂରଚନା sockaddr_storage xxx_hostaddr;
ସ୍ଥିର ଅଚଳ ସଂରଚନା ssh_conn_info *xxx_conn_info;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_type_allowed(ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
verify_host_ଚାବି_callback(ସଂରଚନା sshkey *hostkey, ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	ଯଦି (!ଚାବି_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	ଯଦି (verify_host_ଚାବି(xxx_host, (ସଂରଚନା sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	ଫେରନ୍ତୁ 0;
}

/* Returns the first item from a comma-separated algorithm list */
ସ୍ଥିର ଅକ୍ଷର *
first_alg(ଅଚଳ ଅକ୍ଷର *algs)
{
	ଅକ୍ଷର *ret, *cp;

	ret = xstrdup(algs);
	ଯଦି ((cp = strchr(ret, ',')) != ଖାଲି)
		*cp = '\0';
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅକ୍ଷର *
order_hostkeyalgs(ଅକ୍ଷର *host, ସଂରଚନା sockaddr *hostaddr, u_short port,
    ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ଅକ୍ଷର *oavail = ଖାଲି, *avail = ଖାଲି, *first = ଖାଲି, *last = ଖାଲି;
	ଅକ୍ଷର *alg = ଖାଲି, *hostname = ଖାଲି, *ret = ଖାଲି, *best = ଖାଲି;
	size_t maxlen;
	ସଂରଚନା hostkeys *hostkeys = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, ଖାଲି);
	hostkeys = init_hostkeys();
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	ଯଦି (options.known_hosts_command != ଖାଲି) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, ଖାଲି, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	ଯଦି (lookup_ଚାବି_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), ଖାଲି)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		ଯାଅ out;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = strlen(avail) + 1;
	first = xmalloc(maxlen);
	last = xmalloc(maxlen);
	*first = *last = '\0';

#define ALG_APPEND(to, from) \
	କର { \
		ଯଦି (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} ଯେତେବେଳେ (0)

	ଯେତେବେଳେ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ଯଦି ((ktype = sshkey_type_from_name(alg)) == ଚାବି_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		ଯଦି (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			ଜାରି;
		}
		/* If the key appears in known_hosts then prefer it */
		ଯଦି (lookup_ଚାବି_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ଖାଲି)) {
			ALG_APPEND(first, alg);
			ଜାରି;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	ଯଦି (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	ଅନ୍ୟଥା
		debug3_f("no algorithms matched; accept original");
 out:
	ମୁକ୍ତ(best);
	ମୁକ୍ତ(first);
	ମୁକ୍ତ(last);
	ମୁକ୍ତ(hostname);
	ମୁକ୍ତ(oavail);
	free_hostkeys(hostkeys);

	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
ssh_kex2(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *host, ସଂରଚନା sockaddr_storage *hostaddr,
    u_short port, ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ଅକ୍ଷର *myproposal[PROPOSAL_MAX];
	ଅକ୍ଷର *all_ଚାବି, *hkalgs = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, use_known_hosts_order = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	ଯଦି (options.hostkeyalgorithms == ଖାଲି ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_ଚାବି = sshkey_alg_list(0, 0, 1, ',');
	ଯଦି ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_ଚାବି)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	ମୁକ୍ତ(all_ଚାବି);

	ଯଦି (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (ସଂରଚନା sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	ମୁକ୍ତ(hkalgs);

	/* start key exchange */
	ଯଦି ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#ifdef WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#endif
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_ଚାବି=&verify_host_ଚାବି_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା cauthctxt Authctxt;
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା cauthmethod Authmethod;
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା identity Identity;
ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା idlist Idlist;

ସଂରଚନା identity {
	TAILQ_ENTRY(identity) next;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	agent_fd;		/* >=0 if agent supports key */
	ସଂରଚନା sshkey	*ଚାବି;		/* public/private key */
	ଅକ୍ଷର	*filename;		/* comment for agent-only keys */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	tried;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	isprivate;		/* key points to the private key */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	userprovided;
};
TAILQ_HEAD(idlist, identity);

ସଂରଚନା cauthctxt {
	ଅଚଳ ଅକ୍ଷର *server_user;
	ଅଚଳ ଅକ୍ଷର *local_user;
	ଅଚଳ ଅକ୍ଷର *host;
	ଅଚଳ ଅକ୍ଷର *service;
	ସଂରଚନା cauthmethod *method;
	sig_atomic_t success;
	ଅକ୍ଷର *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	ସଂରଚନା idlist ଚାବିଗୁଡ଼ିକ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	ଅକ୍ଷର *oktypes, *ktypes;
	ଅଚଳ ଅକ୍ଷର *active_ktype;
	/* kbd-interactive */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା info_req_seen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା attempt_kbdint;
	/* password */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା attempt_passwd;
	/* generic */
	ଶୂନ୍ୟ *methoddata;
};

ସଂରଚନା cauthmethod {
	ଅକ୍ଷର	*name;		/* string to compare against server's list */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*userauth)(ସଂରଚନା ssh *ssh);
	ଶୂନ୍ୟ	(*cleanup)(ସଂରଚନା ssh *ssh);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	*enabled;	/* flag in option struct that enables method */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	*batch_flag;	/* flag in option struct that disables method */
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_service_accept(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_success(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_failure(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_banner(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_info_req(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_pk_ok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_userauth_passwd_changereq(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା userauth_none(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା userauth_pubkey(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା userauth_passwd(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା userauth_kbdint(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା userauth_hostbased(ସଂରଚନା ssh *);

#ifdef GSSAPI
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା userauth_gssapi(ସଂରଚନା ssh *);
ସ୍ଥିର ଶୂନ୍ୟ userauth_gssapi_cleanup(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_response(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_token(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_gssapi_errtok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
#endif

ଶୂନ୍ୟ	userauth(ସଂରଚନା ssh *, ଅକ୍ଷର *);

ସ୍ଥିର ଶୂନ୍ୟ pubkey_cleanup(ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sign_and_send_pubkey(ସଂରଚନା ssh *ssh, Identity *);
ସ୍ଥିର ଶୂନ୍ୟ pubkey_prepare(ସଂରଚନା ssh *, Authctxt *);
ସ୍ଥିର ଶୂନ୍ୟ pubkey_reset(Authctxt *);
ସ୍ଥିର ସଂରଚନା sshkey *load_identity_file(Identity *);

ସ୍ଥିର Authmethod *authmethod_get(ଅକ୍ଷର *authlist);
ସ୍ଥିର Authmethod *authmethod_lookup(ଅଚଳ ଅକ୍ଷର *name);
ସ୍ଥିର ଅକ୍ଷର *authmethods_get(ଶୂନ୍ୟ);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ଖାଲି},
#endif
	{"hostbased",
		userauth_hostbased,
		ଖାଲି,
		&options.hostbased_authentication,
		ଖାଲି},
	{"publickey",
		userauth_pubkey,
		ଖାଲି,
		&options.pubkey_authentication,
		ଖାଲି},
	{"keyboard-interactive",
		userauth_kbdint,
		ଖାଲି,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		ଖାଲି,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		ଖାଲି,
		ଖାଲି,
		ଖାଲି},
	{ଖାଲି, ଖାଲି, ଖାଲି, ଖାଲି, ଖାଲି}
};

ଶୂନ୍ୟ
ssh_userauth2(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *local_user,
    ଅଚଳ ଅକ୍ଷର *server_user, ଅକ୍ଷର *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (options.preferred_authentications == ଖାଲି)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, ଆକାର(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = ଖାଲି;
	authctxt.methoddata = ଖାଲି;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = ଖାଲି;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#ଯଦି GSSAPI
	authctxt.gss_supported_mechs = ଖାଲି;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	ଯଦି (authctxt.method == ଖାଲି)
		fatal_f("internal error: cannot send userauth none request");

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &ନିବେଶ_userauth_error);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, kex_ନିବେଶ_ext_info);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_SERVICE_ACCEPT, &ନିବେଶ_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	ଯଦି (authctxt.gss_supported_mechs != ଖାଲି) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ଖାଲି;
	}
#endif
	ssh->authctxt = ଖାଲି;

	ssh_dispatch_range(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_MIN, SSH2_ସନ୍ଦେଶ_USERAUTH_MAX, ଖାଲି);

	ଯଦି (!authctxt.success)
		fatal("Authentication failed.");
	ଯଦି (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} ଅନ୍ୟଥା {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_service_accept(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ssh_packet_remaining(ssh) > 0) {
		ଅକ୍ଷର *reply;

		ଯଦି ((r = sshpkt_get_cstring(ssh, &reply, ଖାଲି)) != 0)
			ଯାଅ out;
		debug2("service_accept: %s", reply);
		ମୁକ୍ତ(reply);
	} ଅନ୍ୟଥା {
		debug2("buggy server: service_accept w/o service");
	}
	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_ନିବେଶ_ext_info : &ନିବେଶ_userauth_error);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_SUCCESS, &ନିବେଶ_userauth_success);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_FAILURE, &ନିବେଶ_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_BANNER, &ନିବେଶ_userauth_banner);
	r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

ଶୂନ୍ୟ
userauth(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ଯଦି (authctxt->method != ଖାଲି && authctxt->method->cleanup != ଖାଲି)
		authctxt->method->cleanup(ssh);

	ମୁକ୍ତ(authctxt->methoddata);
	authctxt->methoddata = ଖାଲି;
	ଯଦି (authlist == ଖାଲି) {
		authlist = authctxt->authlist;
	} ଅନ୍ୟଥା {
		ମୁକ୍ତ(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	ପାଇଁ (;;) {
		Authmethod *method = authmethod_get(authlist);
		ଯଦି (method == ଖାଲି)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PER_METHOD_MIN,
		    SSH2_ସନ୍ଦେଶ_USERAUTH_PER_METHOD_MAX, ଖାଲି);

		/* and try new method */
		ଯଦି (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			ଭାଙ୍ଗ;
		} ଅନ୍ୟଥା {
			debug2("we did not send a packet, disable method");
			method->enabled = ଖାଲି;
		}
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_banner(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");
	ଯଦି ((r = sshpkt_get_cstring(ssh, &ସନ୍ଦେଶ, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ଖାଲି, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", ସନ୍ଦେଶ);
	r = 0;
 out:
	ମୁକ୍ତ(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_success(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ଯଦି (authctxt == ଖାଲି)
		fatal_f("no authentication context");
	ମୁକ୍ତ(authctxt->authlist);
	authctxt->authlist = ଖାଲି;
	ଯଦି (authctxt->method != ଖାଲି && authctxt->method->cleanup != ଖାଲି)
		authctxt->method->cleanup(ssh);
	ମୁକ୍ତ(authctxt->methoddata);
	authctxt->methoddata = ଖାଲି;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, dispatch_protocol_error);
	ଫେରନ୍ତୁ 0;
}

#ଯଦି 0
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_success_unexpected(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ଯଦି (authctxt == ଖାଲି)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	ଫେରନ୍ତୁ 0;
}
#endif

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_failure(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ଅକ୍ଷର *authlist = ଖାଲି;
	u_char partial;

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_userauth_failure: no authentication context");

	ଯଦି (sshpkt_get_cstring(ssh, &authlist, ଖାଲି) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		ଯାଅ out;

	ଯଦି (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ଖାଲି;
 out:
	ମୁକ୍ତ(authlist);
	ଫେରନ୍ତୁ 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ସ୍ଥିର ଅକ୍ଷର *
format_identity(Identity *id)
{
	ଅକ୍ଷର *fp = ଖାଲି, *ret = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *note = "";

	ଯଦି (id->ଚାବି != ଖାଲି) {
		fp = sshkey_fingerprint(id->ଚାବି, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	ଯଦି (id->ଚାବି) {
		ଯଦି ((id->ଚାବି->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		ଅନ୍ୟଥା ଯଦି (sshkey_is_sk(id->ଚାବି))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->ଚାବି ? sshkey_type(id->ଚାବି) : "", id->ଚାବି ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	ମୁକ୍ତ(fp);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_pk_ok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *keyblob = ଖାଲି;
	Identity *id = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pktype, found = 0, sent = 0;
	ଅକ୍ଷର *pkalg = ଖାଲି, *fp = ଖାଲି, *ident = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt == ଖାଲି)
		fatal_f("no authentication context");

	ଯଦି ((r = sshpkt_get_cstring(ssh, &pkalg, ଖାଲି)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ done;

	ଯଦି (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ଯାଅ done;
	}
	ଯଦି ((pktype = sshkey_type_from_name(pkalg)) == ଚାବି_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ done;
	}
	/* inner key type should match signature type */
	ଯଦି ((r = sshkey_fromb_allowlist(keyblob, &ଚାବି, pkalg, ଖାଲି)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		ଯାଅ done;
	}
	ଯଦି (ଚାବି->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    ଚାବି->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->ଚାବିଗୁଡ଼ିକ, idlist, next) {
		ଯଦି (sshkey_equal(ଚାବି, id->ଚାବି)) {
			found = 1;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (!found || id == ଖାଲି) {
		fp = sshkey_fingerprint(ଚାବି, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(ଚାବି), fp == ଖାଲି ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(ଚାବି);
	sshbuf_free(keyblob);
	ମୁକ୍ତ(ident);
	ମୁକ୍ତ(fp);
	ମୁକ୍ତ(pkalg);

	/* try another method if we did not send a packet */
	ଯଦି (r == 0 && sent == 0)
		userauth(ssh, ଖାଲି);
	ଫେରନ୍ତୁ r;
}

#ifdef GSSAPI
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_gssapi(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ଖାଲି;
	OM_uint32 min;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ok = 0;
	gss_OID mech = ଖାଲି;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	ଯଦି (authctxt->gss_supported_mechs == ଖାଲି)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	ଯେତେବେଳେ (authctxt->mech_tried < authctxt->gss_supported_mechs->ଗଣନା_2 &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		ଯଦି (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} ଅନ୍ୟଥା {
			authctxt->mech_tried++;
		}
	}

	ଯଦି (!ok || mech == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	authctxt->methoddata=(ଶୂନ୍ୟ *)gssctxt;

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->length) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->length)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->length)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_RESPONSE, &ନିବେଶ_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN, &ନିବେଶ_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERROR, &ନିବେଶ_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK, &ନିବେଶ_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
userauth_gssapi_cleanup(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ଖାଲି;
}

ସ୍ଥିର OM_uint32
process_gssapi_token(ସଂରଚନା ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	ଯଦି (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_TOKEN;

		ଯଦି ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.ମୂଲ୍ୟ,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	ଯଦି (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		ଯଦି (!(flags & GSS_C_INTEG_FLAG)) {
			ଯଦି ((r = sshpkt_start(ssh,
			    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} ଅନ୍ୟଥା {
			ସଂରଚନା sshbuf *b;

			ଯଦି ((b = sshbuf_new()) == ଖାଲି)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			ଯଦି ((gssbuf.ମୂଲ୍ୟ = sshbuf_mutable_ptr(b)) == ଖାଲି)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			ଯଦି (!GSS_ERROR(status)) {
				ଯଦି ((r = sshpkt_start(ssh,
				    SSH2_ସନ୍ଦେଶ_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.ମୂଲ୍ୟ,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	ଫେରନ୍ତୁ status;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_response(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	ଯଦି ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		ଯାଅ done;

	ଯଦି (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ଖାଲି);
		ଯାଅ ok;
	}

	ଯଦି (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	ଯଦି ((r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ done;

	ଯଦି (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ଖାଲି);
		ଯାଅ ok;
	}
 ok:
	r = 0;
 done:
	ମୁକ୍ତ(oidv);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_token(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = ଖାଲି;
	size_t len;
	OM_uint32 status;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_gssapi_response: no authentication context");

	ଯଦି ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;

	recv_tok.ମୂଲ୍ୟ = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	ଯଦି (GSS_ERROR(status)) {
		userauth(ssh, ଖାଲି);
		/* ok */
	}
	r = 0;
 out:
	ମୁକ୍ତ(p);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_errtok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ଖାଲି;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	ଯଦି ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		ମୁକ୍ତ(p);
		ଫେରନ୍ତୁ r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.ମୂଲ୍ୟ = p;
	recv_tok.length = len;
	(ଶୂନ୍ୟ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ଖାଲି);
	ମୁକ୍ତ(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_gssapi_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t plen, ସଂରଚନା ssh *ssh)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;
	ଅକ୍ଷର *lang = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_get_u32(ssh, ଖାଲି)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ଖାଲି)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &ସନ୍ଦେଶ, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ଖାଲି)) != 0)
		ଯାଅ out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", ସନ୍ଦେଶ);
 out:
	ମୁକ୍ତ(ସନ୍ଦେଶ);
	ମୁକ୍ତ(lang);
	ଫେରନ୍ତୁ r;
}
#endif /* GSSAPI */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_none(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* initial userauth request */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_passwd(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ଅକ୍ଷର *password, *prompt = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *host = options.host_ଚାବି_alias ?  options.host_ଚାବି_alias :
	    authctxt->host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt->attempt_passwd++ >= options.ସଂଖ୍ୟା_of_password_prompts)
		ଫେରନ୍ତୁ 0;

	ଯଦି (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ମୁକ୍ତ(prompt);
	ଯଦି (password != ଖାଲି)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PASSWD_CHANGEREQ,
	    &ନିବେଶ_userauth_passwd_changereq);

	ଫେରନ୍ତୁ 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_passwd_changereq(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seqnr, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ଅକ୍ଷର *info = ଖାଲି, *lang = ଖାଲି, *password = ଖାଲି, *retype = ଖାଲି;
	ଅକ୍ଷର prompt[256];
	ଅଚଳ ଅକ୍ଷର *host;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	ଯଦି (authctxt == ଖାଲି)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_ଚାବି_alias ? options.host_ଚାବି_alias : authctxt->host;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &info, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		ଯାଅ out;

	snprintf(prompt, ଆକାର(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ଯଦି ((r = sshpkt_put_cstring(ssh, password)) != 0)
		ଯାଅ out;

	freezero(password, strlen(password));
	password = ଖାଲି;
	ଯେତେବେଳେ (password == ଖାଲି) {
		snprintf(prompt, ଆକାର(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		ଯଦି (password == ଖାଲି) {
			/* bail out */
			r = 0;
			ଯାଅ out;
		}
		snprintf(prompt, ଆକାର(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		ଯଦି (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ଖାଲି;
		}
		freezero(retype, strlen(retype));
	}
	ଯଦି ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଯାଅ out;

	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PASSWD_CHANGEREQ,
	    &ନିବେଶ_userauth_passwd_changereq);
	r = 0;
 out:
	ଯଦି (password)
		freezero(password, strlen(password));
	ମୁକ୍ତ(info);
	ମୁକ୍ତ(lang);
	ଫେରନ୍ତୁ r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ସ୍ଥିର ଅକ୍ଷର *
ଚାବି_sig_algorithm(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର *allowed, *oallowed, *cp, *tmp, *alg = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	ଯଦି (ssh == ଖାଲି || ssh->kex->server_sig_algs == ଖାଲି ||
	    (ଚାବି->type != ଚାବି_RSA && ଚାବି->type != ଚାବି_RSA_CERT) ||
	    (ଚାବି->type == ଚାବି_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		ଫେରନ୍ତୁ match_list(sshkey_ssh_name(ଚାବି),
		    options.pubkey_accepted_algos, ଖାଲି);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	ଯଦି (ଚାବି->type == ଚାବି_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	ଯେତେବେଳେ ((cp = strsep(&allowed, ",")) != ଖାଲି) {
		ଯଦି (sshkey_type_from_name(cp) != ଚାବି->type)
			ଜାରି;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ଖାଲି);
		ଯଦି (tmp != ଖାଲି)
			alg = xstrdup(cp);
		ମୁକ୍ତ(tmp);
		ଯଦି (alg != ଖାଲି)
			ଭାଙ୍ଗ;
	}
	ମୁକ୍ତ(oallowed);
	ଫେରନ୍ତୁ alg;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
identity_sign(ସଂରଚନା identity *id, u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen, u_int compat, ଅଚଳ ଅକ୍ଷର *alg)
{
	ସଂରଚନା sshkey *sign_ଚାବି = ଖାଲି, *prv = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା notifier_ctx *notifier = ଖାଲି;
	ଅକ୍ଷର *fp = ଖାଲି, *pin = ଖାଲି, *prompt = ଖାଲି;

	*sigp = ଖାଲି;
	*lenp = 0;

	/* The agent supports this key. */
	ଯଦି (id->ଚାବି != ଖାଲି && id->agent_fd != -1) {
		ଫେରନ୍ତୁ ssh_agent_sign(id->agent_fd, id->ଚାବି, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	ଯଦି (id->ଚାବି != ଖାଲି &&
	    (id->isprivate || (id->ଚାବି->flags & SSHKEY_FLAG_EXT))) {
		sign_ଚାବି = id->ଚାବି;
		is_agent = 1;
	} ଅନ୍ୟଥା {
		/* Load the private key from the file. */
		ଯଦି ((prv = load_identity_file(id)) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ଚାବି_NOT_FOUND;
		ଯଦି (id->ଚାବି != ଖାଲି && !sshkey_equal_public(prv, id->ଚାବି)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_ଚାବି_NOT_FOUND;
			ଯାଅ out;
		}
		sign_ଚାବି = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	ଯଦି (!is_agent && sshkey_is_sk(sign_ଚାବି) &&
	    (sign_ଚାବି->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		ଯଦି ((fp = sshkey_fingerprint(sign_ଚାବି,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_ଚାବି), fp);
		ମୁକ୍ତ(fp);
	}
	ଯଦି ((r = sshkey_sign(sign_ଚାବି, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ଯଦି (!retried && pin == ଖାଲି && !is_agent &&
		    sshkey_is_sk(sign_ଚାବି) &&
		    r == SSH_ERR_ଚାବି_WRONG_PASSPHRASE) {
			notify_complete(notifier, ଖାଲି);
			notifier = ଖାଲି;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_ଚାବି), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			ଯାଅ retry_pin;
		}
		ଯାଅ out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	ଯଦି (id->ଚାବି != ଖାଲି && (id->ଚାବି->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(prompt);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ଖାଲି);
	sshkey_free(prv);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
id_filename_matches(Identity *id, Identity *private_id)
{
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ suffixes[] = { ".pub", "-cert.pub", ଖାଲି };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	ଯଦି (strcmp(id->filename, private_id->filename) == 0)
		ଫେରନ୍ତୁ 1;
	ପାଇଁ (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		ଯଦି (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sign_and_send_pubkey(ସଂରଚନା ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	Identity *private_id, *sign_id = ଖାଲି;
	u_char *signature = ଖାଲି;
	size_t slen = 0, skip = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, fallback_sigtype, sent = 0;
	ଅକ୍ଷର *alg = ଖାଲି, *fp = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *loc = "", *method = "publickey";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	ଯଦି ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	ଯଦି ((fp = sshkey_fingerprint(id->ଚାବି, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->ଚାବି), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	ଯଦି (id->agent_fd == -1 && sshkey_is_cert(id->ଚାବି)) {
		TAILQ_FOREACH(private_id, &authctxt->ଚାବିଗୁଡ଼ିକ, next) {
			ଯଦି (sshkey_equal_public(id->ଚାବି, private_id->ଚାବି) &&
			    id->ଚାବି->type != private_id->ଚାବି->type) {
				sign_id = private_id;
				ଭାଙ୍ଗ;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		ଯଦି (sign_id == ଖାଲି &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->ଚାବି->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->ଚାବିଗୁଡ଼ିକ, next) {
				ଯଦି (private_id->ଚାବି == ଖାଲି &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					ଭାଙ୍ଗ;
				}
			}
		}
		ଯଦି (sign_id != ଖାଲି) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} ଅନ୍ୟଥା {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	ଯଦି (sign_id == ଖାଲି)
		sign_id = id;

	/* assemble and sign data */
	ପାଇଁ (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		ମୁକ୍ତ(alg);
		slen = 0;
		signature = ଖାଲି;
		ଯଦି ((alg = ଚାବି_sig_algorithm(fallback_sigtype ? ଖାଲି : ssh,
		    id->ଚାବି)) == ଖାଲି) {
			error_f("no mutual signature supported");
			ଯାଅ out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		ଯଦି ((b = sshbuf_new()) == ଖାଲି)
			fatal_f("sshbuf_new failed");
		ଯଦି ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		ଯଦି ((r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->ଚାବି, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		ଯଦି (hostbound) {
			ଯଦି (ssh->kex->initial_hostkey == ଖାଲି) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			ଯଦି ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		ଯଦି (r == 0)
			ଭାଙ୍ଗ;
		ଅନ୍ୟଥା ଯଦି (r == SSH_ERR_ଚାବି_NOT_FOUND)
			ଯାଅ out; /* soft failure */
		ଅନ୍ୟଥା ଯଦି (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			ଯଦି (sign_id->agent_fd != -1)
				loc = "agent ";
			ଅନ୍ୟଥା ଯଦି (sign_id->ଚାବି != ଖାଲି &&
			    (sign_id->ଚାବି->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->ଚାବି), fp);
			ଜାରି;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->ଚାବି), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		ଯାଅ out;
	}
	ଯଦି (slen == 0 || signature == ଖାଲି) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	ଯଦି ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	ଯଦି ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	ମୁକ୍ତ(fp);
	ମୁକ୍ତ(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	ଫେରନ୍ତୁ sent;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
send_pubkey_test(ସଂରଚନା ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ଖାଲି;
	ଅକ୍ଷର *alg = ଖାଲି;
	size_t bloblen;
	u_int have_sig = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sent = 0, r;

	ଯଦି ((alg = ଚାବି_sig_algorithm(ssh, id->ଚାବି)) == ଖାଲି) {
		debug_f("no mutual signature algorithm");
		ଯାଅ out;
	}

	ଯଦି ((r = sshkey_to_blob(id->ଚାବି, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		ଯାଅ out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PK_OK, &ନିବେଶ_userauth_pk_ok);

	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	sent = 1;

 out:
	ମୁକ୍ତ(alg);
	ମୁକ୍ତ(blob);
	ଫେରନ୍ତୁ sent;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_identity_file(Identity *id)
{
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ = ଖାଲି;
	ଅକ୍ଷର prompt[300], *passphrase, *comment;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, quit = 0, i;
	ସଂରଚନା stat st;

	ଯଦି (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	snprintf(prompt, ଆକାର prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	ପାଇଁ (i = 0; i <= options.ସଂଖ୍ୟା_of_password_prompts; i++) {
		ଯଦି (i == 0)
			passphrase = "";
		ଅନ୍ୟଥା {
			passphrase = read_passphrase(prompt, 0);
			ଯଦି (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				ମୁକ୍ତ(passphrase);
				ଭାଙ୍ଗ;
			}
		}
		ବାଛ ((r = sshkey_load_private_type(ଚାବି_UNSPEC, id->filename,
		    passphrase, &ବ୍ୟକ୍ତିଗତ, &comment))) {
		ସ୍ଥିତି 0:
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH_ERR_ଚାବି_WRONG_PASSPHRASE:
			ଯଦି (options.batch_mode) {
				quit = 1;
				ଭାଙ୍ଗ;
			}
			ଯଦି (i != 0)
				debug2("bad passphrase given, try again...");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି SSH_ERR_SYSTEM_ERROR:
			ଯଦି (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				ଭାଙ୍ଗ;
			}
			/* FALLTHROUGH */
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (ବ୍ୟକ୍ତିଗତ != ଖାଲି && sshkey_is_sk(ବ୍ୟକ୍ତିଗତ) &&
		    options.sk_provider == ଖାଲି) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(ବ୍ୟକ୍ତିଗତ);
			ବ୍ୟକ୍ତିଗତ = ଖାଲି;
			quit = 1;
		}
		ଯଦି (!quit && (r = sshkey_check_rsa_length(ବ୍ୟକ୍ତିଗତ,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(ବ୍ୟକ୍ତିଗତ);
			ବ୍ୟକ୍ତିଗତ = ଖାଲି;
			quit = 1;
		}
		ଯଦି (!quit && ବ୍ୟକ୍ତିଗତ != ଖାଲି && id->agent_fd == -1 &&
		    !(id->ଚାବି && id->isprivate))
			maybe_add_ଚାବି_to_agent(id->filename, ବ୍ୟକ୍ତିଗତ, comment,
			    passphrase);
		ଯଦି (i > 0)
			freezero(passphrase, strlen(passphrase));
		ମୁକ୍ତ(comment);
		ଯଦି (ବ୍ୟକ୍ତିଗତ != ଖାଲି || quit)
			ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ ବ୍ୟକ୍ତିଗତ;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_type_allowed(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *allowlist)
{
	ଯଦି (match_pattern_list(sshkey_ssh_name(ଚାବି), allowlist, 0) == 1)
		ଫେରନ୍ତୁ 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	ବାଛ (ଚାବି->type) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			ଫେରନ୍ତୁ 1;
		ଯଦି (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			ଫେରନ୍ତୁ 1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_RSA_CERT:
		ଯଦି (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ଫେରନ୍ତୁ 1;
		ଯଦି (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ଫେରନ୍ତୁ 1;
		ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_type_allowed_by_config(ସଂରଚନା sshkey *ଚାବି)
{
	ଫେରନ୍ତୁ ଚାବି_type_allowed(ଚାବି, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_agent_identities(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *agent_fdp,
    ସଂରଚନା ssh_identitylist **idlistp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, agent_fd;
	ସଂରଚନା ssh_identitylist *idlist;

	ଯଦି ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ଯଦି (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (ssh != ଖାଲି && ssh->kex != ଖାଲି) {
		ଯଦି ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		ଅନ୍ୟଥା
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	ଯଦି ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		ଫେରନ୍ତୁ r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	ଫେରନ୍ତୁ 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_has_option(ସଂରଚନା sshbuf *oblob, ଅଚଳ ଅକ୍ଷର *target)
{
	ସଂରଚନା sshbuf *c = ଖାଲି, *data = ଖାଲି;
	ଅକ୍ଷର *name = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, found = 0;

	ଯଦି (oblob == ଖାଲି || (c = sshbuf_fromb(oblob)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯେତେବେଳେ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ଖାଲି;
		ମୁକ୍ତ(name);
		name = ଖାଲି;
		ଯଦି ((r = sshbuf_get_cstring(c, &name, ଖାଲି)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			ଭାଙ୍ଗ;
		ଯଦି (strcmp(name, target) == 0) {
			found = 1;
			ଭାଙ୍ଗ;
		}
	}
	sshbuf_free(data);
	ମୁକ୍ତ(name);
	sshbuf_free(c);
	ଫେରନ୍ତୁ found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
identity_prioritise(ସଂରଚନା identity *id)
{
	ଯଦି (id == ଖାଲି || id->ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ 3;
	ଯଦି (!sshkey_is_cert(id->ଚାବି) || id->ଚାବି->cert == ଖାଲି)
		ଫେରନ୍ତୁ 3;
	ଯଦି (sshkey_is_sk(id->ଚାବି) &&
	    cert_has_option(id->ଚାବି->cert->critical, "verify-required"))
		ଫେରନ୍ତୁ 2;
	ଯଦି (sshkey_is_sk(id->ଚାବି) &&
	    cert_has_option(id->ଚାବି->cert->extensions, "no-touch-required"))
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
order_identities_by_prio(ସଂରଚନା idlist *list)
{
	ସଂରଚନା idlist prio[MAX_ID_PRIORITY + 1], sorted;
	ସଂରଚନା identity *id, *tmp, *dummy;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା p;

	ପାଇଁ (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		ଯଦି (id->userprovided)
			ଜାରି;
		dummy = xcalloc(1, ଆକାର(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		ଯଦି (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	ପାଇଁ (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		ଯଦି (id->userprovided != -1)
			ଜାରି;
		ସଂରଚନା identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		ମୁକ୍ତ(id);
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
ସ୍ଥିର ଶୂନ୍ୟ
pubkey_prepare(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
{
	ସଂରଚନା identity *id, *id2, *tmp;
	ସଂରଚନା idlist agent, files, certs, agent_ଚାବିଗୁଡ଼ିକ, *preferred;
	ସଂରଚନା sshkey *ଚାବି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା disallowed, agent_fd = -1, i, r, found;
	size_t j;
	ସଂରଚନା ssh_identitylist *idlist;
	ଅକ୍ଷର *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_ଚାବିଗୁଡ଼ିକ); /* keys supported by the agent */
	preferred = &authctxt->ଚାବିଗୁଡ଼ିକ;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_identity_files; i++) {
		ଚାବି = options.identity_ଚାବିଗୁଡ଼ିକ[i];
		ଯଦି (ଚାବି && ଚାବି->cert &&
		    ଚାବି->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ଜାରି;
		}
		ଯଦି (ଚାବି && sshkey_is_sk(ଚାବି) && options.sk_provider == ଖାଲି) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ଜାରି;
		}
		options.identity_ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
		id = xcalloc(1, ଆକାର(*id));
		id->agent_fd = -1;
		id->ଚାବି = ଚାବି;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_certificate_files; i++) {
		ଚାବି = options.certificates[i];
		ଯଦି (!sshkey_is_cert(ଚାବି) || ଚାବି->cert == ଖାଲି ||
		    ଚାବି->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ଜାରି;
		}
		ଯଦି (ଚାବି && sshkey_is_sk(ଚାବି) && options.sk_provider == ଖାଲି) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ଜାରି;
		}
		id = xcalloc(1, ଆକାର(*id));
		id->agent_fd = -1;
		id->ଚାବି = ଚାବି;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	ଯଦି ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		ପାଇଁ (j = 0; j < idlist->nkeys; j++) {
			ଯଦି ((r = sshkey_check_rsa_length(idlist->ଚାବିଗୁଡ଼ିକ[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->ଚାବିଗୁଡ଼ିକ[j]));
				ଜାରି;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				ଯଦି (sshkey_equal(idlist->ଚାବିଗୁଡ଼ିକ[j], id->ଚାବି)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_ଚାବିଗୁଡ଼ିକ, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					ଭାଙ୍ଗ;
				}
			}
			ଯଦି (!found && !options.identities_only) {
				id = xcalloc(1, ଆକାର(*id));
				/* XXX "steals" key/comment from idlist */
				id->ଚାବି = idlist->ଚାବିଗୁଡ଼ିକ[j];
				id->filename = idlist->comments[j];
				idlist->ଚାବିଗୁଡ଼ିକ[j] = ଖାଲି;
				idlist->comments[j] = ଖାଲି;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_ଚାବିଗୁଡ଼ିକ, &agent, next);
		order_identities_by_prio(&agent_ଚାବିଗୁଡ଼ିକ);
		TAILQ_CONCAT(preferred, &agent_ଚାବିଗୁଡ଼ିକ, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		ଯଦି (id->ଚାବି == ଖାଲି || (id->ଚାବି->flags & SSHKEY_FLAG_EXT) == 0)
			ଜାରି;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			ଯଦି (id2->ଚାବି == ଖାଲି ||
			    (id2->ଚାବି->flags & SSHKEY_FLAG_EXT) != 0)
				ଜାରି;
			ଯଦି (sshkey_equal(id->ଚାବି, id2->ଚାବି)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				ଭାଙ୍ଗ;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		ଯଦି (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, ଆକାର(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = ଖାଲି;
		ଯଦି (id->ଚାବି == ଖାଲି)
			ଜାରି;
		ଯଦି (!ଚାବି_type_allowed_by_config(id->ଚାବି)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->ଚାବି), id->filename);
			disallowed = 1;
		} ଅନ୍ୟଥା ଯଦି (ssh != ଖାଲି && ssh->kex != ଖାଲି &&
		    ssh->kex->server_sig_algs != ଖାଲି &&
		    (cp = ଚାବି_sig_algorithm(ssh, id->ଚାବି)) == ଖାଲି) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->ଚାବି), id->filename);
			disallowed = 1;
		}
		ମୁକ୍ତ(cp);
		ଯଦି (!disallowed)
			ଜାରି;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->ଚାବି);
		ମୁକ୍ତ(id->filename);
		freezero(id, ଆକାର(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		ମୁକ୍ତ(ident);
	}
	debug2_f("done");
}

ସ୍ଥିର ଶୂନ୍ୟ
pubkey_cleanup(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	ଯଦି (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	ପାଇଁ (id = TAILQ_FIRST(&authctxt->ଚାବିଗୁଡ଼ିକ); id;
	    id = TAILQ_FIRST(&authctxt->ଚାବିଗୁଡ଼ିକ)) {
		TAILQ_REMOVE(&authctxt->ଚାବିଗୁଡ଼ିକ, id, next);
		sshkey_free(id->ଚାବି);
		ମୁକ୍ତ(id->filename);
		ମୁକ୍ତ(id);
	}
}

ଶୂନ୍ୟ
pubkey_dump(ସଂରଚନା ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	ଅକ୍ଷର *ident;

	memset(&authctxt, 0, ଆକାର(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.ଚାବିଗୁଡ଼ିକ, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		ମୁକ୍ତ(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->ଚାବିଗୁଡ଼ିକ, next)
		id->tried = 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_pubkey(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sent = 0;
	ଅକ୍ଷର *ident;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା prepared;

	ଯଦି (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	ଯେତେବେଳେ ((id = TAILQ_FIRST(&authctxt->ଚାବିଗୁଡ଼ିକ))) {
		ଯଦି (id->tried++)
			ଫେରନ୍ତୁ (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->ଚାବିଗୁଡ଼ିକ, id, next);
		TAILQ_INSERT_TAIL(&authctxt->ଚାବିଗୁଡ଼ିକ, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		ଯଦି (id->ଚାବି != ଖାଲି) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			ମୁକ୍ତ(ident);
			sent = send_pubkey_test(ssh, id);
		} ଅନ୍ୟଥା {
			debug("Trying private key: %s", id->filename);
			id->ଚାବି = load_identity_file(id);
			ଯଦି (id->ଚାବି != ଖାଲି) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->ଚାବି);
				id->ଚାବି = ଖାଲି;
				id->isprivate = 0;
			}
		}
		ଯଦି (sent)
			ଫେରନ୍ତୁ (sent);
	}
	ଫେରନ୍ତୁ (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_kbdint(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (authctxt->attempt_kbdint++ >= options.ସଂଖ୍ୟା_of_password_prompts)
		ଫେରନ୍ତୁ 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	ଯଦି (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_REQUEST, ଖାଲି);
		ଫେରନ୍ତୁ 0;
	}

	debug2("userauth_kbdint");
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_REQUEST, &ନିବେଶ_userauth_info_req);
	ଫେରନ୍ତୁ 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_userauth_info_req(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ଅକ୍ଷର *name = ଖାଲି, *inst = ଖାଲି, *lang = ଖାଲି, *prompt = ଖାଲି;
	ଅକ୍ଷର *display_prompt = ଖାଲି, *response = ଖାଲି;
	u_char echo = 0;
	u_int ଅଙ୍କ_prompts, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, addnl;
	size_t len;

	debug2_f("entering");

	ଯଦି (authctxt == ଖାଲି)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	ଯଦି ((r = sshpkt_get_cstring(ssh, &name, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	ଯଦି ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	ଯଦି ((r = sshpkt_get_u32(ssh, &ଅଙ୍କ_prompts)) != 0)
		ଯାଅ out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, ଅଙ୍କ_prompts)) != 0)
		ଯାଅ out;

	debug2_f("num_prompts %d", ଅଙ୍କ_prompts);
	ପାଇଁ (i = 0; i < ଅଙ୍କ_prompts; i++) {
		ଯଦି ((r = sshpkt_get_cstring(ssh, &prompt, ଖାଲି)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			ଯାଅ out;
		ଯଦି (asmprintf(&display_prompt, INT_MAX, ଖାଲି, "(%s@%s) %s",
		    authctxt->server_user, options.host_ଚାବି_alias ?
		    options.host_ଚାବି_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		ଯଦି ((r = sshpkt_put_cstring(ssh, response)) != 0)
			ଯାଅ out;
		freezero(response, strlen(response));
		ମୁକ୍ତ(prompt);
		ମୁକ୍ତ(display_prompt);
		display_prompt = response = prompt = ଖାଲି;
	}
	/* done with parsing incoming message. */
	ଯଦି ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		ଯାଅ out;
	r = sshpkt_send(ssh);
 out:
	ଯଦି (response)
		freezero(response, strlen(response));
	ମୁକ୍ତ(prompt);
	ମୁକ୍ତ(display_prompt);
	ମୁକ୍ତ(name);
	ମୁକ୍ତ(inst);
	ମୁକ୍ତ(lang);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_keysign(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey *ଚାବି, u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen)
{
	ସଂରଚନା sshbuf *b;
	ସଂରଚନା stat st;
	pid_t pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, to[2], from[2], status;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

	*sigp = ଖାଲି;
	*lenp = 0;

	ଯଦି (stat(PATH_SSH_ଚାବି_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ଫେରନ୍ତୁ -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ଯଦି (pid == 0) {
		close(from[0]);
		ଯଦି (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		ଯଦି (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		ଯଦି (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		ଯଦି (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_ଚାବି_SIGN);
		execl(PATH_SSH_ଚାବି_SIGN, PATH_SSH_ଚାବି_SIGN, (ଅକ୍ଷର *)ଖାଲି);
		fatal_f("exec(%s): %s", PATH_SSH_ଚାବି_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	ଯଦି ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	ଯଦି (ssh_ସନ୍ଦେଶ_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_ସନ୍ଦେଶ_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	ଯଦି (r < 0) {
		error_f("no reply");
		ଯାଅ fail;
	}

	errno = 0;
	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1) {
		ଯଦି (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			ଯାଅ fail;
		}
	}
	ଯଦି (!WIFEXITED(status)) {
		error_f("exited abnormally");
		ଯାଅ fail;
	}
	ଯଦି (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		ଯାଅ fail;
	}
	ଯଦି ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		ଯାଅ fail;
	}
	ଯଦି (rversion != version) {
		error_f("bad version");
		ଯାଅ fail;
	}
	ଯଦି ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		ଫେରନ୍ତୁ -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
userauth_hostbased(ସଂରଚନା ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ = ଖାଲି;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	u_char *sig = ଖାଲି, *keyblob = ଖାଲି;
	ଅକ୍ଷର *fp = ଖାଲି, *chost = ଖାଲି, *lname = ଖାଲି;
	size_t siglen = 0, keylen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, success = 0;

	ଯଦି (authctxt->ktypes == ଖାଲି) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	ପାଇଁ (;;) {
		ଯଦି (authctxt->active_ktype == ଖାଲି)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		ଯଦି (authctxt->active_ktype == ଖାଲି ||
		    *authctxt->active_ktype == '\0')
			ଭାଙ୍ଗ;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		ବ୍ୟକ୍ତିଗତ = ଖାଲି;
		ପାଇଁ (i = 0; i < authctxt->sensitive->nkeys; i++) {
			ଯଦି (authctxt->sensitive->ଚାବିଗୁଡ଼ିକ[i] == ଖାଲି ||
			    authctxt->sensitive->ଚାବିଗୁଡ଼ିକ[i]->type == ଚାବି_UNSPEC)
				ଜାରି;
			ଯଦି (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->ଚାବିଗୁଡ଼ିକ[i]),
			    authctxt->active_ktype))
				ଜାରି;
			/* we take and free the key */
			ବ୍ୟକ୍ତିଗତ = authctxt->sensitive->ଚାବିଗୁଡ଼ିକ[i];
			authctxt->sensitive->ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
			ଭାଙ୍ଗ;
		}
		/* Found one */
		ଯଦି (ବ୍ୟକ୍ତିଗତ != ଖାଲି)
			ଭାଙ୍ଗ;
		/* No more keys of this type; advance */
		authctxt->active_ktype = ଖାଲି;
	}
	ଯଦି (ବ୍ୟକ୍ତିଗତ == ଖାଲି) {
		ମୁକ୍ତ(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ଖାଲି;
		authctxt->active_ktype = ଖାଲି;
		debug("No more client hostkeys for hostbased authentication.");
		ଯାଅ out;
	}

	ଯଦି ((fp = sshkey_fingerprint(ବ୍ୟକ୍ତିଗତ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ଖାଲି) {
		error_f("sshkey_fingerprint failed");
		ଯାଅ out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(ବ୍ୟକ୍ତିଗତ), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	ଯଦି (lname == ଖାଲି) {
		error_f("cannot get local ipaddr/name");
		ଯାଅ out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		error_f("sshbuf_new failed");
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_to_blob(ବ୍ୟକ୍ତିଗତ, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		ଯାଅ out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	ଯଦି ((r = ssh_keysign(ssh, ବ୍ୟକ୍ତିଗତ, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(ବ୍ୟକ୍ତିଗତ), fp);
		ଯାଅ out;
	}
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->active_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		ଯାଅ out;
	}
	success = 1;

 out:
	ଯଦି (sig != ଖାଲି)
		freezero(sig, siglen);
	ମୁକ୍ତ(keyblob);
	ମୁକ୍ତ(lname);
	ମୁକ୍ତ(fp);
	ମୁକ୍ତ(chost);
	sshkey_free(ବ୍ୟକ୍ତିଗତ);
	sshbuf_free(b);

	ଫେରନ୍ତୁ success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
authmethod_is_enabled(Authmethod *method)
{
	ଯଦି (method == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	/* return false if options indicate this method is disabled */
	ଯଦି  (method->enabled == ଖାଲି || *method->enabled == 0)
		ଫେରନ୍ତୁ 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	ଯଦି  (method->batch_flag != ଖାଲି && *method->batch_flag != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର Authmethod *
authmethod_lookup(ଅଚଳ ଅକ୍ଷର *name)
{
	Authmethod *method = ଖାଲି;
	ଯଦି (name != ଖାଲି)
		ପାଇଁ (method = authmethods; method->name != ଖାଲି; method++)
			ଯଦି (strcmp(name, method->name) == 0)
				ଫେରନ୍ତୁ method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	ଫେରନ୍ତୁ ଖାଲି;
}

/* XXX internal state */
ସ୍ଥିର Authmethod *current = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *supported = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *preferred = ଖାଲି;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ସ୍ଥିର Authmethod *
authmethod_get(ଅକ୍ଷର *authlist)
{
	ଅକ୍ଷର *name = ଖାଲି;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	ଯଦି (authlist == ଖାଲି || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	ଯଦି (supported == ଖାଲି || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		ମୁକ୍ତ(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (current != ଖାଲି && authmethod_is_enabled(current))
		ଫେରନ୍ତୁ current;

	ପାଇଁ (;;) {
		ଯଦି ((name = match_list(preferred, supported, &next)) == ଖାଲି) {
			debug("No more authentication methods to try.");
			current = ଖାଲି;
			ଫେରନ୍ତୁ ଖାଲି;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		ଯଦି ((current = authmethod_lookup(name)) != ଖାଲି &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			ମୁକ୍ତ(name);
			ଫେରନ୍ତୁ current;
		}
		ମୁକ୍ତ(name);
	}
}

ସ୍ଥିର ଅକ୍ଷର *
authmethods_get(ଶୂନ୍ୟ)
{
	Authmethod *method = ଖାଲି;
	ସଂରଚନା sshbuf *b;
	ଅକ୍ଷର *list;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ପାଇଁ (method = authmethods; method->name != ଖାଲି; method++) {
		ଯଦି (authmethod_is_enabled(method)) {
			ଯଦି ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	ଯଦି ((list = sshbuf_dup_string(b)) == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ଫେରନ୍ତୁ list;
}
