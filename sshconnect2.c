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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <unistd.h>
#જો defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#અન્તર્ભાવ <vis.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshconnect.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "msg.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "utf8.h"
#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "sk-api.h"

#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif

/* import */
બાહ્ય Options options;

/*
 * SSH2 key exchange
 */

સ્થિર અક્ષર *xxx_host;
સ્થિર સંરચના sockaddr_storage xxx_hostaddr;
સ્થિર અચલ સંરચના ssh_conn_info *xxx_conn_info;
સ્થિર પૂર્ણાંક ચાવી_type_allowed(સંરચના sshkey *, અચલ અક્ષર *);

સ્થિર પૂર્ણાંક
verify_host_ચાવી_callback(સંરચના sshkey *hostkey, સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	જો (!ચાવી_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	જો (verify_host_ચાવી(xxx_host, (સંરચના sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	પાછા 0;
}

/* Returns the first item from a comma-separated algorithm list */
સ્થિર અક્ષર *
first_alg(અચલ અક્ષર *algs)
{
	અક્ષર *ret, *cp;

	ret = xstrdup(algs);
	જો ((cp = strchr(ret, ',')) != ખાલી)
		*cp = '\0';
	પાછા ret;
}

સ્થિર અક્ષર *
order_hostkeyalgs(અક્ષર *host, સંરચના sockaddr *hostaddr, u_short port,
    અચલ સંરચના ssh_conn_info *cinfo)
{
	અક્ષર *oavail = ખાલી, *avail = ખાલી, *first = ખાલી, *last = ખાલી;
	અક્ષર *alg = ખાલી, *hostname = ખાલી, *ret = ખાલી, *best = ખાલી;
	size_t maxlen;
	સંરચના hostkeys *hostkeys = ખાલી;
	પૂર્ણાંક ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, ખાલી);
	hostkeys = init_hostkeys();
	માટે (i = 0; i < options.અંક_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	માટે (i = 0; i < options.અંક_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	જો (options.known_hosts_command != ખાલી) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, ખાલી, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	જો (lookup_ચાવી_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), ખાલી)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		જાઓ out;
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
	કરો { \
		જો (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} જ્યારે (0)

	જ્યારે ((alg = strsep(&avail, ",")) && *alg != '\0') {
		જો ((ktype = sshkey_type_from_name(alg)) == ચાવી_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		જો (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			ચાલુ;
		}
		/* If the key appears in known_hosts then prefer it */
		જો (lookup_ચાવી_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ખાલી)) {
			ALG_APPEND(first, alg);
			ચાલુ;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	જો (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	નહીંતર
		debug3_f("no algorithms matched; accept original");
 out:
	મુક્ત(best);
	મુક્ત(first);
	મુક્ત(last);
	મુક્ત(hostname);
	મુક્ત(oavail);
	free_hostkeys(hostkeys);

	પાછા ret;
}

શૂન્ય
ssh_kex2(સંરચના ssh *ssh, અક્ષર *host, સંરચના sockaddr_storage *hostaddr,
    u_short port, અચલ સંરચના ssh_conn_info *cinfo)
{
	અક્ષર *myproposal[PROPOSAL_MAX];
	અક્ષર *all_ચાવી, *hkalgs = ખાલી;
	પૂર્ણાંક r, use_known_hosts_order = 0;

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
	જો (options.hostkeyalgorithms == ખાલી ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_ચાવી = sshkey_alg_list(0, 0, 1, ',');
	જો ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_ચાવી)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	મુક્ત(all_ચાવી);

	જો (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (સંરચના sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	મુક્ત(hkalgs);

	/* start key exchange */
	જો ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_ચાવી=&verify_host_ચાવી_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

પ્રકારવ્યાખ્યા સંરચના cauthctxt Authctxt;
પ્રકારવ્યાખ્યા સંરચના cauthmethod Authmethod;
પ્રકારવ્યાખ્યા સંરચના identity Identity;
પ્રકારવ્યાખ્યા સંરચના idlist Idlist;

સંરચના identity {
	TAILQ_ENTRY(identity) next;
	પૂર્ણાંક	agent_fd;		/* >=0 if agent supports key */
	સંરચના sshkey	*ચાવી;		/* public/private key */
	અક્ષર	*filename;		/* comment for agent-only keys */
	પૂર્ણાંક	tried;
	પૂર્ણાંક	isprivate;		/* key points to the private key */
	પૂર્ણાંક	userprovided;
};
TAILQ_HEAD(idlist, identity);

સંરચના cauthctxt {
	અચલ અક્ષર *server_user;
	અચલ અક્ષર *local_user;
	અચલ અક્ષર *host;
	અચલ અક્ષર *service;
	સંરચના cauthmethod *method;
	sig_atomic_t success;
	અક્ષર *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	સંરચના idlist ચાવીઓ;
	પૂર્ણાંક agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	અક્ષર *oktypes, *ktypes;
	અચલ અક્ષર *active_ktype;
	/* kbd-interactive */
	પૂર્ણાંક info_req_seen;
	પૂર્ણાંક attempt_kbdint;
	/* password */
	પૂર્ણાંક attempt_passwd;
	/* generic */
	શૂન્ય *methoddata;
};

સંરચના cauthmethod {
	અક્ષર	*name;		/* string to compare against server's list */
	પૂર્ણાંક	(*userauth)(સંરચના ssh *ssh);
	શૂન્ય	(*cleanup)(સંરચના ssh *ssh);
	પૂર્ણાંક	*enabled;	/* flag in option struct that enables method */
	પૂર્ણાંક	*batch_flag;	/* flag in option struct that disables method */
};

સ્થિર પૂર્ણાંક આગત_userauth_service_accept(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_success(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_failure(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_banner(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_error(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_info_req(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_pk_ok(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_userauth_passwd_changereq(પૂર્ણાંક, uint32_t, સંરચના ssh *);

સ્થિર પૂર્ણાંક userauth_none(સંરચના ssh *);
સ્થિર પૂર્ણાંક userauth_pubkey(સંરચના ssh *);
સ્થિર પૂર્ણાંક userauth_passwd(સંરચના ssh *);
સ્થિર પૂર્ણાંક userauth_kbdint(સંરચના ssh *);
સ્થિર પૂર્ણાંક userauth_hostbased(સંરચના ssh *);

#ifdef GSSAPI
સ્થિર પૂર્ણાંક userauth_gssapi(સંરચના ssh *);
સ્થિર શૂન્ય userauth_gssapi_cleanup(સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_gssapi_response(પૂર્ણાંક type, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_gssapi_token(પૂર્ણાંક type, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_gssapi_error(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_gssapi_errtok(પૂર્ણાંક, uint32_t, સંરચના ssh *);
#endif

શૂન્ય	userauth(સંરચના ssh *, અક્ષર *);

સ્થિર શૂન્ય pubkey_cleanup(સંરચના ssh *);
સ્થિર પૂર્ણાંક sign_and_send_pubkey(સંરચના ssh *ssh, Identity *);
સ્થિર શૂન્ય pubkey_prepare(સંરચના ssh *, Authctxt *);
સ્થિર શૂન્ય pubkey_reset(Authctxt *);
સ્થિર સંરચના sshkey *load_identity_file(Identity *);

સ્થિર Authmethod *authmethod_get(અક્ષર *authlist);
સ્થિર Authmethod *authmethod_lookup(અચલ અક્ષર *name);
સ્થિર અક્ષર *authmethods_get(શૂન્ય);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ખાલી},
#endif
	{"hostbased",
		userauth_hostbased,
		ખાલી,
		&options.hostbased_authentication,
		ખાલી},
	{"publickey",
		userauth_pubkey,
		ખાલી,
		&options.pubkey_authentication,
		ખાલી},
	{"keyboard-interactive",
		userauth_kbdint,
		ખાલી,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		ખાલી,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		ખાલી,
		ખાલી,
		ખાલી},
	{ખાલી, ખાલી, ખાલી, ખાલી, ખાલી}
};

શૂન્ય
ssh_userauth2(સંરચના ssh *ssh, અચલ અક્ષર *local_user,
    અચલ અક્ષર *server_user, અક્ષર *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	પૂર્ણાંક r;

	જો (options.preferred_authentications == ખાલી)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, કદ(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = ખાલી;
	authctxt.methoddata = ખાલી;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = ખાલી;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#જો GSSAPI
	authctxt.gss_supported_mechs = ખાલી;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	જો (authctxt.method == ખાલી)
		fatal_f("internal error: cannot send userauth none request");

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &આગત_userauth_error);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, kex_આગત_ext_info);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_SERVICE_ACCEPT, &આગત_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	જો (authctxt.gss_supported_mechs != ખાલી) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ખાલી;
	}
#endif
	ssh->authctxt = ખાલી;

	ssh_dispatch_range(ssh, SSH2_સંદેશ_USERAUTH_MIN, SSH2_સંદેશ_USERAUTH_MAX, ખાલી);

	જો (!authctxt.success)
		fatal("Authentication failed.");
	જો (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} નહીંતર {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

સ્થિર પૂર્ણાંક
આગત_userauth_service_accept(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	જો (ssh_packet_remaining(ssh) > 0) {
		અક્ષર *reply;

		જો ((r = sshpkt_get_cstring(ssh, &reply, ખાલી)) != 0)
			જાઓ out;
		debug2("service_accept: %s", reply);
		મુક્ત(reply);
	} નહીંતર {
		debug2("buggy server: service_accept w/o service");
	}
	જો ((r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_આગત_ext_info : &આગત_userauth_error);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_SUCCESS, &આગત_userauth_success);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_FAILURE, &આગત_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_BANNER, &આગત_userauth_banner);
	r = 0;
 out:
	પાછા r;
}

શૂન્ય
userauth(સંરચના ssh *ssh, અક્ષર *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	જો (authctxt->method != ખાલી && authctxt->method->cleanup != ખાલી)
		authctxt->method->cleanup(ssh);

	મુક્ત(authctxt->methoddata);
	authctxt->methoddata = ખાલી;
	જો (authlist == ખાલી) {
		authlist = authctxt->authlist;
	} નહીંતર {
		મુક્ત(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	માટે (;;) {
		Authmethod *method = authmethod_get(authlist);
		જો (method == ખાલી)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_સંદેશ_USERAUTH_PER_METHOD_MIN,
		    SSH2_સંદેશ_USERAUTH_PER_METHOD_MAX, ખાલી);

		/* and try new method */
		જો (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			તોડો;
		} નહીંતર {
			debug2("we did not send a packet, disable method");
			method->enabled = ખાલી;
		}
	}
}

સ્થિર પૂર્ણાંક
આગત_userauth_error(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_userauth_banner(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	અક્ષર *સંદેશ = ખાલી;
	size_t len;
	પૂર્ણાંક r;

	debug3_f("entering");
	જો ((r = sshpkt_get_cstring(ssh, &સંદેશ, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ખાલી, ખાલી)) != 0)
		જાઓ out;
	જો (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", સંદેશ);
	r = 0;
 out:
	મુક્ત(સંદેશ);
	પાછા r;
}

સ્થિર પૂર્ણાંક
આગત_userauth_success(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	જો (authctxt == ખાલી)
		fatal_f("no authentication context");
	મુક્ત(authctxt->authlist);
	authctxt->authlist = ખાલી;
	જો (authctxt->method != ખાલી && authctxt->method->cleanup != ખાલી)
		authctxt->method->cleanup(ssh);
	મુક્ત(authctxt->methoddata);
	authctxt->methoddata = ખાલી;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, dispatch_protocol_error);
	પાછા 0;
}

#જો 0
સ્થિર પૂર્ણાંક
આગત_userauth_success_unexpected(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	જો (authctxt == ખાલી)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	પાછા 0;
}
#endif

સ્થિર પૂર્ણાંક
આગત_userauth_failure(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	અક્ષર *authlist = ખાલી;
	u_char partial;

	જો (authctxt == ખાલી)
		fatal("input_userauth_failure: no authentication context");

	જો (sshpkt_get_cstring(ssh, &authlist, ખાલી) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		જાઓ out;

	જો (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ખાલી;
 out:
	મુક્ત(authlist);
	પાછા 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
સ્થિર અક્ષર *
format_identity(Identity *id)
{
	અક્ષર *fp = ખાલી, *ret = ખાલી;
	અચલ અક્ષર *note = "";

	જો (id->ચાવી != ખાલી) {
		fp = sshkey_fingerprint(id->ચાવી, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	જો (id->ચાવી) {
		જો ((id->ચાવી->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		નહીંતર જો (sshkey_is_sk(id->ચાવી))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->ચાવી ? sshkey_type(id->ચાવી) : "", id->ચાવી ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	મુક્ત(fp);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
આગત_userauth_pk_ok(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshbuf *keyblob = ખાલી;
	Identity *id = ખાલી;
	પૂર્ણાંક pktype, found = 0, sent = 0;
	અક્ષર *pkalg = ખાલી, *fp = ખાલી, *ident = ખાલી;
	પૂર્ણાંક r;

	જો (authctxt == ખાલી)
		fatal_f("no authentication context");

	જો ((r = sshpkt_get_cstring(ssh, &pkalg, ખાલી)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ done;

	જો (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		જાઓ done;
	}
	જો ((pktype = sshkey_type_from_name(pkalg)) == ચાવી_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ done;
	}
	/* inner key type should match signature type */
	જો ((r = sshkey_fromb_allowlist(keyblob, &ચાવી, pkalg, ખાલી)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		જાઓ done;
	}
	જો (ચાવી->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    ચાવી->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->ચાવીઓ, idlist, next) {
		જો (sshkey_equal(ચાવી, id->ચાવી)) {
			found = 1;
			તોડો;
		}
	}
	જો (!found || id == ખાલી) {
		fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(ચાવી), fp == ખાલી ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(ચાવી);
	sshbuf_free(keyblob);
	મુક્ત(ident);
	મુક્ત(fp);
	મુક્ત(pkalg);

	/* try another method if we did not send a packet */
	જો (r == 0 && sent == 0)
		userauth(ssh, ખાલી);
	પાછા r;
}

#ifdef GSSAPI
સ્થિર પૂર્ણાંક
userauth_gssapi(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ખાલી;
	OM_uint32 min;
	પૂર્ણાંક r, ok = 0;
	gss_OID mech = ખાલી;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	જો (authctxt->gss_supported_mechs == ખાલી)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	જ્યારે (authctxt->mech_tried < authctxt->gss_supported_mechs->ગણતરી &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		જો (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} નહીંતર {
			authctxt->mech_tried++;
		}
	}

	જો (!ok || mech == ખાલી)
		પાછા 0;

	authctxt->methoddata=(શૂન્ય *)gssctxt;

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_RESPONSE, &આગત_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN, &આગત_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERROR, &આગત_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK, &આગત_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	પાછા 1;
}

સ્થિર શૂન્ય
userauth_gssapi_cleanup(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ખાલી;
}

સ્થિર OM_uint32
process_gssapi_token(સંરચના ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	પૂર્ણાંક r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	જો (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_સંદેશ_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_સંદેશ_USERAUTH_GSSAPI_TOKEN;

		જો ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.કિંમત,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	જો (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		જો (!(flags & GSS_C_INTEG_FLAG)) {
			જો ((r = sshpkt_start(ssh,
			    SSH2_સંદેશ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} નહીંતર {
			સંરચના sshbuf *b;

			જો ((b = sshbuf_new()) == ખાલી)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			જો ((gssbuf.કિંમત = sshbuf_mutable_ptr(b)) == ખાલી)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			જો (!GSS_ERROR(status)) {
				જો ((r = sshpkt_start(ssh,
				    SSH2_સંદેશ_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.કિંમત,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	પાછા status;
}

સ્થિર પૂર્ણાંક
આગત_gssapi_response(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = ખાલી;
	પૂર્ણાંક r;

	જો (authctxt == ખાલી)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	જો ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		જાઓ done;

	જો (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ખાલી);
		જાઓ ok;
	}

	જો (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	જો ((r = sshpkt_get_end(ssh)) != 0)
		જાઓ done;

	જો (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ખાલી);
		જાઓ ok;
	}
 ok:
	r = 0;
 done:
	મુક્ત(oidv);
	પાછા r;
}

સ્થિર પૂર્ણાંક
આગત_gssapi_token(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = ખાલી;
	size_t len;
	OM_uint32 status;
	પૂર્ણાંક r;

	જો (authctxt == ખાલી)
		fatal("input_gssapi_response: no authentication context");

	જો ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;

	recv_tok.કિંમત = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	જો (GSS_ERROR(status)) {
		userauth(ssh, ખાલી);
		/* ok */
	}
	r = 0;
 out:
	મુક્ત(p);
	પાછા r;
}

સ્થિર પૂર્ણાંક
આગત_gssapi_errtok(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ખાલી;
	size_t len;
	પૂર્ણાંક r;

	જો (authctxt == ખાલી)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	જો ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		મુક્ત(p);
		પાછા r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.કિંમત = p;
	recv_tok.length = len;
	(શૂન્ય)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ખાલી);
	મુક્ત(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_gssapi_error(પૂર્ણાંક type, uint32_t plen, સંરચના ssh *ssh)
{
	અક્ષર *સંદેશ = ખાલી;
	અક્ષર *lang = ખાલી;
	પૂર્ણાંક r;

	જો ((r = sshpkt_get_u32(ssh, ખાલી)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ખાલી)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &સંદેશ, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ખાલી)) != 0)
		જાઓ out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", સંદેશ);
 out:
	મુક્ત(સંદેશ);
	મુક્ત(lang);
	પાછા r;
}
#endif /* GSSAPI */

સ્થિર પૂર્ણાંક
userauth_none(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	પૂર્ણાંક r;

	/* initial userauth request */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	પાછા 1;
}

સ્થિર પૂર્ણાંક
userauth_passwd(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	અક્ષર *password, *prompt = ખાલી;
	અચલ અક્ષર *host = options.host_ચાવી_alias ?  options.host_ચાવી_alias :
	    authctxt->host;
	પૂર્ણાંક r;

	જો (authctxt->attempt_passwd++ >= options.સંખ્યા_of_password_prompts)
		પાછા 0;

	જો (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	મુક્ત(prompt);
	જો (password != ખાલી)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_PASSWD_CHANGEREQ,
	    &આગત_userauth_passwd_changereq);

	પાછા 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
સ્થિર પૂર્ણાંક
આગત_userauth_passwd_changereq(પૂર્ણાંક type, uint32_t seqnr, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	અક્ષર *info = ખાલી, *lang = ખાલી, *password = ખાલી, *retype = ખાલી;
	અક્ષર prompt[256];
	અચલ અક્ષર *host;
	પૂર્ણાંક r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	જો (authctxt == ખાલી)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_ચાવી_alias ? options.host_ચાવી_alias : authctxt->host;

	જો ((r = sshpkt_get_cstring(ssh, &info, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ખાલી)) != 0)
		જાઓ out;
	જો ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		જાઓ out;

	snprintf(prompt, કદ(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	જો ((r = sshpkt_put_cstring(ssh, password)) != 0)
		જાઓ out;

	freezero(password, strlen(password));
	password = ખાલી;
	જ્યારે (password == ખાલી) {
		snprintf(prompt, કદ(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		જો (password == ખાલી) {
			/* bail out */
			r = 0;
			જાઓ out;
		}
		snprintf(prompt, કદ(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		જો (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ખાલી;
		}
		freezero(retype, strlen(retype));
	}
	જો ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		જાઓ out;

	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_PASSWD_CHANGEREQ,
	    &આગત_userauth_passwd_changereq);
	r = 0;
 out:
	જો (password)
		freezero(password, strlen(password));
	મુક્ત(info);
	મુક્ત(lang);
	પાછા r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
સ્થિર અક્ષર *
ચાવી_sig_algorithm(સંરચના ssh *ssh, અચલ સંરચના sshkey *ચાવી)
{
	અક્ષર *allowed, *oallowed, *cp, *tmp, *alg = ખાલી;
	અચલ અક્ષર *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	જો (ssh == ખાલી || ssh->kex->server_sig_algs == ખાલી ||
	    (ચાવી->type != ચાવી_RSA && ચાવી->type != ચાવી_RSA_CERT) ||
	    (ચાવી->type == ચાવી_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		પાછા match_list(sshkey_ssh_name(ચાવી),
		    options.pubkey_accepted_algos, ખાલી);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	જો (ચાવી->type == ચાવી_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	જ્યારે ((cp = strsep(&allowed, ",")) != ખાલી) {
		જો (sshkey_type_from_name(cp) != ચાવી->type)
			ચાલુ;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ખાલી);
		જો (tmp != ખાલી)
			alg = xstrdup(cp);
		મુક્ત(tmp);
		જો (alg != ખાલી)
			તોડો;
	}
	મુક્ત(oallowed);
	પાછા alg;
}

સ્થિર પૂર્ણાંક
identity_sign(સંરચના identity *id, u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen, u_int compat, અચલ અક્ષર *alg)
{
	સંરચના sshkey *sign_ચાવી = ખાલી, *prv = ખાલી;
	પૂર્ણાંક is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	સંરચના notifier_ctx *notifier = ખાલી;
	અક્ષર *fp = ખાલી, *pin = ખાલી, *prompt = ખાલી;

	*sigp = ખાલી;
	*lenp = 0;

	/* The agent supports this key. */
	જો (id->ચાવી != ખાલી && id->agent_fd != -1) {
		પાછા ssh_agent_sign(id->agent_fd, id->ચાવી, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	જો (id->ચાવી != ખાલી &&
	    (id->isprivate || (id->ચાવી->flags & SSHKEY_FLAG_EXT))) {
		sign_ચાવી = id->ચાવી;
		is_agent = 1;
	} નહીંતર {
		/* Load the private key from the file. */
		જો ((prv = load_identity_file(id)) == ખાલી)
			પાછા SSH_ERR_ચાવી_NOT_FOUND;
		જો (id->ચાવી != ખાલી && !sshkey_equal_public(prv, id->ચાવી)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_ચાવી_NOT_FOUND;
			જાઓ out;
		}
		sign_ચાવી = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	જો (!is_agent && sshkey_is_sk(sign_ચાવી) &&
	    (sign_ચાવી->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		જો ((fp = sshkey_fingerprint(sign_ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_ચાવી), fp);
		મુક્ત(fp);
	}
	જો ((r = sshkey_sign(sign_ચાવી, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		જો (!retried && pin == ખાલી && !is_agent &&
		    sshkey_is_sk(sign_ચાવી) &&
		    r == SSH_ERR_ચાવી_WRONG_PASSPHRASE) {
			notify_complete(notifier, ખાલી);
			notifier = ખાલી;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_ચાવી), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			જાઓ retry_pin;
		}
		જાઓ out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	જો (id->ચાવી != ખાલી && (id->ચાવી->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	મુક્ત(prompt);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ખાલી);
	sshkey_free(prv);
	પાછા r;
}

સ્થિર પૂર્ણાંક
id_filename_matches(Identity *id, Identity *private_id)
{
	સ્થિર અચલ અક્ષર * અચલ suffixes[] = { ".pub", "-cert.pub", ખાલી };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	જો (strcmp(id->filename, private_id->filename) == 0)
		પાછા 1;
	માટે (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		જો (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			પાછા 1;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
sign_and_send_pubkey(સંરચના ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	સંરચના sshbuf *b = ખાલી;
	Identity *private_id, *sign_id = ખાલી;
	u_char *signature = ખાલી;
	size_t slen = 0, skip = 0;
	પૂર્ણાંક r, fallback_sigtype, sent = 0;
	અક્ષર *alg = ખાલી, *fp = ખાલી;
	અચલ અક્ષર *loc = "", *method = "publickey";
	પૂર્ણાંક hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	જો ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	જો ((fp = sshkey_fingerprint(id->ચાવી, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ખાલી)
		પાછા 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->ચાવી), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	જો (id->agent_fd == -1 && sshkey_is_cert(id->ચાવી)) {
		TAILQ_FOREACH(private_id, &authctxt->ચાવીઓ, next) {
			જો (sshkey_equal_public(id->ચાવી, private_id->ચાવી) &&
			    id->ચાવી->type != private_id->ચાવી->type) {
				sign_id = private_id;
				તોડો;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		જો (sign_id == ખાલી &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->ચાવી->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->ચાવીઓ, next) {
				જો (private_id->ચાવી == ખાલી &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					તોડો;
				}
			}
		}
		જો (sign_id != ખાલી) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} નહીંતર {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	જો (sign_id == ખાલી)
		sign_id = id;

	/* assemble and sign data */
	માટે (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		મુક્ત(alg);
		slen = 0;
		signature = ખાલી;
		જો ((alg = ચાવી_sig_algorithm(fallback_sigtype ? ખાલી : ssh,
		    id->ચાવી)) == ખાલી) {
			error_f("no mutual signature supported");
			જાઓ out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		જો ((b = sshbuf_new()) == ખાલી)
			fatal_f("sshbuf_new failed");
		જો ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		જો ((r = sshbuf_put_u8(b, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->ચાવી, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		જો (hostbound) {
			જો (ssh->kex->initial_hostkey == ખાલી) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			જો ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		જો (r == 0)
			તોડો;
		નહીંતર જો (r == SSH_ERR_ચાવી_NOT_FOUND)
			જાઓ out; /* soft failure */
		નહીંતર જો (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			જો (sign_id->agent_fd != -1)
				loc = "agent ";
			નહીંતર જો (sign_id->ચાવી != ખાલી &&
			    (sign_id->ચાવી->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->ચાવી), fp);
			ચાલુ;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->ચાવી), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		જાઓ out;
	}
	જો (slen == 0 || signature == ખાલી) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	જો ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	જો ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	મુક્ત(fp);
	મુક્ત(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	પાછા sent;
}

સ્થિર પૂર્ણાંક
send_pubkey_test(સંરચના ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ખાલી;
	અક્ષર *alg = ખાલી;
	size_t bloblen;
	u_int have_sig = 0;
	પૂર્ણાંક sent = 0, r;

	જો ((alg = ચાવી_sig_algorithm(ssh, id->ચાવી)) == ખાલી) {
		debug_f("no mutual signature algorithm");
		જાઓ out;
	}

	જો ((r = sshkey_to_blob(id->ચાવી, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		જાઓ out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_PK_OK, &આગત_userauth_pk_ok);

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
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
	મુક્ત(alg);
	મુક્ત(blob);
	પાછા sent;
}

સ્થિર સંરચના sshkey *
load_identity_file(Identity *id)
{
	સંરચના sshkey *ખાનગી = ખાલી;
	અક્ષર prompt[300], *passphrase, *comment;
	પૂર્ણાંક r, quit = 0, i;
	સંરચના stat st;

	જો (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		પાછા ખાલી;
	}
	snprintf(prompt, કદ prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	માટે (i = 0; i <= options.સંખ્યા_of_password_prompts; i++) {
		જો (i == 0)
			passphrase = "";
		નહીંતર {
			passphrase = read_passphrase(prompt, 0);
			જો (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				મુક્ત(passphrase);
				તોડો;
			}
		}
		પસંદગી ((r = sshkey_load_private_type(ચાવી_UNSPEC, id->filename,
		    passphrase, &ખાનગી, &comment))) {
		સ્થિતિ 0:
			તોડો;
		સ્થિતિ SSH_ERR_ચાવી_WRONG_PASSPHRASE:
			જો (options.batch_mode) {
				quit = 1;
				તોડો;
			}
			જો (i != 0)
				debug2("bad passphrase given, try again...");
			તોડો;
		સ્થિતિ SSH_ERR_SYSTEM_ERROR:
			જો (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				તોડો;
			}
			/* FALLTHROUGH */
		મૂળભૂત:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			તોડો;
		}
		જો (ખાનગી != ખાલી && sshkey_is_sk(ખાનગી) &&
		    options.sk_provider == ખાલી) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(ખાનગી);
			ખાનગી = ખાલી;
			quit = 1;
		}
		જો (!quit && (r = sshkey_check_rsa_length(ખાનગી,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(ખાનગી);
			ખાનગી = ખાલી;
			quit = 1;
		}
		જો (!quit && ખાનગી != ખાલી && id->agent_fd == -1 &&
		    !(id->ચાવી && id->isprivate))
			maybe_add_ચાવી_to_agent(id->filename, ખાનગી, comment,
			    passphrase);
		જો (i > 0)
			freezero(passphrase, strlen(passphrase));
		મુક્ત(comment);
		જો (ખાનગી != ખાલી || quit)
			તોડો;
	}
	પાછા ખાનગી;
}

સ્થિર પૂર્ણાંક
ચાવી_type_allowed(સંરચના sshkey *ચાવી, અચલ અક્ષર *allowlist)
{
	જો (match_pattern_list(sshkey_ssh_name(ચાવી), allowlist, 0) == 1)
		પાછા 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	પસંદગી (ચાવી->type) {
	સ્થિતિ ચાવી_RSA:
		જો (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			પાછા 1;
		જો (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			પાછા 1;
		તોડો;
	સ્થિતિ ચાવી_RSA_CERT:
		જો (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			પાછા 1;
		જો (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			પાછા 1;
		તોડો;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ચાવી_type_allowed_by_config(સંરચના sshkey *ચાવી)
{
	પાછા ચાવી_type_allowed(ચાવી, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
સ્થિર પૂર્ણાંક
get_agent_identities(સંરચના ssh *ssh, પૂર્ણાંક *agent_fdp,
    સંરચના ssh_identitylist **idlistp)
{
	પૂર્ણાંક r, agent_fd;
	સંરચના ssh_identitylist *idlist;

	જો ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		જો (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		પાછા r;
	}
	જો (ssh != ખાલી && ssh->kex != ખાલી) {
		જો ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		નહીંતર
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	જો ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		પાછા r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	પાછા 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
સ્થિર પૂર્ણાંક
cert_has_option(સંરચના sshbuf *oblob, અચલ અક્ષર *target)
{
	સંરચના sshbuf *c = ખાલી, *data = ખાલી;
	અક્ષર *name = ખાલી;
	પૂર્ણાંક r, found = 0;

	જો (oblob == ખાલી || (c = sshbuf_fromb(oblob)) == ખાલી)
		પાછા 0;
	જ્યારે (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ખાલી;
		મુક્ત(name);
		name = ખાલી;
		જો ((r = sshbuf_get_cstring(c, &name, ખાલી)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			તોડો;
		જો (strcmp(name, target) == 0) {
			found = 1;
			તોડો;
		}
	}
	sshbuf_free(data);
	મુક્ત(name);
	sshbuf_free(c);
	પાછા found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
સ્થિર પૂર્ણાંક
identity_prioritise(સંરચના identity *id)
{
	જો (id == ખાલી || id->ચાવી == ખાલી)
		પાછા 3;
	જો (!sshkey_is_cert(id->ચાવી) || id->ચાવી->cert == ખાલી)
		પાછા 3;
	જો (sshkey_is_sk(id->ચાવી) &&
	    cert_has_option(id->ચાવી->cert->critical, "verify-required"))
		પાછા 2;
	જો (sshkey_is_sk(id->ચાવી) &&
	    cert_has_option(id->ચાવી->cert->extensions, "no-touch-required"))
		પાછા 0;
	પાછા 1;
}

સ્થિર શૂન્ય
order_identities_by_prio(સંરચના idlist *list)
{
	સંરચના idlist prio[MAX_ID_PRIORITY + 1], sorted;
	સંરચના identity *id, *tmp, *dummy;
	પૂર્ણાંક p;

	માટે (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		જો (id->userprovided)
			ચાલુ;
		dummy = xcalloc(1, કદ(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		જો (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	માટે (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		જો (id->userprovided != -1)
			ચાલુ;
		સંરચના identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		મુક્ત(id);
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
સ્થિર શૂન્ય
pubkey_prepare(સંરચના ssh *ssh, Authctxt *authctxt)
{
	સંરચના identity *id, *id2, *tmp;
	સંરચના idlist agent, files, certs, agent_ચાવીઓ, *preferred;
	સંરચના sshkey *ચાવી;
	પૂર્ણાંક disallowed, agent_fd = -1, i, r, found;
	size_t j;
	સંરચના ssh_identitylist *idlist;
	અક્ષર *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_ચાવીઓ); /* keys supported by the agent */
	preferred = &authctxt->ચાવીઓ;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	માટે (i = 0; i < options.અંક_identity_files; i++) {
		ચાવી = options.identity_ચાવીઓ[i];
		જો (ચાવી && ચાવી->cert &&
		    ચાવી->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ચાલુ;
		}
		જો (ચાવી && sshkey_is_sk(ચાવી) && options.sk_provider == ખાલી) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ચાલુ;
		}
		options.identity_ચાવીઓ[i] = ખાલી;
		id = xcalloc(1, કદ(*id));
		id->agent_fd = -1;
		id->ચાવી = ચાવી;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	માટે (i = 0; i < options.અંક_certificate_files; i++) {
		ચાવી = options.certificates[i];
		જો (!sshkey_is_cert(ચાવી) || ચાવી->cert == ખાલી ||
		    ચાવી->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ચાલુ;
		}
		જો (ચાવી && sshkey_is_sk(ચાવી) && options.sk_provider == ખાલી) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ચાલુ;
		}
		id = xcalloc(1, કદ(*id));
		id->agent_fd = -1;
		id->ચાવી = ચાવી;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	જો ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		માટે (j = 0; j < idlist->nkeys; j++) {
			જો ((r = sshkey_check_rsa_length(idlist->ચાવીઓ[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->ચાવીઓ[j]));
				ચાલુ;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				જો (sshkey_equal(idlist->ચાવીઓ[j], id->ચાવી)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_ચાવીઓ, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					તોડો;
				}
			}
			જો (!found && !options.identities_only) {
				id = xcalloc(1, કદ(*id));
				/* XXX "steals" key/comment from idlist */
				id->ચાવી = idlist->ચાવીઓ[j];
				id->filename = idlist->comments[j];
				idlist->ચાવીઓ[j] = ખાલી;
				idlist->comments[j] = ખાલી;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_ચાવીઓ, &agent, next);
		order_identities_by_prio(&agent_ચાવીઓ);
		TAILQ_CONCAT(preferred, &agent_ચાવીઓ, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		જો (id->ચાવી == ખાલી || (id->ચાવી->flags & SSHKEY_FLAG_EXT) == 0)
			ચાલુ;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			જો (id2->ચાવી == ખાલી ||
			    (id2->ચાવી->flags & SSHKEY_FLAG_EXT) != 0)
				ચાલુ;
			જો (sshkey_equal(id->ચાવી, id2->ચાવી)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				તોડો;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		જો (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, કદ(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = ખાલી;
		જો (id->ચાવી == ખાલી)
			ચાલુ;
		જો (!ચાવી_type_allowed_by_config(id->ચાવી)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->ચાવી), id->filename);
			disallowed = 1;
		} નહીંતર જો (ssh != ખાલી && ssh->kex != ખાલી &&
		    ssh->kex->server_sig_algs != ખાલી &&
		    (cp = ચાવી_sig_algorithm(ssh, id->ચાવી)) == ખાલી) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->ચાવી), id->filename);
			disallowed = 1;
		}
		મુક્ત(cp);
		જો (!disallowed)
			ચાલુ;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->ચાવી);
		મુક્ત(id->filename);
		freezero(id, કદ(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		મુક્ત(ident);
	}
	debug2_f("done");
}

સ્થિર શૂન્ય
pubkey_cleanup(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	જો (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	માટે (id = TAILQ_FIRST(&authctxt->ચાવીઓ); id;
	    id = TAILQ_FIRST(&authctxt->ચાવીઓ)) {
		TAILQ_REMOVE(&authctxt->ચાવીઓ, id, next);
		sshkey_free(id->ચાવી);
		મુક્ત(id->filename);
		મુક્ત(id);
	}
}

શૂન્ય
pubkey_dump(સંરચના ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	અક્ષર *ident;

	memset(&authctxt, 0, કદ(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.ચાવીઓ, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		મુક્ત(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ખાલી;
}

સ્થિર શૂન્ય
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->ચાવીઓ, next)
		id->tried = 0;
}

સ્થિર પૂર્ણાંક
userauth_pubkey(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	પૂર્ણાંક sent = 0;
	અક્ષર *ident;
	સ્થિર પૂર્ણાંક prepared;

	જો (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	જ્યારે ((id = TAILQ_FIRST(&authctxt->ચાવીઓ))) {
		જો (id->tried++)
			પાછા (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->ચાવીઓ, id, next);
		TAILQ_INSERT_TAIL(&authctxt->ચાવીઓ, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		જો (id->ચાવી != ખાલી) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			મુક્ત(ident);
			sent = send_pubkey_test(ssh, id);
		} નહીંતર {
			debug("Trying private key: %s", id->filename);
			id->ચાવી = load_identity_file(id);
			જો (id->ચાવી != ખાલી) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->ચાવી);
				id->ચાવી = ખાલી;
				id->isprivate = 0;
			}
		}
		જો (sent)
			પાછા (sent);
	}
	પાછા (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
સ્થિર પૂર્ણાંક
userauth_kbdint(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	પૂર્ણાંક r;

	જો (authctxt->attempt_kbdint++ >= options.સંખ્યા_of_password_prompts)
		પાછા 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	જો (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_INFO_REQUEST, ખાલી);
		પાછા 0;
	}

	debug2("userauth_kbdint");
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_INFO_REQUEST, &આગત_userauth_info_req);
	પાછા 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
સ્થિર પૂર્ણાંક
આગત_userauth_info_req(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	અક્ષર *name = ખાલી, *inst = ખાલી, *lang = ખાલી, *prompt = ખાલી;
	અક્ષર *display_prompt = ખાલી, *response = ખાલી;
	u_char echo = 0;
	u_int અંક_prompts, i;
	પૂર્ણાંક r, addnl;
	size_t len;

	debug2_f("entering");

	જો (authctxt == ખાલી)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	જો ((r = sshpkt_get_cstring(ssh, &name, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ખાલી)) != 0)
		જાઓ out;
	જો ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	જો ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	જો ((r = sshpkt_get_u32(ssh, &અંક_prompts)) != 0)
		જાઓ out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, અંક_prompts)) != 0)
		જાઓ out;

	debug2_f("num_prompts %d", અંક_prompts);
	માટે (i = 0; i < અંક_prompts; i++) {
		જો ((r = sshpkt_get_cstring(ssh, &prompt, ખાલી)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			જાઓ out;
		જો (asmprintf(&display_prompt, INT_MAX, ખાલી, "(%s@%s) %s",
		    authctxt->server_user, options.host_ચાવી_alias ?
		    options.host_ચાવી_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		જો ((r = sshpkt_put_cstring(ssh, response)) != 0)
			જાઓ out;
		freezero(response, strlen(response));
		મુક્ત(prompt);
		મુક્ત(display_prompt);
		display_prompt = response = prompt = ખાલી;
	}
	/* done with parsing incoming message. */
	જો ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		જાઓ out;
	r = sshpkt_send(ssh);
 out:
	જો (response)
		freezero(response, strlen(response));
	મુક્ત(prompt);
	મુક્ત(display_prompt);
	મુક્ત(name);
	મુક્ત(inst);
	મુક્ત(lang);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_keysign(સંરચના ssh *ssh, સંરચના sshkey *ચાવી, u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen)
{
	સંરચના sshbuf *b;
	સંરચના stat st;
	pid_t pid;
	પૂર્ણાંક r, to[2], from[2], status;
	પૂર્ણાંક sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	શૂન્ય (*osigchld)(પૂર્ણાંક);

	*sigp = ખાલી;
	*lenp = 0;

	જો (stat(PATH_SSH_ચાવી_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		પાછા -1;
	}
	જો (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		પાછા -1;
	}
	જો (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		પાછા -1;
	}
	જો (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		પાછા -1;
	}
	જો ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		પાછા -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	જો (pid == 0) {
		close(from[0]);
		જો (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		જો (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		જો (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		જો (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_ચાવી_SIGN);
		execl(PATH_SSH_ચાવી_SIGN, PATH_SSH_ચાવી_SIGN, (અક્ષર *)ખાલી);
		fatal_f("exec(%s): %s", PATH_SSH_ચાવી_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	જો ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	જો (ssh_સંદેશ_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_સંદેશ_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	જો (r < 0) {
		error_f("no reply");
		જાઓ fail;
	}

	errno = 0;
	જ્યારે (waitpid(pid, &status, 0) == -1) {
		જો (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			જાઓ fail;
		}
	}
	જો (!WIFEXITED(status)) {
		error_f("exited abnormally");
		જાઓ fail;
	}
	જો (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		જાઓ fail;
	}
	જો ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		જાઓ fail;
	}
	જો (rversion != version) {
		error_f("bad version");
		જાઓ fail;
	}
	જો ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		પાછા -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
userauth_hostbased(સંરચના ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	સંરચના sshkey *ખાનગી = ખાલી;
	સંરચના sshbuf *b = ખાલી;
	u_char *sig = ખાલી, *keyblob = ખાલી;
	અક્ષર *fp = ખાલી, *chost = ખાલી, *lname = ખાલી;
	size_t siglen = 0, keylen = 0;
	પૂર્ણાંક i, r, success = 0;

	જો (authctxt->ktypes == ખાલી) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	માટે (;;) {
		જો (authctxt->active_ktype == ખાલી)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		જો (authctxt->active_ktype == ખાલી ||
		    *authctxt->active_ktype == '\0')
			તોડો;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		ખાનગી = ખાલી;
		માટે (i = 0; i < authctxt->sensitive->nkeys; i++) {
			જો (authctxt->sensitive->ચાવીઓ[i] == ખાલી ||
			    authctxt->sensitive->ચાવીઓ[i]->type == ચાવી_UNSPEC)
				ચાલુ;
			જો (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->ચાવીઓ[i]),
			    authctxt->active_ktype))
				ચાલુ;
			/* we take and free the key */
			ખાનગી = authctxt->sensitive->ચાવીઓ[i];
			authctxt->sensitive->ચાવીઓ[i] = ખાલી;
			તોડો;
		}
		/* Found one */
		જો (ખાનગી != ખાલી)
			તોડો;
		/* No more keys of this type; advance */
		authctxt->active_ktype = ખાલી;
	}
	જો (ખાનગી == ખાલી) {
		મુક્ત(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ખાલી;
		authctxt->active_ktype = ખાલી;
		debug("No more client hostkeys for hostbased authentication.");
		જાઓ out;
	}

	જો ((fp = sshkey_fingerprint(ખાનગી, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ખાલી) {
		error_f("sshkey_fingerprint failed");
		જાઓ out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(ખાનગી), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	જો (lname == ખાલી) {
		error_f("cannot get local ipaddr/name");
		જાઓ out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	જો ((b = sshbuf_new()) == ખાલી) {
		error_f("sshbuf_new failed");
		જાઓ out;
	}
	જો ((r = sshkey_to_blob(ખાનગી, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		જાઓ out;
	}
	જો ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		જાઓ out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	જો ((r = ssh_keysign(ssh, ખાનગી, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(ખાનગી), fp);
		જાઓ out;
	}
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_USERAUTH_REQUEST)) != 0 ||
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
		જાઓ out;
	}
	success = 1;

 out:
	જો (sig != ખાલી)
		freezero(sig, siglen);
	મુક્ત(keyblob);
	મુક્ત(lname);
	મુક્ત(fp);
	મુક્ત(chost);
	sshkey_free(ખાનગી);
	sshbuf_free(b);

	પાછા success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
સ્થિર પૂર્ણાંક
authmethod_is_enabled(Authmethod *method)
{
	જો (method == ખાલી)
		પાછા 0;
	/* return false if options indicate this method is disabled */
	જો  (method->enabled == ખાલી || *method->enabled == 0)
		પાછા 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	જો  (method->batch_flag != ખાલી && *method->batch_flag != 0)
		પાછા 0;
	પાછા 1;
}

સ્થિર Authmethod *
authmethod_lookup(અચલ અક્ષર *name)
{
	Authmethod *method = ખાલી;
	જો (name != ખાલી)
		માટે (method = authmethods; method->name != ખાલી; method++)
			જો (strcmp(name, method->name) == 0)
				પાછા method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	પાછા ખાલી;
}

/* XXX internal state */
સ્થિર Authmethod *current = ખાલી;
સ્થિર અક્ષર *supported = ખાલી;
સ્થિર અક્ષર *preferred = ખાલી;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
સ્થિર Authmethod *
authmethod_get(અક્ષર *authlist)
{
	અક્ષર *name = ખાલી;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	જો (authlist == ખાલી || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	જો (supported == ખાલી || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		મુક્ત(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ખાલી;
	} નહીંતર જો (current != ખાલી && authmethod_is_enabled(current))
		પાછા current;

	માટે (;;) {
		જો ((name = match_list(preferred, supported, &next)) == ખાલી) {
			debug("No more authentication methods to try.");
			current = ખાલી;
			પાછા ખાલી;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		જો ((current = authmethod_lookup(name)) != ખાલી &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			મુક્ત(name);
			પાછા current;
		}
		મુક્ત(name);
	}
}

સ્થિર અક્ષર *
authmethods_get(શૂન્ય)
{
	Authmethod *method = ખાલી;
	સંરચના sshbuf *b;
	અક્ષર *list;
	પૂર્ણાંક r;

	જો ((b = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	માટે (method = authmethods; method->name != ખાલી; method++) {
		જો (authmethod_is_enabled(method)) {
			જો ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	જો ((list = sshbuf_dup_string(b)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	પાછા list;
}
