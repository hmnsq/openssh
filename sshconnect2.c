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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#எனில் defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#அந்தர்பாவ <vis.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshconnect.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "utf8.h"
#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "sk-api.h"

#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif

/* import */
வெளி Options options;

/*
 * SSH2 key exchange
 */

நிலையான எழுத்து *xxx_host;
நிலையான கட்டமைப்பு sockaddr_storage xxx_hostaddr;
நிலையான மாறிலி கட்டமைப்பு ssh_conn_info *xxx_conn_info;
நிலையான முழு சாவி_type_allowed(கட்டமைப்பு sshkey *, மாறிலி எழுத்து *);

நிலையான முழு
verify_host_சாவி_callback(கட்டமைப்பு sshkey *hostkey, கட்டமைப்பு ssh *ssh)
{
	முழு r;

	எனில் ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	எனில் (!சாவி_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	எனில் (verify_host_சாவி(xxx_host, (கட்டமைப்பு sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	திரும்பு 0;
}

/* Returns the first item from a comma-separated algorithm list */
நிலையான எழுத்து *
first_alg(மாறிலி எழுத்து *algs)
{
	எழுத்து *ret, *cp;

	ret = xstrdup(algs);
	எனில் ((cp = strchr(ret, ',')) != வெற்று)
		*cp = '\0';
	திரும்பு ret;
}

நிலையான எழுத்து *
order_hostkeyalgs(எழுத்து *host, கட்டமைப்பு sockaddr *hostaddr, u_short port,
    மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	எழுத்து *oavail = வெற்று, *avail = வெற்று, *first = வெற்று, *last = வெற்று;
	எழுத்து *alg = வெற்று, *hostname = வெற்று, *ret = வெற்று, *best = வெற்று;
	size_t maxlen;
	கட்டமைப்பு hostkeys *hostkeys = வெற்று;
	முழு ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, வெற்று);
	hostkeys = init_hostkeys();
	க்கு (i = 0; i < options.இலக்கம்_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	க்கு (i = 0; i < options.இலக்கம்_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	எனில் (options.known_hosts_command != வெற்று) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, வெற்று, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	எனில் (lookup_சாவி_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), வெற்று)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		செல் out;
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
	செய் { \
		எனில் (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} போது (0)

	போது ((alg = strsep(&avail, ",")) && *alg != '\0') {
		எனில் ((ktype = sshkey_type_from_name(alg)) == சாவி_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		எனில் (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			தொடர்;
		}
		/* If the key appears in known_hosts then prefer it */
		எனில் (lookup_சாவி_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), வெற்று)) {
			ALG_APPEND(first, alg);
			தொடர்;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	எனில் (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	இல்லையெனில்
		debug3_f("no algorithms matched; accept original");
 out:
	விடுவி(best);
	விடுவி(first);
	விடுவி(last);
	விடுவி(hostname);
	விடுவி(oavail);
	free_hostkeys(hostkeys);

	திரும்பு ret;
}

வெறுமை
ssh_kex2(கட்டமைப்பு ssh *ssh, எழுத்து *host, கட்டமைப்பு sockaddr_storage *hostaddr,
    u_short port, மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	எழுத்து *myproposal[PROPOSAL_MAX];
	எழுத்து *all_சாவி, *hkalgs = வெற்று;
	முழு r, use_known_hosts_order = 0;

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
	எனில் (options.hostkeyalgorithms == வெற்று ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_சாவி = sshkey_alg_list(0, 0, 1, ',');
	எனில் ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_சாவி)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	விடுவி(all_சாவி);

	எனில் (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (கட்டமைப்பு sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	விடுவி(hkalgs);

	/* start key exchange */
	எனில் ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_சாவி=&verify_host_சாவி_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

வகைவரை கட்டமைப்பு cauthctxt Authctxt;
வகைவரை கட்டமைப்பு cauthmethod Authmethod;
வகைவரை கட்டமைப்பு identity Identity;
வகைவரை கட்டமைப்பு idlist Idlist;

கட்டமைப்பு identity {
	TAILQ_ENTRY(identity) next;
	முழு	agent_fd;		/* >=0 if agent supports key */
	கட்டமைப்பு sshkey	*சாவி;		/* public/private key */
	எழுத்து	*filename;		/* comment for agent-only keys */
	முழு	tried;
	முழு	isprivate;		/* key points to the private key */
	முழு	userprovided;
};
TAILQ_HEAD(idlist, identity);

கட்டமைப்பு cauthctxt {
	மாறிலி எழுத்து *server_user;
	மாறிலி எழுத்து *local_user;
	மாறிலி எழுத்து *host;
	மாறிலி எழுத்து *service;
	கட்டமைப்பு cauthmethod *method;
	sig_atomic_t success;
	எழுத்து *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	கட்டமைப்பு idlist சாவிகள்;
	முழு agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	எழுத்து *oktypes, *ktypes;
	மாறிலி எழுத்து *active_ktype;
	/* kbd-interactive */
	முழு info_req_seen;
	முழு attempt_kbdint;
	/* password */
	முழு attempt_passwd;
	/* generic */
	வெறுமை *methoddata;
};

கட்டமைப்பு cauthmethod {
	எழுத்து	*name;		/* string to compare against server's list */
	முழு	(*userauth)(கட்டமைப்பு ssh *ssh);
	வெறுமை	(*cleanup)(கட்டமைப்பு ssh *ssh);
	முழு	*enabled;	/* flag in option struct that enables method */
	முழு	*batch_flag;	/* flag in option struct that disables method */
};

நிலையான முழு உள்ளீடு_userauth_service_accept(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_success(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_failure(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_banner(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_error(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_info_req(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_pk_ok(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_userauth_passwd_changereq(முழு, uint32_t, கட்டமைப்பு ssh *);

நிலையான முழு userauth_none(கட்டமைப்பு ssh *);
நிலையான முழு userauth_pubkey(கட்டமைப்பு ssh *);
நிலையான முழு userauth_passwd(கட்டமைப்பு ssh *);
நிலையான முழு userauth_kbdint(கட்டமைப்பு ssh *);
நிலையான முழு userauth_hostbased(கட்டமைப்பு ssh *);

#ifdef GSSAPI
நிலையான முழு userauth_gssapi(கட்டமைப்பு ssh *);
நிலையான வெறுமை userauth_gssapi_cleanup(கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_gssapi_response(முழு type, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_gssapi_token(முழு type, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_gssapi_error(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_gssapi_errtok(முழு, uint32_t, கட்டமைப்பு ssh *);
#endif

வெறுமை	userauth(கட்டமைப்பு ssh *, எழுத்து *);

நிலையான வெறுமை pubkey_cleanup(கட்டமைப்பு ssh *);
நிலையான முழு sign_and_send_pubkey(கட்டமைப்பு ssh *ssh, Identity *);
நிலையான வெறுமை pubkey_prepare(கட்டமைப்பு ssh *, Authctxt *);
நிலையான வெறுமை pubkey_reset(Authctxt *);
நிலையான கட்டமைப்பு sshkey *load_identity_file(Identity *);

நிலையான Authmethod *authmethod_get(எழுத்து *authlist);
நிலையான Authmethod *authmethod_lookup(மாறிலி எழுத்து *name);
நிலையான எழுத்து *authmethods_get(வெறுமை);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		வெற்று},
#endif
	{"hostbased",
		userauth_hostbased,
		வெற்று,
		&options.hostbased_authentication,
		வெற்று},
	{"publickey",
		userauth_pubkey,
		வெற்று,
		&options.pubkey_authentication,
		வெற்று},
	{"keyboard-interactive",
		userauth_kbdint,
		வெற்று,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		வெற்று,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		வெற்று,
		வெற்று,
		வெற்று},
	{வெற்று, வெற்று, வெற்று, வெற்று, வெற்று}
};

வெறுமை
ssh_userauth2(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *local_user,
    மாறிலி எழுத்து *server_user, எழுத்து *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	முழு r;

	எனில் (options.preferred_authentications == வெற்று)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, அளவு(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = வெற்று;
	authctxt.methoddata = வெற்று;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = வெற்று;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#எனில் GSSAPI
	authctxt.gss_supported_mechs = வெற்று;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	எனில் (authctxt.method == வெற்று)
		fatal_f("internal error: cannot send userauth none request");

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &உள்ளீடு_userauth_error);
	ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, kex_உள்ளீடு_ext_info);
	ssh_dispatch_set(ssh, SSH2_செய்தி_SERVICE_ACCEPT, &உள்ளீடு_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	எனில் (authctxt.gss_supported_mechs != வெற்று) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = வெற்று;
	}
#endif
	ssh->authctxt = வெற்று;

	ssh_dispatch_range(ssh, SSH2_செய்தி_USERAUTH_MIN, SSH2_செய்தி_USERAUTH_MAX, வெற்று);

	எனில் (!authctxt.success)
		fatal("Authentication failed.");
	எனில் (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} இல்லையெனில் {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

நிலையான முழு
உள்ளீடு_userauth_service_accept(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	முழு r;

	எனில் (ssh_packet_remaining(ssh) > 0) {
		எழுத்து *reply;

		எனில் ((r = sshpkt_get_cstring(ssh, &reply, வெற்று)) != 0)
			செல் out;
		debug2("service_accept: %s", reply);
		விடுவி(reply);
	} இல்லையெனில் {
		debug2("buggy server: service_accept w/o service");
	}
	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		செல் out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_உள்ளீடு_ext_info : &உள்ளீடு_userauth_error);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_SUCCESS, &உள்ளீடு_userauth_success);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_FAILURE, &உள்ளீடு_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_BANNER, &உள்ளீடு_userauth_banner);
	r = 0;
 out:
	திரும்பு r;
}

வெறுமை
userauth(கட்டமைப்பு ssh *ssh, எழுத்து *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	எனில் (authctxt->method != வெற்று && authctxt->method->cleanup != வெற்று)
		authctxt->method->cleanup(ssh);

	விடுவி(authctxt->methoddata);
	authctxt->methoddata = வெற்று;
	எனில் (authlist == வெற்று) {
		authlist = authctxt->authlist;
	} இல்லையெனில் {
		விடுவி(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	க்கு (;;) {
		Authmethod *method = authmethod_get(authlist);
		எனில் (method == வெற்று)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_செய்தி_USERAUTH_PER_METHOD_MIN,
		    SSH2_செய்தி_USERAUTH_PER_METHOD_MAX, வெற்று);

		/* and try new method */
		எனில் (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			நிறுத்து;
		} இல்லையெனில் {
			debug2("we did not send a packet, disable method");
			method->enabled = வெற்று;
		}
	}
}

நிலையான முழு
உள்ளீடு_userauth_error(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_userauth_banner(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	எழுத்து *செய்தி = வெற்று;
	size_t len;
	முழு r;

	debug3_f("entering");
	எனில் ((r = sshpkt_get_cstring(ssh, &செய்தி, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, வெற்று, வெற்று)) != 0)
		செல் out;
	எனில் (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", செய்தி);
	r = 0;
 out:
	விடுவி(செய்தி);
	திரும்பு r;
}

நிலையான முழு
உள்ளீடு_userauth_success(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	எனில் (authctxt == வெற்று)
		fatal_f("no authentication context");
	விடுவி(authctxt->authlist);
	authctxt->authlist = வெற்று;
	எனில் (authctxt->method != வெற்று && authctxt->method->cleanup != வெற்று)
		authctxt->method->cleanup(ssh);
	விடுவி(authctxt->methoddata);
	authctxt->methoddata = வெற்று;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, dispatch_protocol_error);
	திரும்பு 0;
}

#எனில் 0
நிலையான முழு
உள்ளீடு_userauth_success_unexpected(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	எனில் (authctxt == வெற்று)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	திரும்பு 0;
}
#endif

நிலையான முழு
உள்ளீடு_userauth_failure(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	எழுத்து *authlist = வெற்று;
	u_char partial;

	எனில் (authctxt == வெற்று)
		fatal("input_userauth_failure: no authentication context");

	எனில் (sshpkt_get_cstring(ssh, &authlist, வெற்று) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		செல் out;

	எனில் (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = வெற்று;
 out:
	விடுவி(authlist);
	திரும்பு 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
நிலையான எழுத்து *
format_identity(Identity *id)
{
	எழுத்து *fp = வெற்று, *ret = வெற்று;
	மாறிலி எழுத்து *note = "";

	எனில் (id->சாவி != வெற்று) {
		fp = sshkey_fingerprint(id->சாவி, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	எனில் (id->சாவி) {
		எனில் ((id->சாவி->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		இல்லையெனில் எனில் (sshkey_is_sk(id->சாவி))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->சாவி ? sshkey_type(id->சாவி) : "", id->சாவி ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	விடுவி(fp);
	திரும்பு ret;
}

நிலையான முழு
உள்ளீடு_userauth_pk_ok(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshbuf *keyblob = வெற்று;
	Identity *id = வெற்று;
	முழு pktype, found = 0, sent = 0;
	எழுத்து *pkalg = வெற்று, *fp = வெற்று, *ident = வெற்று;
	முழு r;

	எனில் (authctxt == வெற்று)
		fatal_f("no authentication context");

	எனில் ((r = sshpkt_get_cstring(ssh, &pkalg, வெற்று)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் done;

	எனில் (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		செல் done;
	}
	எனில் ((pktype = sshkey_type_from_name(pkalg)) == சாவி_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		செல் done;
	}
	/* inner key type should match signature type */
	எனில் ((r = sshkey_fromb_allowlist(keyblob, &சாவி, pkalg, வெற்று)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		செல் done;
	}
	எனில் (சாவி->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    சாவி->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		செல் done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->சாவிகள், idlist, next) {
		எனில் (sshkey_equal(சாவி, id->சாவி)) {
			found = 1;
			நிறுத்து;
		}
	}
	எனில் (!found || id == வெற்று) {
		fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(சாவி), fp == வெற்று ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		செல் done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(சாவி);
	sshbuf_free(keyblob);
	விடுவி(ident);
	விடுவி(fp);
	விடுவி(pkalg);

	/* try another method if we did not send a packet */
	எனில் (r == 0 && sent == 0)
		userauth(ssh, வெற்று);
	திரும்பு r;
}

#ifdef GSSAPI
நிலையான முழு
userauth_gssapi(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = வெற்று;
	OM_uint32 min;
	முழு r, ok = 0;
	gss_OID mech = வெற்று;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	எனில் (authctxt->gss_supported_mechs == வெற்று)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	போது (authctxt->mech_tried < authctxt->gss_supported_mechs->மொத்தம் &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		எனில் (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} இல்லையெனில் {
			authctxt->mech_tried++;
		}
	}

	எனில் (!ok || mech == வெற்று)
		திரும்பு 0;

	authctxt->methoddata=(வெறுமை *)gssctxt;

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_RESPONSE, &உள்ளீடு_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN, &உள்ளீடு_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERROR, &உள்ளீடு_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK, &உள்ளீடு_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	திரும்பு 1;
}

நிலையான வெறுமை
userauth_gssapi_cleanup(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = வெற்று;
}

நிலையான OM_uint32
process_gssapi_token(கட்டமைப்பு ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	முழு r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	எனில் (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_செய்தி_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_செய்தி_USERAUTH_GSSAPI_TOKEN;

		எனில் ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.மதிப்பு,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	எனில் (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		எனில் (!(flags & GSS_C_INTEG_FLAG)) {
			எனில் ((r = sshpkt_start(ssh,
			    SSH2_செய்தி_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} இல்லையெனில் {
			கட்டமைப்பு sshbuf *b;

			எனில் ((b = sshbuf_new()) == வெற்று)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			எனில் ((gssbuf.மதிப்பு = sshbuf_mutable_ptr(b)) == வெற்று)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			எனில் (!GSS_ERROR(status)) {
				எனில் ((r = sshpkt_start(ssh,
				    SSH2_செய்தி_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.மதிப்பு,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	திரும்பு status;
}

நிலையான முழு
உள்ளீடு_gssapi_response(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = வெற்று;
	முழு r;

	எனில் (authctxt == வெற்று)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	எனில் ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		செல் done;

	எனில் (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, வெற்று);
		செல் ok;
	}

	எனில் (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	எனில் ((r = sshpkt_get_end(ssh)) != 0)
		செல் done;

	எனில் (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, வெற்று);
		செல் ok;
	}
 ok:
	r = 0;
 done:
	விடுவி(oidv);
	திரும்பு r;
}

நிலையான முழு
உள்ளீடு_gssapi_token(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = வெற்று;
	size_t len;
	OM_uint32 status;
	முழு r;

	எனில் (authctxt == வெற்று)
		fatal("input_gssapi_response: no authentication context");

	எனில் ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;

	recv_tok.மதிப்பு = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	எனில் (GSS_ERROR(status)) {
		userauth(ssh, வெற்று);
		/* ok */
	}
	r = 0;
 out:
	விடுவி(p);
	திரும்பு r;
}

நிலையான முழு
உள்ளீடு_gssapi_errtok(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = வெற்று;
	size_t len;
	முழு r;

	எனில் (authctxt == வெற்று)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	எனில் ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		விடுவி(p);
		திரும்பு r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.மதிப்பு = p;
	recv_tok.length = len;
	(வெறுமை)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, வெற்று);
	விடுவி(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_gssapi_error(முழு type, uint32_t plen, கட்டமைப்பு ssh *ssh)
{
	எழுத்து *செய்தி = வெற்று;
	எழுத்து *lang = வெற்று;
	முழு r;

	எனில் ((r = sshpkt_get_u32(ssh, வெற்று)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, வெற்று)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &செய்தி, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, வெற்று)) != 0)
		செல் out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", செய்தி);
 out:
	விடுவி(செய்தி);
	விடுவி(lang);
	திரும்பு r;
}
#endif /* GSSAPI */

நிலையான முழு
userauth_none(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	முழு r;

	/* initial userauth request */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	திரும்பு 1;
}

நிலையான முழு
userauth_passwd(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	எழுத்து *password, *prompt = வெற்று;
	மாறிலி எழுத்து *host = options.host_சாவி_alias ?  options.host_சாவி_alias :
	    authctxt->host;
	முழு r;

	எனில் (authctxt->attempt_passwd++ >= options.எண்_of_password_prompts)
		திரும்பு 0;

	எனில் (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	விடுவி(prompt);
	எனில் (password != வெற்று)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_PASSWD_CHANGEREQ,
	    &உள்ளீடு_userauth_passwd_changereq);

	திரும்பு 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
நிலையான முழு
உள்ளீடு_userauth_passwd_changereq(முழு type, uint32_t seqnr, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	எழுத்து *info = வெற்று, *lang = வெற்று, *password = வெற்று, *retype = வெற்று;
	எழுத்து prompt[256];
	மாறிலி எழுத்து *host;
	முழு r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	எனில் (authctxt == வெற்று)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_சாவி_alias ? options.host_சாவி_alias : authctxt->host;

	எனில் ((r = sshpkt_get_cstring(ssh, &info, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, வெற்று)) != 0)
		செல் out;
	எனில் ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		செல் out;

	snprintf(prompt, அளவு(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	எனில் ((r = sshpkt_put_cstring(ssh, password)) != 0)
		செல் out;

	freezero(password, strlen(password));
	password = வெற்று;
	போது (password == வெற்று) {
		snprintf(prompt, அளவு(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		எனில் (password == வெற்று) {
			/* bail out */
			r = 0;
			செல் out;
		}
		snprintf(prompt, அளவு(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		எனில் (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = வெற்று;
		}
		freezero(retype, strlen(retype));
	}
	எனில் ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		செல் out;

	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_PASSWD_CHANGEREQ,
	    &உள்ளீடு_userauth_passwd_changereq);
	r = 0;
 out:
	எனில் (password)
		freezero(password, strlen(password));
	விடுவி(info);
	விடுவி(lang);
	திரும்பு r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
நிலையான எழுத்து *
சாவி_sig_algorithm(கட்டமைப்பு ssh *ssh, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து *allowed, *oallowed, *cp, *tmp, *alg = வெற்று;
	மாறிலி எழுத்து *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	எனில் (ssh == வெற்று || ssh->kex->server_sig_algs == வெற்று ||
	    (சாவி->type != சாவி_RSA && சாவி->type != சாவி_RSA_CERT) ||
	    (சாவி->type == சாவி_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		திரும்பு match_list(sshkey_ssh_name(சாவி),
		    options.pubkey_accepted_algos, வெற்று);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	எனில் (சாவி->type == சாவி_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	போது ((cp = strsep(&allowed, ",")) != வெற்று) {
		எனில் (sshkey_type_from_name(cp) != சாவி->type)
			தொடர்;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, வெற்று);
		எனில் (tmp != வெற்று)
			alg = xstrdup(cp);
		விடுவி(tmp);
		எனில் (alg != வெற்று)
			நிறுத்து;
	}
	விடுவி(oallowed);
	திரும்பு alg;
}

நிலையான முழு
identity_sign(கட்டமைப்பு identity *id, u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen, u_int compat, மாறிலி எழுத்து *alg)
{
	கட்டமைப்பு sshkey *sign_சாவி = வெற்று, *prv = வெற்று;
	முழு is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு notifier_ctx *notifier = வெற்று;
	எழுத்து *fp = வெற்று, *pin = வெற்று, *prompt = வெற்று;

	*sigp = வெற்று;
	*lenp = 0;

	/* The agent supports this key. */
	எனில் (id->சாவி != வெற்று && id->agent_fd != -1) {
		திரும்பு ssh_agent_sign(id->agent_fd, id->சாவி, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	எனில் (id->சாவி != வெற்று &&
	    (id->isprivate || (id->சாவி->flags & SSHKEY_FLAG_EXT))) {
		sign_சாவி = id->சாவி;
		is_agent = 1;
	} இல்லையெனில் {
		/* Load the private key from the file. */
		எனில் ((prv = load_identity_file(id)) == வெற்று)
			திரும்பு SSH_ERR_சாவி_NOT_FOUND;
		எனில் (id->சாவி != வெற்று && !sshkey_equal_public(prv, id->சாவி)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_சாவி_NOT_FOUND;
			செல் out;
		}
		sign_சாவி = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	எனில் (!is_agent && sshkey_is_sk(sign_சாவி) &&
	    (sign_சாவி->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		எனில் ((fp = sshkey_fingerprint(sign_சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_சாவி), fp);
		விடுவி(fp);
	}
	எனில் ((r = sshkey_sign(sign_சாவி, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		எனில் (!retried && pin == வெற்று && !is_agent &&
		    sshkey_is_sk(sign_சாவி) &&
		    r == SSH_ERR_சாவி_WRONG_PASSPHRASE) {
			notify_complete(notifier, வெற்று);
			notifier = வெற்று;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_சாவி), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			செல் retry_pin;
		}
		செல் out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	எனில் (id->சாவி != வெற்று && (id->சாவி->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		செல் out;
	}
	/* success */
	r = 0;
 out:
	விடுவி(prompt);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : வெற்று);
	sshkey_free(prv);
	திரும்பு r;
}

நிலையான முழு
id_filename_matches(Identity *id, Identity *private_id)
{
	நிலையான மாறிலி எழுத்து * மாறிலி suffixes[] = { ".pub", "-cert.pub", வெற்று };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	எனில் (strcmp(id->filename, private_id->filename) == 0)
		திரும்பு 1;
	க்கு (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		எனில் (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			திரும்பு 1;
	}
	திரும்பு 0;
}

நிலையான முழு
sign_and_send_pubkey(கட்டமைப்பு ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	கட்டமைப்பு sshbuf *b = வெற்று;
	Identity *private_id, *sign_id = வெற்று;
	u_char *signature = வெற்று;
	size_t slen = 0, skip = 0;
	முழு r, fallback_sigtype, sent = 0;
	எழுத்து *alg = வெற்று, *fp = வெற்று;
	மாறிலி எழுத்து *loc = "", *method = "publickey";
	முழு hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	எனில் ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	எனில் ((fp = sshkey_fingerprint(id->சாவி, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == வெற்று)
		திரும்பு 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->சாவி), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	எனில் (id->agent_fd == -1 && sshkey_is_cert(id->சாவி)) {
		TAILQ_FOREACH(private_id, &authctxt->சாவிகள், next) {
			எனில் (sshkey_equal_public(id->சாவி, private_id->சாவி) &&
			    id->சாவி->type != private_id->சாவி->type) {
				sign_id = private_id;
				நிறுத்து;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		எனில் (sign_id == வெற்று &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->சாவி->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->சாவிகள், next) {
				எனில் (private_id->சாவி == வெற்று &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					நிறுத்து;
				}
			}
		}
		எனில் (sign_id != வெற்று) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} இல்லையெனில் {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	எனில் (sign_id == வெற்று)
		sign_id = id;

	/* assemble and sign data */
	க்கு (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		விடுவி(alg);
		slen = 0;
		signature = வெற்று;
		எனில் ((alg = சாவி_sig_algorithm(fallback_sigtype ? வெற்று : ssh,
		    id->சாவி)) == வெற்று) {
			error_f("no mutual signature supported");
			செல் out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		எனில் ((b = sshbuf_new()) == வெற்று)
			fatal_f("sshbuf_new failed");
		எனில் ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		எனில் ((r = sshbuf_put_u8(b, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->சாவி, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		எனில் (hostbound) {
			எனில் (ssh->kex->initial_hostkey == வெற்று) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			எனில் ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		எனில் (r == 0)
			நிறுத்து;
		இல்லையெனில் எனில் (r == SSH_ERR_சாவி_NOT_FOUND)
			செல் out; /* soft failure */
		இல்லையெனில் எனில் (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			எனில் (sign_id->agent_fd != -1)
				loc = "agent ";
			இல்லையெனில் எனில் (sign_id->சாவி != வெற்று &&
			    (sign_id->சாவி->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->சாவி), fp);
			தொடர்;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->சாவி), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		செல் out;
	}
	எனில் (slen == 0 || signature == வெற்று) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	எனில் ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	எனில் ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	விடுவி(fp);
	விடுவி(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	திரும்பு sent;
}

நிலையான முழு
send_pubkey_test(கட்டமைப்பு ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = வெற்று;
	எழுத்து *alg = வெற்று;
	size_t bloblen;
	u_int have_sig = 0;
	முழு sent = 0, r;

	எனில் ((alg = சாவி_sig_algorithm(ssh, id->சாவி)) == வெற்று) {
		debug_f("no mutual signature algorithm");
		செல் out;
	}

	எனில் ((r = sshkey_to_blob(id->சாவி, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		செல் out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_PK_OK, &உள்ளீடு_userauth_pk_ok);

	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
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
	விடுவி(alg);
	விடுவி(blob);
	திரும்பு sent;
}

நிலையான கட்டமைப்பு sshkey *
load_identity_file(Identity *id)
{
	கட்டமைப்பு sshkey *தனிப்பட்ட = வெற்று;
	எழுத்து prompt[300], *passphrase, *comment;
	முழு r, quit = 0, i;
	கட்டமைப்பு stat st;

	எனில் (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		திரும்பு வெற்று;
	}
	snprintf(prompt, அளவு prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	க்கு (i = 0; i <= options.எண்_of_password_prompts; i++) {
		எனில் (i == 0)
			passphrase = "";
		இல்லையெனில் {
			passphrase = read_passphrase(prompt, 0);
			எனில் (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				விடுவி(passphrase);
				நிறுத்து;
			}
		}
		தேர்வு ((r = sshkey_load_private_type(சாவி_UNSPEC, id->filename,
		    passphrase, &தனிப்பட்ட, &comment))) {
		நிலை 0:
			நிறுத்து;
		நிலை SSH_ERR_சாவி_WRONG_PASSPHRASE:
			எனில் (options.batch_mode) {
				quit = 1;
				நிறுத்து;
			}
			எனில் (i != 0)
				debug2("bad passphrase given, try again...");
			நிறுத்து;
		நிலை SSH_ERR_SYSTEM_ERROR:
			எனில் (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				நிறுத்து;
			}
			/* FALLTHROUGH */
		இயல்பு:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			நிறுத்து;
		}
		எனில் (தனிப்பட்ட != வெற்று && sshkey_is_sk(தனிப்பட்ட) &&
		    options.sk_provider == வெற்று) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(தனிப்பட்ட);
			தனிப்பட்ட = வெற்று;
			quit = 1;
		}
		எனில் (!quit && (r = sshkey_check_rsa_length(தனிப்பட்ட,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(தனிப்பட்ட);
			தனிப்பட்ட = வெற்று;
			quit = 1;
		}
		எனில் (!quit && தனிப்பட்ட != வெற்று && id->agent_fd == -1 &&
		    !(id->சாவி && id->isprivate))
			maybe_add_சாவி_to_agent(id->filename, தனிப்பட்ட, comment,
			    passphrase);
		எனில் (i > 0)
			freezero(passphrase, strlen(passphrase));
		விடுவி(comment);
		எனில் (தனிப்பட்ட != வெற்று || quit)
			நிறுத்து;
	}
	திரும்பு தனிப்பட்ட;
}

நிலையான முழு
சாவி_type_allowed(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *allowlist)
{
	எனில் (match_pattern_list(sshkey_ssh_name(சாவி), allowlist, 0) == 1)
		திரும்பு 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	தேர்வு (சாவி->type) {
	நிலை சாவி_RSA:
		எனில் (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			திரும்பு 1;
		எனில் (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			திரும்பு 1;
		நிறுத்து;
	நிலை சாவி_RSA_CERT:
		எனில் (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			திரும்பு 1;
		எனில் (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			திரும்பு 1;
		நிறுத்து;
	}
	திரும்பு 0;
}

நிலையான முழு
சாவி_type_allowed_by_config(கட்டமைப்பு sshkey *சாவி)
{
	திரும்பு சாவி_type_allowed(சாவி, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
நிலையான முழு
get_agent_identities(கட்டமைப்பு ssh *ssh, முழு *agent_fdp,
    கட்டமைப்பு ssh_identitylist **idlistp)
{
	முழு r, agent_fd;
	கட்டமைப்பு ssh_identitylist *idlist;

	எனில் ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		எனில் (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		திரும்பு r;
	}
	எனில் (ssh != வெற்று && ssh->kex != வெற்று) {
		எனில் ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		இல்லையெனில்
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	எனில் ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		திரும்பு r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	திரும்பு 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
நிலையான முழு
cert_has_option(கட்டமைப்பு sshbuf *oblob, மாறிலி எழுத்து *target)
{
	கட்டமைப்பு sshbuf *c = வெற்று, *data = வெற்று;
	எழுத்து *name = வெற்று;
	முழு r, found = 0;

	எனில் (oblob == வெற்று || (c = sshbuf_fromb(oblob)) == வெற்று)
		திரும்பு 0;
	போது (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = வெற்று;
		விடுவி(name);
		name = வெற்று;
		எனில் ((r = sshbuf_get_cstring(c, &name, வெற்று)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			நிறுத்து;
		எனில் (strcmp(name, target) == 0) {
			found = 1;
			நிறுத்து;
		}
	}
	sshbuf_free(data);
	விடுவி(name);
	sshbuf_free(c);
	திரும்பு found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
நிலையான முழு
identity_prioritise(கட்டமைப்பு identity *id)
{
	எனில் (id == வெற்று || id->சாவி == வெற்று)
		திரும்பு 3;
	எனில் (!sshkey_is_cert(id->சாவி) || id->சாவி->cert == வெற்று)
		திரும்பு 3;
	எனில் (sshkey_is_sk(id->சாவி) &&
	    cert_has_option(id->சாவி->cert->critical, "verify-required"))
		திரும்பு 2;
	எனில் (sshkey_is_sk(id->சாவி) &&
	    cert_has_option(id->சாவி->cert->extensions, "no-touch-required"))
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான வெறுமை
order_identities_by_prio(கட்டமைப்பு idlist *list)
{
	கட்டமைப்பு idlist prio[MAX_ID_PRIORITY + 1], sorted;
	கட்டமைப்பு identity *id, *tmp, *dummy;
	முழு p;

	க்கு (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		எனில் (id->userprovided)
			தொடர்;
		dummy = xcalloc(1, அளவு(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		எனில் (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	க்கு (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		எனில் (id->userprovided != -1)
			தொடர்;
		கட்டமைப்பு identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		விடுவி(id);
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
நிலையான வெறுமை
pubkey_prepare(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
{
	கட்டமைப்பு identity *id, *id2, *tmp;
	கட்டமைப்பு idlist agent, files, certs, agent_சாவிகள், *preferred;
	கட்டமைப்பு sshkey *சாவி;
	முழு disallowed, agent_fd = -1, i, r, found;
	size_t j;
	கட்டமைப்பு ssh_identitylist *idlist;
	எழுத்து *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_சாவிகள்); /* keys supported by the agent */
	preferred = &authctxt->சாவிகள்;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	க்கு (i = 0; i < options.இலக்கம்_identity_files; i++) {
		சாவி = options.identity_சாவிகள்[i];
		எனில் (சாவி && சாவி->cert &&
		    சாவி->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			தொடர்;
		}
		எனில் (சாவி && sshkey_is_sk(சாவி) && options.sk_provider == வெற்று) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			தொடர்;
		}
		options.identity_சாவிகள்[i] = வெற்று;
		id = xcalloc(1, அளவு(*id));
		id->agent_fd = -1;
		id->சாவி = சாவி;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	க்கு (i = 0; i < options.இலக்கம்_certificate_files; i++) {
		சாவி = options.certificates[i];
		எனில் (!sshkey_is_cert(சாவி) || சாவி->cert == வெற்று ||
		    சாவி->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			தொடர்;
		}
		எனில் (சாவி && sshkey_is_sk(சாவி) && options.sk_provider == வெற்று) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			தொடர்;
		}
		id = xcalloc(1, அளவு(*id));
		id->agent_fd = -1;
		id->சாவி = சாவி;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	எனில் ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		க்கு (j = 0; j < idlist->nkeys; j++) {
			எனில் ((r = sshkey_check_rsa_length(idlist->சாவிகள்[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->சாவிகள்[j]));
				தொடர்;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				எனில் (sshkey_equal(idlist->சாவிகள்[j], id->சாவி)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_சாவிகள், id, next);
					id->agent_fd = agent_fd;
					found = 1;
					நிறுத்து;
				}
			}
			எனில் (!found && !options.identities_only) {
				id = xcalloc(1, அளவு(*id));
				/* XXX "steals" key/comment from idlist */
				id->சாவி = idlist->சாவிகள்[j];
				id->filename = idlist->comments[j];
				idlist->சாவிகள்[j] = வெற்று;
				idlist->comments[j] = வெற்று;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_சாவிகள், &agent, next);
		order_identities_by_prio(&agent_சாவிகள்);
		TAILQ_CONCAT(preferred, &agent_சாவிகள், next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		எனில் (id->சாவி == வெற்று || (id->சாவி->flags & SSHKEY_FLAG_EXT) == 0)
			தொடர்;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			எனில் (id2->சாவி == வெற்று ||
			    (id2->சாவி->flags & SSHKEY_FLAG_EXT) != 0)
				தொடர்;
			எனில் (sshkey_equal(id->சாவி, id2->சாவி)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				நிறுத்து;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		எனில் (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, அளவு(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = வெற்று;
		எனில் (id->சாவி == வெற்று)
			தொடர்;
		எனில் (!சாவி_type_allowed_by_config(id->சாவி)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->சாவி), id->filename);
			disallowed = 1;
		} இல்லையெனில் எனில் (ssh != வெற்று && ssh->kex != வெற்று &&
		    ssh->kex->server_sig_algs != வெற்று &&
		    (cp = சாவி_sig_algorithm(ssh, id->சாவி)) == வெற்று) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->சாவி), id->filename);
			disallowed = 1;
		}
		விடுவி(cp);
		எனில் (!disallowed)
			தொடர்;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->சாவி);
		விடுவி(id->filename);
		freezero(id, அளவு(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		விடுவி(ident);
	}
	debug2_f("done");
}

நிலையான வெறுமை
pubkey_cleanup(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	எனில் (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	க்கு (id = TAILQ_FIRST(&authctxt->சாவிகள்); id;
	    id = TAILQ_FIRST(&authctxt->சாவிகள்)) {
		TAILQ_REMOVE(&authctxt->சாவிகள், id, next);
		sshkey_free(id->சாவி);
		விடுவி(id->filename);
		விடுவி(id);
	}
}

வெறுமை
pubkey_dump(கட்டமைப்பு ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	எழுத்து *ident;

	memset(&authctxt, 0, அளவு(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.சாவிகள், next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		விடுவி(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = வெற்று;
}

நிலையான வெறுமை
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->சாவிகள், next)
		id->tried = 0;
}

நிலையான முழு
userauth_pubkey(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	முழு sent = 0;
	எழுத்து *ident;
	நிலையான முழு prepared;

	எனில் (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	போது ((id = TAILQ_FIRST(&authctxt->சாவிகள்))) {
		எனில் (id->tried++)
			திரும்பு (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->சாவிகள், id, next);
		TAILQ_INSERT_TAIL(&authctxt->சாவிகள், id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		எனில் (id->சாவி != வெற்று) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			விடுவி(ident);
			sent = send_pubkey_test(ssh, id);
		} இல்லையெனில் {
			debug("Trying private key: %s", id->filename);
			id->சாவி = load_identity_file(id);
			எனில் (id->சாவி != வெற்று) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->சாவி);
				id->சாவி = வெற்று;
				id->isprivate = 0;
			}
		}
		எனில் (sent)
			திரும்பு (sent);
	}
	திரும்பு (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
நிலையான முழு
userauth_kbdint(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	முழு r;

	எனில் (authctxt->attempt_kbdint++ >= options.எண்_of_password_prompts)
		திரும்பு 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	எனில் (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_INFO_REQUEST, வெற்று);
		திரும்பு 0;
	}

	debug2("userauth_kbdint");
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_INFO_REQUEST, &உள்ளீடு_userauth_info_req);
	திரும்பு 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
நிலையான முழு
உள்ளீடு_userauth_info_req(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	எழுத்து *name = வெற்று, *inst = வெற்று, *lang = வெற்று, *prompt = வெற்று;
	எழுத்து *display_prompt = வெற்று, *response = வெற்று;
	u_char echo = 0;
	u_int இலக்கம்_prompts, i;
	முழு r, addnl;
	size_t len;

	debug2_f("entering");

	எனில் (authctxt == வெற்று)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	எனில் ((r = sshpkt_get_cstring(ssh, &name, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, வெற்று)) != 0)
		செல் out;
	எனில் ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	எனில் ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	எனில் ((r = sshpkt_get_u32(ssh, &இலக்கம்_prompts)) != 0)
		செல் out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, இலக்கம்_prompts)) != 0)
		செல் out;

	debug2_f("num_prompts %d", இலக்கம்_prompts);
	க்கு (i = 0; i < இலக்கம்_prompts; i++) {
		எனில் ((r = sshpkt_get_cstring(ssh, &prompt, வெற்று)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			செல் out;
		எனில் (asmprintf(&display_prompt, INT_MAX, வெற்று, "(%s@%s) %s",
		    authctxt->server_user, options.host_சாவி_alias ?
		    options.host_சாவி_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		எனில் ((r = sshpkt_put_cstring(ssh, response)) != 0)
			செல் out;
		freezero(response, strlen(response));
		விடுவி(prompt);
		விடுவி(display_prompt);
		display_prompt = response = prompt = வெற்று;
	}
	/* done with parsing incoming message. */
	எனில் ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		செல் out;
	r = sshpkt_send(ssh);
 out:
	எனில் (response)
		freezero(response, strlen(response));
	விடுவி(prompt);
	விடுவி(display_prompt);
	விடுவி(name);
	விடுவி(inst);
	விடுவி(lang);
	திரும்பு r;
}

நிலையான முழு
ssh_keysign(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *சாவி, u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen)
{
	கட்டமைப்பு sshbuf *b;
	கட்டமைப்பு stat st;
	pid_t pid;
	முழு r, to[2], from[2], status;
	முழு sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	வெறுமை (*osigchld)(முழு);

	*sigp = வெற்று;
	*lenp = 0;

	எனில் (stat(PATH_SSH_சாவி_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		திரும்பு -1;
	}
	எனில் (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		திரும்பு -1;
	}
	எனில் ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		திரும்பு -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	எனில் (pid == 0) {
		close(from[0]);
		எனில் (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		எனில் (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		எனில் (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		எனில் (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_சாவி_SIGN);
		execl(PATH_SSH_சாவி_SIGN, PATH_SSH_சாவி_SIGN, (எழுத்து *)வெற்று);
		fatal_f("exec(%s): %s", PATH_SSH_சாவி_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	எனில் ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	எனில் (ssh_செய்தி_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_செய்தி_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	எனில் (r < 0) {
		error_f("no reply");
		செல் fail;
	}

	errno = 0;
	போது (waitpid(pid, &status, 0) == -1) {
		எனில் (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			செல் fail;
		}
	}
	எனில் (!WIFEXITED(status)) {
		error_f("exited abnormally");
		செல் fail;
	}
	எனில் (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		செல் fail;
	}
	எனில் ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		செல் fail;
	}
	எனில் (rversion != version) {
		error_f("bad version");
		செல் fail;
	}
	எனில் ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		திரும்பு -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	திரும்பு 0;
}

நிலையான முழு
userauth_hostbased(கட்டமைப்பு ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	கட்டமைப்பு sshkey *தனிப்பட்ட = வெற்று;
	கட்டமைப்பு sshbuf *b = வெற்று;
	u_char *sig = வெற்று, *keyblob = வெற்று;
	எழுத்து *fp = வெற்று, *chost = வெற்று, *lname = வெற்று;
	size_t siglen = 0, keylen = 0;
	முழு i, r, success = 0;

	எனில் (authctxt->ktypes == வெற்று) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	க்கு (;;) {
		எனில் (authctxt->active_ktype == வெற்று)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		எனில் (authctxt->active_ktype == வெற்று ||
		    *authctxt->active_ktype == '\0')
			நிறுத்து;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		தனிப்பட்ட = வெற்று;
		க்கு (i = 0; i < authctxt->sensitive->nkeys; i++) {
			எனில் (authctxt->sensitive->சாவிகள்[i] == வெற்று ||
			    authctxt->sensitive->சாவிகள்[i]->type == சாவி_UNSPEC)
				தொடர்;
			எனில் (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->சாவிகள்[i]),
			    authctxt->active_ktype))
				தொடர்;
			/* we take and free the key */
			தனிப்பட்ட = authctxt->sensitive->சாவிகள்[i];
			authctxt->sensitive->சாவிகள்[i] = வெற்று;
			நிறுத்து;
		}
		/* Found one */
		எனில் (தனிப்பட்ட != வெற்று)
			நிறுத்து;
		/* No more keys of this type; advance */
		authctxt->active_ktype = வெற்று;
	}
	எனில் (தனிப்பட்ட == வெற்று) {
		விடுவி(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = வெற்று;
		authctxt->active_ktype = வெற்று;
		debug("No more client hostkeys for hostbased authentication.");
		செல் out;
	}

	எனில் ((fp = sshkey_fingerprint(தனிப்பட்ட, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == வெற்று) {
		error_f("sshkey_fingerprint failed");
		செல் out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(தனிப்பட்ட), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	எனில் (lname == வெற்று) {
		error_f("cannot get local ipaddr/name");
		செல் out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	எனில் ((b = sshbuf_new()) == வெற்று) {
		error_f("sshbuf_new failed");
		செல் out;
	}
	எனில் ((r = sshkey_to_blob(தனிப்பட்ட, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		செல் out;
	}
	எனில் ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		செல் out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	எனில் ((r = ssh_keysign(ssh, தனிப்பட்ட, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(தனிப்பட்ட), fp);
		செல் out;
	}
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_USERAUTH_REQUEST)) != 0 ||
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
		செல் out;
	}
	success = 1;

 out:
	எனில் (sig != வெற்று)
		freezero(sig, siglen);
	விடுவி(keyblob);
	விடுவி(lname);
	விடுவி(fp);
	விடுவி(chost);
	sshkey_free(தனிப்பட்ட);
	sshbuf_free(b);

	திரும்பு success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
நிலையான முழு
authmethod_is_enabled(Authmethod *method)
{
	எனில் (method == வெற்று)
		திரும்பு 0;
	/* return false if options indicate this method is disabled */
	எனில்  (method->enabled == வெற்று || *method->enabled == 0)
		திரும்பு 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	எனில்  (method->batch_flag != வெற்று && *method->batch_flag != 0)
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான Authmethod *
authmethod_lookup(மாறிலி எழுத்து *name)
{
	Authmethod *method = வெற்று;
	எனில் (name != வெற்று)
		க்கு (method = authmethods; method->name != வெற்று; method++)
			எனில் (strcmp(name, method->name) == 0)
				திரும்பு method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	திரும்பு வெற்று;
}

/* XXX internal state */
நிலையான Authmethod *current = வெற்று;
நிலையான எழுத்து *supported = வெற்று;
நிலையான எழுத்து *preferred = வெற்று;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
நிலையான Authmethod *
authmethod_get(எழுத்து *authlist)
{
	எழுத்து *name = வெற்று;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	எனில் (authlist == வெற்று || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	எனில் (supported == வெற்று || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		விடுவி(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = வெற்று;
	} இல்லையெனில் எனில் (current != வெற்று && authmethod_is_enabled(current))
		திரும்பு current;

	க்கு (;;) {
		எனில் ((name = match_list(preferred, supported, &next)) == வெற்று) {
			debug("No more authentication methods to try.");
			current = வெற்று;
			திரும்பு வெற்று;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		எனில் ((current = authmethod_lookup(name)) != வெற்று &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			விடுவி(name);
			திரும்பு current;
		}
		விடுவி(name);
	}
}

நிலையான எழுத்து *
authmethods_get(வெறுமை)
{
	Authmethod *method = வெற்று;
	கட்டமைப்பு sshbuf *b;
	எழுத்து *list;
	முழு r;

	எனில் ((b = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	க்கு (method = authmethods; method->name != வெற்று; method++) {
		எனில் (authmethod_is_enabled(method)) {
			எனில் ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	எனில் ((list = sshbuf_dup_string(b)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	திரும்பு list;
}
