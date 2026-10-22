/* $OpenBSD: servconf.c,v 1.459 2026/10/09 10:48:43 dtucker Exp $ */
/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ifdef __OpenBSD__
#ଅନ୍ତର୍ଭାଵ <sys/sysctl.h>
#endif

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#ଅନ୍ତର୍ଭାଵ <net/route.h>
#endif

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <util.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "groupaccess.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#ଯଦି !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

ସ୍ଥିର ଶୂନ୍ୟ add_listen_addr(ServerOptions *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ଶୂନ୍ୟ add_one_listen_addr(ServerOptions *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ଶୂନ୍ୟ parse_server_config_depth(ServerOptions *options,
    ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା sshbuf *conf, ସଂରଚନା include_list *includes,
    ସଂରଚନା connection_info *connectinfo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth);

ବାହ୍ୟ ସଂରଚନା sshbuf *cfg;

/* Initializes the server options to their default values. */

ଶୂନ୍ୟ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, ଆକାର(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = ଖାଲି;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ଖାଲି;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ଖାଲି;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_ଚାବି_files = 0; \
	options->ଅଙ୍କ_host_ଚାବି_files = 0; \
	options->host_ଚାବି_file_userprovided = ଖାଲି;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = ଖାଲି; \
	options->ଅଙ୍କ_queued_listens = 0; \
	options->listen_addrs = ଖାଲି; \
	options->ଅଙ୍କ_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->ଅଙ୍କ_ports = 0; \
	options->ports_from_cmdline = 0;
#define init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#define init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
#define init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#define init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_rate = -1; \
	options->max_startups = -1;
#define init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = ଖାଲି;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = ଖାଲି; \
	options->per_source_penalty.enabled = -1; \
	options->per_source_penalty.max_sources4 = -1; \
	options->per_source_penalty.max_sources6 = -1; \
	options->per_source_penalty.overflow_mode = -1; \
	options->per_source_penalty.overflow_mode6 = -1; \
	options->per_source_penalty.penalty_crash = -1.0; \
	options->per_source_penalty.penalty_authfail = -1.0; \
	options->per_source_penalty.penalty_invaliduser = -1.0; \
	options->per_source_penalty.penalty_noauth = -1.0; \
	options->per_source_penalty.penalty_grace = -1.0; \
	options->per_source_penalty.penalty_refuseconnection = -1.0; \
	options->per_source_penalty.penalty_max = -1.0; \
	options->per_source_penalty.penalty_min = -1.0;
#define init_rekeylimit(options) \
	options->rekey_limit = -1; \
	options->rekey_interval = -1;
#define init_subsystem(options) \
	options->ଅଙ୍କ_subsystems = 0; \
	options->subsystem_name = ଖାଲି; \
	options->subsystem_command = ଖାଲି; \
	options->subsystem_args = ଖାଲି;
#define init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#define init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#undef init_hostkeyfile
#undef init_ipqos
#undef init_listenaddress
#undef init_logfacility
#undef init_loglevel
#undef init_port
#undef init_gatewayports
#undef init_streamlocalbindmask
#undef init_streamlocalbindunlink
#undef init_maxstartups
#undef init_permituserenv
#undef init_persourcenetblocksize
#undef init_persourcepenalties
#undef init_rekeylimit
#undef init_subsystem
#undef init_timingsecret
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
option_clear_or_none(ଅଚଳ ଅକ୍ଷର *o)
{
	ଫେରନ୍ତୁ o == ଖାଲି || strcasecmp(o, "none") == 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
assemble_algorithms(ServerOptions *o)
{
	ଅକ୍ଷର *all_cipher, *all_mac, *all_kex, *all_ଚାବି, *all_sig;
	ଅକ୍ଷର *def_cipher, *def_mac, *def_kex, *def_ଚାବି, *def_sig;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ଚାବି = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_ଚାବି = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ଚାବି);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	କର { \
		ଯଦି ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} ଯେତେବେଳେ (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_ଚାବି, all_ଚାବି);
	ASSEMBLE(hostbased_accepted_algos, def_ଚାବି, all_ଚାବି);
	ASSEMBLE(pubkey_accepted_algos, def_ଚାବି, all_ଚାବି);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	ମୁକ୍ତ(all_cipher);
	ମୁକ୍ତ(all_mac);
	ମୁକ୍ତ(all_kex);
	ମୁକ୍ତ(all_ଚାବି);
	ମୁକ୍ତ(all_sig);
	ମୁକ୍ତ(def_cipher);
	ମୁକ୍ତ(def_mac);
	ମୁକ୍ତ(def_kex);
	ମୁକ୍ତ(def_ଚାବି);
	ମୁକ୍ତ(def_sig);
}

ଶୂନ୍ୟ
servconf_add_hostkey(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି,
    ServerOptions *options, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା userprovided)
{
	ଅକ୍ଷର *apath = derelativise_path(path);

	opt_array_append2(file, ଧାଡ଼ି, "HostKey",
	    &options->host_ଚାବି_files, &options->host_ଚାବି_file_userprovided,
	    &options->ଅଙ୍କ_host_ଚାବି_files, apath, userprovided);
	ମୁକ୍ତ(apath);
}

ଶୂନ୍ୟ
servconf_add_hostcert(ଅଚଳ ଅକ୍ଷର *file, ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି,
    ServerOptions *options, ଅଚଳ ଅକ୍ଷର *path)
{
	ଅକ୍ଷର *apath = derelativise_path(path);

	opt_array_append(file, ଧାଡ଼ି, "HostCertificate",
	    &options->host_cert_files, &options->ଅଙ୍କ_host_cert_files, apath);
	ମୁକ୍ତ(apath);
}

ଶୂନ୍ୟ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	ଯଦି (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	ଯଦି (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ଯଦି (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ଯଦି (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	କର { \
		ମୁକ୍ତ(options->var); \
		options->var = ଖାଲି; \
	} ଯେତେବେଳେ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

#ifdef USE_PAM
	ଯଦି (options->pam_service_name == ଖାଲି)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	ଯଦି (options->ଅଙ୍କ_host_ଚାବି_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_ଚାବି_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_ଚାବି_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_ଚାବି_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_ଚାବି_FILE, 0);
	}
	/* No certificates by default */
	ଯଦି (options->ଅଙ୍କ_ports == 0)
		options->ports[options->ଅଙ୍କ_ports++] = SSH_DEFAULT_PORT;
	ଯଦି (options->listen_addrs == ଖାଲି)
		add_listen_addr(options, ଖାଲି, ଖାଲି, 0);
	ଯଦି (options->pid_file == ଖାଲି)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	ଯଦି (options->moduli_file == ଖାଲି)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	ଯଦି (options->xauth_location == ଖାଲି)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	ଯଦି (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	ଯଦି (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	ଯଦି (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ଖାଲି;
	}
	ଯଦି (options->rekey_limit == -1)
		options->rekey_limit = 0;
	ଯଦି (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ଯଦି (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ଯଦି (options->max_startups == -1)
		options->max_startups = 100;
	ଯଦି (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	ଯଦି (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	ଯଦି (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	ଯଦି (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	ଯଦି (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	ଯଦି (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	ଯଦି (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	ଯଦି (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	ଯଦି (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	ଯଦି (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	ଯଦି (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	ଯଦି (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	ଯଦି (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	ଯଦି (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	ଯଦି (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	ଯଦି (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	ଯଦି (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	ଯଦି (options->ଅଙ୍କ_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ଚାବିଗୁଡ଼ିକ_files,
		    &options->ଅଙ୍କ_authkeys_files,
		    PATH_SSH_USER_PERMITTED_ଚାବିଗୁଡ଼ିକ);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ଚାବିଗୁଡ଼ିକ_files,
		    &options->ଅଙ୍କ_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	ଯଦି (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ଯଦି (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ଯଦି (options->version_addendum == ଖାଲି)
		options->version_addendum = xstrdup("");
	ଯଦି (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	ଯଦି (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ଯଦି (options->sk_provider == ଖାଲି)
		options->sk_provider = xstrdup("internal");
	ଯଦି (options->sshd_session_path == ଖାଲି)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	ଯଦି (options->sshd_auth_path == ଖାଲି)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	ଯଦି (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	ଯଦି (options->agent_socket_path == ଖାଲି)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	କର { \
		ଯଦି (option_clear_or_none(v)) { \
			ମୁକ୍ତ(v); \
			v = ଖାଲି; \
		} \
	} ଯେତେବେଳେ(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	କର { \
		ଯଦି (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ମୁକ୍ତ(options->v[0]); \
			ମୁକ୍ତ(options->v); \
			options->v = ଖାଲି; \
			options->nv = 0; \
		} \
	} ଯେତେବେଳେ (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_ଚାବିଗୁଡ଼ିକ);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_ଚାବି_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_host_ଚାବି_files; i++)
		CLEAR_ON_NONE(options->host_ଚାବି_files[i]);
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, ଅଙ୍କ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, ଅଙ୍କ_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_ଚାବିଗୁଡ଼ିକ_files, ଅଙ୍କ_revoked_ଚାବିଗୁଡ଼ିକ_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_ଚାବିଗୁଡ଼ିକ_files, ଅଙ୍କ_authkeys_files, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#define SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

/* Keyword tokens. */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଗଣନା {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	sMatch, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

#define SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#define SSHCFG_MATCH		0x02	/* allowed inside a Match section */
#define SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_MATCH)
#define SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#define SSHCFG_MATCH_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#define SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATED				sDeprecated
#define SSHCONF_IGNORE					sIgnore
#define SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#define SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
ସ୍ଥିର ସଂରଚନା {
	ଅଚଳ ଅକ୍ଷର *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ଖାଲି, sBadOption, 0 }
};
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATED
#undef SSHCONF_IGNORE
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

ସ୍ଥିର ସଂରଚନା {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;
	ଅକ୍ଷର *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ଖାଲି }
};

/* Returns an opcode name from its number */

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	ପାଇଁ (i = 0; keywords[i].name != ଖାଲି; i++)
		ଯଦି (keywords[i].opcode == code)
			ଫେରନ୍ତୁ(keywords[i].name);
	ଫେରନ୍ତୁ "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ସ୍ଥିର ServerOpCodes
parse_token(ଅଚଳ ଅକ୍ଷର *cp, ଅଚଳ ଅକ୍ଷର *filename,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, u_int *flags)
{
	u_int i;

	ପାଇଁ (i = 0; keywords[i].name; i++)
		ଯଦି (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			ଫେରନ୍ତୁ keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ଫେରନ୍ତୁ sBadOption;
}

ଅକ୍ଷର *
derelativise_path(ଅଚଳ ଅକ୍ଷର *path)
{
	ଅକ୍ଷର *expanded, *ret, cwd[PATH_MAX];

	ଯଦି (strcasecmp(path, "none") == 0)
		ଫେରନ୍ତୁ xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	ଯଦି (path_absolute(expanded))
		ଫେରନ୍ତୁ expanded;
	ଯଦି (getcwd(cwd, ଆକାର(cwd)) == ଖାଲି)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	ମୁକ୍ତ(expanded);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
add_listen_addr(ServerOptions *options, ଅଚଳ ଅକ୍ଷର *addr,
    ଅଚଳ ଅକ୍ଷର *rdomain, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	u_int i;

	ଯଦି (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; i < options->ଅଙ୍କ_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
add_one_listen_addr(ServerOptions *options, ଅଚଳ ଅକ୍ଷର *addr,
    ଅଚଳ ଅକ୍ଷର *rdomain, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	ସଂରଚନା addrinfo hints, *ai, *aitop;
	ଅକ୍ଷର strport[NI_MAXSERV];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_listen_addrs; i++) {
		ଯଦି (rdomain == ଖାଲି && options->listen_addrs[i].rdomain == ଖାଲି)
			ଭାଙ୍ଗ;
		ଯଦି (rdomain == ଖାଲି || options->listen_addrs[i].rdomain == ଖାଲି)
			ଜାରି;
		ଯଦି (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			ଭାଙ୍ଗ;
	}
	ଯଦି (i >= options->ଅଙ୍କ_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		ଯଦି (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->ଅଙ୍କ_listen_addrs, options->ଅଙ୍କ_listen_addrs + 1,
		    ଆକାର(*options->listen_addrs));
		i = options->ଅଙ୍କ_listen_addrs++;
		ଯଦି (rdomain != ଖାଲି)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ଖାଲି) ? AI_PASSIVE : 0;
	snprintf(strport, ଆକାର strport, "%d", port);
	ଯଦି ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	ପାଇଁ (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
valid_rdomain(ଅଚଳ ଅକ୍ଷର *name)
{
#ଯଦି defined(HAVE_SYS_VALID_RDOMAIN)
	ଫେରନ୍ତୁ sys_valid_rdomain(name);
#ନଚେତଯଦି defined(__OpenBSD__)
	ଅଚଳ ଅକ୍ଷର *errstr;
	long long ଅଙ୍କ;
	ସଂରଚନା rt_tableinfo info;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା mib[6];
	size_t miblen = ଆକାର(mib);

	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ 1;

	ଅଙ୍କ = strtonum(name, 0, 255, &errstr);
	ଯଦି (errstr != ଖାଲି)
		ଫେରନ୍ତୁ 0;

	/* Check whether the table actually exists */
	memset(mib, 0, ଆକାର(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଅଙ୍କ;
	ଯଦି (sysctl(mib, 6, &info, &miblen, ଖାଲି, 0) == -1)
		ଫେରନ୍ତୁ 0;

	ଫେରନ୍ତୁ 1;
#ଅନ୍ୟଥା /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	ଫେରନ୍ତୁ 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ସ୍ଥିର ଶୂନ୍ୟ
queue_listen_addr(ServerOptions *options, ଅଚଳ ଅକ୍ଷର *addr,
    ଅଚଳ ଅକ୍ଷର *rdomain, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	ସଂରଚନା queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->ଅଙ୍କ_queued_listens, options->ଅଙ୍କ_queued_listens + 1,
	    ଆକାର(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->ଅଙ୍କ_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == ଖାଲି ? ଖାଲି : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ସ୍ଥିର ଶୂନ୍ୟ
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ସଂରଚନା queued_listenaddr *qla;

	ଯଦି (options->ଅଙ୍କ_ports == 0)
		options->ports[options->ଅଙ୍କ_ports++] = SSH_DEFAULT_PORT;
	ଯଦି (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		ମୁକ୍ତ(qla->addr);
		ମୁକ୍ତ(qla->rdomain);
	}
	ମୁକ୍ତ(options->queued_listen_addrs);
	options->queued_listen_addrs = ଖାଲି;
	options->ଅଙ୍କ_queued_listens = 0;
}

/*
 * The strategy for the Match blocks is that the config file is parsed twice.
 *
 * The first time is at startup.  activep is initialized to 1 and the
 * directives in the global context are processed and acted on.  Hitting a
 * Match directive unsets activep and the directives inside the block are
 * checked for syntax only.
 *
 * The second time is after a connection has been established but before
 * authentication.  activep is initialized to 2 and global config directives
 * are ignored since they have already been processed.  If the criteria in a
 * Match block is met, activep is set and the subsequent directives
 * processed and actioned until EOF or another Match block unsets it.  Any
 * options set are copied into the main server config.
 *
 * Potential additions/improvements:
 *  - Add Match support for pre-kex directives, eg. Ciphers.
 *
 *  - Add a Tag directive (idea from David Leonard) ala pf, eg:
 *	Match Address 192.168.0.*
 *		Tag trusted
 *	Match Group wheel
 *		Tag trusted
 *	Match Tag trusted
 *		AllowTcpForwarding yes
 *		GatewayPorts clientspecified
 *		[...]
 *
 *  - Add a PermittedChannelRequests directive
 *	Match Group shell
 *		PermittedChannelRequests session,forwarded-tcpip
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_cfg_ଧାଡ଼ି_group(ଅଚଳ ଅକ୍ଷର *grps, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *user)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result = 0;
	ସଂରଚନା passwd *pw;

	ଯଦି (user == ଖାଲି)
		ଯାଅ out;

	ଯଦି ((pw = getpwnam(user)) == ଖାଲି) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", ଧାଡ଼ି, user);
	} ଅନ୍ୟଥା ଯଦି (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, ଧାଡ଼ି);
	} ଅନ୍ୟଥା ଯଦି (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, ଧାଡ଼ି);
	} ଅନ୍ୟଥା {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, ଧାଡ଼ି);
		result = 1;
	}
out:
	ga_free();
	ଫେରନ୍ତୁ result;
}

ସ୍ଥିର ଶୂନ୍ୟ
match_test_missing_fatal(ଅଚଳ ଅକ୍ଷର *criteria, ଅଚଳ ଅକ୍ଷର *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_cfg_ଧାଡ଼ି(ଅଚଳ ଅକ୍ଷର *full_ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *acp, ଅକ୍ଷର ***avp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଧାଡ଼ି, ସଂରଚନା connection_info *ci)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result = 1, attributes = 0, port;
	ଅକ୍ଷର *arg, *attrib = ଖାଲି, *oattrib;

	ଯଦି (ci == ଖାଲି) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_ଧାଡ଼ି, ଧାଡ଼ି);
	} ଅନ୍ୟଥା {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_ଧାଡ଼ି,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", ଧାଡ଼ି);
	}

	ଯେତେବେଳେ ((oattrib = argv_next(acp, avp)) != ଖାଲି) {
		/* Terminate on comment */
		ଯଦି (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			ଭାଙ୍ଗ;
		}
		attrib = xstrdup(oattrib);
		arg = ଖାଲି;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		ଯଦି (strcasecmp(attrib, "all") == 0) {
			ଯଦି (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ଖାଲି &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				ଯାଅ out;
			}
			ଯଦି (arg != ଖାଲି && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			ଯାଅ out;
		}
		/* Criterion "invalid-user" also has no argument */
		ଯଦି (strcasecmp(attrib, "invalid-user") == 0) {
			ଯଦି (ci == ଖାଲି) {
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->user_invalid == 0)
				result = 0;
			ଅନ୍ୟଥା
				debug("matched invalid-user at line %d", ଧାଡ଼ି);
			ଯାଅ next;
		}

		/* Keep this list in sync with below */
		ଯଦି (strprefix(attrib, "user=", 1) != ଖାଲି ||
		    strprefix(attrib, "group=", 1) != ଖାଲି ||
		    strprefix(attrib, "host=", 1) != ଖାଲି ||
		    strprefix(attrib, "address=", 1) != ଖାଲି ||
		    strprefix(attrib, "localaddress=", 1) != ଖାଲି ||
		    strprefix(attrib, "localport=", 1) != ଖାଲି ||
		    strprefix(attrib, "rdomain=", 1) != ଖାଲି ||
		    strprefix(attrib, "version=", 1) != ଖାଲି) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ଅନ୍ୟଥା {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		ଯଦି (arg == ଖାଲି || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			ଯାଅ out;
		}
		ଯଦି (strcasecmp(attrib, "user") == 0) {
			ଯଦି (ci == ଖାଲି || (ci->test && ci->user == ଖାଲି)) {
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->user == ଖାଲି)
				match_test_missing_fatal("User", "user");
			ଯଦି (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			ଅନ୍ୟଥା
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, ଧାଡ଼ି);
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "group") == 0) {
			ଯଦି (ci == ଖାଲି || (ci->test && ci->user == ଖାଲି)) {
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->user == ଖାଲି)
				match_test_missing_fatal("Group", "user");
			ବାଛ (match_cfg_ଧାଡ଼ି_group(arg, ଧାଡ଼ି, ci->user)) {
			ସ୍ଥିତି -1:
				result = -1;
				ଯାଅ out;
			ସ୍ଥିତି 0:
				result = 0;
			}
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "host") == 0) {
			ଯଦି (ci == ଖାଲି || (ci->test && ci->host == ଖାଲି)) {
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->host == ଖାଲି)
				match_test_missing_fatal("Host", "host");
			ଯଦି (match_hostname(ci->host, arg) != 1)
				result = 0;
			ଅନ୍ୟଥା
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, ଧାଡ଼ି);
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "address") == 0) {
			ଯଦି (ci == ଖାଲି || (ci->test && ci->address == ଖାଲି)) {
				ଯଦି (addr_match_list(ଖାଲି, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, ଧାଡ଼ି);
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->address == ଖାଲି)
				match_test_missing_fatal("Address", "addr");
			ବାଛ (addr_match_list(ci->address, arg)) {
			ସ୍ଥିତି 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, ଧାଡ଼ି);
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 0:
			ସ୍ଥିତି -1:
				result = 0;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି -2:
				result = -1;
				ଯାଅ out;
			}
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "localaddress") == 0){
			ଯଦି (ci == ଖାଲି || (ci->test && ci->laddress == ଖାଲି)) {
				ଯଦି (addr_match_list(ଖାଲି, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    ଧାଡ଼ି);
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->laddress == ଖାଲି)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			ବାଛ (addr_match_list(ci->laddress, arg)) {
			ସ୍ଥିତି 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, ଧାଡ଼ି);
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 0:
			ସ୍ଥିତି -1:
				result = 0;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି -2:
				result = -1;
				ଯାଅ out;
			}
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "localport") == 0) {
			ଯଦି ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				ଯାଅ out;
			}
			ଯଦି (ci == ଖାଲି || (ci->test && ci->lport == -1)) {
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			ଯଦି (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, ଧାଡ଼ି);
			ଅନ୍ୟଥା
				result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "rdomain") == 0) {
			ଯଦି (ci == ଖାଲି || (ci->test && ci->rdomain == ଖାଲି)) {
				result = 0;
				ଯାଅ next;
			}
			ଯଦି (ci->rdomain == ଖାଲି)
				match_test_missing_fatal("RDomain", "rdomain");
			ଯଦି (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			ଅନ୍ୟଥା
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, ଧାଡ଼ି);
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "version") == 0) {
			ଯଦି (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			ଅନ୍ୟଥା
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, ଧାଡ଼ି);
		} ଅନ୍ୟଥା {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			ଯାଅ out;
		}
 next:
		ମୁକ୍ତ(attrib);
		attrib = ଖାଲି;
	}
	ଯଦି (attributes == 0) {
		error("One or more attributes required for Match");
		ଫେରନ୍ତୁ -1;
	}
 out:
	ଯଦି (ci != ଖାଲି && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", ଧାଡ଼ି);
	ମୁକ୍ତ(attrib);
	ଫେରନ୍ତୁ result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
ସଂରଚନା multistate {
	ଅକ୍ଷର *ଚାବି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୂଲ୍ୟ;
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ଖାଲି, -1 }
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_server_config_ଧାଡ଼ି_depth(ServerOptions *options, ଅକ୍ଷର *ଧାଡ଼ି,
    ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep,
    ସଂରଚନା connection_info *connectinfo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *inc_flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth,
    ସଂରଚନା include_list *includes)
{
	ଅକ୍ଷର *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cmdline = 0, *intptr, ମୂଲ୍ୟ, value2, value3, n, port, oactive, r;
	ଦ୍ୱିଗୁଣ dvalue, *doubleptr = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	ଅଚଳ ସଂରଚନା multistate *multistate_ptr;
	ଅଚଳ ଅକ୍ଷର *errstr;
	ସଂରଚନା include_item *item;
	glob_t gbuf;
	ଅକ୍ଷର **oav = ଖାଲି, **av;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oac = 0, ac;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	ଅକ୍ଷର **strs = ଖାଲି; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ଯଦି ((len = strlen(ଧାଡ଼ି)) == 0)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (len--; len > 0; len--) {
		ଯଦି (strchr(WHITESPACE "\f", ଧାଡ଼ି[len]) == ଖାଲି)
			ଭାଙ୍ଗ;
		ଧାଡ଼ି[len] = '\0';
	}

	str = ଧାଡ଼ି;
	ଯଦି ((keyword = strdelim(&str)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	/* Ignore leading whitespace */
	ଯଦି (*keyword == '\0')
		keyword = strdelim(&str);
	ଯଦି (!keyword || !*keyword || *keyword == '#')
		ଫେରନ୍ତୁ 0;
	ଯଦି (str == ଖାଲି || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ଫେରନ୍ତୁ -1;
	}
	intptr = ଖାଲି;
	charptr = ଖାଲି;
	opcode = parse_token(keyword, filename, linenum, &flags);

	ଯଦି (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ଫେରନ୍ତୁ -1;
	}
	ac = oac;
	av = oav;

	ଯଦି (activep == ଖାଲି) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	ଯଦି (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	ଯଦି (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		ଯଦି (connectinfo == ଖାଲି) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} ଅନ୍ୟଥା { /* this is a directive we have already processed */
			ret = 0;
			ଯାଅ out;
		}
	}

	ବାଛ (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	ସ୍ଥିତି sUsePAM:
		intptr = &options->use_pam;
		ଯାଅ parse_flag;
	ସ୍ଥିତି sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;
#endif

	/* Standard Options */
	ସ୍ଥିତି sBadOption:
		ଯାଅ out;
	ସ୍ଥିତି sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		ଯଦି (options->ports_from_cmdline) {
			argv_consume(&ac);
			ଭାଙ୍ଗ;
		}
		ଯଦି (options->ଅଙ୍କ_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->ଅଙ୍କ_ports++] = a2port(arg);
		ଯଦି (options->ports[options->ଅଙ୍କ_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		ଯଦି ((ମୂଲ୍ୟ = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sListenAddress:
		arg = argv_next(&ac, &av);
		ଯଦି (arg == ଖାଲି || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		ଯଦି (strchr(arg, '[') == ଖାଲି && (p = strchr(arg, ':')) != ଖାଲି
		    && strchr(p+1, ':') != ଖାଲି) {
			port = 0;
			p = arg;
		} ଅନ୍ୟଥା {
			arg2 = ଖାଲି;
			p = hpdelim(&arg);
			ଯଦି (p == ଖାଲି)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			ଯଦି (arg == ଖାଲି)
				port = 0;
			ଅନ୍ୟଥା ଯଦି ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ଖାଲି;
		ଯଦି ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == ଖାଲି)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			ଯଦି (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		ଭାଙ୍ଗ;

	ସ୍ଥିତି sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ମୂଲ୍ୟ = -1;
		ପାଇଁ (i = 0; multistate_ptr[i].ଚାବି != ଖାଲି; i++) {
			ଯଦି (strcasecmp(arg, multistate_ptr[i].ଚାବି) == 0) {
				ମୂଲ୍ୟ = multistate_ptr[i].ମୂଲ୍ୟ;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (ମୂଲ୍ୟ == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି s_Host_ଚାବି:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ଯଦି (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି s_Host_ଚାବି_Agent:
		charptr = &options->host_ଚାବି_agent;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sHostCertificate:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ଯଦି (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ଯଦି (*activep && *charptr == ଖାଲି) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			ଯଦି (intptr != ଖାଲି)
				*intptr = *intptr + 1;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sModuliFile:
		charptr = &options->moduli_file;
		ଯାଅ parse_filename;

	ସ୍ଥିତି s_Permit_ମୂଳ_Login:
		intptr = &options->permit_ମୂଳ_login;
		multistate_ptr = multistate_permitrootlogin;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		ଯଦି (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି s_Host_ଚାବି_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		ଯାଅ parse_pubkey_algos;

	ସ୍ଥିତି sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ଯାଅ parse_pubkey_algos;

	ସ୍ଥିତି sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ଯାଅ parse_pubkey_algos;

	ସ୍ଥିତି sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		ମୂଲ୍ୟ = 0;
		value2 = -1;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (strcasecmp(arg, "none") == 0)
				ଜାରି;
			ଯଦି (strcasecmp(arg, "touch-required") == 0)
				ମୂଲ୍ୟ |= PUBKEYAUTH_TOUCH_REQUIRED;
			ଅନ୍ୟଥା ଯଦି (strcasecmp(arg, "verify-required") == 0)
				ମୂଲ୍ୟ |= PUBKEYAUTH_VERIFY_REQUIRED;
			ଅନ୍ୟଥା ଯଦି (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				ଯଦି (errstr != ଖାଲି) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					ଯାଅ out;
				}
			} ଅନ୍ୟଥା {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				ଯାଅ out;
			}
		}
		ଯଦି (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = ମୂଲ୍ୟ;
			options->max_pubkey_ok = value2;
		}
		ଭାଙ୍ଗ;

#ifdef KRB5
	ସ୍ଥିତି sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		ଯାଅ parse_flag;
#ifdef USE_AFS
	ସ୍ଥିତି sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		ଯାଅ parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	ସ୍ଥିତି sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		ଯାଅ parse_flag;
#endif /* GSSAPI */

	ସ୍ଥିତି sPasswordAuthentication:
		intptr = &options->password_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sPrintMotd:
		intptr = &options->print_motd;
		ଯାଅ parse_flag;

#ifndef DISABLE_LASTLOG
	ସ୍ଥିତି sPrintLastLog:
		intptr = &options->print_lastlog;
		ଯାଅ parse_flag;
#endif

	ସ୍ଥିତି sX11Forwarding:
		intptr = &options->x11_forwarding;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		ଯଦି ((errstr = atoi_err(arg, &ମୂଲ୍ୟ)) != ଖାଲି)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sXAuthLocation:
		charptr = &options->xauth_location;
		ଯାଅ parse_filename;

	ସ୍ଥିତି sPermitTTY:
		intptr = &options->permit_tty;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sPermitUserRC:
		intptr = &options->permit_user_rc;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sStrictModes:
		intptr = &options->strict_modes;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ମୂଲ୍ୟ = 0;
		p = ଖାଲି;
		ଯଦି (strcmp(arg, "yes") == 0)
			ମୂଲ୍ୟ = 1;
		ଅନ୍ୟଥା ଯଦି (strcmp(arg, "no") == 0)
			ମୂଲ୍ୟ = 0;
		ଅନ୍ୟଥା {
			/* Pattern-list specified */
			ମୂଲ୍ୟ = 1;
			p = xstrdup(arg);
		}
		ଯଦି (*activep && *intptr == -1) {
			*intptr = ମୂଲ୍ୟ;
			*charptr = p;
			p = ଖାଲି;
		}
		ମୁକ୍ତ(p);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sRekeyLimit:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ଅନ୍ୟଥା {
			ଯଦି (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			ଯଦି (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		ଯଦି (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		ଯଦି (ac != 0) { /* optional rekey interval present */
			ଯଦି (strcmp(av[0], "none") == 0) {
				(ଶୂନ୍ୟ)argv_next(&ac, &av);	/* discard */
				ଭାଙ୍ଗ;
			}
			intptr = &options->rekey_interval;
			ଯାଅ parse_time;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sUseDNS:
		intptr = &options->use_dns;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		ମୂଲ୍ୟ = log_facility_ସଂଖ୍ୟା(arg);
		ଯଦି (ମୂଲ୍ୟ == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ଯଦି (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		ମୂଲ୍ୟ = log_level_ସଂଖ୍ୟା(arg);
		ଯଦି (ମୂଲ୍ୟ == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ଯଦି (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sLogVerbose:
		found = options->ଅଙ୍କ_log_verbose == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->log_verbose = strs;
			options->ଅଙ୍କ_log_verbose = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		ଯଦି (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			ଯଦି (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} ଅନ୍ୟଥା ଯଦି (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			ଯଦି (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} ଅନ୍ୟଥା ଯଦି (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sDisableForwarding:
		intptr = &options->disable_forwarding;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->ଅଙ୍କ_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0' ||
			    match_user(ଖାଲି, ଖାଲି, ଖାଲି, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			ଯଦି (!*activep)
				ଜାରି;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ଯଦି (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->ଅଙ୍କ_deny_users;
		ଯାଅ parse_allowdenyusers;

	ସ୍ଥିତି sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->ଅଙ୍କ_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			ଯଦି (!*activep)
				ଜାରି;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ଯଦି (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->ଅଙ୍କ_deny_groups;
		ଯାଅ parse_allowdenygroups;

	ସ୍ଥିତି sCiphers:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ଯଦି (options->ciphers == ଖାଲି)
			options->ciphers = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sMacs:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ଯଦି (options->macs == ଖାଲି)
			options->macs = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sKexAlgorithms:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ଯଦି (options->kex_algorithms == ଖାଲି)
			options->kex_algorithms = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sSubsystem:
		ଯଦି ((arg = argv_next(&ac, &av)) == ଖାଲି || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == ଖାଲି || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (!*activep) {
			argv_consume(&ac);
			ଭାଙ୍ଗ;
		}
		found = 0;
		ପାଇଁ (i = 0; i < options->ଅଙ୍କ_subsystems; i++) {
			ଯଦି (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			ଭାଙ୍ଗ;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->ଅଙ୍କ_subsystems,
		    options->ଅଙ୍କ_subsystems + 1,
		    ଆକାର(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->ଅଙ୍କ_subsystems,
		    options->ଅଙ୍କ_subsystems + 1,
		    ଆକାର(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->ଅଙ୍କ_subsystems,
		    options->ଅଙ୍କ_subsystems + 1,
		    ଆକାର(*options->subsystem_args));
		options->subsystem_name[options->ଅଙ୍କ_subsystems] = xstrdup(arg);
		options->subsystem_command[options->ଅଙ୍କ_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->ଅଙ୍କ_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		ମୁକ୍ତ(arg2);
		ମୁକ୍ତ(arg);
		argv_consume(&ac);
		options->ଅଙ୍କ_subsystems++;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sMaxStartups:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		ଯଦି ((n = sscanf(arg, "%d:%d:%d",
		    &ମୂଲ୍ୟ, &value2, &value3)) == 3) {
			ଯଦି (ମୂଲ୍ୟ > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} ଅନ୍ୟଥା ଯଦି (n == 1) {
			value3 = ମୂଲ୍ୟ;
			value2 = -1;
		} ଅନ୍ୟଥା {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		ଯଦି (ମୂଲ୍ୟ <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ଯଦି (*activep && options->max_startups == -1) {
			options->max_startups_begin = ମୂଲ୍ୟ;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ବାଛ (n = sscanf(arg, "%d:%d", &ମୂଲ୍ୟ, &value2)) {
		ସ୍ଥିତି 2:
			ଯଦି (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		ସ୍ଥିତି 1:
			ଯଦି (ମୂଲ୍ୟ < 0 || ମୂଲ୍ୟ > 32)
				n = -1;
		}
		ଯଦି (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ଯଦି (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = ମୂଲ୍ୟ;
			ଯଦି (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (strcmp(arg, "none") == 0) { /* no limit */
			ମୂଲ୍ୟ = INT_MAX;
		} ଅନ୍ୟଥା {
			ଯଦି ((errstr = atoi_err(arg, &ମୂଲ୍ୟ)) != ଖାଲି)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		ଯଦି (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ଯଦି (addr_match_list(ଖାଲି, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPerSourcePenalties:
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଅଚଳ ଅକ୍ଷର *q = ଖାଲି;

			found = 1;
			intptr = ଖାଲି;
			doubleptr = ଖାଲି;
			ମୂଲ୍ୟ = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			ଯଦି (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				ଯଦି (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				ଯଦି (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				ଜାରି;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "crash:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "authfail:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "invaliduser:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "noauth:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "grace-exceeded:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "refuseconnection:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "max:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "min:", 0)) != ଖାଲି) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "max-sources4:", 0)) != ଖାଲି) {
				intptr = &options->per_source_penalty.max_sources4;
				ଯଦି ((errstr = atoi_err(q, &ମୂଲ୍ୟ)) != ଖାଲି)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ଅନ୍ୟଥା ଯଦି ((q = strprefix(arg, "max-sources6:", 0)) != ଖାଲି) {
				intptr = &options->per_source_penalty.max_sources6;
				ଯଦି ((errstr = atoi_err(q, &ମୂଲ୍ୟ)) != ଖାଲି)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ଅନ୍ୟଥା ଯଦି (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				ମୂଲ୍ୟ = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} ଅନ୍ୟଥା ଯଦି (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				ମୂଲ୍ୟ = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} ଅନ୍ୟଥା ଯଦି (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				ମୂଲ୍ୟ = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} ଅନ୍ୟଥା ଯଦି (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				ମୂଲ୍ୟ = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} ଅନ୍ୟଥା {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			ଯଦି (doubleptr != ଖାଲି) {
				ଯଦି ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				ଯଦି (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} ଅନ୍ୟଥା ଯଦି (intptr != ଖାଲି) {
				ଯଦି (*activep && *intptr == -1) {
					*intptr = ମୂଲ୍ୟ;
					options->per_source_penalty.enabled = 1;
				}
			} ଅନ୍ୟଥା {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		ଯଦି (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sMaxAuthTries:
		intptr = &options->max_authtries;
		ଯାଅ parse_int;

	ସ୍ଥିତି sMaxSessions:
		intptr = &options->max_sessions;
		ଯାଅ parse_int;

	ସ୍ଥିତି sBanner:
		charptr = &options->banner;
		ଯାଅ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	ସ୍ଥିତି s_Authorized_ଚାବିଗୁଡ଼ିକ_File:
		uintptr = &options->ଅଙ୍କ_authkeys_files;
		chararrayptr = &options->authorized_ଚାବିଗୁଡ଼ିକ_files;
 parse_filenames:
		found = *uintptr == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ମୁକ୍ତ(arg2);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (*activep && *charptr == ଖାଲି) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			ଯଦି (intptr != ଖାଲି)
				*intptr = *intptr + 1;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sClientAliveInterval:
		intptr = &options->client_alive_interval;
		ଯାଅ parse_time;

	ସ୍ଥିତି s_Client_Alive_ଗଣନା_Max:
		intptr = &options->client_alive_ଗଣନା_max;
		ଯାଅ parse_int;

	ସ୍ଥିତି sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0' || strchr(arg, '=') != ଖାଲି)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			ଯଦି (!*activep)
				ଜାରି;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->ଅଙ୍କ_accept_env,
			    arg);
		}
		ଯଦି (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sSetEnv:
		found = options->ଅଙ୍କ_setenv == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0' || strchr(arg, '=') == ଖାଲି)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			ଯଦି (lookup_setenv_in_list(arg, strs, nstrs) != ଖାଲି) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ଜାରି;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->setenv = strs;
			options->ଅଙ୍କ_setenv = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ମୂଲ୍ୟ = -1;
		ପାଇଁ (i = 0; tunmode_desc[i].val != -1; i++)
			ଯଦି (strcmp(tunmode_desc[i].text, arg) == 0) {
				ମୂଲ୍ୟ = tunmode_desc[i].val;
				ଭାଙ୍ଗ;
			}
		ଯଦି (ମୂଲ୍ୟ == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sInclude:
		ଯଦି (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		ମୂଲ୍ୟ = 0;
		ଯେତେବେଳେ ((arg2 = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			ମୂଲ୍ୟ++;
			found = 0;
			ଯଦି (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} ଅନ୍ୟଥା
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				ଯଦି (strcmp(item->selector, arg) != 0)
					ଜାରି;
				ଯଦି (item->filename != ଖାଲି) {
					parse_server_config_depth(options,
					    item->filename, item->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_MATCH_ONLY
					        ? SSHCFG_MATCH_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, depth + 1);
				}
				found = 1;
				*activep = oactive;
			}
			ଯଦି (found != 0) {
				ମୁକ୍ତ(arg);
				ଜାରି;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			ଯଦି ((r = glob(arg, 0, ଖାଲି, &gbuf)) != 0) {
				ଯଦି (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, ଆକାର(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			ଯଦି (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			ପାଇଁ (n = 0; n < (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, ଆକାର(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				ଯଦି ((item->contents = sshbuf_new()) == ଖାଲି)
					fatal_f("sshbuf_new failed");
				load_server_config(item->filename,
				    item->contents);
				parse_server_config_depth(options,
				    item->filename, item->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_MATCH_ONLY
				        ? SSHCFG_MATCH_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, depth + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, item, entry);
			}
			globfree(&gbuf);
			ମୁକ୍ତ(arg);
		}
		ଯଦି (ମୂଲ୍ୟ == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sMatch:
		ଯଦି (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		ମୂଲ୍ୟ = match_cfg_ଧାଡ଼ି(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ଖାଲି : connectinfo));
		ଯଦି (ମୂଲ୍ୟ < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : ମୂଲ୍ୟ;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sPermitListen:
	ସ୍ଥିତି sPermitOpen:
		ଯଦି (opcode == sPermitListen) {
			uintptr = &options->ଅଙ୍କ_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} ଅନ୍ୟଥା {
			uintptr = &options->ଅଙ୍କ_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				ଯଦି (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				ଜାରି;
			}

			ଯଦି (opcode == sPermitListen &&
			    strchr(arg, ':') == ଖାଲି) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} ଅନ୍ୟଥା {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				ଯଦି (p == ଖାଲି) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			ଯଦି (arg == ଖାଲି ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ମୁକ୍ତ(arg2);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sForceCommand:
		ଯଦି (str == ଖାଲି || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ଯଦି (*activep && options->adm_forced_command == ଖାଲି)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_ଚାବିଗୁଡ଼ିକ;
		ଯାଅ parse_filename;

	ସ୍ଥିତି s_Revoked_ଚାବିଗୁଡ଼ିକ:
		uintptr = &options->ଅଙ୍କ_revoked_ଚାବିଗୁଡ଼ିକ_files;
		chararrayptr = &options->revoked_ଚାବିଗୁଡ଼ିକ_files;
		ଯାଅ parse_filenames;

	ସ୍ଥିତି s_Security_ଚାବି_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (*activep && *charptr == ଖାଲି) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			ଯଦି (intptr != ଖାଲି)
				*intptr = *intptr + 1;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sIPQoS:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି ((ମୂଲ୍ୟ = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ଯଦି (ମୂଲ୍ୟ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ମୂଲ୍ୟ = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		ଯଦି (arg == ଖାଲି)
			value2 = ମୂଲ୍ୟ;
		ଅନ୍ୟଥା ଯଦି ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ଯଦି (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		ଯଦି (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ମୂଲ୍ୟ;
			options->ip_qos_bulk = value2;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sVersionAddendum:
		ଯଦି (str == ଖାଲି || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ଯଦି (strchr(str + len, '\r') != ଖାଲି) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ଯଦି ((arg = strchr(ଧାଡ଼ି, '#')) != ଖାଲି) {
			*arg = '\0';
			rtrim(ଧାଡ଼ି);
		}
		ଯଦି (*activep && options->version_addendum == ଖାଲି) {
			ଯଦି (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			ଅନ୍ୟଥା
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି s_Authorized_ଚାବିଗୁଡ଼ିକ_Command:
		charptr = &options->authorized_ଚାବିଗୁଡ଼ିକ_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		ଯଦି (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି s_Authorized_ଚାବିଗୁଡ଼ିକ_Command_User:
		charptr = &options->authorized_ଚାବିଗୁଡ଼ିକ_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		ଯାଅ parse_command;

	ସ୍ଥିତି sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		ଯାଅ parse_localuser;

	ସ୍ଥିତି sAuthenticationMethods:
		found = options->ଅଙ୍କ_auth_methods == 0;
		ମୂଲ୍ୟ = 0; /* seen "any" pseudo-method */
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (strcmp(arg, "any") == 0) {
				ଯଦି (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				ମୂଲ୍ୟ = 1;
			} ଅନ୍ୟଥା ଯଦି (ମୂଲ୍ୟ) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} ଅନ୍ୟଥା ଯଦି (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->auth_methods = strs;
			options->ଅଙ୍କ_auth_methods = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		ମୂଲ୍ୟ = strtol(arg, &p, 8);
		ଯଦି (arg == p || ମୂଲ୍ୟ < 0 || ମୂଲ୍ୟ > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		ଯଦି (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sFingerprintHash:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି ((ମୂଲ୍ୟ = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		ଯଦି (*activep)
			options->fingerprint_hash = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		ଯାଅ parse_flag;

	ସ୍ଥିତି sRDomain:
#ଯଦି !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ଯଦି (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sRequiredRSASize:
		intptr = &options->required_rsa_size;
		ଯାଅ parse_int;

	ସ୍ଥିତି sChannelTimeout:
		found = options->ଅଙ୍କ_channel_timeouts == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			} ଅନ୍ୟଥା ଯଦି (parse_pattern_interval(arg,
			    ଖାଲି, ଖାଲି) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->channel_timeouts = strs;
			options->ଅଙ୍କ_channel_timeouts = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		ଯଦି (av[0] != ଖାଲି && strcasecmp(av[0], "none") == 0) {
			(ଶୂନ୍ୟ)argv_next(&ac, &av); /* consume arg */
			ଯଦି (*activep)
				*intptr = 0;
			ଭାଙ୍ଗ;
		}
		ଯାଅ parse_time;

	ସ୍ଥିତି sSshdSessionPath:
		charptr = &options->sshd_session_path;
		ଯାଅ parse_filename;

	ସ୍ଥିତି sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		ଯାଅ parse_filename;

	ସ୍ଥିତି sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି sDeprecated:
	ସ୍ଥିତି sIgnore:
	ସ୍ଥିତି sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	ଯଦି (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ଯାଅ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, ଖାଲି, nstrs);
	argv_free(oav, oac);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_server_config_ଧାଡ଼ି(ServerOptions *options, ଅକ୍ଷର *ଧାଡ଼ି,
    ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep,
    ସଂରଚନା connection_info *connectinfo, ସଂରଚନା include_list *includes)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା inc_flags = 0;

	ଫେରନ୍ତୁ process_server_config_ଧାଡ଼ି_depth(options, ଧାଡ଼ି, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

ଶୂନ୍ୟ
load_server_config(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା sshbuf *conf)
{
	ସଂରଚନା stat st;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି, *cp;
	size_t linesize = 0;
	FILE *f;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2_f("filename %s", filename);
	ଯଦି ((f = fopen(filename, "r")) == ଖାଲି) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	ଯଦି (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = ଧାଡ଼ି + strspn(ଧାଡ଼ି, " \t\r");
		ଯଦି ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	ମୁକ୍ତ(ଧାଡ଼ି);
	ଯଦି ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

ଶୂନ୍ୟ
parse_server_match_config(ServerOptions *options,
   ସଂରଚନା include_list *includes, ସଂରଚନା connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_server_match_testspec(ସଂରଚନା connection_info *ci, ଅକ୍ଷର *spec)
{
	ଅକ୍ଷର *p;
	ଅଚଳ ଅକ୍ଷର *val;

	ଯେତେବେଳେ ((p = strsep(&spec, ",")) && *p != '\0') {
		ଯଦି ((val = strprefix(p, "addr=", 0)) != ଖାଲି) {
			ci->address = xstrdup(val);
		} ଅନ୍ୟଥା ଯଦି ((val = strprefix(p, "host=", 0)) != ଖାଲି) {
			ci->host = xstrdup(val);
		} ଅନ୍ୟଥା ଯଦି ((val = strprefix(p, "user=", 0)) != ଖାଲି) {
			ci->user = xstrdup(val);
		} ଅନ୍ୟଥା ଯଦି ((val = strprefix(p, "laddr=", 0)) != ଖାଲି) {
			ci->laddress = xstrdup(val);
		} ଅନ୍ୟଥା ଯଦି ((val = strprefix(p, "rdomain=", 0)) != ଖାଲି) {
			ci->rdomain = xstrdup(val);
		} ଅନ୍ୟଥା ଯଦି ((val = strprefix(p, "lport=", 0)) != ଖାଲି) {
			ci->lport = a2port(val);
			ଯଦି (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				ଫେରନ୍ତୁ -1;
			}
		} ଅନ୍ୟଥା ଯଦି (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} ଅନ୍ୟଥା {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			ଫେରନ୍ତୁ -1;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	ପାଇଁ (i = 0; i < src->ଅଙ୍କ_subsystems; i++) {
		found = 0;
		ପାଇଁ (j = 0; j < dst->ଅଙ୍କ_subsystems; j++) {
			ଯଦି (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			ମୁକ୍ତ(dst->subsystem_command[j]);
			ମୁକ୍ତ(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			ଜାରି;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->ଅଙ୍କ_subsystems,
		    dst->ଅଙ୍କ_subsystems + 1, ଆକାର(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->ଅଙ୍କ_subsystems,
		    dst->ଅଙ୍କ_subsystems + 1, ଆକାର(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->ଅଙ୍କ_subsystems,
		    dst->ଅଙ୍କ_subsystems + 1, ଆକାର(*dst->subsystem_args));
		j = dst->ଅଙ୍କ_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_s32(ସଂରଚନା sshbuf *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା v)
{
	uint32_t uv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	ଯଦି ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_s64(ସଂରଚନା sshbuf *buf, int64_t v)
{
	uint64_t uv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	ଯଦି ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_mode(ସଂରଚନା sshbuf *buf, mode_t v)
{
	u_int uv;

	ଯଦି (v == (mode_t)-1)
		ଫେରନ୍ତୁ serialise_s32(buf, -1);
	uv = (u_int)v;
	ଯଦି ((mode_t)uv != v || uv > 0777)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ serialise_s32(buf, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)uv);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_double(ସଂରଚନା sshbuf *buf, ଦ୍ୱିଗୁଣ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	ଫେରନ୍ତୁ sshbuf_put(buf, &v, ଆକାର(v));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_nullable_string(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *s)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u8(buf, s != ଖାଲି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (s == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ sshbuf_put_cstring(buf, s);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_nullable_string_array(ସଂରଚନା sshbuf *buf, ଅକ୍ଷର **a, u_int n)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((r = sshbuf_put_u32(buf, n)) != 0)
		ଫେରନ୍ତୁ r;
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = serialise_nullable_string(buf, a[i])) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_hostkeyfile(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((r = sshbuf_put_u32(buf, options->ଅଙ୍କ_host_ଚାବି_files)) != 0) {
		error_fr(r, "serialise length");
		ଫେରନ୍ତୁ r;
	}
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_host_ଚାବି_files; i++) {
		ଯଦି ((r = serialise_s32(buf,
		    options->host_ଚାବି_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_ଚାବି_files[i])) != 0) {
			error_fr(r, "serialise member");
			ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_ipqos(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_listenaddress(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	ଯଦି ((r = sshbuf_put_u32(buf, options->ଅଙ୍କ_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		ଫେରନ୍ତୁ r;
	}
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_queued_listens; i++) {
		ଅଚଳ ସଂରଚନା queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		ଯଦି ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_logfacility(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_loglevel(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)options->log_level)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_port(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((r = sshbuf_put_u32(buf, options->ଅଙ୍କ_ports)) != 0) {
		error_fr(r, "serialise length");
		ଫେରନ୍ତୁ r;
	}
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_ports; i++) {
		ଯଦି ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_gatewayports(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_streamlocalbindmask(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_streamlocalbindunlink(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_maxstartups(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_permituserenv(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_persourcenetblocksize(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_persourcepenalties(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ଅଚଳ ସଂରଚନା per_source_penalty *psp = &options->per_source_penalty;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->overflow_mode)) != 0 ||
	    (r = serialise_s32(buf, psp->overflow_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_rekeylimit(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_subsystem(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i;

	ଯଦି ((r = sshbuf_put_u32(buf, options->ଅଙ୍କ_subsystems)) != 0) {
		error_fr(r, "serialise length");
		ଫେରନ୍ତୁ r;
	}
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_subsystems; i++) {
		ଯଦି ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_pubkey_auth_options(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_timingsecret(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}


ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serialise_server_options(ଅଚଳ ServerOptions *options, ସଂରଚନା sshbuf **bufp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*bufp = ଖାଲି;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		ଯାଅ out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ଯଦି ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ଯଦି ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	ଯଦି ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ଯଦି ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ଯଦି ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ଯାଅ out;
#define SSHCONF_NONCONF(funcsuffix) \
	ଯଦି ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ଯାଅ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = ଖାଲି; /* transferred */
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_s32(ସଂରଚନା sshbuf *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *v)
{
	uint32_t tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char was_signed;

	ଯଦି ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (was_signed > 1)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (was_signed) {
		ଯଦି (tmp > (uint32_t)INT_MAX + 1)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(ପୂର୍ଣ୍ଣସଂଖ୍ୟା)tmp;
	} ଅନ୍ୟଥା {
		ଯଦି (tmp > INT_MAX)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		*v = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)tmp;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_s64(ସଂରଚନା sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char was_signed;

	ଯଦି ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (was_signed > 1)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (was_signed) {
		ଯଦି (tmp > (uint64_t)INT64_MAX + 1)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} ଅନ୍ୟଥା {
		ଯଦି (tmp > INT64_MAX)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_mode(ସଂରଚନା sshbuf *buf, mode_t *v)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, tmp;

	ଯଦି ((r = deserialise_s32(buf, &tmp)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (tmp == -1) {
		*v = (mode_t)-1;
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (tmp < 0 || tmp > 0777)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_double(ସଂରଚନା sshbuf *buf, ଦ୍ୱିଗୁଣ *v)
{
	ଫେରନ୍ତୁ sshbuf_get(buf, v, ଆକାର(*v));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_nullable_string(ସଂରଚନା sshbuf *buf, ଅକ୍ଷର **sp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char present;

	ଯଦି ((r = sshbuf_get_u8(buf, &present)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (present == 0) {
		*sp = ଖାଲି;
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (present != 1)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ sshbuf_get_cstring(buf, sp, ଖାଲି);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_string_array(ଅକ୍ଷର **a, u_int n)
{
	u_int i;

	ଯଦି (a == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < n; i++)
		ମୁକ୍ତ(a[i]);
	ମୁକ୍ତ(a);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_ଗଣନା(ସଂରଚନା sshbuf *buf, u_int *np, ଅଚଳ ଅକ୍ଷର *what)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	uint32_t n;

	ଯଦି ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (n > UINT_MAX) {
		error_f("bad number of %s", what);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଯଦି (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_nullable_string_array(ସଂରଚନା sshbuf *buf, ଅକ୍ଷର ***arrayp,
    u_int *np)
{
	ଅକ୍ଷର **a = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i, n;

	*arrayp = ଖାଲି;
	*np = 0;
	ଯଦି ((r = deserialise_ଗଣନା(buf, &n, "strings")) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (n > 0)
		a = xcalloc(n, ଆକାର(*a));
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			ଫେରନ୍ତୁ r;
		}
	}
	*arrayp = a;
	*np = n;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
free_queued_listen_addrs(ସଂରଚନା queued_listenaddr *qla, u_int n)
{
	u_int i;

	ଯଦି (qla == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < n; i++) {
		ମୁକ୍ତ(qla[i].addr);
		ମୁକ୍ତ(qla[i].rdomain);
	}
	ମୁକ୍ତ(qla);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_hostkeyfile(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, *userprovided = ଖାଲି;
	u_int i, n;
	ଅକ୍ଷର **files = ଖାଲି;

	ଯଦି ((r = deserialise_ଗଣନା(buf, &n, "host key files")) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (n > 0) {
		userprovided = xcalloc(n, ଆକାର(*userprovided));
		files = xcalloc(n, ଆକାର(*files));
	}
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			ମୁକ୍ତ(userprovided);
			ଫେରନ୍ତୁ r;
		}
	}
	options->ଅଙ୍କ_host_ଚାବି_files = n;
	options->host_ଚାବି_file_userprovided = userprovided;
	options->host_ଚାବି_files = files;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_ipqos(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_listenaddress(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i, n;
	ସଂରଚନା queued_listenaddr *qla = ଖାଲି;

	ଯଦି ((r = deserialise_ଗଣନା(buf, &n, "listen addresses")) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (n > 0)
		qla = xcalloc(n, ଆକାର(*qla));
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = sshbuf_get_cstring(buf, &qla[i].addr, ଖାଲି)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			ଫେରନ୍ତୁ r;
		}
	}
	options->ଅଙ୍କ_queued_listens = n;
	options->queued_listen_addrs = qla;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_logfacility(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, tmp;

	ଯଦି ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == ଖାଲି) {
		error_f("bad syslog facility");
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_loglevel(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, tmp;

	ଯଦି ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == ଖାଲି) {
		error_f("bad log level");
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_port(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i, n;

	ଯଦି ((r = deserialise_ଗଣନା(buf, &n, "ports")) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (n > MAX_PORTS) {
		error_f("bad number of ports");
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	options->ଅଙ୍କ_ports = n;
	memset(options->ports, 0, ଆକାର(options->ports));
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_ports; i++) {
		ଯଦି ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_gatewayports(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_streamlocalbindmask(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_streamlocalbindunlink(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char tmp;

	ଯଦି ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (tmp > 1) {
		error_f("bad boolean");
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_maxstartups(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_permituserenv(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_persourcenetblocksize(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_persourcepenalties(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ସଂରଚନା per_source_penalty *psp = &options->per_source_penalty;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->overflow_mode)) != 0 ||
	    (r = deserialise_s32(buf, &psp->overflow_mode6)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_crash)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_grace)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_authfail)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_invaliduser)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_noauth)) != 0 ||
	    (r = deserialise_double(buf,
	    &psp->penalty_refuseconnection)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_max)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_min)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_rekeylimit(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_subsystem(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int i, n;
	ଅକ୍ଷର **names = ଖାଲି, **commands = ଖାଲି, **args = ଖାଲି;

	ଯଦି ((r = deserialise_ଗଣନା(buf, &n, "subsystems")) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (n > 0) {
		names = xcalloc(n, ଆକାର(*names));
		commands = xcalloc(n, ଆକାର(*names));
		args = xcalloc(n, ଆକାର(*args));
	}
	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି ((r = sshbuf_get_cstring(buf, names + i, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, ଖାଲି)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			ଫେରନ୍ତୁ r;
		}
	}
	options->ଅଙ୍କ_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_pubkey_auth_options(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_timingsecret(ServerOptions *options, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
deserialise_server_options(ସଂରଚନା sshbuf *buf, ServerOptions *options)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	ଯଦି ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		ଯାଅ out;
	}
	ଯଦି (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ଯଦି ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ଯଦି ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	ଯଦି ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ଯଦି ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ଯାଅ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ଯଦି ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ଯାଅ out;
#define SSHCONF_NONCONF(funcsuffix) \
	ଯଦି ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ଯାଅ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	କର { \
		ମୁକ୍ତ(new_options.var); \
		new_options.var = ଖାଲି; \
	} ଯେତେବେଳେ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	ଯଦି (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, ଆକାର(new_options));
 out:
	free_server_options(&new_options);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_host_ଚାବି_files; i++)
		ମୁକ୍ତ(options->host_ଚାବି_files[i]);
	ମୁକ୍ତ(options->host_ଚାବି_files);
	ମୁକ୍ତ(options->host_ଚାବି_file_userprovided);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->ଅଙ୍କ_queued_listens);

	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_listen_addrs; i++) {
		ମୁକ୍ତ(options->listen_addrs[i].rdomain);
		ଯଦି (options->listen_addrs[i].addrs != ଖାଲି)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	ମୁକ୍ତ(options->listen_addrs);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_permituserenv(ServerOptions *options)
{
	ମୁକ୍ତ(options->permit_user_env_allowlist);
}

ସ୍ଥିର ଶୂନ୍ୟ
free_subsystem(ServerOptions *options)
{
	u_int i;

	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_subsystems; i++) {
		ମୁକ୍ତ(options->subsystem_name[i]);
		ମୁକ୍ତ(options->subsystem_command[i]);
		ମୁକ୍ତ(options->subsystem_args[i]);
	}
	ମୁକ୍ତ(options->subsystem_name);
	ମୁକ୍ତ(options->subsystem_command);
	ମୁକ୍ତ(options->subsystem_args);
}

ଶୂନ୍ୟ
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		ମୁକ୍ତ(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	କର { \
		ମୁକ୍ତ(options->var); \
		options->var = ଖାଲି; \
	} ଯେତେବେଳେ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

#define free_ipqos(options)
#define free_logfacility(options)
#define free_loglevel(options)
#define free_port(options)
#define free_gatewayports(options)
#define free_streamlocalbindmask(options)
#define free_streamlocalbindunlink(options)
#define free_maxstartups(options)
#define free_persourcenetblocksize(options)
#define free_persourcepenalties(options)
#define free_rekeylimit(options)
#define free_pubkey_auth_options(options)
#define free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#undef free_ipqos
#undef free_logfacility
#undef free_loglevel
#undef free_port
#undef free_gatewayports
#undef free_streamlocalbindmask
#undef free_streamlocalbindunlink
#undef free_maxstartups
#undef free_persourcenetblocksize
#undef free_persourcepenalties
#undef free_rekeylimit
#undef free_timingsecret

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	initialize_server_options(options);
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_server_option_int(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *dst, ପୂର୍ଣ୍ଣସଂଖ୍ୟା src)
{
	ଯଦି (src != -1)
		*dst = src;
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_server_option_int64(int64_t *dst, int64_t src)
{
	ଯଦି (src != -1)
		*dst = src;
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_server_option_string(ଅକ୍ଷର **dst, ଅଚଳ ଅକ୍ଷର *src)
{
	ଯଦି (src != ଖାଲି && *dst != src) {
		ମୁକ୍ତ(*dst);
		*dst = xstrdup(src);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_server_option_strarray_ମୂଲ୍ୟଗୁଡ଼ିକ(ଅକ୍ଷର ***dst, u_int ndst,
    ଅକ୍ଷର * ଅଚଳ *src, u_int nsrc)
{
	u_int i;

	ଯଦି (nsrc == 0)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < ndst; i++)
		ମୁକ୍ତ((*dst)[i]);
	ମୁକ୍ତ(*dst);
	*dst = xcalloc(nsrc, ଆକାର(**dst));
	ପାଇଁ (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ଖାଲି ? ଖାଲି : xstrdup(src[i]);
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_server_option_strarray(ଅକ୍ଷର ***dst, u_int *ndst,
    ଅକ୍ଷର * ଅଚଳ *src, u_int nsrc)
{
	ଯଦି (nsrc == 0)
		ଫେରନ୍ତୁ;
	copy_server_option_strarray_ମୂଲ୍ୟଗୁଡ଼ିକ(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_ipqos(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_gatewayports(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_streamlocalbindunlink(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_loglevel(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	ଯଦି (src->log_level != -1)
		dst->log_level = src->log_level;
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_rekeylimit(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_subsystem(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	u_int old_ଅଙ୍କ_subsystems = dst->ଅଙ୍କ_subsystems;

	ଯଦି (src->ଅଙ୍କ_subsystems == 0)
		ଫେରନ୍ତୁ;
	copy_server_option_strarray_ମୂଲ୍ୟଗୁଡ଼ିକ(&dst->subsystem_name,
	    old_ଅଙ୍କ_subsystems, src->subsystem_name, src->ଅଙ୍କ_subsystems);
	copy_server_option_strarray_ମୂଲ୍ୟଗୁଡ଼ିକ(&dst->subsystem_command,
	    old_ଅଙ୍କ_subsystems, src->subsystem_command, src->ଅଙ୍କ_subsystems);
	copy_server_option_strarray_ମୂଲ୍ୟଗୁଡ଼ିକ(&dst->subsystem_args,
	    old_ଅଙ୍କ_subsystems, src->subsystem_args, src->ଅଙ୍କ_subsystems);
	dst->ଅଙ୍କ_subsystems = src->ଅଙ୍କ_subsystems;
}

ସ୍ଥିର ଶୂନ୍ୟ
copy_pubkey_auth_options(ServerOptions *dst, ଅଚଳ ServerOptions *src)
{
	ଯଦି (src->pubkey_auth_options != -1) {
		dst->pubkey_auth_options = src->pubkey_auth_options;
		dst->max_pubkey_ok = src->max_pubkey_ok;
	}
}

/*
 * Copy any supported values that are set.
 *
 * If the preauth flag is set, skip the post-authentication-only manual
 * string cleanup and subsystem merge below.
 */
ଶୂନ୍ୟ
copy_set_server_options(ServerOptions *dst, ServerOptions *src, ପୂର୍ଣ୍ଣସଂଖ୍ୟା preauth)
{
	ଯଦି (dst == src)
		ଫେରନ୍ତୁ;

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#define SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	କର { \
		ମୁକ୍ତ(dst->var); \
		dst->var = ଖାଲି; \
	} ଯେତେବେଳେ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	ଯଦି (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
		dst->fwd_opts.streamlocal_bind_mask =
		    src->fwd_opts.streamlocal_bind_mask;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#define CLEAR_ON_NONE(v) \
	କର { \
		ଯଦି (option_clear_or_none(v)) { \
			ମୁକ୍ତ(v); \
			v = ଖାଲି; \
		} \
	} ଯେତେବେଳେ(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_ଚାବିଗୁଡ଼ିକ);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	ଯଦି (preauth)
		ଫେରନ୍ତୁ;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#undef CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_merge_subsystems(dst, src);
}

#define SERVCONF_MAX_DEPTH	16
ସ୍ଥିର ଶୂନ୍ୟ
parse_server_config_depth(ServerOptions *options, ଅଚଳ ଅକ୍ଷର *filename,
    ସଂରଚନା sshbuf *conf, ସଂରଚନା include_list *includes,
    ସଂରଚନା connection_info *connectinfo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, bad_options = 0;
	ଅକ୍ଷର *cp, *obuf, *cbuf;

	ଯଦି (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	ଯଦି ((obuf = cbuf = sshbuf_dup_string(conf)) == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	ଯେତେବେଳେ ((cp = strsep(&cbuf, "\n")) != ଖାଲି) {
		ଯଦି (process_server_config_ଧାଡ଼ି_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	ମୁକ୍ତ(obuf);
	ଯଦି (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

ଶୂନ୍ୟ
parse_server_config(ServerOptions *options, ଅଚଳ ଅକ୍ଷର *filename,
    ସଂରଚନା sshbuf *conf, ସଂରଚନା include_list *includes,
    ସଂରଚନା connection_info *connectinfo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା reexec)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	ଯଦି (!reexec)
		process_queued_listen_addrs(options);
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
fmt_multistate_int(ପୂର୍ଣ୍ଣସଂଖ୍ୟା val, ଅଚଳ ସଂରଚନା multistate *m)
{
	u_int i;

	ପାଇଁ (i = 0; m[i].ଚାବି != ଖାଲି; i++) {
		ଯଦି (m[i].ମୂଲ୍ୟ == val)
			ଫେରନ୍ତୁ m[i].ଚାବି;
	}
	ଫେରନ୍ତୁ "UNKNOWN";
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
fmt_intarg(ServerOpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	ଯଦି (val == -1)
		ଫେରନ୍ତୁ "unset";
	ବାଛ (code) {
	ସ୍ଥିତି sAddressFamily:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_addressfamily);
	ସ୍ଥିତି s_Permit_ମୂଳ_Login:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_permitrootlogin);
	ସ୍ଥିତି sGatewayPorts:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_gatewayports);
	ସ୍ଥିତି sCompression:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_compression);
	ସ୍ଥିତି sAllowTcpForwarding:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_tcpfwd);
	ସ୍ଥିତି sAllowStreamLocalForwarding:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_tcpfwd);
	ସ୍ଥିତି sIgnoreRhosts:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_ignore_rhosts);
	ସ୍ଥିତି sTCPKeepAlive:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_keepalives);
	ସ୍ଥିତି sWarnWeakCrypto:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_warnweakcrypto);
	ସ୍ଥିତି sFingerprintHash:
		ଫେରନ୍ତୁ ssh_digest_alg_name(val);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ବାଛ (val) {
		ସ୍ଥିତି 0:
			ଫେରନ୍ତୁ "no";
		ସ୍ଥିତି 1:
			ଫେରନ୍ତୁ "yes";
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଫେରନ୍ତୁ "UNKNOWN";
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_int(ServerOpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	ଯଦି (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		ଫେରନ୍ତୁ;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_oct(ServerOpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_fmtint(ServerOpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_string(ServerOpCodes code, ଅଚଳ ଅକ୍ଷର *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == ଖାଲି ? "none" : val);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_strarray(ServerOpCodes code, u_int ଗଣନା_2, ଅକ୍ଷର **vals)
{
	u_int i;

	ପାଇଁ (i = 0; i < ଗଣନା_2; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_strarray_oneline(ServerOpCodes code, u_int ଗଣନା_2, ଅକ୍ଷର **vals)
{
	u_int i;

	ବାଛ (code) {
	ସ୍ଥିତି sAuthenticationMethods:
	ସ୍ଥିତି sChannelTimeout:
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଯଦି (ଗଣନା_2 <= 0)
			ଫେରନ୍ତୁ;
		ଭାଙ୍ଗ;
	}

	printf("%s", lookup_opcode_name(code));
	ପାଇଁ (i = 0; i < ଗଣନା_2; i++)
		printf(" %s",  vals[i]);
	ଯଦି (code == sAuthenticationMethods && ଗଣନା_2 == 0)
		printf(" any");
	ଅନ୍ୟଥା ଯଦି (code == sChannelTimeout && ଗଣନା_2 == 0)
		printf(" none");
	printf("\n");
}

ସ୍ଥିର ଅକ୍ଷର *
format_listen_addrs(ସଂରଚନା listenaddr *la)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା addrinfo *ai;
	ଅକ୍ଷର addr[NI_MAXHOST], port[NI_MAXSERV];
	ଅକ୍ଷର *laddr1 = xstrdup(""), *laddr2 = ଖାଲି;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	ପାଇଁ (ai = la->addrs; ai; ai = ai->ai_next) {
		ଯଦି ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    ଆକାର(addr), port, ଆକାର(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			ଜାରି;
		}
		laddr2 = laddr1;
		ଯଦି (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ଖାଲି ? "" : " rdomain ",
			    la->rdomain == ଖାଲି ? "" : la->rdomain,
			    laddr2);
		} ଅନ୍ୟଥା {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ଖାଲି ? "" : " rdomain ",
			    la->rdomain == ଖାଲି ? "" : la->rdomain,
			    laddr2);
		}
		ମୁକ୍ତ(laddr2);
	}
	ଫେରନ୍ତୁ laddr1;
}

ଶୂନ୍ୟ
dump_config(ServerOptions *o)
{
	ଅକ୍ଷର *s;
	u_int i;

	/* these are usually at the top of the config */
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		ମୁକ୍ତ(s);
	}

	/* integer arguments */
#ifdef USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#endif
	dump_cfg_int(sLoginGraceTime, o->login_grace_time);
	dump_cfg_int(sX11DisplayOffset, o->x11_display_offset);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_ଗଣନା_Max, o->client_alive_ଗଣନା_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_ମୂଳ_Login, o->permit_ମୂଳ_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(sIgnoreUserKnownHosts, o->ignore_user_known_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(sHostbasedUsesNameFromPacketOnly,
	    o->hostbased_uses_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#ifdef KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#endif
#ifdef GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#endif
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#ifndef DISABLE_LASTLOG
	dump_cfg_fmtint(sPrintLastLog, o->print_lastlog);
#endif
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(sPermitEmptyPasswords, o->permit_empty_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(sAllowStreamLocalForwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(sStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(sFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(sExposeAuthInfo, o->expose_userauth_info);
	dump_cfg_fmtint(sWarnWeakCrypto, o->warn_weak_crypto);
	dump_cfg_fmtint(sRefuseConnection, o->refuse_connection);

	/* string arguments */
	dump_cfg_string(sPidFile, o->pid_file);
	dump_cfg_string(sModuliFile, o->moduli_file);
	dump_cfg_string(sXAuthLocation, o->xauth_location);
	dump_cfg_string(sCiphers, o->ciphers);
	dump_cfg_string(sMacs, o->macs);
	dump_cfg_string(sBanner, o->banner);
	dump_cfg_string(sForceCommand, o->adm_forced_command);
	dump_cfg_string(sChrootDirectory, o->chroot_directory);
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_ଚାବିଗୁଡ଼ିକ);
	dump_cfg_string(s_Security_ଚାବି_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_ଚାବିଗୁଡ଼ିକ_Command, o->authorized_ଚାବିଗୁଡ଼ିକ_command);
	dump_cfg_string(s_Authorized_ଚାବିଗୁଡ଼ିକ_Command_User, o->authorized_ଚାବିଗୁଡ଼ିକ_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_ଚାବି_Agent, o->host_ଚାବି_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_ଚାବି_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#ଯଦି defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#endif
	dump_cfg_string(sSshdSessionPath, o->sshd_session_path);
	dump_cfg_string(sSshdAuthPath, o->sshd_auth_path);
	dump_cfg_string(sPerSourcePenaltyExemptList, o->per_source_penalty_exempt);
	dump_cfg_string(sAgentSocketPath, o->agent_socket_path);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_ଚାବିଗୁଡ଼ିକ_File, o->ଅଙ୍କ_authkeys_files,
	    o->authorized_ଚାବିଗୁଡ଼ିକ_files);
	dump_cfg_strarray_oneline(s_Revoked_ଚାବିଗୁଡ଼ିକ, o->ଅଙ୍କ_revoked_ଚାବିଗୁଡ଼ିକ_files,
	    o->revoked_ଚାବିଗୁଡ଼ିକ_files);
	dump_cfg_strarray(s_Host_ଚାବି, o->ଅଙ୍କ_host_ଚାବି_files, o->host_ଚାବି_files);
	dump_cfg_strarray(sHostCertificate, o->ଅଙ୍କ_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->ଅଙ୍କ_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->ଅଙ୍କ_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->ଅଙ୍କ_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->ଅଙ୍କ_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->ଅଙ୍କ_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->ଅଙ୍କ_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->ଅଙ୍କ_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->ଅଙ୍କ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->ଅଙ୍କ_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	ଯଦି (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	ଅନ୍ୟଥା
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = ଖାଲି;
	ପାଇଁ (i = 0; tunmode_desc[i].val != -1; i++) {
		ଯଦି (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			ଭାଙ୍ଗ;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	ଯଦି (o->ଅଙ୍କ_permitted_opens == 0)
		printf(" any");
	ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; i < o->ଅଙ୍କ_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	ଯଦି (o->ଅଙ୍କ_permitted_listens == 0)
		printf(" any");
	ଅନ୍ୟଥା {
		ପାଇଁ (i = 0; i < o->ଅଙ୍କ_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	ଯଦି (o->permit_user_env_allowlist == ଖାଲି) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} ଅନ୍ୟଥା {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	ଯଦି (o->pubkey_auth_options == 0)
		printf(" none");
	ଯଦି (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	ଯଦି (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	ଯଦି (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	ଯଦି (o->per_source_penalty.enabled) {
		printf("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->per_source_penalty.penalty_crash,
		    o->per_source_penalty.penalty_authfail,
		    o->per_source_penalty.penalty_noauth,
		    o->per_source_penalty.penalty_invaliduser,
		    o->per_source_penalty.penalty_grace,
		    o->per_source_penalty.penalty_refuseconnection,
		    o->per_source_penalty.penalty_max,
		    o->per_source_penalty.penalty_min,
		    o->per_source_penalty.max_sources4,
		    o->per_source_penalty.max_sources6,
		    o->per_source_penalty.overflow_mode ==
		    PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->per_source_penalty.overflow_mode6 ==
		    PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL ?
		    "deny-all" : "permissive");
	} ଅନ୍ୟଥା
		printf("PerSourcePenalties no\n");
}
