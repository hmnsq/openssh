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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ifdef __OpenBSD__
#ಅನ್ತರ್ಭಾವ <sys/sysctl.h>
#endif

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#ಅನ್ತರ್ಭಾವ <net/route.h>
#endif

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "groupaccess.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#ಯದಿ !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

ಸ್ಥಿರ ಶೂನ್ಯ add_listen_addr(ServerOptions *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಶೂನ್ಯ add_one_listen_addr(ServerOptions *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಶೂನ್ಯ parse_server_config_depth(ServerOptions *options,
    ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ sshbuf *conf, ಸಂರಚನಾ include_list *includes,
    ಸಂರಚನಾ connection_info *connectinfo, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ depth);

ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *cfg;

/* Initializes the server options to their default values. */

ಶೂನ್ಯ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, ಪರಿಮಾಣ(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = ರಿಕ್ತ;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ರಿಕ್ತ;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ರಿಕ್ತ;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_ಕೀಲಿ_files = 0; \
	options->ಅಂಕೆ_host_ಕೀಲಿ_files = 0; \
	options->host_ಕೀಲಿ_file_userprovided = ರಿಕ್ತ;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = ರಿಕ್ತ; \
	options->ಅಂಕೆ_queued_listens = 0; \
	options->listen_addrs = ರಿಕ್ತ; \
	options->ಅಂಕೆ_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->ಅಂಕೆ_ports = 0; \
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
	options->permit_user_env_allowlist = ರಿಕ್ತ;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = ರಿಕ್ತ; \
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
	options->ಅಂಕೆ_subsystems = 0; \
	options->subsystem_name = ರಿಕ್ತ; \
	options->subsystem_command = ರಿಕ್ತ; \
	options->subsystem_args = ರಿಕ್ತ;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
option_clear_or_none(ಧ್ರುವ ವರ್ಣ *o)
{
	ಪ್ರತ್ಯಾಗಮ o == ರಿಕ್ತ || strcasecmp(o, "none") == 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
assemble_algorithms(ServerOptions *o)
{
	ವರ್ಣ *all_cipher, *all_mac, *all_kex, *all_ಕೀಲಿ, *all_sig;
	ವರ್ಣ *def_cipher, *def_mac, *def_kex, *def_ಕೀಲಿ, *def_sig;
	ಪೂರ್ಣಾಙ್ಕ r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_ಕೀಲಿ = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ಕೀಲಿ);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	ಕುರು { \
		ಯದಿ ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} ಯಾವತ್ (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(hostbased_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(pubkey_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	ಮುಕ್ತ(all_cipher);
	ಮುಕ್ತ(all_mac);
	ಮುಕ್ತ(all_kex);
	ಮುಕ್ತ(all_ಕೀಲಿ);
	ಮುಕ್ತ(all_sig);
	ಮುಕ್ತ(def_cipher);
	ಮುಕ್ತ(def_mac);
	ಮುಕ್ತ(def_kex);
	ಮುಕ್ತ(def_ಕೀಲಿ);
	ಮುಕ್ತ(def_sig);
}

ಶೂನ್ಯ
servconf_add_hostkey(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ ಸಾಲು,
    ServerOptions *options, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ userprovided)
{
	ವರ್ಣ *apath = derelativise_path(path);

	opt_array_append2(file, ಸಾಲು, "HostKey",
	    &options->host_ಕೀಲಿ_files, &options->host_ಕೀಲಿ_file_userprovided,
	    &options->ಅಂಕೆ_host_ಕೀಲಿ_files, apath, userprovided);
	ಮುಕ್ತ(apath);
}

ಶೂನ್ಯ
servconf_add_hostcert(ಧ್ರುವ ವರ್ಣ *file, ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ ಸಾಲು,
    ServerOptions *options, ಧ್ರುವ ವರ್ಣ *path)
{
	ವರ್ಣ *apath = derelativise_path(path);

	opt_array_append(file, ಸಾಲು, "HostCertificate",
	    &options->host_cert_files, &options->ಅಂಕೆ_host_cert_files, apath);
	ಮುಕ್ತ(apath);
}

ಶೂನ್ಯ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	ಯದಿ (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	ಯದಿ (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ಯದಿ (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ಯದಿ (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಕುರು { \
		ಮುಕ್ತ(options->var); \
		options->var = ರಿಕ್ತ; \
	} ಯಾವತ್ (0);
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
	ಯದಿ (options->pam_service_name == ರಿಕ್ತ)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	ಯದಿ (options->ಅಂಕೆ_host_ಕೀಲಿ_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_ಕೀಲಿ_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_ಕೀಲಿ_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_ಕೀಲಿ_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, 0);
	}
	/* No certificates by default */
	ಯದಿ (options->ಅಂಕೆ_ports == 0)
		options->ports[options->ಅಂಕೆ_ports++] = SSH_DEFAULT_PORT;
	ಯದಿ (options->listen_addrs == ರಿಕ್ತ)
		add_listen_addr(options, ರಿಕ್ತ, ರಿಕ್ತ, 0);
	ಯದಿ (options->pid_file == ರಿಕ್ತ)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	ಯದಿ (options->moduli_file == ರಿಕ್ತ)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	ಯದಿ (options->xauth_location == ರಿಕ್ತ)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	ಯದಿ (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	ಯದಿ (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	ಯದಿ (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ರಿಕ್ತ;
	}
	ಯದಿ (options->rekey_limit == -1)
		options->rekey_limit = 0;
	ಯದಿ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ಯದಿ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ಯದಿ (options->max_startups == -1)
		options->max_startups = 100;
	ಯದಿ (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	ಯದಿ (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	ಯದಿ (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	ಯದಿ (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	ಯದಿ (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	ಯದಿ (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	ಯದಿ (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	ಯದಿ (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	ಯದಿ (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	ಯದಿ (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	ಯದಿ (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	ಯದಿ (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	ಯದಿ (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	ಯದಿ (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	ಯದಿ (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	ಯದಿ (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	ಯದಿ (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	ಯದಿ (options->ಅಂಕೆ_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ಕೀಲಿಗಳು_files,
		    &options->ಅಂಕೆ_authkeys_files,
		    PATH_SSH_USER_PERMITTED_ಕೀಲಿಗಳು);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ಕೀಲಿಗಳು_files,
		    &options->ಅಂಕೆ_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	ಯದಿ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ಯದಿ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ಯದಿ (options->version_addendum == ರಿಕ್ತ)
		options->version_addendum = xstrdup("");
	ಯದಿ (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	ಯದಿ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ಯದಿ (options->sk_provider == ರಿಕ್ತ)
		options->sk_provider = xstrdup("internal");
	ಯದಿ (options->sshd_session_path == ರಿಕ್ತ)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	ಯದಿ (options->sshd_auth_path == ರಿಕ್ತ)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	ಯದಿ (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	ಯದಿ (options->agent_socket_path == ರಿಕ್ತ)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	ಕುರು { \
		ಯದಿ (option_clear_or_none(v)) { \
			ಮುಕ್ತ(v); \
			v = ರಿಕ್ತ; \
		} \
	} ಯಾವತ್(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ಕುರು { \
		ಯದಿ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ಮುಕ್ತ(options->v[0]); \
			ಮುಕ್ತ(options->v); \
			options->v = ರಿಕ್ತ; \
			options->nv = 0; \
		} \
	} ಯಾವತ್ (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_ಕೀಲಿಗಳು);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_ಕೀಲಿ_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_host_ಕೀಲಿ_files; i++)
		CLEAR_ON_NONE(options->host_ಕೀಲಿ_files[i]);
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, ಅಂಕೆ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, ಅಂಕೆ_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_ಕೀಲಿಗಳು_files, ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_ಕೀಲಿಗಳು_files, ಅಂಕೆ_authkeys_files, "none");
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
ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ {
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
ಸ್ಥಿರ ಸಂರಚನಾ {
	ಧ್ರುವ ವರ್ಣ *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ರಿಕ್ತ, sBadOption, 0 }
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

ಸ್ಥಿರ ಸಂರಚನಾ {
	ಪೂರ್ಣಾಙ್ಕ val;
	ವರ್ಣ *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ರಿಕ್ತ }
};

/* Returns an opcode name from its number */

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	ಪ್ರತಿ (i = 0; keywords[i].name != ರಿಕ್ತ; i++)
		ಯದಿ (keywords[i].opcode == code)
			ಪ್ರತ್ಯಾಗಮ(keywords[i].name);
	ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ಸ್ಥಿರ ServerOpCodes
parse_token(ಧ್ರುವ ವರ್ಣ *cp, ಧ್ರುವ ವರ್ಣ *filename,
	    ಪೂರ್ಣಾಙ್ಕ linenum, u_int *flags)
{
	u_int i;

	ಪ್ರತಿ (i = 0; keywords[i].name; i++)
		ಯದಿ (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			ಪ್ರತ್ಯಾಗಮ keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ಪ್ರತ್ಯಾಗಮ sBadOption;
}

ವರ್ಣ *
derelativise_path(ಧ್ರುವ ವರ್ಣ *path)
{
	ವರ್ಣ *expanded, *ret, cwd[PATH_MAX];

	ಯದಿ (strcasecmp(path, "none") == 0)
		ಪ್ರತ್ಯಾಗಮ xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	ಯದಿ (path_absolute(expanded))
		ಪ್ರತ್ಯಾಗಮ expanded;
	ಯದಿ (getcwd(cwd, ಪರಿಮಾಣ(cwd)) == ರಿಕ್ತ)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	ಮುಕ್ತ(expanded);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
add_listen_addr(ServerOptions *options, ಧ್ರುವ ವರ್ಣ *addr,
    ಧ್ರುವ ವರ್ಣ *rdomain, ಪೂರ್ಣಾಙ್ಕ port)
{
	u_int i;

	ಯದಿ (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
add_one_listen_addr(ServerOptions *options, ಧ್ರುವ ವರ್ಣ *addr,
    ಧ್ರುವ ವರ್ಣ *rdomain, ಪೂರ್ಣಾಙ್ಕ port)
{
	ಸಂರಚನಾ addrinfo hints, *ai, *aitop;
	ವರ್ಣ strport[NI_MAXSERV];
	ಪೂರ್ಣಾಙ್ಕ gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_listen_addrs; i++) {
		ಯದಿ (rdomain == ರಿಕ್ತ && options->listen_addrs[i].rdomain == ರಿಕ್ತ)
			ಭಙ್ಗ;
		ಯದಿ (rdomain == ರಿಕ್ತ || options->listen_addrs[i].rdomain == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			ಭಙ್ಗ;
	}
	ಯದಿ (i >= options->ಅಂಕೆ_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		ಯದಿ (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->ಅಂಕೆ_listen_addrs, options->ಅಂಕೆ_listen_addrs + 1,
		    ಪರಿಮಾಣ(*options->listen_addrs));
		i = options->ಅಂಕೆ_listen_addrs++;
		ಯದಿ (rdomain != ರಿಕ್ತ)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ರಿಕ್ತ) ? AI_PASSIVE : 0;
	snprintf(strport, ಪರಿಮಾಣ strport, "%d", port);
	ಯದಿ ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	ಪ್ರತಿ (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
valid_rdomain(ಧ್ರುವ ವರ್ಣ *name)
{
#ಯದಿ defined(HAVE_SYS_VALID_RDOMAIN)
	ಪ್ರತ್ಯಾಗಮ sys_valid_rdomain(name);
#ನೋಚೇದ್ಯದಿ defined(__OpenBSD__)
	ಧ್ರುವ ವರ್ಣ *errstr;
	long long ಅಂಕೆ;
	ಸಂರಚನಾ rt_tableinfo info;
	ಪೂರ್ಣಾಙ್ಕ mib[6];
	size_t miblen = ಪರಿಮಾಣ(mib);

	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;

	ಅಂಕೆ = strtonum(name, 0, 255, &errstr);
	ಯದಿ (errstr != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Check whether the table actually exists */
	memset(mib, 0, ಪರಿಮಾಣ(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (ಪೂರ್ಣಾಙ್ಕ)ಅಂಕೆ;
	ಯದಿ (sysctl(mib, 6, &info, &miblen, ರಿಕ್ತ, 0) == -1)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಪ್ರತ್ಯಾಗಮ 1;
#ಅನ್ಯಥಾ /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	ಪ್ರತ್ಯಾಗಮ 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
queue_listen_addr(ServerOptions *options, ಧ್ರುವ ವರ್ಣ *addr,
    ಧ್ರುವ ವರ್ಣ *rdomain, ಪೂರ್ಣಾಙ್ಕ port)
{
	ಸಂರಚನಾ queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->ಅಂಕೆ_queued_listens, options->ಅಂಕೆ_queued_listens + 1,
	    ಪರಿಮಾಣ(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->ಅಂಕೆ_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ಸಂರಚನಾ queued_listenaddr *qla;

	ಯದಿ (options->ಅಂಕೆ_ports == 0)
		options->ports[options->ಅಂಕೆ_ports++] = SSH_DEFAULT_PORT;
	ಯದಿ (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		ಮುಕ್ತ(qla->addr);
		ಮುಕ್ತ(qla->rdomain);
	}
	ಮುಕ್ತ(options->queued_listen_addrs);
	options->queued_listen_addrs = ರಿಕ್ತ;
	options->ಅಂಕೆ_queued_listens = 0;
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

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_cfg_ಸಾಲು_group(ಧ್ರುವ ವರ್ಣ *grps, ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಧ್ರುವ ವರ್ಣ *user)
{
	ಪೂರ್ಣಾಙ್ಕ result = 0;
	ಸಂರಚನಾ passwd *pw;

	ಯದಿ (user == ರಿಕ್ತ)
		ಗಚ್ಛ out;

	ಯದಿ ((pw = getpwnam(user)) == ರಿಕ್ತ) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", ಸಾಲು, user);
	} ಅನ್ಯಥಾ ಯದಿ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, ಸಾಲು);
	} ಅನ್ಯಥಾ ಯದಿ (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, ಸಾಲು);
	} ಅನ್ಯಥಾ {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, ಸಾಲು);
		result = 1;
	}
out:
	ga_free();
	ಪ್ರತ್ಯಾಗಮ result;
}

ಸ್ಥಿರ ಶೂನ್ಯ
match_test_missing_fatal(ಧ್ರುವ ವರ್ಣ *criteria, ಧ್ರುವ ವರ್ಣ *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_cfg_ಸಾಲು(ಧ್ರುವ ವರ್ಣ *full_ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ *acp, ವರ್ಣ ***avp,
    ಪೂರ್ಣಾಙ್ಕ ಸಾಲು, ಸಂರಚನಾ connection_info *ci)
{
	ಪೂರ್ಣಾಙ್ಕ result = 1, attributes = 0, port;
	ವರ್ಣ *arg, *attrib = ರಿಕ್ತ, *oattrib;

	ಯದಿ (ci == ರಿಕ್ತ) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_ಸಾಲು, ಸಾಲು);
	} ಅನ್ಯಥಾ {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_ಸಾಲು,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", ಸಾಲು);
	}

	ಯಾವತ್ ((oattrib = argv_next(acp, avp)) != ರಿಕ್ತ) {
		/* Terminate on comment */
		ಯದಿ (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			ಭಙ್ಗ;
		}
		attrib = xstrdup(oattrib);
		arg = ರಿಕ್ತ;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		ಯದಿ (strcasecmp(attrib, "all") == 0) {
			ಯದಿ (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ರಿಕ್ತ &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				ಗಚ್ಛ out;
			}
			ಯದಿ (arg != ರಿಕ್ತ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			ಗಚ್ಛ out;
		}
		/* Criterion "invalid-user" also has no argument */
		ಯದಿ (strcasecmp(attrib, "invalid-user") == 0) {
			ಯದಿ (ci == ರಿಕ್ತ) {
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->user_invalid == 0)
				result = 0;
			ಅನ್ಯಥಾ
				debug("matched invalid-user at line %d", ಸಾಲು);
			ಗಚ್ಛ next;
		}

		/* Keep this list in sync with below */
		ಯದಿ (strprefix(attrib, "user=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "group=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "host=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "address=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "localaddress=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "localport=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "rdomain=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "version=", 1) != ರಿಕ್ತ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ಅನ್ಯಥಾ {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		ಯದಿ (arg == ರಿಕ್ತ || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcasecmp(attrib, "user") == 0) {
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->user == ರಿಕ್ತ)) {
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->user == ರಿಕ್ತ)
				match_test_missing_fatal("User", "user");
			ಯದಿ (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			ಅನ್ಯಥಾ
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, ಸಾಲು);
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "group") == 0) {
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->user == ರಿಕ್ತ)) {
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->user == ರಿಕ್ತ)
				match_test_missing_fatal("Group", "user");
			ವಿಕಲ್ಪ (match_cfg_ಸಾಲು_group(arg, ಸಾಲು, ci->user)) {
			ಪಕ್ಷ -1:
				result = -1;
				ಗಚ್ಛ out;
			ಪಕ್ಷ 0:
				result = 0;
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "host") == 0) {
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->host == ರಿಕ್ತ)) {
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->host == ರಿಕ್ತ)
				match_test_missing_fatal("Host", "host");
			ಯದಿ (match_hostname(ci->host, arg) != 1)
				result = 0;
			ಅನ್ಯಥಾ
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, ಸಾಲು);
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "address") == 0) {
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->address == ರಿಕ್ತ)) {
				ಯದಿ (addr_match_list(ರಿಕ್ತ, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, ಸಾಲು);
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->address == ರಿಕ್ತ)
				match_test_missing_fatal("Address", "addr");
			ವಿಕಲ್ಪ (addr_match_list(ci->address, arg)) {
			ಪಕ್ಷ 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, ಸಾಲು);
				ಭಙ್ಗ;
			ಪಕ್ಷ 0:
			ಪಕ್ಷ -1:
				result = 0;
				ಭಙ್ಗ;
			ಪಕ್ಷ -2:
				result = -1;
				ಗಚ್ಛ out;
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "localaddress") == 0){
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->laddress == ರಿಕ್ತ)) {
				ಯದಿ (addr_match_list(ರಿಕ್ತ, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    ಸಾಲು);
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->laddress == ರಿಕ್ತ)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			ವಿಕಲ್ಪ (addr_match_list(ci->laddress, arg)) {
			ಪಕ್ಷ 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, ಸಾಲು);
				ಭಙ್ಗ;
			ಪಕ್ಷ 0:
			ಪಕ್ಷ -1:
				result = 0;
				ಭಙ್ಗ;
			ಪಕ್ಷ -2:
				result = -1;
				ಗಚ್ಛ out;
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "localport") == 0) {
			ಯದಿ ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				ಗಚ್ಛ out;
			}
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->lport == -1)) {
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			ಯದಿ (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, ಸಾಲು);
			ಅನ್ಯಥಾ
				result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "rdomain") == 0) {
			ಯದಿ (ci == ರಿಕ್ತ || (ci->test && ci->rdomain == ರಿಕ್ತ)) {
				result = 0;
				ಗಚ್ಛ next;
			}
			ಯದಿ (ci->rdomain == ರಿಕ್ತ)
				match_test_missing_fatal("RDomain", "rdomain");
			ಯದಿ (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			ಅನ್ಯಥಾ
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, ಸಾಲು);
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "version") == 0) {
			ಯದಿ (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			ಅನ್ಯಥಾ
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, ಸಾಲು);
		} ಅನ್ಯಥಾ {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			ಗಚ್ಛ out;
		}
 next:
		ಮುಕ್ತ(attrib);
		attrib = ರಿಕ್ತ;
	}
	ಯದಿ (attributes == 0) {
		error("One or more attributes required for Match");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
 out:
	ಯದಿ (ci != ರಿಕ್ತ && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", ಸಾಲು);
	ಮುಕ್ತ(attrib);
	ಪ್ರತ್ಯಾಗಮ result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
ಸಂರಚನಾ multistate {
	ವರ್ಣ *ಕೀಲಿ;
	ಪೂರ್ಣಾಙ್ಕ ಮೌಲ್ಯ;
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ರಿಕ್ತ, -1 }
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_server_config_ಸಾಲು_depth(ServerOptions *options, ವರ್ಣ *ಸಾಲು,
    ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum, ಪೂರ್ಣಾಙ್ಕ *activep,
    ಸಂರಚನಾ connection_info *connectinfo, ಪೂರ್ಣಾಙ್ಕ *inc_flags, ಪೂರ್ಣಾಙ್ಕ depth,
    ಸಂರಚನಾ include_list *includes)
{
	ವರ್ಣ *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	ಪೂರ್ಣಾಙ್ಕ cmdline = 0, *intptr, ಮೌಲ್ಯ, value2, value3, n, port, oactive, r;
	ದ್ವಿಗುಣ dvalue, *doubleptr = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	ಧ್ರುವ ಸಂರಚನಾ multistate *multistate_ptr;
	ಧ್ರುವ ವರ್ಣ *errstr;
	ಸಂರಚನಾ include_item *item;
	glob_t gbuf;
	ವರ್ಣ **oav = ರಿಕ್ತ, **av;
	ಪೂರ್ಣಾಙ್ಕ oac = 0, ac;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	ವರ್ಣ **strs = ರಿಕ್ತ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ಯದಿ ((len = strlen(ಸಾಲು)) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (len--; len > 0; len--) {
		ಯದಿ (strchr(WHITESPACE "\f", ಸಾಲು[len]) == ರಿಕ್ತ)
			ಭಙ್ಗ;
		ಸಾಲು[len] = '\0';
	}

	str = ಸಾಲು;
	ಯದಿ ((keyword = strdelim(&str)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* Ignore leading whitespace */
	ಯದಿ (*keyword == '\0')
		keyword = strdelim(&str);
	ಯದಿ (!keyword || !*keyword || *keyword == '#')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (str == ರಿಕ್ತ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	intptr = ರಿಕ್ತ;
	charptr = ರಿಕ್ತ;
	opcode = parse_token(keyword, filename, linenum, &flags);

	ಯದಿ (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ac = oac;
	av = oav;

	ಯದಿ (activep == ರಿಕ್ತ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	ಯದಿ (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	ಯದಿ (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		ಯದಿ (connectinfo == ರಿಕ್ತ) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} ಅನ್ಯಥಾ { /* this is a directive we have already processed */
			ret = 0;
			ಗಚ್ಛ out;
		}
	}

	ವಿಕಲ್ಪ (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	ಪಕ್ಷ sUsePAM:
		intptr = &options->use_pam;
		ಗಚ್ಛ parse_flag;
	ಪಕ್ಷ sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;
#endif

	/* Standard Options */
	ಪಕ್ಷ sBadOption:
		ಗಚ್ಛ out;
	ಪಕ್ಷ sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		ಯದಿ (options->ports_from_cmdline) {
			argv_consume(&ac);
			ಭಙ್ಗ;
		}
		ಯದಿ (options->ಅಂಕೆ_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->ಅಂಕೆ_ports++] = a2port(arg);
		ಯದಿ (options->ports[options->ಅಂಕೆ_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		ಭಙ್ಗ;

	ಪಕ್ಷ sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		ಯದಿ ((ಮೌಲ್ಯ = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sListenAddress:
		arg = argv_next(&ac, &av);
		ಯದಿ (arg == ರಿಕ್ತ || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		ಯದಿ (strchr(arg, '[') == ರಿಕ್ತ && (p = strchr(arg, ':')) != ರಿಕ್ತ
		    && strchr(p+1, ':') != ರಿಕ್ತ) {
			port = 0;
			p = arg;
		} ಅನ್ಯಥಾ {
			arg2 = ರಿಕ್ತ;
			p = hpdelim(&arg);
			ಯದಿ (p == ರಿಕ್ತ)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			ಯದಿ (arg == ರಿಕ್ತ)
				port = 0;
			ಅನ್ಯಥಾ ಯದಿ ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ರಿಕ್ತ;
		ಯದಿ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == ರಿಕ್ತ)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			ಯದಿ (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		ಭಙ್ಗ;

	ಪಕ್ಷ sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ಮೌಲ್ಯ = -1;
		ಪ್ರತಿ (i = 0; multistate_ptr[i].ಕೀಲಿ != ರಿಕ್ತ; i++) {
			ಯದಿ (strcasecmp(arg, multistate_ptr[i].ಕೀಲಿ) == 0) {
				ಮೌಲ್ಯ = multistate_ptr[i].ಮೌಲ್ಯ;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (ಮೌಲ್ಯ == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ s_Host_ಕೀಲಿ:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ಯದಿ (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ s_Host_ಕೀಲಿ_Agent:
		charptr = &options->host_ಕೀಲಿ_agent;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sHostCertificate:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ಯದಿ (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			ಯದಿ (intptr != ರಿಕ್ತ)
				*intptr = *intptr + 1;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sModuliFile:
		charptr = &options->moduli_file;
		ಗಚ್ಛ parse_filename;

	ಪಕ್ಷ s_Permit_ಬೇರು_Login:
		intptr = &options->permit_ಬೇರು_login;
		multistate_ptr = multistate_permitrootlogin;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		ಯದಿ (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ s_Host_ಕೀಲಿ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		ಗಚ್ಛ parse_pubkey_algos;

	ಪಕ್ಷ sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ಗಚ್ಛ parse_pubkey_algos;

	ಪಕ್ಷ sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ಗಚ್ಛ parse_pubkey_algos;

	ಪಕ್ಷ sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		ಮೌಲ್ಯ = 0;
		value2 = -1;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (strcasecmp(arg, "none") == 0)
				ಅನುವರ್ತ;
			ಯದಿ (strcasecmp(arg, "touch-required") == 0)
				ಮೌಲ್ಯ |= PUBKEYAUTH_TOUCH_REQUIRED;
			ಅನ್ಯಥಾ ಯದಿ (strcasecmp(arg, "verify-required") == 0)
				ಮೌಲ್ಯ |= PUBKEYAUTH_VERIFY_REQUIRED;
			ಅನ್ಯಥಾ ಯದಿ (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				ಯದಿ (errstr != ರಿಕ್ತ) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					ಗಚ್ಛ out;
				}
			} ಅನ್ಯಥಾ {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				ಗಚ್ಛ out;
			}
		}
		ಯದಿ (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = ಮೌಲ್ಯ;
			options->max_pubkey_ok = value2;
		}
		ಭಙ್ಗ;

#ifdef KRB5
	ಪಕ್ಷ sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		ಗಚ್ಛ parse_flag;
#ifdef USE_AFS
	ಪಕ್ಷ sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		ಗಚ್ಛ parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	ಪಕ್ಷ sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		ಗಚ್ಛ parse_flag;
#endif /* GSSAPI */

	ಪಕ್ಷ sPasswordAuthentication:
		intptr = &options->password_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sPrintMotd:
		intptr = &options->print_motd;
		ಗಚ್ಛ parse_flag;

#ifndef DISABLE_LASTLOG
	ಪಕ್ಷ sPrintLastLog:
		intptr = &options->print_lastlog;
		ಗಚ್ಛ parse_flag;
#endif

	ಪಕ್ಷ sX11Forwarding:
		intptr = &options->x11_forwarding;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		ಯದಿ ((errstr = atoi_err(arg, &ಮೌಲ್ಯ)) != ರಿಕ್ತ)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sXAuthLocation:
		charptr = &options->xauth_location;
		ಗಚ್ಛ parse_filename;

	ಪಕ್ಷ sPermitTTY:
		intptr = &options->permit_tty;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sPermitUserRC:
		intptr = &options->permit_user_rc;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sStrictModes:
		intptr = &options->strict_modes;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಮೌಲ್ಯ = 0;
		p = ರಿಕ್ತ;
		ಯದಿ (strcmp(arg, "yes") == 0)
			ಮೌಲ್ಯ = 1;
		ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "no") == 0)
			ಮೌಲ್ಯ = 0;
		ಅನ್ಯಥಾ {
			/* Pattern-list specified */
			ಮೌಲ್ಯ = 1;
			p = xstrdup(arg);
		}
		ಯದಿ (*activep && *intptr == -1) {
			*intptr = ಮೌಲ್ಯ;
			*charptr = p;
			p = ರಿಕ್ತ;
		}
		ಮುಕ್ತ(p);
		ಭಙ್ಗ;

	ಪಕ್ಷ sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sRekeyLimit:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ಅನ್ಯಥಾ {
			ಯದಿ (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			ಯದಿ (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		ಯದಿ (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		ಯದಿ (ac != 0) { /* optional rekey interval present */
			ಯದಿ (strcmp(av[0], "none") == 0) {
				(ಶೂನ್ಯ)argv_next(&ac, &av);	/* discard */
				ಭಙ್ಗ;
			}
			intptr = &options->rekey_interval;
			ಗಚ್ಛ parse_time;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sUseDNS:
		intptr = &options->use_dns;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		ಮೌಲ್ಯ = log_facility_ಸಂಖ್ಯೆ(arg);
		ಯದಿ (ಮೌಲ್ಯ == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ಯದಿ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		ಮೌಲ್ಯ = log_level_ಸಂಖ್ಯೆ(arg);
		ಯದಿ (ಮೌಲ್ಯ == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ಯದಿ (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sLogVerbose:
		found = options->ಅಂಕೆ_log_verbose == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->log_verbose = strs;
			options->ಅಂಕೆ_log_verbose = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		ಯದಿ (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			ಯದಿ (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} ಅನ್ಯಥಾ ಯದಿ (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			ಯದಿ (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sDisableForwarding:
		intptr = &options->disable_forwarding;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->ಅಂಕೆ_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0' ||
			    match_user(ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			ಯದಿ (!*activep)
				ಅನುವರ್ತ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ಯದಿ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->ಅಂಕೆ_deny_users;
		ಗಚ್ಛ parse_allowdenyusers;

	ಪಕ್ಷ sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->ಅಂಕೆ_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			ಯದಿ (!*activep)
				ಅನುವರ್ತ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ಯದಿ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->ಅಂಕೆ_deny_groups;
		ಗಚ್ಛ parse_allowdenygroups;

	ಪಕ್ಷ sCiphers:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಯದಿ (options->ciphers == ರಿಕ್ತ)
			options->ciphers = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sMacs:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಯದಿ (options->macs == ರಿಕ್ತ)
			options->macs = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sKexAlgorithms:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ಯದಿ (options->kex_algorithms == ರಿಕ್ತ)
			options->kex_algorithms = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sSubsystem:
		ಯದಿ ((arg = argv_next(&ac, &av)) == ರಿಕ್ತ || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == ರಿಕ್ತ || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (!*activep) {
			argv_consume(&ac);
			ಭಙ್ಗ;
		}
		found = 0;
		ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_subsystems; i++) {
			ಯದಿ (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			ಭಙ್ಗ;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->ಅಂಕೆ_subsystems,
		    options->ಅಂಕೆ_subsystems + 1,
		    ಪರಿಮಾಣ(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->ಅಂಕೆ_subsystems,
		    options->ಅಂಕೆ_subsystems + 1,
		    ಪರಿಮಾಣ(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->ಅಂಕೆ_subsystems,
		    options->ಅಂಕೆ_subsystems + 1,
		    ಪರಿಮಾಣ(*options->subsystem_args));
		options->subsystem_name[options->ಅಂಕೆ_subsystems] = xstrdup(arg);
		options->subsystem_command[options->ಅಂಕೆ_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->ಅಂಕೆ_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		ಮುಕ್ತ(arg2);
		ಮುಕ್ತ(arg);
		argv_consume(&ac);
		options->ಅಂಕೆ_subsystems++;
		ಭಙ್ಗ;

	ಪಕ್ಷ sMaxStartups:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		ಯದಿ ((n = sscanf(arg, "%d:%d:%d",
		    &ಮೌಲ್ಯ, &value2, &value3)) == 3) {
			ಯದಿ (ಮೌಲ್ಯ > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} ಅನ್ಯಥಾ ಯದಿ (n == 1) {
			value3 = ಮೌಲ್ಯ;
			value2 = -1;
		} ಅನ್ಯಥಾ {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		ಯದಿ (ಮೌಲ್ಯ <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ಯದಿ (*activep && options->max_startups == -1) {
			options->max_startups_begin = ಮೌಲ್ಯ;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ವಿಕಲ್ಪ (n = sscanf(arg, "%d:%d", &ಮೌಲ್ಯ, &value2)) {
		ಪಕ್ಷ 2:
			ಯದಿ (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		ಪಕ್ಷ 1:
			ಯದಿ (ಮೌಲ್ಯ < 0 || ಮೌಲ್ಯ > 32)
				n = -1;
		}
		ಯದಿ (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ಯದಿ (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = ಮೌಲ್ಯ;
			ಯದಿ (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (strcmp(arg, "none") == 0) { /* no limit */
			ಮೌಲ್ಯ = INT_MAX;
		} ಅನ್ಯಥಾ {
			ಯದಿ ((errstr = atoi_err(arg, &ಮೌಲ್ಯ)) != ರಿಕ್ತ)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		ಯದಿ (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ಯದಿ (addr_match_list(ರಿಕ್ತ, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sPerSourcePenalties:
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಧ್ರುವ ವರ್ಣ *q = ರಿಕ್ತ;

			found = 1;
			intptr = ರಿಕ್ತ;
			doubleptr = ರಿಕ್ತ;
			ಮೌಲ್ಯ = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			ಯದಿ (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				ಯದಿ (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				ಯದಿ (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				ಅನುವರ್ತ;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "crash:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "authfail:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "invaliduser:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "noauth:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "grace-exceeded:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "refuseconnection:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "max:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "min:", 0)) != ರಿಕ್ತ) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "max-sources4:", 0)) != ರಿಕ್ತ) {
				intptr = &options->per_source_penalty.max_sources4;
				ಯದಿ ((errstr = atoi_err(q, &ಮೌಲ್ಯ)) != ರಿಕ್ತ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ಅನ್ಯಥಾ ಯದಿ ((q = strprefix(arg, "max-sources6:", 0)) != ರಿಕ್ತ) {
				intptr = &options->per_source_penalty.max_sources6;
				ಯದಿ ((errstr = atoi_err(q, &ಮೌಲ್ಯ)) != ರಿಕ್ತ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				ಮೌಲ್ಯ = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				ಮೌಲ್ಯ = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				ಮೌಲ್ಯ = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				ಮೌಲ್ಯ = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} ಅನ್ಯಥಾ {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			ಯದಿ (doubleptr != ರಿಕ್ತ) {
				ಯದಿ ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				ಯದಿ (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} ಅನ್ಯಥಾ ಯದಿ (intptr != ರಿಕ್ತ) {
				ಯದಿ (*activep && *intptr == -1) {
					*intptr = ಮೌಲ್ಯ;
					options->per_source_penalty.enabled = 1;
				}
			} ಅನ್ಯಥಾ {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		ಯದಿ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sMaxAuthTries:
		intptr = &options->max_authtries;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ sMaxSessions:
		intptr = &options->max_sessions;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ sBanner:
		charptr = &options->banner;
		ಗಚ್ಛ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	ಪಕ್ಷ s_Authorized_ಕೀಲಿಗಳು_File:
		uintptr = &options->ಅಂಕೆ_authkeys_files;
		chararrayptr = &options->authorized_ಕೀಲಿಗಳು_files;
 parse_filenames:
		found = *uintptr == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ಮುಕ್ತ(arg2);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			ಯದಿ (intptr != ರಿಕ್ತ)
				*intptr = *intptr + 1;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sClientAliveInterval:
		intptr = &options->client_alive_interval;
		ಗಚ್ಛ parse_time;

	ಪಕ್ಷ s_Client_Alive_ಎಣಿಕೆ_Max:
		intptr = &options->client_alive_ಎಣಿಕೆ_max;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0' || strchr(arg, '=') != ರಿಕ್ತ)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			ಯದಿ (!*activep)
				ಅನುವರ್ತ;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->ಅಂಕೆ_accept_env,
			    arg);
		}
		ಯದಿ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sSetEnv:
		found = options->ಅಂಕೆ_setenv == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0' || strchr(arg, '=') == ರಿಕ್ತ)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			ಯದಿ (lookup_setenv_in_list(arg, strs, nstrs) != ರಿಕ್ತ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ಅನುವರ್ತ;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->setenv = strs;
			options->ಅಂಕೆ_setenv = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಮೌಲ್ಯ = -1;
		ಪ್ರತಿ (i = 0; tunmode_desc[i].val != -1; i++)
			ಯದಿ (strcmp(tunmode_desc[i].text, arg) == 0) {
				ಮೌಲ್ಯ = tunmode_desc[i].val;
				ಭಙ್ಗ;
			}
		ಯದಿ (ಮೌಲ್ಯ == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sInclude:
		ಯದಿ (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		ಮೌಲ್ಯ = 0;
		ಯಾವತ್ ((arg2 = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			ಮೌಲ್ಯ++;
			found = 0;
			ಯದಿ (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} ಅನ್ಯಥಾ
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				ಯದಿ (strcmp(item->selector, arg) != 0)
					ಅನುವರ್ತ;
				ಯದಿ (item->filename != ರಿಕ್ತ) {
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
			ಯದಿ (found != 0) {
				ಮುಕ್ತ(arg);
				ಅನುವರ್ತ;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			ಯದಿ ((r = glob(arg, 0, ರಿಕ್ತ, &gbuf)) != 0) {
				ಯದಿ (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, ಪರಿಮಾಣ(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			ಯದಿ (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			ಪ್ರತಿ (n = 0; n < (ಪೂರ್ಣಾಙ್ಕ)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, ಪರಿಮಾಣ(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				ಯದಿ ((item->contents = sshbuf_new()) == ರಿಕ್ತ)
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
			ಮುಕ್ತ(arg);
		}
		ಯದಿ (ಮೌಲ್ಯ == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sMatch:
		ಯದಿ (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		ಮೌಲ್ಯ = match_cfg_ಸಾಲು(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ರಿಕ್ತ : connectinfo));
		ಯದಿ (ಮೌಲ್ಯ < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : ಮೌಲ್ಯ;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		ಭಙ್ಗ;

	ಪಕ್ಷ sPermitListen:
	ಪಕ್ಷ sPermitOpen:
		ಯದಿ (opcode == sPermitListen) {
			uintptr = &options->ಅಂಕೆ_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} ಅನ್ಯಥಾ {
			uintptr = &options->ಅಂಕೆ_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				ಯದಿ (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				ಅನುವರ್ತ;
			}

			ಯದಿ (opcode == sPermitListen &&
			    strchr(arg, ':') == ರಿಕ್ತ) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} ಅನ್ಯಥಾ {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				ಯದಿ (p == ರಿಕ್ತ) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			ಯದಿ (arg == ರಿಕ್ತ ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ಮುಕ್ತ(arg2);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sForceCommand:
		ಯದಿ (str == ರಿಕ್ತ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ಯದಿ (*activep && options->adm_forced_command == ರಿಕ್ತ)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_ಕೀಲಿಗಳು;
		ಗಚ್ಛ parse_filename;

	ಪಕ್ಷ s_Revoked_ಕೀಲಿಗಳು:
		uintptr = &options->ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files;
		chararrayptr = &options->revoked_ಕೀಲಿಗಳು_files;
		ಗಚ್ಛ parse_filenames;

	ಪಕ್ಷ s_Security_ಕೀಲಿ_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			ಯದಿ (intptr != ರಿಕ್ತ)
				*intptr = *intptr + 1;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sIPQoS:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ ((ಮೌಲ್ಯ = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ಯದಿ (ಮೌಲ್ಯ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ಮೌಲ್ಯ = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		ಯದಿ (arg == ರಿಕ್ತ)
			value2 = ಮೌಲ್ಯ;
		ಅನ್ಯಥಾ ಯದಿ ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ಯದಿ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		ಯದಿ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ಮೌಲ್ಯ;
			options->ip_qos_bulk = value2;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sVersionAddendum:
		ಯದಿ (str == ರಿಕ್ತ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ಯದಿ (strchr(str + len, '\r') != ರಿಕ್ತ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ಯದಿ ((arg = strchr(ಸಾಲು, '#')) != ರಿಕ್ತ) {
			*arg = '\0';
			rtrim(ಸಾಲು);
		}
		ಯದಿ (*activep && options->version_addendum == ರಿಕ್ತ) {
			ಯದಿ (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			ಅನ್ಯಥಾ
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ s_Authorized_ಕೀಲಿಗಳು_Command:
		charptr = &options->authorized_ಕೀಲಿಗಳು_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		ಯದಿ (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ s_Authorized_ಕೀಲಿಗಳು_Command_User:
		charptr = &options->authorized_ಕೀಲಿಗಳು_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		ಗಚ್ಛ parse_command;

	ಪಕ್ಷ sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		ಗಚ್ಛ parse_localuser;

	ಪಕ್ಷ sAuthenticationMethods:
		found = options->ಅಂಕೆ_auth_methods == 0;
		ಮೌಲ್ಯ = 0; /* seen "any" pseudo-method */
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (strcmp(arg, "any") == 0) {
				ಯದಿ (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				ಮೌಲ್ಯ = 1;
			} ಅನ್ಯಥಾ ಯದಿ (ಮೌಲ್ಯ) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} ಅನ್ಯಥಾ ಯದಿ (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->auth_methods = strs;
			options->ಅಂಕೆ_auth_methods = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		ಮೌಲ್ಯ = strtol(arg, &p, 8);
		ಯದಿ (arg == p || ಮೌಲ್ಯ < 0 || ಮೌಲ್ಯ > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		ಯದಿ (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sFingerprintHash:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ ((ಮೌಲ್ಯ = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		ಯದಿ (*activep)
			options->fingerprint_hash = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ sRDomain:
#ಯದಿ !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ಯದಿ (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ sRequiredRSASize:
		intptr = &options->required_rsa_size;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ sChannelTimeout:
		found = options->ಅಂಕೆ_channel_timeouts == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			} ಅನ್ಯಥಾ ಯದಿ (parse_pattern_interval(arg,
			    ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->channel_timeouts = strs;
			options->ಅಂಕೆ_channel_timeouts = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		ಯದಿ (av[0] != ರಿಕ್ತ && strcasecmp(av[0], "none") == 0) {
			(ಶೂನ್ಯ)argv_next(&ac, &av); /* consume arg */
			ಯದಿ (*activep)
				*intptr = 0;
			ಭಙ್ಗ;
		}
		ಗಚ್ಛ parse_time;

	ಪಕ್ಷ sSshdSessionPath:
		charptr = &options->sshd_session_path;
		ಗಚ್ಛ parse_filename;

	ಪಕ್ಷ sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		ಗಚ್ಛ parse_filename;

	ಪಕ್ಷ sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ sDeprecated:
	ಪಕ್ಷ sIgnore:
	ಪಕ್ಷ sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಸ್ವಭಾವ:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	ಯದಿ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ಗಚ್ಛ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, ರಿಕ್ತ, nstrs);
	argv_free(oav, oac);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
process_server_config_ಸಾಲು(ServerOptions *options, ವರ್ಣ *ಸಾಲು,
    ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum, ಪೂರ್ಣಾಙ್ಕ *activep,
    ಸಂರಚನಾ connection_info *connectinfo, ಸಂರಚನಾ include_list *includes)
{
	ಪೂರ್ಣಾಙ್ಕ inc_flags = 0;

	ಪ್ರತ್ಯಾಗಮ process_server_config_ಸಾಲು_depth(options, ಸಾಲು, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

ಶೂನ್ಯ
load_server_config(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ sshbuf *conf)
{
	ಸಂರಚನಾ stat st;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ, *cp;
	size_t linesize = 0;
	FILE *f;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2_f("filename %s", filename);
	ಯದಿ ((f = fopen(filename, "r")) == ರಿಕ್ತ) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	ಯದಿ (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = ಸಾಲು + strspn(ಸಾಲು, " \t\r");
		ಯದಿ ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	ಮುಕ್ತ(ಸಾಲು);
	ಯದಿ ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

ಶೂನ್ಯ
parse_server_match_config(ServerOptions *options,
   ಸಂರಚನಾ include_list *includes, ಸಂರಚನಾ connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

ಪೂರ್ಣಾಙ್ಕ
parse_server_match_testspec(ಸಂರಚನಾ connection_info *ci, ವರ್ಣ *spec)
{
	ವರ್ಣ *p;
	ಧ್ರುವ ವರ್ಣ *val;

	ಯಾವತ್ ((p = strsep(&spec, ",")) && *p != '\0') {
		ಯದಿ ((val = strprefix(p, "addr=", 0)) != ರಿಕ್ತ) {
			ci->address = xstrdup(val);
		} ಅನ್ಯಥಾ ಯದಿ ((val = strprefix(p, "host=", 0)) != ರಿಕ್ತ) {
			ci->host = xstrdup(val);
		} ಅನ್ಯಥಾ ಯದಿ ((val = strprefix(p, "user=", 0)) != ರಿಕ್ತ) {
			ci->user = xstrdup(val);
		} ಅನ್ಯಥಾ ಯದಿ ((val = strprefix(p, "laddr=", 0)) != ರಿಕ್ತ) {
			ci->laddress = xstrdup(val);
		} ಅನ್ಯಥಾ ಯದಿ ((val = strprefix(p, "rdomain=", 0)) != ರಿಕ್ತ) {
			ci->rdomain = xstrdup(val);
		} ಅನ್ಯಥಾ ಯದಿ ((val = strprefix(p, "lport=", 0)) != ರಿಕ್ತ) {
			ci->lport = a2port(val);
			ಯದಿ (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} ಅನ್ಯಥಾ {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	ಪ್ರತಿ (i = 0; i < src->ಅಂಕೆ_subsystems; i++) {
		found = 0;
		ಪ್ರತಿ (j = 0; j < dst->ಅಂಕೆ_subsystems; j++) {
			ಯದಿ (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			ಮುಕ್ತ(dst->subsystem_command[j]);
			ಮುಕ್ತ(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			ಅನುವರ್ತ;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->ಅಂಕೆ_subsystems,
		    dst->ಅಂಕೆ_subsystems + 1, ಪರಿಮಾಣ(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->ಅಂಕೆ_subsystems,
		    dst->ಅಂಕೆ_subsystems + 1, ಪರಿಮಾಣ(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->ಅಂಕೆ_subsystems,
		    dst->ಅಂಕೆ_subsystems + 1, ಪರಿಮಾಣ(*dst->subsystem_args));
		j = dst->ಅಂಕೆ_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_s32(ಸಂರಚನಾ sshbuf *buf, ಪೂರ್ಣಾಙ್ಕ v)
{
	uint32_t uv;
	ಪೂರ್ಣಾಙ್ಕ r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	ಯದಿ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_s64(ಸಂರಚನಾ sshbuf *buf, int64_t v)
{
	uint64_t uv;
	ಪೂರ್ಣಾಙ್ಕ r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	ಯದಿ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_mode(ಸಂರಚನಾ sshbuf *buf, mode_t v)
{
	u_int uv;

	ಯದಿ (v == (mode_t)-1)
		ಪ್ರತ್ಯಾಗಮ serialise_s32(buf, -1);
	uv = (u_int)v;
	ಯದಿ ((mode_t)uv != v || uv > 0777)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ serialise_s32(buf, (ಪೂರ್ಣಾಙ್ಕ)uv);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_double(ಸಂರಚನಾ sshbuf *buf, ದ್ವಿಗುಣ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	ಪ್ರತ್ಯಾಗಮ sshbuf_put(buf, &v, ಪರಿಮಾಣ(v));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_nullable_string(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *s)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u8(buf, s != ರಿಕ್ತ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ sshbuf_put_cstring(buf, s);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_nullable_string_array(ಸಂರಚನಾ sshbuf *buf, ವರ್ಣ **a, u_int n)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಯದಿ ((r = sshbuf_put_u32(buf, n)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = serialise_nullable_string(buf, a[i])) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_hostkeyfile(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಯದಿ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_host_ಕೀಲಿ_files)) != 0) {
		error_fr(r, "serialise length");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_host_ಕೀಲಿ_files; i++) {
		ಯದಿ ((r = serialise_s32(buf,
		    options->host_ಕೀಲಿ_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_ಕೀಲಿ_files[i])) != 0) {
			error_fr(r, "serialise member");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_ipqos(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_listenaddress(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	ಯದಿ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_queued_listens; i++) {
		ಧ್ರುವ ಸಂರಚನಾ queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		ಯದಿ ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_logfacility(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, (ಪೂರ್ಣಾಙ್ಕ)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_loglevel(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, (ಪೂರ್ಣಾಙ್ಕ)options->log_level)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_port(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಯದಿ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_ports)) != 0) {
		error_fr(r, "serialise length");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_ports; i++) {
		ಯದಿ ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_gatewayports(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_streamlocalbindmask(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_streamlocalbindunlink(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_maxstartups(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_permituserenv(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_persourcenetblocksize(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_persourcepenalties(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಧ್ರುವ ಸಂರಚನಾ per_source_penalty *psp = &options->per_source_penalty;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_rekeylimit(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_subsystem(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i;

	ಯದಿ ((r = sshbuf_put_u32(buf, options->ಅಂಕೆ_subsystems)) != 0) {
		error_fr(r, "serialise length");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_subsystems; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_pubkey_auth_options(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serialise_timingsecret(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}


ಪೂರ್ಣಾಙ್ಕ
serialise_server_options(ಧ್ರುವ ServerOptions *options, ಸಂರಚನಾ sshbuf **bufp)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	*bufp = ರಿಕ್ತ;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		ಗಚ್ಛ out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ಯದಿ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ಯದಿ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	ಯದಿ ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ಯದಿ ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ಯದಿ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ಗಚ್ಛ out;
#define SSHCONF_NONCONF(funcsuffix) \
	ಯದಿ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ಗಚ್ಛ out;
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
	buf = ರಿಕ್ತ; /* transferred */
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_s32(ಸಂರಚನಾ sshbuf *buf, ಪೂರ್ಣಾಙ್ಕ *v)
{
	uint32_t tmp;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char was_signed;

	ಯದಿ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (was_signed > 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (was_signed) {
		ಯದಿ (tmp > (uint32_t)INT_MAX + 1)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(ಪೂರ್ಣಾಙ್ಕ)tmp;
	} ಅನ್ಯಥಾ {
		ಯದಿ (tmp > INT_MAX)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		*v = (ಪೂರ್ಣಾಙ್ಕ)tmp;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_s64(ಸಂರಚನಾ sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char was_signed;

	ಯದಿ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (was_signed > 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (was_signed) {
		ಯದಿ (tmp > (uint64_t)INT64_MAX + 1)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} ಅನ್ಯಥಾ {
		ಯದಿ (tmp > INT64_MAX)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_mode(ಸಂರಚನಾ sshbuf *buf, mode_t *v)
{
	ಪೂರ್ಣಾಙ್ಕ r, tmp;

	ಯದಿ ((r = deserialise_s32(buf, &tmp)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (tmp == -1) {
		*v = (mode_t)-1;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (tmp < 0 || tmp > 0777)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_double(ಸಂರಚನಾ sshbuf *buf, ದ್ವಿಗುಣ *v)
{
	ಪ್ರತ್ಯಾಗಮ sshbuf_get(buf, v, ಪರಿಮಾಣ(*v));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_nullable_string(ಸಂರಚನಾ sshbuf *buf, ವರ್ಣ **sp)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char present;

	ಯದಿ ((r = sshbuf_get_u8(buf, &present)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (present == 0) {
		*sp = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (present != 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ sshbuf_get_cstring(buf, sp, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_string_array(ವರ್ಣ **a, u_int n)
{
	u_int i;

	ಯದಿ (a == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < n; i++)
		ಮುಕ್ತ(a[i]);
	ಮುಕ್ತ(a);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_ಎಣಿಕೆ(ಸಂರಚನಾ sshbuf *buf, u_int *np, ಧ್ರುವ ವರ್ಣ *what)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	uint32_t n;

	ಯದಿ ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (n > UINT_MAX) {
		error_f("bad number of %s", what);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಯದಿ (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_nullable_string_array(ಸಂರಚನಾ sshbuf *buf, ವರ್ಣ ***arrayp,
    u_int *np)
{
	ವರ್ಣ **a = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i, n;

	*arrayp = ರಿಕ್ತ;
	*np = 0;
	ಯದಿ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "strings")) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (n > 0)
		a = xcalloc(n, ಪರಿಮಾಣ(*a));
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	*arrayp = a;
	*np = n;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_queued_listen_addrs(ಸಂರಚನಾ queued_listenaddr *qla, u_int n)
{
	u_int i;

	ಯದಿ (qla == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಮುಕ್ತ(qla[i].addr);
		ಮುಕ್ತ(qla[i].rdomain);
	}
	ಮುಕ್ತ(qla);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_hostkeyfile(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r, *userprovided = ರಿಕ್ತ;
	u_int i, n;
	ವರ್ಣ **files = ರಿಕ್ತ;

	ಯದಿ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "host key files")) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (n > 0) {
		userprovided = xcalloc(n, ಪರಿಮಾಣ(*userprovided));
		files = xcalloc(n, ಪರಿಮಾಣ(*files));
	}
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			ಮುಕ್ತ(userprovided);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	options->ಅಂಕೆ_host_ಕೀಲಿ_files = n;
	options->host_ಕೀಲಿ_file_userprovided = userprovided;
	options->host_ಕೀಲಿ_files = files;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_ipqos(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_listenaddress(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i, n;
	ಸಂರಚನಾ queued_listenaddr *qla = ರಿಕ್ತ;

	ಯದಿ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "listen addresses")) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (n > 0)
		qla = xcalloc(n, ಪರಿಮಾಣ(*qla));
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = sshbuf_get_cstring(buf, &qla[i].addr, ರಿಕ್ತ)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	options->ಅಂಕೆ_queued_listens = n;
	options->queued_listen_addrs = qla;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_logfacility(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r, tmp;

	ಯದಿ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == ರಿಕ್ತ) {
		error_f("bad syslog facility");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_loglevel(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r, tmp;

	ಯದಿ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == ರಿಕ್ತ) {
		error_f("bad log level");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_port(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i, n;

	ಯದಿ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "ports")) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (n > MAX_PORTS) {
		error_f("bad number of ports");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	options->ಅಂಕೆ_ports = n;
	memset(options->ports, 0, ಪರಿಮಾಣ(options->ports));
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_ports; i++) {
		ಯದಿ ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_gatewayports(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_streamlocalbindmask(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_streamlocalbindunlink(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char tmp;

	ಯದಿ ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (tmp > 1) {
		error_f("bad boolean");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_maxstartups(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_permituserenv(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_persourcenetblocksize(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_persourcepenalties(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಸಂರಚನಾ per_source_penalty *psp = &options->per_source_penalty;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_rekeylimit(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_subsystem(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int i, n;
	ವರ್ಣ **names = ರಿಕ್ತ, **commands = ರಿಕ್ತ, **args = ರಿಕ್ತ;

	ಯದಿ ((r = deserialise_ಎಣಿಕೆ(buf, &n, "subsystems")) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (n > 0) {
		names = xcalloc(n, ಪರಿಮಾಣ(*names));
		commands = xcalloc(n, ಪರಿಮಾಣ(*names));
		args = xcalloc(n, ಪರಿಮಾಣ(*args));
	}
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ ((r = sshbuf_get_cstring(buf, names + i, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, ರಿಕ್ತ)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	options->ಅಂಕೆ_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_pubkey_auth_options(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
deserialise_timingsecret(ServerOptions *options, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
deserialise_server_options(ಸಂರಚನಾ sshbuf *buf, ServerOptions *options)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	ಯದಿ ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		ಗಚ್ಛ out;
	}
	ಯದಿ (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ಯದಿ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ಯದಿ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	ಯದಿ ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ಯದಿ ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ಗಚ್ಛ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ಯದಿ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ಗಚ್ಛ out;
#define SSHCONF_NONCONF(funcsuffix) \
	ಯದಿ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ಗಚ್ಛ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಕುರು { \
		ಮುಕ್ತ(new_options.var); \
		new_options.var = ರಿಕ್ತ; \
	} ಯಾವತ್ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	ಯದಿ (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
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
	memset(&new_options, 0, ಪರಿಮಾಣ(new_options));
 out:
	free_server_options(&new_options);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_host_ಕೀಲಿ_files; i++)
		ಮುಕ್ತ(options->host_ಕೀಲಿ_files[i]);
	ಮುಕ್ತ(options->host_ಕೀಲಿ_files);
	ಮುಕ್ತ(options->host_ಕೀಲಿ_file_userprovided);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->ಅಂಕೆ_queued_listens);

	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_listen_addrs; i++) {
		ಮುಕ್ತ(options->listen_addrs[i].rdomain);
		ಯದಿ (options->listen_addrs[i].addrs != ರಿಕ್ತ)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	ಮುಕ್ತ(options->listen_addrs);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_permituserenv(ServerOptions *options)
{
	ಮುಕ್ತ(options->permit_user_env_allowlist);
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_subsystem(ServerOptions *options)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_subsystems; i++) {
		ಮುಕ್ತ(options->subsystem_name[i]);
		ಮುಕ್ತ(options->subsystem_command[i]);
		ಮುಕ್ತ(options->subsystem_args[i]);
	}
	ಮುಕ್ತ(options->subsystem_name);
	ಮುಕ್ತ(options->subsystem_command);
	ಮುಕ್ತ(options->subsystem_args);
}

ಶೂನ್ಯ
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		ಮುಕ್ತ(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ಕುರು { \
		ಮುಕ್ತ(options->var); \
		options->var = ರಿಕ್ತ; \
	} ಯಾವತ್ (0);
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

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_int(ಪೂರ್ಣಾಙ್ಕ *dst, ಪೂರ್ಣಾಙ್ಕ src)
{
	ಯದಿ (src != -1)
		*dst = src;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_int64(int64_t *dst, int64_t src)
{
	ಯದಿ (src != -1)
		*dst = src;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_string(ವರ್ಣ **dst, ಧ್ರುವ ವರ್ಣ *src)
{
	ಯದಿ (src != ರಿಕ್ತ && *dst != src) {
		ಮುಕ್ತ(*dst);
		*dst = xstrdup(src);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_strarray_ಮೌಲ್ಯಗಳು(ವರ್ಣ ***dst, u_int ndst,
    ವರ್ಣ * ಧ್ರುವ *src, u_int nsrc)
{
	u_int i;

	ಯದಿ (nsrc == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < ndst; i++)
		ಮುಕ್ತ((*dst)[i]);
	ಮುಕ್ತ(*dst);
	*dst = xcalloc(nsrc, ಪರಿಮಾಣ(**dst));
	ಪ್ರತಿ (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ರಿಕ್ತ ? ರಿಕ್ತ : xstrdup(src[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_server_option_strarray(ವರ್ಣ ***dst, u_int *ndst,
    ವರ್ಣ * ಧ್ರುವ *src, u_int nsrc)
{
	ಯದಿ (nsrc == 0)
		ಪ್ರತ್ಯಾಗಮ;
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_ipqos(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_gatewayports(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_streamlocalbindunlink(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_loglevel(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	ಯದಿ (src->log_level != -1)
		dst->log_level = src->log_level;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_rekeylimit(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_subsystem(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	u_int old_ಅಂಕೆ_subsystems = dst->ಅಂಕೆ_subsystems;

	ಯದಿ (src->ಅಂಕೆ_subsystems == 0)
		ಪ್ರತ್ಯಾಗಮ;
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(&dst->subsystem_name,
	    old_ಅಂಕೆ_subsystems, src->subsystem_name, src->ಅಂಕೆ_subsystems);
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(&dst->subsystem_command,
	    old_ಅಂಕೆ_subsystems, src->subsystem_command, src->ಅಂಕೆ_subsystems);
	copy_server_option_strarray_ಮೌಲ್ಯಗಳು(&dst->subsystem_args,
	    old_ಅಂಕೆ_subsystems, src->subsystem_args, src->ಅಂಕೆ_subsystems);
	dst->ಅಂಕೆ_subsystems = src->ಅಂಕೆ_subsystems;
}

ಸ್ಥಿರ ಶೂನ್ಯ
copy_pubkey_auth_options(ServerOptions *dst, ಧ್ರುವ ServerOptions *src)
{
	ಯದಿ (src->pubkey_auth_options != -1) {
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
ಶೂನ್ಯ
copy_set_server_options(ServerOptions *dst, ServerOptions *src, ಪೂರ್ಣಾಙ್ಕ preauth)
{
	ಯದಿ (dst == src)
		ಪ್ರತ್ಯಾಗಮ;

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
	ಕುರು { \
		ಮುಕ್ತ(dst->var); \
		dst->var = ರಿಕ್ತ; \
	} ಯಾವತ್ (0);
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
	ಯದಿ (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	ಕುರು { \
		ಯದಿ (option_clear_or_none(v)) { \
			ಮುಕ್ತ(v); \
			v = ರಿಕ್ತ; \
		} \
	} ಯಾವತ್(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_ಕೀಲಿಗಳು);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	ಯದಿ (preauth)
		ಪ್ರತ್ಯಾಗಮ;

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
ಸ್ಥಿರ ಶೂನ್ಯ
parse_server_config_depth(ServerOptions *options, ಧ್ರುವ ವರ್ಣ *filename,
    ಸಂರಚನಾ sshbuf *conf, ಸಂರಚನಾ include_list *includes,
    ಸಂರಚನಾ connection_info *connectinfo, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ depth)
{
	ಪೂರ್ಣಾಙ್ಕ linenum, bad_options = 0;
	ವರ್ಣ *cp, *obuf, *cbuf;

	ಯದಿ (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	ಯದಿ ((obuf = cbuf = sshbuf_dup_string(conf)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	ಯಾವತ್ ((cp = strsep(&cbuf, "\n")) != ರಿಕ್ತ) {
		ಯದಿ (process_server_config_ಸಾಲು_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	ಮುಕ್ತ(obuf);
	ಯದಿ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

ಶೂನ್ಯ
parse_server_config(ServerOptions *options, ಧ್ರುವ ವರ್ಣ *filename,
    ಸಂರಚನಾ sshbuf *conf, ಸಂರಚನಾ include_list *includes,
    ಸಂರಚನಾ connection_info *connectinfo, ಪೂರ್ಣಾಙ್ಕ reexec)
{
	ಪೂರ್ಣಾಙ್ಕ active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	ಯದಿ (!reexec)
		process_queued_listen_addrs(options);
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
fmt_multistate_int(ಪೂರ್ಣಾಙ್ಕ val, ಧ್ರುವ ಸಂರಚನಾ multistate *m)
{
	u_int i;

	ಪ್ರತಿ (i = 0; m[i].ಕೀಲಿ != ರಿಕ್ತ; i++) {
		ಯದಿ (m[i].ಮೌಲ್ಯ == val)
			ಪ್ರತ್ಯಾಗಮ m[i].ಕೀಲಿ;
	}
	ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
fmt_intarg(ServerOpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	ಯದಿ (val == -1)
		ಪ್ರತ್ಯಾಗಮ "unset";
	ವಿಕಲ್ಪ (code) {
	ಪಕ್ಷ sAddressFamily:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_addressfamily);
	ಪಕ್ಷ s_Permit_ಬೇರು_Login:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_permitrootlogin);
	ಪಕ್ಷ sGatewayPorts:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_gatewayports);
	ಪಕ್ಷ sCompression:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_compression);
	ಪಕ್ಷ sAllowTcpForwarding:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_tcpfwd);
	ಪಕ್ಷ sAllowStreamLocalForwarding:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_tcpfwd);
	ಪಕ್ಷ sIgnoreRhosts:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_ignore_rhosts);
	ಪಕ್ಷ sTCPKeepAlive:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_keepalives);
	ಪಕ್ಷ sWarnWeakCrypto:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_warnweakcrypto);
	ಪಕ್ಷ sFingerprintHash:
		ಪ್ರತ್ಯಾಗಮ ssh_digest_alg_name(val);
	ಸ್ವಭಾವ:
		ವಿಕಲ್ಪ (val) {
		ಪಕ್ಷ 0:
			ಪ್ರತ್ಯಾಗಮ "no";
		ಪಕ್ಷ 1:
			ಪ್ರತ್ಯಾಗಮ "yes";
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_int(ServerOpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	ಯದಿ (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		ಪ್ರತ್ಯಾಗಮ;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_oct(ServerOpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_fmtint(ServerOpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_string(ServerOpCodes code, ಧ್ರುವ ವರ್ಣ *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == ರಿಕ್ತ ? "none" : val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray(ServerOpCodes code, u_int ಎಣಿಕೆ, ವರ್ಣ **vals)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray_oneline(ServerOpCodes code, u_int ಎಣಿಕೆ, ವರ್ಣ **vals)
{
	u_int i;

	ವಿಕಲ್ಪ (code) {
	ಪಕ್ಷ sAuthenticationMethods:
	ಪಕ್ಷ sChannelTimeout:
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಯದಿ (ಎಣಿಕೆ <= 0)
			ಪ್ರತ್ಯಾಗಮ;
		ಭಙ್ಗ;
	}

	printf("%s", lookup_opcode_name(code));
	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++)
		printf(" %s",  vals[i]);
	ಯದಿ (code == sAuthenticationMethods && ಎಣಿಕೆ == 0)
		printf(" any");
	ಅನ್ಯಥಾ ಯದಿ (code == sChannelTimeout && ಎಣಿಕೆ == 0)
		printf(" none");
	printf("\n");
}

ಸ್ಥಿರ ವರ್ಣ *
format_listen_addrs(ಸಂರಚನಾ listenaddr *la)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ addrinfo *ai;
	ವರ್ಣ addr[NI_MAXHOST], port[NI_MAXSERV];
	ವರ್ಣ *laddr1 = xstrdup(""), *laddr2 = ರಿಕ್ತ;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	ಪ್ರತಿ (ai = la->addrs; ai; ai = ai->ai_next) {
		ಯದಿ ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    ಪರಿಮಾಣ(addr), port, ಪರಿಮಾಣ(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			ಅನುವರ್ತ;
		}
		laddr2 = laddr1;
		ಯದಿ (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ರಿಕ್ತ ? "" : " rdomain ",
			    la->rdomain == ರಿಕ್ತ ? "" : la->rdomain,
			    laddr2);
		} ಅನ್ಯಥಾ {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ರಿಕ್ತ ? "" : " rdomain ",
			    la->rdomain == ರಿಕ್ತ ? "" : la->rdomain,
			    laddr2);
		}
		ಮುಕ್ತ(laddr2);
	}
	ಪ್ರತ್ಯಾಗಮ laddr1;
}

ಶೂನ್ಯ
dump_config(ServerOptions *o)
{
	ವರ್ಣ *s;
	u_int i;

	/* these are usually at the top of the config */
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		ಮುಕ್ತ(s);
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
	dump_cfg_int(s_Client_Alive_ಎಣಿಕೆ_Max, o->client_alive_ಎಣಿಕೆ_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_ಬೇರು_Login, o->permit_ಬೇರು_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_ಕೀಲಿಗಳು);
	dump_cfg_string(s_Security_ಕೀಲಿ_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_ಕೀಲಿಗಳು_Command, o->authorized_ಕೀಲಿಗಳು_command);
	dump_cfg_string(s_Authorized_ಕೀಲಿಗಳು_Command_User, o->authorized_ಕೀಲಿಗಳು_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_ಕೀಲಿ_Agent, o->host_ಕೀಲಿ_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_ಕೀಲಿ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#ಯದಿ defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_ಕೀಲಿಗಳು_File, o->ಅಂಕೆ_authkeys_files,
	    o->authorized_ಕೀಲಿಗಳು_files);
	dump_cfg_strarray_oneline(s_Revoked_ಕೀಲಿಗಳು, o->ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files,
	    o->revoked_ಕೀಲಿಗಳು_files);
	dump_cfg_strarray(s_Host_ಕೀಲಿ, o->ಅಂಕೆ_host_ಕೀಲಿ_files, o->host_ಕೀಲಿ_files);
	dump_cfg_strarray(sHostCertificate, o->ಅಂಕೆ_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->ಅಂಕೆ_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->ಅಂಕೆ_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->ಅಂಕೆ_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->ಅಂಕೆ_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->ಅಂಕೆ_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->ಅಂಕೆ_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->ಅಂಕೆ_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->ಅಂಕೆ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->ಅಂಕೆ_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	ಯದಿ (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	ಅನ್ಯಥಾ
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = ರಿಕ್ತ;
	ಪ್ರತಿ (i = 0; tunmode_desc[i].val != -1; i++) {
		ಯದಿ (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			ಭಙ್ಗ;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	ಯದಿ (o->ಅಂಕೆ_permitted_opens == 0)
		printf(" any");
	ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	ಯದಿ (o->ಅಂಕೆ_permitted_listens == 0)
		printf(" any");
	ಅನ್ಯಥಾ {
		ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	ಯದಿ (o->permit_user_env_allowlist == ರಿಕ್ತ) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} ಅನ್ಯಥಾ {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	ಯದಿ (o->pubkey_auth_options == 0)
		printf(" none");
	ಯದಿ (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	ಯದಿ (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	ಯದಿ (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	ಯದಿ (o->per_source_penalty.enabled) {
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
	} ಅನ್ಯಥಾ
		printf("PerSourcePenalties no\n");
}
