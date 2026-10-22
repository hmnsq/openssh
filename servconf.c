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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/stat.h>
#ifdef __OpenBSD__
#অন্তর্ভাব <sys/sysctl.h>
#endif

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#অন্তর্ভাব <net/route.h>
#endif

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <util.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "groupaccess.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#যদি !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

স্থির শূন্য add_listen_addr(ServerOptions *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
স্থির শূন্য add_one_listen_addr(ServerOptions *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, পূর্ণসংখ্যা);
স্থির শূন্য parse_server_config_depth(ServerOptions *options,
    ধ্রুবক অক্ষর *filename, কাঠামো sshbuf *conf, কাঠামো include_list *includes,
    কাঠামো connection_info *connectinfo, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা depth);

বাহ্যিক কাঠামো sshbuf *cfg;

/* Initializes the server options to their default values. */

শূন্য
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, আকার(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = ফাঁকা;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ফাঁকা;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ফাঁকা;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_চাবি_files = 0; \
	options->অঙ্ক_host_চাবি_files = 0; \
	options->host_চাবি_file_userprovided = ফাঁকা;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = ফাঁকা; \
	options->অঙ্ক_queued_listens = 0; \
	options->listen_addrs = ফাঁকা; \
	options->অঙ্ক_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->অঙ্ক_ports = 0; \
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
	options->permit_user_env_allowlist = ফাঁকা;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = ফাঁকা; \
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
	options->অঙ্ক_subsystems = 0; \
	options->subsystem_name = ফাঁকা; \
	options->subsystem_command = ফাঁকা; \
	options->subsystem_args = ফাঁকা;
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
স্থির পূর্ণসংখ্যা
option_clear_or_none(ধ্রুবক অক্ষর *o)
{
	ফেরত o == ফাঁকা || strcasecmp(o, "none") == 0;
}

স্থির শূন্য
assemble_algorithms(ServerOptions *o)
{
	অক্ষর *all_cipher, *all_mac, *all_kex, *all_চাবি, *all_sig;
	অক্ষর *def_cipher, *def_mac, *def_kex, *def_চাবি, *def_sig;
	পূর্ণসংখ্যা r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_চাবি = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_চাবি = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_চাবি);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	করো { \
		যদি ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} যখন (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_চাবি, all_চাবি);
	ASSEMBLE(hostbased_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(pubkey_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	মুক্ত(all_cipher);
	মুক্ত(all_mac);
	মুক্ত(all_kex);
	মুক্ত(all_চাবি);
	মুক্ত(all_sig);
	মুক্ত(def_cipher);
	মুক্ত(def_mac);
	মুক্ত(def_kex);
	মুক্ত(def_চাবি);
	মুক্ত(def_sig);
}

শূন্য
servconf_add_hostkey(ধ্রুবক অক্ষর *file, ধ্রুবক পূর্ণসংখ্যা সারি,
    ServerOptions *options, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা userprovided)
{
	অক্ষর *apath = derelativise_path(path);

	opt_array_append2(file, সারি, "HostKey",
	    &options->host_চাবি_files, &options->host_চাবি_file_userprovided,
	    &options->অঙ্ক_host_চাবি_files, apath, userprovided);
	মুক্ত(apath);
}

শূন্য
servconf_add_hostcert(ধ্রুবক অক্ষর *file, ধ্রুবক পূর্ণসংখ্যা সারি,
    ServerOptions *options, ধ্রুবক অক্ষর *path)
{
	অক্ষর *apath = derelativise_path(path);

	opt_array_append(file, সারি, "HostCertificate",
	    &options->host_cert_files, &options->অঙ্ক_host_cert_files, apath);
	মুক্ত(apath);
}

শূন্য
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	যদি (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	যদি (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	যদি (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	যদি (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	করো { \
		মুক্ত(options->var); \
		options->var = ফাঁকা; \
	} যখন (0);
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
	যদি (options->pam_service_name == ফাঁকা)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	যদি (options->অঙ্ক_host_চাবি_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_চাবি_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_চাবি_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_চাবি_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_চাবি_FILE, 0);
	}
	/* No certificates by default */
	যদি (options->অঙ্ক_ports == 0)
		options->ports[options->অঙ্ক_ports++] = SSH_DEFAULT_PORT;
	যদি (options->listen_addrs == ফাঁকা)
		add_listen_addr(options, ফাঁকা, ফাঁকা, 0);
	যদি (options->pid_file == ফাঁকা)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	যদি (options->moduli_file == ফাঁকা)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	যদি (options->xauth_location == ফাঁকা)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	যদি (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	যদি (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	যদি (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ফাঁকা;
	}
	যদি (options->rekey_limit == -1)
		options->rekey_limit = 0;
	যদি (options->rekey_interval == -1)
		options->rekey_interval = 0;
	যদি (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	যদি (options->max_startups == -1)
		options->max_startups = 100;
	যদি (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	যদি (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	যদি (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	যদি (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	যদি (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	যদি (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	যদি (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	যদি (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	যদি (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	যদি (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	যদি (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	যদি (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	যদি (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	যদি (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	যদি (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	যদি (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	যদি (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	যদি (options->অঙ্ক_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_চাবিগুলি_files,
		    &options->অঙ্ক_authkeys_files,
		    PATH_SSH_USER_PERMITTED_চাবিগুলি);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_চাবিগুলি_files,
		    &options->অঙ্ক_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	যদি (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	যদি (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	যদি (options->version_addendum == ফাঁকা)
		options->version_addendum = xstrdup("");
	যদি (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	যদি (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	যদি (options->sk_provider == ফাঁকা)
		options->sk_provider = xstrdup("internal");
	যদি (options->sshd_session_path == ফাঁকা)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	যদি (options->sshd_auth_path == ফাঁকা)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	যদি (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	যদি (options->agent_socket_path == ফাঁকা)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	করো { \
		যদি (option_clear_or_none(v)) { \
			মুক্ত(v); \
			v = ফাঁকা; \
		} \
	} যখন(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	করো { \
		যদি (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			মুক্ত(options->v[0]); \
			মুক্ত(options->v); \
			options->v = ফাঁকা; \
			options->nv = 0; \
		} \
	} যখন (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_চাবিগুলি);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_চাবি_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	জন্য (i = 0; i < options->অঙ্ক_host_চাবি_files; i++)
		CLEAR_ON_NONE(options->host_চাবি_files[i]);
	জন্য (i = 0; i < options->অঙ্ক_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, অঙ্ক_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, অঙ্ক_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_চাবিগুলি_files, অঙ্ক_revoked_চাবিগুলি_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_চাবিগুলি_files, অঙ্ক_authkeys_files, "none");
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
প্রকারলেখ গণনা {
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
স্থির কাঠামো {
	ধ্রুবক অক্ষর *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ফাঁকা, sBadOption, 0 }
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

স্থির কাঠামো {
	পূর্ণসংখ্যা val;
	অক্ষর *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ফাঁকা }
};

/* Returns an opcode name from its number */

স্থির ধ্রুবক অক্ষর *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	জন্য (i = 0; keywords[i].name != ফাঁকা; i++)
		যদি (keywords[i].opcode == code)
			ফেরত(keywords[i].name);
	ফেরত "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

স্থির ServerOpCodes
parse_token(ধ্রুবক অক্ষর *cp, ধ্রুবক অক্ষর *filename,
	    পূর্ণসংখ্যা linenum, u_int *flags)
{
	u_int i;

	জন্য (i = 0; keywords[i].name; i++)
		যদি (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			ফেরত keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ফেরত sBadOption;
}

অক্ষর *
derelativise_path(ধ্রুবক অক্ষর *path)
{
	অক্ষর *expanded, *ret, cwd[PATH_MAX];

	যদি (strcasecmp(path, "none") == 0)
		ফেরত xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	যদি (path_absolute(expanded))
		ফেরত expanded;
	যদি (getcwd(cwd, আকার(cwd)) == ফাঁকা)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	মুক্ত(expanded);
	ফেরত ret;
}

স্থির শূন্য
add_listen_addr(ServerOptions *options, ধ্রুবক অক্ষর *addr,
    ধ্রুবক অক্ষর *rdomain, পূর্ণসংখ্যা port)
{
	u_int i;

	যদি (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	অন্যথা {
		জন্য (i = 0; i < options->অঙ্ক_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

স্থির শূন্য
add_one_listen_addr(ServerOptions *options, ধ্রুবক অক্ষর *addr,
    ধ্রুবক অক্ষর *rdomain, পূর্ণসংখ্যা port)
{
	কাঠামো addrinfo hints, *ai, *aitop;
	অক্ষর strport[NI_MAXSERV];
	পূর্ণসংখ্যা gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	জন্য (i = 0; i < options->অঙ্ক_listen_addrs; i++) {
		যদি (rdomain == ফাঁকা && options->listen_addrs[i].rdomain == ফাঁকা)
			বিরতি;
		যদি (rdomain == ফাঁকা || options->listen_addrs[i].rdomain == ফাঁকা)
			চালু;
		যদি (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			বিরতি;
	}
	যদি (i >= options->অঙ্ক_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		যদি (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->অঙ্ক_listen_addrs, options->অঙ্ক_listen_addrs + 1,
		    আকার(*options->listen_addrs));
		i = options->অঙ্ক_listen_addrs++;
		যদি (rdomain != ফাঁকা)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, আকার(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ফাঁকা) ? AI_PASSIVE : 0;
	snprintf(strport, আকার strport, "%d", port);
	যদি ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	জন্য (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
স্থির পূর্ণসংখ্যা
valid_rdomain(ধ্রুবক অক্ষর *name)
{
#যদি defined(HAVE_SYS_VALID_RDOMAIN)
	ফেরত sys_valid_rdomain(name);
#নতুবা_যদি defined(__OpenBSD__)
	ধ্রুবক অক্ষর *errstr;
	long long অঙ্ক;
	কাঠামো rt_tableinfo info;
	পূর্ণসংখ্যা mib[6];
	আকার_t miblen = আকার(mib);

	যদি (name == ফাঁকা)
		ফেরত 1;

	অঙ্ক = strtonum(name, 0, 255, &errstr);
	যদি (errstr != ফাঁকা)
		ফেরত 0;

	/* Check whether the table actually exists */
	memset(mib, 0, আকার(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (পূর্ণসংখ্যা)অঙ্ক;
	যদি (sysctl(mib, 6, &info, &miblen, ফাঁকা, 0) == -1)
		ফেরত 0;

	ফেরত 1;
#অন্যথা /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	ফেরত 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
স্থির শূন্য
queue_listen_addr(ServerOptions *options, ধ্রুবক অক্ষর *addr,
    ধ্রুবক অক্ষর *rdomain, পূর্ণসংখ্যা port)
{
	কাঠামো queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->অঙ্ক_queued_listens, options->অঙ্ক_queued_listens + 1,
	    আকার(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->অঙ্ক_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == ফাঁকা ? ফাঁকা : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
স্থির শূন্য
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	কাঠামো queued_listenaddr *qla;

	যদি (options->অঙ্ক_ports == 0)
		options->ports[options->অঙ্ক_ports++] = SSH_DEFAULT_PORT;
	যদি (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	জন্য (i = 0; i < options->অঙ্ক_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		মুক্ত(qla->addr);
		মুক্ত(qla->rdomain);
	}
	মুক্ত(options->queued_listen_addrs);
	options->queued_listen_addrs = ফাঁকা;
	options->অঙ্ক_queued_listens = 0;
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

স্থির পূর্ণসংখ্যা
match_cfg_সারি_group(ধ্রুবক অক্ষর *grps, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *user)
{
	পূর্ণসংখ্যা ফলাফল = 0;
	কাঠামো passwd *pw;

	যদি (user == ফাঁকা)
		যাও out;

	যদি ((pw = getpwnam(user)) == ফাঁকা) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", সারি, user);
	} অন্যথা যদি (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, সারি);
	} অন্যথা যদি (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, সারি);
	} অন্যথা {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, সারি);
		ফলাফল = 1;
	}
out:
	ga_free();
	ফেরত ফলাফল;
}

স্থির শূন্য
match_test_missing_fatal(ধ্রুবক অক্ষর *criteria, ধ্রুবক অক্ষর *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
স্থির পূর্ণসংখ্যা
match_cfg_সারি(ধ্রুবক অক্ষর *full_সারি, পূর্ণসংখ্যা *acp, অক্ষর ***avp,
    পূর্ণসংখ্যা সারি, কাঠামো connection_info *ci)
{
	পূর্ণসংখ্যা ফলাফল = 1, attributes = 0, port;
	অক্ষর *arg, *attrib = ফাঁকা, *oattrib;

	যদি (ci == ফাঁকা) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_সারি, সারি);
	} অন্যথা {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_সারি,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", সারি);
	}

	যখন ((oattrib = argv_পরবর্তী(acp, avp)) != ফাঁকা) {
		/* Terminate on comment */
		যদি (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			বিরতি;
		}
		attrib = xstrdup(oattrib);
		arg = ফাঁকা;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		যদি (strcasecmp(attrib, "all") == 0) {
			যদি (attributes > 1 ||
			    ((arg = argv_পরবর্তী(acp, avp)) != ফাঁকা &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				ফলাফল = -1;
				যাও out;
			}
			যদি (arg != ফাঁকা && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ফলাফল = 1;
			যাও out;
		}
		/* Criterion "invalid-user" also has no argument */
		যদি (strcasecmp(attrib, "invalid-user") == 0) {
			যদি (ci == ফাঁকা) {
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->user_invalid == 0)
				ফলাফল = 0;
			অন্যথা
				debug("matched invalid-user at line %d", সারি);
			যাও পরবর্তী;
		}

		/* Keep this list in sync with below */
		যদি (strprefix(attrib, "user=", 1) != ফাঁকা ||
		    strprefix(attrib, "group=", 1) != ফাঁকা ||
		    strprefix(attrib, "host=", 1) != ফাঁকা ||
		    strprefix(attrib, "address=", 1) != ফাঁকা ||
		    strprefix(attrib, "localaddress=", 1) != ফাঁকা ||
		    strprefix(attrib, "localport=", 1) != ফাঁকা ||
		    strprefix(attrib, "rdomain=", 1) != ফাঁকা ||
		    strprefix(attrib, "version=", 1) != ফাঁকা) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} অন্যথা {
			arg = argv_পরবর্তী(acp, avp);
		}

		/* All other criteria require an argument */
		যদি (arg == ফাঁকা || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ফলাফল = -1;
			যাও out;
		}
		যদি (strcasecmp(attrib, "user") == 0) {
			যদি (ci == ফাঁকা || (ci->test && ci->user == ফাঁকা)) {
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->user == ফাঁকা)
				match_test_missing_fatal("User", "user");
			যদি (match_usergroup_pattern_list(ci->user, arg) != 1)
				ফলাফল = 0;
			অন্যথা
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, সারি);
		} অন্যথা যদি (strcasecmp(attrib, "group") == 0) {
			যদি (ci == ফাঁকা || (ci->test && ci->user == ফাঁকা)) {
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->user == ফাঁকা)
				match_test_missing_fatal("Group", "user");
			নির্বাচন (match_cfg_সারি_group(arg, সারি, ci->user)) {
			ক্ষেত্র -1:
				ফলাফল = -1;
				যাও out;
			ক্ষেত্র 0:
				ফলাফল = 0;
			}
		} অন্যথা যদি (strcasecmp(attrib, "host") == 0) {
			যদি (ci == ফাঁকা || (ci->test && ci->host == ফাঁকা)) {
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->host == ফাঁকা)
				match_test_missing_fatal("Host", "host");
			যদি (match_hostname(ci->host, arg) != 1)
				ফলাফল = 0;
			অন্যথা
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, সারি);
		} অন্যথা যদি (strcasecmp(attrib, "address") == 0) {
			যদি (ci == ফাঁকা || (ci->test && ci->address == ফাঁকা)) {
				যদি (addr_match_list(ফাঁকা, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, সারি);
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->address == ফাঁকা)
				match_test_missing_fatal("Address", "addr");
			নির্বাচন (addr_match_list(ci->address, arg)) {
			ক্ষেত্র 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, সারি);
				বিরতি;
			ক্ষেত্র 0:
			ক্ষেত্র -1:
				ফলাফল = 0;
				বিরতি;
			ক্ষেত্র -2:
				ফলাফল = -1;
				যাও out;
			}
		} অন্যথা যদি (strcasecmp(attrib, "localaddress") == 0){
			যদি (ci == ফাঁকা || (ci->test && ci->laddress == ফাঁকা)) {
				যদি (addr_match_list(ফাঁকা, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    সারি);
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->laddress == ফাঁকা)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			নির্বাচন (addr_match_list(ci->laddress, arg)) {
			ক্ষেত্র 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, সারি);
				বিরতি;
			ক্ষেত্র 0:
			ক্ষেত্র -1:
				ফলাফল = 0;
				বিরতি;
			ক্ষেত্র -2:
				ফলাফল = -1;
				যাও out;
			}
		} অন্যথা যদি (strcasecmp(attrib, "localport") == 0) {
			যদি ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				ফলাফল = -1;
				যাও out;
			}
			যদি (ci == ফাঁকা || (ci->test && ci->lport == -1)) {
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			যদি (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, সারি);
			অন্যথা
				ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "rdomain") == 0) {
			যদি (ci == ফাঁকা || (ci->test && ci->rdomain == ফাঁকা)) {
				ফলাফল = 0;
				যাও পরবর্তী;
			}
			যদি (ci->rdomain == ফাঁকা)
				match_test_missing_fatal("RDomain", "rdomain");
			যদি (match_pattern_list(ci->rdomain, arg, 0) != 1)
				ফলাফল = 0;
			অন্যথা
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, সারি);
		} অন্যথা যদি (strcasecmp(attrib, "version") == 0) {
			যদি (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				ফলাফল = 0;
			অন্যথা
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, সারি);
		} অন্যথা {
			error("Unsupported Match attribute %s", oattrib);
			ফলাফল = -1;
			যাও out;
		}
 পরবর্তী:
		মুক্ত(attrib);
		attrib = ফাঁকা;
	}
	যদি (attributes == 0) {
		error("One or more attributes required for Match");
		ফেরত -1;
	}
 out:
	যদি (ci != ফাঁকা && ফলাফল != -1)
		debug3("match %sfound on line %d", ফলাফল ? "" : "not ", সারি);
	মুক্ত(attrib);
	ফেরত ফলাফল;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
কাঠামো multistate {
	অক্ষর *চাবি;
	পূর্ণসংখ্যা মান;
};
স্থির ধ্রুবক কাঠামো multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ফাঁকা, -1 }
};

স্থির পূর্ণসংখ্যা
process_server_config_সারি_depth(ServerOptions *options, অক্ষর *সারি,
    ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum, পূর্ণসংখ্যা *activep,
    কাঠামো connection_info *connectinfo, পূর্ণসংখ্যা *inc_flags, পূর্ণসংখ্যা depth,
    কাঠামো include_list *includes)
{
	অক্ষর *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	পূর্ণসংখ্যা cmdline = 0, *intptr, মান, value2, value3, n, port, oactive, r;
	দ্বিগুণ dvalue, *doubleptr = ফাঁকা;
	পূর্ণসংখ্যা ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	আকার_t len;
	long long val64;
	ধ্রুবক কাঠামো multistate *multistate_ptr;
	ধ্রুবক অক্ষর *errstr;
	কাঠামো include_item *item;
	glob_t gbuf;
	অক্ষর **oav = ফাঁকা, **av;
	পূর্ণসংখ্যা oac = 0, ac;
	পূর্ণসংখ্যা ret = -1;
	অক্ষর **strs = ফাঁকা; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	যদি ((len = strlen(সারি)) == 0)
		ফেরত 0;
	জন্য (len--; len > 0; len--) {
		যদি (strchr(WHITESPACE "\f", সারি[len]) == ফাঁকা)
			বিরতি;
		সারি[len] = '\0';
	}

	str = সারি;
	যদি ((keyword = strdelim(&str)) == ফাঁকা)
		ফেরত 0;
	/* Ignore leading whitespace */
	যদি (*keyword == '\0')
		keyword = strdelim(&str);
	যদি (!keyword || !*keyword || *keyword == '#')
		ফেরত 0;
	যদি (str == ফাঁকা || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ফেরত -1;
	}
	intptr = ফাঁকা;
	charptr = ফাঁকা;
	opcode = parse_token(keyword, filename, linenum, &flags);

	যদি (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ফেরত -1;
	}
	ac = oac;
	av = oav;

	যদি (activep == ফাঁকা) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	যদি (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	যদি (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		যদি (connectinfo == ফাঁকা) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} অন্যথা { /* this is a directive we have already processed */
			ret = 0;
			যাও out;
		}
	}

	নির্বাচন (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	ক্ষেত্র sUsePAM:
		intptr = &options->use_pam;
		যাও parse_flag;
	ক্ষেত্র sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;
#endif

	/* Standard Options */
	ক্ষেত্র sBadOption:
		যাও out;
	ক্ষেত্র sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		যদি (options->ports_from_cmdline) {
			argv_consume(&ac);
			বিরতি;
		}
		যদি (options->অঙ্ক_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->অঙ্ক_ports++] = a2port(arg);
		যদি (options->ports[options->অঙ্ক_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		বিরতি;

	ক্ষেত্র sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		যদি ((মান = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র sListenAddress:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (arg == ফাঁকা || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		যদি (strchr(arg, '[') == ফাঁকা && (p = strchr(arg, ':')) != ফাঁকা
		    && strchr(p+1, ':') != ফাঁকা) {
			port = 0;
			p = arg;
		} অন্যথা {
			arg2 = ফাঁকা;
			p = hpdelim(&arg);
			যদি (p == ফাঁকা)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			যদি (arg == ফাঁকা)
				port = 0;
			অন্যথা যদি ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ফাঁকা;
		যদি ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_পরবর্তী(&ac, &av)) == ফাঁকা)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			যদি (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		বিরতি;

	ক্ষেত্র sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		মান = -1;
		জন্য (i = 0; multistate_ptr[i].চাবি != ফাঁকা; i++) {
			যদি (strcasecmp(arg, multistate_ptr[i].চাবি) == 0) {
				মান = multistate_ptr[i].মান;
				বিরতি;
			}
		}
		যদি (মান == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র s_Host_চাবি:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		যদি (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		বিরতি;

	ক্ষেত্র s_Host_চাবি_Agent:
		charptr = &options->host_চাবি_agent;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		বিরতি;

	ক্ষেত্র sHostCertificate:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		যদি (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		বিরতি;

	ক্ষেত্র sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		যদি (*activep && *charptr == ফাঁকা) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			যদি (intptr != ফাঁকা)
				*intptr = *intptr + 1;
		}
		বিরতি;

	ক্ষেত্র sModuliFile:
		charptr = &options->moduli_file;
		যাও parse_filename;

	ক্ষেত্র s_Permit_মূল_Login:
		intptr = &options->permit_মূল_login;
		multistate_ptr = multistate_permitrootlogin;
		যাও parse_multistate;

	ক্ষেত্র sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		যাও parse_multistate;

	ক্ষেত্র sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		যাও parse_multistate;

	ক্ষেত্র sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		যাও parse_flag;

	ক্ষেত্র sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		যাও parse_flag;

	ক্ষেত্র sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		যদি (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র s_Host_চাবি_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		যাও parse_pubkey_algos;

	ক্ষেত্র sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		যাও parse_pubkey_algos;

	ক্ষেত্র sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		যাও parse_flag;

	ক্ষেত্র sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		যাও parse_pubkey_algos;

	ক্ষেত্র sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		মান = 0;
		value2 = -1;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (strcasecmp(arg, "none") == 0)
				চালু;
			যদি (strcasecmp(arg, "touch-required") == 0)
				মান |= PUBKEYAUTH_TOUCH_REQUIRED;
			অন্যথা যদি (strcasecmp(arg, "verify-required") == 0)
				মান |= PUBKEYAUTH_VERIFY_REQUIRED;
			অন্যথা যদি (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				যদি (errstr != ফাঁকা) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					যাও out;
				}
			} অন্যথা {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				যাও out;
			}
		}
		যদি (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = মান;
			options->max_pubkey_ok = value2;
		}
		বিরতি;

#ifdef KRB5
	ক্ষেত্র sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		যাও parse_flag;

	ক্ষেত্র sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		যাও parse_flag;

	ক্ষেত্র sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		যাও parse_flag;
#ifdef USE_AFS
	ক্ষেত্র sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		যাও parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	ক্ষেত্র sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		যাও parse_flag;

	ক্ষেত্র sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		যাও parse_flag;

	ক্ষেত্র sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		যাও parse_flag;

	ক্ষেত্র sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		যাও parse_flag;
#endif /* GSSAPI */

	ক্ষেত্র sPasswordAuthentication:
		intptr = &options->password_authentication;
		যাও parse_flag;

	ক্ষেত্র sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		যাও parse_flag;

	ক্ষেত্র sPrintMotd:
		intptr = &options->print_motd;
		যাও parse_flag;

#ifndef DISABLE_LASTLOG
	ক্ষেত্র sPrintLastLog:
		intptr = &options->print_lastlog;
		যাও parse_flag;
#endif

	ক্ষেত্র sX11Forwarding:
		intptr = &options->x11_forwarding;
		যাও parse_flag;

	ক্ষেত্র sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_পরবর্তী(&ac, &av);
		যদি ((errstr = atoi_err(arg, &মান)) != ফাঁকা)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		যাও parse_flag;

	ক্ষেত্র sXAuthLocation:
		charptr = &options->xauth_location;
		যাও parse_filename;

	ক্ষেত্র sPermitTTY:
		intptr = &options->permit_tty;
		যাও parse_flag;

	ক্ষেত্র sPermitUserRC:
		intptr = &options->permit_user_rc;
		যাও parse_flag;

	ক্ষেত্র sStrictModes:
		intptr = &options->strict_modes;
		যাও parse_flag;

	ক্ষেত্র sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		যাও parse_multistate;

	ক্ষেত্র sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		যাও parse_flag;

	ক্ষেত্র sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		মান = 0;
		p = ফাঁকা;
		যদি (strcmp(arg, "yes") == 0)
			মান = 1;
		অন্যথা যদি (strcmp(arg, "no") == 0)
			মান = 0;
		অন্যথা {
			/* Pattern-list specified */
			মান = 1;
			p = xstrdup(arg);
		}
		যদি (*activep && *intptr == -1) {
			*intptr = মান;
			*charptr = p;
			p = ফাঁকা;
		}
		মুক্ত(p);
		বিরতি;

	ক্ষেত্র sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		যাও parse_multistate;

	ক্ষেত্র sRekeyLimit:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (strcmp(arg, "default") == 0) {
			val64 = 0;
		} অন্যথা {
			যদি (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			যদি (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		যদি (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		যদি (ac != 0) { /* optional rekey interval present */
			যদি (strcmp(av[0], "none") == 0) {
				(শূন্য)argv_পরবর্তী(&ac, &av);	/* discard */
				বিরতি;
			}
			intptr = &options->rekey_interval;
			যাও parse_time;
		}
		বিরতি;

	ক্ষেত্র sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		যাও parse_multistate;

	ক্ষেত্র sUseDNS:
		intptr = &options->use_dns;
		যাও parse_flag;

	ক্ষেত্র sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_পরবর্তী(&ac, &av);
		মান = log_facility_সংখ্যা(arg);
		যদি (মান == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) মান;
		বিরতি;

	ক্ষেত্র sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_পরবর্তী(&ac, &av);
		মান = log_level_সংখ্যা(arg);
		যদি (মান == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) মান;
		বিরতি;

	ক্ষেত্র sLogVerbose:
		found = options->অঙ্ক_log_verbose == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->log_verbose = strs;
			options->অঙ্ক_log_verbose = nstrs;
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		যাও parse_multistate;

	ক্ষেত্র sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		যাও parse_multistate;

	ক্ষেত্র sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		যাও parse_flag;

	ক্ষেত্র sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		যদি (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			যদি (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} অন্যথা যদি (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			যদি (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} অন্যথা যদি (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sDisableForwarding:
		intptr = &options->disable_forwarding;
		যাও parse_flag;

	ক্ষেত্র sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->অঙ্ক_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0' ||
			    match_user(ফাঁকা, ফাঁকা, ফাঁকা, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			যদি (!*activep)
				চালু;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		বিরতি;

	ক্ষেত্র sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->অঙ্ক_deny_users;
		যাও parse_allowdenyusers;

	ক্ষেত্র sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->অঙ্ক_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			যদি (!*activep)
				চালু;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		বিরতি;

	ক্ষেত্র sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->অঙ্ক_deny_groups;
		যাও parse_allowdenygroups;

	ক্ষেত্র sCiphers:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (options->ciphers == ফাঁকা)
			options->ciphers = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sMacs:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (options->macs == ফাঁকা)
			options->macs = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sKexAlgorithms:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (options->kex_algorithms == ফাঁকা)
			options->kex_algorithms = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sSubsystem:
		যদি ((arg = argv_পরবর্তী(&ac, &av)) == ফাঁকা || *arg == '\0' ||
		   ((arg2 = argv_পরবর্তী(&ac, &av)) == ফাঁকা || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (!*activep) {
			argv_consume(&ac);
			বিরতি;
		}
		found = 0;
		জন্য (i = 0; i < options->অঙ্ক_subsystems; i++) {
			যদি (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				বিরতি;
			}
		}
		যদি (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			বিরতি;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->অঙ্ক_subsystems,
		    options->অঙ্ক_subsystems + 1,
		    আকার(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->অঙ্ক_subsystems,
		    options->অঙ্ক_subsystems + 1,
		    আকার(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->অঙ্ক_subsystems,
		    options->অঙ্ক_subsystems + 1,
		    আকার(*options->subsystem_args));
		options->subsystem_name[options->অঙ্ক_subsystems] = xstrdup(arg);
		options->subsystem_command[options->অঙ্ক_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->অঙ্ক_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		মুক্ত(arg2);
		মুক্ত(arg);
		argv_consume(&ac);
		options->অঙ্ক_subsystems++;
		বিরতি;

	ক্ষেত্র sMaxStartups:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		যদি ((n = sscanf(arg, "%d:%d:%d",
		    &মান, &value2, &value3)) == 3) {
			যদি (মান > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} অন্যথা যদি (n == 1) {
			value3 = মান;
			value2 = -1;
		} অন্যথা {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		যদি (মান <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		যদি (*activep && options->max_startups == -1) {
			options->max_startups_begin = মান;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		বিরতি;

	ক্ষেত্র s_Per_Source_Net_Block_আকার:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		নির্বাচন (n = sscanf(arg, "%d:%d", &মান, &value2)) {
		ক্ষেত্র 2:
			যদি (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		ক্ষেত্র 1:
			যদি (মান < 0 || মান > 32)
				n = -1;
		}
		যদি (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		যদি (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = মান;
			যদি (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		বিরতি;

	ক্ষেত্র sPerSourceMaxStartups:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (strcmp(arg, "none") == 0) { /* no limit */
			মান = INT_MAX;
		} অন্যথা {
			যদি ((errstr = atoi_err(arg, &মান)) != ফাঁকা)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		যদি (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = মান;
		বিরতি;

	ক্ষেত্র sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		যদি (addr_match_list(ফাঁকা, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sPerSourcePenalties:
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			ধ্রুবক অক্ষর *q = ফাঁকা;

			found = 1;
			intptr = ফাঁকা;
			doubleptr = ফাঁকা;
			মান = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			যদি (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				যদি (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				যদি (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				চালু;
			} অন্যথা যদি ((q = strprefix(arg, "crash:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} অন্যথা যদি ((q = strprefix(arg, "authfail:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} অন্যথা যদি ((q = strprefix(arg, "invaliduser:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} অন্যথা যদি ((q = strprefix(arg, "noauth:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} অন্যথা যদি ((q = strprefix(arg, "grace-exceeded:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} অন্যথা যদি ((q = strprefix(arg, "refuseconnection:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} অন্যথা যদি ((q = strprefix(arg, "max:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} অন্যথা যদি ((q = strprefix(arg, "min:", 0)) != ফাঁকা) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} অন্যথা যদি ((q = strprefix(arg, "max-sources4:", 0)) != ফাঁকা) {
				intptr = &options->per_source_penalty.max_sources4;
				যদি ((errstr = atoi_err(q, &মান)) != ফাঁকা)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} অন্যথা যদি ((q = strprefix(arg, "max-sources6:", 0)) != ফাঁকা) {
				intptr = &options->per_source_penalty.max_sources6;
				যদি ((errstr = atoi_err(q, &মান)) != ফাঁকা)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} অন্যথা যদি (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				মান = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} অন্যথা যদি (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				মান = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} অন্যথা যদি (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				মান = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} অন্যথা যদি (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				মান = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} অন্যথা {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			যদি (doubleptr != ফাঁকা) {
				যদি ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				যদি (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} অন্যথা যদি (intptr != ফাঁকা) {
				যদি (*activep && *intptr == -1) {
					*intptr = মান;
					options->per_source_penalty.enabled = 1;
				}
			} অন্যথা {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		বিরতি;

	ক্ষেত্র sMaxAuthTries:
		intptr = &options->max_authtries;
		যাও parse_int;

	ক্ষেত্র sMaxSessions:
		intptr = &options->max_sessions;
		যাও parse_int;

	ক্ষেত্র sBanner:
		charptr = &options->banner;
		যাও parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	ক্ষেত্র s_Authorized_চাবিগুলি_File:
		uintptr = &options->অঙ্ক_authkeys_files;
		chararrayptr = &options->authorized_চাবিগুলি_files;
 parse_filenames:
		found = *uintptr == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			মুক্ত(arg2);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*activep && *charptr == ফাঁকা) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			যদি (intptr != ফাঁকা)
				*intptr = *intptr + 1;
		}
		বিরতি;

	ক্ষেত্র sClientAliveInterval:
		intptr = &options->client_alive_interval;
		যাও parse_time;

	ক্ষেত্র s_Client_Alive_গুনতি_Max:
		intptr = &options->client_alive_গুনতি_max;
		যাও parse_int;

	ক্ষেত্র sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0' || strchr(arg, '=') != ফাঁকা)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			যদি (!*activep)
				চালু;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->অঙ্ক_accept_env,
			    arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		বিরতি;

	ক্ষেত্র sSetEnv:
		found = options->অঙ্ক_setenv == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0' || strchr(arg, '=') == ফাঁকা)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			যদি (lookup_setenv_in_list(arg, strs, nstrs) != ফাঁকা) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				চালু;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->setenv = strs;
			options->অঙ্ক_setenv = nstrs;
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		মান = -1;
		জন্য (i = 0; tunmode_desc[i].val != -1; i++)
			যদি (strcmp(tunmode_desc[i].text, arg) == 0) {
				মান = tunmode_desc[i].val;
				বিরতি;
			}
		যদি (মান == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র sInclude:
		যদি (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		মান = 0;
		যখন ((arg2 = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			মান++;
			found = 0;
			যদি (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} অন্যথা
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				যদি (strcmp(item->selector, arg) != 0)
					চালু;
				যদি (item->filename != ফাঁকা) {
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
			যদি (found != 0) {
				মুক্ত(arg);
				চালু;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			যদি ((r = glob(arg, 0, ফাঁকা, &gbuf)) != 0) {
				যদি (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, আকার(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			যদি (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			জন্য (n = 0; n < (পূর্ণসংখ্যা)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, আকার(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				যদি ((item->contents = sshbuf_new()) == ফাঁকা)
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
			মুক্ত(arg);
		}
		যদি (মান == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		বিরতি;

	ক্ষেত্র sMatch:
		যদি (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		মান = match_cfg_সারি(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ফাঁকা : connectinfo));
		যদি (মান < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : মান;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		বিরতি;

	ক্ষেত্র sPermitListen:
	ক্ষেত্র sPermitOpen:
		যদি (opcode == sPermitListen) {
			uintptr = &options->অঙ্ক_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} অন্যথা {
			uintptr = &options->অঙ্ক_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				যদি (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				চালু;
			}

			যদি (opcode == sPermitListen &&
			    strchr(arg, ':') == ফাঁকা) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} অন্যথা {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				যদি (p == ফাঁকা) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			যদি (arg == ফাঁকা ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			মুক্ত(arg2);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র sForceCommand:
		যদি (str == ফাঁকা || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		যদি (*activep && options->adm_forced_command == ফাঁকা)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_চাবিগুলি;
		যাও parse_filename;

	ক্ষেত্র s_Revoked_চাবিগুলি:
		uintptr = &options->অঙ্ক_revoked_চাবিগুলি_files;
		chararrayptr = &options->revoked_চাবিগুলি_files;
		যাও parse_filenames;

	ক্ষেত্র s_Security_চাবি_Provider:
		charptr = &options->sk_provider;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*activep && *charptr == ফাঁকা) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			যদি (intptr != ফাঁকা)
				*intptr = *intptr + 1;
		}
		বিরতি;

	ক্ষেত্র sIPQoS:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি ((মান = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		যদি (মান == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			মান = INT_MAX;
		}
		arg = argv_পরবর্তী(&ac, &av);
		যদি (arg == ফাঁকা)
			value2 = মান;
		অন্যথা যদি ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		যদি (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		যদি (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = মান;
			options->ip_qos_bulk = value2;
		}
		বিরতি;

	ক্ষেত্র sVersionAddendum:
		যদি (str == ফাঁকা || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		যদি (strchr(str + len, '\r') != ফাঁকা) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		যদি ((arg = strchr(সারি, '#')) != ফাঁকা) {
			*arg = '\0';
			rtrim(সারি);
		}
		যদি (*activep && options->version_addendum == ফাঁকা) {
			যদি (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			অন্যথা
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র s_Authorized_চাবিগুলি_Command:
		charptr = &options->authorized_চাবিগুলি_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		যদি (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র s_Authorized_চাবিগুলি_Command_User:
		charptr = &options->authorized_চাবিগুলি_command_user;
 parse_localuser:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		যাও parse_command;

	ক্ষেত্র sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		যাও parse_localuser;

	ক্ষেত্র sAuthenticationMethods:
		found = options->অঙ্ক_auth_methods == 0;
		মান = 0; /* seen "any" pseudo-method */
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (strcmp(arg, "any") == 0) {
				যদি (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				মান = 1;
			} অন্যথা যদি (মান) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} অন্যথা যদি (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->auth_methods = strs;
			options->অঙ্ক_auth_methods = nstrs;
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র sStreamLocalBindMask:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		মান = strtol(arg, &p, 8);
		যদি (arg == p || মান < 0 || মান > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		যদি (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)মান;
		বিরতি;

	ক্ষেত্র sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		যাও parse_flag;

	ক্ষেত্র sFingerprintHash:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি ((মান = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		যদি (*activep)
			options->fingerprint_hash = মান;
		বিরতি;

	ক্ষেত্র sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		যাও parse_flag;

	ক্ষেত্র sRDomain:
#যদি !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র sRequiredRSASize:
		intptr = &options->required_rsa_আকার;
		যাও parse_int;

	ক্ষেত্র sChannelTimeout:
		found = options->অঙ্ক_channel_timeouts == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			} অন্যথা যদি (parse_pattern_interval(arg,
			    ফাঁকা, ফাঁকা) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->channel_timeouts = strs;
			options->অঙ্ক_channel_timeouts = nstrs;
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		যদি (av[0] != ফাঁকা && strcasecmp(av[0], "none") == 0) {
			(শূন্য)argv_পরবর্তী(&ac, &av); /* consume arg */
			যদি (*activep)
				*intptr = 0;
			বিরতি;
		}
		যাও parse_time;

	ক্ষেত্র sSshdSessionPath:
		charptr = &options->sshd_session_path;
		যাও parse_filename;

	ক্ষেত্র sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		যাও parse_filename;

	ক্ষেত্র sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		যাও parse_multistate;

	ক্ষেত্র sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		যাও parse_multistate;

	ক্ষেত্র sDeprecated:
	ক্ষেত্র sIgnore:
	ক্ষেত্র sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		বিরতি;

	পূর্বনির্ধারিত:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	যদি (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		যাও out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, ফাঁকা, nstrs);
	argv_free(oav, oac);
	ফেরত ret;
}

পূর্ণসংখ্যা
process_server_config_সারি(ServerOptions *options, অক্ষর *সারি,
    ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum, পূর্ণসংখ্যা *activep,
    কাঠামো connection_info *connectinfo, কাঠামো include_list *includes)
{
	পূর্ণসংখ্যা inc_flags = 0;

	ফেরত process_server_config_সারি_depth(options, সারি, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

শূন্য
load_server_config(ধ্রুবক অক্ষর *filename, কাঠামো sshbuf *conf)
{
	কাঠামো stat st;
	অক্ষর *সারি = ফাঁকা, *cp;
	আকার_t linesize = 0;
	FILE *f;
	পূর্ণসংখ্যা r;

	debug2_f("filename %s", filename);
	যদি ((f = fopen(filename, "r")) == ফাঁকা) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	যদি (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	যখন (getline(&সারি, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = সারি + strspn(সারি, " \t\r");
		যদি ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	মুক্ত(সারি);
	যদি ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

শূন্য
parse_server_match_config(ServerOptions *options,
   কাঠামো include_list *includes, কাঠামো connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

পূর্ণসংখ্যা
parse_server_match_testspec(কাঠামো connection_info *ci, অক্ষর *spec)
{
	অক্ষর *p;
	ধ্রুবক অক্ষর *val;

	যখন ((p = strsep(&spec, ",")) && *p != '\0') {
		যদি ((val = strprefix(p, "addr=", 0)) != ফাঁকা) {
			ci->address = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "host=", 0)) != ফাঁকা) {
			ci->host = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "user=", 0)) != ফাঁকা) {
			ci->user = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "laddr=", 0)) != ফাঁকা) {
			ci->laddress = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "rdomain=", 0)) != ফাঁকা) {
			ci->rdomain = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "lport=", 0)) != ফাঁকা) {
			ci->lport = a2port(val);
			যদি (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				ফেরত -1;
			}
		} অন্যথা যদি (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} অন্যথা {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			ফেরত -1;
		}
	}
	ফেরত 0;
}

শূন্য
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	জন্য (i = 0; i < src->অঙ্ক_subsystems; i++) {
		found = 0;
		জন্য (j = 0; j < dst->অঙ্ক_subsystems; j++) {
			যদি (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				বিরতি;
			}
		}
		যদি (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			মুক্ত(dst->subsystem_command[j]);
			মুক্ত(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			চালু;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->অঙ্ক_subsystems,
		    dst->অঙ্ক_subsystems + 1, আকার(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->অঙ্ক_subsystems,
		    dst->অঙ্ক_subsystems + 1, আকার(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->অঙ্ক_subsystems,
		    dst->অঙ্ক_subsystems + 1, আকার(*dst->subsystem_args));
		j = dst->অঙ্ক_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

স্থির পূর্ণসংখ্যা
serialise_s32(কাঠামো sshbuf *buf, পূর্ণসংখ্যা v)
{
	uint32_t uv;
	পূর্ণসংখ্যা r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	যদি ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		ফেরত r;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_s64(কাঠামো sshbuf *buf, int64_t v)
{
	uint64_t uv;
	পূর্ণসংখ্যা r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	যদি ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		ফেরত r;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_mode(কাঠামো sshbuf *buf, mode_t v)
{
	u_int uv;

	যদি (v == (mode_t)-1)
		ফেরত serialise_s32(buf, -1);
	uv = (u_int)v;
	যদি ((mode_t)uv != v || uv > 0777)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত serialise_s32(buf, (পূর্ণসংখ্যা)uv);
}

স্থির পূর্ণসংখ্যা
serialise_double(কাঠামো sshbuf *buf, দ্বিগুণ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	ফেরত sshbuf_put(buf, &v, আকার(v));
}

স্থির পূর্ণসংখ্যা
serialise_nullable_string(কাঠামো sshbuf *buf, ধ্রুবক অক্ষর *s)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u8(buf, s != ফাঁকা)) != 0)
		ফেরত r;
	যদি (s == ফাঁকা)
		ফেরত 0;
	ফেরত sshbuf_put_cstring(buf, s);
}

স্থির পূর্ণসংখ্যা
serialise_nullable_string_array(কাঠামো sshbuf *buf, অক্ষর **a, u_int n)
{
	পূর্ণসংখ্যা r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, n)) != 0)
		ফেরত r;
	জন্য (i = 0; i < n; i++) {
		যদি ((r = serialise_nullable_string(buf, a[i])) != 0)
			ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_hostkeyfile(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_host_চাবি_files)) != 0) {
		error_fr(r, "serialise length");
		ফেরত r;
	}
	জন্য (i = 0; i < options->অঙ্ক_host_চাবি_files; i++) {
		যদি ((r = serialise_s32(buf,
		    options->host_চাবি_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_চাবি_files[i])) != 0) {
			error_fr(r, "serialise member");
			ফেরত r;
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_ipqos(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_listenaddress(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		ফেরত r;
	}
	জন্য (i = 0; i < options->অঙ্ক_queued_listens; i++) {
		ধ্রুবক কাঠামো queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		যদি ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			ফেরত r;
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_logfacility(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, (পূর্ণসংখ্যা)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_loglevel(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, (পূর্ণসংখ্যা)options->log_level)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_port(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_ports)) != 0) {
		error_fr(r, "serialise length");
		ফেরত r;
	}
	জন্য (i = 0; i < options->অঙ্ক_ports; i++) {
		যদি ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			ফেরত r;
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_gatewayports(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_streamlocalbindmask(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_streamlocalbindunlink(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_maxstartups(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_permituserenv(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_persourcenetblocksize(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_persourcepenalties(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	ধ্রুবক কাঠামো per_source_penalty *psp = &options->per_source_penalty;
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_rekeylimit(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_subsystem(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_subsystems)) != 0) {
		error_fr(r, "serialise length");
		ফেরত r;
	}
	জন্য (i = 0; i < options->অঙ্ক_subsystems; i++) {
		যদি ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			ফেরত r;
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_pubkey_auth_options(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
serialise_timingsecret(ধ্রুবক ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		ফেরত r;
	}
	ফেরত 0;
}


পূর্ণসংখ্যা
serialise_server_options(ধ্রুবক ServerOptions *options, কাঠামো sshbuf **bufp)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	*bufp = ফাঁকা;

	যদি ((buf = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		যাও out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	যদি ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	যদি ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	যদি ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	যদি ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	যদি ((r = serialise_##funcsuffix(options, buf)) != 0) \
		যাও out;
#define SSHCONF_NONCONF(funcsuffix) \
	যদি ((r = serialise_##funcsuffix(options, buf)) != 0) \
		যাও out;
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
	buf = ফাঁকা; /* transferred */
 out:
	sshbuf_free(buf);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
deserialise_s32(কাঠামো sshbuf *buf, পূর্ণসংখ্যা *v)
{
	uint32_t tmp;
	পূর্ণসংখ্যা r;
	u_char was_signed;

	যদি ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		ফেরত r;
	যদি (was_signed > 1)
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (was_signed) {
		যদি (tmp > (uint32_t)INT_MAX + 1)
			ফেরত SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(পূর্ণসংখ্যা)tmp;
	} অন্যথা {
		যদি (tmp > INT_MAX)
			ফেরত SSH_ERR_INVALID_FORMAT;
		*v = (পূর্ণসংখ্যা)tmp;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_s64(কাঠামো sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	পূর্ণসংখ্যা r;
	u_char was_signed;

	যদি ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		ফেরত r;
	যদি (was_signed > 1)
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (was_signed) {
		যদি (tmp > (uint64_t)INT64_MAX + 1)
			ফেরত SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} অন্যথা {
		যদি (tmp > INT64_MAX)
			ফেরত SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_mode(কাঠামো sshbuf *buf, mode_t *v)
{
	পূর্ণসংখ্যা r, tmp;

	যদি ((r = deserialise_s32(buf, &tmp)) != 0)
		ফেরত r;
	যদি (tmp == -1) {
		*v = (mode_t)-1;
		ফেরত 0;
	}
	যদি (tmp < 0 || tmp > 0777)
		ফেরত SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_double(কাঠামো sshbuf *buf, দ্বিগুণ *v)
{
	ফেরত sshbuf_get(buf, v, আকার(*v));
}

স্থির পূর্ণসংখ্যা
deserialise_nullable_string(কাঠামো sshbuf *buf, অক্ষর **sp)
{
	পূর্ণসংখ্যা r;
	u_char present;

	যদি ((r = sshbuf_get_u8(buf, &present)) != 0)
		ফেরত r;
	যদি (present == 0) {
		*sp = ফাঁকা;
		ফেরত 0;
	}
	যদি (present != 1)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত sshbuf_get_cstring(buf, sp, ফাঁকা);
}

স্থির শূন্য
free_string_array(অক্ষর **a, u_int n)
{
	u_int i;

	যদি (a == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < n; i++)
		মুক্ত(a[i]);
	মুক্ত(a);
}

স্থির পূর্ণসংখ্যা
deserialise_গুনতি(কাঠামো sshbuf *buf, u_int *np, ধ্রুবক অক্ষর *what)
{
	পূর্ণসংখ্যা r;
	uint32_t n;

	যদি ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		ফেরত r;
	}
	যদি (n > UINT_MAX) {
		error_f("bad number of %s", what);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	যদি (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_nullable_string_array(কাঠামো sshbuf *buf, অক্ষর ***arrayp,
    u_int *np)
{
	অক্ষর **a = ফাঁকা;
	পূর্ণসংখ্যা r;
	u_int i, n;

	*arrayp = ফাঁকা;
	*np = 0;
	যদি ((r = deserialise_গুনতি(buf, &n, "strings")) != 0)
		ফেরত r;
	যদি (n > 0)
		a = xcalloc(n, আকার(*a));
	জন্য (i = 0; i < n; i++) {
		যদি ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			ফেরত r;
		}
	}
	*arrayp = a;
	*np = n;
	ফেরত 0;
}

স্থির শূন্য
free_queued_listen_addrs(কাঠামো queued_listenaddr *qla, u_int n)
{
	u_int i;

	যদি (qla == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < n; i++) {
		মুক্ত(qla[i].addr);
		মুক্ত(qla[i].rdomain);
	}
	মুক্ত(qla);
}

স্থির পূর্ণসংখ্যা
deserialise_hostkeyfile(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r, *userprovided = ফাঁকা;
	u_int i, n;
	অক্ষর **files = ফাঁকা;

	যদি ((r = deserialise_গুনতি(buf, &n, "host key files")) != 0)
		ফেরত r;
	যদি (n > 0) {
		userprovided = xcalloc(n, আকার(*userprovided));
		files = xcalloc(n, আকার(*files));
	}
	জন্য (i = 0; i < n; i++) {
		যদি ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			মুক্ত(userprovided);
			ফেরত r;
		}
	}
	options->অঙ্ক_host_চাবি_files = n;
	options->host_চাবি_file_userprovided = userprovided;
	options->host_চাবি_files = files;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_ipqos(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_listenaddress(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i, n;
	কাঠামো queued_listenaddr *qla = ফাঁকা;

	যদি ((r = deserialise_গুনতি(buf, &n, "listen addresses")) != 0)
		ফেরত r;
	যদি (n > 0)
		qla = xcalloc(n, আকার(*qla));
	জন্য (i = 0; i < n; i++) {
		যদি ((r = sshbuf_get_cstring(buf, &qla[i].addr, ফাঁকা)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			ফেরত r;
		}
	}
	options->অঙ্ক_queued_listens = n;
	options->queued_listen_addrs = qla;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_logfacility(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r, tmp;

	যদি ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	যদি (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == ফাঁকা) {
		error_f("bad syslog facility");
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_loglevel(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r, tmp;

	যদি ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	যদি (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == ফাঁকা) {
		error_f("bad log level");
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_port(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i, n;

	যদি ((r = deserialise_গুনতি(buf, &n, "ports")) != 0)
		ফেরত r;
	যদি (n > MAX_PORTS) {
		error_f("bad number of ports");
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	options->অঙ্ক_ports = n;
	memset(options->ports, 0, আকার(options->ports));
	জন্য (i = 0; i < options->অঙ্ক_ports; i++) {
		যদি ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			ফেরত r;
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_gatewayports(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_streamlocalbindmask(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_streamlocalbindunlink(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_char tmp;

	যদি ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	যদি (tmp > 1) {
		error_f("bad boolean");
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_maxstartups(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_permituserenv(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_persourcenetblocksize(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_persourcepenalties(ServerOptions *options, কাঠামো sshbuf *buf)
{
	কাঠামো per_source_penalty *psp = &options->per_source_penalty;
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_rekeylimit(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_subsystem(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;
	u_int i, n;
	অক্ষর **names = ফাঁকা, **commands = ফাঁকা, **args = ফাঁকা;

	যদি ((r = deserialise_গুনতি(buf, &n, "subsystems")) != 0)
		ফেরত r;
	যদি (n > 0) {
		names = xcalloc(n, আকার(*names));
		commands = xcalloc(n, আকার(*names));
		args = xcalloc(n, আকার(*args));
	}
	জন্য (i = 0; i < n; i++) {
		যদি ((r = sshbuf_get_cstring(buf, names + i, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ফাঁকা)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, ফাঁকা)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			ফেরত r;
		}
	}
	options->অঙ্ক_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_pubkey_auth_options(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
deserialise_timingsecret(ServerOptions *options, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		ফেরত r;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
deserialise_server_options(কাঠামো sshbuf *buf, ServerOptions *options)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	যদি ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		যাও out;
	}
	যদি (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	যদি ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	যদি ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	যদি ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	যদি ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		যাও out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	যদি ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		যাও out;
#define SSHCONF_NONCONF(funcsuffix) \
	যদি ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		যাও out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	করো { \
		মুক্ত(new_options.var); \
		new_options.var = ফাঁকা; \
	} যখন (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	যদি (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
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
	memset(&new_options, 0, আকার(new_options));
 out:
	free_server_options(&new_options);
	ফেরত r;
}

স্থির শূন্য
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	জন্য (i = 0; i < options->অঙ্ক_host_চাবি_files; i++)
		মুক্ত(options->host_চাবি_files[i]);
	মুক্ত(options->host_চাবি_files);
	মুক্ত(options->host_চাবি_file_userprovided);
}

স্থির শূন্য
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->অঙ্ক_queued_listens);

	জন্য (i = 0; i < options->অঙ্ক_listen_addrs; i++) {
		মুক্ত(options->listen_addrs[i].rdomain);
		যদি (options->listen_addrs[i].addrs != ফাঁকা)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	মুক্ত(options->listen_addrs);
}

স্থির শূন্য
free_permituserenv(ServerOptions *options)
{
	মুক্ত(options->permit_user_env_allowlist);
}

স্থির শূন্য
free_subsystem(ServerOptions *options)
{
	u_int i;

	জন্য (i = 0; i < options->অঙ্ক_subsystems; i++) {
		মুক্ত(options->subsystem_name[i]);
		মুক্ত(options->subsystem_command[i]);
		মুক্ত(options->subsystem_args[i]);
	}
	মুক্ত(options->subsystem_name);
	মুক্ত(options->subsystem_command);
	মুক্ত(options->subsystem_args);
}

শূন্য
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		মুক্ত(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	করো { \
		মুক্ত(options->var); \
		options->var = ফাঁকা; \
	} যখন (0);
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

স্থির শূন্য
copy_server_option_int(পূর্ণসংখ্যা *dst, পূর্ণসংখ্যা src)
{
	যদি (src != -1)
		*dst = src;
}

স্থির শূন্য
copy_server_option_int64(int64_t *dst, int64_t src)
{
	যদি (src != -1)
		*dst = src;
}

স্থির শূন্য
copy_server_option_string(অক্ষর **dst, ধ্রুবক অক্ষর *src)
{
	যদি (src != ফাঁকা && *dst != src) {
		মুক্ত(*dst);
		*dst = xstrdup(src);
	}
}

স্থির শূন্য
copy_server_option_strarray_মানসমূহ(অক্ষর ***dst, u_int ndst,
    অক্ষর * ধ্রুবক *src, u_int nsrc)
{
	u_int i;

	যদি (nsrc == 0)
		ফেরত;
	জন্য (i = 0; i < ndst; i++)
		মুক্ত((*dst)[i]);
	মুক্ত(*dst);
	*dst = xcalloc(nsrc, আকার(**dst));
	জন্য (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ফাঁকা ? ফাঁকা : xstrdup(src[i]);
}

স্থির শূন্য
copy_server_option_strarray(অক্ষর ***dst, u_int *ndst,
    অক্ষর * ধ্রুবক *src, u_int nsrc)
{
	যদি (nsrc == 0)
		ফেরত;
	copy_server_option_strarray_মানসমূহ(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

স্থির শূন্য
copy_ipqos(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

স্থির শূন্য
copy_gatewayports(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

স্থির শূন্য
copy_streamlocalbindunlink(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

স্থির শূন্য
copy_loglevel(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	যদি (src->log_level != -1)
		dst->log_level = src->log_level;
}

স্থির শূন্য
copy_rekeylimit(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

স্থির শূন্য
copy_subsystem(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	u_int old_অঙ্ক_subsystems = dst->অঙ্ক_subsystems;

	যদি (src->অঙ্ক_subsystems == 0)
		ফেরত;
	copy_server_option_strarray_মানসমূহ(&dst->subsystem_name,
	    old_অঙ্ক_subsystems, src->subsystem_name, src->অঙ্ক_subsystems);
	copy_server_option_strarray_মানসমূহ(&dst->subsystem_command,
	    old_অঙ্ক_subsystems, src->subsystem_command, src->অঙ্ক_subsystems);
	copy_server_option_strarray_মানসমূহ(&dst->subsystem_args,
	    old_অঙ্ক_subsystems, src->subsystem_args, src->অঙ্ক_subsystems);
	dst->অঙ্ক_subsystems = src->অঙ্ক_subsystems;
}

স্থির শূন্য
copy_pubkey_auth_options(ServerOptions *dst, ধ্রুবক ServerOptions *src)
{
	যদি (src->pubkey_auth_options != -1) {
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
শূন্য
copy_set_server_options(ServerOptions *dst, ServerOptions *src, পূর্ণসংখ্যা preauth)
{
	যদি (dst == src)
		ফেরত;

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
	করো { \
		মুক্ত(dst->var); \
		dst->var = ফাঁকা; \
	} যখন (0);
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
	যদি (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	করো { \
		যদি (option_clear_or_none(v)) { \
			মুক্ত(v); \
			v = ফাঁকা; \
		} \
	} যখন(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_চাবিগুলি);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	যদি (preauth)
		ফেরত;

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
স্থির শূন্য
parse_server_config_depth(ServerOptions *options, ধ্রুবক অক্ষর *filename,
    কাঠামো sshbuf *conf, কাঠামো include_list *includes,
    কাঠামো connection_info *connectinfo, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা depth)
{
	পূর্ণসংখ্যা linenum, bad_options = 0;
	অক্ষর *cp, *obuf, *cbuf;

	যদি (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	যদি ((obuf = cbuf = sshbuf_dup_string(conf)) == ফাঁকা)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	যখন ((cp = strsep(&cbuf, "\n")) != ফাঁকা) {
		যদি (process_server_config_সারি_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	মুক্ত(obuf);
	যদি (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

শূন্য
parse_server_config(ServerOptions *options, ধ্রুবক অক্ষর *filename,
    কাঠামো sshbuf *conf, কাঠামো include_list *includes,
    কাঠামো connection_info *connectinfo, পূর্ণসংখ্যা reexec)
{
	পূর্ণসংখ্যা active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	যদি (!reexec)
		process_queued_listen_addrs(options);
}

স্থির ধ্রুবক অক্ষর *
fmt_multistate_int(পূর্ণসংখ্যা val, ধ্রুবক কাঠামো multistate *m)
{
	u_int i;

	জন্য (i = 0; m[i].চাবি != ফাঁকা; i++) {
		যদি (m[i].মান == val)
			ফেরত m[i].চাবি;
	}
	ফেরত "UNKNOWN";
}

স্থির ধ্রুবক অক্ষর *
fmt_intarg(ServerOpCodes code, পূর্ণসংখ্যা val)
{
	যদি (val == -1)
		ফেরত "unset";
	নির্বাচন (code) {
	ক্ষেত্র sAddressFamily:
		ফেরত fmt_multistate_int(val, multistate_addressfamily);
	ক্ষেত্র s_Permit_মূল_Login:
		ফেরত fmt_multistate_int(val, multistate_permitrootlogin);
	ক্ষেত্র sGatewayPorts:
		ফেরত fmt_multistate_int(val, multistate_gatewayports);
	ক্ষেত্র sCompression:
		ফেরত fmt_multistate_int(val, multistate_compression);
	ক্ষেত্র sAllowTcpForwarding:
		ফেরত fmt_multistate_int(val, multistate_tcpfwd);
	ক্ষেত্র sAllowStreamLocalForwarding:
		ফেরত fmt_multistate_int(val, multistate_tcpfwd);
	ক্ষেত্র sIgnoreRhosts:
		ফেরত fmt_multistate_int(val, multistate_ignore_rhosts);
	ক্ষেত্র sTCPKeepAlive:
		ফেরত fmt_multistate_int(val, multistate_keepalives);
	ক্ষেত্র sWarnWeakCrypto:
		ফেরত fmt_multistate_int(val, multistate_warnweakcrypto);
	ক্ষেত্র sFingerprintHash:
		ফেরত ssh_digest_alg_name(val);
	পূর্বনির্ধারিত:
		নির্বাচন (val) {
		ক্ষেত্র 0:
			ফেরত "no";
		ক্ষেত্র 1:
			ফেরত "yes";
		পূর্বনির্ধারিত:
			ফেরত "UNKNOWN";
		}
	}
}

স্থির শূন্য
dump_cfg_int(ServerOpCodes code, পূর্ণসংখ্যা val)
{
	যদি (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		ফেরত;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_oct(ServerOpCodes code, পূর্ণসংখ্যা val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_fmtint(ServerOpCodes code, পূর্ণসংখ্যা val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

স্থির শূন্য
dump_cfg_string(ServerOpCodes code, ধ্রুবক অক্ষর *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == ফাঁকা ? "none" : val);
}

স্থির শূন্য
dump_cfg_strarray(ServerOpCodes code, u_int গুনতি, অক্ষর **vals)
{
	u_int i;

	জন্য (i = 0; i < গুনতি; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

স্থির শূন্য
dump_cfg_strarray_oneline(ServerOpCodes code, u_int গুনতি, অক্ষর **vals)
{
	u_int i;

	নির্বাচন (code) {
	ক্ষেত্র sAuthenticationMethods:
	ক্ষেত্র sChannelTimeout:
		বিরতি;
	পূর্বনির্ধারিত:
		যদি (গুনতি <= 0)
			ফেরত;
		বিরতি;
	}

	printf("%s", lookup_opcode_name(code));
	জন্য (i = 0; i < গুনতি; i++)
		printf(" %s",  vals[i]);
	যদি (code == sAuthenticationMethods && গুনতি == 0)
		printf(" any");
	অন্যথা যদি (code == sChannelTimeout && গুনতি == 0)
		printf(" none");
	printf("\n");
}

স্থির অক্ষর *
format_listen_addrs(কাঠামো listenaddr *la)
{
	পূর্ণসংখ্যা r;
	কাঠামো addrinfo *ai;
	অক্ষর addr[NI_MAXHOST], port[NI_MAXSERV];
	অক্ষর *laddr1 = xstrdup(""), *laddr2 = ফাঁকা;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	জন্য (ai = la->addrs; ai; ai = ai->ai_next) {
		যদি ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    আকার(addr), port, আকার(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			চালু;
		}
		laddr2 = laddr1;
		যদি (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ফাঁকা ? "" : " rdomain ",
			    la->rdomain == ফাঁকা ? "" : la->rdomain,
			    laddr2);
		} অন্যথা {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ফাঁকা ? "" : " rdomain ",
			    la->rdomain == ফাঁকা ? "" : la->rdomain,
			    laddr2);
		}
		মুক্ত(laddr2);
	}
	ফেরত laddr1;
}

শূন্য
dump_config(ServerOptions *o)
{
	অক্ষর *s;
	u_int i;

	/* these are usually at the top of the config */
	জন্য (i = 0; i < o->অঙ্ক_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	জন্য (i = 0; i < o->অঙ্ক_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		মুক্ত(s);
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
	dump_cfg_int(s_Client_Alive_গুনতি_Max, o->client_alive_গুনতি_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_আকার);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_মূল_Login, o->permit_মূল_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_চাবিগুলি);
	dump_cfg_string(s_Security_চাবি_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_চাবিগুলি_Command, o->authorized_চাবিগুলি_command);
	dump_cfg_string(s_Authorized_চাবিগুলি_Command_User, o->authorized_চাবিগুলি_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_চাবি_Agent, o->host_চাবি_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_চাবি_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#যদি defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_চাবিগুলি_File, o->অঙ্ক_authkeys_files,
	    o->authorized_চাবিগুলি_files);
	dump_cfg_strarray_oneline(s_Revoked_চাবিগুলি, o->অঙ্ক_revoked_চাবিগুলি_files,
	    o->revoked_চাবিগুলি_files);
	dump_cfg_strarray(s_Host_চাবি, o->অঙ্ক_host_চাবি_files, o->host_চাবি_files);
	dump_cfg_strarray(sHostCertificate, o->অঙ্ক_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->অঙ্ক_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->অঙ্ক_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->অঙ্ক_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->অঙ্ক_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->অঙ্ক_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->অঙ্ক_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->অঙ্ক_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->অঙ্ক_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->অঙ্ক_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	জন্য (i = 0; i < o->অঙ্ক_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	যদি (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	অন্যথা
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = ফাঁকা;
	জন্য (i = 0; tunmode_desc[i].val != -1; i++) {
		যদি (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			বিরতি;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	যদি (o->অঙ্ক_permitted_opens == 0)
		printf(" any");
	অন্যথা {
		জন্য (i = 0; i < o->অঙ্ক_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	যদি (o->অঙ্ক_permitted_listens == 0)
		printf(" any");
	অন্যথা {
		জন্য (i = 0; i < o->অঙ্ক_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	যদি (o->permit_user_env_allowlist == ফাঁকা) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} অন্যথা {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	যদি (o->pubkey_auth_options == 0)
		printf(" none");
	যদি (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	যদি (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	যদি (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	যদি (o->per_source_penalty.enabled) {
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
	} অন্যথা
		printf("PerSourcePenalties no\n");
}
