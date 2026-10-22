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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/stat.h>
#ifdef __OpenBSD__
#अन्तर्भाव <sys/sysctl.h>
#endif

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#अन्तर्भाव <net/route.h>
#endif

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "groupaccess.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#जर !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

स्थिर शून्य add_listen_addr(ServerOptions *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, पूर्णांक);
स्थिर शून्य add_one_listen_addr(ServerOptions *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, पूर्णांक);
स्थिर शून्य parse_server_config_depth(ServerOptions *options,
    स्थिरांक अक्षर *filename, संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णांक flags, पूर्णांक *activep, पूर्णांक depth);

बाह्य संरचना sshbuf *cfg;

/* Initializes the server options to their default values. */

शून्य
initialize_server_options(ServerOptions *options)
{
	स_रखो(options, 0, आकार(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = रिक्त;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = रिक्त;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = रिक्त;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_किल्ली_files = 0; \
	options->अंक_host_किल्ली_files = 0; \
	options->host_किल्ली_file_userprovided = रिक्त;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = रिक्त; \
	options->अंक_queued_listens = 0; \
	options->listen_addrs = रिक्त; \
	options->अंक_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->अंक_ports = 0; \
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
	options->permit_user_env_allowlist = रिक्त;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = रिक्त; \
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
	options->अंक_subsystems = 0; \
	options->subsystem_name = रिक्त; \
	options->subsystem_command = रिक्त; \
	options->subsystem_args = रिक्त;
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
स्थिर पूर्णांक
option_clear_or_none(स्थिरांक अक्षर *o)
{
	परत o == रिक्त || strcasecmp(o, "none") == 0;
}

स्थिर शून्य
assemble_algorithms(ServerOptions *o)
{
	अक्षर *all_cipher, *all_mac, *all_kex, *all_किल्ली, *all_sig;
	अक्षर *def_cipher, *def_mac, *def_kex, *def_किल्ली, *def_sig;
	पूर्णांक r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_किल्ली = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_किल्ली = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_किल्ली);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	करा { \
		जर ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} पर्यंत (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_किल्ली, all_किल्ली);
	ASSEMBLE(hostbased_accepted_algos, def_किल्ली, all_किल्ली);
	ASSEMBLE(pubkey_accepted_algos, def_किल्ली, all_किल्ली);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_किल्ली);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_किल्ली);
	मुक्त(def_sig);
}

शून्य
servconf_add_hostkey(स्थिरांक अक्षर *file, स्थिरांक पूर्णांक ओळ,
    ServerOptions *options, स्थिरांक अक्षर *path, पूर्णांक userprovided)
{
	अक्षर *apath = derelativise_path(path);

	opt_array_append2(file, ओळ, "HostKey",
	    &options->host_किल्ली_files, &options->host_किल्ली_file_userprovided,
	    &options->अंक_host_किल्ली_files, apath, userprovided);
	मुक्त(apath);
}

शून्य
servconf_add_hostcert(स्थिरांक अक्षर *file, स्थिरांक पूर्णांक ओळ,
    ServerOptions *options, स्थिरांक अक्षर *path)
{
	अक्षर *apath = derelativise_path(path);

	opt_array_append(file, ओळ, "HostCertificate",
	    &options->host_cert_files, &options->अंक_host_cert_files, apath);
	मुक्त(apath);
}

शून्य
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	जर (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	जर (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	जर (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	जर (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करा { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} पर्यंत (0);
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
	जर (options->pam_service_name == रिक्त)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	जर (options->अंक_host_किल्ली_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_किल्ली_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_किल्ली_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_किल्ली_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_किल्ली_FILE, 0);
	}
	/* No certificates by default */
	जर (options->अंक_ports == 0)
		options->ports[options->अंक_ports++] = SSH_DEFAULT_PORT;
	जर (options->listen_addrs == रिक्त)
		add_listen_addr(options, रिक्त, रिक्त, 0);
	जर (options->pid_file == रिक्त)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	जर (options->moduli_file == रिक्त)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	जर (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	जर (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	जर (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	जर (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = रिक्त;
	}
	जर (options->rekey_limit == -1)
		options->rekey_limit = 0;
	जर (options->rekey_interval == -1)
		options->rekey_interval = 0;
	जर (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	जर (options->max_startups == -1)
		options->max_startups = 100;
	जर (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	जर (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	जर (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	जर (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	जर (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	जर (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	जर (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	जर (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	जर (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	जर (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	जर (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	जर (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	जर (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	जर (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	जर (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	जर (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	जर (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	जर (options->अंक_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_किल्ल्या_files,
		    &options->अंक_authkeys_files,
		    PATH_SSH_USER_PERMITTED_किल्ल्या);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_किल्ल्या_files,
		    &options->अंक_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	जर (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	जर (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	जर (options->version_addendum == रिक्त)
		options->version_addendum = xstrdup("");
	जर (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	जर (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	जर (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
	जर (options->sshd_session_path == रिक्त)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	जर (options->sshd_auth_path == रिक्त)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	जर (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	जर (options->agent_socket_path == रिक्त)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	करा { \
		जर (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} पर्यंत(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	करा { \
		जर (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} पर्यंत (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_किल्ल्या);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_किल्ली_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	साठी (i = 0; i < options->अंक_host_किल्ली_files; i++)
		CLEAR_ON_NONE(options->host_किल्ली_files[i]);
	साठी (i = 0; i < options->अंक_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, अंक_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, अंक_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_किल्ल्या_files, अंक_revoked_किल्ल्या_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_किल्ल्या_files, अंक_authkeys_files, "none");
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
प्रकारव्याख्या गणना {
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
स्थिर संरचना {
	स्थिरांक अक्षर *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ रिक्त, sBadOption, 0 }
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

स्थिर संरचना {
	पूर्णांक val;
	अक्षर *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, रिक्त }
};

/* Returns an opcode name from its number */

स्थिर स्थिरांक अक्षर *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	साठी (i = 0; keywords[i].name != रिक्त; i++)
		जर (keywords[i].opcode == code)
			परत(keywords[i].name);
	परत "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

स्थिर ServerOpCodes
parse_token(स्थिरांक अक्षर *cp, स्थिरांक अक्षर *filename,
	    पूर्णांक linenum, u_int *flags)
{
	u_int i;

	साठी (i = 0; keywords[i].name; i++)
		जर (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			परत keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	परत sBadOption;
}

अक्षर *
derelativise_path(स्थिरांक अक्षर *path)
{
	अक्षर *expanded, *ret, cwd[PATH_MAX];

	जर (strcasecmp(path, "none") == 0)
		परत xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	जर (path_absolute(expanded))
		परत expanded;
	जर (getcwd(cwd, आकार(cwd)) == रिक्त)
		fatal_f("getcwd: %s", म_त्रुटि(त्रुटि_सं));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	मुक्त(expanded);
	परत ret;
}

स्थिर शून्य
add_listen_addr(ServerOptions *options, स्थिरांक अक्षर *addr,
    स्थिरांक अक्षर *rdomain, पूर्णांक port)
{
	u_int i;

	जर (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	अन्यथा {
		साठी (i = 0; i < options->अंक_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

स्थिर शून्य
add_one_listen_addr(ServerOptions *options, स्थिरांक अक्षर *addr,
    स्थिरांक अक्षर *rdomain, पूर्णांक port)
{
	संरचना addrinfo hints, *ai, *aitop;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	साठी (i = 0; i < options->अंक_listen_addrs; i++) {
		जर (rdomain == रिक्त && options->listen_addrs[i].rdomain == रिक्त)
			थांबा;
		जर (rdomain == रिक्त || options->listen_addrs[i].rdomain == रिक्त)
			सुरूठेवा;
		जर (म_भेद(rdomain, options->listen_addrs[i].rdomain) == 0)
			थांबा;
	}
	जर (i >= options->अंक_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		जर (i >= पूर्णांक_उच्च)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->अंक_listen_addrs, options->अंक_listen_addrs + 1,
		    आकार(*options->listen_addrs));
		i = options->अंक_listen_addrs++;
		जर (rdomain != रिक्त)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	स_रखो(&hints, 0, आकार(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == रिक्त) ? AI_PASSIVE : 0;
	snprintf(strport, आकार strport, "%d", port);
	जर ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	साठी (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
स्थिर पूर्णांक
valid_rdomain(स्थिरांक अक्षर *name)
{
#जर defined(HAVE_SYS_VALID_RDOMAIN)
	परत sys_valid_rdomain(name);
#किंवाजर defined(__OpenBSD__)
	स्थिरांक अक्षर *errstr;
	दीर्घ दीर्घ अंक;
	संरचना rt_tableinfo info;
	पूर्णांक mib[6];
	माप_प्रकार miblen = आकार(mib);

	जर (name == रिक्त)
		परत 1;

	अंक = strtonum(name, 0, 255, &errstr);
	जर (errstr != रिक्त)
		परत 0;

	/* Check whether the table actually exists */
	स_रखो(mib, 0, आकार(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (पूर्णांक)अंक;
	जर (sysctl(mib, 6, &info, &miblen, रिक्त, 0) == -1)
		परत 0;

	परत 1;
#अन्यथा /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	परत 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
स्थिर शून्य
queue_listen_addr(ServerOptions *options, स्थिरांक अक्षर *addr,
    स्थिरांक अक्षर *rdomain, पूर्णांक port)
{
	संरचना queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->अंक_queued_listens, options->अंक_queued_listens + 1,
	    आकार(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->अंक_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == रिक्त ? रिक्त : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
स्थिर शून्य
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	संरचना queued_listenaddr *qla;

	जर (options->अंक_ports == 0)
		options->ports[options->अंक_ports++] = SSH_DEFAULT_PORT;
	जर (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	साठी (i = 0; i < options->अंक_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		मुक्त(qla->addr);
		मुक्त(qla->rdomain);
	}
	मुक्त(options->queued_listen_addrs);
	options->queued_listen_addrs = रिक्त;
	options->अंक_queued_listens = 0;
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

स्थिर पूर्णांक
match_cfg_ओळ_group(स्थिरांक अक्षर *grps, पूर्णांक ओळ, स्थिरांक अक्षर *user)
{
	पूर्णांक result = 0;
	संरचना passwd *pw;

	जर (user == रिक्त)
		जा out;

	जर ((pw = getpwnam(user)) == रिक्त) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", ओळ, user);
	} अन्यथा जर (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, ओळ);
	} अन्यथा जर (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, ओळ);
	} अन्यथा {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, ओळ);
		result = 1;
	}
out:
	ga_free();
	परत result;
}

स्थिर शून्य
match_test_missing_fatal(स्थिरांक अक्षर *criteria, स्थिरांक अक्षर *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
स्थिर पूर्णांक
match_cfg_ओळ(स्थिरांक अक्षर *full_ओळ, पूर्णांक *acp, अक्षर ***avp,
    पूर्णांक ओळ, संरचना connection_info *ci)
{
	पूर्णांक result = 1, attributes = 0, port;
	अक्षर *arg, *attrib = रिक्त, *oattrib;

	जर (ci == रिक्त) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_ओळ, ओळ);
	} अन्यथा {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_ओळ,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", ओळ);
	}

	पर्यंत ((oattrib = argv_next(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		जर (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			थांबा;
		}
		attrib = xstrdup(oattrib);
		arg = रिक्त;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		जर (strcasecmp(attrib, "all") == 0) {
			जर (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				जा out;
			}
			जर (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			जा out;
		}
		/* Criterion "invalid-user" also has no argument */
		जर (strcasecmp(attrib, "invalid-user") == 0) {
			जर (ci == रिक्त) {
				result = 0;
				जा next;
			}
			जर (ci->user_invalid == 0)
				result = 0;
			अन्यथा
				debug("matched invalid-user at line %d", ओळ);
			जा next;
		}

		/* Keep this list in sync with below */
		जर (strprefix(attrib, "user=", 1) != रिक्त ||
		    strprefix(attrib, "group=", 1) != रिक्त ||
		    strprefix(attrib, "host=", 1) != रिक्त ||
		    strprefix(attrib, "address=", 1) != रिक्त ||
		    strprefix(attrib, "localaddress=", 1) != रिक्त ||
		    strprefix(attrib, "localport=", 1) != रिक्त ||
		    strprefix(attrib, "rdomain=", 1) != रिक्त ||
		    strprefix(attrib, "version=", 1) != रिक्त) {
			arg = म_अक्षर(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		जर (arg == रिक्त || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			जा out;
		}
		जर (strcasecmp(attrib, "user") == 0) {
			जर (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				result = 0;
				जा next;
			}
			जर (ci->user == रिक्त)
				match_test_missing_fatal("User", "user");
			जर (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			अन्यथा
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, ओळ);
		} अन्यथा जर (strcasecmp(attrib, "group") == 0) {
			जर (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				result = 0;
				जा next;
			}
			जर (ci->user == रिक्त)
				match_test_missing_fatal("Group", "user");
			निवड (match_cfg_ओळ_group(arg, ओळ, ci->user)) {
			स्थिती -1:
				result = -1;
				जा out;
			स्थिती 0:
				result = 0;
			}
		} अन्यथा जर (strcasecmp(attrib, "host") == 0) {
			जर (ci == रिक्त || (ci->test && ci->host == रिक्त)) {
				result = 0;
				जा next;
			}
			जर (ci->host == रिक्त)
				match_test_missing_fatal("Host", "host");
			जर (match_hostname(ci->host, arg) != 1)
				result = 0;
			अन्यथा
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, ओळ);
		} अन्यथा जर (strcasecmp(attrib, "address") == 0) {
			जर (ci == रिक्त || (ci->test && ci->address == रिक्त)) {
				जर (addr_match_list(रिक्त, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, ओळ);
				result = 0;
				जा next;
			}
			जर (ci->address == रिक्त)
				match_test_missing_fatal("Address", "addr");
			निवड (addr_match_list(ci->address, arg)) {
			स्थिती 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, ओळ);
				थांबा;
			स्थिती 0:
			स्थिती -1:
				result = 0;
				थांबा;
			स्थिती -2:
				result = -1;
				जा out;
			}
		} अन्यथा जर (strcasecmp(attrib, "localaddress") == 0){
			जर (ci == रिक्त || (ci->test && ci->laddress == रिक्त)) {
				जर (addr_match_list(रिक्त, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    ओळ);
				result = 0;
				जा next;
			}
			जर (ci->laddress == रिक्त)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			निवड (addr_match_list(ci->laddress, arg)) {
			स्थिती 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, ओळ);
				थांबा;
			स्थिती 0:
			स्थिती -1:
				result = 0;
				थांबा;
			स्थिती -2:
				result = -1;
				जा out;
			}
		} अन्यथा जर (strcasecmp(attrib, "localport") == 0) {
			जर ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				जा out;
			}
			जर (ci == रिक्त || (ci->test && ci->lport == -1)) {
				result = 0;
				जा next;
			}
			जर (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			जर (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, ओळ);
			अन्यथा
				result = 0;
		} अन्यथा जर (strcasecmp(attrib, "rdomain") == 0) {
			जर (ci == रिक्त || (ci->test && ci->rdomain == रिक्त)) {
				result = 0;
				जा next;
			}
			जर (ci->rdomain == रिक्त)
				match_test_missing_fatal("RDomain", "rdomain");
			जर (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			अन्यथा
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, ओळ);
		} अन्यथा जर (strcasecmp(attrib, "version") == 0) {
			जर (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			अन्यथा
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, ओळ);
		} अन्यथा {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			जा out;
		}
 next:
		मुक्त(attrib);
		attrib = रिक्त;
	}
	जर (attributes == 0) {
		error("One or more attributes required for Match");
		परत -1;
	}
 out:
	जर (ci != रिक्त && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", ओळ);
	मुक्त(attrib);
	परत result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
संरचना multistate {
	अक्षर *किल्ली;
	पूर्णांक मूल्य;
};
स्थिर स्थिरांक संरचना multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
स्थिर स्थिरांक संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णांक
process_server_config_ओळ_depth(ServerOptions *options, अक्षर *ओळ,
    स्थिरांक अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep,
    संरचना connection_info *connectinfo, पूर्णांक *inc_flags, पूर्णांक depth,
    संरचना include_list *includes)
{
	अक्षर *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	पूर्णांक cmdline = 0, *intptr, मूल्य, value2, value3, n, port, oactive, r;
	द्विगुण dvalue, *doubleptr = रिक्त;
	पूर्णांक ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	माप_प्रकार len;
	दीर्घ दीर्घ val64;
	स्थिरांक संरचना multistate *multistate_ptr;
	स्थिरांक अक्षर *errstr;
	संरचना include_item *item;
	glob_t gbuf;
	अक्षर **oav = रिक्त, **av;
	पूर्णांक oac = 0, ac;
	पूर्णांक ret = -1;
	अक्षर **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	जर ((len = म_माप(ओळ)) == 0)
		परत 0;
	साठी (len--; len > 0; len--) {
		जर (म_अक्षर(WHITESPACE "\f", ओळ[len]) == रिक्त)
			थांबा;
		ओळ[len] = '\0';
	}

	str = ओळ;
	जर ((keyword = strdelim(&str)) == रिक्त)
		परत 0;
	/* Ignore leading whitespace */
	जर (*keyword == '\0')
		keyword = strdelim(&str);
	जर (!keyword || !*keyword || *keyword == '#')
		परत 0;
	जर (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		परत -1;
	}
	intptr = रिक्त;
	charptr = रिक्त;
	opcode = parse_token(keyword, filename, linenum, &flags);

	जर (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		परत -1;
	}
	ac = oac;
	av = oav;

	जर (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	जर (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	जर (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		जर (connectinfo == रिक्त) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} अन्यथा { /* this is a directive we have already processed */
			ret = 0;
			जा out;
		}
	}

	निवड (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	स्थिती sUsePAM:
		intptr = &options->use_pam;
		जा parse_flag;
	स्थिती sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;
#endif

	/* Standard Options */
	स्थिती sBadOption:
		जा out;
	स्थिती sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		जर (options->ports_from_cmdline) {
			argv_consume(&ac);
			थांबा;
		}
		जर (options->अंक_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->अंक_ports++] = a2port(arg);
		जर (options->ports[options->अंक_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		थांबा;

	स्थिती sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		जर ((मूल्य = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती sListenAddress:
		arg = argv_next(&ac, &av);
		जर (arg == रिक्त || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		जर (म_अक्षर(arg, '[') == रिक्त && (p = म_अक्षर(arg, ':')) != रिक्त
		    && म_अक्षर(p+1, ':') != रिक्त) {
			port = 0;
			p = arg;
		} अन्यथा {
			arg2 = रिक्त;
			p = hpdelim(&arg);
			जर (p == रिक्त)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			जर (arg == रिक्त)
				port = 0;
			अन्यथा जर ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = रिक्त;
		जर ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (म_भेद(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == रिक्त)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			जर (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		थांबा;

	स्थिती sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		मूल्य = -1;
		साठी (i = 0; multistate_ptr[i].किल्ली != रिक्त; i++) {
			जर (strcasecmp(arg, multistate_ptr[i].किल्ली) == 0) {
				मूल्य = multistate_ptr[i].मूल्य;
				थांबा;
			}
		}
		जर (मूल्य == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती s_Host_किल्ली:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		जर (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		थांबा;

	स्थिती s_Host_किल्ली_Agent:
		charptr = &options->host_किल्ली_agent;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		जर (*activep && *charptr == रिक्त)
			*charptr = !म_भेद(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		थांबा;

	स्थिती sHostCertificate:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		जर (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		थांबा;

	स्थिती sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		जर (*activep && *charptr == रिक्त) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			जर (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		थांबा;

	स्थिती sModuliFile:
		charptr = &options->moduli_file;
		जा parse_filename;

	स्थिती s_Permit_मूळ_Login:
		intptr = &options->permit_मूळ_login;
		multistate_ptr = multistate_permitrootlogin;
		जा parse_multistate;

	स्थिती sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		जा parse_multistate;

	स्थिती sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		जा parse_multistate;

	स्थिती sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		जा parse_flag;

	स्थिती sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		जा parse_flag;

	स्थिती sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		जर (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती s_Host_किल्ली_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		जा parse_pubkey_algos;

	स्थिती sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		जा parse_pubkey_algos;

	स्थिती sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		जा parse_flag;

	स्थिती sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		जा parse_pubkey_algos;

	स्थिती sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		मूल्य = 0;
		value2 = -1;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (strcasecmp(arg, "none") == 0)
				सुरूठेवा;
			जर (strcasecmp(arg, "touch-required") == 0)
				मूल्य |= PUBKEYAUTH_TOUCH_REQUIRED;
			अन्यथा जर (strcasecmp(arg, "verify-required") == 0)
				मूल्य |= PUBKEYAUTH_VERIFY_REQUIRED;
			अन्यथा जर (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				जर (errstr != रिक्त) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					जा out;
				}
			} अन्यथा {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				जा out;
			}
		}
		जर (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = मूल्य;
			options->max_pubkey_ok = value2;
		}
		थांबा;

#ifdef KRB5
	स्थिती sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		जा parse_flag;

	स्थिती sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		जा parse_flag;

	स्थिती sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		जा parse_flag;
#ifdef USE_AFS
	स्थिती sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		जा parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	स्थिती sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		जा parse_flag;

	स्थिती sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		जा parse_flag;

	स्थिती sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		जा parse_flag;

	स्थिती sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		जा parse_flag;
#endif /* GSSAPI */

	स्थिती sPasswordAuthentication:
		intptr = &options->password_authentication;
		जा parse_flag;

	स्थिती sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		जा parse_flag;

	स्थिती sPrintMotd:
		intptr = &options->print_motd;
		जा parse_flag;

#ifndef DISABLE_LASTLOG
	स्थिती sPrintLastLog:
		intptr = &options->print_lastlog;
		जा parse_flag;
#endif

	स्थिती sX11Forwarding:
		intptr = &options->x11_forwarding;
		जा parse_flag;

	स्थिती sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		जर ((errstr = atoi_err(arg, &मूल्य)) != रिक्त)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		जा parse_flag;

	स्थिती sXAuthLocation:
		charptr = &options->xauth_location;
		जा parse_filename;

	स्थिती sPermitTTY:
		intptr = &options->permit_tty;
		जा parse_flag;

	स्थिती sPermitUserRC:
		intptr = &options->permit_user_rc;
		जा parse_flag;

	स्थिती sStrictModes:
		intptr = &options->strict_modes;
		जा parse_flag;

	स्थिती sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		जा parse_multistate;

	स्थिती sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		जा parse_flag;

	स्थिती sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मूल्य = 0;
		p = रिक्त;
		जर (म_भेद(arg, "yes") == 0)
			मूल्य = 1;
		अन्यथा जर (म_भेद(arg, "no") == 0)
			मूल्य = 0;
		अन्यथा {
			/* Pattern-list specified */
			मूल्य = 1;
			p = xstrdup(arg);
		}
		जर (*activep && *intptr == -1) {
			*intptr = मूल्य;
			*charptr = p;
			p = रिक्त;
		}
		मुक्त(p);
		थांबा;

	स्थिती sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		जा parse_multistate;

	स्थिती sRekeyLimit:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (म_भेद(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			जर (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, म_त्रुटि(त्रुटि_सं));
			जर (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		जर (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		जर (ac != 0) { /* optional rekey interval present */
			जर (म_भेद(av[0], "none") == 0) {
				(शून्य)argv_next(&ac, &av);	/* discard */
				थांबा;
			}
			intptr = &options->rekey_interval;
			जा parse_time;
		}
		थांबा;

	स्थिती sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		जा parse_multistate;

	स्थिती sUseDNS:
		intptr = &options->use_dns;
		जा parse_flag;

	स्थिती sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		मूल्य = log_facility_संख्या(arg);
		जर (मूल्य == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		जर (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मूल्य;
		थांबा;

	स्थिती sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		मूल्य = log_level_संख्या(arg);
		जर (मूल्य == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		जर (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) मूल्य;
		थांबा;

	स्थिती sLogVerbose:
		found = options->अंक_log_verbose == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->log_verbose = strs;
			options->अंक_log_verbose = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		जा parse_multistate;

	स्थिती sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		जा parse_multistate;

	स्थिती sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		जा parse_flag;

	स्थिती sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		जर (म_भेदन(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			जर (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} अन्यथा जर (म_भेदन(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			जर (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} अन्यथा जर (म_भेद(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती sDisableForwarding:
		intptr = &options->disable_forwarding;
		जा parse_flag;

	स्थिती sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->अंक_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0' ||
			    match_user(रिक्त, रिक्त, रिक्त, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			जर (!*activep)
				सुरूठेवा;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		जर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		थांबा;

	स्थिती sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->अंक_deny_users;
		जा parse_allowdenyusers;

	स्थिती sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->अंक_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			जर (!*activep)
				सुरूठेवा;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		जर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		थांबा;

	स्थिती sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->अंक_deny_groups;
		जा parse_allowdenygroups;

	स्थिती sCiphers:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		जर (options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		थांबा;

	स्थिती sMacs:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		जर (options->macs == रिक्त)
			options->macs = xstrdup(arg);
		थांबा;

	स्थिती sKexAlgorithms:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		जर (options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		थांबा;

	स्थिती sSubsystem:
		जर ((arg = argv_next(&ac, &av)) == रिक्त || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == रिक्त || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (!*activep) {
			argv_consume(&ac);
			थांबा;
		}
		found = 0;
		साठी (i = 0; i < options->अंक_subsystems; i++) {
			जर (म_भेद(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				थांबा;
			}
		}
		जर (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			थांबा;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->अंक_subsystems,
		    options->अंक_subsystems + 1,
		    आकार(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->अंक_subsystems,
		    options->अंक_subsystems + 1,
		    आकार(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->अंक_subsystems,
		    options->अंक_subsystems + 1,
		    आकार(*options->subsystem_args));
		options->subsystem_name[options->अंक_subsystems] = xstrdup(arg);
		options->subsystem_command[options->अंक_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->अंक_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		मुक्त(arg2);
		मुक्त(arg);
		argv_consume(&ac);
		options->अंक_subsystems++;
		थांबा;

	स्थिती sMaxStartups:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		जर ((n = माला_पूछो(arg, "%d:%d:%d",
		    &मूल्य, &value2, &value3)) == 3) {
			जर (मूल्य > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} अन्यथा जर (n == 1) {
			value3 = मूल्य;
			value2 = -1;
		} अन्यथा {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		जर (मूल्य <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		जर (*activep && options->max_startups == -1) {
			options->max_startups_begin = मूल्य;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		थांबा;

	स्थिती sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		निवड (n = माला_पूछो(arg, "%d:%d", &मूल्य, &value2)) {
		स्थिती 2:
			जर (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		स्थिती 1:
			जर (मूल्य < 0 || मूल्य > 32)
				n = -1;
		}
		जर (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		जर (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = मूल्य;
			जर (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		थांबा;

	स्थिती sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (म_भेद(arg, "none") == 0) { /* no limit */
			मूल्य = पूर्णांक_उच्च;
		} अन्यथा {
			जर ((errstr = atoi_err(arg, &मूल्य)) != रिक्त)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		जर (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = मूल्य;
		थांबा;

	स्थिती sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		जर (addr_match_list(रिक्त, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती sPerSourcePenalties:
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			स्थिरांक अक्षर *q = रिक्त;

			found = 1;
			intptr = रिक्त;
			doubleptr = रिक्त;
			मूल्य = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			जर (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				जर (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				जर (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				सुरूठेवा;
			} अन्यथा जर ((q = strprefix(arg, "crash:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} अन्यथा जर ((q = strprefix(arg, "authfail:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} अन्यथा जर ((q = strprefix(arg, "invaliduser:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} अन्यथा जर ((q = strprefix(arg, "noauth:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} अन्यथा जर ((q = strprefix(arg, "grace-exceeded:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} अन्यथा जर ((q = strprefix(arg, "refuseconnection:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} अन्यथा जर ((q = strprefix(arg, "max:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} अन्यथा जर ((q = strprefix(arg, "min:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} अन्यथा जर ((q = strprefix(arg, "max-sources4:", 0)) != रिक्त) {
				intptr = &options->per_source_penalty.max_sources4;
				जर ((errstr = atoi_err(q, &मूल्य)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा जर ((q = strprefix(arg, "max-sources6:", 0)) != रिक्त) {
				intptr = &options->per_source_penalty.max_sources6;
				जर ((errstr = atoi_err(q, &मूल्य)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा जर (म_भेद(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अन्यथा जर (म_भेद(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अन्यथा जर (म_भेद(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अन्यथा जर (म_भेद(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अन्यथा {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			जर (doubleptr != रिक्त) {
				जर ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				जर (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} अन्यथा जर (intptr != रिक्त) {
				जर (*activep && *intptr == -1) {
					*intptr = मूल्य;
					options->per_source_penalty.enabled = 1;
				}
			} अन्यथा {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		जर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		थांबा;

	स्थिती sMaxAuthTries:
		intptr = &options->max_authtries;
		जा parse_int;

	स्थिती sMaxSessions:
		intptr = &options->max_sessions;
		जा parse_int;

	स्थिती sBanner:
		charptr = &options->banner;
		जा parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	स्थिती s_Authorized_किल्ल्या_File:
		uintptr = &options->अंक_authkeys_files;
		chararrayptr = &options->authorized_किल्ल्या_files;
 parse_filenames:
		found = *uintptr == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (*activep && *charptr == रिक्त) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			जर (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		थांबा;

	स्थिती sClientAliveInterval:
		intptr = &options->client_alive_interval;
		जा parse_time;

	स्थिती s_Client_Alive_मोजणी_Max:
		intptr = &options->client_alive_मोजणी_max;
		जा parse_int;

	स्थिती sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0' || म_अक्षर(arg, '=') != रिक्त)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			जर (!*activep)
				सुरूठेवा;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->अंक_accept_env,
			    arg);
		}
		जर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		थांबा;

	स्थिती sSetEnv:
		found = options->अंक_setenv == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg == '\0' || म_अक्षर(arg, '=') == रिक्त)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			जर (lookup_setenv_in_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				सुरूठेवा;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->setenv = strs;
			options->अंक_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मूल्य = -1;
		साठी (i = 0; tunmode_desc[i].val != -1; i++)
			जर (म_भेद(tunmode_desc[i].text, arg) == 0) {
				मूल्य = tunmode_desc[i].val;
				थांबा;
			}
		जर (मूल्य == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		जर (*activep && *intptr == -1)
			*intptr = मूल्य;
		थांबा;

	स्थिती sInclude:
		जर (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		मूल्य = 0;
		पर्यंत ((arg2 = argv_next(&ac, &av)) != रिक्त) {
			जर (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जा out;
			}
			मूल्य++;
			found = 0;
			जर (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} अन्यथा
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				जर (म_भेद(item->selector, arg) != 0)
					सुरूठेवा;
				जर (item->filename != रिक्त) {
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
			जर (found != 0) {
				मुक्त(arg);
				सुरूठेवा;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			जर ((r = glob(arg, 0, रिक्त, &gbuf)) != 0) {
				जर (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, आकार(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			जर (gbuf.gl_pathc > पूर्णांक_उच्च)
				fatal_f("too many glob results");
			साठी (n = 0; n < (पूर्णांक)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, आकार(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				जर ((item->contents = sshbuf_new()) == रिक्त)
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
			मुक्त(arg);
		}
		जर (मूल्य == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		थांबा;

	स्थिती sMatch:
		जर (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		मूल्य = match_cfg_ओळ(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? रिक्त : connectinfo));
		जर (मूल्य < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : मूल्य;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		थांबा;

	स्थिती sPermitListen:
	स्थिती sPermitOpen:
		जर (opcode == sPermitListen) {
			uintptr = &options->अंक_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} अन्यथा {
			uintptr = &options->अंक_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (म_भेद(arg, "any") == 0 ||
			    म_भेद(arg, "none") == 0) {
				जर (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				सुरूठेवा;
			}

			जर (opcode == sPermitListen &&
			    म_अक्षर(arg, ':') == रिक्त) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} अन्यथा {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				जर (p == रिक्त) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			जर (arg == रिक्त ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती sForceCommand:
		जर (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		जर (*activep && options->adm_forced_command == रिक्त)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		थांबा;

	स्थिती sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_किल्ल्या;
		जा parse_filename;

	स्थिती s_Revoked_किल्ल्या:
		uintptr = &options->अंक_revoked_किल्ल्या_files;
		chararrayptr = &options->revoked_किल्ल्या_files;
		जा parse_filenames;

	स्थिती s_Security_किल्ली_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (*activep && *charptr == रिक्त) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			जर (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		थांबा;

	स्थिती sIPQoS:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर ((मूल्य = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		जर (मूल्य == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मूल्य = पूर्णांक_उच्च;
		}
		arg = argv_next(&ac, &av);
		जर (arg == रिक्त)
			value2 = मूल्य;
		अन्यथा जर ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		जर (value2 == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = पूर्णांक_उच्च;
		}
		जर (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मूल्य;
			options->ip_qos_bulk = value2;
		}
		थांबा;

	स्थिती sVersionAddendum:
		जर (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		जर (म_अक्षर(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		जर ((arg = म_अक्षर(ओळ, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(ओळ);
		}
		जर (*activep && options->version_addendum == रिक्त) {
			जर (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अन्यथा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		थांबा;

	स्थिती s_Authorized_किल्ल्या_Command:
		charptr = &options->authorized_किल्ल्या_command;
 parse_command:
		len = म_अखोज(str, WHITESPACE);
		जर (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		थांबा;

	स्थिती s_Authorized_किल्ल्या_Command_User:
		charptr = &options->authorized_किल्ल्या_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		जा parse_command;

	स्थिती sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		जा parse_localuser;

	स्थिती sAuthenticationMethods:
		found = options->अंक_auth_methods == 0;
		मूल्य = 0; /* seen "any" pseudo-method */
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			जर (म_भेद(arg, "any") == 0) {
				जर (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				मूल्य = 1;
			} अन्यथा जर (मूल्य) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} अन्यथा जर (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->auth_methods = strs;
			options->अंक_auth_methods = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		मूल्य = म_से_दीर्घ(arg, &p, 8);
		जर (arg == p || मूल्य < 0 || मूल्य > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		जर (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मूल्य;
		थांबा;

	स्थिती sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		जा parse_flag;

	स्थिती sFingerprintHash:
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर ((मूल्य = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		जर (*activep)
			options->fingerprint_hash = मूल्य;
		थांबा;

	स्थिती sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		जा parse_flag;

	स्थिती sRDomain:
#जर !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		जर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		जर (strcasecmp(arg, "none") != 0 && म_भेद(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		जर (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		थांबा;

	स्थिती sRequiredRSASize:
		intptr = &options->required_rsa_size;
		जा parse_int;

	स्थिती sChannelTimeout:
		found = options->अंक_channel_timeouts == 0;
		पर्यंत ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			जर (strcasecmp(arg, "none") == 0) {
				जर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जा out;
				}
			} अन्यथा जर (parse_pattern_interval(arg,
			    रिक्त, रिक्त) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जर (found && *activep) {
			options->channel_timeouts = strs;
			options->अंक_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		थांबा;

	स्थिती sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		जर (av[0] != रिक्त && strcasecmp(av[0], "none") == 0) {
			(शून्य)argv_next(&ac, &av); /* consume arg */
			जर (*activep)
				*intptr = 0;
			थांबा;
		}
		जा parse_time;

	स्थिती sSshdSessionPath:
		charptr = &options->sshd_session_path;
		जा parse_filename;

	स्थिती sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		जा parse_filename;

	स्थिती sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		जा parse_multistate;

	स्थिती sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		जा parse_multistate;

	स्थिती sDeprecated:
	स्थिती sIgnore:
	स्थिती sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		थांबा;

	पूर्वनिर्धारित:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	जर (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		जा out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	परत ret;
}

पूर्णांक
process_server_config_ओळ(ServerOptions *options, अक्षर *ओळ,
    स्थिरांक अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep,
    संरचना connection_info *connectinfo, संरचना include_list *includes)
{
	पूर्णांक inc_flags = 0;

	परत process_server_config_ओळ_depth(options, ओळ, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

शून्य
load_server_config(स्थिरांक अक्षर *filename, संरचना sshbuf *conf)
{
	संरचना stat st;
	अक्षर *ओळ = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	खाता *f;
	पूर्णांक r;

	debug2_f("filename %s", filename);
	जर ((f = ख_खोलो(filename, "r")) == रिक्त) {
		लिखो_त्रुटि(filename);
		निकास(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	जर (ख_स्थिति(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = ओळ + म_अखोज(ओळ, " \t\r");
		जर ((r = sshbuf_put(conf, cp, म_माप(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	मुक्त(ओळ);
	जर ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	ख_बंद(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

शून्य
parse_server_match_config(ServerOptions *options,
   संरचना include_list *includes, संरचना connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

पूर्णांक
parse_server_match_testspec(संरचना connection_info *ci, अक्षर *spec)
{
	अक्षर *p;
	स्थिरांक अक्षर *val;

	पर्यंत ((p = strsep(&spec, ",")) && *p != '\0') {
		जर ((val = strprefix(p, "addr=", 0)) != रिक्त) {
			ci->address = xstrdup(val);
		} अन्यथा जर ((val = strprefix(p, "host=", 0)) != रिक्त) {
			ci->host = xstrdup(val);
		} अन्यथा जर ((val = strprefix(p, "user=", 0)) != रिक्त) {
			ci->user = xstrdup(val);
		} अन्यथा जर ((val = strprefix(p, "laddr=", 0)) != रिक्त) {
			ci->laddress = xstrdup(val);
		} अन्यथा जर ((val = strprefix(p, "rdomain=", 0)) != रिक्त) {
			ci->rdomain = xstrdup(val);
		} अन्यथा जर ((val = strprefix(p, "lport=", 0)) != रिक्त) {
			ci->lport = a2port(val);
			जर (ci->lport == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				परत -1;
			}
		} अन्यथा जर (म_भेद(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Invalid test mode specification %s\n",
			    p);
			परत -1;
		}
	}
	परत 0;
}

शून्य
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	साठी (i = 0; i < src->अंक_subsystems; i++) {
		found = 0;
		साठी (j = 0; j < dst->अंक_subsystems; j++) {
			जर (म_भेद(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				थांबा;
			}
		}
		जर (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			मुक्त(dst->subsystem_command[j]);
			मुक्त(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			सुरूठेवा;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->अंक_subsystems,
		    dst->अंक_subsystems + 1, आकार(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->अंक_subsystems,
		    dst->अंक_subsystems + 1, आकार(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->अंक_subsystems,
		    dst->अंक_subsystems + 1, आकार(*dst->subsystem_args));
		j = dst->अंक_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

स्थिर पूर्णांक
serialise_s32(संरचना sshbuf *buf, पूर्णांक v)
{
	uint32_t uv;
	पूर्णांक r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	जर ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
serialise_s64(संरचना sshbuf *buf, int64_t v)
{
	uint64_t uv;
	पूर्णांक r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	जर ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
serialise_mode(संरचना sshbuf *buf, mode_t v)
{
	u_int uv;

	जर (v == (mode_t)-1)
		परत serialise_s32(buf, -1);
	uv = (u_int)v;
	जर ((mode_t)uv != v || uv > 0777)
		परत SSH_ERR_INVALID_FORMAT;
	परत serialise_s32(buf, (पूर्णांक)uv);
}

स्थिर पूर्णांक
serialise_double(संरचना sshbuf *buf, द्विगुण v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	परत sshbuf_put(buf, &v, आकार(v));
}

स्थिर पूर्णांक
serialise_nullable_string(संरचना sshbuf *buf, स्थिरांक अक्षर *s)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u8(buf, s != रिक्त)) != 0)
		परत r;
	जर (s == रिक्त)
		परत 0;
	परत sshbuf_put_cstring(buf, s);
}

स्थिर पूर्णांक
serialise_nullable_string_array(संरचना sshbuf *buf, अक्षर **a, u_int n)
{
	पूर्णांक r;
	u_int i;

	जर ((r = sshbuf_put_u32(buf, n)) != 0)
		परत r;
	साठी (i = 0; i < n; i++) {
		जर ((r = serialise_nullable_string(buf, a[i])) != 0)
			परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_hostkeyfile(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	जर ((r = sshbuf_put_u32(buf, options->अंक_host_किल्ली_files)) != 0) {
		error_fr(r, "serialise length");
		परत r;
	}
	साठी (i = 0; i < options->अंक_host_किल्ली_files; i++) {
		जर ((r = serialise_s32(buf,
		    options->host_किल्ली_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_किल्ली_files[i])) != 0) {
			error_fr(r, "serialise member");
			परत r;
		}
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_ipqos(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_listenaddress(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	जर ((r = sshbuf_put_u32(buf, options->अंक_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		परत r;
	}
	साठी (i = 0; i < options->अंक_queued_listens; i++) {
		स्थिरांक संरचना queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		जर ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			परत r;
		}
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_logfacility(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, (पूर्णांक)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_loglevel(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, (पूर्णांक)options->log_level)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_port(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	जर ((r = sshbuf_put_u32(buf, options->अंक_ports)) != 0) {
		error_fr(r, "serialise length");
		परत r;
	}
	साठी (i = 0; i < options->अंक_ports; i++) {
		जर ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			परत r;
		}
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_gatewayports(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_streamlocalbindmask(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_streamlocalbindunlink(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_maxstartups(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_permituserenv(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_persourcenetblocksize(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_persourcepenalties(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	स्थिरांक संरचना per_source_penalty *psp = &options->per_source_penalty;
	पूर्णांक r;

	जर ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_rekeylimit(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
serialise_subsystem(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	जर ((r = sshbuf_put_u32(buf, options->अंक_subsystems)) != 0) {
		error_fr(r, "serialise length");
		परत r;
	}
	साठी (i = 0; i < options->अंक_subsystems; i++) {
		जर ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			परत r;
		}
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_pubkey_auth_options(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
serialise_timingsecret(स्थिरांक ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		परत r;
	}
	परत 0;
}


पूर्णांक
serialise_server_options(स्थिरांक ServerOptions *options, संरचना sshbuf **bufp)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*bufp = रिक्त;

	जर ((buf = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		जा out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	जर ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जा out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	जर ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जा out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	जर ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जा out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	जर ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जा out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	जर ((r = serialise_##funcsuffix(options, buf)) != 0) \
		जा out;
#define SSHCONF_NONCONF(funcsuffix) \
	जर ((r = serialise_##funcsuffix(options, buf)) != 0) \
		जा out;
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
	buf = रिक्त; /* transferred */
 out:
	sshbuf_free(buf);
	परत r;
}

स्थिर पूर्णांक
deserialise_s32(संरचना sshbuf *buf, पूर्णांक *v)
{
	uint32_t tmp;
	पूर्णांक r;
	u_char was_signed;

	जर ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		परत r;
	जर (was_signed > 1)
		परत SSH_ERR_INVALID_FORMAT;
	जर (was_signed) {
		जर (tmp > (uint32_t)पूर्णांक_उच्च + 1)
			परत SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)पूर्णांक_उच्च + 1 ? पूर्णांक_न्यून : -(पूर्णांक)tmp;
	} अन्यथा {
		जर (tmp > पूर्णांक_उच्च)
			परत SSH_ERR_INVALID_FORMAT;
		*v = (पूर्णांक)tmp;
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_s64(संरचना sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	पूर्णांक r;
	u_char was_signed;

	जर ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		परत r;
	जर (was_signed > 1)
		परत SSH_ERR_INVALID_FORMAT;
	जर (was_signed) {
		जर (tmp > (uint64_t)INT64_MAX + 1)
			परत SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} अन्यथा {
		जर (tmp > INT64_MAX)
			परत SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_mode(संरचना sshbuf *buf, mode_t *v)
{
	पूर्णांक r, tmp;

	जर ((r = deserialise_s32(buf, &tmp)) != 0)
		परत r;
	जर (tmp == -1) {
		*v = (mode_t)-1;
		परत 0;
	}
	जर (tmp < 0 || tmp > 0777)
		परत SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	परत 0;
}

स्थिर पूर्णांक
deserialise_double(संरचना sshbuf *buf, द्विगुण *v)
{
	परत sshbuf_get(buf, v, आकार(*v));
}

स्थिर पूर्णांक
deserialise_nullable_string(संरचना sshbuf *buf, अक्षर **sp)
{
	पूर्णांक r;
	u_char present;

	जर ((r = sshbuf_get_u8(buf, &present)) != 0)
		परत r;
	जर (present == 0) {
		*sp = रिक्त;
		परत 0;
	}
	जर (present != 1)
		परत SSH_ERR_INVALID_FORMAT;
	परत sshbuf_get_cstring(buf, sp, रिक्त);
}

स्थिर शून्य
free_string_array(अक्षर **a, u_int n)
{
	u_int i;

	जर (a == रिक्त)
		परत;
	साठी (i = 0; i < n; i++)
		मुक्त(a[i]);
	मुक्त(a);
}

स्थिर पूर्णांक
deserialise_मोजणी(संरचना sshbuf *buf, u_int *np, स्थिरांक अक्षर *what)
{
	पूर्णांक r;
	uint32_t n;

	जर ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		परत r;
	}
	जर (n > अच_पूर्णांक_उच्च) {
		error_f("bad number of %s", what);
		परत SSH_ERR_INVALID_FORMAT;
	}
	जर (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		परत SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	परत 0;
}

स्थिर पूर्णांक
deserialise_nullable_string_array(संरचना sshbuf *buf, अक्षर ***arrayp,
    u_int *np)
{
	अक्षर **a = रिक्त;
	पूर्णांक r;
	u_int i, n;

	*arrayp = रिक्त;
	*np = 0;
	जर ((r = deserialise_मोजणी(buf, &n, "strings")) != 0)
		परत r;
	जर (n > 0)
		a = xcalloc(n, आकार(*a));
	साठी (i = 0; i < n; i++) {
		जर ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			परत r;
		}
	}
	*arrayp = a;
	*np = n;
	परत 0;
}

स्थिर शून्य
free_queued_listen_addrs(संरचना queued_listenaddr *qla, u_int n)
{
	u_int i;

	जर (qla == रिक्त)
		परत;
	साठी (i = 0; i < n; i++) {
		मुक्त(qla[i].addr);
		मुक्त(qla[i].rdomain);
	}
	मुक्त(qla);
}

स्थिर पूर्णांक
deserialise_hostkeyfile(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r, *userprovided = रिक्त;
	u_int i, n;
	अक्षर **files = रिक्त;

	जर ((r = deserialise_मोजणी(buf, &n, "host key files")) != 0)
		परत r;
	जर (n > 0) {
		userprovided = xcalloc(n, आकार(*userprovided));
		files = xcalloc(n, आकार(*files));
	}
	साठी (i = 0; i < n; i++) {
		जर ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			मुक्त(userprovided);
			परत r;
		}
	}
	options->अंक_host_किल्ली_files = n;
	options->host_किल्ली_file_userprovided = userprovided;
	options->host_किल्ली_files = files;
	परत 0;
}

स्थिर पूर्णांक
deserialise_ipqos(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
deserialise_listenaddress(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i, n;
	संरचना queued_listenaddr *qla = रिक्त;

	जर ((r = deserialise_मोजणी(buf, &n, "listen addresses")) != 0)
		परत r;
	जर (n > 0)
		qla = xcalloc(n, आकार(*qla));
	साठी (i = 0; i < n; i++) {
		जर ((r = sshbuf_get_cstring(buf, &qla[i].addr, रिक्त)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			परत r;
		}
	}
	options->अंक_queued_listens = n;
	options->queued_listen_addrs = qla;
	परत 0;
}

स्थिर पूर्णांक
deserialise_logfacility(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r, tmp;

	जर ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	जर (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == रिक्त) {
		error_f("bad syslog facility");
		परत SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	परत 0;
}

स्थिर पूर्णांक
deserialise_loglevel(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r, tmp;

	जर ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	जर (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == रिक्त) {
		error_f("bad log level");
		परत SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	परत 0;
}

स्थिर पूर्णांक
deserialise_port(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i, n;

	जर ((r = deserialise_मोजणी(buf, &n, "ports")) != 0)
		परत r;
	जर (n > MAX_PORTS) {
		error_f("bad number of ports");
		परत SSH_ERR_INVALID_FORMAT;
	}
	options->अंक_ports = n;
	स_रखो(options->ports, 0, आकार(options->ports));
	साठी (i = 0; i < options->अंक_ports; i++) {
		जर ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			परत r;
		}
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_gatewayports(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_streamlocalbindmask(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_streamlocalbindunlink(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_char tmp;

	जर ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	जर (tmp > 1) {
		error_f("bad boolean");
		परत SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	परत 0;
}

स्थिर पूर्णांक
deserialise_maxstartups(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
deserialise_permituserenv(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_persourcenetblocksize(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
deserialise_persourcepenalties(ServerOptions *options, संरचना sshbuf *buf)
{
	संरचना per_source_penalty *psp = &options->per_source_penalty;
	पूर्णांक r;

	जर ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
deserialise_rekeylimit(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}

	परत 0;
}

स्थिर पूर्णांक
deserialise_subsystem(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;
	u_int i, n;
	अक्षर **names = रिक्त, **commands = रिक्त, **args = रिक्त;

	जर ((r = deserialise_मोजणी(buf, &n, "subsystems")) != 0)
		परत r;
	जर (n > 0) {
		names = xcalloc(n, आकार(*names));
		commands = xcalloc(n, आकार(*names));
		args = xcalloc(n, आकार(*args));
	}
	साठी (i = 0; i < n; i++) {
		जर ((r = sshbuf_get_cstring(buf, names + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, रिक्त)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			परत r;
		}
	}
	options->अंक_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	परत 0;
}

स्थिर पूर्णांक
deserialise_pubkey_auth_options(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
deserialise_timingsecret(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णांक r;

	जर ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		परत r;
	}
	परत 0;
}

पूर्णांक
deserialise_server_options(संरचना sshbuf *buf, ServerOptions *options)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	जर ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		जा out;
	}
	जर (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	जर ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जा out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	जर ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जा out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	जर ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जा out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	जर ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जा out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	जर ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		जा out;
#define SSHCONF_NONCONF(funcsuffix) \
	जर ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		जा out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करा { \
		मुक्त(new_options.var); \
		new_options.var = रिक्त; \
	} पर्यंत (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	जर (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
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
	स_रखो(&new_options, 0, आकार(new_options));
 out:
	free_server_options(&new_options);
	परत r;
}

स्थिर शून्य
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	साठी (i = 0; i < options->अंक_host_किल्ली_files; i++)
		मुक्त(options->host_किल्ली_files[i]);
	मुक्त(options->host_किल्ली_files);
	मुक्त(options->host_किल्ली_file_userprovided);
}

स्थिर शून्य
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->अंक_queued_listens);

	साठी (i = 0; i < options->अंक_listen_addrs; i++) {
		मुक्त(options->listen_addrs[i].rdomain);
		जर (options->listen_addrs[i].addrs != रिक्त)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	मुक्त(options->listen_addrs);
}

स्थिर शून्य
free_permituserenv(ServerOptions *options)
{
	मुक्त(options->permit_user_env_allowlist);
}

स्थिर शून्य
free_subsystem(ServerOptions *options)
{
	u_int i;

	साठी (i = 0; i < options->अंक_subsystems; i++) {
		मुक्त(options->subsystem_name[i]);
		मुक्त(options->subsystem_command[i]);
		मुक्त(options->subsystem_args[i]);
	}
	मुक्त(options->subsystem_name);
	मुक्त(options->subsystem_command);
	मुक्त(options->subsystem_args);
}

शून्य
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		मुक्त(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करा { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} पर्यंत (0);
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

स्थिर शून्य
copy_server_option_int(पूर्णांक *dst, पूर्णांक src)
{
	जर (src != -1)
		*dst = src;
}

स्थिर शून्य
copy_server_option_int64(int64_t *dst, int64_t src)
{
	जर (src != -1)
		*dst = src;
}

स्थिर शून्य
copy_server_option_string(अक्षर **dst, स्थिरांक अक्षर *src)
{
	जर (src != रिक्त && *dst != src) {
		मुक्त(*dst);
		*dst = xstrdup(src);
	}
}

स्थिर शून्य
copy_server_option_strarray_मूल्ये(अक्षर ***dst, u_int ndst,
    अक्षर * स्थिरांक *src, u_int nsrc)
{
	u_int i;

	जर (nsrc == 0)
		परत;
	साठी (i = 0; i < ndst; i++)
		मुक्त((*dst)[i]);
	मुक्त(*dst);
	*dst = xcalloc(nsrc, आकार(**dst));
	साठी (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == रिक्त ? रिक्त : xstrdup(src[i]);
}

स्थिर शून्य
copy_server_option_strarray(अक्षर ***dst, u_int *ndst,
    अक्षर * स्थिरांक *src, u_int nsrc)
{
	जर (nsrc == 0)
		परत;
	copy_server_option_strarray_मूल्ये(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

स्थिर शून्य
copy_ipqos(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

स्थिर शून्य
copy_gatewayports(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

स्थिर शून्य
copy_streamlocalbindunlink(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

स्थिर शून्य
copy_loglevel(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	जर (src->log_level != -1)
		dst->log_level = src->log_level;
}

स्थिर शून्य
copy_rekeylimit(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

स्थिर शून्य
copy_subsystem(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	u_int old_अंक_subsystems = dst->अंक_subsystems;

	जर (src->अंक_subsystems == 0)
		परत;
	copy_server_option_strarray_मूल्ये(&dst->subsystem_name,
	    old_अंक_subsystems, src->subsystem_name, src->अंक_subsystems);
	copy_server_option_strarray_मूल्ये(&dst->subsystem_command,
	    old_अंक_subsystems, src->subsystem_command, src->अंक_subsystems);
	copy_server_option_strarray_मूल्ये(&dst->subsystem_args,
	    old_अंक_subsystems, src->subsystem_args, src->अंक_subsystems);
	dst->अंक_subsystems = src->अंक_subsystems;
}

स्थिर शून्य
copy_pubkey_auth_options(ServerOptions *dst, स्थिरांक ServerOptions *src)
{
	जर (src->pubkey_auth_options != -1) {
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
शून्य
copy_set_server_options(ServerOptions *dst, ServerOptions *src, पूर्णांक preauth)
{
	जर (dst == src)
		परत;

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
	करा { \
		मुक्त(dst->var); \
		dst->var = रिक्त; \
	} पर्यंत (0);
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
	जर (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	करा { \
		जर (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} पर्यंत(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_किल्ल्या);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	जर (preauth)
		परत;

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
स्थिर शून्य
parse_server_config_depth(ServerOptions *options, स्थिरांक अक्षर *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णांक flags, पूर्णांक *activep, पूर्णांक depth)
{
	पूर्णांक linenum, bad_options = 0;
	अक्षर *cp, *obuf, *cbuf;

	जर (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	जर ((obuf = cbuf = sshbuf_dup_string(conf)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	पर्यंत ((cp = strsep(&cbuf, "\n")) != रिक्त) {
		जर (process_server_config_ओळ_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	मुक्त(obuf);
	जर (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

शून्य
parse_server_config(ServerOptions *options, स्थिरांक अक्षर *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णांक reexec)
{
	पूर्णांक active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	जर (!reexec)
		process_queued_listen_addrs(options);
}

स्थिर स्थिरांक अक्षर *
fmt_multistate_int(पूर्णांक val, स्थिरांक संरचना multistate *m)
{
	u_int i;

	साठी (i = 0; m[i].किल्ली != रिक्त; i++) {
		जर (m[i].मूल्य == val)
			परत m[i].किल्ली;
	}
	परत "UNKNOWN";
}

स्थिर स्थिरांक अक्षर *
fmt_intarg(ServerOpCodes code, पूर्णांक val)
{
	जर (val == -1)
		परत "unset";
	निवड (code) {
	स्थिती sAddressFamily:
		परत fmt_multistate_int(val, multistate_addressfamily);
	स्थिती s_Permit_मूळ_Login:
		परत fmt_multistate_int(val, multistate_permitrootlogin);
	स्थिती sGatewayPorts:
		परत fmt_multistate_int(val, multistate_gatewayports);
	स्थिती sCompression:
		परत fmt_multistate_int(val, multistate_compression);
	स्थिती sAllowTcpForwarding:
		परत fmt_multistate_int(val, multistate_tcpfwd);
	स्थिती sAllowStreamLocalForwarding:
		परत fmt_multistate_int(val, multistate_tcpfwd);
	स्थिती sIgnoreRhosts:
		परत fmt_multistate_int(val, multistate_ignore_rhosts);
	स्थिती sTCPKeepAlive:
		परत fmt_multistate_int(val, multistate_keepalives);
	स्थिती sWarnWeakCrypto:
		परत fmt_multistate_int(val, multistate_warnweakcrypto);
	स्थिती sFingerprintHash:
		परत ssh_digest_alg_name(val);
	पूर्वनिर्धारित:
		निवड (val) {
		स्थिती 0:
			परत "no";
		स्थिती 1:
			परत "yes";
		पूर्वनिर्धारित:
			परत "UNKNOWN";
		}
	}
}

स्थिर शून्य
dump_cfg_int(ServerOpCodes code, पूर्णांक val)
{
	जर (code == sUnusedConnectionTimeout && val == 0) {
		म_लिखो("%s none\n", lookup_opcode_name(code));
		परत;
	}
	म_लिखो("%s %d\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_oct(ServerOpCodes code, पूर्णांक val)
{
	म_लिखो("%s 0%o\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_fmtint(ServerOpCodes code, पूर्णांक val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

स्थिर शून्य
dump_cfg_string(ServerOpCodes code, स्थिरांक अक्षर *val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code),
	    val == रिक्त ? "none" : val);
}

स्थिर शून्य
dump_cfg_strarray(ServerOpCodes code, u_int मोजणी, अक्षर **vals)
{
	u_int i;

	साठी (i = 0; i < मोजणी; i++)
		म_लिखो("%s %s\n", lookup_opcode_name(code), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(ServerOpCodes code, u_int मोजणी, अक्षर **vals)
{
	u_int i;

	निवड (code) {
	स्थिती sAuthenticationMethods:
	स्थिती sChannelTimeout:
		थांबा;
	पूर्वनिर्धारित:
		जर (मोजणी <= 0)
			परत;
		थांबा;
	}

	म_लिखो("%s", lookup_opcode_name(code));
	साठी (i = 0; i < मोजणी; i++)
		म_लिखो(" %s",  vals[i]);
	जर (code == sAuthenticationMethods && मोजणी == 0)
		म_लिखो(" any");
	अन्यथा जर (code == sChannelTimeout && मोजणी == 0)
		म_लिखो(" none");
	म_लिखो("\n");
}

स्थिर अक्षर *
format_listen_addrs(संरचना listenaddr *la)
{
	पूर्णांक r;
	संरचना addrinfo *ai;
	अक्षर addr[NI_MAXHOST], port[NI_MAXSERV];
	अक्षर *laddr1 = xstrdup(""), *laddr2 = रिक्त;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	साठी (ai = la->addrs; ai; ai = ai->ai_next) {
		जर ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    आकार(addr), port, आकार(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			सुरूठेवा;
		}
		laddr2 = laddr1;
		जर (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		} अन्यथा {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		}
		मुक्त(laddr2);
	}
	परत laddr1;
}

शून्य
dump_config(ServerOptions *o)
{
	अक्षर *s;
	u_int i;

	/* these are usually at the top of the config */
	साठी (i = 0; i < o->अंक_ports; i++)
		म_लिखो("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	साठी (i = 0; i < o->अंक_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		म_लिखो("%s", s);
		मुक्त(s);
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
	dump_cfg_int(s_Client_Alive_मोजणी_Max, o->client_alive_मोजणी_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_मूळ_Login, o->permit_मूळ_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_किल्ल्या);
	dump_cfg_string(s_Security_किल्ली_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_किल्ल्या_Command, o->authorized_किल्ल्या_command);
	dump_cfg_string(s_Authorized_किल्ल्या_Command_User, o->authorized_किल्ल्या_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_किल्ली_Agent, o->host_किल्ली_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_किल्ली_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#जर defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_किल्ल्या_File, o->अंक_authkeys_files,
	    o->authorized_किल्ल्या_files);
	dump_cfg_strarray_oneline(s_Revoked_किल्ल्या, o->अंक_revoked_किल्ल्या_files,
	    o->revoked_किल्ल्या_files);
	dump_cfg_strarray(s_Host_किल्ली, o->अंक_host_किल्ली_files, o->host_किल्ली_files);
	dump_cfg_strarray(sHostCertificate, o->अंक_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->अंक_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->अंक_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->अंक_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->अंक_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->अंक_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->अंक_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->अंक_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->अंक_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->अंक_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	साठी (i = 0; i < o->अंक_subsystems; i++)
		म_लिखो("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	म_लिखो("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	म_लिखो("PerSourceMaxStartups ");
	जर (o->per_source_max_startups == पूर्णांक_उच्च)
		म_लिखो("none\n");
	अन्यथा
		म_लिखो("%d\n", o->per_source_max_startups);
	म_लिखो("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = रिक्त;
	साठी (i = 0; tunmode_desc[i].val != -1; i++) {
		जर (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			थांबा;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	म_लिखो("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	म_लिखो("%s\n", iptos2str(o->ip_qos_bulk));

	म_लिखो("RekeyLimit %llu %d\n", (अचिन्हित दीर्घ दीर्घ)o->rekey_limit,
	    o->rekey_interval);

	म_लिखो("PermitOpen");
	जर (o->अंक_permitted_opens == 0)
		म_लिखो(" any");
	अन्यथा {
		साठी (i = 0; i < o->अंक_permitted_opens; i++)
			म_लिखो(" %s", o->permitted_opens[i]);
	}
	म_लिखो("\n");
	म_लिखो("PermitListen");
	जर (o->अंक_permitted_listens == 0)
		म_लिखो(" any");
	अन्यथा {
		साठी (i = 0; i < o->अंक_permitted_listens; i++)
			म_लिखो(" %s", o->permitted_listens[i]);
	}
	म_लिखो("\n");

	जर (o->permit_user_env_allowlist == रिक्त) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} अन्यथा {
		म_लिखो("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	म_लिखो("PubkeyAuthOptions");
	जर (o->pubkey_auth_options == 0)
		म_लिखो(" none");
	जर (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		म_लिखो(" touch-required");
	जर (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		म_लिखो(" verify-required");
	जर (o->max_pubkey_ok != -1)
		म_लिखो(" max-pk-ok:%d", o->max_pubkey_ok);
	म_लिखो("\n");

	जर (o->per_source_penalty.enabled) {
		म_लिखो("PerSourcePenalties crash:%f authfail:%f noauth:%f "
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
	} अन्यथा
		म_लिखो("PerSourcePenalties no\n");
}
