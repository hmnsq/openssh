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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/stat.h>
#ifdef __OpenBSD__
#அந்தர்பாவ <sys/sysctl.h>
#endif

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#அந்தர்பாவ <net/route.h>
#endif

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <util.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "groupaccess.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#எனில் !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

நிலையான வெறுமை add_listen_addr(ServerOptions *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, முழு);
நிலையான வெறுமை add_one_listen_addr(ServerOptions *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, முழு);
நிலையான வெறுமை parse_server_config_depth(ServerOptions *options,
    மாறிலி எழுத்து *filename, கட்டமைப்பு sshbuf *conf, கட்டமைப்பு include_list *includes,
    கட்டமைப்பு connection_info *connectinfo, முழு flags, முழு *activep, முழு depth);

வெளி கட்டமைப்பு sshbuf *cfg;

/* Initializes the server options to their default values. */

வெறுமை
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, அளவு(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = வெற்று;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = வெற்று;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = வெற்று;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_சாவி_files = 0; \
	options->இலக்கம்_host_சாவி_files = 0; \
	options->host_சாவி_file_userprovided = வெற்று;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = வெற்று; \
	options->இலக்கம்_queued_listens = 0; \
	options->listen_addrs = வெற்று; \
	options->இலக்கம்_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->இலக்கம்_ports = 0; \
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
	options->permit_user_env_allowlist = வெற்று;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = வெற்று; \
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
	options->இலக்கம்_subsystems = 0; \
	options->subsystem_name = வெற்று; \
	options->subsystem_command = வெற்று; \
	options->subsystem_args = வெற்று;
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
நிலையான முழு
option_clear_or_none(மாறிலி எழுத்து *o)
{
	திரும்பு o == வெற்று || strcasecmp(o, "none") == 0;
}

நிலையான வெறுமை
assemble_algorithms(ServerOptions *o)
{
	எழுத்து *all_cipher, *all_mac, *all_kex, *all_சாவி, *all_sig;
	எழுத்து *def_cipher, *def_mac, *def_kex, *def_சாவி, *def_sig;
	முழு r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_சாவி = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_சாவி = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_சாவி);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	செய் { \
		எனில் ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} போது (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_சாவி, all_சாவி);
	ASSEMBLE(hostbased_accepted_algos, def_சாவி, all_சாவி);
	ASSEMBLE(pubkey_accepted_algos, def_சாவி, all_சாவி);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	விடுவி(all_cipher);
	விடுவி(all_mac);
	விடுவி(all_kex);
	விடுவி(all_சாவி);
	விடுவி(all_sig);
	விடுவி(def_cipher);
	விடுவி(def_mac);
	விடுவி(def_kex);
	விடுவி(def_சாவி);
	விடுவி(def_sig);
}

வெறுமை
servconf_add_hostkey(மாறிலி எழுத்து *file, மாறிலி முழு வரி,
    ServerOptions *options, மாறிலி எழுத்து *path, முழு userprovided)
{
	எழுத்து *apath = derelativise_path(path);

	opt_array_append2(file, வரி, "HostKey",
	    &options->host_சாவி_files, &options->host_சாவி_file_userprovided,
	    &options->இலக்கம்_host_சாவி_files, apath, userprovided);
	விடுவி(apath);
}

வெறுமை
servconf_add_hostcert(மாறிலி எழுத்து *file, மாறிலி முழு வரி,
    ServerOptions *options, மாறிலி எழுத்து *path)
{
	எழுத்து *apath = derelativise_path(path);

	opt_array_append(file, வரி, "HostCertificate",
	    &options->host_cert_files, &options->இலக்கம்_host_cert_files, apath);
	விடுவி(apath);
}

வெறுமை
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	எனில் (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	எனில் (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	எனில் (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	எனில் (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	செய் { \
		விடுவி(options->var); \
		options->var = வெற்று; \
	} போது (0);
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
	எனில் (options->pam_service_name == வெற்று)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	எனில் (options->இலக்கம்_host_சாவி_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_சாவி_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_சாவி_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_சாவி_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_சாவி_FILE, 0);
	}
	/* No certificates by default */
	எனில் (options->இலக்கம்_ports == 0)
		options->ports[options->இலக்கம்_ports++] = SSH_DEFAULT_PORT;
	எனில் (options->listen_addrs == வெற்று)
		add_listen_addr(options, வெற்று, வெற்று, 0);
	எனில் (options->pid_file == வெற்று)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	எனில் (options->moduli_file == வெற்று)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	எனில் (options->xauth_location == வெற்று)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	எனில் (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	எனில் (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	எனில் (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = வெற்று;
	}
	எனில் (options->rekey_limit == -1)
		options->rekey_limit = 0;
	எனில் (options->rekey_interval == -1)
		options->rekey_interval = 0;
	எனில் (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	எனில் (options->max_startups == -1)
		options->max_startups = 100;
	எனில் (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	எனில் (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	எனில் (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	எனில் (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	எனில் (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	எனில் (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	எனில் (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	எனில் (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	எனில் (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	எனில் (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	எனில் (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	எனில் (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	எனில் (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	எனில் (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	எனில் (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	எனில் (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	எனில் (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	எனில் (options->இலக்கம்_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_சாவிகள்_files,
		    &options->இலக்கம்_authkeys_files,
		    PATH_SSH_USER_PERMITTED_சாவிகள்);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_சாவிகள்_files,
		    &options->இலக்கம்_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	எனில் (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	எனில் (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	எனில் (options->version_addendum == வெற்று)
		options->version_addendum = xstrdup("");
	எனில் (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	எனில் (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	எனில் (options->sk_provider == வெற்று)
		options->sk_provider = xstrdup("internal");
	எனில் (options->sshd_session_path == வெற்று)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	எனில் (options->sshd_auth_path == வெற்று)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	எனில் (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	எனில் (options->agent_socket_path == வெற்று)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	செய் { \
		எனில் (option_clear_or_none(v)) { \
			விடுவி(v); \
			v = வெற்று; \
		} \
	} போது(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	செய் { \
		எனில் (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			விடுவி(options->v[0]); \
			விடுவி(options->v); \
			options->v = வெற்று; \
			options->nv = 0; \
		} \
	} போது (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_சாவிகள்);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_சாவி_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	க்கு (i = 0; i < options->இலக்கம்_host_சாவி_files; i++)
		CLEAR_ON_NONE(options->host_சாவி_files[i]);
	க்கு (i = 0; i < options->இலக்கம்_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, இலக்கம்_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, இலக்கம்_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_சாவிகள்_files, இலக்கம்_revoked_சாவிகள்_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_சாவிகள்_files, இலக்கம்_authkeys_files, "none");
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
வகைவரை எண்ணிக்கை {
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
நிலையான கட்டமைப்பு {
	மாறிலி எழுத்து *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ வெற்று, sBadOption, 0 }
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

நிலையான கட்டமைப்பு {
	முழு val;
	எழுத்து *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, வெற்று }
};

/* Returns an opcode name from its number */

நிலையான மாறிலி எழுத்து *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	க்கு (i = 0; keywords[i].name != வெற்று; i++)
		எனில் (keywords[i].opcode == code)
			திரும்பு(keywords[i].name);
	திரும்பு "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

நிலையான ServerOpCodes
parse_token(மாறிலி எழுத்து *cp, மாறிலி எழுத்து *filename,
	    முழு linenum, u_int *flags)
{
	u_int i;

	க்கு (i = 0; keywords[i].name; i++)
		எனில் (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			திரும்பு keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	திரும்பு sBadOption;
}

எழுத்து *
derelativise_path(மாறிலி எழுத்து *path)
{
	எழுத்து *expanded, *ret, cwd[PATH_MAX];

	எனில் (strcasecmp(path, "none") == 0)
		திரும்பு xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	எனில் (path_absolute(expanded))
		திரும்பு expanded;
	எனில் (getcwd(cwd, அளவு(cwd)) == வெற்று)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	விடுவி(expanded);
	திரும்பு ret;
}

நிலையான வெறுமை
add_listen_addr(ServerOptions *options, மாறிலி எழுத்து *addr,
    மாறிலி எழுத்து *rdomain, முழு port)
{
	u_int i;

	எனில் (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	இல்லையெனில் {
		க்கு (i = 0; i < options->இலக்கம்_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

நிலையான வெறுமை
add_one_listen_addr(ServerOptions *options, மாறிலி எழுத்து *addr,
    மாறிலி எழுத்து *rdomain, முழு port)
{
	கட்டமைப்பு addrinfo hints, *ai, *aitop;
	எழுத்து strport[NI_MAXSERV];
	முழு gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	க்கு (i = 0; i < options->இலக்கம்_listen_addrs; i++) {
		எனில் (rdomain == வெற்று && options->listen_addrs[i].rdomain == வெற்று)
			நிறுத்து;
		எனில் (rdomain == வெற்று || options->listen_addrs[i].rdomain == வெற்று)
			தொடர்;
		எனில் (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			நிறுத்து;
	}
	எனில் (i >= options->இலக்கம்_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		எனில் (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->இலக்கம்_listen_addrs, options->இலக்கம்_listen_addrs + 1,
		    அளவு(*options->listen_addrs));
		i = options->இலக்கம்_listen_addrs++;
		எனில் (rdomain != வெற்று)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, அளவு(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == வெற்று) ? AI_PASSIVE : 0;
	snprintf(strport, அளவு strport, "%d", port);
	எனில் ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	க்கு (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
நிலையான முழு
valid_rdomain(மாறிலி எழுத்து *name)
{
#எனில் defined(HAVE_SYS_VALID_RDOMAIN)
	திரும்பு sys_valid_rdomain(name);
#அல்லதெனில் defined(__OpenBSD__)
	மாறிலி எழுத்து *errstr;
	long long இலக்கம்;
	கட்டமைப்பு rt_tableinfo info;
	முழு mib[6];
	size_t miblen = அளவு(mib);

	எனில் (name == வெற்று)
		திரும்பு 1;

	இலக்கம் = strtonum(name, 0, 255, &errstr);
	எனில் (errstr != வெற்று)
		திரும்பு 0;

	/* Check whether the table actually exists */
	memset(mib, 0, அளவு(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (முழு)இலக்கம்;
	எனில் (sysctl(mib, 6, &info, &miblen, வெற்று, 0) == -1)
		திரும்பு 0;

	திரும்பு 1;
#இல்லையெனில் /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	திரும்பு 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
நிலையான வெறுமை
queue_listen_addr(ServerOptions *options, மாறிலி எழுத்து *addr,
    மாறிலி எழுத்து *rdomain, முழு port)
{
	கட்டமைப்பு queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->இலக்கம்_queued_listens, options->இலக்கம்_queued_listens + 1,
	    அளவு(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->இலக்கம்_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == வெற்று ? வெற்று : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
நிலையான வெறுமை
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	கட்டமைப்பு queued_listenaddr *qla;

	எனில் (options->இலக்கம்_ports == 0)
		options->ports[options->இலக்கம்_ports++] = SSH_DEFAULT_PORT;
	எனில் (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	க்கு (i = 0; i < options->இலக்கம்_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		விடுவி(qla->addr);
		விடுவி(qla->rdomain);
	}
	விடுவி(options->queued_listen_addrs);
	options->queued_listen_addrs = வெற்று;
	options->இலக்கம்_queued_listens = 0;
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

நிலையான முழு
match_cfg_வரி_group(மாறிலி எழுத்து *grps, முழு வரி, மாறிலி எழுத்து *user)
{
	முழு result = 0;
	கட்டமைப்பு passwd *pw;

	எனில் (user == வெற்று)
		செல் out;

	எனில் ((pw = getpwnam(user)) == வெற்று) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", வரி, user);
	} இல்லையெனில் எனில் (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, வரி);
	} இல்லையெனில் எனில் (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, வரி);
	} இல்லையெனில் {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, வரி);
		result = 1;
	}
out:
	ga_free();
	திரும்பு result;
}

நிலையான வெறுமை
match_test_missing_fatal(மாறிலி எழுத்து *criteria, மாறிலி எழுத்து *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
நிலையான முழு
match_cfg_வரி(மாறிலி எழுத்து *full_வரி, முழு *acp, எழுத்து ***avp,
    முழு வரி, கட்டமைப்பு connection_info *ci)
{
	முழு result = 1, attributes = 0, port;
	எழுத்து *arg, *attrib = வெற்று, *oattrib;

	எனில் (ci == வெற்று) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_வரி, வரி);
	} இல்லையெனில் {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_வரி,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", வரி);
	}

	போது ((oattrib = argv_next(acp, avp)) != வெற்று) {
		/* Terminate on comment */
		எனில் (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			நிறுத்து;
		}
		attrib = xstrdup(oattrib);
		arg = வெற்று;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		எனில் (strcasecmp(attrib, "all") == 0) {
			எனில் (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != வெற்று &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				செல் out;
			}
			எனில் (arg != வெற்று && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			செல் out;
		}
		/* Criterion "invalid-user" also has no argument */
		எனில் (strcasecmp(attrib, "invalid-user") == 0) {
			எனில் (ci == வெற்று) {
				result = 0;
				செல் next;
			}
			எனில் (ci->user_invalid == 0)
				result = 0;
			இல்லையெனில்
				debug("matched invalid-user at line %d", வரி);
			செல் next;
		}

		/* Keep this list in sync with below */
		எனில் (strprefix(attrib, "user=", 1) != வெற்று ||
		    strprefix(attrib, "group=", 1) != வெற்று ||
		    strprefix(attrib, "host=", 1) != வெற்று ||
		    strprefix(attrib, "address=", 1) != வெற்று ||
		    strprefix(attrib, "localaddress=", 1) != வெற்று ||
		    strprefix(attrib, "localport=", 1) != வெற்று ||
		    strprefix(attrib, "rdomain=", 1) != வெற்று ||
		    strprefix(attrib, "version=", 1) != வெற்று) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} இல்லையெனில் {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		எனில் (arg == வெற்று || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			செல் out;
		}
		எனில் (strcasecmp(attrib, "user") == 0) {
			எனில் (ci == வெற்று || (ci->test && ci->user == வெற்று)) {
				result = 0;
				செல் next;
			}
			எனில் (ci->user == வெற்று)
				match_test_missing_fatal("User", "user");
			எனில் (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			இல்லையெனில்
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, வரி);
		} இல்லையெனில் எனில் (strcasecmp(attrib, "group") == 0) {
			எனில் (ci == வெற்று || (ci->test && ci->user == வெற்று)) {
				result = 0;
				செல் next;
			}
			எனில் (ci->user == வெற்று)
				match_test_missing_fatal("Group", "user");
			தேர்வு (match_cfg_வரி_group(arg, வரி, ci->user)) {
			நிலை -1:
				result = -1;
				செல் out;
			நிலை 0:
				result = 0;
			}
		} இல்லையெனில் எனில் (strcasecmp(attrib, "host") == 0) {
			எனில் (ci == வெற்று || (ci->test && ci->host == வெற்று)) {
				result = 0;
				செல் next;
			}
			எனில் (ci->host == வெற்று)
				match_test_missing_fatal("Host", "host");
			எனில் (match_hostname(ci->host, arg) != 1)
				result = 0;
			இல்லையெனில்
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, வரி);
		} இல்லையெனில் எனில் (strcasecmp(attrib, "address") == 0) {
			எனில் (ci == வெற்று || (ci->test && ci->address == வெற்று)) {
				எனில் (addr_match_list(வெற்று, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, வரி);
				result = 0;
				செல் next;
			}
			எனில் (ci->address == வெற்று)
				match_test_missing_fatal("Address", "addr");
			தேர்வு (addr_match_list(ci->address, arg)) {
			நிலை 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, வரி);
				நிறுத்து;
			நிலை 0:
			நிலை -1:
				result = 0;
				நிறுத்து;
			நிலை -2:
				result = -1;
				செல் out;
			}
		} இல்லையெனில் எனில் (strcasecmp(attrib, "localaddress") == 0){
			எனில் (ci == வெற்று || (ci->test && ci->laddress == வெற்று)) {
				எனில் (addr_match_list(வெற்று, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    வரி);
				result = 0;
				செல் next;
			}
			எனில் (ci->laddress == வெற்று)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			தேர்வு (addr_match_list(ci->laddress, arg)) {
			நிலை 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, வரி);
				நிறுத்து;
			நிலை 0:
			நிலை -1:
				result = 0;
				நிறுத்து;
			நிலை -2:
				result = -1;
				செல் out;
			}
		} இல்லையெனில் எனில் (strcasecmp(attrib, "localport") == 0) {
			எனில் ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				செல் out;
			}
			எனில் (ci == வெற்று || (ci->test && ci->lport == -1)) {
				result = 0;
				செல் next;
			}
			எனில் (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			எனில் (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, வரி);
			இல்லையெனில்
				result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "rdomain") == 0) {
			எனில் (ci == வெற்று || (ci->test && ci->rdomain == வெற்று)) {
				result = 0;
				செல் next;
			}
			எனில் (ci->rdomain == வெற்று)
				match_test_missing_fatal("RDomain", "rdomain");
			எனில் (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			இல்லையெனில்
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, வரி);
		} இல்லையெனில் எனில் (strcasecmp(attrib, "version") == 0) {
			எனில் (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			இல்லையெனில்
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, வரி);
		} இல்லையெனில் {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			செல் out;
		}
 next:
		விடுவி(attrib);
		attrib = வெற்று;
	}
	எனில் (attributes == 0) {
		error("One or more attributes required for Match");
		திரும்பு -1;
	}
 out:
	எனில் (ci != வெற்று && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", வரி);
	விடுவி(attrib);
	திரும்பு result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
கட்டமைப்பு multistate {
	எழுத்து *சாவி;
	முழு மதிப்பு;
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ வெற்று, -1 }
};

நிலையான முழு
process_server_config_வரி_depth(ServerOptions *options, எழுத்து *வரி,
    மாறிலி எழுத்து *filename, முழு linenum, முழு *activep,
    கட்டமைப்பு connection_info *connectinfo, முழு *inc_flags, முழு depth,
    கட்டமைப்பு include_list *includes)
{
	எழுத்து *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	முழு cmdline = 0, *intptr, மதிப்பு, value2, value3, n, port, oactive, r;
	இரட்டை dvalue, *doubleptr = வெற்று;
	முழு ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	மாறிலி கட்டமைப்பு multistate *multistate_ptr;
	மாறிலி எழுத்து *errstr;
	கட்டமைப்பு include_item *item;
	glob_t gbuf;
	எழுத்து **oav = வெற்று, **av;
	முழு oac = 0, ac;
	முழு ret = -1;
	எழுத்து **strs = வெற்று; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	எனில் ((len = strlen(வரி)) == 0)
		திரும்பு 0;
	க்கு (len--; len > 0; len--) {
		எனில் (strchr(WHITESPACE "\f", வரி[len]) == வெற்று)
			நிறுத்து;
		வரி[len] = '\0';
	}

	str = வரி;
	எனில் ((keyword = strdelim(&str)) == வெற்று)
		திரும்பு 0;
	/* Ignore leading whitespace */
	எனில் (*keyword == '\0')
		keyword = strdelim(&str);
	எனில் (!keyword || !*keyword || *keyword == '#')
		திரும்பு 0;
	எனில் (str == வெற்று || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		திரும்பு -1;
	}
	intptr = வெற்று;
	charptr = வெற்று;
	opcode = parse_token(keyword, filename, linenum, &flags);

	எனில் (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		திரும்பு -1;
	}
	ac = oac;
	av = oav;

	எனில் (activep == வெற்று) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	எனில் (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	எனில் (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		எனில் (connectinfo == வெற்று) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} இல்லையெனில் { /* this is a directive we have already processed */
			ret = 0;
			செல் out;
		}
	}

	தேர்வு (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	நிலை sUsePAM:
		intptr = &options->use_pam;
		செல் parse_flag;
	நிலை sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;
#endif

	/* Standard Options */
	நிலை sBadOption:
		செல் out;
	நிலை sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		எனில் (options->ports_from_cmdline) {
			argv_consume(&ac);
			நிறுத்து;
		}
		எனில் (options->இலக்கம்_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->இலக்கம்_ports++] = a2port(arg);
		எனில் (options->ports[options->இலக்கம்_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		நிறுத்து;

	நிலை sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		எனில் ((மதிப்பு = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை sListenAddress:
		arg = argv_next(&ac, &av);
		எனில் (arg == வெற்று || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		எனில் (strchr(arg, '[') == வெற்று && (p = strchr(arg, ':')) != வெற்று
		    && strchr(p+1, ':') != வெற்று) {
			port = 0;
			p = arg;
		} இல்லையெனில் {
			arg2 = வெற்று;
			p = hpdelim(&arg);
			எனில் (p == வெற்று)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			எனில் (arg == வெற்று)
				port = 0;
			இல்லையெனில் எனில் ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = வெற்று;
		எனில் ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == வெற்று)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			எனில் (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		நிறுத்து;

	நிலை sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		மதிப்பு = -1;
		க்கு (i = 0; multistate_ptr[i].சாவி != வெற்று; i++) {
			எனில் (strcasecmp(arg, multistate_ptr[i].சாவி) == 0) {
				மதிப்பு = multistate_ptr[i].மதிப்பு;
				நிறுத்து;
			}
		}
		எனில் (மதிப்பு == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை s_Host_சாவி:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		எனில் (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		நிறுத்து;

	நிலை s_Host_சாவி_Agent:
		charptr = &options->host_சாவி_agent;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		எனில் (*activep && *charptr == வெற்று)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		நிறுத்து;

	நிலை sHostCertificate:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		எனில் (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		நிறுத்து;

	நிலை sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		எனில் (*activep && *charptr == வெற்று) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			எனில் (intptr != வெற்று)
				*intptr = *intptr + 1;
		}
		நிறுத்து;

	நிலை sModuliFile:
		charptr = &options->moduli_file;
		செல் parse_filename;

	நிலை s_Permit_வேர்_Login:
		intptr = &options->permit_வேர்_login;
		multistate_ptr = multistate_permitrootlogin;
		செல் parse_multistate;

	நிலை sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		செல் parse_multistate;

	நிலை sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		செல் parse_multistate;

	நிலை sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		செல் parse_flag;

	நிலை sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		செல் parse_flag;

	நிலை sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		எனில் (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை s_Host_சாவி_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		செல் parse_pubkey_algos;

	நிலை sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		செல் parse_pubkey_algos;

	நிலை sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		செல் parse_flag;

	நிலை sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		செல் parse_pubkey_algos;

	நிலை sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		மதிப்பு = 0;
		value2 = -1;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (strcasecmp(arg, "none") == 0)
				தொடர்;
			எனில் (strcasecmp(arg, "touch-required") == 0)
				மதிப்பு |= PUBKEYAUTH_TOUCH_REQUIRED;
			இல்லையெனில் எனில் (strcasecmp(arg, "verify-required") == 0)
				மதிப்பு |= PUBKEYAUTH_VERIFY_REQUIRED;
			இல்லையெனில் எனில் (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				எனில் (errstr != வெற்று) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					செல் out;
				}
			} இல்லையெனில் {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				செல் out;
			}
		}
		எனில் (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = மதிப்பு;
			options->max_pubkey_ok = value2;
		}
		நிறுத்து;

#ifdef KRB5
	நிலை sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		செல் parse_flag;

	நிலை sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		செல் parse_flag;

	நிலை sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		செல் parse_flag;
#ifdef USE_AFS
	நிலை sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		செல் parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	நிலை sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		செல் parse_flag;

	நிலை sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		செல் parse_flag;

	நிலை sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		செல் parse_flag;

	நிலை sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		செல் parse_flag;
#endif /* GSSAPI */

	நிலை sPasswordAuthentication:
		intptr = &options->password_authentication;
		செல் parse_flag;

	நிலை sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		செல் parse_flag;

	நிலை sPrintMotd:
		intptr = &options->print_motd;
		செல் parse_flag;

#ifndef DISABLE_LASTLOG
	நிலை sPrintLastLog:
		intptr = &options->print_lastlog;
		செல் parse_flag;
#endif

	நிலை sX11Forwarding:
		intptr = &options->x11_forwarding;
		செல் parse_flag;

	நிலை sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		எனில் ((errstr = atoi_err(arg, &மதிப்பு)) != வெற்று)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		செல் parse_flag;

	நிலை sXAuthLocation:
		charptr = &options->xauth_location;
		செல் parse_filename;

	நிலை sPermitTTY:
		intptr = &options->permit_tty;
		செல் parse_flag;

	நிலை sPermitUserRC:
		intptr = &options->permit_user_rc;
		செல் parse_flag;

	நிலை sStrictModes:
		intptr = &options->strict_modes;
		செல் parse_flag;

	நிலை sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		செல் parse_multistate;

	நிலை sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		செல் parse_flag;

	நிலை sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		மதிப்பு = 0;
		p = வெற்று;
		எனில் (strcmp(arg, "yes") == 0)
			மதிப்பு = 1;
		இல்லையெனில் எனில் (strcmp(arg, "no") == 0)
			மதிப்பு = 0;
		இல்லையெனில் {
			/* Pattern-list specified */
			மதிப்பு = 1;
			p = xstrdup(arg);
		}
		எனில் (*activep && *intptr == -1) {
			*intptr = மதிப்பு;
			*charptr = p;
			p = வெற்று;
		}
		விடுவி(p);
		நிறுத்து;

	நிலை sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		செல் parse_multistate;

	நிலை sRekeyLimit:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (strcmp(arg, "default") == 0) {
			val64 = 0;
		} இல்லையெனில் {
			எனில் (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			எனில் (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		எனில் (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		எனில் (ac != 0) { /* optional rekey interval present */
			எனில் (strcmp(av[0], "none") == 0) {
				(வெறுமை)argv_next(&ac, &av);	/* discard */
				நிறுத்து;
			}
			intptr = &options->rekey_interval;
			செல் parse_time;
		}
		நிறுத்து;

	நிலை sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		செல் parse_multistate;

	நிலை sUseDNS:
		intptr = &options->use_dns;
		செல் parse_flag;

	நிலை sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		மதிப்பு = log_facility_எண்(arg);
		எனில் (மதிப்பு == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		எனில் (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) மதிப்பு;
		நிறுத்து;

	நிலை sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		மதிப்பு = log_level_எண்(arg);
		எனில் (மதிப்பு == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		எனில் (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) மதிப்பு;
		நிறுத்து;

	நிலை sLogVerbose:
		found = options->இலக்கம்_log_verbose == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->log_verbose = strs;
			options->இலக்கம்_log_verbose = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		செல் parse_multistate;

	நிலை sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		செல் parse_multistate;

	நிலை sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		செல் parse_flag;

	நிலை sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		எனில் (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			எனில் (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} இல்லையெனில் எனில் (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			எனில் (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} இல்லையெனில் எனில் (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை sDisableForwarding:
		intptr = &options->disable_forwarding;
		செல் parse_flag;

	நிலை sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->இலக்கம்_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0' ||
			    match_user(வெற்று, வெற்று, வெற்று, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			எனில் (!*activep)
				தொடர்;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		எனில் (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		நிறுத்து;

	நிலை sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->இலக்கம்_deny_users;
		செல் parse_allowdenyusers;

	நிலை sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->இலக்கம்_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			எனில் (!*activep)
				தொடர்;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		எனில் (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		நிறுத்து;

	நிலை sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->இலக்கம்_deny_groups;
		செல் parse_allowdenygroups;

	நிலை sCiphers:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		எனில் (options->ciphers == வெற்று)
			options->ciphers = xstrdup(arg);
		நிறுத்து;

	நிலை sMacs:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		எனில் (options->macs == வெற்று)
			options->macs = xstrdup(arg);
		நிறுத்து;

	நிலை sKexAlgorithms:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		எனில் (options->kex_algorithms == வெற்று)
			options->kex_algorithms = xstrdup(arg);
		நிறுத்து;

	நிலை sSubsystem:
		எனில் ((arg = argv_next(&ac, &av)) == வெற்று || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == வெற்று || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (!*activep) {
			argv_consume(&ac);
			நிறுத்து;
		}
		found = 0;
		க்கு (i = 0; i < options->இலக்கம்_subsystems; i++) {
			எனில் (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				நிறுத்து;
			}
		}
		எனில் (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			நிறுத்து;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->இலக்கம்_subsystems,
		    options->இலக்கம்_subsystems + 1,
		    அளவு(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->இலக்கம்_subsystems,
		    options->இலக்கம்_subsystems + 1,
		    அளவு(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->இலக்கம்_subsystems,
		    options->இலக்கம்_subsystems + 1,
		    அளவு(*options->subsystem_args));
		options->subsystem_name[options->இலக்கம்_subsystems] = xstrdup(arg);
		options->subsystem_command[options->இலக்கம்_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->இலக்கம்_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		விடுவி(arg2);
		விடுவி(arg);
		argv_consume(&ac);
		options->இலக்கம்_subsystems++;
		நிறுத்து;

	நிலை sMaxStartups:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		எனில் ((n = sscanf(arg, "%d:%d:%d",
		    &மதிப்பு, &value2, &value3)) == 3) {
			எனில் (மதிப்பு > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} இல்லையெனில் எனில் (n == 1) {
			value3 = மதிப்பு;
			value2 = -1;
		} இல்லையெனில் {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		எனில் (மதிப்பு <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		எனில் (*activep && options->max_startups == -1) {
			options->max_startups_begin = மதிப்பு;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		நிறுத்து;

	நிலை sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		தேர்வு (n = sscanf(arg, "%d:%d", &மதிப்பு, &value2)) {
		நிலை 2:
			எனில் (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		நிலை 1:
			எனில் (மதிப்பு < 0 || மதிப்பு > 32)
				n = -1;
		}
		எனில் (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		எனில் (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = மதிப்பு;
			எனில் (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		நிறுத்து;

	நிலை sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (strcmp(arg, "none") == 0) { /* no limit */
			மதிப்பு = INT_MAX;
		} இல்லையெனில் {
			எனில் ((errstr = atoi_err(arg, &மதிப்பு)) != வெற்று)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		எனில் (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = மதிப்பு;
		நிறுத்து;

	நிலை sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		எனில் (addr_match_list(வெற்று, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை sPerSourcePenalties:
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			மாறிலி எழுத்து *q = வெற்று;

			found = 1;
			intptr = வெற்று;
			doubleptr = வெற்று;
			மதிப்பு = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			எனில் (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				எனில் (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				எனில் (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				தொடர்;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "crash:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "authfail:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "invaliduser:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "noauth:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "grace-exceeded:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "refuseconnection:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "max:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "min:", 0)) != வெற்று) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} இல்லையெனில் எனில் ((q = strprefix(arg, "max-sources4:", 0)) != வெற்று) {
				intptr = &options->per_source_penalty.max_sources4;
				எனில் ((errstr = atoi_err(q, &மதிப்பு)) != வெற்று)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} இல்லையெனில் எனில் ((q = strprefix(arg, "max-sources6:", 0)) != வெற்று) {
				intptr = &options->per_source_penalty.max_sources6;
				எனில் ((errstr = atoi_err(q, &மதிப்பு)) != வெற்று)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} இல்லையெனில் எனில் (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				மதிப்பு = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} இல்லையெனில் எனில் (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				மதிப்பு = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} இல்லையெனில் எனில் (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				மதிப்பு = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} இல்லையெனில் எனில் (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				மதிப்பு = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} இல்லையெனில் {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			எனில் (doubleptr != வெற்று) {
				எனில் ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				எனில் (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} இல்லையெனில் எனில் (intptr != வெற்று) {
				எனில் (*activep && *intptr == -1) {
					*intptr = மதிப்பு;
					options->per_source_penalty.enabled = 1;
				}
			} இல்லையெனில் {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		எனில் (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		நிறுத்து;

	நிலை sMaxAuthTries:
		intptr = &options->max_authtries;
		செல் parse_int;

	நிலை sMaxSessions:
		intptr = &options->max_sessions;
		செல் parse_int;

	நிலை sBanner:
		charptr = &options->banner;
		செல் parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	நிலை s_Authorized_சாவிகள்_File:
		uintptr = &options->இலக்கம்_authkeys_files;
		chararrayptr = &options->authorized_சாவிகள்_files;
 parse_filenames:
		found = *uintptr == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			விடுவி(arg2);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (*activep && *charptr == வெற்று) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			எனில் (intptr != வெற்று)
				*intptr = *intptr + 1;
		}
		நிறுத்து;

	நிலை sClientAliveInterval:
		intptr = &options->client_alive_interval;
		செல் parse_time;

	நிலை s_Client_Alive_மொத்தம்_Max:
		intptr = &options->client_alive_மொத்தம்_max;
		செல் parse_int;

	நிலை sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0' || strchr(arg, '=') != வெற்று)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			எனில் (!*activep)
				தொடர்;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->இலக்கம்_accept_env,
			    arg);
		}
		எனில் (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		நிறுத்து;

	நிலை sSetEnv:
		found = options->இலக்கம்_setenv == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0' || strchr(arg, '=') == வெற்று)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			எனில் (lookup_setenv_in_list(arg, strs, nstrs) != வெற்று) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				தொடர்;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->setenv = strs;
			options->இலக்கம்_setenv = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		மதிப்பு = -1;
		க்கு (i = 0; tunmode_desc[i].val != -1; i++)
			எனில் (strcmp(tunmode_desc[i].text, arg) == 0) {
				மதிப்பு = tunmode_desc[i].val;
				நிறுத்து;
			}
		எனில் (மதிப்பு == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை sInclude:
		எனில் (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		மதிப்பு = 0;
		போது ((arg2 = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			மதிப்பு++;
			found = 0;
			எனில் (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} இல்லையெனில்
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				எனில் (strcmp(item->selector, arg) != 0)
					தொடர்;
				எனில் (item->filename != வெற்று) {
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
			எனில் (found != 0) {
				விடுவி(arg);
				தொடர்;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			எனில் ((r = glob(arg, 0, வெற்று, &gbuf)) != 0) {
				எனில் (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, அளவு(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			எனில் (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			க்கு (n = 0; n < (முழு)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, அளவு(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				எனில் ((item->contents = sshbuf_new()) == வெற்று)
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
			விடுவி(arg);
		}
		எனில் (மதிப்பு == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		நிறுத்து;

	நிலை sMatch:
		எனில் (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		மதிப்பு = match_cfg_வரி(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? வெற்று : connectinfo));
		எனில் (மதிப்பு < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : மதிப்பு;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		நிறுத்து;

	நிலை sPermitListen:
	நிலை sPermitOpen:
		எனில் (opcode == sPermitListen) {
			uintptr = &options->இலக்கம்_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} இல்லையெனில் {
			uintptr = &options->இலக்கம்_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				எனில் (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				தொடர்;
			}

			எனில் (opcode == sPermitListen &&
			    strchr(arg, ':') == வெற்று) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} இல்லையெனில் {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				எனில் (p == வெற்று) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			எனில் (arg == வெற்று ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			விடுவி(arg2);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை sForceCommand:
		எனில் (str == வெற்று || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		எனில் (*activep && options->adm_forced_command == வெற்று)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		நிறுத்து;

	நிலை sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_சாவிகள்;
		செல் parse_filename;

	நிலை s_Revoked_சாவிகள்:
		uintptr = &options->இலக்கம்_revoked_சாவிகள்_files;
		chararrayptr = &options->revoked_சாவிகள்_files;
		செல் parse_filenames;

	நிலை s_Security_சாவி_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (*activep && *charptr == வெற்று) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			எனில் (intptr != வெற்று)
				*intptr = *intptr + 1;
		}
		நிறுத்து;

	நிலை sIPQoS:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் ((மதிப்பு = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		எனில் (மதிப்பு == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			மதிப்பு = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		எனில் (arg == வெற்று)
			value2 = மதிப்பு;
		இல்லையெனில் எனில் ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		எனில் (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		எனில் (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = மதிப்பு;
			options->ip_qos_bulk = value2;
		}
		நிறுத்து;

	நிலை sVersionAddendum:
		எனில் (str == வெற்று || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		எனில் (strchr(str + len, '\r') != வெற்று) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		எனில் ((arg = strchr(வரி, '#')) != வெற்று) {
			*arg = '\0';
			rtrim(வரி);
		}
		எனில் (*activep && options->version_addendum == வெற்று) {
			எனில் (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			இல்லையெனில்
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		நிறுத்து;

	நிலை s_Authorized_சாவிகள்_Command:
		charptr = &options->authorized_சாவிகள்_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		எனில் (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		நிறுத்து;

	நிலை s_Authorized_சாவிகள்_Command_User:
		charptr = &options->authorized_சாவிகள்_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		செல் parse_command;

	நிலை sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		செல் parse_localuser;

	நிலை sAuthenticationMethods:
		found = options->இலக்கம்_auth_methods == 0;
		மதிப்பு = 0; /* seen "any" pseudo-method */
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (strcmp(arg, "any") == 0) {
				எனில் (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				மதிப்பு = 1;
			} இல்லையெனில் எனில் (மதிப்பு) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} இல்லையெனில் எனில் (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->auth_methods = strs;
			options->இலக்கம்_auth_methods = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		மதிப்பு = strtol(arg, &p, 8);
		எனில் (arg == p || மதிப்பு < 0 || மதிப்பு > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		எனில் (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)மதிப்பு;
		நிறுத்து;

	நிலை sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		செல் parse_flag;

	நிலை sFingerprintHash:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் ((மதிப்பு = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		எனில் (*activep)
			options->fingerprint_hash = மதிப்பு;
		நிறுத்து;

	நிலை sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		செல் parse_flag;

	நிலை sRDomain:
#எனில் !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		எனில் (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை sRequiredRSASize:
		intptr = &options->required_rsa_size;
		செல் parse_int;

	நிலை sChannelTimeout:
		found = options->இலக்கம்_channel_timeouts == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			} இல்லையெனில் எனில் (parse_pattern_interval(arg,
			    வெற்று, வெற்று) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->channel_timeouts = strs;
			options->இலக்கம்_channel_timeouts = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		எனில் (av[0] != வெற்று && strcasecmp(av[0], "none") == 0) {
			(வெறுமை)argv_next(&ac, &av); /* consume arg */
			எனில் (*activep)
				*intptr = 0;
			நிறுத்து;
		}
		செல் parse_time;

	நிலை sSshdSessionPath:
		charptr = &options->sshd_session_path;
		செல் parse_filename;

	நிலை sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		செல் parse_filename;

	நிலை sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		செல் parse_multistate;

	நிலை sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		செல் parse_multistate;

	நிலை sDeprecated:
	நிலை sIgnore:
	நிலை sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		நிறுத்து;

	இயல்பு:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	எனில் (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		செல் out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, வெற்று, nstrs);
	argv_free(oav, oac);
	திரும்பு ret;
}

முழு
process_server_config_வரி(ServerOptions *options, எழுத்து *வரி,
    மாறிலி எழுத்து *filename, முழு linenum, முழு *activep,
    கட்டமைப்பு connection_info *connectinfo, கட்டமைப்பு include_list *includes)
{
	முழு inc_flags = 0;

	திரும்பு process_server_config_வரி_depth(options, வரி, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

வெறுமை
load_server_config(மாறிலி எழுத்து *filename, கட்டமைப்பு sshbuf *conf)
{
	கட்டமைப்பு stat st;
	எழுத்து *வரி = வெற்று, *cp;
	size_t linesize = 0;
	FILE *f;
	முழு r;

	debug2_f("filename %s", filename);
	எனில் ((f = fopen(filename, "r")) == வெற்று) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	எனில் (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	போது (getline(&வரி, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = வரி + strspn(வரி, " \t\r");
		எனில் ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	விடுவி(வரி);
	எனில் ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

வெறுமை
parse_server_match_config(ServerOptions *options,
   கட்டமைப்பு include_list *includes, கட்டமைப்பு connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

முழு
parse_server_match_testspec(கட்டமைப்பு connection_info *ci, எழுத்து *spec)
{
	எழுத்து *p;
	மாறிலி எழுத்து *val;

	போது ((p = strsep(&spec, ",")) && *p != '\0') {
		எனில் ((val = strprefix(p, "addr=", 0)) != வெற்று) {
			ci->address = xstrdup(val);
		} இல்லையெனில் எனில் ((val = strprefix(p, "host=", 0)) != வெற்று) {
			ci->host = xstrdup(val);
		} இல்லையெனில் எனில் ((val = strprefix(p, "user=", 0)) != வெற்று) {
			ci->user = xstrdup(val);
		} இல்லையெனில் எனில் ((val = strprefix(p, "laddr=", 0)) != வெற்று) {
			ci->laddress = xstrdup(val);
		} இல்லையெனில் எனில் ((val = strprefix(p, "rdomain=", 0)) != வெற்று) {
			ci->rdomain = xstrdup(val);
		} இல்லையெனில் எனில் ((val = strprefix(p, "lport=", 0)) != வெற்று) {
			ci->lport = a2port(val);
			எனில் (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				திரும்பு -1;
			}
		} இல்லையெனில் எனில் (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} இல்லையெனில் {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			திரும்பு -1;
		}
	}
	திரும்பு 0;
}

வெறுமை
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	க்கு (i = 0; i < src->இலக்கம்_subsystems; i++) {
		found = 0;
		க்கு (j = 0; j < dst->இலக்கம்_subsystems; j++) {
			எனில் (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				நிறுத்து;
			}
		}
		எனில் (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			விடுவி(dst->subsystem_command[j]);
			விடுவி(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			தொடர்;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->இலக்கம்_subsystems,
		    dst->இலக்கம்_subsystems + 1, அளவு(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->இலக்கம்_subsystems,
		    dst->இலக்கம்_subsystems + 1, அளவு(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->இலக்கம்_subsystems,
		    dst->இலக்கம்_subsystems + 1, அளவு(*dst->subsystem_args));
		j = dst->இலக்கம்_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

நிலையான முழு
serialise_s32(கட்டமைப்பு sshbuf *buf, முழு v)
{
	uint32_t uv;
	முழு r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	எனில் ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
serialise_s64(கட்டமைப்பு sshbuf *buf, int64_t v)
{
	uint64_t uv;
	முழு r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	எனில் ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
serialise_mode(கட்டமைப்பு sshbuf *buf, mode_t v)
{
	u_int uv;

	எனில் (v == (mode_t)-1)
		திரும்பு serialise_s32(buf, -1);
	uv = (u_int)v;
	எனில் ((mode_t)uv != v || uv > 0777)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு serialise_s32(buf, (முழு)uv);
}

நிலையான முழு
serialise_double(கட்டமைப்பு sshbuf *buf, இரட்டை v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	திரும்பு sshbuf_put(buf, &v, அளவு(v));
}

நிலையான முழு
serialise_nullable_string(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *s)
{
	முழு r;

	எனில் ((r = sshbuf_put_u8(buf, s != வெற்று)) != 0)
		திரும்பு r;
	எனில் (s == வெற்று)
		திரும்பு 0;
	திரும்பு sshbuf_put_cstring(buf, s);
}

நிலையான முழு
serialise_nullable_string_array(கட்டமைப்பு sshbuf *buf, எழுத்து **a, u_int n)
{
	முழு r;
	u_int i;

	எனில் ((r = sshbuf_put_u32(buf, n)) != 0)
		திரும்பு r;
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = serialise_nullable_string(buf, a[i])) != 0)
			திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_hostkeyfile(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i;

	எனில் ((r = sshbuf_put_u32(buf, options->இலக்கம்_host_சாவி_files)) != 0) {
		error_fr(r, "serialise length");
		திரும்பு r;
	}
	க்கு (i = 0; i < options->இலக்கம்_host_சாவி_files; i++) {
		எனில் ((r = serialise_s32(buf,
		    options->host_சாவி_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_சாவி_files[i])) != 0) {
			error_fr(r, "serialise member");
			திரும்பு r;
		}
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_ipqos(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_listenaddress(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	எனில் ((r = sshbuf_put_u32(buf, options->இலக்கம்_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		திரும்பு r;
	}
	க்கு (i = 0; i < options->இலக்கம்_queued_listens; i++) {
		மாறிலி கட்டமைப்பு queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		எனில் ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			திரும்பு r;
		}
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_logfacility(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, (முழு)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_loglevel(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, (முழு)options->log_level)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_port(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i;

	எனில் ((r = sshbuf_put_u32(buf, options->இலக்கம்_ports)) != 0) {
		error_fr(r, "serialise length");
		திரும்பு r;
	}
	க்கு (i = 0; i < options->இலக்கம்_ports; i++) {
		எனில் ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			திரும்பு r;
		}
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_gatewayports(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_streamlocalbindmask(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_streamlocalbindunlink(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_maxstartups(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_permituserenv(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_persourcenetblocksize(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_persourcepenalties(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	மாறிலி கட்டமைப்பு per_source_penalty *psp = &options->per_source_penalty;
	முழு r;

	எனில் ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_rekeylimit(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
serialise_subsystem(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i;

	எனில் ((r = sshbuf_put_u32(buf, options->இலக்கம்_subsystems)) != 0) {
		error_fr(r, "serialise length");
		திரும்பு r;
	}
	க்கு (i = 0; i < options->இலக்கம்_subsystems; i++) {
		எனில் ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			திரும்பு r;
		}
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_pubkey_auth_options(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
serialise_timingsecret(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		திரும்பு r;
	}
	திரும்பு 0;
}


முழு
serialise_server_options(மாறிலி ServerOptions *options, கட்டமைப்பு sshbuf **bufp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	*bufp = வெற்று;

	எனில் ((buf = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		செல் out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	எனில் ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	எனில் ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	எனில் ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	எனில் ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	எனில் ((r = serialise_##funcsuffix(options, buf)) != 0) \
		செல் out;
#define SSHCONF_NONCONF(funcsuffix) \
	எனில் ((r = serialise_##funcsuffix(options, buf)) != 0) \
		செல் out;
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
	buf = வெற்று; /* transferred */
 out:
	sshbuf_free(buf);
	திரும்பு r;
}

நிலையான முழு
deserialise_s32(கட்டமைப்பு sshbuf *buf, முழு *v)
{
	uint32_t tmp;
	முழு r;
	u_char was_signed;

	எனில் ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		திரும்பு r;
	எனில் (was_signed > 1)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (was_signed) {
		எனில் (tmp > (uint32_t)INT_MAX + 1)
			திரும்பு SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(முழு)tmp;
	} இல்லையெனில் {
		எனில் (tmp > INT_MAX)
			திரும்பு SSH_ERR_INVALID_FORMAT;
		*v = (முழு)tmp;
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_s64(கட்டமைப்பு sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	முழு r;
	u_char was_signed;

	எனில் ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		திரும்பு r;
	எனில் (was_signed > 1)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (was_signed) {
		எனில் (tmp > (uint64_t)INT64_MAX + 1)
			திரும்பு SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} இல்லையெனில் {
		எனில் (tmp > INT64_MAX)
			திரும்பு SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_mode(கட்டமைப்பு sshbuf *buf, mode_t *v)
{
	முழு r, tmp;

	எனில் ((r = deserialise_s32(buf, &tmp)) != 0)
		திரும்பு r;
	எனில் (tmp == -1) {
		*v = (mode_t)-1;
		திரும்பு 0;
	}
	எனில் (tmp < 0 || tmp > 0777)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	திரும்பு 0;
}

நிலையான முழு
deserialise_double(கட்டமைப்பு sshbuf *buf, இரட்டை *v)
{
	திரும்பு sshbuf_get(buf, v, அளவு(*v));
}

நிலையான முழு
deserialise_nullable_string(கட்டமைப்பு sshbuf *buf, எழுத்து **sp)
{
	முழு r;
	u_char present;

	எனில் ((r = sshbuf_get_u8(buf, &present)) != 0)
		திரும்பு r;
	எனில் (present == 0) {
		*sp = வெற்று;
		திரும்பு 0;
	}
	எனில் (present != 1)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு sshbuf_get_cstring(buf, sp, வெற்று);
}

நிலையான வெறுமை
free_string_array(எழுத்து **a, u_int n)
{
	u_int i;

	எனில் (a == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < n; i++)
		விடுவி(a[i]);
	விடுவி(a);
}

நிலையான முழு
deserialise_மொத்தம்(கட்டமைப்பு sshbuf *buf, u_int *np, மாறிலி எழுத்து *what)
{
	முழு r;
	uint32_t n;

	எனில் ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		திரும்பு r;
	}
	எனில் (n > UINT_MAX) {
		error_f("bad number of %s", what);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	எனில் (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	திரும்பு 0;
}

நிலையான முழு
deserialise_nullable_string_array(கட்டமைப்பு sshbuf *buf, எழுத்து ***arrayp,
    u_int *np)
{
	எழுத்து **a = வெற்று;
	முழு r;
	u_int i, n;

	*arrayp = வெற்று;
	*np = 0;
	எனில் ((r = deserialise_மொத்தம்(buf, &n, "strings")) != 0)
		திரும்பு r;
	எனில் (n > 0)
		a = xcalloc(n, அளவு(*a));
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			திரும்பு r;
		}
	}
	*arrayp = a;
	*np = n;
	திரும்பு 0;
}

நிலையான வெறுமை
free_queued_listen_addrs(கட்டமைப்பு queued_listenaddr *qla, u_int n)
{
	u_int i;

	எனில் (qla == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < n; i++) {
		விடுவி(qla[i].addr);
		விடுவி(qla[i].rdomain);
	}
	விடுவி(qla);
}

நிலையான முழு
deserialise_hostkeyfile(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r, *userprovided = வெற்று;
	u_int i, n;
	எழுத்து **files = வெற்று;

	எனில் ((r = deserialise_மொத்தம்(buf, &n, "host key files")) != 0)
		திரும்பு r;
	எனில் (n > 0) {
		userprovided = xcalloc(n, அளவு(*userprovided));
		files = xcalloc(n, அளவு(*files));
	}
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			விடுவி(userprovided);
			திரும்பு r;
		}
	}
	options->இலக்கம்_host_சாவி_files = n;
	options->host_சாவி_file_userprovided = userprovided;
	options->host_சாவி_files = files;
	திரும்பு 0;
}

நிலையான முழு
deserialise_ipqos(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
deserialise_listenaddress(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i, n;
	கட்டமைப்பு queued_listenaddr *qla = வெற்று;

	எனில் ((r = deserialise_மொத்தம்(buf, &n, "listen addresses")) != 0)
		திரும்பு r;
	எனில் (n > 0)
		qla = xcalloc(n, அளவு(*qla));
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = sshbuf_get_cstring(buf, &qla[i].addr, வெற்று)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			திரும்பு r;
		}
	}
	options->இலக்கம்_queued_listens = n;
	options->queued_listen_addrs = qla;
	திரும்பு 0;
}

நிலையான முழு
deserialise_logfacility(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r, tmp;

	எனில் ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	எனில் (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == வெற்று) {
		error_f("bad syslog facility");
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	திரும்பு 0;
}

நிலையான முழு
deserialise_loglevel(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r, tmp;

	எனில் ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	எனில் (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == வெற்று) {
		error_f("bad log level");
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	திரும்பு 0;
}

நிலையான முழு
deserialise_port(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i, n;

	எனில் ((r = deserialise_மொத்தம்(buf, &n, "ports")) != 0)
		திரும்பு r;
	எனில் (n > MAX_PORTS) {
		error_f("bad number of ports");
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	options->இலக்கம்_ports = n;
	memset(options->ports, 0, அளவு(options->ports));
	க்கு (i = 0; i < options->இலக்கம்_ports; i++) {
		எனில் ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			திரும்பு r;
		}
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_gatewayports(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_streamlocalbindmask(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_streamlocalbindunlink(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_char tmp;

	எனில் ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	எனில் (tmp > 1) {
		error_f("bad boolean");
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	திரும்பு 0;
}

நிலையான முழு
deserialise_maxstartups(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
deserialise_permituserenv(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_persourcenetblocksize(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
deserialise_persourcepenalties(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	கட்டமைப்பு per_source_penalty *psp = &options->per_source_penalty;
	முழு r;

	எனில் ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
deserialise_rekeylimit(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}

	திரும்பு 0;
}

நிலையான முழு
deserialise_subsystem(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;
	u_int i, n;
	எழுத்து **names = வெற்று, **commands = வெற்று, **args = வெற்று;

	எனில் ((r = deserialise_மொத்தம்(buf, &n, "subsystems")) != 0)
		திரும்பு r;
	எனில் (n > 0) {
		names = xcalloc(n, அளவு(*names));
		commands = xcalloc(n, அளவு(*names));
		args = xcalloc(n, அளவு(*args));
	}
	க்கு (i = 0; i < n; i++) {
		எனில் ((r = sshbuf_get_cstring(buf, names + i, வெற்று)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, வெற்று)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, வெற்று)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			திரும்பு r;
		}
	}
	options->இலக்கம்_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	திரும்பு 0;
}

நிலையான முழு
deserialise_pubkey_auth_options(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

நிலையான முழு
deserialise_timingsecret(ServerOptions *options, கட்டமைப்பு sshbuf *buf)
{
	முழு r;

	எனில் ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		திரும்பு r;
	}
	திரும்பு 0;
}

முழு
deserialise_server_options(கட்டமைப்பு sshbuf *buf, ServerOptions *options)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	எனில் ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		செல் out;
	}
	எனில் (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	எனில் ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	எனில் ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	எனில் ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	எனில் ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		செல் out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	எனில் ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		செல் out;
#define SSHCONF_NONCONF(funcsuffix) \
	எனில் ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		செல் out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	செய் { \
		விடுவி(new_options.var); \
		new_options.var = வெற்று; \
	} போது (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	எனில் (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
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
	memset(&new_options, 0, அளவு(new_options));
 out:
	free_server_options(&new_options);
	திரும்பு r;
}

நிலையான வெறுமை
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	க்கு (i = 0; i < options->இலக்கம்_host_சாவி_files; i++)
		விடுவி(options->host_சாவி_files[i]);
	விடுவி(options->host_சாவி_files);
	விடுவி(options->host_சாவி_file_userprovided);
}

நிலையான வெறுமை
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->இலக்கம்_queued_listens);

	க்கு (i = 0; i < options->இலக்கம்_listen_addrs; i++) {
		விடுவி(options->listen_addrs[i].rdomain);
		எனில் (options->listen_addrs[i].addrs != வெற்று)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	விடுவி(options->listen_addrs);
}

நிலையான வெறுமை
free_permituserenv(ServerOptions *options)
{
	விடுவி(options->permit_user_env_allowlist);
}

நிலையான வெறுமை
free_subsystem(ServerOptions *options)
{
	u_int i;

	க்கு (i = 0; i < options->இலக்கம்_subsystems; i++) {
		விடுவி(options->subsystem_name[i]);
		விடுவி(options->subsystem_command[i]);
		விடுவி(options->subsystem_args[i]);
	}
	விடுவி(options->subsystem_name);
	விடுவி(options->subsystem_command);
	விடுவி(options->subsystem_args);
}

வெறுமை
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		விடுவி(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	செய் { \
		விடுவி(options->var); \
		options->var = வெற்று; \
	} போது (0);
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

நிலையான வெறுமை
copy_server_option_int(முழு *dst, முழு src)
{
	எனில் (src != -1)
		*dst = src;
}

நிலையான வெறுமை
copy_server_option_int64(int64_t *dst, int64_t src)
{
	எனில் (src != -1)
		*dst = src;
}

நிலையான வெறுமை
copy_server_option_string(எழுத்து **dst, மாறிலி எழுத்து *src)
{
	எனில் (src != வெற்று && *dst != src) {
		விடுவி(*dst);
		*dst = xstrdup(src);
	}
}

நிலையான வெறுமை
copy_server_option_strarray_மதிப்புகள்(எழுத்து ***dst, u_int ndst,
    எழுத்து * மாறிலி *src, u_int nsrc)
{
	u_int i;

	எனில் (nsrc == 0)
		திரும்பு;
	க்கு (i = 0; i < ndst; i++)
		விடுவி((*dst)[i]);
	விடுவி(*dst);
	*dst = xcalloc(nsrc, அளவு(**dst));
	க்கு (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == வெற்று ? வெற்று : xstrdup(src[i]);
}

நிலையான வெறுமை
copy_server_option_strarray(எழுத்து ***dst, u_int *ndst,
    எழுத்து * மாறிலி *src, u_int nsrc)
{
	எனில் (nsrc == 0)
		திரும்பு;
	copy_server_option_strarray_மதிப்புகள்(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

நிலையான வெறுமை
copy_ipqos(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

நிலையான வெறுமை
copy_gatewayports(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

நிலையான வெறுமை
copy_streamlocalbindunlink(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

நிலையான வெறுமை
copy_loglevel(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	எனில் (src->log_level != -1)
		dst->log_level = src->log_level;
}

நிலையான வெறுமை
copy_rekeylimit(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

நிலையான வெறுமை
copy_subsystem(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	u_int old_இலக்கம்_subsystems = dst->இலக்கம்_subsystems;

	எனில் (src->இலக்கம்_subsystems == 0)
		திரும்பு;
	copy_server_option_strarray_மதிப்புகள்(&dst->subsystem_name,
	    old_இலக்கம்_subsystems, src->subsystem_name, src->இலக்கம்_subsystems);
	copy_server_option_strarray_மதிப்புகள்(&dst->subsystem_command,
	    old_இலக்கம்_subsystems, src->subsystem_command, src->இலக்கம்_subsystems);
	copy_server_option_strarray_மதிப்புகள்(&dst->subsystem_args,
	    old_இலக்கம்_subsystems, src->subsystem_args, src->இலக்கம்_subsystems);
	dst->இலக்கம்_subsystems = src->இலக்கம்_subsystems;
}

நிலையான வெறுமை
copy_pubkey_auth_options(ServerOptions *dst, மாறிலி ServerOptions *src)
{
	எனில் (src->pubkey_auth_options != -1) {
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
வெறுமை
copy_set_server_options(ServerOptions *dst, ServerOptions *src, முழு preauth)
{
	எனில் (dst == src)
		திரும்பு;

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
	செய் { \
		விடுவி(dst->var); \
		dst->var = வெற்று; \
	} போது (0);
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
	எனில் (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	செய் { \
		எனில் (option_clear_or_none(v)) { \
			விடுவி(v); \
			v = வெற்று; \
		} \
	} போது(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_சாவிகள்);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	எனில் (preauth)
		திரும்பு;

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
நிலையான வெறுமை
parse_server_config_depth(ServerOptions *options, மாறிலி எழுத்து *filename,
    கட்டமைப்பு sshbuf *conf, கட்டமைப்பு include_list *includes,
    கட்டமைப்பு connection_info *connectinfo, முழு flags, முழு *activep, முழு depth)
{
	முழு linenum, bad_options = 0;
	எழுத்து *cp, *obuf, *cbuf;

	எனில் (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	எனில் ((obuf = cbuf = sshbuf_dup_string(conf)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	போது ((cp = strsep(&cbuf, "\n")) != வெற்று) {
		எனில் (process_server_config_வரி_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	விடுவி(obuf);
	எனில் (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

வெறுமை
parse_server_config(ServerOptions *options, மாறிலி எழுத்து *filename,
    கட்டமைப்பு sshbuf *conf, கட்டமைப்பு include_list *includes,
    கட்டமைப்பு connection_info *connectinfo, முழு reexec)
{
	முழு active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	எனில் (!reexec)
		process_queued_listen_addrs(options);
}

நிலையான மாறிலி எழுத்து *
fmt_multistate_int(முழு val, மாறிலி கட்டமைப்பு multistate *m)
{
	u_int i;

	க்கு (i = 0; m[i].சாவி != வெற்று; i++) {
		எனில் (m[i].மதிப்பு == val)
			திரும்பு m[i].சாவி;
	}
	திரும்பு "UNKNOWN";
}

நிலையான மாறிலி எழுத்து *
fmt_intarg(ServerOpCodes code, முழு val)
{
	எனில் (val == -1)
		திரும்பு "unset";
	தேர்வு (code) {
	நிலை sAddressFamily:
		திரும்பு fmt_multistate_int(val, multistate_addressfamily);
	நிலை s_Permit_வேர்_Login:
		திரும்பு fmt_multistate_int(val, multistate_permitrootlogin);
	நிலை sGatewayPorts:
		திரும்பு fmt_multistate_int(val, multistate_gatewayports);
	நிலை sCompression:
		திரும்பு fmt_multistate_int(val, multistate_compression);
	நிலை sAllowTcpForwarding:
		திரும்பு fmt_multistate_int(val, multistate_tcpfwd);
	நிலை sAllowStreamLocalForwarding:
		திரும்பு fmt_multistate_int(val, multistate_tcpfwd);
	நிலை sIgnoreRhosts:
		திரும்பு fmt_multistate_int(val, multistate_ignore_rhosts);
	நிலை sTCPKeepAlive:
		திரும்பு fmt_multistate_int(val, multistate_keepalives);
	நிலை sWarnWeakCrypto:
		திரும்பு fmt_multistate_int(val, multistate_warnweakcrypto);
	நிலை sFingerprintHash:
		திரும்பு ssh_digest_alg_name(val);
	இயல்பு:
		தேர்வு (val) {
		நிலை 0:
			திரும்பு "no";
		நிலை 1:
			திரும்பு "yes";
		இயல்பு:
			திரும்பு "UNKNOWN";
		}
	}
}

நிலையான வெறுமை
dump_cfg_int(ServerOpCodes code, முழு val)
{
	எனில் (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		திரும்பு;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

நிலையான வெறுமை
dump_cfg_oct(ServerOpCodes code, முழு val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

நிலையான வெறுமை
dump_cfg_fmtint(ServerOpCodes code, முழு val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

நிலையான வெறுமை
dump_cfg_string(ServerOpCodes code, மாறிலி எழுத்து *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == வெற்று ? "none" : val);
}

நிலையான வெறுமை
dump_cfg_strarray(ServerOpCodes code, u_int மொத்தம், எழுத்து **vals)
{
	u_int i;

	க்கு (i = 0; i < மொத்தம்; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

நிலையான வெறுமை
dump_cfg_strarray_oneline(ServerOpCodes code, u_int மொத்தம், எழுத்து **vals)
{
	u_int i;

	தேர்வு (code) {
	நிலை sAuthenticationMethods:
	நிலை sChannelTimeout:
		நிறுத்து;
	இயல்பு:
		எனில் (மொத்தம் <= 0)
			திரும்பு;
		நிறுத்து;
	}

	printf("%s", lookup_opcode_name(code));
	க்கு (i = 0; i < மொத்தம்; i++)
		printf(" %s",  vals[i]);
	எனில் (code == sAuthenticationMethods && மொத்தம் == 0)
		printf(" any");
	இல்லையெனில் எனில் (code == sChannelTimeout && மொத்தம் == 0)
		printf(" none");
	printf("\n");
}

நிலையான எழுத்து *
format_listen_addrs(கட்டமைப்பு listenaddr *la)
{
	முழு r;
	கட்டமைப்பு addrinfo *ai;
	எழுத்து addr[NI_MAXHOST], port[NI_MAXSERV];
	எழுத்து *laddr1 = xstrdup(""), *laddr2 = வெற்று;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	க்கு (ai = la->addrs; ai; ai = ai->ai_next) {
		எனில் ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    அளவு(addr), port, அளவு(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			தொடர்;
		}
		laddr2 = laddr1;
		எனில் (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == வெற்று ? "" : " rdomain ",
			    la->rdomain == வெற்று ? "" : la->rdomain,
			    laddr2);
		} இல்லையெனில் {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == வெற்று ? "" : " rdomain ",
			    la->rdomain == வெற்று ? "" : la->rdomain,
			    laddr2);
		}
		விடுவி(laddr2);
	}
	திரும்பு laddr1;
}

வெறுமை
dump_config(ServerOptions *o)
{
	எழுத்து *s;
	u_int i;

	/* these are usually at the top of the config */
	க்கு (i = 0; i < o->இலக்கம்_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	க்கு (i = 0; i < o->இலக்கம்_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		விடுவி(s);
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
	dump_cfg_int(s_Client_Alive_மொத்தம்_Max, o->client_alive_மொத்தம்_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_வேர்_Login, o->permit_வேர்_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_சாவிகள்);
	dump_cfg_string(s_Security_சாவி_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_சாவிகள்_Command, o->authorized_சாவிகள்_command);
	dump_cfg_string(s_Authorized_சாவிகள்_Command_User, o->authorized_சாவிகள்_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_சாவி_Agent, o->host_சாவி_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_சாவி_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#எனில் defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_சாவிகள்_File, o->இலக்கம்_authkeys_files,
	    o->authorized_சாவிகள்_files);
	dump_cfg_strarray_oneline(s_Revoked_சாவிகள், o->இலக்கம்_revoked_சாவிகள்_files,
	    o->revoked_சாவிகள்_files);
	dump_cfg_strarray(s_Host_சாவி, o->இலக்கம்_host_சாவி_files, o->host_சாவி_files);
	dump_cfg_strarray(sHostCertificate, o->இலக்கம்_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->இலக்கம்_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->இலக்கம்_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->இலக்கம்_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->இலக்கம்_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->இலக்கம்_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->இலக்கம்_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->இலக்கம்_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->இலக்கம்_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->இலக்கம்_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	க்கு (i = 0; i < o->இலக்கம்_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	எனில் (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	இல்லையெனில்
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = வெற்று;
	க்கு (i = 0; tunmode_desc[i].val != -1; i++) {
		எனில் (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			நிறுத்து;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	எனில் (o->இலக்கம்_permitted_opens == 0)
		printf(" any");
	இல்லையெனில் {
		க்கு (i = 0; i < o->இலக்கம்_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	எனில் (o->இலக்கம்_permitted_listens == 0)
		printf(" any");
	இல்லையெனில் {
		க்கு (i = 0; i < o->இலக்கம்_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	எனில் (o->permit_user_env_allowlist == வெற்று) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} இல்லையெனில் {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	எனில் (o->pubkey_auth_options == 0)
		printf(" none");
	எனில் (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	எனில் (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	எனில் (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	எனில் (o->per_source_penalty.enabled) {
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
	} இல்லையெனில்
		printf("PerSourcePenalties no\n");
}
