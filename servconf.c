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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>
#ifdef __OpenBSD__
#include <sys/sysctl.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#include <ctype.h>
#include <glob.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>
#include <util.h>

#include "xmalloc.h"
#include "ssh.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "servconf.h"
#include "pathnames.h"
#include "cipher.h"
#include "sshkey.h"
#include "kex.h"
#include "mac.h"
#include "match.h"
#include "channels.h"
#include "groupaccess.h"
#include "canohost.h"
#include "packet.h"
#include "ssherr.h"
#include "hostfile.h"
#include "auth.h"
#include "myproposal.h"
#include "digest.h"
#include "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#නම් !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

static void add_listen_addr(ServerOptions *, const var_na *,
    const var_na *, පූර්ණ_සංඛ්‍යා);
static void add_one_listen_addr(ServerOptions *, const var_na *,
    const var_na *, පූර්ණ_සංඛ්‍යා);
static void parse_server_config_depth(ServerOptions *options,
    const var_na *filename, sa_nracanaa sshbuf *conf, sa_nracanaa include_list *includes,
    sa_nracanaa connection_info *connectinfo, පූර්ණ_සංඛ්‍යා flags, පූර්ණ_සංඛ්‍යා *activep, පූර්ණ_සංඛ්‍යා depth);

extern sa_nracanaa sshbuf *cfg;

/* Initializes the server options to their default values. */

void
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, parimaa_na(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = NULL;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = NULL;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = NULL;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_key_files = 0; \
	options->num_host_key_files = 0; \
	options->host_key_file_userprovided = NULL;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = NULL; \
	options->num_queued_listens = 0; \
	options->listen_addrs = NULL; \
	options->num_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->num_ports = 0; \
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
	options->permit_user_env_allowlist = NULL;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = NULL; \
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
	options->num_subsystems = 0; \
	options->subsystem_name = NULL; \
	options->subsystem_command = NULL; \
	options->subsystem_args = NULL;
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
static පූර්ණ_සංඛ්‍යා
option_clear_or_none(const var_na *o)
{
	ආපසු o == NULL || strcasecmp(o, "none") == 0;
}

static void
assemble_algorithms(ServerOptions *o)
{
	var_na *all_cipher, *all_mac, *all_kex, *all_key, *all_sig;
	var_na *def_cipher, *def_mac, *def_kex, *def_key, *def_sig;
	පූර්ණ_සංඛ්‍යා r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_key = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_key = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_key);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	do { \
		නම් ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} අතරතුර (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_key, all_key);
	ASSEMBLE(hostbased_accepted_algos, def_key, all_key);
	ASSEMBLE(pubkey_accepted_algos, def_key, all_key);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	free(all_cipher);
	free(all_mac);
	free(all_kex);
	free(all_key);
	free(all_sig);
	free(def_cipher);
	free(def_mac);
	free(def_kex);
	free(def_key);
	free(def_sig);
}

void
servconf_add_hostkey(const var_na *file, const පූර්ණ_සංඛ්‍යා line,
    ServerOptions *options, const var_na *path, පූර්ණ_සංඛ්‍යා userprovided)
{
	var_na *apath = derelativise_path(path);

	opt_array_append2(file, line, "HostKey",
	    &options->host_key_files, &options->host_key_file_userprovided,
	    &options->num_host_key_files, apath, userprovided);
	free(apath);
}

void
servconf_add_hostcert(const var_na *file, const පූර්ණ_සංඛ්‍යා line,
    ServerOptions *options, const var_na *path)
{
	var_na *apath = derelativise_path(path);

	opt_array_append(file, line, "HostCertificate",
	    &options->host_cert_files, &options->num_host_cert_files, apath);
	free(apath);
}

void
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	නම් (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	නම් (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	නම් (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	නම් (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	do { \
		free(options->var); \
		options->var = NULL; \
	} අතරතුර (0);
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
	නම් (options->pam_service_name == NULL)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	නම් (options->num_host_key_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_RSA_KEY_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_ECDSA_KEY_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_ED25519_KEY_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_MLDSA44_ED25519_KEY_FILE, 0);
	}
	/* No certificates by default */
	නම් (options->num_ports == 0)
		options->ports[options->num_ports++] = SSH_DEFAULT_PORT;
	නම් (options->listen_addrs == NULL)
		add_listen_addr(options, NULL, NULL, 0);
	නම් (options->pid_file == NULL)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	නම් (options->moduli_file == NULL)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	නම් (options->xauth_location == NULL)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	නම් (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	නම් (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	නම් (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = NULL;
	}
	නම් (options->rekey_limit == -1)
		options->rekey_limit = 0;
	නම් (options->rekey_interval == -1)
		options->rekey_interval = 0;
	නම් (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	නම් (options->max_startups == -1)
		options->max_startups = 100;
	නම් (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	නම් (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	නම් (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	නම් (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	නම් (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	නම් (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	නම් (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	නම් (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	නම් (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	නම් (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	නම් (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	නම් (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	නම් (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	නම් (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	නම් (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	නම් (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	නම් (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	නම් (options->num_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_keys_files,
		    &options->num_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_keys_files,
		    &options->num_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	නම් (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	නම් (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	නම් (options->version_addendum == NULL)
		options->version_addendum = xstrdup("");
	නම් (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	නම් (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	නම් (options->sk_provider == NULL)
		options->sk_provider = xstrdup("internal");
	නම් (options->sshd_session_path == NULL)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	නම් (options->sshd_auth_path == NULL)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	නම් (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	නම් (options->agent_socket_path == NULL)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	do { \
		නම් (option_clear_or_none(v)) { \
			free(v); \
			v = NULL; \
		} \
	} අතරතුර(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	do { \
		නම් (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			free(options->v[0]); \
			free(options->v); \
			options->v = NULL; \
			options->nv = 0; \
		} \
	} අතරතුර (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_keys);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_key_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	සඳහා (i = 0; i < options->num_host_key_files; i++)
		CLEAR_ON_NONE(options->host_key_files[i]);
	සඳහා (i = 0; i < options->num_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, num_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, num_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_keys_files, num_revoked_keys_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_keys_files, num_authkeys_files, "none");
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
typedef ga_nanaa {
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
static sa_nracanaa {
	const var_na *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ NULL, sBadOption, 0 }
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

static sa_nracanaa {
	පූර්ණ_සංඛ්‍යා val;
	var_na *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, NULL }
};

/* Returns an opcode name from its number */

static const var_na *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	සඳහා (i = 0; keywords[i].name != NULL; i++)
		නම් (keywords[i].opcode == code)
			ආපසු(keywords[i].name);
	ආපසු "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

static ServerOpCodes
parse_token(const var_na *cp, const var_na *filename,
	    පූර්ණ_සංඛ්‍යා linenum, u_int *flags)
{
	u_int i;

	සඳහා (i = 0; keywords[i].name; i++)
		නම් (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			ආපසු keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ආපසු sBadOption;
}

var_na *
derelativise_path(const var_na *path)
{
	var_na *expanded, *ret, cwd[PATH_MAX];

	නම් (strcasecmp(path, "none") == 0)
		ආපසු xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	නම් (path_absolute(expanded))
		ආපසු expanded;
	නම් (getcwd(cwd, parimaa_na(cwd)) == NULL)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	free(expanded);
	ආපසු ret;
}

static void
add_listen_addr(ServerOptions *options, const var_na *addr,
    const var_na *rdomain, පූර්ණ_සංඛ්‍යා port)
{
	u_int i;

	නම් (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	නැතහොත් {
		සඳහා (i = 0; i < options->num_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

static void
add_one_listen_addr(ServerOptions *options, const var_na *addr,
    const var_na *rdomain, පූර්ණ_සංඛ්‍යා port)
{
	sa_nracanaa addrinfo hints, *ai, *aitop;
	var_na strport[NI_MAXSERV];
	පූර්ණ_සංඛ්‍යා gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	සඳහා (i = 0; i < options->num_listen_addrs; i++) {
		නම් (rdomain == NULL && options->listen_addrs[i].rdomain == NULL)
			bha_nga;
		නම් (rdomain == NULL || options->listen_addrs[i].rdomain == NULL)
			continue;
		නම් (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			bha_nga;
	}
	නම් (i >= options->num_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		නම් (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->num_listen_addrs, options->num_listen_addrs + 1,
		    parimaa_na(*options->listen_addrs));
		i = options->num_listen_addrs++;
		නම් (rdomain != NULL)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, parimaa_na(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == NULL) ? AI_PASSIVE : 0;
	snprintf(strport, parimaa_na strport, "%d", port);
	නම් ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	සඳහා (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
static පූර්ණ_සංඛ්‍යා
valid_rdomain(const var_na *name)
{
#නම් defined(HAVE_SYS_VALID_RDOMAIN)
	ආපසු sys_valid_rdomain(name);
#elif defined(__OpenBSD__)
	const var_na *errstr;
	long long num;
	sa_nracanaa rt_tableinfo info;
	පූර්ණ_සංඛ්‍යා mib[6];
	size_t miblen = parimaa_na(mib);

	නම් (name == NULL)
		ආපසු 1;

	num = strtonum(name, 0, 255, &errstr);
	නම් (errstr != NULL)
		ආපසු 0;

	/* Check whether the table actually exists */
	memset(mib, 0, parimaa_na(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (පූර්ණ_සංඛ්‍යා)num;
	නම් (sysctl(mib, 6, &info, &miblen, NULL, 0) == -1)
		ආපසු 0;

	ආපසු 1;
#නැතහොත් /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	ආපසු 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
static void
queue_listen_addr(ServerOptions *options, const var_na *addr,
    const var_na *rdomain, පූර්ණ_සංඛ්‍යා port)
{
	sa_nracanaa queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->num_queued_listens, options->num_queued_listens + 1,
	    parimaa_na(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->num_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == NULL ? NULL : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
static void
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	sa_nracanaa queued_listenaddr *qla;

	නම් (options->num_ports == 0)
		options->ports[options->num_ports++] = SSH_DEFAULT_PORT;
	නම් (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	සඳහා (i = 0; i < options->num_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		free(qla->addr);
		free(qla->rdomain);
	}
	free(options->queued_listen_addrs);
	options->queued_listen_addrs = NULL;
	options->num_queued_listens = 0;
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

static පූර්ණ_සංඛ්‍යා
match_cfg_line_group(const var_na *grps, පූර්ණ_සංඛ්‍යා line, const var_na *user)
{
	පූර්ණ_සංඛ්‍යා result = 0;
	sa_nracanaa passwd *pw;

	නම් (user == NULL)
		goto out;

	නම් ((pw = getpwnam(user)) == NULL) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", line, user);
	} නැතහොත් නම් (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, line);
	} නැතහොත් නම් (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, line);
	} නැතහොත් {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, line);
		result = 1;
	}
out:
	ga_free();
	ආපසු result;
}

static void
match_test_missing_fatal(const var_na *criteria, const var_na *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
static පූර්ණ_සංඛ්‍යා
match_cfg_line(const var_na *full_line, පූර්ණ_සංඛ්‍යා *acp, var_na ***avp,
    පූර්ණ_සංඛ්‍යා line, sa_nracanaa connection_info *ci)
{
	පූර්ණ_සංඛ්‍යා result = 1, attributes = 0, port;
	var_na *arg, *attrib = NULL, *oattrib;

	නම් (ci == NULL) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_line, line);
	} නැතහොත් {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_line,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", line);
	}

	අතරතුර ((oattrib = argv_next(acp, avp)) != NULL) {
		/* Terminate on comment */
		නම් (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			bha_nga;
		}
		attrib = xstrdup(oattrib);
		arg = NULL;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		නම් (strcasecmp(attrib, "all") == 0) {
			නම් (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != NULL &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				goto out;
			}
			නම් (arg != NULL && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			goto out;
		}
		/* Criterion "invalid-user" also has no argument */
		නම් (strcasecmp(attrib, "invalid-user") == 0) {
			නම් (ci == NULL) {
				result = 0;
				goto next;
			}
			නම් (ci->user_invalid == 0)
				result = 0;
			නැතහොත්
				debug("matched invalid-user at line %d", line);
			goto next;
		}

		/* Keep this list in sync with below */
		නම් (strprefix(attrib, "user=", 1) != NULL ||
		    strprefix(attrib, "group=", 1) != NULL ||
		    strprefix(attrib, "host=", 1) != NULL ||
		    strprefix(attrib, "address=", 1) != NULL ||
		    strprefix(attrib, "localaddress=", 1) != NULL ||
		    strprefix(attrib, "localport=", 1) != NULL ||
		    strprefix(attrib, "rdomain=", 1) != NULL ||
		    strprefix(attrib, "version=", 1) != NULL) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} නැතහොත් {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		නම් (arg == NULL || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			goto out;
		}
		නම් (strcasecmp(attrib, "user") == 0) {
			නම් (ci == NULL || (ci->test && ci->user == NULL)) {
				result = 0;
				goto next;
			}
			නම් (ci->user == NULL)
				match_test_missing_fatal("User", "user");
			නම් (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			නැතහොත්
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, line);
		} නැතහොත් නම් (strcasecmp(attrib, "group") == 0) {
			නම් (ci == NULL || (ci->test && ci->user == NULL)) {
				result = 0;
				goto next;
			}
			නම් (ci->user == NULL)
				match_test_missing_fatal("Group", "user");
			switch (match_cfg_line_group(arg, line, ci->user)) {
			pak_sa -1:
				result = -1;
				goto out;
			pak_sa 0:
				result = 0;
			}
		} නැතහොත් නම් (strcasecmp(attrib, "host") == 0) {
			නම් (ci == NULL || (ci->test && ci->host == NULL)) {
				result = 0;
				goto next;
			}
			නම් (ci->host == NULL)
				match_test_missing_fatal("Host", "host");
			නම් (match_hostname(ci->host, arg) != 1)
				result = 0;
			නැතහොත්
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, line);
		} නැතහොත් නම් (strcasecmp(attrib, "address") == 0) {
			නම් (ci == NULL || (ci->test && ci->address == NULL)) {
				නම් (addr_match_list(NULL, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, line);
				result = 0;
				goto next;
			}
			නම් (ci->address == NULL)
				match_test_missing_fatal("Address", "addr");
			switch (addr_match_list(ci->address, arg)) {
			pak_sa 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, line);
				bha_nga;
			pak_sa 0:
			pak_sa -1:
				result = 0;
				bha_nga;
			pak_sa -2:
				result = -1;
				goto out;
			}
		} නැතහොත් නම් (strcasecmp(attrib, "localaddress") == 0){
			නම් (ci == NULL || (ci->test && ci->laddress == NULL)) {
				නම් (addr_match_list(NULL, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    line);
				result = 0;
				goto next;
			}
			නම් (ci->laddress == NULL)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			switch (addr_match_list(ci->laddress, arg)) {
			pak_sa 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, line);
				bha_nga;
			pak_sa 0:
			pak_sa -1:
				result = 0;
				bha_nga;
			pak_sa -2:
				result = -1;
				goto out;
			}
		} නැතහොත් නම් (strcasecmp(attrib, "localport") == 0) {
			නම් ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				goto out;
			}
			නම් (ci == NULL || (ci->test && ci->lport == -1)) {
				result = 0;
				goto next;
			}
			නම් (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			නම් (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, line);
			නැතහොත්
				result = 0;
		} නැතහොත් නම් (strcasecmp(attrib, "rdomain") == 0) {
			නම් (ci == NULL || (ci->test && ci->rdomain == NULL)) {
				result = 0;
				goto next;
			}
			නම් (ci->rdomain == NULL)
				match_test_missing_fatal("RDomain", "rdomain");
			නම් (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			නැතහොත්
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, line);
		} නැතහොත් නම් (strcasecmp(attrib, "version") == 0) {
			නම් (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			නැතහොත්
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, line);
		} නැතහොත් {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			goto out;
		}
 next:
		free(attrib);
		attrib = NULL;
	}
	නම් (attributes == 0) {
		error("One or more attributes required for Match");
		ආපසු -1;
	}
 out:
	නම් (ci != NULL && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", line);
	free(attrib);
	ආපසු result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
sa_nracanaa multistate {
	var_na *key;
	පූර්ණ_සංඛ්‍යා value;
};
static const sa_nracanaa multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ NULL, -1 }
};

static පූර්ණ_සංඛ්‍යා
process_server_config_line_depth(ServerOptions *options, var_na *line,
    const var_na *filename, පූර්ණ_සංඛ්‍යා linenum, පූර්ණ_සංඛ්‍යා *activep,
    sa_nracanaa connection_info *connectinfo, පූර්ණ_සංඛ්‍යා *inc_flags, පූර්ණ_සංඛ්‍යා depth,
    sa_nracanaa include_list *includes)
{
	var_na *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	පූර්ණ_සංඛ්‍යා cmdline = 0, *intptr, value, value2, value3, n, port, oactive, r;
	dviguu_na dvalue, *doubleptr = NULL;
	පූර්ණ_සංඛ්‍යා ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	const sa_nracanaa multistate *multistate_ptr;
	const var_na *errstr;
	sa_nracanaa include_item *item;
	glob_t gbuf;
	var_na **oav = NULL, **av;
	පූර්ණ_සංඛ්‍යා oac = 0, ac;
	පූර්ණ_සංඛ්‍යා ret = -1;
	var_na **strs = NULL; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	නම් ((len = strlen(line)) == 0)
		ආපසු 0;
	සඳහා (len--; len > 0; len--) {
		නම් (strchr(WHITESPACE "\f", line[len]) == NULL)
			bha_nga;
		line[len] = '\0';
	}

	str = line;
	නම් ((keyword = strdelim(&str)) == NULL)
		ආපසු 0;
	/* Ignore leading whitespace */
	නම් (*keyword == '\0')
		keyword = strdelim(&str);
	නම් (!keyword || !*keyword || *keyword == '#')
		ආපසු 0;
	නම් (str == NULL || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ආපසු -1;
	}
	intptr = NULL;
	charptr = NULL;
	opcode = parse_token(keyword, filename, linenum, &flags);

	නම් (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ආපසු -1;
	}
	ac = oac;
	av = oav;

	නම් (activep == NULL) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	නම් (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	නම් (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		නම් (connectinfo == NULL) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} නැතහොත් { /* this is a directive we have already processed */
			ret = 0;
			goto out;
		}
	}

	switch (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	pak_sa sUsePAM:
		intptr = &options->use_pam;
		goto parse_flag;
	pak_sa sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;
#endif

	/* Standard Options */
	pak_sa sBadOption:
		goto out;
	pak_sa sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		නම් (options->ports_from_cmdline) {
			argv_consume(&ac);
			bha_nga;
		}
		නම් (options->num_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->num_ports++] = a2port(arg);
		නම් (options->ports[options->num_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		bha_nga;

	pak_sa sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		නම් ((value = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		නම් (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa sListenAddress:
		arg = argv_next(&ac, &av);
		නම් (arg == NULL || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		නම් (strchr(arg, '[') == NULL && (p = strchr(arg, ':')) != NULL
		    && strchr(p+1, ':') != NULL) {
			port = 0;
			p = arg;
		} නැතහොත් {
			arg2 = NULL;
			p = hpdelim(&arg);
			නම් (p == NULL)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			නම් (arg == NULL)
				port = 0;
			නැතහොත් නම් ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = NULL;
		නම් ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == NULL)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			නම් (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		bha_nga;

	pak_sa sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		value = -1;
		සඳහා (i = 0; multistate_ptr[i].key != NULL; i++) {
			නම් (strcasecmp(arg, multistate_ptr[i].key) == 0) {
				value = multistate_ptr[i].value;
				bha_nga;
			}
		}
		නම් (value == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		නම් (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa sHostKey:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		නම් (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		bha_nga;

	pak_sa sHostKeyAgent:
		charptr = &options->host_key_agent;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		නම් (*activep && *charptr == NULL)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		bha_nga;

	pak_sa sHostCertificate:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		නම් (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		bha_nga;

	pak_sa sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		නම් (*activep && *charptr == NULL) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			නම් (intptr != NULL)
				*intptr = *intptr + 1;
		}
		bha_nga;

	pak_sa sModuliFile:
		charptr = &options->moduli_file;
		goto parse_filename;

	pak_sa sPermitRootLogin:
		intptr = &options->permit_root_login;
		multistate_ptr = multistate_permitrootlogin;
		goto parse_multistate;

	pak_sa sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		goto parse_multistate;

	pak_sa sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		goto parse_multistate;

	pak_sa sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		goto parse_flag;

	pak_sa sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		goto parse_flag;

	pak_sa sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		නම් (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa sHostKeyAlgorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		goto parse_pubkey_algos;

	pak_sa sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		goto parse_pubkey_algos;

	pak_sa sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		goto parse_flag;

	pak_sa sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		goto parse_pubkey_algos;

	pak_sa sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		value = 0;
		value2 = -1;
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (strcasecmp(arg, "none") == 0)
				continue;
			නම් (strcasecmp(arg, "touch-required") == 0)
				value |= PUBKEYAUTH_TOUCH_REQUIRED;
			නැතහොත් නම් (strcasecmp(arg, "verify-required") == 0)
				value |= PUBKEYAUTH_VERIFY_REQUIRED;
			නැතහොත් නම් (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				නම් (errstr != NULL) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					goto out;
				}
			} නැතහොත් {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				goto out;
			}
		}
		නම් (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = value;
			options->max_pubkey_ok = value2;
		}
		bha_nga;

#ifdef KRB5
	pak_sa sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		goto parse_flag;

	pak_sa sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		goto parse_flag;

	pak_sa sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		goto parse_flag;
#ifdef USE_AFS
	pak_sa sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		goto parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	pak_sa sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		goto parse_flag;

	pak_sa sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		goto parse_flag;

	pak_sa sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		goto parse_flag;

	pak_sa sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		goto parse_flag;
#endif /* GSSAPI */

	pak_sa sPasswordAuthentication:
		intptr = &options->password_authentication;
		goto parse_flag;

	pak_sa sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		goto parse_flag;

	pak_sa sPrintMotd:
		intptr = &options->print_motd;
		goto parse_flag;

#ifndef DISABLE_LASTLOG
	pak_sa sPrintLastLog:
		intptr = &options->print_lastlog;
		goto parse_flag;
#endif

	pak_sa sX11Forwarding:
		intptr = &options->x11_forwarding;
		goto parse_flag;

	pak_sa sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		නම් ((errstr = atoi_err(arg, &value)) != NULL)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		නම් (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		goto parse_flag;

	pak_sa sXAuthLocation:
		charptr = &options->xauth_location;
		goto parse_filename;

	pak_sa sPermitTTY:
		intptr = &options->permit_tty;
		goto parse_flag;

	pak_sa sPermitUserRC:
		intptr = &options->permit_user_rc;
		goto parse_flag;

	pak_sa sStrictModes:
		intptr = &options->strict_modes;
		goto parse_flag;

	pak_sa sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		goto parse_multistate;

	pak_sa sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		goto parse_flag;

	pak_sa sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		value = 0;
		p = NULL;
		නම් (strcmp(arg, "yes") == 0)
			value = 1;
		නැතහොත් නම් (strcmp(arg, "no") == 0)
			value = 0;
		නැතහොත් {
			/* Pattern-list specified */
			value = 1;
			p = xstrdup(arg);
		}
		නම් (*activep && *intptr == -1) {
			*intptr = value;
			*charptr = p;
			p = NULL;
		}
		free(p);
		bha_nga;

	pak_sa sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		goto parse_multistate;

	pak_sa sRekeyLimit:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (strcmp(arg, "default") == 0) {
			val64 = 0;
		} නැතහොත් {
			නම් (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			නම් (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		නම් (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		නම් (ac != 0) { /* optional rekey interval present */
			නම් (strcmp(av[0], "none") == 0) {
				(void)argv_next(&ac, &av);	/* discard */
				bha_nga;
			}
			intptr = &options->rekey_interval;
			goto parse_time;
		}
		bha_nga;

	pak_sa sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		goto parse_multistate;

	pak_sa sUseDNS:
		intptr = &options->use_dns;
		goto parse_flag;

	pak_sa sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		value = log_facility_number(arg);
		නම් (value == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		නම් (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) value;
		bha_nga;

	pak_sa sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		value = log_level_number(arg);
		නම් (value == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		නම් (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) value;
		bha_nga;

	pak_sa sLogVerbose:
		found = options->num_log_verbose == 0;
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			නම් (strcasecmp(arg, "none") == 0) {
				නම් (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		නම් (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		නම් (found && *activep) {
			options->log_verbose = strs;
			options->num_log_verbose = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		goto parse_multistate;

	pak_sa sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		goto parse_multistate;

	pak_sa sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		goto parse_flag;

	pak_sa sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		නම් (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			නම් (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} නැතහොත් නම් (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			නම් (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} නැතහොත් නම් (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa sDisableForwarding:
		intptr = &options->disable_forwarding;
		goto parse_flag;

	pak_sa sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->num_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (*arg == '\0' ||
			    match_user(NULL, NULL, NULL, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			නම් (!*activep)
				continue;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		නම් (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		bha_nga;

	pak_sa sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->num_deny_users;
		goto parse_allowdenyusers;

	pak_sa sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->num_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			නම් (!*activep)
				continue;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		නම් (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		bha_nga;

	pak_sa sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->num_deny_groups;
		goto parse_allowdenygroups;

	pak_sa sCiphers:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		නම් (options->ciphers == NULL)
			options->ciphers = xstrdup(arg);
		bha_nga;

	pak_sa sMacs:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		නම් (options->macs == NULL)
			options->macs = xstrdup(arg);
		bha_nga;

	pak_sa sKexAlgorithms:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		නම් (options->kex_algorithms == NULL)
			options->kex_algorithms = xstrdup(arg);
		bha_nga;

	pak_sa sSubsystem:
		නම් ((arg = argv_next(&ac, &av)) == NULL || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == NULL || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (!*activep) {
			argv_consume(&ac);
			bha_nga;
		}
		found = 0;
		සඳහා (i = 0; i < options->num_subsystems; i++) {
			නම් (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				bha_nga;
			}
		}
		නම් (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			bha_nga;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->num_subsystems,
		    options->num_subsystems + 1,
		    parimaa_na(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->num_subsystems,
		    options->num_subsystems + 1,
		    parimaa_na(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->num_subsystems,
		    options->num_subsystems + 1,
		    parimaa_na(*options->subsystem_args));
		options->subsystem_name[options->num_subsystems] = xstrdup(arg);
		options->subsystem_command[options->num_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->num_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		free(arg2);
		free(arg);
		argv_consume(&ac);
		options->num_subsystems++;
		bha_nga;

	pak_sa sMaxStartups:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		නම් ((n = sscanf(arg, "%d:%d:%d",
		    &value, &value2, &value3)) == 3) {
			නම් (value > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} නැතහොත් නම් (n == 1) {
			value3 = value;
			value2 = -1;
		} නැතහොත් {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		නම් (value <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		නම් (*activep && options->max_startups == -1) {
			options->max_startups_begin = value;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		bha_nga;

	pak_sa sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		switch (n = sscanf(arg, "%d:%d", &value, &value2)) {
		pak_sa 2:
			නම් (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		pak_sa 1:
			නම් (value < 0 || value > 32)
				n = -1;
		}
		නම් (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		නම් (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = value;
			නම් (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		bha_nga;

	pak_sa sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (strcmp(arg, "none") == 0) { /* no limit */
			value = INT_MAX;
		} නැතහොත් {
			නම් ((errstr = atoi_err(arg, &value)) != NULL)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		නම් (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = value;
		bha_nga;

	pak_sa sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		නම් (addr_match_list(NULL, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa sPerSourcePenalties:
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			const var_na *q = NULL;

			found = 1;
			intptr = NULL;
			doubleptr = NULL;
			value = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			නම් (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				නම් (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				නම් (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				continue;
			} නැතහොත් නම් ((q = strprefix(arg, "crash:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} නැතහොත් නම් ((q = strprefix(arg, "authfail:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} නැතහොත් නම් ((q = strprefix(arg, "invaliduser:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} නැතහොත් නම් ((q = strprefix(arg, "noauth:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} නැතහොත් නම් ((q = strprefix(arg, "grace-exceeded:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} නැතහොත් නම් ((q = strprefix(arg, "refuseconnection:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} නැතහොත් නම් ((q = strprefix(arg, "max:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} නැතහොත් නම් ((q = strprefix(arg, "min:", 0)) != NULL) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} නැතහොත් නම් ((q = strprefix(arg, "max-sources4:", 0)) != NULL) {
				intptr = &options->per_source_penalty.max_sources4;
				නම් ((errstr = atoi_err(q, &value)) != NULL)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} නැතහොත් නම් ((q = strprefix(arg, "max-sources6:", 0)) != NULL) {
				intptr = &options->per_source_penalty.max_sources6;
				නම් ((errstr = atoi_err(q, &value)) != NULL)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} නැතහොත් නම් (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				value = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} නැතහොත් නම් (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				value = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} නැතහොත් නම් (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				value = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} නැතහොත් නම් (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				value = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} නැතහොත් {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			නම් (doubleptr != NULL) {
				නම් ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				නම් (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} නැතහොත් නම් (intptr != NULL) {
				නම් (*activep && *intptr == -1) {
					*intptr = value;
					options->per_source_penalty.enabled = 1;
				}
			} නැතහොත් {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		නම් (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		bha_nga;

	pak_sa sMaxAuthTries:
		intptr = &options->max_authtries;
		goto parse_int;

	pak_sa sMaxSessions:
		intptr = &options->max_sessions;
		goto parse_int;

	pak_sa sBanner:
		charptr = &options->banner;
		goto parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	pak_sa sAuthorizedKeysFile:
		uintptr = &options->num_authkeys_files;
		chararrayptr = &options->authorized_keys_files;
 parse_filenames:
		found = *uintptr == 0;
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			නම් (strcasecmp(arg, "none") == 0) {
				නම් (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			free(arg2);
		}
		නම් (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		නම් (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (*activep && *charptr == NULL) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			නම් (intptr != NULL)
				*intptr = *intptr + 1;
		}
		bha_nga;

	pak_sa sClientAliveInterval:
		intptr = &options->client_alive_interval;
		goto parse_time;

	pak_sa sClientAliveCountMax:
		intptr = &options->client_alive_count_max;
		goto parse_int;

	pak_sa sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (*arg == '\0' || strchr(arg, '=') != NULL)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			නම් (!*activep)
				continue;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->num_accept_env,
			    arg);
		}
		නම් (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		bha_nga;

	pak_sa sSetEnv:
		found = options->num_setenv == 0;
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (*arg == '\0' || strchr(arg, '=') == NULL)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			නම් (lookup_setenv_in_list(arg, strs, nstrs) != NULL) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				continue;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		නම් (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		නම් (found && *activep) {
			options->setenv = strs;
			options->num_setenv = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		value = -1;
		සඳහා (i = 0; tunmode_desc[i].val != -1; i++)
			නම් (strcmp(tunmode_desc[i].text, arg) == 0) {
				value = tunmode_desc[i].val;
				bha_nga;
			}
		නම් (value == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		නම් (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa sInclude:
		නම් (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		value = 0;
		අතරතුර ((arg2 = argv_next(&ac, &av)) != NULL) {
			නම් (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			value++;
			found = 0;
			නම් (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} නැතහොත්
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				නම් (strcmp(item->selector, arg) != 0)
					continue;
				නම් (item->filename != NULL) {
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
			නම් (found != 0) {
				free(arg);
				continue;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			නම් ((r = glob(arg, 0, NULL, &gbuf)) != 0) {
				නම් (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, parimaa_na(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			නම් (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			සඳහා (n = 0; n < (පූර්ණ_සංඛ්‍යා)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, parimaa_na(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				නම් ((item->contents = sshbuf_new()) == NULL)
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
			free(arg);
		}
		නම් (value == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		bha_nga;

	pak_sa sMatch:
		නම් (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		value = match_cfg_line(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? NULL : connectinfo));
		නම් (value < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : value;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		bha_nga;

	pak_sa sPermitListen:
	pak_sa sPermitOpen:
		නම් (opcode == sPermitListen) {
			uintptr = &options->num_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} නැතහොත් {
			uintptr = &options->num_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				නම් (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				continue;
			}

			නම් (opcode == sPermitListen &&
			    strchr(arg, ':') == NULL) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} නැතහොත් {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				නම් (p == NULL) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			නම් (arg == NULL ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			free(arg2);
		}
		නම් (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		නම් (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa sForceCommand:
		නම් (str == NULL || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		නම් (*activep && options->adm_forced_command == NULL)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		bha_nga;

	pak_sa sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_keys;
		goto parse_filename;

	pak_sa sRevokedKeys:
		uintptr = &options->num_revoked_keys_files;
		chararrayptr = &options->revoked_keys_files;
		goto parse_filenames;

	pak_sa sSecurityKeyProvider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (*activep && *charptr == NULL) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			නම් (intptr != NULL)
				*intptr = *intptr + 1;
		}
		bha_nga;

	pak_sa sIPQoS:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් ((value = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		නම් (value == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		නම් (arg == NULL)
			value2 = value;
		නැතහොත් නම් ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		නම් (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		නම් (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = value;
			options->ip_qos_bulk = value2;
		}
		bha_nga;

	pak_sa sVersionAddendum:
		නම් (str == NULL || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		නම් (strchr(str + len, '\r') != NULL) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		නම් ((arg = strchr(line, '#')) != NULL) {
			*arg = '\0';
			rtrim(line);
		}
		නම් (*activep && options->version_addendum == NULL) {
			නම් (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			නැතහොත්
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		bha_nga;

	pak_sa sAuthorizedKeysCommand:
		charptr = &options->authorized_keys_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		නම් (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		bha_nga;

	pak_sa sAuthorizedKeysCommandUser:
		charptr = &options->authorized_keys_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		goto parse_command;

	pak_sa sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		goto parse_localuser;

	pak_sa sAuthenticationMethods:
		found = options->num_auth_methods == 0;
		value = 0; /* seen "any" pseudo-method */
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			නම් (strcmp(arg, "any") == 0) {
				නම් (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				value = 1;
			} නැතහොත් නම් (value) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} නැතහොත් නම් (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		නම් (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		නම් (found && *activep) {
			options->auth_methods = strs;
			options->num_auth_methods = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		value = strtol(arg, &p, 8);
		නම් (arg == p || value < 0 || value > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		නම් (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)value;
		bha_nga;

	pak_sa sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		goto parse_flag;

	pak_sa sFingerprintHash:
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් ((value = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		නම් (*activep)
			options->fingerprint_hash = value;
		bha_nga;

	pak_sa sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		goto parse_flag;

	pak_sa sRDomain:
#නම් !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		නම් (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		නම් (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		නම් (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa sRequiredRSASize:
		intptr = &options->required_rsa_size;
		goto parse_int;

	pak_sa sChannelTimeout:
		found = options->num_channel_timeouts == 0;
		අතරතුර ((arg = argv_next(&ac, &av)) != NULL) {
			/* Allow "none" only in first position */
			නම් (strcasecmp(arg, "none") == 0) {
				නම් (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			} නැතහොත් නම් (parse_pattern_interval(arg,
			    NULL, NULL) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		නම් (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		නම් (found && *activep) {
			options->channel_timeouts = strs;
			options->num_channel_timeouts = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		නම් (av[0] != NULL && strcasecmp(av[0], "none") == 0) {
			(void)argv_next(&ac, &av); /* consume arg */
			නම් (*activep)
				*intptr = 0;
			bha_nga;
		}
		goto parse_time;

	pak_sa sSshdSessionPath:
		charptr = &options->sshd_session_path;
		goto parse_filename;

	pak_sa sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		goto parse_filename;

	pak_sa sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		goto parse_multistate;

	pak_sa sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		goto parse_multistate;

	pak_sa sDeprecated:
	pak_sa sIgnore:
	pak_sa sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		bha_nga;

	default:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	නම් (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		goto out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, NULL, nstrs);
	argv_free(oav, oac);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
process_server_config_line(ServerOptions *options, var_na *line,
    const var_na *filename, පූර්ණ_සංඛ්‍යා linenum, පූර්ණ_සංඛ්‍යා *activep,
    sa_nracanaa connection_info *connectinfo, sa_nracanaa include_list *includes)
{
	පූර්ණ_සංඛ්‍යා inc_flags = 0;

	ආපසු process_server_config_line_depth(options, line, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

void
load_server_config(const var_na *filename, sa_nracanaa sshbuf *conf)
{
	sa_nracanaa stat st;
	var_na *line = NULL, *cp;
	size_t linesize = 0;
	FILE *f;
	පූර්ණ_සංඛ්‍යා r;

	debug2_f("filename %s", filename);
	නම් ((f = fopen(filename, "r")) == NULL) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	නම් (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	අතරතුර (getline(&line, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = line + strspn(line, " \t\r");
		නම් ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	free(line);
	නම් ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

void
parse_server_match_config(ServerOptions *options,
   sa_nracanaa include_list *includes, sa_nracanaa connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

පූර්ණ_සංඛ්‍යා
parse_server_match_testspec(sa_nracanaa connection_info *ci, var_na *spec)
{
	var_na *p;
	const var_na *val;

	අතරතුර ((p = strsep(&spec, ",")) && *p != '\0') {
		නම් ((val = strprefix(p, "addr=", 0)) != NULL) {
			ci->address = xstrdup(val);
		} නැතහොත් නම් ((val = strprefix(p, "host=", 0)) != NULL) {
			ci->host = xstrdup(val);
		} නැතහොත් නම් ((val = strprefix(p, "user=", 0)) != NULL) {
			ci->user = xstrdup(val);
		} නැතහොත් නම් ((val = strprefix(p, "laddr=", 0)) != NULL) {
			ci->laddress = xstrdup(val);
		} නැතහොත් නම් ((val = strprefix(p, "rdomain=", 0)) != NULL) {
			ci->rdomain = xstrdup(val);
		} නැතහොත් නම් ((val = strprefix(p, "lport=", 0)) != NULL) {
			ci->lport = a2port(val);
			නම් (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				ආපසු -1;
			}
		} නැතහොත් නම් (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} නැතහොත් {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			ආපසු -1;
		}
	}
	ආපසු 0;
}

void
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	සඳහා (i = 0; i < src->num_subsystems; i++) {
		found = 0;
		සඳහා (j = 0; j < dst->num_subsystems; j++) {
			නම් (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				bha_nga;
			}
		}
		නම් (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			free(dst->subsystem_command[j]);
			free(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			continue;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->num_subsystems,
		    dst->num_subsystems + 1, parimaa_na(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->num_subsystems,
		    dst->num_subsystems + 1, parimaa_na(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->num_subsystems,
		    dst->num_subsystems + 1, parimaa_na(*dst->subsystem_args));
		j = dst->num_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

static පූර්ණ_සංඛ්‍යා
serialise_s32(sa_nracanaa sshbuf *buf, පූර්ණ_සංඛ්‍යා v)
{
	uint32_t uv;
	පූර්ණ_සංඛ්‍යා r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	නම් ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		ආපසු r;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_s64(sa_nracanaa sshbuf *buf, int64_t v)
{
	uint64_t uv;
	පූර්ණ_සංඛ්‍යා r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	නම් ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		ආපසු r;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_mode(sa_nracanaa sshbuf *buf, mode_t v)
{
	u_int uv;

	නම් (v == (mode_t)-1)
		ආපසු serialise_s32(buf, -1);
	uv = (u_int)v;
	නම් ((mode_t)uv != v || uv > 0777)
		ආපසු SSH_ERR_INVALID_FORMAT;
	ආපසු serialise_s32(buf, (පූර්ණ_සංඛ්‍යා)uv);
}

static පූර්ණ_සංඛ්‍යා
serialise_double(sa_nracanaa sshbuf *buf, dviguu_na v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	ආපසු sshbuf_put(buf, &v, parimaa_na(v));
}

static පූර්ණ_සංඛ්‍යා
serialise_nullable_string(sa_nracanaa sshbuf *buf, const var_na *s)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = sshbuf_put_u8(buf, s != NULL)) != 0)
		ආපසු r;
	නම් (s == NULL)
		ආපසු 0;
	ආපසු sshbuf_put_cstring(buf, s);
}

static පූර්ණ_සංඛ්‍යා
serialise_nullable_string_array(sa_nracanaa sshbuf *buf, var_na **a, u_int n)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	නම් ((r = sshbuf_put_u32(buf, n)) != 0)
		ආපසු r;
	සඳහා (i = 0; i < n; i++) {
		නම් ((r = serialise_nullable_string(buf, a[i])) != 0)
			ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_hostkeyfile(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	නම් ((r = sshbuf_put_u32(buf, options->num_host_key_files)) != 0) {
		error_fr(r, "serialise length");
		ආපසු r;
	}
	සඳහා (i = 0; i < options->num_host_key_files; i++) {
		නම් ((r = serialise_s32(buf,
		    options->host_key_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_key_files[i])) != 0) {
			error_fr(r, "serialise member");
			ආපසු r;
		}
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_ipqos(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_listenaddress(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	නම් ((r = sshbuf_put_u32(buf, options->num_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		ආපසු r;
	}
	සඳහා (i = 0; i < options->num_queued_listens; i++) {
		const sa_nracanaa queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		නම් ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			ආපසු r;
		}
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_logfacility(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, (පූර්ණ_සංඛ්‍යා)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_loglevel(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, (පූර්ණ_සංඛ්‍යා)options->log_level)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_port(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	නම් ((r = sshbuf_put_u32(buf, options->num_ports)) != 0) {
		error_fr(r, "serialise length");
		ආපසු r;
	}
	සඳහා (i = 0; i < options->num_ports; i++) {
		නම් ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			ආපසු r;
		}
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_gatewayports(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_streamlocalbindmask(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_streamlocalbindunlink(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_maxstartups(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_permituserenv(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_persourcenetblocksize(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_persourcepenalties(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	const sa_nracanaa per_source_penalty *psp = &options->per_source_penalty;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_rekeylimit(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_subsystem(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i;

	නම් ((r = sshbuf_put_u32(buf, options->num_subsystems)) != 0) {
		error_fr(r, "serialise length");
		ආපසු r;
	}
	සඳහා (i = 0; i < options->num_subsystems; i++) {
		නම් ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			ආපසු r;
		}
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_pubkey_auth_options(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
serialise_timingsecret(const ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		ආපසු r;
	}
	ආපසු 0;
}


පූර්ණ_සංඛ්‍යා
serialise_server_options(const ServerOptions *options, sa_nracanaa sshbuf **bufp)
{
	sa_nracanaa sshbuf *buf = NULL;
	පූර්ණ_සංඛ්‍යා r = SSH_ERR_INTERNAL_ERROR;

	*bufp = NULL;

	නම් ((buf = sshbuf_new()) == NULL)
		ආපසු SSH_ERR_ALLOC_FAIL;
	නම් ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		goto out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	නම් ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		goto out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	නම් ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		goto out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	නම් ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		goto out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	නම් ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		goto out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	නම් ((r = serialise_##funcsuffix(options, buf)) != 0) \
		goto out;
#define SSHCONF_NONCONF(funcsuffix) \
	නම් ((r = serialise_##funcsuffix(options, buf)) != 0) \
		goto out;
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
	buf = NULL; /* transferred */
 out:
	sshbuf_free(buf);
	ආපසු r;
}

static පූර්ණ_සංඛ්‍යා
deserialise_s32(sa_nracanaa sshbuf *buf, පූර්ණ_සංඛ්‍යා *v)
{
	uint32_t tmp;
	පූර්ණ_සංඛ්‍යා r;
	u_char was_signed;

	නම් ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		ආපසු r;
	නම් (was_signed > 1)
		ආපසු SSH_ERR_INVALID_FORMAT;
	නම් (was_signed) {
		නම් (tmp > (uint32_t)INT_MAX + 1)
			ආපසු SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(පූර්ණ_සංඛ්‍යා)tmp;
	} නැතහොත් {
		නම් (tmp > INT_MAX)
			ආපසු SSH_ERR_INVALID_FORMAT;
		*v = (පූර්ණ_සංඛ්‍යා)tmp;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_s64(sa_nracanaa sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	පූර්ණ_සංඛ්‍යා r;
	u_char was_signed;

	නම් ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		ආපසු r;
	නම් (was_signed > 1)
		ආපසු SSH_ERR_INVALID_FORMAT;
	නම් (was_signed) {
		නම් (tmp > (uint64_t)INT64_MAX + 1)
			ආපසු SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} නැතහොත් {
		නම් (tmp > INT64_MAX)
			ආපසු SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_mode(sa_nracanaa sshbuf *buf, mode_t *v)
{
	පූර්ණ_සංඛ්‍යා r, tmp;

	නම් ((r = deserialise_s32(buf, &tmp)) != 0)
		ආපසු r;
	නම් (tmp == -1) {
		*v = (mode_t)-1;
		ආපසු 0;
	}
	නම් (tmp < 0 || tmp > 0777)
		ආපසු SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_double(sa_nracanaa sshbuf *buf, dviguu_na *v)
{
	ආපසු sshbuf_get(buf, v, parimaa_na(*v));
}

static පූර්ණ_සංඛ්‍යා
deserialise_nullable_string(sa_nracanaa sshbuf *buf, var_na **sp)
{
	පූර්ණ_සංඛ්‍යා r;
	u_char present;

	නම් ((r = sshbuf_get_u8(buf, &present)) != 0)
		ආපසු r;
	නම් (present == 0) {
		*sp = NULL;
		ආපසු 0;
	}
	නම් (present != 1)
		ආපසු SSH_ERR_INVALID_FORMAT;
	ආපසු sshbuf_get_cstring(buf, sp, NULL);
}

static void
free_string_array(var_na **a, u_int n)
{
	u_int i;

	නම් (a == NULL)
		ආපසු;
	සඳහා (i = 0; i < n; i++)
		free(a[i]);
	free(a);
}

static පූර්ණ_සංඛ්‍යා
deserialise_count(sa_nracanaa sshbuf *buf, u_int *np, const var_na *what)
{
	පූර්ණ_සංඛ්‍යා r;
	uint32_t n;

	නම් ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		ආපසු r;
	}
	නම් (n > UINT_MAX) {
		error_f("bad number of %s", what);
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	නම් (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_nullable_string_array(sa_nracanaa sshbuf *buf, var_na ***arrayp,
    u_int *np)
{
	var_na **a = NULL;
	පූර්ණ_සංඛ්‍යා r;
	u_int i, n;

	*arrayp = NULL;
	*np = 0;
	නම් ((r = deserialise_count(buf, &n, "strings")) != 0)
		ආපසු r;
	නම් (n > 0)
		a = xcalloc(n, parimaa_na(*a));
	සඳහා (i = 0; i < n; i++) {
		නම් ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			ආපසු r;
		}
	}
	*arrayp = a;
	*np = n;
	ආපසු 0;
}

static void
free_queued_listen_addrs(sa_nracanaa queued_listenaddr *qla, u_int n)
{
	u_int i;

	නම් (qla == NULL)
		ආපසු;
	සඳහා (i = 0; i < n; i++) {
		free(qla[i].addr);
		free(qla[i].rdomain);
	}
	free(qla);
}

static පූර්ණ_සංඛ්‍යා
deserialise_hostkeyfile(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r, *userprovided = NULL;
	u_int i, n;
	var_na **files = NULL;

	නම් ((r = deserialise_count(buf, &n, "host key files")) != 0)
		ආපසු r;
	නම් (n > 0) {
		userprovided = xcalloc(n, parimaa_na(*userprovided));
		files = xcalloc(n, parimaa_na(*files));
	}
	සඳහා (i = 0; i < n; i++) {
		නම් ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			free(userprovided);
			ආපසු r;
		}
	}
	options->num_host_key_files = n;
	options->host_key_file_userprovided = userprovided;
	options->host_key_files = files;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_ipqos(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_listenaddress(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i, n;
	sa_nracanaa queued_listenaddr *qla = NULL;

	නම් ((r = deserialise_count(buf, &n, "listen addresses")) != 0)
		ආපසු r;
	නම් (n > 0)
		qla = xcalloc(n, parimaa_na(*qla));
	සඳහා (i = 0; i < n; i++) {
		නම් ((r = sshbuf_get_cstring(buf, &qla[i].addr, NULL)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			ආපසු r;
		}
	}
	options->num_queued_listens = n;
	options->queued_listen_addrs = qla;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_logfacility(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r, tmp;

	නම් ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	නම් (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == NULL) {
		error_f("bad syslog facility");
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_loglevel(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r, tmp;

	නම් ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	නම් (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == NULL) {
		error_f("bad log level");
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_port(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i, n;

	නම් ((r = deserialise_count(buf, &n, "ports")) != 0)
		ආපසු r;
	නම් (n > MAX_PORTS) {
		error_f("bad number of ports");
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	options->num_ports = n;
	memset(options->ports, 0, parimaa_na(options->ports));
	සඳහා (i = 0; i < options->num_ports; i++) {
		නම් ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			ආපසු r;
		}
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_gatewayports(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_streamlocalbindmask(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_streamlocalbindunlink(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_char tmp;

	නම් ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	නම් (tmp > 1) {
		error_f("bad boolean");
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_maxstartups(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_permituserenv(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_persourcenetblocksize(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_persourcepenalties(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	sa_nracanaa per_source_penalty *psp = &options->per_source_penalty;
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_rekeylimit(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_subsystem(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;
	u_int i, n;
	var_na **names = NULL, **commands = NULL, **args = NULL;

	නම් ((r = deserialise_count(buf, &n, "subsystems")) != 0)
		ආපසු r;
	නම් (n > 0) {
		names = xcalloc(n, parimaa_na(*names));
		commands = xcalloc(n, parimaa_na(*names));
		args = xcalloc(n, parimaa_na(*args));
	}
	සඳහා (i = 0; i < n; i++) {
		නම් ((r = sshbuf_get_cstring(buf, names + i, NULL)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, NULL)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, NULL)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			ආපසු r;
		}
	}
	options->num_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_pubkey_auth_options(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
deserialise_timingsecret(ServerOptions *options, sa_nracanaa sshbuf *buf)
{
	පූර්ණ_සංඛ්‍යා r;

	නම් ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		ආපසු r;
	}
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
deserialise_server_options(sa_nracanaa sshbuf *buf, ServerOptions *options)
{
	පූර්ණ_සංඛ්‍යා r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	නම් ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		goto out;
	}
	නම් (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	නම් ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		goto out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	නම් ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		goto out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	නම් ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		goto out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	නම් ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		goto out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	නම් ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		goto out;
#define SSHCONF_NONCONF(funcsuffix) \
	නම් ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		goto out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	do { \
		free(new_options.var); \
		new_options.var = NULL; \
	} අතරතුර (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	නම් (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
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
	memset(&new_options, 0, parimaa_na(new_options));
 out:
	free_server_options(&new_options);
	ආපසු r;
}

static void
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	සඳහා (i = 0; i < options->num_host_key_files; i++)
		free(options->host_key_files[i]);
	free(options->host_key_files);
	free(options->host_key_file_userprovided);
}

static void
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->num_queued_listens);

	සඳහා (i = 0; i < options->num_listen_addrs; i++) {
		free(options->listen_addrs[i].rdomain);
		නම් (options->listen_addrs[i].addrs != NULL)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	free(options->listen_addrs);
}

static void
free_permituserenv(ServerOptions *options)
{
	free(options->permit_user_env_allowlist);
}

static void
free_subsystem(ServerOptions *options)
{
	u_int i;

	සඳහා (i = 0; i < options->num_subsystems; i++) {
		free(options->subsystem_name[i]);
		free(options->subsystem_command[i]);
		free(options->subsystem_args[i]);
	}
	free(options->subsystem_name);
	free(options->subsystem_command);
	free(options->subsystem_args);
}

void
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		free(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	do { \
		free(options->var); \
		options->var = NULL; \
	} අතරතුර (0);
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

static void
copy_server_option_int(පූර්ණ_සංඛ්‍යා *dst, පූර්ණ_සංඛ්‍යා src)
{
	නම් (src != -1)
		*dst = src;
}

static void
copy_server_option_int64(int64_t *dst, int64_t src)
{
	නම් (src != -1)
		*dst = src;
}

static void
copy_server_option_string(var_na **dst, const var_na *src)
{
	නම් (src != NULL && *dst != src) {
		free(*dst);
		*dst = xstrdup(src);
	}
}

static void
copy_server_option_strarray_values(var_na ***dst, u_int ndst,
    var_na * const *src, u_int nsrc)
{
	u_int i;

	නම් (nsrc == 0)
		ආපසු;
	සඳහා (i = 0; i < ndst; i++)
		free((*dst)[i]);
	free(*dst);
	*dst = xcalloc(nsrc, parimaa_na(**dst));
	සඳහා (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == NULL ? NULL : xstrdup(src[i]);
}

static void
copy_server_option_strarray(var_na ***dst, u_int *ndst,
    var_na * const *src, u_int nsrc)
{
	නම් (nsrc == 0)
		ආපසු;
	copy_server_option_strarray_values(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

static void
copy_ipqos(ServerOptions *dst, const ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

static void
copy_gatewayports(ServerOptions *dst, const ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

static void
copy_streamlocalbindunlink(ServerOptions *dst, const ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

static void
copy_loglevel(ServerOptions *dst, const ServerOptions *src)
{
	නම් (src->log_level != -1)
		dst->log_level = src->log_level;
}

static void
copy_rekeylimit(ServerOptions *dst, const ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

static void
copy_subsystem(ServerOptions *dst, const ServerOptions *src)
{
	u_int old_num_subsystems = dst->num_subsystems;

	නම් (src->num_subsystems == 0)
		ආපසු;
	copy_server_option_strarray_values(&dst->subsystem_name,
	    old_num_subsystems, src->subsystem_name, src->num_subsystems);
	copy_server_option_strarray_values(&dst->subsystem_command,
	    old_num_subsystems, src->subsystem_command, src->num_subsystems);
	copy_server_option_strarray_values(&dst->subsystem_args,
	    old_num_subsystems, src->subsystem_args, src->num_subsystems);
	dst->num_subsystems = src->num_subsystems;
}

static void
copy_pubkey_auth_options(ServerOptions *dst, const ServerOptions *src)
{
	නම් (src->pubkey_auth_options != -1) {
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
void
copy_set_server_options(ServerOptions *dst, ServerOptions *src, පූර්ණ_සංඛ්‍යා preauth)
{
	නම් (dst == src)
		ආපසු;

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
	do { \
		free(dst->var); \
		dst->var = NULL; \
	} අතරතුර (0);
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
	නම් (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	do { \
		නම් (option_clear_or_none(v)) { \
			free(v); \
			v = NULL; \
		} \
	} අතරතුර(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_keys);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	නම් (preauth)
		ආපසු;

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
static void
parse_server_config_depth(ServerOptions *options, const var_na *filename,
    sa_nracanaa sshbuf *conf, sa_nracanaa include_list *includes,
    sa_nracanaa connection_info *connectinfo, පූර්ණ_සංඛ්‍යා flags, පූර්ණ_සංඛ්‍යා *activep, පූර්ණ_සංඛ්‍යා depth)
{
	පූර්ණ_සංඛ්‍යා linenum, bad_options = 0;
	var_na *cp, *obuf, *cbuf;

	නම් (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	නම් ((obuf = cbuf = sshbuf_dup_string(conf)) == NULL)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	අතරතුර ((cp = strsep(&cbuf, "\n")) != NULL) {
		නම් (process_server_config_line_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	free(obuf);
	නම් (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

void
parse_server_config(ServerOptions *options, const var_na *filename,
    sa_nracanaa sshbuf *conf, sa_nracanaa include_list *includes,
    sa_nracanaa connection_info *connectinfo, පූර්ණ_සංඛ්‍යා reexec)
{
	පූර්ණ_සංඛ්‍යා active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	නම් (!reexec)
		process_queued_listen_addrs(options);
}

static const var_na *
fmt_multistate_int(පූර්ණ_සංඛ්‍යා val, const sa_nracanaa multistate *m)
{
	u_int i;

	සඳහා (i = 0; m[i].key != NULL; i++) {
		නම් (m[i].value == val)
			ආපසු m[i].key;
	}
	ආපසු "UNKNOWN";
}

static const var_na *
fmt_intarg(ServerOpCodes code, පූර්ණ_සංඛ්‍යා val)
{
	නම් (val == -1)
		ආපසු "unset";
	switch (code) {
	pak_sa sAddressFamily:
		ආපසු fmt_multistate_int(val, multistate_addressfamily);
	pak_sa sPermitRootLogin:
		ආපසු fmt_multistate_int(val, multistate_permitrootlogin);
	pak_sa sGatewayPorts:
		ආපසු fmt_multistate_int(val, multistate_gatewayports);
	pak_sa sCompression:
		ආපසු fmt_multistate_int(val, multistate_compression);
	pak_sa sAllowTcpForwarding:
		ආපසු fmt_multistate_int(val, multistate_tcpfwd);
	pak_sa sAllowStreamLocalForwarding:
		ආපසු fmt_multistate_int(val, multistate_tcpfwd);
	pak_sa sIgnoreRhosts:
		ආපසු fmt_multistate_int(val, multistate_ignore_rhosts);
	pak_sa sTCPKeepAlive:
		ආපසු fmt_multistate_int(val, multistate_keepalives);
	pak_sa sWarnWeakCrypto:
		ආපසු fmt_multistate_int(val, multistate_warnweakcrypto);
	pak_sa sFingerprintHash:
		ආපසු ssh_digest_alg_name(val);
	default:
		switch (val) {
		pak_sa 0:
			ආපසු "no";
		pak_sa 1:
			ආපසු "yes";
		default:
			ආපසු "UNKNOWN";
		}
	}
}

static void
dump_cfg_int(ServerOpCodes code, පූර්ණ_සංඛ්‍යා val)
{
	නම් (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		ආපසු;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

static void
dump_cfg_oct(ServerOpCodes code, පූර්ණ_සංඛ්‍යා val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

static void
dump_cfg_fmtint(ServerOpCodes code, පූර්ණ_සංඛ්‍යා val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

static void
dump_cfg_string(ServerOpCodes code, const var_na *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == NULL ? "none" : val);
}

static void
dump_cfg_strarray(ServerOpCodes code, u_int count, var_na **vals)
{
	u_int i;

	සඳහා (i = 0; i < count; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

static void
dump_cfg_strarray_oneline(ServerOpCodes code, u_int count, var_na **vals)
{
	u_int i;

	switch (code) {
	pak_sa sAuthenticationMethods:
	pak_sa sChannelTimeout:
		bha_nga;
	default:
		නම් (count <= 0)
			ආපසු;
		bha_nga;
	}

	printf("%s", lookup_opcode_name(code));
	සඳහා (i = 0; i < count; i++)
		printf(" %s",  vals[i]);
	නම් (code == sAuthenticationMethods && count == 0)
		printf(" any");
	නැතහොත් නම් (code == sChannelTimeout && count == 0)
		printf(" none");
	printf("\n");
}

static var_na *
format_listen_addrs(sa_nracanaa listenaddr *la)
{
	පූර්ණ_සංඛ්‍යා r;
	sa_nracanaa addrinfo *ai;
	var_na addr[NI_MAXHOST], port[NI_MAXSERV];
	var_na *laddr1 = xstrdup(""), *laddr2 = NULL;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	සඳහා (ai = la->addrs; ai; ai = ai->ai_next) {
		නම් ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    parimaa_na(addr), port, parimaa_na(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			continue;
		}
		laddr2 = laddr1;
		නම් (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == NULL ? "" : " rdomain ",
			    la->rdomain == NULL ? "" : la->rdomain,
			    laddr2);
		} නැතහොත් {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == NULL ? "" : " rdomain ",
			    la->rdomain == NULL ? "" : la->rdomain,
			    laddr2);
		}
		free(laddr2);
	}
	ආපසු laddr1;
}

void
dump_config(ServerOptions *o)
{
	var_na *s;
	u_int i;

	/* these are usually at the top of the config */
	සඳහා (i = 0; i < o->num_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	සඳහා (i = 0; i < o->num_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		free(s);
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
	dump_cfg_int(sClientAliveCountMax, o->client_alive_count_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(sPermitRootLogin, o->permit_root_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_keys);
	dump_cfg_string(sSecurityKeyProvider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(sAuthorizedKeysCommand, o->authorized_keys_command);
	dump_cfg_string(sAuthorizedKeysCommandUser, o->authorized_keys_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(sHostKeyAgent, o->host_key_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(sHostKeyAlgorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#නම් defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(sAuthorizedKeysFile, o->num_authkeys_files,
	    o->authorized_keys_files);
	dump_cfg_strarray_oneline(sRevokedKeys, o->num_revoked_keys_files,
	    o->revoked_keys_files);
	dump_cfg_strarray(sHostKey, o->num_host_key_files, o->host_key_files);
	dump_cfg_strarray(sHostCertificate, o->num_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->num_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->num_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->num_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->num_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->num_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->num_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->num_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->num_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->num_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	සඳහා (i = 0; i < o->num_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	නම් (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	නැතහොත්
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = NULL;
	සඳහා (i = 0; tunmode_desc[i].val != -1; i++) {
		නම් (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			bha_nga;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	නම් (o->num_permitted_opens == 0)
		printf(" any");
	නැතහොත් {
		සඳහා (i = 0; i < o->num_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	නම් (o->num_permitted_listens == 0)
		printf(" any");
	නැතහොත් {
		සඳහා (i = 0; i < o->num_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	නම් (o->permit_user_env_allowlist == NULL) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} නැතහොත් {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	නම් (o->pubkey_auth_options == 0)
		printf(" none");
	නම් (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	නම් (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	නම් (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	නම් (o->per_source_penalty.enabled) {
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
	} නැතහොත්
		printf("PerSourcePenalties no\n");
}
