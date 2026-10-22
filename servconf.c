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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __OpenBSD__
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/sysctl.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_NET_ROUTE_H
#ਅਨ੍ਤਰ੍ਭਾਵ <net/route.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "groupaccess.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHD_CONFIG_BLOB_ਸੰਸਕਰਣ	1

#ਜੇ !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਖਾਲੀ ਜੋੜੋ_listen_addr(ServerOptions *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਸਥਿਰ ਖਾਲੀ ਜੋੜੋ_one_listen_addr(ServerOptions *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਸਥਿਰ ਖਾਲੀ parse_server_config_ਡੂੰਘਾਈ(ServerOptions *options,
    ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ sshbuf *conf, ਬਣਤਰ include_list *includes,
    ਬਣਤਰ connection_info *connectinfo, ਪੂਰਨ flags, ਪੂਰਨ *activep, ਪੂਰਨ ਡੂੰਘਾਈ);

ਬਾਹਰੀ ਬਣਤਰ sshbuf *cfg;

/* Initializes the server options to their default values. */

ਖਾਲੀ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, ਆਕਾਰ(*options));
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp)		options->var = ਨਿਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ਨਿਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ਨਿਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

	/* Using macros for these is a bit overkill but forces consistency */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_hostkeyfile(options) \
	options->host_ਕੁੰਜੀ_files = 0; \
	options->ਅੰਕ_host_ਕੁੰਜੀ_files = 0; \
	options->host_ਕੁੰਜੀ_file_userprovided = ਨਿਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_listenaddress(options) \
	options->queued_listen_addrs = ਨਿਰਾ; \
	options->ਅੰਕ_queued_listens = 0; \
	options->listen_addrs = ਨਿਰਾ; \
	options->ਅੰਕ_listen_addrs = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_ਸੈੱਟ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_ਸੈੱਟ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_ਪੋਰਟ(options) \
	options->ਅੰਕ_ports = 0; \
	options->ports_from_cmdline = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_ਨਕਾਬ = (ਬਹੁਲਕ_t)-1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_ਦਰ = -1; \
	options->max_startups = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = ਨਿਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_persourcenetblocksize(options) \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4 = -1; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6 = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_persourcepenalties(options) \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty_exempt = ਨਿਰਾ; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled = -1; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources4 = -1; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources6 = -1; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ = -1; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_mode6 = -1; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_crash = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_authfail = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_invaliduser = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_noauth = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_grace = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_refuseconnection = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_max = -1.0; \
	options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_min = -1.0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_rekeylimit(options) \
	options->rekey_ਹੱਦਬੰਦੀ = -1; \
	options->rekey_interval = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_subsystem(options) \
	options->ਅੰਕ_subsystems = 0; \
	options->subsystem_name = ਨਿਰਾ; \
	options->subsystem_command = ਨਿਰਾ; \
	options->subsystem_ਦਲੀਲਾਂ = ਨਿਰਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_hostkeyfile
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_ipqos
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_listenaddress
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_logfacility
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_loglevel
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_ਪੋਰਟ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_gatewayports
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_streamlocalbindmask
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_streamlocalbindunlink
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_maxstartups
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_permituserenv
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_persourcenetblocksize
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_persourcepenalties
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_rekeylimit
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_subsystem
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ init_timingsecret
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ਸਥਿਰ ਪੂਰਨ
option_clear_or_none(ਅਚਲ ਅੱਖਰ *o)
{
	ਵਾਪਸ o == ਨਿਰਾ || strcasecmp(o, "none") == 0;
}

ਸਥਿਰ ਖਾਲੀ
assemble_algorithms(ServerOptions *o)
{
	ਅੱਖਰ *all_cipher, *all_mac, *all_kex, *all_ਕੁੰਜੀ, *all_sig;
	ਅੱਖਰ *def_cipher, *def_mac, *def_kex, *def_ਕੁੰਜੀ, *def_sig;
	ਪੂਰਨ r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ਕੁੰਜੀ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = ਮੇਲ_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = ਮੇਲ_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = ਮੇਲ_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_ਕੁੰਜੀ = ਮੇਲ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ਕੁੰਜੀ);
	def_sig = ਮੇਲ_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSEMBLE(what, defaults, all) \
	ਕਰੋ { \
		ਜੇ ((r = kex_assemble_ਨਾਂ(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} ਜਦੋਂ (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_ਕੁੰਜੀ, all_ਕੁੰਜੀ);
	ASSEMBLE(hostbased_accepted_algos, def_ਕੁੰਜੀ, all_ਕੁੰਜੀ);
	ASSEMBLE(pubkey_accepted_algos, def_ਕੁੰਜੀ, all_ਕੁੰਜੀ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ASSEMBLE
	ਮੁਕਤ(all_cipher);
	ਮੁਕਤ(all_mac);
	ਮੁਕਤ(all_kex);
	ਮੁਕਤ(all_ਕੁੰਜੀ);
	ਮੁਕਤ(all_sig);
	ਮੁਕਤ(def_cipher);
	ਮੁਕਤ(def_mac);
	ਮੁਕਤ(def_kex);
	ਮੁਕਤ(def_ਕੁੰਜੀ);
	ਮੁਕਤ(def_sig);
}

ਖਾਲੀ
servconf_ਜੋੜੋ_hostkey(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਪੂਰਨ ਸਤਰ,
    ServerOptions *options, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ userprovided)
{
	ਅੱਖਰ *apath = derelativise_ਰਸਤਾ(ਰਸਤਾ);

	opt_array_append2(file, ਸਤਰ, "HostKey",
	    &options->host_ਕੁੰਜੀ_files, &options->host_ਕੁੰਜੀ_file_userprovided,
	    &options->ਅੰਕ_host_ਕੁੰਜੀ_files, apath, userprovided);
	ਮੁਕਤ(apath);
}

ਖਾਲੀ
servconf_ਜੋੜੋ_hostcert(ਅਚਲ ਅੱਖਰ *file, ਅਚਲ ਪੂਰਨ ਸਤਰ,
    ServerOptions *options, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਅੱਖਰ *apath = derelativise_ਰਸਤਾ(ਰਸਤਾ);

	opt_array_append(file, ਸਤਰ, "HostCertificate",
	    &options->host_cert_files, &options->ਅੰਕ_host_cert_files, apath);
	ਮੁਕਤ(apath);
}

ਖਾਲੀ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SKIP_PRIVDROP
	ਜੇ (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	ਜੇ (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ਜੇ (options->var == -1) \
		options->var = def;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ਜੇ (options->var == -1) \
		options->var = def;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix)			/* done manually */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ਕਰੋ { \
		ਮੁਕਤ(options->var); \
		options->var = ਨਿਰਾ; \
	} ਜਦੋਂ (0);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options->pam_service_name == ਨਿਰਾ)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#ਜੇ_ਅੰਤ

	ਜੇ (options->ਅੰਕ_host_ਕੁੰਜੀ_files == 0) {
		/* fill default hostkeys */
		servconf_ਜੋੜੋ_hostkey("[default]", 0, options,
		    ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE, 0);
		servconf_ਜੋੜੋ_hostkey("[default]", 0, options,
		    ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE, 0);
		servconf_ਜੋੜੋ_hostkey("[default]", 0, options,
		    ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE, 0);
		servconf_ਜੋੜੋ_hostkey("[default]", 0, options,
		    ਰਸਤਾ_HOST_MLDSA44_ED25519_ਕੁੰਜੀ_FILE, 0);
	}
	/* No certificates by default */
	ਜੇ (options->ਅੰਕ_ports == 0)
		options->ports[options->ਅੰਕ_ports++] = SSH_DEFAULT_ਪੋਰਟ;
	ਜੇ (options->listen_addrs == ਨਿਰਾ)
		ਜੋੜੋ_listen_addr(options, ਨਿਰਾ, ਨਿਰਾ, 0);
	ਜੇ (options->pid_file == ਨਿਰਾ)
		options->pid_file = xstrdup(ਰਸਤਾ_SSH_DAEMON_PID_FILE);
	ਜੇ (options->moduli_file == ਨਿਰਾ)
		options->moduli_file = xstrdup(ਰਸਤਾ_DH_MODULI);
	ਜੇ (options->xauth_location == ਨਿਰਾ)
		options->xauth_location = xstrdup(ਰਸਤਾ_XAUTH);
	ਜੇ (options->log_facility == SYSLOG_FACILITY_NOT_ਸੈੱਟ)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	ਜੇ (options->log_level == SYSLOG_LEVEL_NOT_ਸੈੱਟ)
		options->log_level = SYSLOG_LEVEL_INFO;
	ਜੇ (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ਨਿਰਾ;
	}
	ਜੇ (options->rekey_ਹੱਦਬੰਦੀ == -1)
		options->rekey_ਹੱਦਬੰਦੀ = 0;
	ਜੇ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ਜੇ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ਜੇ (options->max_startups == -1)
		options->max_startups = 100;
	ਜੇ (options->max_startups_ਦਰ == -1)
		options->max_startups_ਦਰ = 30;		/* 30% */
	ਜੇ (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4 == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4 = 32;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6 == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6 = 128;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled = 1;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources4 == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources4 = 65536;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources6 == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources6 = 65536;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ = ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_PERMISSIVE;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_mode6 == -1)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_mode6 = options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_crash < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_crash = 90.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_grace < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_grace = 10.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_authfail < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_authfail = 5.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_invaliduser < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_invaliduser = 5.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_noauth < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_noauth = 1.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_refuseconnection < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_refuseconnection = 10.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_min < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_min = 15.0;
	ਜੇ (options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_max < 0.0)
		options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_max = 600.0;
	ਜੇ (options->ਅੰਕ_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ਕੁੰਜੀਆਂ_files,
		    &options->ਅੰਕ_authkeys_files,
		    ਰਸਤਾ_SSH_USER_PERMITTED_ਕੁੰਜੀਆਂ);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_ਕੁੰਜੀਆਂ_files,
		    &options->ਅੰਕ_authkeys_files,
		    ਰਸਤਾ_SSH_USER_PERMITTED_KEYS2);
	}
	ਜੇ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ਜੇ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ਜੇ (options->ਸੰਸਕਰਣ_addendum == ਨਿਰਾ)
		options->ਸੰਸਕਰਣ_addendum = xstrdup("");
	ਜੇ (options->fwd_opts.streamlocal_bind_ਨਕਾਬ == (ਬਹੁਲਕ_t)-1)
		options->fwd_opts.streamlocal_bind_ਨਕਾਬ = 0177;
	ਜੇ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ਜੇ (options->sk_provider == ਨਿਰਾ)
		options->sk_provider = xstrdup("internal");
	ਜੇ (options->sshd_session_ਰਸਤਾ == ਨਿਰਾ)
		options->sshd_session_ਰਸਤਾ = xstrdup(ਰਸਤਾ_SSHD_SESSION);
	ਜੇ (options->sshd_auth_ਰਸਤਾ == ਨਿਰਾ)
		options->sshd_auth_ਰਸਤਾ = xstrdup(ਰਸਤਾ_SSHD_AUTH);
	ਜੇ (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	ਜੇ (options->agent_socket_ਰਸਤਾ == ਨਿਰਾ)
		options->agent_socket_ਰਸਤਾ = xstrdup(ਰਸਤਾ_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CLEAR_ON_NONE(v) \
	ਕਰੋ { \
		ਜੇ (option_clear_or_none(v)) { \
			ਮੁਕਤ(v); \
			v = ਨਿਰਾ; \
		} \
	} ਜਦੋਂ(0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ਕਰੋ { \
		ਜੇ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ਮੁਕਤ(options->v[0]); \
			ਮੁਕਤ(options->v); \
			options->v = ਨਿਰਾ; \
			options->nv = 0; \
		} \
	} ਜਦੋਂ (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_ਕੁੰਜੀਆਂ);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_ਕੁੰਜੀ_agent);
	CLEAR_ON_NONE(options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_ਰਸਤਾ);

	ਲਈ (i = 0; i < options->ਅੰਕ_host_ਕੁੰਜੀ_files; i++)
		CLEAR_ON_NONE(options->host_ਕੁੰਜੀ_files[i]);
	ਲਈ (i = 0; i < options->ਅੰਕ_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, ਅੰਕ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, ਅੰਕ_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_ਕੁੰਜੀਆਂ_files, ਅੰਕ_revoked_ਕੁੰਜੀਆਂ_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_ਕੁੰਜੀਆਂ_files, ਅੰਕ_authkeys_files, "none");
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CLEAR_ON_NONE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix)			/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

/* Keyword tokens. */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_ਮੇਲ, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_ਮੇਲ		0x02	/* allowed inside a Match section */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_ਮੇਲ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCFG_ਮੇਲ_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix)			/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATED				sDeprecated
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_IGNORE					sIgnore
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
ਸਥਿਰ ਬਣਤਰ {
	ਅਚਲ ਅੱਖਰ *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_ਮੇਲ, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ਨਿਰਾ, sBadOption, 0 }
};
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATED
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_IGNORE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

ਸਥਿਰ ਬਣਤਰ {
	ਪੂਰਨ val;
	ਅੱਖਰ *ਪਾਠ;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ਨਿਰਾ }
};

/* Returns an opcode name from its number */

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
lookup_opcode_name(ServerOpCodes ਕੋਡ)
{
	u_int i;

	ਲਈ (i = 0; keywords[i].name != ਨਿਰਾ; i++)
		ਜੇ (keywords[i].opcode == ਕੋਡ)
			ਵਾਪਸ(keywords[i].name);
	ਵਾਪਸ "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ਸਥਿਰ ServerOpCodes
parse_token(ਅਚਲ ਅੱਖਰ *cp, ਅਚਲ ਅੱਖਰ *filename,
	    ਪੂਰਨ linenum, u_int *flags)
{
	u_int i;

	ਲਈ (i = 0; keywords[i].name; i++)
		ਜੇ (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			ਵਾਪਸ keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ਵਾਪਸ sBadOption;
}

ਅੱਖਰ *
derelativise_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਅੱਖਰ *expanded, *ret, cwd[PATH_MAX];

	ਜੇ (strcasecmp(ਰਸਤਾ, "none") == 0)
		ਵਾਪਸ xstrdup("none");
	expanded = tilde_expand_filename(ਰਸਤਾ, getuid());
	ਜੇ (ਰਸਤਾ_absolute(expanded))
		ਵਾਪਸ expanded;
	ਜੇ (getcwd(cwd, ਆਕਾਰ(cwd)) == ਨਿਰਾ)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	ਮੁਕਤ(expanded);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
ਜੋੜੋ_listen_addr(ServerOptions *options, ਅਚਲ ਅੱਖਰ *addr,
    ਅਚਲ ਅੱਖਰ *rdomain, ਪੂਰਨ ਪੋਰਟ)
{
	u_int i;

	ਜੇ (ਪੋਰਟ > 0)
		ਜੋੜੋ_one_listen_addr(options, addr, rdomain, ਪੋਰਟ);
	ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; i < options->ਅੰਕ_ports; i++) {
			ਜੋੜੋ_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
ਜੋੜੋ_one_listen_addr(ServerOptions *options, ਅਚਲ ਅੱਖਰ *addr,
    ਅਚਲ ਅੱਖਰ *rdomain, ਪੂਰਨ ਪੋਰਟ)
{
	ਬਣਤਰ addrinfo hints, *ai, *aitop;
	ਅੱਖਰ strport[NI_MAXSERV];
	ਪੂਰਨ gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	ਲਈ (i = 0; i < options->ਅੰਕ_listen_addrs; i++) {
		ਜੇ (rdomain == ਨਿਰਾ && options->listen_addrs[i].rdomain == ਨਿਰਾ)
			ਰੋਕੋ;
		ਜੇ (rdomain == ਨਿਰਾ || options->listen_addrs[i].rdomain == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			ਰੋਕੋ;
	}
	ਜੇ (i >= options->ਅੰਕ_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		ਜੇ (i >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->ਅੰਕ_listen_addrs, options->ਅੰਕ_listen_addrs + 1,
		    ਆਕਾਰ(*options->listen_addrs));
		i = options->ਅੰਕ_listen_addrs++;
		ਜੇ (rdomain != ਨਿਰਾ)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = options->ਪਤਾ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ਨਿਰਾ) ? AI_PASSIVE : 0;
	snprintf(strport, ਆਕਾਰ strport, "%d", ਪੋਰਟ);
	ਜੇ ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	ਲਈ (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ਸਥਿਰ ਪੂਰਨ
valid_rdomain(ਅਚਲ ਅੱਖਰ *name)
{
#ਜੇ defined(HAVE_SYS_VALID_RDOMAIN)
	ਵਾਪਸ sys_valid_rdomain(name);
#ਜਾਂਜੇ defined(__OpenBSD__)
	ਅਚਲ ਅੱਖਰ *errstr;
	ਲੰਮਾ ਲੰਮਾ ਅੰਕ;
	ਬਣਤਰ rt_tableinfo info;
	ਪੂਰਨ mib[6];
	ਮਾਪ_t miblen = ਆਕਾਰ(mib);

	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ 1;

	ਅੰਕ = strtonum(name, 0, 255, &errstr);
	ਜੇ (errstr != ਨਿਰਾ)
		ਵਾਪਸ 0;

	/* Check whether the table actually exists */
	memset(mib, 0, ਆਕਾਰ(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_ਸਾਰਣੀ;
	mib[5] = (ਪੂਰਨ)ਅੰਕ;
	ਜੇ (sysctl(mib, 6, &info, &miblen, ਨਿਰਾ, 0) == -1)
		ਵਾਪਸ 0;

	ਵਾਪਸ 1;
#ਨਹੀਂਤਾਂ /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ਸਥਿਰ ਖਾਲੀ
ਕਤਾਰ_listen_addr(ServerOptions *options, ਅਚਲ ਅੱਖਰ *addr,
    ਅਚਲ ਅੱਖਰ *rdomain, ਪੂਰਨ ਪੋਰਟ)
{
	ਬਣਤਰ queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->ਅੰਕ_queued_listens, options->ਅੰਕ_queued_listens + 1,
	    ਆਕਾਰ(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->ਅੰਕ_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->ਪੋਰਟ = ਪੋਰਟ;
	qla->rdomain = rdomain == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ਸਥਿਰ ਖਾਲੀ
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ਬਣਤਰ queued_listenaddr *qla;

	ਜੇ (options->ਅੰਕ_ports == 0)
		options->ports[options->ਅੰਕ_ports++] = SSH_DEFAULT_ਪੋਰਟ;
	ਜੇ (options->ਪਤਾ_family == -1)
		options->ਪਤਾ_family = AF_UNSPEC;

	ਲਈ (i = 0; i < options->ਅੰਕ_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		ਜੋੜੋ_listen_addr(options, qla->addr, qla->rdomain, qla->ਪੋਰਟ);
		ਮੁਕਤ(qla->addr);
		ਮੁਕਤ(qla->rdomain);
	}
	ਮੁਕਤ(options->queued_listen_addrs);
	options->queued_listen_addrs = ਨਿਰਾ;
	options->ਅੰਕ_queued_listens = 0;
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

ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_cfg_ਸਤਰ_ਸਮੂਹ(ਅਚਲ ਅੱਖਰ *grps, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *user)
{
	ਪੂਰਨ ਨਤੀਜਾ = 0;
	ਬਣਤਰ passwd *pw;

	ਜੇ (user == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((pw = getpwnam(user)) == ਨਿਰਾ) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", ਸਤਰ, user);
	} ਨਹੀਂਤਾਂ ਜੇ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, ਸਤਰ);
	} ਨਹੀਂਤਾਂ ਜੇ (ga_ਮੇਲ_ਨਮੂਨਾ_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, ਸਤਰ);
	} ਨਹੀਂਤਾਂ {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, ਸਤਰ);
		ਨਤੀਜਾ = 1;
	}
ਬਾਹਰਲਾ:
	ga_free();
	ਵਾਪਸ ਨਤੀਜਾ;
}

ਸਥਿਰ ਖਾਲੀ
ਮੇਲ_test_missing_fatal(ਅਚਲ ਅੱਖਰ *criteria, ਅਚਲ ਅੱਖਰ *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_cfg_ਸਤਰ(ਅਚਲ ਅੱਖਰ *ਭਰਿਆ_ਸਤਰ, ਪੂਰਨ *acp, ਅੱਖਰ ***avp,
    ਪੂਰਨ ਸਤਰ, ਬਣਤਰ connection_info *ci)
{
	ਪੂਰਨ ਨਤੀਜਾ = 1, ਗੁਣ = 0, ਪੋਰਟ;
	ਅੱਖਰ *arg, *attrib = ਨਿਰਾ, *oattrib;

	ਜੇ (ci == ਨਿਰਾ) {
		debug3("checking syntax for 'Match %s' on line %d",
		    ਭਰਿਆ_ਸਤਰ, ਸਤਰ);
	} ਨਹੀਂਤਾਂ {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", ਭਰਿਆ_ਸਤਰ,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->ਪਤਾ ? ci->ਪਤਾ : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", ਸਤਰ);
	}

	ਜਦੋਂ ((oattrib = argv_ਅਗਲਾ(acp, avp)) != ਨਿਰਾ) {
		/* Terminate on comment */
		ਜੇ (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			ਰੋਕੋ;
		}
		attrib = xstrdup(oattrib);
		arg = ਨਿਰਾ;
		ਗੁਣ++;
		/* Criterion "all" has no argument and must appear alone */
		ਜੇ (strcasecmp(attrib, "all") == 0) {
			ਜੇ (ਗੁਣ > 1 ||
			    ((arg = argv_ਅਗਲਾ(acp, avp)) != ਨਿਰਾ &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (arg != ਨਿਰਾ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ਨਤੀਜਾ = 1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Criterion "invalid-user" also has no argument */
		ਜੇ (strcasecmp(attrib, "invalid-user") == 0) {
			ਜੇ (ci == ਨਿਰਾ) {
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->user_invalid == 0)
				ਨਤੀਜਾ = 0;
			ਨਹੀਂਤਾਂ
				debug("matched invalid-user at line %d", ਸਤਰ);
			ਜਾਓ ਅਗਲਾ;
		}

		/* Keep this list in sync with below */
		ਜੇ (strprefix(attrib, "user=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "group=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "host=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "address=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "localaddress=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "localport=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "rdomain=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "version=", 1) != ਨਿਰਾ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ਨਹੀਂਤਾਂ {
			arg = argv_ਅਗਲਾ(acp, avp);
		}

		/* All other criteria require an argument */
		ਜੇ (arg == ਨਿਰਾ || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ਨਤੀਜਾ = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcasecmp(attrib, "user") == 0) {
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->user == ਨਿਰਾ)) {
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->user == ਨਿਰਾ)
				ਮੇਲ_test_missing_fatal("User", "user");
			ਜੇ (ਮੇਲ_usergroup_ਨਮੂਨਾ_list(ci->user, arg) != 1)
				ਨਤੀਜਾ = 0;
			ਨਹੀਂਤਾਂ
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, ਸਤਰ);
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "group") == 0) {
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->user == ਨਿਰਾ)) {
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->user == ਨਿਰਾ)
				ਮੇਲ_test_missing_fatal("Group", "user");
			ਚੋਣ (ਮੇਲ_cfg_ਸਤਰ_ਸਮੂਹ(arg, ਸਤਰ, ci->user)) {
			ਹਾਲਤ -1:
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			ਹਾਲਤ 0:
				ਨਤੀਜਾ = 0;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "host") == 0) {
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->host == ਨਿਰਾ)) {
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->host == ਨਿਰਾ)
				ਮੇਲ_test_missing_fatal("Host", "host");
			ਜੇ (ਮੇਲ_hostname(ci->host, arg) != 1)
				ਨਤੀਜਾ = 0;
			ਨਹੀਂਤਾਂ
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, ਸਤਰ);
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "address") == 0) {
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->ਪਤਾ == ਨਿਰਾ)) {
				ਜੇ (addr_ਮੇਲ_list(ਨਿਰਾ, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, ਸਤਰ);
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->ਪਤਾ == ਨਿਰਾ)
				ਮੇਲ_test_missing_fatal("Address", "addr");
			ਚੋਣ (addr_ਮੇਲ_list(ci->ਪਤਾ, arg)) {
			ਹਾਲਤ 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->ਪਤਾ, arg, ਸਤਰ);
				ਰੋਕੋ;
			ਹਾਲਤ 0:
			ਹਾਲਤ -1:
				ਨਤੀਜਾ = 0;
				ਰੋਕੋ;
			ਹਾਲਤ -2:
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "localaddress") == 0){
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->laddress == ਨਿਰਾ)) {
				ਜੇ (addr_ਮੇਲ_list(ਨਿਰਾ, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    ਸਤਰ);
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->laddress == ਨਿਰਾ)
				ਮੇਲ_test_missing_fatal("LocalAddress",
				    "laddr");
			ਚੋਣ (addr_ਮੇਲ_list(ci->laddress, arg)) {
			ਹਾਲਤ 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, ਸਤਰ);
				ਰੋਕੋ;
			ਹਾਲਤ 0:
			ਹਾਲਤ -1:
				ਨਤੀਜਾ = 0;
				ਰੋਕੋ;
			ਹਾਲਤ -2:
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "localport") == 0) {
			ਜੇ ((ਪੋਰਟ = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->lport == -1)) {
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->lport == 0)
				ਮੇਲ_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			ਜੇ (ਪੋਰਟ == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, ਪੋਰਟ, ਸਤਰ);
			ਨਹੀਂਤਾਂ
				ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "rdomain") == 0) {
			ਜੇ (ci == ਨਿਰਾ || (ci->test && ci->rdomain == ਨਿਰਾ)) {
				ਨਤੀਜਾ = 0;
				ਜਾਓ ਅਗਲਾ;
			}
			ਜੇ (ci->rdomain == ਨਿਰਾ)
				ਮੇਲ_test_missing_fatal("RDomain", "rdomain");
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(ci->rdomain, arg, 0) != 1)
				ਨਤੀਜਾ = 0;
			ਨਹੀਂਤਾਂ
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, ਸਤਰ);
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "version") == 0) {
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(SSH_RELEASE, arg, 0) != 1)
				ਨਤੀਜਾ = 0;
			ਨਹੀਂਤਾਂ
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, ਸਤਰ);
		} ਨਹੀਂਤਾਂ {
			error("Unsupported Match attribute %s", oattrib);
			ਨਤੀਜਾ = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
 ਅਗਲਾ:
		ਮੁਕਤ(attrib);
		attrib = ਨਿਰਾ;
	}
	ਜੇ (ਗੁਣ == 0) {
		error("One or more attributes required for Match");
		ਵਾਪਸ -1;
	}
 ਬਾਹਰਲਾ:
	ਜੇ (ci != ਨਿਰਾ && ਨਤੀਜਾ != -1)
		debug3("match %sfound on line %d", ਨਤੀਜਾ ? "" : "not ", ਸਤਰ);
	ਮੁਕਤ(attrib);
	ਵਾਪਸ ਨਤੀਜਾ;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WHITESPACE " \t\r\n"

/* Multistate option parsing */
ਬਣਤਰ multistate {
	ਅੱਖਰ *ਕੁੰਜੀ;
	ਪੂਰਨ ਮੁੱਲ;
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_compression[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#ਜੇ_ਅੰਤ
	{ "no",				COMP_NONE },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ਨਿਰਾ, -1 }
};

ਸਥਿਰ ਪੂਰਨ
process_server_config_ਸਤਰ_ਡੂੰਘਾਈ(ServerOptions *options, ਅੱਖਰ *ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum, ਪੂਰਨ *activep,
    ਬਣਤਰ connection_info *connectinfo, ਪੂਰਨ *inc_flags, ਪੂਰਨ ਡੂੰਘਾਈ,
    ਬਣਤਰ include_list *includes)
{
	ਅੱਖਰ *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	ਪੂਰਨ cmdline = 0, *intptr, ਮੁੱਲ, value2, value3, n, ਪੋਰਟ, oactive, r;
	ਦੁੱਗਣਾ dvalue, *doubleptr = ਨਿਰਾ;
	ਪੂਰਨ ca_only = 0, ਮਿਲਿਆ = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	ਮਾਪ_t len;
	ਲੰਮਾ ਲੰਮਾ val64;
	ਅਚਲ ਬਣਤਰ multistate *multistate_ptr;
	ਅਚਲ ਅੱਖਰ *errstr;
	ਬਣਤਰ include_ਵਸਤੂ *ਵਸਤੂ;
	glob_t gbuf;
	ਅੱਖਰ **oav = ਨਿਰਾ, **av;
	ਪੂਰਨ oac = 0, ac;
	ਪੂਰਨ ret = -1;
	ਅੱਖਰ **strs = ਨਿਰਾ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ਜੇ ((len = ਲੜੀ_ਲੰਬਾਈ(ਸਤਰ)) == 0)
		ਵਾਪਸ 0;
	ਲਈ (len--; len > 0; len--) {
		ਜੇ (strchr(WHITESPACE "\f", ਸਤਰ[len]) == ਨਿਰਾ)
			ਰੋਕੋ;
		ਸਤਰ[len] = '\0';
	}

	str = ਸਤਰ;
	ਜੇ ((keyword = strdelim(&str)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	/* Ignore leading whitespace */
	ਜੇ (*keyword == '\0')
		keyword = strdelim(&str);
	ਜੇ (!keyword || !*keyword || *keyword == '#')
		ਵਾਪਸ 0;
	ਜੇ (str == ਨਿਰਾ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ਵਾਪਸ -1;
	}
	intptr = ਨਿਰਾ;
	charptr = ਨਿਰਾ;
	opcode = parse_token(keyword, filename, linenum, &flags);

	ਜੇ (argv_ਵੰਡੋ(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ਵਾਪਸ -1;
	}
	ac = oac;
	av = oav;

	ਜੇ (activep == ਨਿਰਾ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	ਜੇ (*activep && opcode != s_ਮੇਲ && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	ਜੇ (*activep == 0 && !(flags & SSHCFG_ਮੇਲ)) {
		ਜੇ (connectinfo == ਨਿਰਾ) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} ਨਹੀਂਤਾਂ { /* this is a directive we have already processed */
			ret = 0;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	ਚੋਣ (opcode) {
	/* Portable-specific options */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਹਾਲਤ sUsePAM:
		intptr = &options->use_pam;
		ਜਾਓ parse_flag;
	ਹਾਲਤ sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ

	/* Standard Options */
	ਹਾਲਤ sBadOption:
		ਜਾਓ ਬਾਹਰਲਾ;
	ਹਾਲਤ s_ਪੋਰਟ:
		/* ignore ports from configfile if cmdline specifies ports */
		ਜੇ (options->ports_from_cmdline) {
			argv_consume(&ac);
			ਰੋਕੋ;
		}
		ਜੇ (options->ਅੰਕ_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->ਅੰਕ_ports++] = a2port(arg);
		ਜੇ (options->ports[options->ਅੰਕ_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		ਰੋਕੋ;

	ਹਾਲਤ s_Login_Grace_ਸਮਾਂ:
		intptr = &options->login_grace_ਸਮਾਂ;
 parse_ਸਮਾਂ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		ਜੇ ((ਮੁੱਲ = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ s_Listen_ਪਤਾ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (arg == ਨਿਰਾ || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		ਜੇ (strchr(arg, '[') == ਨਿਰਾ && (p = strchr(arg, ':')) != ਨਿਰਾ
		    && strchr(p+1, ':') != ਨਿਰਾ) {
			ਪੋਰਟ = 0;
			p = arg;
		} ਨਹੀਂਤਾਂ {
			arg2 = ਨਿਰਾ;
			p = hpdelim(&arg);
			ਜੇ (p == ਨਿਰਾ)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			ਜੇ (arg == ਨਿਰਾ)
				ਪੋਰਟ = 0;
			ਨਹੀਂਤਾਂ ਜੇ ((ਪੋਰਟ = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ਨਿਰਾ;
		ਜੇ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_ਅਗਲਾ(&ac, &av)) == ਨਿਰਾ)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			ਜੇ (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		ਕਤਾਰ_listen_addr(options, p, arg2, ਪੋਰਟ);

		ਰੋਕੋ;

	ਹਾਲਤ s_ਪਤਾ_Family:
		intptr = &options->ਪਤਾ_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ਮੁੱਲ = -1;
		ਲਈ (i = 0; multistate_ptr[i].ਕੁੰਜੀ != ਨਿਰਾ; i++) {
			ਜੇ (strcasecmp(arg, multistate_ptr[i].ਕੁੰਜੀ) == 0) {
				ਮੁੱਲ = multistate_ptr[i].ਮੁੱਲ;
				ਰੋਕੋ;
			}
		}
		ਜੇ (ਮੁੱਲ == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ s_Host_ਕੁੰਜੀ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ਜੇ (*activep) {
			servconf_ਜੋੜੋ_hostkey(filename, linenum,
			    options, arg, 1);
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_Host_ਕੁੰਜੀ_Agent:
		charptr = &options->host_ਕੁੰਜੀ_agent;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_ਰਸਤਾ(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sHostCertificate:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ਜੇ (*activep)
			servconf_ਜੋੜੋ_hostcert(filename, linenum, options, arg);
		ਰੋਕੋ;

	ਹਾਲਤ sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ਜੇ (*activep && *charptr == ਨਿਰਾ) {
			*charptr = derelativise_ਰਸਤਾ(arg);
			/* increase optional counter */
			ਜੇ (intptr != ਨਿਰਾ)
				*intptr = *intptr + 1;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sModuliFile:
		charptr = &options->moduli_file;
		ਜਾਓ parse_filename;

	ਹਾਲਤ s_Permit_ਜੜ੍ਹ_Login:
		intptr = &options->permit_ਜੜ੍ਹ_login;
		multistate_ptr = multistate_permitrootlogin;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ s_Ignore_User_ਗਿਆਤ_Hosts:
		intptr = &options->ignore_user_ਗਿਆਤ_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ s_Hostbased_ਵਰਤਦਾ_Name_From_Packet_Only:
		intptr = &options->hostbased_ਵਰਤਦਾ_name_from_packet_only;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		ਜੇ (*arg != '-' &&
		    !sshkey_ਨਾਂ_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ s_Host_ਕੁੰਜੀ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		ਜਾਓ parse_pubkey_algos;

	ਹਾਲਤ sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ਜਾਓ parse_pubkey_algos;

	ਹਾਲਤ sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ਜਾਓ parse_pubkey_algos;

	ਹਾਲਤ sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		ਮੁੱਲ = 0;
		value2 = -1;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (strcasecmp(arg, "none") == 0)
				ਜਾਰੀ;
			ਜੇ (strcasecmp(arg, "touch-required") == 0)
				ਮੁੱਲ |= PUBKEYAUTH_TOUCH_REQUIRED;
			ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(arg, "verify-required") == 0)
				ਮੁੱਲ |= PUBKEYAUTH_VERIFY_REQUIRED;
			ਨਹੀਂਤਾਂ ਜੇ (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				ਜੇ (errstr != ਨਿਰਾ) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			} ਨਹੀਂਤਾਂ {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		ਜੇ (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = ਮੁੱਲ;
			options->max_pubkey_ok = value2;
		}
		ਰੋਕੋ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	ਹਾਲਤ sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		ਜਾਓ parse_flag;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_AFS
	ਹਾਲਤ sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		ਜਾਓ parse_flag;
#ਜੇ_ਅੰਤ /* USE_AFS */
#ਜੇ_ਅੰਤ /* KRB5 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	ਹਾਲਤ sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		ਜਾਓ parse_flag;
#ਜੇ_ਅੰਤ /* GSSAPI */

	ਹਾਲਤ sPasswordAuthentication:
		intptr = &options->password_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sPrintMotd:
		intptr = &options->print_motd;
		ਜਾਓ parse_flag;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DISABLE_LASTLOG
	ਹਾਲਤ s_Print_ਆਖਰੀ_Log:
		intptr = &options->print_lastlog;
		ਜਾਓ parse_flag;
#ਜੇ_ਅੰਤ

	ਹਾਲਤ sX11Forwarding:
		intptr = &options->x11_forwarding;
		ਜਾਓ parse_flag;

	ਹਾਲਤ s_X11_Display_ਵਿੱਥ:
		intptr = &options->x11_display_ਵਿੱਥ;
 parse_int:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ ((errstr = atoi_err(arg, &ਮੁੱਲ)) != ਨਿਰਾ)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sXAuthLocation:
		charptr = &options->xauth_location;
		ਜਾਓ parse_filename;

	ਹਾਲਤ sPermitTTY:
		intptr = &options->permit_tty;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sPermitUserRC:
		intptr = &options->permit_user_rc;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sStrictModes:
		intptr = &options->strict_modes;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ s_Permit_ਖਾਲੀ_ਥਾਵਾਂ_Passwords:
		intptr = &options->permit_ਖਾਲੀ_ਥਾਵਾਂ_passwd;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਮੁੱਲ = 0;
		p = ਨਿਰਾ;
		ਜੇ (strcmp(arg, "yes") == 0)
			ਮੁੱਲ = 1;
		ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "no") == 0)
			ਮੁੱਲ = 0;
		ਨਹੀਂਤਾਂ {
			/* Pattern-list specified */
			ਮੁੱਲ = 1;
			p = xstrdup(arg);
		}
		ਜੇ (*activep && *intptr == -1) {
			*intptr = ਮੁੱਲ;
			*charptr = p;
			p = ਨਿਰਾ;
		}
		ਮੁਕਤ(p);
		ਰੋਕੋ;

	ਹਾਲਤ sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ s_Rekey_ਹੱਦਬੰਦੀ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (ਜਾਂਚ_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			ਜੇ (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		ਜੇ (*activep && options->rekey_ਹੱਦਬੰਦੀ == -1)
			options->rekey_ਹੱਦਬੰਦੀ = val64;
		ਜੇ (ac != 0) { /* optional rekey interval present */
			ਜੇ (strcmp(av[0], "none") == 0) {
				(ਖਾਲੀ)argv_ਅਗਲਾ(&ac, &av);	/* discard */
				ਰੋਕੋ;
			}
			intptr = &options->rekey_interval;
			ਜਾਓ parse_ਸਮਾਂ;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ sUseDNS:
		intptr = &options->use_dns;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਮੁੱਲ = log_facility_ਸੰਖਿਆ(arg);
		ਜੇ (ਮੁੱਲ == SYSLOG_FACILITY_NOT_ਸੈੱਟ)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ਜੇ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਮੁੱਲ = log_level_ਸੰਖਿਆ(arg);
		ਜੇ (ਮੁੱਲ == SYSLOG_LEVEL_NOT_ਸੈੱਟ)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ਜੇ (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ sLogVerbose:
		ਮਿਲਿਆ = options->ਅੰਕ_log_verbose == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->log_verbose = strs;
			options->ਅੰਕ_log_verbose = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ s_Allow_ਧਾਰਾ_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		ਜਾਓ parse_flag;

	ਹਾਲਤ s_Agent_Socket_ਰਸਤਾ:
		charptr = &options->agent_socket_ਰਸਤਾ;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			ਜੇ (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			ਜੇ (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sDisableForwarding:
		intptr = &options->disable_forwarding;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->ਅੰਕ_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0' ||
			    ਮੇਲ_user(ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			ਮਿਲਿਆ = 1;
			ਜੇ (!*activep)
				ਜਾਰੀ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ਜੇ (!ਮਿਲਿਆ) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਰੋਕੋ;

	ਹਾਲਤ sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->ਅੰਕ_deny_users;
		ਜਾਓ parse_allowdenyusers;

	ਹਾਲਤ sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->ਅੰਕ_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			ਮਿਲਿਆ = 1;
			ਜੇ (!*activep)
				ਜਾਰੀ;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ਜੇ (!ਮਿਲਿਆ) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਰੋਕੋ;

	ਹਾਲਤ sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->ਅੰਕ_deny_groups;
		ਜਾਓ parse_allowdenygroups;

	ਹਾਲਤ sCiphers:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ਜੇ (options->ciphers == ਨਿਰਾ)
			options->ciphers = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sMacs:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ਜੇ (options->macs == ਨਿਰਾ)
			options->macs = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sKexAlgorithms:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (*arg != '-' &&
		    !kex_ਨਾਂ_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ਜੇ (options->kex_algorithms == ਨਿਰਾ)
			options->kex_algorithms = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sSubsystem:
		ਜੇ ((arg = argv_ਅਗਲਾ(&ac, &av)) == ਨਿਰਾ || *arg == '\0' ||
		   ((arg2 = argv_ਅਗਲਾ(&ac, &av)) == ਨਿਰਾ || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (!*activep) {
			argv_consume(&ac);
			ਰੋਕੋ;
		}
		ਮਿਲਿਆ = 0;
		ਲਈ (i = 0; i < options->ਅੰਕ_subsystems; i++) {
			ਜੇ (strcmp(arg, options->subsystem_name[i]) == 0) {
				ਮਿਲਿਆ = 1;
				ਰੋਕੋ;
			}
		}
		ਜੇ (ਮਿਲਿਆ) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			ਰੋਕੋ;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->ਅੰਕ_subsystems,
		    options->ਅੰਕ_subsystems + 1,
		    ਆਕਾਰ(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->ਅੰਕ_subsystems,
		    options->ਅੰਕ_subsystems + 1,
		    ਆਕਾਰ(*options->subsystem_command));
		options->subsystem_ਦਲੀਲਾਂ = xrecallocarray(
		    options->subsystem_ਦਲੀਲਾਂ, options->ਅੰਕ_subsystems,
		    options->ਅੰਕ_subsystems + 1,
		    ਆਕਾਰ(*options->subsystem_ਦਲੀਲਾਂ));
		options->subsystem_name[options->ਅੰਕ_subsystems] = xstrdup(arg);
		options->subsystem_command[options->ਅੰਕ_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_ਦਲੀਲਾਂ[options->ਅੰਕ_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		ਮੁਕਤ(arg2);
		ਮੁਕਤ(arg);
		argv_consume(&ac);
		options->ਅੰਕ_subsystems++;
		ਰੋਕੋ;

	ਹਾਲਤ sMaxStartups:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		ਜੇ ((n = ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(arg, "%d:%d:%d",
		    &ਮੁੱਲ, &value2, &value3)) == 3) {
			ਜੇ (ਮੁੱਲ > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} ਨਹੀਂਤਾਂ ਜੇ (n == 1) {
			value3 = ਮੁੱਲ;
			value2 = -1;
		} ਨਹੀਂਤਾਂ {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮੁੱਲ <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ਜੇ (*activep && options->max_startups == -1) {
			options->max_startups_begin = ਮੁੱਲ;
			options->max_startups_ਦਰ = value2;
			options->max_startups = value3;
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਪ੍ਰਤੀ_ਸਰੋਤ_Net_ਖੰਡ_ਮਾਪ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਚੋਣ (n = ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(arg, "%d:%d", &ਮੁੱਲ, &value2)) {
		ਹਾਲਤ 2:
			ਜੇ (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		ਹਾਲਤ 1:
			ਜੇ (ਮੁੱਲ < 0 || ਮੁੱਲ > 32)
				n = -1;
		}
		ਜੇ (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ਜੇ (*activep && options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4 == -1) {
			options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4 = ਮੁੱਲ;
			ਜੇ (n == 2)
				options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6 = value2;
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਪ੍ਰਤੀ_ਸਰੋਤ_Max_Startups:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (strcmp(arg, "none") == 0) { /* no limit */
			ਮੁੱਲ = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
		} ਨਹੀਂਤਾਂ {
			ਜੇ ((errstr = atoi_err(arg, &ਮੁੱਲ)) != ਨਿਰਾ)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		ਜੇ (*activep && options->ਪ੍ਰਤੀ_ਸਰੋਤ_max_startups == -1)
			options->ਪ੍ਰਤੀ_ਸਰੋਤ_max_startups = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ s_ਪ੍ਰਤੀ_ਸਰੋਤ_Penalty_Exempt_List:
		charptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty_exempt;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ਜੇ (addr_ਮੇਲ_list(ਨਿਰਾ, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ s_ਪ੍ਰਤੀ_ਸਰੋਤ_Penalties:
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਅਚਲ ਅੱਖਰ *q = ਨਿਰਾ;

			ਮਿਲਿਆ = 1;
			intptr = ਨਿਰਾ;
			doubleptr = ਨਿਰਾ;
			ਮੁੱਲ = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			ਜੇ (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				ਜੇ (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				ਜੇ (*activep &&
				    options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled == -1)
					options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled = value2;
				ਜਾਰੀ;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "crash:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_crash;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "authfail:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_authfail;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "invaliduser:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_invaliduser;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "noauth:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_noauth;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "grace-exceeded:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_grace;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "refuseconnection:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_refuseconnection;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "max:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_max;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "min:", 0)) != ਨਿਰਾ) {
				doubleptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_min;
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "max-sources4:", 0)) != ਨਿਰਾ) {
				intptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources4;
				ਜੇ ((errstr = atoi_err(q, &ਮੁੱਲ)) != ਨਿਰਾ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ਨਹੀਂਤਾਂ ਜੇ ((q = strprefix(arg, "max-sources6:", 0)) != ਨਿਰਾ) {
				intptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources6;
				ਜੇ ((errstr = atoi_err(q, &ਮੁੱਲ)) != ਨਿਰਾ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ;
				ਮੁੱਲ = ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ;
				ਮੁੱਲ = ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_PERMISSIVE;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_mode6;
				ਮੁੱਲ = ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL;
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_mode6;
				ਮੁੱਲ = ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_PERMISSIVE;
			} ਨਹੀਂਤਾਂ {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			ਜੇ (doubleptr != ਨਿਰਾ) {
				ਜੇ ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				ਜੇ (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled = 1;
				}
			} ਨਹੀਂਤਾਂ ਜੇ (intptr != ਨਿਰਾ) {
				ਜੇ (*activep && *intptr == -1) {
					*intptr = ਮੁੱਲ;
					options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled = 1;
				}
			} ਨਹੀਂਤਾਂ {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		ਜੇ (!ਮਿਲਿਆ) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਰੋਕੋ;

	ਹਾਲਤ sMaxAuthTries:
		intptr = &options->max_authtries;
		ਜਾਓ parse_int;

	ਹਾਲਤ sMaxSessions:
		intptr = &options->max_sessions;
		ਜਾਓ parse_int;

	ਹਾਲਤ sBanner:
		charptr = &options->banner;
		ਜਾਓ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	ਹਾਲਤ s_Authorized_ਕੁੰਜੀਆਂ_File:
		uintptr = &options->ਅੰਕ_authkeys_files;
		chararrayptr = &options->authorized_ਕੁੰਜੀਆਂ_files;
 parse_filenames:
		ਮਿਲਿਆ = *uintptr == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ਮੁਕਤ(arg2);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (*activep && *charptr == ਨਿਰਾ) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			ਜੇ (intptr != ਨਿਰਾ)
				*intptr = *intptr + 1;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sClientAliveInterval:
		intptr = &options->client_alive_interval;
		ਜਾਓ parse_ਸਮਾਂ;

	ਹਾਲਤ s_Client_Alive_ਗਿਣਤੀ_Max:
		intptr = &options->client_alive_ਗਿਣਤੀ_max;
		ਜਾਓ parse_int;

	ਹਾਲਤ sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0' || strchr(arg, '=') != ਨਿਰਾ)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			ਮਿਲਿਆ = 1;
			ਜੇ (!*activep)
				ਜਾਰੀ;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->ਅੰਕ_accept_env,
			    arg);
		}
		ਜੇ (!ਮਿਲਿਆ) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਸੈੱਟ_Env:
		ਮਿਲਿਆ = options->ਅੰਕ_setenv == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0' || strchr(arg, '=') == ਨਿਰਾ)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			ਜੇ (lookup_setenv_ਵਿੱਚ_list(arg, strs, nstrs) != ਨਿਰਾ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ਜਾਰੀ;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->setenv = strs;
			options->ਅੰਕ_setenv = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਮੁੱਲ = -1;
		ਲਈ (i = 0; tunmode_desc[i].val != -1; i++)
			ਜੇ (strcmp(tunmode_desc[i].ਪਾਠ, arg) == 0) {
				ਮੁੱਲ = tunmode_desc[i].val;
				ਰੋਕੋ;
			}
		ਜੇ (ਮੁੱਲ == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ sInclude:
		ਜੇ (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		ਮੁੱਲ = 0;
		ਜਦੋਂ ((arg2 = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਮੁੱਲ++;
			ਮਿਲਿਆ = 0;
			ਜੇ (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} ਨਹੀਂਤਾਂ
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(ਵਸਤੂ, includes, ਇੰਦਰਾਜ) {
				ਜੇ (strcmp(ਵਸਤੂ->selector, arg) != 0)
					ਜਾਰੀ;
				ਜੇ (ਵਸਤੂ->filename != ਨਿਰਾ) {
					parse_server_config_ਡੂੰਘਾਈ(options,
					    ਵਸਤੂ->filename, ਵਸਤੂ->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_ਮੇਲ_ONLY
					        ? SSHCFG_ਮੇਲ_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, ਡੂੰਘਾਈ + 1);
				}
				ਮਿਲਿਆ = 1;
				*activep = oactive;
			}
			ਜੇ (ਮਿਲਿਆ != 0) {
				ਮੁਕਤ(arg);
				ਜਾਰੀ;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			ਜੇ ((r = glob(arg, 0, ਨਿਰਾ, &gbuf)) != 0) {
				ਜੇ (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				ਵਸਤੂ = xcalloc(1, ਆਕਾਰ(*ਵਸਤੂ));
				ਵਸਤੂ->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    ਵਸਤੂ, ਇੰਦਰਾਜ);
			}
			ਜੇ (gbuf.gl_pathc > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
				fatal_f("too many glob results");
			ਲਈ (n = 0; n < (ਪੂਰਨ)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				ਵਸਤੂ = xcalloc(1, ਆਕਾਰ(*ਵਸਤੂ));
				ਵਸਤੂ->selector = xstrdup(arg);
				ਵਸਤੂ->filename = xstrdup(gbuf.gl_pathv[n]);
				ਜੇ ((ਵਸਤੂ->contents = sshbuf_new()) == ਨਿਰਾ)
					fatal_f("sshbuf_new failed");
				ਲੱਦੋ_server_config(ਵਸਤੂ->filename,
				    ਵਸਤੂ->contents);
				parse_server_config_ਡੂੰਘਾਈ(options,
				    ਵਸਤੂ->filename, ਵਸਤੂ->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_ਮੇਲ_ONLY
				        ? SSHCFG_ਮੇਲ_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, ਡੂੰਘਾਈ + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, ਵਸਤੂ, ਇੰਦਰਾਜ);
			}
			globfree(&gbuf);
			ਮੁਕਤ(arg);
		}
		ਜੇ (ਮੁੱਲ == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਮੇਲ:
		ਜੇ (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		ਮੁੱਲ = ਮੇਲ_cfg_ਸਤਰ(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ਨਿਰਾ : connectinfo));
		ਜੇ (ਮੁੱਲ < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : ਮੁੱਲ;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_ਮੇਲ_ONLY;
		ਰੋਕੋ;

	ਹਾਲਤ sPermitListen:
	ਹਾਲਤ sPermitOpen:
		ਜੇ (opcode == sPermitListen) {
			uintptr = &options->ਅੰਕ_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} ਨਹੀਂਤਾਂ {
			uintptr = &options->ਅੰਕ_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		ਮਿਲਿਆ = *uintptr == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				ਜੇ (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				ਜਾਰੀ;
			}

			ਜੇ (opcode == sPermitListen &&
			    strchr(arg, ':') == ਨਿਰਾ) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} ਨਹੀਂਤਾਂ {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				ਜੇ (p == ਨਿਰਾ) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			ਜੇ (arg == ਨਿਰਾ ||
			    ((ਪੋਰਟ = permitopen_ਪੋਰਟ(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			ਮੁਕਤ(arg2);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sForceCommand:
		ਜੇ (str == ਨਿਰਾ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ਜੇ (*activep && options->adm_forced_command == ਨਿਰਾ)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_ਕੁੰਜੀਆਂ;
		ਜਾਓ parse_filename;

	ਹਾਲਤ s_Revoked_ਕੁੰਜੀਆਂ:
		uintptr = &options->ਅੰਕ_revoked_ਕੁੰਜੀਆਂ_files;
		chararrayptr = &options->revoked_ਕੁੰਜੀਆਂ_files;
		ਜਾਓ parse_filenames;

	ਹਾਲਤ s_Security_ਕੁੰਜੀ_Provider:
		charptr = &options->sk_provider;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (*activep && *charptr == ਨਿਰਾ) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_ਰਸਤਾ(arg);
			/* increase optional counter */
			ਜੇ (intptr != ਨਿਰਾ)
				*intptr = *intptr + 1;
		}
		ਰੋਕੋ;

	ਹਾਲਤ sIPQoS:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ ((ਮੁੱਲ = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ਜੇ (ਮੁੱਲ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ਮੁੱਲ = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
		}
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (arg == ਨਿਰਾ)
			value2 = ਮੁੱਲ;
		ਨਹੀਂਤਾਂ ਜੇ ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ਜੇ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
		}
		ਜੇ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ਮੁੱਲ;
			options->ip_qos_bulk = value2;
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਸੰਸਕਰਣ_Addendum:
		ਜੇ (str == ਨਿਰਾ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ਜੇ (strchr(str + len, '\r') != ਨਿਰਾ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ਜੇ ((arg = strchr(ਸਤਰ, '#')) != ਨਿਰਾ) {
			*arg = '\0';
			rtrim(ਸਤਰ);
		}
		ਜੇ (*activep && options->ਸੰਸਕਰਣ_addendum == ਨਿਰਾ) {
			ਜੇ (strcasecmp(str + len, "none") == 0)
				options->ਸੰਸਕਰਣ_addendum = xstrdup("");
			ਨਹੀਂਤਾਂ
				options->ਸੰਸਕਰਣ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ s_Authorized_ਕੁੰਜੀਆਂ_Command:
		charptr = &options->authorized_ਕੁੰਜੀਆਂ_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		ਜੇ (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ s_Authorized_ਕੁੰਜੀਆਂ_Command_User:
		charptr = &options->authorized_ਕੁੰਜੀਆਂ_command_user;
 parse_localuser:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		ਜਾਓ parse_command;

	ਹਾਲਤ sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		ਜਾਓ parse_localuser;

	ਹਾਲਤ sAuthenticationMethods:
		ਮਿਲਿਆ = options->ਅੰਕ_auth_methods == 0;
		ਮੁੱਲ = 0; /* seen "any" pseudo-method */
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (strcmp(arg, "any") == 0) {
				ਜੇ (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				ਮੁੱਲ = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (ਮੁੱਲ) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} ਨਹੀਂਤਾਂ ਜੇ (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->auth_methods = strs;
			options->ਅੰਕ_auth_methods = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਧਾਰਾ_Local_Bind_ਨਕਾਬ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		ਮੁੱਲ = strtol(arg, &p, 8);
		ਜੇ (arg == p || ਮੁੱਲ < 0 || ਮੁੱਲ > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		ਜੇ (*activep &&
		    options->fwd_opts.streamlocal_bind_ਨਕਾਬ == (ਬਹੁਲਕ_t)-1)
			options->fwd_opts.streamlocal_bind_ਨਕਾਬ = (ਬਹੁਲਕ_t)ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ s_ਧਾਰਾ_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sFingerprintHash:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ ((ਮੁੱਲ = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		ਜੇ (*activep)
			options->fingerprint_hash = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		ਜਾਓ parse_flag;

	ਹਾਲਤ sRDomain:
#ਜੇ !defined(__OpenBSD__) && !defined(HAVE_SYS_ਸੈੱਟ_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#ਜੇ_ਅੰਤ
		charptr = &options->routing_domain;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ਜੇ (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ sRequiredRSASize:
		intptr = &options->required_rsa_ਮਾਪ;
		ਜਾਓ parse_int;

	ਹਾਲਤ sChannelTimeout:
		ਮਿਲਿਆ = options->ਅੰਕ_channel_timeouts == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			} ਨਹੀਂਤਾਂ ਜੇ (parse_ਨਮੂਨਾ_interval(arg,
			    ਨਿਰਾ, ਨਿਰਾ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->channel_timeouts = strs;
			options->ਅੰਕ_channel_timeouts = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ s_ਅਣਵਰਤਿਆ_Connection_Timeout:
		intptr = &options->ਅਣਵਰਤਿਆ_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		ਜੇ (av[0] != ਨਿਰਾ && strcasecmp(av[0], "none") == 0) {
			(ਖਾਲੀ)argv_ਅਗਲਾ(&ac, &av); /* consume arg */
			ਜੇ (*activep)
				*intptr = 0;
			ਰੋਕੋ;
		}
		ਜਾਓ parse_ਸਮਾਂ;

	ਹਾਲਤ s_Sshd_Session_ਰਸਤਾ:
		charptr = &options->sshd_session_ਰਸਤਾ;
		ਜਾਓ parse_filename;

	ਹਾਲਤ s_Sshd_Auth_ਰਸਤਾ:
		charptr = &options->sshd_auth_ਰਸਤਾ;
		ਜਾਓ parse_filename;

	ਹਾਲਤ sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ sDeprecated:
	ਹਾਲਤ sIgnore:
	ਹਾਲਤ sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		ਰੋਕੋ;

	ਮੂਲ:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	ਜੇ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	opt_array_free2(strs, ਨਿਰਾ, nstrs);
	argv_free(oav, oac);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
process_server_config_ਸਤਰ(ServerOptions *options, ਅੱਖਰ *ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum, ਪੂਰਨ *activep,
    ਬਣਤਰ connection_info *connectinfo, ਬਣਤਰ include_list *includes)
{
	ਪੂਰਨ inc_flags = 0;

	ਵਾਪਸ process_server_config_ਸਤਰ_ਡੂੰਘਾਈ(options, ਸਤਰ, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

ਖਾਲੀ
ਲੱਦੋ_server_config(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ sshbuf *conf)
{
	ਬਣਤਰ stat st;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ, *cp;
	ਮਾਪ_t linesize = 0;
	FILE *f;
	ਪੂਰਨ r;

	debug2_f("filename %s", filename);
	ਜੇ ((f = fopen(filename, "r")) == ਨਿਰਾ) {
		perror(filename);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	ਜੇ (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = ਸਤਰ + strspn(ਸਤਰ, " \t\r");
		ਜੇ ((r = sshbuf_put(conf, cp, ਲੜੀ_ਲੰਬਾਈ(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	ਮੁਕਤ(ਸਤਰ);
	ਜੇ ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

ਖਾਲੀ
parse_server_ਮੇਲ_config(ServerOptions *options,
   ਬਣਤਰ include_list *includes, ਬਣਤਰ connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_ਸੈੱਟ_server_options(options, &mo, 0);
	free_server_options(&mo);
}

ਪੂਰਨ
parse_server_ਮੇਲ_testspec(ਬਣਤਰ connection_info *ci, ਅੱਖਰ *spec)
{
	ਅੱਖਰ *p;
	ਅਚਲ ਅੱਖਰ *val;

	ਜਦੋਂ ((p = strsep(&spec, ",")) && *p != '\0') {
		ਜੇ ((val = strprefix(p, "addr=", 0)) != ਨਿਰਾ) {
			ci->ਪਤਾ = xstrdup(val);
		} ਨਹੀਂਤਾਂ ਜੇ ((val = strprefix(p, "host=", 0)) != ਨਿਰਾ) {
			ci->host = xstrdup(val);
		} ਨਹੀਂਤਾਂ ਜੇ ((val = strprefix(p, "user=", 0)) != ਨਿਰਾ) {
			ci->user = xstrdup(val);
		} ਨਹੀਂਤਾਂ ਜੇ ((val = strprefix(p, "laddr=", 0)) != ਨਿਰਾ) {
			ci->laddress = xstrdup(val);
		} ਨਹੀਂਤਾਂ ਜੇ ((val = strprefix(p, "rdomain=", 0)) != ਨਿਰਾ) {
			ci->rdomain = xstrdup(val);
		} ਨਹੀਂਤਾਂ ਜੇ ((val = strprefix(p, "lport=", 0)) != ਨਿਰਾ) {
			ci->lport = a2port(val);
			ਜੇ (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				ਵਾਪਸ -1;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} ਨਹੀਂਤਾਂ {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			ਵਾਪਸ -1;
		}
	}
	ਵਾਪਸ 0;
}

ਖਾਲੀ
servconf_ਮਿਲਾਓ_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, ਮਿਲਿਆ;

	ਲਈ (i = 0; i < src->ਅੰਕ_subsystems; i++) {
		ਮਿਲਿਆ = 0;
		ਲਈ (j = 0; j < dst->ਅੰਕ_subsystems; j++) {
			ਜੇ (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				ਮਿਲਿਆ = 1;
				ਰੋਕੋ;
			}
		}
		ਜੇ (ਮਿਲਿਆ) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			ਮੁਕਤ(dst->subsystem_command[j]);
			ਮੁਕਤ(dst->subsystem_ਦਲੀਲਾਂ[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_ਦਲੀਲਾਂ[j] =
			    xstrdup(src->subsystem_ਦਲੀਲਾਂ[i]);
			ਜਾਰੀ;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->ਅੰਕ_subsystems,
		    dst->ਅੰਕ_subsystems + 1, ਆਕਾਰ(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->ਅੰਕ_subsystems,
		    dst->ਅੰਕ_subsystems + 1, ਆਕਾਰ(*dst->subsystem_command));
		dst->subsystem_ਦਲੀਲਾਂ = xrecallocarray(
		    dst->subsystem_ਦਲੀਲਾਂ, dst->ਅੰਕ_subsystems,
		    dst->ਅੰਕ_subsystems + 1, ਆਕਾਰ(*dst->subsystem_ਦਲੀਲਾਂ));
		j = dst->ਅੰਕ_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_ਦਲੀਲਾਂ[j] = xstrdup(src->subsystem_ਦਲੀਲਾਂ[i]);
	}
}

ਸਥਿਰ ਪੂਰਨ
serialise_s32(ਬਣਤਰ sshbuf *buf, ਪੂਰਨ v)
{
	uint32_t uv;
	ਪੂਰਨ r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	ਜੇ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_s64(ਬਣਤਰ sshbuf *buf, int64_t v)
{
	uint64_t uv;
	ਪੂਰਨ r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	ਜੇ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_ਬਹੁਲਕ(ਬਣਤਰ sshbuf *buf, ਬਹੁਲਕ_t v)
{
	u_int uv;

	ਜੇ (v == (ਬਹੁਲਕ_t)-1)
		ਵਾਪਸ serialise_s32(buf, -1);
	uv = (u_int)v;
	ਜੇ ((ਬਹੁਲਕ_t)uv != v || uv > 0777)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ serialise_s32(buf, (ਪੂਰਨ)uv);
}

ਸਥਿਰ ਪੂਰਨ
serialise_double(ਬਣਤਰ sshbuf *buf, ਦੁੱਗਣਾ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	ਵਾਪਸ sshbuf_put(buf, &v, ਆਕਾਰ(v));
}

ਸਥਿਰ ਪੂਰਨ
serialise_nullable_string(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *s)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u8(buf, s != ਨਿਰਾ)) != 0)
		ਵਾਪਸ r;
	ਜੇ (s == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ sshbuf_put_cstring(buf, s);
}

ਸਥਿਰ ਪੂਰਨ
serialise_nullable_string_array(ਬਣਤਰ sshbuf *buf, ਅੱਖਰ **a, u_int n)
{
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((r = sshbuf_put_u32(buf, n)) != 0)
		ਵਾਪਸ r;
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = serialise_nullable_string(buf, a[i])) != 0)
			ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_hostkeyfile(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((r = sshbuf_put_u32(buf, options->ਅੰਕ_host_ਕੁੰਜੀ_files)) != 0) {
		error_fr(r, "serialise length");
		ਵਾਪਸ r;
	}
	ਲਈ (i = 0; i < options->ਅੰਕ_host_ਕੁੰਜੀ_files; i++) {
		ਜੇ ((r = serialise_s32(buf,
		    options->host_ਕੁੰਜੀ_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_ਕੁੰਜੀ_files[i])) != 0) {
			error_fr(r, "serialise member");
			ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_ipqos(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_listenaddress(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	ਜੇ ((r = sshbuf_put_u32(buf, options->ਅੰਕ_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		ਵਾਪਸ r;
	}
	ਲਈ (i = 0; i < options->ਅੰਕ_queued_listens; i++) {
		ਅਚਲ ਬਣਤਰ queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		ਜੇ ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->ਪੋਰਟ)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_logfacility(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, (ਪੂਰਨ)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_loglevel(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, (ਪੂਰਨ)options->log_level)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_ਪੋਰਟ(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((r = sshbuf_put_u32(buf, options->ਅੰਕ_ports)) != 0) {
		error_fr(r, "serialise length");
		ਵਾਪਸ r;
	}
	ਲਈ (i = 0; i < options->ਅੰਕ_ports; i++) {
		ਜੇ ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_gatewayports(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_streamlocalbindmask(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_ਬਹੁਲਕ(buf,
	    options->fwd_opts.streamlocal_bind_ਨਕਾਬ)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_streamlocalbindunlink(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_maxstartups(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_ਦਰ)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_permituserenv(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_persourcenetblocksize(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_persourcepenalties(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਅਚਲ ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty *psp = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty;
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->ਉਛਾਲ_ਬਹੁਲਕ)) != 0 ||
	    (r = serialise_s32(buf, psp->ਉਛਾਲ_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_rekeylimit(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s64(buf, options->rekey_ਹੱਦਬੰਦੀ)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_subsystem(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i;

	ਜੇ ((r = sshbuf_put_u32(buf, options->ਅੰਕ_subsystems)) != 0) {
		error_fr(r, "serialise length");
		ਵਾਪਸ r;
	}
	ਲਈ (i = 0; i < options->ਅੰਕ_subsystems; i++) {
		ਜੇ ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_ਦਲੀਲਾਂ[i])) != 0) {
			error_fr(r, "serialise member");
			ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_pubkey_auth_options(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
serialise_timingsecret(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}


ਪੂਰਨ
serialise_server_options(ਅਚਲ ServerOptions *options, ਬਣਤਰ sshbuf **bufp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*bufp = ਨਿਰਾ;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_ਸੰਸਕਰਣ)) != 0) {
		error_fr(r, "serialise version");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ਜੇ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ਜੇ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp) \
	ਜੇ ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ਜੇ ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ਜੇ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ਜਾਓ ਬਾਹਰਲਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix) \
	ਜੇ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		ਜਾਓ ਬਾਹਰਲਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

	SSHD_CONFIG_ENTRIES

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = ਨਿਰਾ; /* transferred */
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_s32(ਬਣਤਰ sshbuf *buf, ਪੂਰਨ *v)
{
	uint32_t tmp;
	ਪੂਰਨ r;
	u_char was_signed;

	ਜੇ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		ਵਾਪਸ r;
	ਜੇ (was_signed > 1)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (was_signed) {
		ਜੇ (tmp > (uint32_t)ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ + 1)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ + 1 ? INT_MIN : -(ਪੂਰਨ)tmp;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (tmp > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		*v = (ਪੂਰਨ)tmp;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_s64(ਬਣਤਰ sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	ਪੂਰਨ r;
	u_char was_signed;

	ਜੇ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		ਵਾਪਸ r;
	ਜੇ (was_signed > 1)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (was_signed) {
		ਜੇ (tmp > (uint64_t)INT64_MAX + 1)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (tmp > INT64_MAX)
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_ਬਹੁਲਕ(ਬਣਤਰ sshbuf *buf, ਬਹੁਲਕ_t *v)
{
	ਪੂਰਨ r, tmp;

	ਜੇ ((r = deserialise_s32(buf, &tmp)) != 0)
		ਵਾਪਸ r;
	ਜੇ (tmp == -1) {
		*v = (ਬਹੁਲਕ_t)-1;
		ਵਾਪਸ 0;
	}
	ਜੇ (tmp < 0 || tmp > 0777)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	*v = (ਬਹੁਲਕ_t)tmp;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_double(ਬਣਤਰ sshbuf *buf, ਦੁੱਗਣਾ *v)
{
	ਵਾਪਸ sshbuf_get(buf, v, ਆਕਾਰ(*v));
}

ਸਥਿਰ ਪੂਰਨ
deserialise_nullable_string(ਬਣਤਰ sshbuf *buf, ਅੱਖਰ **sp)
{
	ਪੂਰਨ r;
	u_char present;

	ਜੇ ((r = sshbuf_get_u8(buf, &present)) != 0)
		ਵਾਪਸ r;
	ਜੇ (present == 0) {
		*sp = ਨਿਰਾ;
		ਵਾਪਸ 0;
	}
	ਜੇ (present != 1)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ sshbuf_get_cstring(buf, sp, ਨਿਰਾ);
}

ਸਥਿਰ ਖਾਲੀ
free_string_array(ਅੱਖਰ **a, u_int n)
{
	u_int i;

	ਜੇ (a == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < n; i++)
		ਮੁਕਤ(a[i]);
	ਮੁਕਤ(a);
}

ਸਥਿਰ ਪੂਰਨ
deserialise_ਗਿਣਤੀ(ਬਣਤਰ sshbuf *buf, u_int *np, ਅਚਲ ਅੱਖਰ *what)
{
	ਪੂਰਨ r;
	uint32_t n;

	ਜੇ ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		ਵਾਪਸ r;
	}
	ਜੇ (n > UINT_MAX) {
		error_f("bad number of %s", what);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਜੇ (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_nullable_string_array(ਬਣਤਰ sshbuf *buf, ਅੱਖਰ ***arrayp,
    u_int *np)
{
	ਅੱਖਰ **a = ਨਿਰਾ;
	ਪੂਰਨ r;
	u_int i, n;

	*arrayp = ਨਿਰਾ;
	*np = 0;
	ਜੇ ((r = deserialise_ਗਿਣਤੀ(buf, &n, "strings")) != 0)
		ਵਾਪਸ r;
	ਜੇ (n > 0)
		a = xcalloc(n, ਆਕਾਰ(*a));
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			ਵਾਪਸ r;
		}
	}
	*arrayp = a;
	*np = n;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
free_queued_listen_addrs(ਬਣਤਰ queued_listenaddr *qla, u_int n)
{
	u_int i;

	ਜੇ (qla == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < n; i++) {
		ਮੁਕਤ(qla[i].addr);
		ਮੁਕਤ(qla[i].rdomain);
	}
	ਮੁਕਤ(qla);
}

ਸਥਿਰ ਪੂਰਨ
deserialise_hostkeyfile(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r, *userprovided = ਨਿਰਾ;
	u_int i, n;
	ਅੱਖਰ **files = ਨਿਰਾ;

	ਜੇ ((r = deserialise_ਗਿਣਤੀ(buf, &n, "host key files")) != 0)
		ਵਾਪਸ r;
	ਜੇ (n > 0) {
		userprovided = xcalloc(n, ਆਕਾਰ(*userprovided));
		files = xcalloc(n, ਆਕਾਰ(*files));
	}
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			ਮੁਕਤ(userprovided);
			ਵਾਪਸ r;
		}
	}
	options->ਅੰਕ_host_ਕੁੰਜੀ_files = n;
	options->host_ਕੁੰਜੀ_file_userprovided = userprovided;
	options->host_ਕੁੰਜੀ_files = files;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_ipqos(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_listenaddress(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i, n;
	ਬਣਤਰ queued_listenaddr *qla = ਨਿਰਾ;

	ਜੇ ((r = deserialise_ਗਿਣਤੀ(buf, &n, "listen addresses")) != 0)
		ਵਾਪਸ r;
	ਜੇ (n > 0)
		qla = xcalloc(n, ਆਕਾਰ(*qla));
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = sshbuf_get_cstring(buf, &qla[i].addr, ਨਿਰਾ)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].ਪੋਰਟ)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			ਵਾਪਸ r;
		}
	}
	options->ਅੰਕ_queued_listens = n;
	options->queued_listen_addrs = qla;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_logfacility(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r, tmp;

	ਜੇ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਜੇ (tmp != SYSLOG_FACILITY_NOT_ਸੈੱਟ &&
	    log_facility_name((SyslogFacility)tmp) == ਨਿਰਾ) {
		error_f("bad syslog facility");
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_loglevel(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r, tmp;

	ਜੇ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਜੇ (tmp != SYSLOG_LEVEL_NOT_ਸੈੱਟ &&
	    log_level_name((LogLevel)tmp) == ਨਿਰਾ) {
		error_f("bad log level");
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_ਪੋਰਟ(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i, n;

	ਜੇ ((r = deserialise_ਗਿਣਤੀ(buf, &n, "ports")) != 0)
		ਵਾਪਸ r;
	ਜੇ (n > MAX_PORTS) {
		error_f("bad number of ports");
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	options->ਅੰਕ_ports = n;
	memset(options->ports, 0, ਆਕਾਰ(options->ports));
	ਲਈ (i = 0; i < options->ਅੰਕ_ports; i++) {
		ਜੇ ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_gatewayports(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_streamlocalbindmask(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_ਬਹੁਲਕ(buf,
	    &options->fwd_opts.streamlocal_bind_ਨਕਾਬ)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_streamlocalbindunlink(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_char tmp;

	ਜੇ ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਜੇ (tmp > 1) {
		error_f("bad boolean");
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_maxstartups(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_ਦਰ)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_permituserenv(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_persourcenetblocksize(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf,
	    &options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_persourcepenalties(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਬਣਤਰ ਪ੍ਰਤੀ_ਸਰੋਤ_penalty *psp = &options->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty;
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->ਉਛਾਲ_ਬਹੁਲਕ)) != 0 ||
	    (r = deserialise_s32(buf, &psp->ਉਛਾਲ_mode6)) != 0 ||
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
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_rekeylimit(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s64(buf, &options->rekey_ਹੱਦਬੰਦੀ)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_subsystem(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;
	u_int i, n;
	ਅੱਖਰ **ਨਾਂ = ਨਿਰਾ, **commands = ਨਿਰਾ, **ਦਲੀਲਾਂ = ਨਿਰਾ;

	ਜੇ ((r = deserialise_ਗਿਣਤੀ(buf, &n, "subsystems")) != 0)
		ਵਾਪਸ r;
	ਜੇ (n > 0) {
		ਨਾਂ = xcalloc(n, ਆਕਾਰ(*ਨਾਂ));
		commands = xcalloc(n, ਆਕਾਰ(*ਨਾਂ));
		ਦਲੀਲਾਂ = xcalloc(n, ਆਕਾਰ(*ਦਲੀਲਾਂ));
	}
	ਲਈ (i = 0; i < n; i++) {
		ਜੇ ((r = sshbuf_get_cstring(buf, ਨਾਂ + i, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, ਦਲੀਲਾਂ + i, ਨਿਰਾ)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(ਨਾਂ, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(ਦਲੀਲਾਂ, i + 1);
			ਵਾਪਸ r;
		}
	}
	options->ਅੰਕ_subsystems = n;
	options->subsystem_name = ਨਾਂ;
	options->subsystem_command = commands;
	options->subsystem_ਦਲੀਲਾਂ = ਦਲੀਲਾਂ;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_pubkey_auth_options(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
deserialise_timingsecret(ServerOptions *options, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
deserialise_server_options(ਬਣਤਰ sshbuf *buf, ServerOptions *options)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	uint32_t ਸੰਸਕਰਣ;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	ਜੇ ((r = sshbuf_get_u32(buf, &ਸੰਸਕਰਣ)) != 0) {
		error_fr(r, "deserialise version");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ਸੰਸਕਰਣ != SSHD_CONFIG_BLOB_ਸੰਸਕਰਣ) {
		error_f("unsupported config blob version %u", ਸੰਸਕਰਣ);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ਜੇ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ਜੇ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp) \
	ਜੇ ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ਜੇ ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		ਜਾਓ ਬਾਹਰਲਾ; \
	}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ਜੇ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ਜਾਓ ਬਾਹਰਲਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix) \
	ਜੇ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		ਜਾਓ ਬਾਹਰਲਾ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ਕਰੋ { \
		ਮੁਕਤ(new_options.var); \
		new_options.var = ਨਿਰਾ; \
	} ਜਦੋਂ (0);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

	SSHD_CONFIG_ENTRIES

	ਜੇ (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, ਆਕਾਰ(new_options));
 ਬਾਹਰਲਾ:
	free_server_options(&new_options);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	ਲਈ (i = 0; i < options->ਅੰਕ_host_ਕੁੰਜੀ_files; i++)
		ਮੁਕਤ(options->host_ਕੁੰਜੀ_files[i]);
	ਮੁਕਤ(options->host_ਕੁੰਜੀ_files);
	ਮੁਕਤ(options->host_ਕੁੰਜੀ_file_userprovided);
}

ਸਥਿਰ ਖਾਲੀ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->ਅੰਕ_queued_listens);

	ਲਈ (i = 0; i < options->ਅੰਕ_listen_addrs; i++) {
		ਮੁਕਤ(options->listen_addrs[i].rdomain);
		ਜੇ (options->listen_addrs[i].addrs != ਨਿਰਾ)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	ਮੁਕਤ(options->listen_addrs);
}

ਸਥਿਰ ਖਾਲੀ
free_permituserenv(ServerOptions *options)
{
	ਮੁਕਤ(options->permit_user_env_allowlist);
}

ਸਥਿਰ ਖਾਲੀ
free_subsystem(ServerOptions *options)
{
	u_int i;

	ਲਈ (i = 0; i < options->ਅੰਕ_subsystems; i++) {
		ਮੁਕਤ(options->subsystem_name[i]);
		ਮੁਕਤ(options->subsystem_command[i]);
		ਮੁਕਤ(options->subsystem_ਦਲੀਲਾਂ[i]);
	}
	ਮੁਕਤ(options->subsystem_name);
	ਮੁਕਤ(options->subsystem_command);
	ਮੁਕਤ(options->subsystem_ਦਲੀਲਾਂ);
}

ਖਾਲੀ
free_server_options(ServerOptions *options)
{
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp)		ਮੁਕਤ(options->var);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ਕਰੋ { \
		ਮੁਕਤ(options->var); \
		options->var = ਨਿਰਾ; \
	} ਜਦੋਂ (0);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_ipqos(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_logfacility(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_loglevel(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_ਪੋਰਟ(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_gatewayports(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_streamlocalbindmask(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_streamlocalbindunlink(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_maxstartups(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_persourcenetblocksize(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_persourcepenalties(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_rekeylimit(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_pubkey_auth_options(options)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_ipqos
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_logfacility
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_loglevel
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_ਪੋਰਟ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_gatewayports
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_streamlocalbindmask
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_streamlocalbindunlink
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_maxstartups
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_persourcenetblocksize
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_persourcepenalties
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_rekeylimit
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_timingsecret

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

	initialize_server_options(options);
}

ਸਥਿਰ ਖਾਲੀ
copy_server_option_int(ਪੂਰਨ *dst, ਪੂਰਨ src)
{
	ਜੇ (src != -1)
		*dst = src;
}

ਸਥਿਰ ਖਾਲੀ
copy_server_option_int64(int64_t *dst, int64_t src)
{
	ਜੇ (src != -1)
		*dst = src;
}

ਸਥਿਰ ਖਾਲੀ
copy_server_option_string(ਅੱਖਰ **dst, ਅਚਲ ਅੱਖਰ *src)
{
	ਜੇ (src != ਨਿਰਾ && *dst != src) {
		ਮੁਕਤ(*dst);
		*dst = xstrdup(src);
	}
}

ਸਥਿਰ ਖਾਲੀ
copy_server_option_strarray_ਮੁੱਲਾਂ(ਅੱਖਰ ***dst, u_int ndst,
    ਅੱਖਰ * ਅਚਲ *src, u_int nsrc)
{
	u_int i;

	ਜੇ (nsrc == 0)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < ndst; i++)
		ਮੁਕਤ((*dst)[i]);
	ਮੁਕਤ(*dst);
	*dst = xcalloc(nsrc, ਆਕਾਰ(**dst));
	ਲਈ (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ਨਿਰਾ ? ਨਿਰਾ : xstrdup(src[i]);
}

ਸਥਿਰ ਖਾਲੀ
copy_server_option_strarray(ਅੱਖਰ ***dst, u_int *ndst,
    ਅੱਖਰ * ਅਚਲ *src, u_int nsrc)
{
	ਜੇ (nsrc == 0)
		ਵਾਪਸ;
	copy_server_option_strarray_ਮੁੱਲਾਂ(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ਸਥਿਰ ਖਾਲੀ
copy_ipqos(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ਸਥਿਰ ਖਾਲੀ
copy_gatewayports(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ਸਥਿਰ ਖਾਲੀ
copy_streamlocalbindunlink(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ਸਥਿਰ ਖਾਲੀ
copy_loglevel(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	ਜੇ (src->log_level != -1)
		dst->log_level = src->log_level;
}

ਸਥਿਰ ਖਾਲੀ
copy_rekeylimit(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_ਹੱਦਬੰਦੀ, src->rekey_ਹੱਦਬੰਦੀ);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ਸਥਿਰ ਖਾਲੀ
copy_subsystem(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	u_int old_ਅੰਕ_subsystems = dst->ਅੰਕ_subsystems;

	ਜੇ (src->ਅੰਕ_subsystems == 0)
		ਵਾਪਸ;
	copy_server_option_strarray_ਮੁੱਲਾਂ(&dst->subsystem_name,
	    old_ਅੰਕ_subsystems, src->subsystem_name, src->ਅੰਕ_subsystems);
	copy_server_option_strarray_ਮੁੱਲਾਂ(&dst->subsystem_command,
	    old_ਅੰਕ_subsystems, src->subsystem_command, src->ਅੰਕ_subsystems);
	copy_server_option_strarray_ਮੁੱਲਾਂ(&dst->subsystem_ਦਲੀਲਾਂ,
	    old_ਅੰਕ_subsystems, src->subsystem_ਦਲੀਲਾਂ, src->ਅੰਕ_subsystems);
	dst->ਅੰਕ_subsystems = src->ਅੰਕ_subsystems;
}

ਸਥਿਰ ਖਾਲੀ
copy_pubkey_auth_options(ServerOptions *dst, ਅਚਲ ServerOptions *src)
{
	ਜੇ (src->pubkey_auth_options != -1) {
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
ਖਾਲੀ
copy_ਸੈੱਟ_server_options(ServerOptions *dst, ServerOptions *src, ਪੂਰਨ preauth)
{
	ਜੇ (dst == src)
		ਵਾਪਸ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_NONCONF(funcsuffix)			/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_DEPRECATE(conf, flags, opcode)		/*ਖਾਲੀ_ਥਾਵਾਂ*/
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ਕਰੋ { \
		ਮੁਕਤ(dst->var); \
		dst->var = ਨਿਰਾ; \
	} ਜਦੋਂ (0);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHCONF_ALIAS(old, conf, flags)			/*ਖਾਲੀ_ਥਾਵਾਂ*/

	SSHD_CONFIG_ENTRIES

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_INTFLAG
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_STRARRAY
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_CUSTOM
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_NONCONF
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_DEPRECATE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_INT
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_UNSUPPORTED_STRING
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	ਜੇ (src->fwd_opts.streamlocal_bind_ਨਕਾਬ != (ਬਹੁਲਕ_t)-1) {
		dst->fwd_opts.streamlocal_bind_ਨਕਾਬ =
		    src->fwd_opts.streamlocal_bind_ਨਕਾਬ;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CLEAR_ON_NONE(v) \
	ਕਰੋ { \
		ਜੇ (option_clear_or_none(v)) { \
			ਮੁਕਤ(v); \
			v = ਨਿਰਾ; \
		} \
	} ਜਦੋਂ(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_ਕੁੰਜੀਆਂ);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	ਜੇ (preauth)
		ਵਾਪਸ;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_ਮਿਲਾਓ_subsystems(dst, src);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SERVCONF_MAX_ਡੂੰਘਾਈ	16
ਸਥਿਰ ਖਾਲੀ
parse_server_config_ਡੂੰਘਾਈ(ServerOptions *options, ਅਚਲ ਅੱਖਰ *filename,
    ਬਣਤਰ sshbuf *conf, ਬਣਤਰ include_list *includes,
    ਬਣਤਰ connection_info *connectinfo, ਪੂਰਨ flags, ਪੂਰਨ *activep, ਪੂਰਨ ਡੂੰਘਾਈ)
{
	ਪੂਰਨ linenum, bad_options = 0;
	ਅੱਖਰ *cp, *obuf, *cbuf;

	ਜੇ (ਡੂੰਘਾਈ < 0 || ਡੂੰਘਾਈ > SERVCONF_MAX_ਡੂੰਘਾਈ)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	ਜੇ ((obuf = cbuf = sshbuf_dup_string(conf)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	ਜਦੋਂ ((cp = strsep(&cbuf, "\n")) != ਨਿਰਾ) {
		ਜੇ (process_server_config_ਸਤਰ_ਡੂੰਘਾਈ(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    ਡੂੰਘਾਈ, includes) != 0)
			bad_options++;
	}
	ਮੁਕਤ(obuf);
	ਜੇ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

ਖਾਲੀ
parse_server_config(ServerOptions *options, ਅਚਲ ਅੱਖਰ *filename,
    ਬਣਤਰ sshbuf *conf, ਬਣਤਰ include_list *includes,
    ਬਣਤਰ connection_info *connectinfo, ਪੂਰਨ reexec)
{
	ਪੂਰਨ ਸਰਗਰਮ = connectinfo ? 0 : 1;
	parse_server_config_ਡੂੰਘਾਈ(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_ਮੇਲ_ONLY : 0), &ਸਰਗਰਮ, 0);
	ਜੇ (!reexec)
		process_queued_listen_addrs(options);
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
fmt_multistate_int(ਪੂਰਨ val, ਅਚਲ ਬਣਤਰ multistate *m)
{
	u_int i;

	ਲਈ (i = 0; m[i].ਕੁੰਜੀ != ਨਿਰਾ; i++) {
		ਜੇ (m[i].ਮੁੱਲ == val)
			ਵਾਪਸ m[i].ਕੁੰਜੀ;
	}
	ਵਾਪਸ "UNKNOWN";
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
fmt_intarg(ServerOpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਜੇ (val == -1)
		ਵਾਪਸ "unset";
	ਚੋਣ (ਕੋਡ) {
	ਹਾਲਤ s_ਪਤਾ_Family:
		ਵਾਪਸ fmt_multistate_int(val, multistate_addressfamily);
	ਹਾਲਤ s_Permit_ਜੜ੍ਹ_Login:
		ਵਾਪਸ fmt_multistate_int(val, multistate_permitrootlogin);
	ਹਾਲਤ sGatewayPorts:
		ਵਾਪਸ fmt_multistate_int(val, multistate_gatewayports);
	ਹਾਲਤ sCompression:
		ਵਾਪਸ fmt_multistate_int(val, multistate_compression);
	ਹਾਲਤ sAllowTcpForwarding:
		ਵਾਪਸ fmt_multistate_int(val, multistate_tcpfwd);
	ਹਾਲਤ s_Allow_ਧਾਰਾ_Local_Forwarding:
		ਵਾਪਸ fmt_multistate_int(val, multistate_tcpfwd);
	ਹਾਲਤ sIgnoreRhosts:
		ਵਾਪਸ fmt_multistate_int(val, multistate_ignore_rhosts);
	ਹਾਲਤ sTCPKeepAlive:
		ਵਾਪਸ fmt_multistate_int(val, multistate_keepalives);
	ਹਾਲਤ sWarnWeakCrypto:
		ਵਾਪਸ fmt_multistate_int(val, multistate_warnweakcrypto);
	ਹਾਲਤ sFingerprintHash:
		ਵਾਪਸ ssh_digest_alg_name(val);
	ਮੂਲ:
		ਚੋਣ (val) {
		ਹਾਲਤ 0:
			ਵਾਪਸ "no";
		ਹਾਲਤ 1:
			ਵਾਪਸ "yes";
		ਮੂਲ:
			ਵਾਪਸ "UNKNOWN";
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_int(ServerOpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਜੇ (ਕੋਡ == s_ਅਣਵਰਤਿਆ_Connection_Timeout && val == 0) {
		ਲਿਖੋ("%s none\n", lookup_opcode_name(ਕੋਡ));
		ਵਾਪਸ;
	}
	ਲਿਖੋ("%s %d\n", lookup_opcode_name(ਕੋਡ), val);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_oct(ServerOpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਲਿਖੋ("%s 0%o\n", lookup_opcode_name(ਕੋਡ), val);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_fmtint(ServerOpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਲਿਖੋ("%s %s\n", lookup_opcode_name(ਕੋਡ), fmt_intarg(ਕੋਡ, val));
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_string(ServerOpCodes ਕੋਡ, ਅਚਲ ਅੱਖਰ *val)
{
	ਲਿਖੋ("%s %s\n", lookup_opcode_name(ਕੋਡ),
	    val == ਨਿਰਾ ? "none" : val);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_strarray(ServerOpCodes ਕੋਡ, u_int ਗਿਣਤੀ_2, ਅੱਖਰ **vals)
{
	u_int i;

	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++)
		ਲਿਖੋ("%s %s\n", lookup_opcode_name(ਕੋਡ), vals[i]);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_strarray_oneline(ServerOpCodes ਕੋਡ, u_int ਗਿਣਤੀ_2, ਅੱਖਰ **vals)
{
	u_int i;

	ਚੋਣ (ਕੋਡ) {
	ਹਾਲਤ sAuthenticationMethods:
	ਹਾਲਤ sChannelTimeout:
		ਰੋਕੋ;
	ਮੂਲ:
		ਜੇ (ਗਿਣਤੀ_2 <= 0)
			ਵਾਪਸ;
		ਰੋਕੋ;
	}

	ਲਿਖੋ("%s", lookup_opcode_name(ਕੋਡ));
	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++)
		ਲਿਖੋ(" %s",  vals[i]);
	ਜੇ (ਕੋਡ == sAuthenticationMethods && ਗਿਣਤੀ_2 == 0)
		ਲਿਖੋ(" any");
	ਨਹੀਂਤਾਂ ਜੇ (ਕੋਡ == sChannelTimeout && ਗਿਣਤੀ_2 == 0)
		ਲਿਖੋ(" none");
	ਲਿਖੋ("\n");
}

ਸਥਿਰ ਅੱਖਰ *
format_listen_addrs(ਬਣਤਰ listenaddr *la)
{
	ਪੂਰਨ r;
	ਬਣਤਰ addrinfo *ai;
	ਅੱਖਰ addr[NI_MAXHOST], ਪੋਰਟ[NI_MAXSERV];
	ਅੱਖਰ *laddr1 = xstrdup(""), *laddr2 = ਨਿਰਾ;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	ਲਈ (ai = la->addrs; ai; ai = ai->ai_next) {
		ਜੇ ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    ਆਕਾਰ(addr), ਪੋਰਟ, ਆਕਾਰ(ਪੋਰਟ),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			ਜਾਰੀ;
		}
		laddr2 = laddr1;
		ਜੇ (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, ਪੋਰਟ,
			    la->rdomain == ਨਿਰਾ ? "" : " rdomain ",
			    la->rdomain == ਨਿਰਾ ? "" : la->rdomain,
			    laddr2);
		} ਨਹੀਂਤਾਂ {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, ਪੋਰਟ,
			    la->rdomain == ਨਿਰਾ ? "" : " rdomain ",
			    la->rdomain == ਨਿਰਾ ? "" : la->rdomain,
			    laddr2);
		}
		ਮੁਕਤ(laddr2);
	}
	ਵਾਪਸ laddr1;
}

ਖਾਲੀ
dump_config(ServerOptions *o)
{
	ਅੱਖਰ *s;
	u_int i;

	/* these are usually at the top of the config */
	ਲਈ (i = 0; i < o->ਅੰਕ_ports; i++)
		ਲਿਖੋ("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_ਪਤਾ_Family, o->ਪਤਾ_family);

	ਲਈ (i = 0; i < o->ਅੰਕ_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		ਲਿਖੋ("%s", s);
		ਮੁਕਤ(s);
	}

	/* integer arguments */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#ਜੇ_ਅੰਤ
	dump_cfg_int(s_Login_Grace_ਸਮਾਂ, o->login_grace_ਸਮਾਂ);
	dump_cfg_int(s_X11_Display_ਵਿੱਥ, o->x11_display_ਵਿੱਥ);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_ਗਿਣਤੀ_Max, o->client_alive_ਗਿਣਤੀ_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_ਮਾਪ);
	dump_cfg_oct(s_ਧਾਰਾ_Local_Bind_ਨਕਾਬ, o->fwd_opts.streamlocal_bind_ਨਕਾਬ);
	dump_cfg_int(s_ਅਣਵਰਤਿਆ_Connection_Timeout, o->ਅਣਵਰਤਿਆ_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_ਜੜ੍ਹ_Login, o->permit_ਜੜ੍ਹ_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_ਗਿਆਤ_Hosts, o->ignore_user_ਗਿਆਤ_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_ਵਰਤਦਾ_Name_From_Packet_Only,
	    o->hostbased_ਵਰਤਦਾ_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#ਜੇ_ਅੰਤ
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_ਆਖਰੀ_Log, o->print_lastlog);
#ਜੇ_ਅੰਤ
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_ਖਾਲੀ_ਥਾਵਾਂ_Passwords, o->permit_ਖਾਲੀ_ਥਾਵਾਂ_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_ਧਾਰਾ_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_ਧਾਰਾ_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_ਕੁੰਜੀਆਂ);
	dump_cfg_string(s_Security_ਕੁੰਜੀ_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_ਸੰਸਕਰਣ_Addendum, *o->ਸੰਸਕਰਣ_addendum == '\0'
	    ? "none" : o->ਸੰਸਕਰਣ_addendum);
	dump_cfg_string(s_Authorized_ਕੁੰਜੀਆਂ_Command, o->authorized_ਕੁੰਜੀਆਂ_command);
	dump_cfg_string(s_Authorized_ਕੁੰਜੀਆਂ_Command_User, o->authorized_ਕੁੰਜੀਆਂ_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_ਕੁੰਜੀ_Agent, o->host_ਕੁੰਜੀ_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_ਕੁੰਜੀ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#ਜੇ defined(__OpenBSD__) || defined(HAVE_SYS_ਸੈੱਟ_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#ਜੇ_ਅੰਤ
	dump_cfg_string(s_Sshd_Session_ਰਸਤਾ, o->sshd_session_ਰਸਤਾ);
	dump_cfg_string(s_Sshd_Auth_ਰਸਤਾ, o->sshd_auth_ਰਸਤਾ);
	dump_cfg_string(s_ਪ੍ਰਤੀ_ਸਰੋਤ_Penalty_Exempt_List, o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_ਰਸਤਾ, o->agent_socket_ਰਸਤਾ);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_ਕੁੰਜੀਆਂ_File, o->ਅੰਕ_authkeys_files,
	    o->authorized_ਕੁੰਜੀਆਂ_files);
	dump_cfg_strarray_oneline(s_Revoked_ਕੁੰਜੀਆਂ, o->ਅੰਕ_revoked_ਕੁੰਜੀਆਂ_files,
	    o->revoked_ਕੁੰਜੀਆਂ_files);
	dump_cfg_strarray(s_Host_ਕੁੰਜੀ, o->ਅੰਕ_host_ਕੁੰਜੀ_files, o->host_ਕੁੰਜੀ_files);
	dump_cfg_strarray(sHostCertificate, o->ਅੰਕ_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->ਅੰਕ_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->ਅੰਕ_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->ਅੰਕ_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->ਅੰਕ_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->ਅੰਕ_accept_env, o->accept_env);
	dump_cfg_strarray(s_ਸੈੱਟ_Env, o->ਅੰਕ_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->ਅੰਕ_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->ਅੰਕ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->ਅੰਕ_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	ਲਈ (i = 0; i < o->ਅੰਕ_subsystems; i++)
		ਲਿਖੋ("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_ਦਲੀਲਾਂ[i]);

	ਲਿਖੋ("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_ਦਰ, o->max_startups);
	ਲਿਖੋ("PerSourceMaxStartups ");
	ਜੇ (o->ਪ੍ਰਤੀ_ਸਰੋਤ_max_startups == ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਲਿਖੋ("none\n");
	ਨਹੀਂਤਾਂ
		ਲਿਖੋ("%d\n", o->ਪ੍ਰਤੀ_ਸਰੋਤ_max_startups);
	ਲਿਖੋ("PerSourceNetBlockSize %d:%d\n", o->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv4,
	    o->ਪ੍ਰਤੀ_ਸਰੋਤ_masklen_ipv6);

	s = ਨਿਰਾ;
	ਲਈ (i = 0; tunmode_desc[i].val != -1; i++) {
		ਜੇ (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].ਪਾਠ;
			ਰੋਕੋ;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	ਲਿਖੋ("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	ਲਿਖੋ("%s\n", iptos2str(o->ip_qos_bulk));

	ਲਿਖੋ("RekeyLimit %llu %d\n", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)o->rekey_ਹੱਦਬੰਦੀ,
	    o->rekey_interval);

	ਲਿਖੋ("PermitOpen");
	ਜੇ (o->ਅੰਕ_permitted_opens == 0)
		ਲਿਖੋ(" any");
	ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; i < o->ਅੰਕ_permitted_opens; i++)
			ਲਿਖੋ(" %s", o->permitted_opens[i]);
	}
	ਲਿਖੋ("\n");
	ਲਿਖੋ("PermitListen");
	ਜੇ (o->ਅੰਕ_permitted_listens == 0)
		ਲਿਖੋ(" any");
	ਨਹੀਂਤਾਂ {
		ਲਈ (i = 0; i < o->ਅੰਕ_permitted_listens; i++)
			ਲਿਖੋ(" %s", o->permitted_listens[i]);
	}
	ਲਿਖੋ("\n");

	ਜੇ (o->permit_user_env_allowlist == ਨਿਰਾ) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	ਲਿਖੋ("PubkeyAuthOptions");
	ਜੇ (o->pubkey_auth_options == 0)
		ਲਿਖੋ(" none");
	ਜੇ (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		ਲਿਖੋ(" touch-required");
	ਜੇ (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		ਲਿਖੋ(" verify-required");
	ਜੇ (o->max_pubkey_ok != -1)
		ਲਿਖੋ(" max-pk-ok:%d", o->max_pubkey_ok);
	ਲਿਖੋ("\n");

	ਜੇ (o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.enabled) {
		ਲਿਖੋ("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_crash,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_authfail,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_noauth,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_invaliduser,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_grace,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_refuseconnection,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_max,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.penalty_min,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources4,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.max_sources6,
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_ਬਹੁਲਕ ==
		    ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->ਪ੍ਰਤੀ_ਸਰੋਤ_penalty.ਉਛਾਲ_mode6 ==
		    ਪ੍ਰਤੀ_ਸਰੋਤ_PENALTY_ਉਛਾਲ_DENY_ALL ?
		    "deny-all" : "permissive");
	} ਨਹੀਂਤਾਂ
		ਲਿਖੋ("PerSourcePenalties no\n");
}
