/* $OpenBSD: ssh.c,v 1.642 2026/09/23 21:42:39 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Ssh client program.  This program can be used to log into a remote machine.
 * The software supports strong authentication, encryption, and forwarding
 * of X11, TCP/IP, and authentication connections.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
 * Copyright (c) 2000, 2001, 2002, 2003 Markus Friedl.  All rights reserved.
 *
 * Modified to work with SSLeay by Niels Provos <provos@citi.umich.edu>
 * in Canada (German citizen).
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/utsname.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <locale.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "clientloop.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshconnect.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"
#ਜੇ_ਅੰਤ

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
ਸਥਿਰ ਅੱਖਰ **saved_av;
#ਜੇ_ਅੰਤ

/* Flag indicating whether debug mode is on.  May be set on the command line. */
ਪੂਰਨ debug_flag = 0;

/* Flag indicating whether a tty should be requested */
ਪੂਰਨ tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
ਸਥਿਰ ਪੂਰਨ need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
ਸਥਿਰ ਪੂਰਨ ostdin_null_flag, osession_type, otty_flag, orequest_tty;
ਸਥਿਰ ਪੂਰਨ ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
ਅੱਖਰ *config = ਨਿਰਾ;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ਅੱਖਰ *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
ਅੱਖਰ *forward_agent_sock_ਰਸਤਾ = ਨਿਰਾ;

/* socket address the host resolves to */
ਬਣਤਰ sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_ਅੰਕੜੇ;

/* command to be executed */
ਬਣਤਰ sshbuf *command;

/* # of replies received for global requests */
ਸਥਿਰ ਪੂਰਨ forward_confirms_pending = -1;

/* mux.c */
ਬਾਹਰੀ ਪੂਰਨ muxserver_sock;
ਬਾਹਰੀ u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	fprintf(stderr,
"usage: ssh [-46AaCfGgKkMNnqsTtVvXxYyZ] [-B bind_interface] [-b bind_address]\n"
"           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n"
"           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n"
"           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n"
"           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n"
"           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n"
"           destination [command [argument ...]]\n"
"       ssh [-Q query_option]\n"
	);
	ਬਾਹਰ_ਨਿਕਲੋ(255);
}

ਸਥਿਰ ਪੂਰਨ ssh_session2(ਬਣਤਰ ssh *, ਅਚਲ ਬਣਤਰ ssh_conn_info *);
ਸਥਿਰ ਖਾਲੀ ਲੱਦੋ_ਜਨਤਕ_ਪਛਾਣ_ਤੱਤ_files(ਅਚਲ ਬਣਤਰ ssh_conn_info *);
ਸਥਿਰ ਖਾਲੀ main_sigchld_handler(ਪੂਰਨ);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
ਸਥਿਰ ਖਾਲੀ
tilde_expand_paths(ਅੱਖਰ **paths, u_int ਅੰਕ_paths)
{
	u_int i;
	ਅੱਖਰ *cp;

	ਲਈ (i = 0; i < ਅੰਕ_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		ਮੁਕਤ(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
ਸਥਿਰ ਅੱਖਰ *
default_client_percent_expand(ਅਚਲ ਅੱਖਰ *str,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਵਾਪਸ percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ(cinfo),
	    (ਅੱਖਰ *)ਨਿਰਾ);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
ਸਥਿਰ ਅੱਖਰ *
default_client_percent_dollar_expand(ਅਚਲ ਅੱਖਰ *str,
    ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਅੱਖਰ *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ(cinfo),
	    (ਅੱਖਰ *)ਨਿਰਾ);
	ਜੇ (ret == ਨਿਰਾ)
		fatal("invalid environment variable expansion");
	ਵਾਪਸ ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ਸਥਿਰ ਬਣਤਰ addrinfo *
resolve_host(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ਪੋਰਟ, ਪੂਰਨ logerr, ਅੱਖਰ *cname, ਮਾਪ_t clen)
{
	ਅੱਖਰ strport[NI_MAXSERV];
	ਅਚਲ ਅੱਖਰ *errstr = ਨਿਰਾ;
	ਬਣਤਰ addrinfo hints, *res;
	ਪੂਰਨ gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	ਜੇ (ਪੋਰਟ <= 0)
		ਪੋਰਟ = default_ssh_ਪੋਰਟ();
	ਜੇ (cname != ਨਿਰਾ)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, ਪੋਰਟ);

	snprintf(strport, ਆਕਾਰ strport, "%d", ਪੋਰਟ);
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = options.ਪਤਾ_family == -1 ?
	    AF_UNSPEC : options.ਪਤਾ_family;
	hints.ai_socktype = SOCK_STREAM;
	ਜੇ (cname != ਨਿਰਾ)
		hints.ai_flags = AI_CANONNAME;
	ਜੇ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		ਜੇ (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (cname != ਨਿਰਾ && res->ai_canonname != ਨਿਰਾ) {
		ਜੇ (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} ਨਹੀਂਤਾਂ ਜੇ (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			ਜੇ (clen > 0)
				*cname = '\0';
		}
	}
	ਵਾਪਸ res;
}

/* Returns non-zero if name can only be an address and not a hostname */
ਸਥਿਰ ਪੂਰਨ
is_addr_fast(ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ (strchr(name, '%') != ਨਿਰਾ || strchr(name, ':') != ਨਿਰਾ ||
	    strspn(name, "0123456789.") == ਲੜੀ_ਲੰਬਾਈ(name));
}

/* Returns non-zero if name represents a valid, single address */
ਸਥਿਰ ਪੂਰਨ
is_addr(ਅਚਲ ਅੱਖਰ *name)
{
	ਅੱਖਰ strport[NI_MAXSERV];
	ਬਣਤਰ addrinfo hints, *res;

	ਜੇ (is_addr_fast(name))
		ਵਾਪਸ 1;

	snprintf(strport, ਆਕਾਰ strport, "%u", default_ssh_ਪੋਰਟ());
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = options.ਪਤਾ_family == -1 ?
	    AF_UNSPEC : options.ਪਤਾ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ਜੇ (getaddrinfo(name, strport, &hints, &res) != 0)
		ਵਾਪਸ 0;
	ਜੇ (res == ਨਿਰਾ || res->ai_next != ਨਿਰਾ) {
		freeaddrinfo(res);
		ਵਾਪਸ 0;
	}
	freeaddrinfo(res);
	ਵਾਪਸ 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ਸਥਿਰ ਬਣਤਰ addrinfo *
resolve_addr(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ ਪੋਰਟ, ਅੱਖਰ *caddr, ਮਾਪ_t clen)
{
	ਅੱਖਰ addr[NI_MAXHOST], strport[NI_MAXSERV];
	ਬਣਤਰ addrinfo hints, *res;
	ਪੂਰਨ gaierr;

	ਜੇ (ਪੋਰਟ <= 0)
		ਪੋਰਟ = default_ssh_ਪੋਰਟ();
	snprintf(strport, ਆਕਾਰ strport, "%u", ਪੋਰਟ);
	memset(&hints, 0, ਆਕਾਰ(hints));
	hints.ai_family = options.ਪਤਾ_family == -1 ?
	    AF_UNSPEC : options.ਪਤਾ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ਜੇ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (res == ਨਿਰਾ) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (res->ai_next != ਨਿਰਾ) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		ਜਾਓ fail;
	}
	ਜੇ ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, ਆਕਾਰ(addr), ਨਿਰਾ, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		ਜਾਓ fail;
	}
	ਜੇ (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		ਜੇ (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
ਸਥਿਰ ਪੂਰਨ
check_follow_cname(ਪੂਰਨ direct, ਅੱਖਰ **namep, ਅਚਲ ਅੱਖਰ *cname)
{
	ਪੂਰਨ i;
	ਬਣਤਰ allowed_cname *ਨਿਯਮ;

	ਜੇ (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		ਵਾਪਸ 0;
	ਜੇ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ਵਾਪਸ 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	ਜੇ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ਵਾਪਸ 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	ਲਈ (i = 0; i < options.ਅੰਕ_permitted_cnames; i++) {
		ਨਿਯਮ = options.permitted_cnames + i;
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(*namep, ਨਿਯਮ->ਸਰੋਤ_list, 1) != 1 ||
		    ਮੇਲ_ਨਮੂਨਾ_list(cname, ਨਿਯਮ->ਨਿਸ਼ਾਨਾ_list, 1) != 1)
			ਜਾਰੀ;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		ਮੁਕਤ(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
ਸਥਿਰ ਬਣਤਰ addrinfo *
resolve_canonicalize(ਅੱਖਰ **hostp, ਪੂਰਨ ਪੋਰਟ)
{
	ਪੂਰਨ i, direct, ndots;
	ਅੱਖਰ *cp, *fullhost, newname[NI_MAXHOST];
	ਬਣਤਰ addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	ਜੇ ((addrs = resolve_addr(*hostp, ਪੋਰਟ,
	    newname, ਆਕਾਰ(newname))) != ਨਿਰਾ) {
		debug2_f("hostname %.100s is address", *hostp);
		ਜੇ (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			ਮੁਕਤ(*hostp);
			*hostp = xstrdup(newname);
		}
		ਵਾਪਸ addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	ਜੇ (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਜੇ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ਵਾਪਸ ਨਿਰਾ;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	ਜੇ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ਵਾਪਸ ਨਿਰਾ;

	/* If domain name is anchored, then resolve it now */
	ਜੇ ((*hostp)[ਲੜੀ_ਲੰਬਾਈ(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		ਜੇ ((addrs = resolve_host(fullhost, ਪੋਰਟ, 0,
		    newname, ਆਕਾਰ(newname))) != ਨਿਰਾ)
			ਜਾਓ ਮਿਲਿਆ;
		ਮੁਕਤ(fullhost);
		ਜਾਓ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	ਲਈ (cp = *hostp; *cp != '\0'; cp++) {
		ਜੇ (*cp == '.')
			ndots++;
	}
	ਜੇ (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		ਵਾਪਸ ਨਿਰਾ;
	}
	/* Attempt each supplied suffix */
	ਲਈ (i = 0; i < options.ਅੰਕ_canonical_domains; i++) {
		ਜੇ (strcasecmp(options.canonical_domains[i], "none") == 0)
			ਰੋਕੋ;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		ਜੇ ((addrs = resolve_host(fullhost, ਪੋਰਟ, 0,
		    newname, ਆਕਾਰ(newname))) == ਨਿਰਾ) {
			ਮੁਕਤ(fullhost);
			ਜਾਰੀ;
		}
 ਮਿਲਿਆ:
		/* Remove trailing '.' */
		fullhost[ਲੜੀ_ਲੰਬਾਈ(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		ਜੇ (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		ਮੁਕਤ(*hostp);
		*hostp = fullhost;
		ਵਾਪਸ addrs;
	}
 notfound:
	ਜੇ (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
ਸਥਿਰ ਖਾਲੀ
check_ਲੱਦੋ(ਪੂਰਨ r, ਬਣਤਰ sshkey **k, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ_2)
{
	ਅੱਖਰ *fp;

	ਚੋਣ (r) {
	ਹਾਲਤ 0:
		ਜੇ (k == ਨਿਰਾ || *k == ਨਿਰਾ)
			ਵਾਪਸ;
		/* Check RSA keys size and discard if undersized */
		ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(*k,
		    options.required_rsa_ਮਾਪ)) != 0) {
			error_r(r, "load %s \"%s\"", ਸੁਨੇਹਾ_2, ਰਸਤਾ);
			ਮੁਕਤ(*k);
			*k = ਨਿਰਾ;
			ਰੋਕੋ;
		}
		ਜੇ ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ਨਿਰਾ) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), ਸੁਨੇਹਾ_2, ਰਸਤਾ);
		}
		debug("loaded %s from %s: %s %s", ਸੁਨੇਹਾ_2, ਰਸਤਾ,
		    sshkey_type(*k), fp);
		ਮੁਕਤ(fp);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR:
	ਹਾਲਤ SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", ਸੁਨੇਹਾ_2, ਰਸਤਾ);
	ਹਾਲਤ SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		ਜੇ (errno == ENOENT)
			ਰੋਕੋ;
		/* FALLTHROUGH */
	ਮੂਲ:
		error_r(r, "load %s \"%s\"", ਸੁਨੇਹਾ_2, ਰਸਤਾ);
		ਰੋਕੋ;
	}
	ਜੇ (k != ਨਿਰਾ && *k == ਨਿਰਾ)
		debug("no %s loaded from %s", ਸੁਨੇਹਾ_2, ਰਸਤਾ);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
ਸਥਿਰ ਖਾਲੀ
process_config_files(ਅਚਲ ਅੱਖਰ *host_name, ਬਣਤਰ passwd *pw,
    ਪੂਰਨ final_pass, ਪੂਰਨ *want_final_pass)
{
	ਅੱਖਰ *cmd, buf[PATH_MAX];
	ਪੂਰਨ r;

	ਜੇ ((cmd = sshbuf_dup_string(command)) == ਨਿਰਾ)
		fatal_f("sshbuf_dup_string failed");
	ਜੇ (config != ਨਿਰਾ) {
		ਜੇ (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} ਨਹੀਂਤਾਂ {
		r = snprintf(buf, ਆਕਾਰ buf, "%s/%s", pw->pw_dir,
		    ਰਸਤਾ_SSH_USER_CONFFILE);
		ਜੇ (r > 0 && (ਮਾਪ_t)r < ਆਕਾਰ(buf))
			(ਖਾਲੀ)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(ਖਾਲੀ)read_config_file(ਰਸਤਾ_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	ਮੁਕਤ(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
ਸਥਿਰ ਖਾਲੀ
ਸੈੱਟ_addrinfo_ਪੋਰਟ(ਬਣਤਰ addrinfo *addrs, ਪੂਰਨ ਪੋਰਟ)
{
	ਬਣਤਰ addrinfo *addr;

	ਲਈ (addr = addrs; addr != ਨਿਰਾ; addr = addr->ai_next) {
		ਚੋਣ (addr->ai_family) {
		ਹਾਲਤ AF_INET:
			((ਬਣਤਰ sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(ਪੋਰਟ);
			ਰੋਕੋ;
		ਹਾਲਤ AF_INET6:
			((ਬਣਤਰ sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(ਪੋਰਟ);
			ਰੋਕੋ;
		}
	}
}

/*
 * Main program for the ssh client.
 */
ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ ac, ਅੱਖਰ **av)
{
	ਬਣਤਰ ssh *ssh = ਨਿਰਾ;
	ਪੂਰਨ i, r, opt, exit_ਸਥਿਤੀ, use_syslog, direct, timeout_ms;
	ਪੂਰਨ was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	ਪੂਰਨ user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	ਅੱਖਰ *p, *cp, *ਸਤਰ, *argv0, *logfile, *ਦਲੀਲਾਂ;
	ਅੱਖਰ cname[NI_MAXHOST], thishost[NI_MAXHOST];
	ਬਣਤਰ stat st;
	ਬਣਤਰ passwd *pw;
	ਬਾਹਰੀ ਪੂਰਨ optind, optreset;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਣਤਰ Forward fwd;
	ਬਣਤਰ addrinfo *addrs = ਨਿਰਾ;
	ਮਾਪ_t n, len;
	u_int j;
	ਬਣਤਰ utsname utsname;
	ਬਣਤਰ ssh_conn_info *cinfo = ਨਿਰਾ;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, ਆਕਾਰ(*saved_av));
	ਲਈ (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ਨਿਰਾ;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#ਜੇ_ਅੰਤ

	ਬੀਜ_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	ਜੇ (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		ਬਾਹਰ_ਨਿਕਲੋ(255);
	}
	/* Take a copy of the returned structure. */
	pw = pwcopy(pw);

	/*
	 * Set our umask to something reasonable, as some files are created
	 * with the default umask.  This will make them world-readable but
	 * writable only by the owner, which is ok for all files for which we
	 * don't set the modes explicitly.
	 */
	umask(022 | umask(077));

	msetlocale();

	/*
	 * Initialize option structure to indicate that no values have been
	 * set.
	 */
	initialize_options(&options);

	/*
	 * Prepare main ssh transport/connection structures
	 */
	ਜੇ ((ssh = ssh_alloc_session_state()) == ਨਿਰਾ)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	ਦਲੀਲਾਂ = argv_assemble(ac, av); /* logged later */
	host = ਨਿਰਾ;
	use_syslog = 0;
	logfile = ਨਿਰਾ;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	ਜਦੋਂ ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		ਚੋਣ (opt) {
		ਹਾਲਤ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ਰੋਕੋ;
		ਹਾਲਤ '2':
			/* Ignored */
			ਰੋਕੋ;
		ਹਾਲਤ '4':
			options.ਪਤਾ_family = AF_INET;
			ਰੋਕੋ;
		ਹਾਲਤ '6':
			options.ਪਤਾ_family = AF_INET6;
			ਰੋਕੋ;
		ਹਾਲਤ 'n':
			options.stdin_null = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'x':
			options.forward_x11 = 0;
			ਰੋਕੋ;
		ਹਾਲਤ 'X':
			options.forward_x11 = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'y':
			use_syslog = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'E':
			logfile = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'G':
			config_test = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'Z':
			dump_pubkeys = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'g':
			options.fwd_opts.gateway_ports = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			ਜੇ (options.stdio_forward_host != ਨਿਰਾ)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			ਨਹੀਂਤਾਂ ਜੇ (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			ਜੇ (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			ਨਹੀਂਤਾਂ
				fatal("Invalid multiplex command.");
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			ਜੇ (options.ਟੈਗ == ਨਿਰਾ)
				options.ਟੈਗ = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'Q':
			cp = ਨਿਰਾ;
			ਜੇ (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = ਲੜੀ_ਲੰਬਾਈ(cp);
				ਲਈ (n = 0; n < len; n++)
					ਜੇ (cp[n] == ',')
						cp[n] = '\n';
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			ਜੇ (cp == ਨਿਰਾ)
				fatal("Unsupported query \"%s\"", optarg);
			ਲਿਖੋ("%s\n", cp);
			ਮੁਕਤ(cp);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
			ਰੋਕੋ;
		ਹਾਲਤ 'a':
			options.forward_agent = 0;
			ਰੋਕੋ;
		ਹਾਲਤ 'A':
			options.forward_agent = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'k':
			options.gss_deleg_creds = 0;
			ਰੋਕੋ;
		ਹਾਲਤ 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'i':
			p = tilde_expand_filename(optarg, getuid());
			ਜੇ (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			ਨਹੀਂਤਾਂ
				ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(&options, ਨਿਰਾ, p, 1);
			ਮੁਕਤ(p);
			ਰੋਕੋ;
		ਹਾਲਤ 'I':
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
			ਮੁਕਤ(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#ਨਹੀਂਤਾਂ
			fprintf(stderr, "no support for PKCS#11.\n");
#ਜੇ_ਅੰਤ
			ਰੋਕੋ;
		ਹਾਲਤ 'J':
			ਜੇ (options.jump_host != ਨਿਰਾ) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			ਜੇ (options.proxy_command != ਨਿਰਾ)
				fatal("Cannot specify -J with ProxyCommand");
			ਜੇ (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			ਜੇ (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			ਨਹੀਂਤਾਂ
				options.request_tty = REQUEST_TTY_YES;
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			ਜੇ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ਨਹੀਂਤਾਂ {
				ਜੇ (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_ਸੰਸਕਰਣ);
			ਬਾਹਰ_ਨਿਕਲੋ(0);
			ਰੋਕੋ;
		ਹਾਲਤ 'w':
			ਜੇ (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			ਜੇ (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'W':
			ਜੇ (options.stdio_forward_host != ਨਿਰਾ)
				fatal("stdio forward already specified");
			ਜੇ (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			ਜੇ (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL ?
				    fwd.listen_ਰਸਤਾ : fwd.listen_host;
				options.stdio_forward_ਪੋਰਟ = fwd.listen_ਪੋਰਟ;
				ਮੁਕਤ(fwd.connect_host);
			} ਨਹੀਂਤਾਂ {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ਰੋਕੋ;
		ਹਾਲਤ 'e':
			ਜੇ (ਲੜੀ_ਲੰਬਾਈ(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਲੰਬਾਈ(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			ਨਹੀਂਤਾਂ {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'c':
			ਜੇ (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਮੁਕਤ(options.ciphers);
			options.ciphers = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'm':
			ਜੇ (mac_valid(optarg)) {
				ਮੁਕਤ(options.macs);
				options.macs = xstrdup(optarg);
			} ਨਹੀਂਤਾਂ {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'M':
			ਜੇ (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			ਨਹੀਂਤਾਂ
				options.control_master = SSHCTL_MASTER_YES;
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			ਜੇ (options.ਪੋਰਟ == -1) {
				options.ਪੋਰਟ = a2port(optarg);
				ਜੇ (options.ਪੋਰਟ <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					ਬਾਹਰ_ਨਿਕਲੋ(255);
				}
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			ਜੇ (options.user == ਨਿਰਾ) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			ਰੋਕੋ;

		ਹਾਲਤ 'L':
			ਜੇ (parse_forward(&fwd, optarg, 0, 0))
				ਜੋੜੋ_local_forward(&options, &fwd);
			ਨਹੀਂਤਾਂ {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਰੋਕੋ;

		ਹਾਲਤ 'R':
			ਜੇ (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				ਜੋੜੋ_remote_forward(&options, &fwd);
			} ਨਹੀਂਤਾਂ {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਰੋਕੋ;

		ਹਾਲਤ 'D':
			ਜੇ (parse_forward(&fwd, optarg, 1, 0)) {
				ਜੋੜੋ_local_forward(&options, &fwd);
			} ਨਹੀਂਤਾਂ {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			}
			ਰੋਕੋ;

		ਹਾਲਤ 'C':
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
			options.compression = 1;
#ਨਹੀਂਤਾਂ
			error("Compression not supported, disabling.");
#ਜੇ_ਅੰਤ
			ਰੋਕੋ;
		ਹਾਲਤ 'N':
			ਜੇ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			options.request_tty = REQUEST_TTY_NO;
			ਰੋਕੋ;
		ਹਾਲਤ 'o':
			ਸਤਰ = xstrdup(optarg);
			ਜੇ (process_config_ਸਤਰ(&options, pw,
			    host ? host : "", host ? host : "", "", ਸਤਰ,
			    "command-line", 0, ਨਿਰਾ, SSHCONF_USERCONF) != 0)
				ਬਾਹਰ_ਨਿਕਲੋ(255);
			ਮੁਕਤ(ਸਤਰ);
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			ਜੇ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			ਰੋਕੋ;
		ਹਾਲਤ 'S':
			ਮੁਕਤ(options.control_ਰਸਤਾ);
			options.control_ਰਸਤਾ = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'b':
			options.bind_ਪਤਾ = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'B':
			options.bind_interface = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'F':
			config = optarg;
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
		}
	}

	ਜੇ (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	ਜੇ (ac > 0 && !host) {
		ਪੂਰਨ tport;
		ਅੱਖਰ *tuser;
		ਚੋਣ (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		ਹਾਲਤ -1:
			usage();
			ਰੋਕੋ;
		ਹਾਲਤ 0:
			ਜੇ (options.user == ਨਿਰਾ) {
				options.user = tuser;
				tuser = ਨਿਰਾ;
				user_on_commandline = 1;
			}
			ਮੁਕਤ(tuser);
			ਜੇ (options.ਪੋਰਟ == -1 && tport != -1)
				options.ਪੋਰਟ = tport;
			ਰੋਕੋ;
		ਮੂਲ:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			ਜੇ (cp != ਨਿਰਾ) {
				ਜੇ (cp == p)
					usage();
				ਜੇ (options.user == ਨਿਰਾ) {
					options.user = p;
					p = ਨਿਰਾ;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				ਮੁਕਤ(p);
			} ਨਹੀਂਤਾਂ
				host = p;
			ਰੋਕੋ;
		}
		ਜੇ (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			ਜਾਓ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	ਜੇ (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	ਜੇ (options.user != ਨਿਰਾ && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	ਜੇ (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	ਜੇ ((command = sshbuf_new()) == ਨਿਰਾ)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	ਜੇ (!ac) {
		/* No command specified - execute shell on a tty. */
		ਜੇ (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} ਨਹੀਂਤਾਂ {
		/* A command has been specified.  Store it into the buffer. */
		ਲਈ (i = 0; i < ac; i++) {
			ਜੇ ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	ਜੇ (use_syslog && logfile != ਨਿਰਾ)
		fatal("Can't specify both -y and -E");
	ਜੇ (logfile != ਨਿਰਾ)
		log_redirect_stderr_ਮੰਜ਼ਿਲ(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_ਸੈੱਟ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_ਸੈੱਟ ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_ਸੰਸਕਰਣ);
	ਜੇ (uname(&utsname) != 0) {
		memset(&utsname, 0, ਆਕਾਰ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ਆਕਾਰ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.ਸੰਸਕਰਣ, utsname.machine);
	debug3("Started with: %s", ਦਲੀਲਾਂ);
	ਮੁਕਤ(ਦਲੀਲਾਂ);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	ਜੇ (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	ਜੇ (options.hostname != ਨਿਰਾ) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (ਅੱਖਰ *)ਨਿਰਾ);
		ਮੁਕਤ(host);
		host = cp;
		ਮੁਕਤ(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	ਜੇ ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	ਜੇ (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
		addrs = resolve_canonicalize(&host, options.ਪੋਰਟ);

	/*
	 * If CanonicalizePermittedCNAMEs have been specified but
	 * other canonicalization did not happen (by not being requested
	 * or by failing with fallback) then the hostname may still be changed
	 * as a result of CNAME following.
	 *
	 * Try to resolve the bare hostname name using the system resolver's
	 * usual search rules and then apply the CNAME follow rules.
	 *
	 * Skip the lookup if a ProxyCommand is being used unless the user
	 * has specifically requested canonicalisation for this case via
	 * CanonicalizeHostname=always
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	ਜੇ (addrs == ਨਿਰਾ && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		ਜੇ ((addrs = resolve_host(host, options.ਪੋਰਟ,
		    direct, cname, ਆਕਾਰ(cname))) == ਨਿਰਾ) {
			/* Don't fatal proxied host names not in the DNS */
			ਜੇ (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} ਨਹੀਂਤਾਂ
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	ਜੇ (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	ਜੇ (want_final_pass) {
		debug("re-parsing configuration");
		ਮੁਕਤ(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ਨਿਰਾ);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		ਜੇ (addrs != ਨਿਰਾ && options.ਪੋਰਟ > 0)
			ਸੈੱਟ_addrinfo_ਪੋਰਟ(addrs, options.ਪੋਰਟ);
	}

	/* Fill configuration defaults. */
	ਜੇ (fill_default_options(&options) != 0)
		cleanup_exit(255);

	ਜੇ (options.user == ਨਿਰਾ) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	ਜੇ (options.jump_host != ਨਿਰਾ) {
		ਅੱਖਰ ਪੋਰਟ_s[8];
		ਅਚਲ ਅੱਖਰ *jumpuser = options.jump_user, *sshbin = argv0;
		ਪੂਰਨ ਪੋਰਟ = options.ਪੋਰਟ, jumpport = options.jump_ਪੋਰਟ;

		ਜੇ (ਪੋਰਟ <= 0)
			ਪੋਰਟ = default_ssh_ਪੋਰਟ();
		ਜੇ (jumpport <= 0)
			jumpport = default_ssh_ਪੋਰਟ();
		ਜੇ (jumpuser == ਨਿਰਾ)
			jumpuser = options.user;
		ਜੇ (strcmp(options.jump_host, host) == 0 && ਪੋਰਟ == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		ਜੇ (strchr(argv0, '/') != ਨਿਰਾ && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		ਜੇ (options.proxy_command != ਨਿਰਾ &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(ਪੋਰਟ_s, ਆਕਾਰ(ਪੋਰਟ_s), "%d", options.jump_ਪੋਰਟ);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ਨਿਰਾ ? "" : " -l ",
		    options.jump_user == ਨਿਰਾ ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_ਪੋਰਟ <= 0 ? "" : " -p ",
		    options.jump_ਪੋਰਟ <= 0 ? "" : ਪੋਰਟ_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ਨਿਰਾ ? "" : " -J ",
		    options.jump_extra == ਨਿਰਾ ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ਨਿਰਾ ? "" : " -F ",
		    config == ਨਿਰਾ ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	ਜੇ (options.ਪੋਰਟ == 0)
		options.ਪੋਰਟ = default_ssh_ਪੋਰਟ();
	channel_ਸੈੱਟ_af(ssh, options.ਪਤਾ_family);
	ssh_packet_ਸੈੱਟ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	ਜੇ (options.host_ਕੁੰਜੀ_alias != ਨਿਰਾ)
		lowercase(options.host_ਕੁੰਜੀ_alias);
	ਜੇ (options.proxy_command != ਨਿਰਾ &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	ਜੇ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ਜੇ (options.control_persist && options.control_ਰਸਤਾ != ਨਿਰਾ) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (sshbuf_len(command) != 0 ||
		    options.remote_command != ਨਿਰਾ ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	ਜੇ (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	ਜੇ (sshbuf_len(command) != 0 && options.remote_command != ਨਿਰਾ)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	ਜੇ (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ਨਿਰਾ &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	ਲਈ (j = 0; j < options.ਅੰਕ_log_verbose; j++) {
		ਜੇ (strcasecmp(options.log_verbose[j], "none") == 0)
			ਰੋਕੋ;
		log_verbose_ਜੋੜੋ(options.log_verbose[j]);
	}

	ਜੇ (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	ਜੇ (sshbuf_len(command) == 0 && options.remote_command == ਨਿਰਾ)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	ਜੇ (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	ਜੇ ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		ਜੇ (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, ਆਕਾਰ(*cinfo));
	ਜੇ (gethostname(thishost, ਆਕਾਰ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.ਪੋਰਟ);
	xasprintf(&cinfo->uidstr, "%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_ਕੁੰਜੀ_alias ?
	    options.host_ਕੁੰਜੀ_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ਨਿਰਾ ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	ਜੇ (!user_on_commandline && !user_was_default) {
		ਜੇ ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ_NOUSER(cinfo),
		    (ਅੱਖਰ *)ਨਿਰਾ)) == ਨਿਰਾ)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		ਮੁਕਤ(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	ਜੇ ((user_on_commandline || user_expanded) &&
	    !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");

	/* Now User is expanded, store it and calculate hash. */
	cinfo->remuser = xstrdup(options.user);
	cinfo->conn_hash_hex = ssh_connection_hash(cinfo->thishost,
	    cinfo->remhost, cinfo->portstr, cinfo->remuser, cinfo->jmphost);

	/*
	 * Expand tokens in arguments. NB. LocalCommand is expanded later,
	 * after port-forwarding is set up, so it may pick up any local
	 * tunnel interface name allocated.
	 */
	ਜੇ (options.remote_command != ਨਿਰਾ) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		ਮੁਕਤ(cp);
		ਜੇ ((r = sshbuf_put(command, options.remote_command,
		    ਲੜੀ_ਲੰਬਾਈ(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	ਜੇ (options.control_ਰਸਤਾ != ਨਿਰਾ) {
		cp = tilde_expand_filename(options.control_ਰਸਤਾ, getuid());
		ਮੁਕਤ(options.control_ਰਸਤਾ);
		options.control_ਰਸਤਾ = default_client_percent_dollar_expand(cp,
		    cinfo);
		ਮੁਕਤ(cp);
	}

	ਜੇ (options.ਪਛਾਣ_ਤੱਤ_agent != ਨਿਰਾ) {
		p = tilde_expand_filename(options.ਪਛਾਣ_ਤੱਤ_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ਮੁਕਤ(p);
		ਮੁਕਤ(options.ਪਛਾਣ_ਤੱਤ_agent);
		options.ਪਛਾਣ_ਤੱਤ_agent = cp;
	}

	ਲਈ (j = 0; j < options.ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ; j++) {
		p = tilde_expand_filename(options.revoked_host_ਕੁੰਜੀਆਂ[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ਮੁਕਤ(p);
		ਮੁਕਤ(options.revoked_host_ਕੁੰਜੀਆਂ[j]);
		options.revoked_host_ਕੁੰਜੀਆਂ[j] = cp;
	}

	ਜੇ (options.forward_agent_sock_ਰਸਤਾ != ਨਿਰਾ) {
		p = tilde_expand_filename(options.forward_agent_sock_ਰਸਤਾ,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ਮੁਕਤ(p);
		ਮੁਕਤ(options.forward_agent_sock_ਰਸਤਾ);
		options.forward_agent_sock_ਰਸਤਾ = cp;
		ਜੇ (stat(options.forward_agent_sock_ਰਸਤਾ, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_ਰਸਤਾ, strerror(errno));
			ਜੇ (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	ਜੇ (options.ਸੰਸਕਰਣ_addendum != ਨਿਰਾ) {
		cp = default_client_percent_dollar_expand(
		    options.ਸੰਸਕਰਣ_addendum, cinfo);
		ਮੁਕਤ(options.ਸੰਸਕਰਣ_addendum);
		options.ਸੰਸਕਰਣ_addendum = cp;
	}

	ਜੇ (options.ਅੰਕ_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		ਜੇ (options.ਅੰਕ_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ਮੁਕਤ(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ਨਿਰਾ;
		options.ਅੰਕ_system_hostfiles = 0;
	}

	ਜੇ (options.ਅੰਕ_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		ਜੇ (options.ਅੰਕ_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ਮੁਕਤ(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ਨਿਰਾ;
		options.ਅੰਕ_user_hostfiles = 0;
	}
	ਲਈ (j = 0; j < options.ਅੰਕ_user_hostfiles; j++) {
		ਜੇ (options.user_hostfiles[j] == ਨਿਰਾ)
			ਜਾਰੀ;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		ਜੇ (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		ਮੁਕਤ(options.user_hostfiles[j]);
		ਮੁਕਤ(cp);
		options.user_hostfiles[j] = p;
	}

	ਲਈ (j = 0; j < options.ਅੰਕ_setenv; j++) {
		ਅੱਖਰ *name = options.setenv[j], *ਮੁੱਲ;

		ਜੇ (name == ਨਿਰਾ)
			ਜਾਰੀ;
		/* Expand only the value portion, not the variable name. */
		ਜੇ ((ਮੁੱਲ = strchr(name, '=')) == ਨਿਰਾ) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*ਮੁੱਲ++ = '\0';
		cp = default_client_percent_dollar_expand(ਮੁੱਲ, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		ਜੇ (strcmp(ਮੁੱਲ, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, ਮੁੱਲ, cp);
		}
		ਮੁਕਤ(options.setenv[j]);
		ਮੁਕਤ(cp);
		options.setenv[j] = p;
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_local_forwards; i++) {
		ਜੇ (options.local_forwards[i].listen_ਰਸਤਾ != ਨਿਰਾ) {
			cp = options.local_forwards[i].listen_ਰਸਤਾ;
			p = options.local_forwards[i].listen_ਰਸਤਾ =
			    default_client_percent_expand(cp, cinfo);
			ਜੇ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			ਮੁਕਤ(cp);
		}
		ਜੇ (options.local_forwards[i].connect_ਰਸਤਾ != ਨਿਰਾ) {
			cp = options.local_forwards[i].connect_ਰਸਤਾ;
			p = options.local_forwards[i].connect_ਰਸਤਾ =
			    default_client_percent_expand(cp, cinfo);
			ਜੇ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			ਮੁਕਤ(cp);
		}
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_remote_forwards; i++) {
		ਜੇ (options.remote_forwards[i].listen_ਰਸਤਾ != ਨਿਰਾ) {
			cp = options.remote_forwards[i].listen_ਰਸਤਾ;
			p = options.remote_forwards[i].listen_ਰਸਤਾ =
			    default_client_percent_expand(cp, cinfo);
			ਜੇ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			ਮੁਕਤ(cp);
		}
		ਜੇ (options.remote_forwards[i].connect_ਰਸਤਾ != ਨਿਰਾ) {
			cp = options.remote_forwards[i].connect_ਰਸਤਾ;
			p = options.remote_forwards[i].connect_ਰਸਤਾ =
			    default_client_percent_expand(cp, cinfo);
			ਜੇ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			ਮੁਕਤ(cp);
		}
	}

	ਜੇ (config_test) {
		dump_client_config(&options, host);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	ਜੇ (options.sk_provider != ਨਿਰਾ && *options.sk_provider == '$' &&
	    ਲੜੀ_ਲੰਬਾਈ(options.sk_provider) > 1) {
		ਜੇ ((cp = getenv(options.sk_provider + 1)) == ਨਿਰਾ) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			ਮੁਕਤ(options.sk_provider);
			options.sk_provider = ਨਿਰਾ;
		} ਨਹੀਂਤਾਂ {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			ਮੁਕਤ(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	ਜੇ (muxclient_command != 0 && options.control_ਰਸਤਾ == ਨਿਰਾ)
		fatal("No ControlPath specified for \"-O\" command");
	ਜੇ (options.control_ਰਸਤਾ != ਨਿਰਾ) {
		ਪੂਰਨ sock;
		ਜੇ ((sock = muxclient(options.control_ਰਸਤਾ)) >= 0) {
			ਜੇ (ssh_packet_ਸੈੱਟ_connection(ssh, sock, sock) == ਨਿਰਾ)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_ਸੈੱਟ_mux(ssh);
			ਜਾਓ skip_connect;
		}
	}

	/* load options.identity_files */
	ਲੱਦੋ_ਜਨਤਕ_ਪਛਾਣ_ਤੱਤ_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	ਜੇ (options.ਪਛਾਣ_ਤੱਤ_agent &&
	    strcmp(options.ਪਛਾਣ_ਤੱਤ_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		ਜੇ (strcmp(options.ਪਛਾਣ_ਤੱਤ_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} ਨਹੀਂਤਾਂ {
			cp = options.ਪਛਾਣ_ਤੱਤ_agent;
			/* legacy (limited) format */
			ਜੇ (cp[0] == '$' && cp[1] != '{') {
				ਜੇ (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				ਜੇ ((p = getenv(cp + 1)) == ਨਿਰਾ)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				ਨਹੀਂਤਾਂ
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} ਨਹੀਂਤਾਂ {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	ਜੇ (dump_pubkeys) {
		pubkey_dump(ssh);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	ਜੇ (addrs == ਨਿਰਾ && options.proxy_command == ਨਿਰਾ) {
		debug2("resolving \"%s\" port %d", host, options.ਪੋਰਟ);
		ਜੇ ((addrs = resolve_host(host, options.ਪੋਰਟ, 1,
		    cname, ਆਕਾਰ(cname))) == ਨਿਰਾ)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	ਜੇ (options.connection_timeout >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ/1000)
		timeout_ms = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
	ਨਹੀਂਤਾਂ
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	ਲਈ (j = 0; j < options.ਅੰਕ_channel_timeouts; j++) {
		ਦੁੱਗਣਾ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		ਜੇ (parse_ਨਮੂਨਾ_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_ਜੋੜੋ_timeout(ssh, cp, timeout);
		ਮੁਕਤ(cp);
	}
	channel_ਸੈੱਟ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	ਜੇ (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.ਪੋਰਟ, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		ਬਾਹਰ_ਨਿਕਲੋ(255);


	ssh_packet_ਸੈੱਟ_timeout(ssh, options.server_alive_interval,
	    options.server_alive_ਗਿਣਤੀ_max);

	ਜੇ (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_ਅੰਕੜੇ.nkeys = 0;
	sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ = ਨਿਰਾ;
	ਜੇ (options.hostbased_authentication) {
		ਪੂਰਨ loaded = 0;

		sensitive_ਅੰਕੜੇ.nkeys = 10;
		sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ = xcalloc(sensitive_ਅੰਕੜੇ.nkeys,
		    ਆਕਾਰ(*sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ));

		/* XXX check errors? */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ L_PUBKEY(p,o) ਕਰੋ { \
	ਜੇ ((o) >= sensitive_ਅੰਕੜੇ.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_ਲੱਦੋ(sshkey_ਲੱਦੋ_ਜਨਤਕ(p, &(sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[o]), ਨਿਰਾ), \
	    &(sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[o]), p, "hostbased pubkey"); \
	ਜੇ (sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[o] != ਨਿਰਾ) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ਜਦੋਂ (0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ L_CERT(p,o) ਕਰੋ { \
	ਜੇ ((o) >= sensitive_ਅੰਕੜੇ.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_ਲੱਦੋ(sshkey_ਲੱਦੋ_cert(p, &(sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[o])), \
	    &(sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[o]), p, "hostbased cert"); \
	ਜੇ (sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[o] != ਨਿਰਾ) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ਜਦੋਂ (0)

		ਜੇ (options.hostbased_authentication == 1) {
			L_CERT(ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE, 0);
			L_CERT(ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE, 1);
			L_CERT(ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE, 2);
			L_CERT(ਰਸਤਾ_HOST_MLDSA44_ED25519_ਕੁੰਜੀ_FILE, 3);
			L_PUBKEY(ਰਸਤਾ_HOST_ECDSA_ਕੁੰਜੀ_FILE, 4);
			L_PUBKEY(ਰਸਤਾ_HOST_ED25519_ਕੁੰਜੀ_FILE, 5);
			L_PUBKEY(ਰਸਤਾ_HOST_RSA_ਕੁੰਜੀ_FILE, 6);
			L_PUBKEY(ਰਸਤਾ_HOST_MLDSA44_ED25519_ਕੁੰਜੀ_FILE, 7);
			ਜੇ (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	ਜੇ (options.forward_agent && options.forward_agent_sock_ਰਸਤਾ != ਨਿਰਾ) {
		cp = options.forward_agent_sock_ਰਸਤਾ;
		ਜੇ (cp[0] == '$') {
			ਜੇ (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			ਜੇ ((p = getenv(cp + 1)) != ਨਿਰਾ)
				forward_agent_sock_ਰਸਤਾ = xstrdup(p);
			ਨਹੀਂਤਾਂ
				options.forward_agent = 0;
			ਮੁਕਤ(cp);
		} ਨਹੀਂਤਾਂ {
			forward_agent_sock_ਰਸਤਾ = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.ਅੰਕ_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.ਅੰਕ_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_ਅੰਕੜੇ, host, &hostaddr, options.ਪੋਰਟ,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	ਜੇ (sensitive_ਅੰਕੜੇ.nkeys != 0) {
		ਲਈ (i = 0; i < sensitive_ਅੰਕੜੇ.nkeys; i++) {
			ਜੇ (sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[i] != ਨਿਰਾ) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[i]);
				sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
			}
		}
		ਮੁਕਤ(sensitive_ਅੰਕੜੇ.ਕੁੰਜੀਆਂ);
	}
	ਲਈ (i = 0; i < options.ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files; i++) {
		ਮੁਕਤ(options.ਪਛਾਣ_ਤੱਤ_files[i]);
		options.ਪਛਾਣ_ਤੱਤ_files[i] = ਨਿਰਾ;
		ਜੇ (options.ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[i]) {
			sshkey_free(options.ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[i]);
			options.ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[i] = ਨਿਰਾ;
		}
	}
	ਲਈ (i = 0; i < options.ਅੰਕ_certificate_files; i++) {
		ਮੁਕਤ(options.certificate_files[i]);
		options.certificate_files[i] = ਨਿਰਾ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	(ਖਾਲੀ)pkcs11_del_provider(options.pkcs11_provider);
#ਜੇ_ਅੰਤ

 skip_connect:
	ਜੇ (addrs != ਨਿਰਾ)
		freeaddrinfo(addrs);
	exit_ਸਥਿਤੀ = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	ਜੇ (options.control_ਰਸਤਾ != ਨਿਰਾ && muxserver_sock != -1)
		unlink(options.control_ਰਸਤਾ);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	ਵਾਪਸ exit_ਸਥਿਤੀ;
}

ਸਥਿਰ ਖਾਲੀ
control_persist_detach(ਖਾਲੀ)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	ਚੋਣ ((pid = fork())) {
	ਹਾਲਤ -1:
		fatal_f("fork: %s", strerror(errno));
	ਹਾਲਤ 0:
		/* Child: master process continues mainloop */
		ਰੋਕੋ;
	ਮੂਲ:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (ਲੰਮਾ)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(ਖਾਲੀ)muxclient(options.control_ਰਸਤਾ);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	ਜੇ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_ਰਸਤਾ);
}

/* Do fork() after authentication. Used by "ssh -f" */
ਸਥਿਰ ਖਾਲੀ
fork_postauth(ਖਾਲੀ)
{
	ਜੇ (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	ਜੇ (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	ਜੇ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

ਸਥਿਰ ਖਾਲੀ
forwarding_success(ਖਾਲੀ)
{
	ਜੇ (forward_confirms_pending == -1)
		ਵਾਪਸ;
	ਜੇ (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		ਜੇ (options.fork_after_authentication)
			fork_postauth();
	} ਨਹੀਂਤਾਂ {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

ਬਣਤਰ rfwd_confirm_ctx {
	ਪੂਰਨ fid;
};

/* Callback for remote forward global requests */
ਸਥਿਰ ਖਾਲੀ
ssh_confirm_remote_forward(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type, uint32_t seq, ਖਾਲੀ *ctxt)
{
	ਬਣਤਰ rfwd_confirm_ctx *rctx = (ਬਣਤਰ rfwd_confirm_ctx *)ctxt;
	ਬਣਤਰ Forward *rfwd;
	u_int ਪੋਰਟ;
	ਪੂਰਨ r;

	ਜੇ (rctx->fid < 0 || rctx->fid >= options.ਅੰਕ_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, ਆਕਾਰ(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_ਰਸਤਾ ? rfwd->listen_ਰਸਤਾ :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_ਰਸਤਾ || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_ਪੋਰਟ, rfwd->connect_ਰਸਤਾ ? rfwd->connect_ਰਸਤਾ :
	    rfwd->connect_host, rfwd->connect_ਪੋਰਟ);
	ਜੇ (rfwd->listen_ਰਸਤਾ == ਨਿਰਾ && rfwd->listen_ਪੋਰਟ == 0) {
		ਜੇ (type == SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS) {
			ਜੇ ((r = sshpkt_get_u32(ssh, &ਪੋਰਟ)) != 0)
				fatal_fr(r, "parse packet");
			ਜੇ (ਪੋਰਟ > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", ਪੋਰਟ,
				    rfwd->connect_host, rfwd->connect_ਪੋਰਟ);
				/* Ensure failure processing runs below */
				type = SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} ਨਹੀਂਤਾਂ {
				rfwd->allocated_ਪੋਰਟ = (ਪੂਰਨ)ਪੋਰਟ;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_ਪੋਰਟ, rfwd->connect_ਰਸਤਾ ?
				    rfwd->connect_ਰਸਤਾ : rfwd->connect_host,
				    rfwd->connect_ਪੋਰਟ);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_ਪੋਰਟ);
			}
		} ਨਹੀਂਤਾਂ {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE) {
		ਜੇ (options.exit_on_forward_failure) {
			ਜੇ (rfwd->listen_ਰਸਤਾ != ਨਿਰਾ)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_ਰਸਤਾ);
			ਨਹੀਂਤਾਂ
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_ਪੋਰਟ);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (rfwd->listen_ਰਸਤਾ != ਨਿਰਾ)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_ਰਸਤਾ);
			ਨਹੀਂਤਾਂ
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_ਪੋਰਟ);
		}
	}
	forwarding_success();
}

ਸਥਿਰ ਖਾਲੀ
client_cleanup_stdio_fwd(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ force, ਖਾਲੀ *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

ਸਥਿਰ ਖਾਲੀ
ssh_stdio_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ success, ਖਾਲੀ *arg)
{
	ਜੇ (!success)
		fatal("stdio forwarding failed");
}

ਸਥਿਰ ਖਾਲੀ
ssh_tun_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ success, ਖਾਲੀ *arg)
{
	ਜੇ (!success) {
		error("Tunnel forwarding failed");
		ਜੇ (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

ਸਥਿਰ ਖਾਲੀ
ssh_init_stdio_forwarding(ਬਣਤਰ ssh *ssh)
{
	Channel *c;
	ਪੂਰਨ ਵਿੱਚ, ਬਾਹਰਲਾ;

	ਜੇ (options.stdio_forward_host == ਨਿਰਾ)
		ਵਾਪਸ;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_ਪੋਰਟ);

	ਜੇ ((ਵਿੱਚ = dup(STDIN_FILENO)) == -1 ||
	    (ਬਾਹਰਲਾ = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	ਜੇ ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_ਪੋਰਟ, ਵਿੱਚ, ਬਾਹਰਲਾ,
	    CHANNEL_NONBLOCK_STDIO)) == ਨਿਰਾ)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_ਰਜਿਸਟਰ_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_ਰਜਿਸਟਰ_open_confirm(ssh, c->self, ssh_stdio_confirm, ਨਿਰਾ);
}

ਸਥਿਰ ਖਾਲੀ
ssh_init_forward_permissions(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *what, ਅੱਖਰ **opens,
    u_int ਅੰਕ_opens)
{
	u_int i;
	ਪੂਰਨ ਪੋਰਟ;
	ਅੱਖਰ *addr, *arg, *oarg;
	ਪੂਰਨ where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ਜੇ (ਅੰਕ_opens == 0)
		ਵਾਪਸ; /* permit any */

	/* handle keywords: "any" / "none" */
	ਜੇ (ਅੰਕ_opens == 1 && strcmp(opens[0], "any") == 0)
		ਵਾਪਸ;
	ਜੇ (ਅੰਕ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ਵਾਪਸ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ਲਈ (i = 0; i < ਅੰਕ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		ਜੇ (addr == ਨਿਰਾ)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		ਜੇ (arg == ਨਿਰਾ || ((ਪੋਰਟ = permitopen_ਪੋਰਟ(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_ਜੋੜੋ_permission(ssh, FORWARD_ADM,
		    where, addr, ਪੋਰਟ);
		ਮੁਕਤ(oarg);
	}
}

ਸਥਿਰ ਖਾਲੀ
ssh_init_forwarding(ਬਣਤਰ ssh *ssh, ਅੱਖਰ **ifname)
{
	ਪੂਰਨ success = 0;
	ਪੂਰਨ i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.ਅੰਕ_permitted_remote_opens);

	ਜੇ (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	ਲਈ (i = 0; i < options.ਅੰਕ_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_ਰਸਤਾ != ਨਿਰਾ) ?
		    options.local_forwards[i].listen_ਰਸਤਾ :
		    (options.local_forwards[i].listen_host == ਨਿਰਾ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_ਪੋਰਟ,
		    (options.local_forwards[i].connect_ਰਸਤਾ != ਨਿਰਾ) ?
		    options.local_forwards[i].connect_ਰਸਤਾ :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_ਪੋਰਟ);
		success += channel_ਤਿਆਰੀ_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	ਜੇ (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	ਜੇ (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	ਲਈ (i = 0; i < options.ਅੰਕ_remote_forwards; i++) {
		ਬਣਤਰ rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_ਰਸਤਾ != ਨਿਰਾ) ?
		    options.remote_forwards[i].listen_ਰਸਤਾ :
		    (options.remote_forwards[i].listen_host == ਨਿਰਾ) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_ਪੋਰਟ,
		    (options.remote_forwards[i].connect_ਰਸਤਾ != ਨਿਰਾ) ?
		    options.remote_forwards[i].connect_ਰਸਤਾ :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_ਪੋਰਟ);
		ਜੇ ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, ਆਕਾਰ(*rctx));
			rctx->fid = i;
			client_ਰਜਿਸਟਰ_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} ਨਹੀਂਤਾਂ ਜੇ (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		ਨਹੀਂਤਾਂ
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	ਜੇ (options.tun_open != SSH_TUNMODE_NO) {
		ਜੇ ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ਨਿਰਾ)) != ਨਿਰਾ)
			forward_confirms_pending++;
		ਨਹੀਂਤਾਂ ਜੇ (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		ਨਹੀਂਤਾਂ
			error("Could not request tunnel forwarding.");
	}
	ਜੇ (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

ਸਥਿਰ ਖਾਲੀ
check_agent_present(ਖਾਲੀ)
{
	ਪੂਰਨ r;

	ਜੇ (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		ਜੇ ((r = ssh_get_authentication_socket(ਨਿਰਾ)) != 0) {
			options.forward_agent = 0;
			ਜੇ (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

ਸਥਿਰ ਖਾਲੀ
ssh_session2_ਤਿਆਰੀ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ success, ਖਾਲੀ *arg)
{
	ਬਾਹਰੀ ਅੱਖਰ **environ;
	ਅਚਲ ਅੱਖਰ *display, *ਪਦ;
	ਅੱਖਰ *proto = ਨਿਰਾ, *ਅੰਕੜੇ = ਨਿਰਾ;

	ਜੇ (!success)
		ਵਾਪਸ; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	ਜੇ (display == ਨਿਰਾ && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	ਜੇ (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &ਅੰਕੜੇ) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    ਅੰਕੜੇ, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	ਜੇ (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	ਜੇ ((ਪਦ = lookup_env_ਵਿੱਚ_list("TERM", options.setenv,
	    options.ਅੰਕ_setenv)) == ਨਿਰਾ || *ਪਦ == '\0')
		ਪਦ = getenv("TERM");
	client_session2_ਤਿਆਰੀ(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, ਪਦ,
	    ਨਿਰਾ, fileno(stdin), command, environ);
}

/* open new channel for a session */
ਸਥਿਰ ਪੂਰਨ
ssh_session2_open(ਬਣਤਰ ssh *ssh)
{
	Channel *c;
	ਪੂਰਨ ਖਿੜਕੀ, packetmax, ਵਿੱਚ, ਬਾਹਰਲਾ, err;

	ਜੇ (options.stdin_null) {
		ਵਿੱਚ = open(_PATH_DEVNULL, O_RDONLY);
	} ਨਹੀਂਤਾਂ {
		ਵਿੱਚ = dup(STDIN_FILENO);
	}
	ਬਾਹਰਲਾ = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	ਜੇ (ਵਿੱਚ == -1 || ਬਾਹਰਲਾ == -1 || err == -1)
		fatal("dup() in/out/err failed");

	ਖਿੜਕੀ = CHAN_SES_ਖਿੜਕੀ_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ਜੇ (tty_flag) {
		ਖਿੜਕੀ >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, ਵਿੱਚ, ਬਾਹਰਲਾ, err,
	    ਖਿੜਕੀ, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	ਜੇ (tty_flag)
		channel_ਸੈੱਟ_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	ਜੇ (options.session_type != SESSION_TYPE_NONE)
		channel_ਰਜਿਸਟਰ_open_confirm(ssh, c->self,
		    ssh_session2_ਤਿਆਰੀ, ਨਿਰਾ);

	ਵਾਪਸ c->self;
}

ਸਥਿਰ ਪੂਰਨ
ssh_session2(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਪੂਰਨ r, id = -1;
	ਅੱਖਰ *cp, *tun_fwd_ifname = ਨਿਰਾ;

	/* XXX should be pre-session */
	ਜੇ (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	ਜੇ (options.local_command != ਨਿਰਾ) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ਦਲੀਲਾਂ(cinfo),
		    "T", tun_fwd_ifname == ਨਿਰਾ ? "NONE" : tun_fwd_ifname,
		    (ਅੱਖਰ *)ਨਿਰਾ);
		debug3("expanded LocalCommand: %s", options.local_command);
		ਮੁਕਤ(cp);
	}

	/* Start listening for multiplex clients */
	ਜੇ (!ssh_packet_get_mux(ssh))
		muxserver_listen(ssh);

	/*
	 * If we are in control persist mode and have a working mux listen
	 * socket, then prepare to background ourselves and have a foreground
	 * client attach as a control client.
	 * NB. we must save copies of the flags that we override for
	 * the backgrounding, since we defer attachment of the client until
	 * after the connection is fully established (in particular,
	 * async rfwd replies have been received for ExitOnForwardFailure).
	 */
	ਜੇ (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		ਜੇ ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ਨਿਰਾ))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	ਜੇ (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	ਜੇ (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	ਜੇ (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	ਜੇ (options.local_command != ਨਿਰਾ &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	ਜੇ (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	ਜੇ (options.fork_after_authentication) {
		ਜੇ (options.exit_on_forward_failure &&
		    options.ਅੰਕ_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} ਨਹੀਂਤਾਂ
			fork_postauth();
	}

	ਵਾਪਸ client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
ਸਥਿਰ ਖਾਲੀ
ਲੱਦੋ_ਜਨਤਕ_ਪਛਾਣ_ਤੱਤ_files(ਅਚਲ ਬਣਤਰ ssh_conn_info *cinfo)
{
	ਅੱਖਰ *filename, *cp;
	ਬਣਤਰ sshkey *ਜਨਤਕ;
	ਪੂਰਨ i;
	u_int n_ids, n_certs;
	ਅੱਖਰ *ਪਛਾਣ_ਤੱਤ_files[SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES];
	ਬਣਤਰ sshkey *ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES];
	ਪੂਰਨ ਪਛਾਣ_ਤੱਤ_file_userprovided[SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES];
	ਅੱਖਰ *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ਬਣਤਰ sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	ਪੂਰਨ certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ = ਨਿਰਾ;
	ਅੱਖਰ **comments = ਨਿਰਾ;
	ਪੂਰਨ nkeys;
#ਜੇ_ਅੰਤ /* PKCS11 */

	n_ids = n_certs = 0;
	memset(ਪਛਾਣ_ਤੱਤ_files, 0, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_files));
	memset(ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ, 0, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ));
	memset(ਪਛਾਣ_ਤੱਤ_file_userprovided, 0,
	    ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file_userprovided));
	memset(certificate_files, 0, ਆਕਾਰ(certificate_files));
	memset(certificates, 0, ਆਕਾਰ(certificates));
	memset(certificate_file_userprovided, 0,
	    ਆਕਾਰ(certificate_file_userprovided));

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	ਜੇ (options.pkcs11_provider != ਨਿਰਾ &&
	    options.ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files < SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES &&
	    (pkcs11_init(!options.batch_ਬਹੁਲਕ) == 0) &&
	    (nkeys = pkcs11_ਜੋੜੋ_provider(options.pkcs11_provider, ਨਿਰਾ,
	    &ਕੁੰਜੀਆਂ, &comments)) > 0) {
		ਲਈ (i = 0; i < nkeys; i++) {
			ਜੇ (n_ids >= SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES) {
				sshkey_free(ਕੁੰਜੀਆਂ[i]);
				ਮੁਕਤ(comments[i]);
				ਜਾਰੀ;
			}
			ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[n_ids] = ਕੁੰਜੀਆਂ[i];
			ਪਛਾਣ_ਤੱਤ_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		ਮੁਕਤ(ਕੁੰਜੀਆਂ);
		ਮੁਕਤ(comments);
	}
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */
	ਲਈ (i = 0; i < options.ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files; i++) {
		ਜੇ (n_ids >= SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES ||
		    strcasecmp(options.ਪਛਾਣ_ਤੱਤ_files[i], "none") == 0) {
			ਮੁਕਤ(options.ਪਛਾਣ_ਤੱਤ_files[i]);
			options.ਪਛਾਣ_ਤੱਤ_files[i] = ਨਿਰਾ;
			ਜਾਰੀ;
		}
		cp = tilde_expand_filename(options.ਪਛਾਣ_ਤੱਤ_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ਮੁਕਤ(cp);
		check_ਲੱਦੋ(sshkey_ਲੱਦੋ_ਜਨਤਕ(filename, &ਜਨਤਕ, ਨਿਰਾ),
		    &ਜਨਤਕ, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    ਜਨਤਕ ? ਜਨਤਕ->type : -1);
		ਮੁਕਤ(options.ਪਛਾਣ_ਤੱਤ_files[i]);
		ਪਛਾਣ_ਤੱਤ_files[n_ids] = filename;
		ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[n_ids] = ਜਨਤਕ;
		ਪਛਾਣ_ਤੱਤ_file_userprovided[n_ids] =
		    options.ਪਛਾਣ_ਤੱਤ_file_userprovided[i];
		ਜੇ (++n_ids >= SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES)
			ਜਾਰੀ;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		ਜੇ (options.ਅੰਕ_certificate_files != 0)
			ਜਾਰੀ;
		xasprintf(&cp, "%s-cert", filename);
		check_ਲੱਦੋ(sshkey_ਲੱਦੋ_ਜਨਤਕ(cp, &ਜਨਤਕ, ਨਿਰਾ),
		    &ਜਨਤਕ, filename, "identity pubkey");
		ਜੇ (ਜਨਤਕ == ਨਿਰਾ) {
			ਮੁਕਤ(cp);
			ਜਾਰੀ;
		}
		ਜੇ (!sshkey_is_cert(ਜਨਤਕ)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(ਜਨਤਕ));
			sshkey_free(ਜਨਤਕ);
			ਮੁਕਤ(cp);
			ਜਾਰੀ;
		}
		ਮੁਕਤ(cp);
		/* NB. leave filename pointing to private key */
		ਪਛਾਣ_ਤੱਤ_files[n_ids] = xstrdup(filename);
		ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[n_ids] = ਜਨਤਕ;
		ਪਛਾਣ_ਤੱਤ_file_userprovided[n_ids] =
		    options.ਪਛਾਣ_ਤੱਤ_file_userprovided[i];
		n_ids++;
	}

	ਜੇ (options.ਅੰਕ_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	ਲਈ (i = 0; i < options.ਅੰਕ_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ਮੁਕਤ(cp);

		check_ਲੱਦੋ(sshkey_ਲੱਦੋ_ਜਨਤਕ(filename, &ਜਨਤਕ, ਨਿਰਾ),
		    &ਜਨਤਕ, filename, "identity cert");
		ਮੁਕਤ(options.certificate_files[i]);
		options.certificate_files[i] = ਨਿਰਾ;
		ਜੇ (ਜਨਤਕ == ਨਿਰਾ) {
			ਮੁਕਤ(filename);
			ਜਾਰੀ;
		}
		ਜੇ (!sshkey_is_cert(ਜਨਤਕ)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(ਜਨਤਕ));
			sshkey_free(ਜਨਤਕ);
			ਮੁਕਤ(filename);
			ਜਾਰੀ;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = ਜਨਤਕ;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files = n_ids;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(options.ਪਛਾਣ_ਤੱਤ_files, ਪਛਾਣ_ਤੱਤ_files, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_files));
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(options.ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ, ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ));
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(options.ਪਛਾਣ_ਤੱਤ_file_userprovided,
	    ਪਛਾਣ_ਤੱਤ_file_userprovided, ਆਕਾਰ(ਪਛਾਣ_ਤੱਤ_file_userprovided));

	options.ਅੰਕ_certificate_files = n_certs;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(options.certificate_files,
	    certificate_files, ਆਕਾਰ(certificate_files));
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(options.certificates, certificates, ਆਕਾਰ(certificates));
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    ਆਕਾਰ(certificate_file_userprovided));
}

ਸਥਿਰ ਖਾਲੀ
main_sigchld_handler(ਪੂਰਨ sig)
{
	ਪੂਰਨ save_errno = errno;
	pid_t pid;
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜਦੋਂ ((pid = waitpid(-1, &ਸਥਿਤੀ, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
