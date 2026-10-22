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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/utsname.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <locale.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#endif
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "clientloop.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "sshconnect.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#ifdef ENABLE_PKCS11
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#endif

ಬಾಹ್ಯ ವರ್ಣ *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
ಸ್ಥಿರ ವರ್ಣ **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
ಪೂರ್ಣಾಙ್ಕ debug_flag = 0;

/* Flag indicating whether a tty should be requested */
ಪೂರ್ಣಾಙ್ಕ tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ostdin_null_flag, osession_type, otty_flag, orequest_tty;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
ವರ್ಣ *config = ರಿಕ್ತ;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ವರ್ಣ *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
ವರ್ಣ *forward_agent_sock_path = ರಿಕ್ತ;

/* socket address the host resolves to */
ಸಂರಚನಾ sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
ಸಂರಚನಾ sshbuf *command;

/* # of replies received for global requests */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ forward_confirms_pending = -1;

/* mux.c */
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ muxserver_sock;
ಬಾಹ್ಯ u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
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
	exit(255);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ssh_session2(ಸಂರಚನಾ ssh *, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *);
ಸ್ಥಿರ ಶೂನ್ಯ load_public_identity_files(ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *);
ಸ್ಥಿರ ಶೂನ್ಯ main_sigchld_handler(ಪೂರ್ಣಾಙ್ಕ);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
ಸ್ಥಿರ ಶೂನ್ಯ
tilde_expand_paths(ವರ್ಣ **paths, u_int ಅಂಕೆ_paths)
{
	u_int i;
	ವರ್ಣ *cp;

	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		ಮುಕ್ತ(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
ಸ್ಥಿರ ವರ್ಣ *
default_client_percent_expand(ಧ್ರುವ ವರ್ಣ *str,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ಪ್ರತ್ಯಾಗಮ percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (ವರ್ಣ *)ರಿಕ್ತ);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
ಸ್ಥಿರ ವರ್ಣ *
default_client_percent_dollar_expand(ಧ್ರುವ ವರ್ಣ *str,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ವರ್ಣ *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (ವರ್ಣ *)ರಿಕ್ತ);
	ಯದಿ (ret == ರಿಕ್ತ)
		fatal("invalid environment variable expansion");
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ಸಂರಚನಾ addrinfo *
resolve_host(ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ port, ಪೂರ್ಣಾಙ್ಕ logerr, ವರ್ಣ *cname, size_t clen)
{
	ವರ್ಣ strport[NI_MAXSERV];
	ಧ್ರುವ ವರ್ಣ *errstr = ರಿಕ್ತ;
	ಸಂರಚನಾ addrinfo hints, *res;
	ಪೂರ್ಣಾಙ್ಕ gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	ಯದಿ (port <= 0)
		port = default_ssh_port();
	ಯದಿ (cname != ರಿಕ್ತ)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, ಪರಿಮಾಣ strport, "%d", port);
	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	ಯದಿ (cname != ರಿಕ್ತ)
		hints.ai_flags = AI_CANONNAME;
	ಯದಿ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		ಯದಿ (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (cname != ರಿಕ್ತ && res->ai_canonname != ರಿಕ್ತ) {
		ಯದಿ (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} ಅನ್ಯಥಾ ಯದಿ (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			ಯದಿ (clen > 0)
				*cname = '\0';
		}
	}
	ಪ್ರತ್ಯಾಗಮ res;
}

/* Returns non-zero if name can only be an address and not a hostname */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
is_addr_fast(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ (strchr(name, '%') != ರಿಕ್ತ || strchr(name, ':') != ರಿಕ್ತ ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
is_addr(ಧ್ರುವ ವರ್ಣ *name)
{
	ವರ್ಣ strport[NI_MAXSERV];
	ಸಂರಚನಾ addrinfo hints, *res;

	ಯದಿ (is_addr_fast(name))
		ಪ್ರತ್ಯಾಗಮ 1;

	snprintf(strport, ಪರಿಮಾಣ strport, "%u", default_ssh_port());
	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ಯದಿ (getaddrinfo(name, strport, &hints, &res) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (res == ರಿಕ್ತ || res->ai_next != ರಿಕ್ತ) {
		freeaddrinfo(res);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	freeaddrinfo(res);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ಸಂರಚನಾ addrinfo *
resolve_addr(ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ port, ವರ್ಣ *caddr, size_t clen)
{
	ವರ್ಣ addr[NI_MAXHOST], strport[NI_MAXSERV];
	ಸಂರಚನಾ addrinfo hints, *res;
	ಪೂರ್ಣಾಙ್ಕ gaierr;

	ಯದಿ (port <= 0)
		port = default_ssh_port();
	snprintf(strport, ಪರಿಮಾಣ strport, "%u", port);
	memset(&hints, 0, ಪರಿಮಾಣ(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ಯದಿ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (res == ರಿಕ್ತ) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (res->ai_next != ರಿಕ್ತ) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, ಪರಿಮಾಣ(addr), ರಿಕ್ತ, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		ಗಚ್ಛ fail;
	}
	ಯದಿ (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		ಯದಿ (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_follow_cname(ಪೂರ್ಣಾಙ್ಕ direct, ವರ್ಣ **namep, ಧ್ರುವ ವರ್ಣ *cname)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಸಂರಚನಾ allowed_cname *rule;

	ಯದಿ (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ಪ್ರತ್ಯಾಗಮ 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	ಯದಿ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ಪ್ರತ್ಯಾಗಮ 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		ಯದಿ (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			ಅನುವರ್ತ;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		ಮುಕ್ತ(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ಸಂರಚನಾ addrinfo *
resolve_canonicalize(ವರ್ಣ **hostp, ಪೂರ್ಣಾಙ್ಕ port)
{
	ಪೂರ್ಣಾಙ್ಕ i, direct, ndots;
	ವರ್ಣ *cp, *fullhost, newname[NI_MAXHOST];
	ಸಂರಚನಾ addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	ಯದಿ ((addrs = resolve_addr(*hostp, port,
	    newname, ಪರಿಮಾಣ(newname))) != ರಿಕ್ತ) {
		debug2_f("hostname %.100s is address", *hostp);
		ಯದಿ (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			ಮುಕ್ತ(*hostp);
			*hostp = xstrdup(newname);
		}
		ಪ್ರತ್ಯಾಗಮ addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	ಯದಿ (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಯದಿ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	ಯದಿ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* If domain name is anchored, then resolve it now */
	ಯದಿ ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		ಯದಿ ((addrs = resolve_host(fullhost, port, 0,
		    newname, ಪರಿಮಾಣ(newname))) != ರಿಕ್ತ)
			ಗಚ್ಛ found;
		ಮುಕ್ತ(fullhost);
		ಗಚ್ಛ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	ಪ್ರತಿ (cp = *hostp; *cp != '\0'; cp++) {
		ಯದಿ (*cp == '.')
			ndots++;
	}
	ಯದಿ (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	/* Attempt each supplied suffix */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_canonical_domains; i++) {
		ಯದಿ (strcasecmp(options.canonical_domains[i], "none") == 0)
			ಭಙ್ಗ;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		ಯದಿ ((addrs = resolve_host(fullhost, port, 0,
		    newname, ಪರಿಮಾಣ(newname))) == ರಿಕ್ತ) {
			ಮುಕ್ತ(fullhost);
			ಅನುವರ್ತ;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		ಯದಿ (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		ಮುಕ್ತ(*hostp);
		*hostp = fullhost;
		ಪ್ರತ್ಯಾಗಮ addrs;
	}
 notfound:
	ಯದಿ (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
check_load(ಪೂರ್ಣಾಙ್ಕ r, ಸಂರಚನಾ sshkey **k, ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *message)
{
	ವರ್ಣ *fp;

	ವಿಕಲ್ಪ (r) {
	ಪಕ್ಷ 0:
		ಯದಿ (k == ರಿಕ್ತ || *k == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ;
		/* Check RSA keys size and discard if undersized */
		ಯದಿ ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			ಮುಕ್ತ(*k);
			*k = ರಿಕ್ತ;
			ಭಙ್ಗ;
		}
		ಯದಿ ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		ಮುಕ್ತ(fp);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_ERR_INTERNAL_ERROR:
	ಪಕ್ಷ SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	ಪಕ್ಷ SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		ಯದಿ (errno == ENOENT)
			ಭಙ್ಗ;
		/* FALLTHROUGH */
	ಸ್ವಭಾವ:
		error_r(r, "load %s \"%s\"", message, path);
		ಭಙ್ಗ;
	}
	ಯದಿ (k != ರಿಕ್ತ && *k == ರಿಕ್ತ)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
process_config_files(ಧ್ರುವ ವರ್ಣ *host_name, ಸಂರಚನಾ passwd *pw,
    ಪೂರ್ಣಾಙ್ಕ final_pass, ಪೂರ್ಣಾಙ್ಕ *want_final_pass)
{
	ವರ್ಣ *cmd, buf[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((cmd = sshbuf_dup_string(command)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	ಯದಿ (config != ರಿಕ್ತ) {
		ಯದಿ (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} ಅನ್ಯಥಾ {
		r = snprintf(buf, ಪರಿಮಾಣ buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		ಯದಿ (r > 0 && (size_t)r < ಪರಿಮಾಣ(buf))
			(ಶೂನ್ಯ)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(ಶೂನ್ಯ)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	ಮುಕ್ತ(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
ಸ್ಥಿರ ಶೂನ್ಯ
set_addrinfo_port(ಸಂರಚನಾ addrinfo *addrs, ಪೂರ್ಣಾಙ್ಕ port)
{
	ಸಂರಚನಾ addrinfo *addr;

	ಪ್ರತಿ (addr = addrs; addr != ರಿಕ್ತ; addr = addr->ai_next) {
		ವಿಕಲ್ಪ (addr->ai_family) {
		ಪಕ್ಷ AF_INET:
			((ಸಂರಚನಾ sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			ಭಙ್ಗ;
		ಪಕ್ಷ AF_INET6:
			((ಸಂರಚನಾ sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			ಭಙ್ಗ;
		}
	}
}

/*
 * Main program for the ssh client.
 */
ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ ac, ವರ್ಣ **av)
{
	ಸಂರಚನಾ ssh *ssh = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	ಪೂರ್ಣಾಙ್ಕ was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	ಪೂರ್ಣಾಙ್ಕ user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	ವರ್ಣ *p, *cp, *ಸಾಲು, *argv0, *logfile, *args;
	ವರ್ಣ cname[NI_MAXHOST], thishost[NI_MAXHOST];
	ಸಂರಚನಾ stat st;
	ಸಂರಚನಾ passwd *pw;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind, optreset;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಸಂರಚನಾ Forward fwd;
	ಸಂರಚನಾ addrinfo *addrs = ರಿಕ್ತ;
	size_t n, len;
	u_int j;
	ಸಂರಚನಾ utsname utsname;
	ಸಂರಚನಾ ssh_conn_info *cinfo = ರಿಕ್ತ;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, ಪರಿಮಾಣ(*saved_av));
	ಪ್ರತಿ (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ರಿಕ್ತ;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	ಯದಿ (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		exit(255);
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
	ಯದಿ ((ssh = ssh_alloc_session_state()) == ರಿಕ್ತ)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = ರಿಕ್ತ;
	use_syslog = 0;
	logfile = ರಿಕ್ತ;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	ಯಾವತ್ ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		ವಿಕಲ್ಪ (opt) {
		ಪಕ್ಷ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ಭಙ್ಗ;
		ಪಕ್ಷ '2':
			/* Ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ '4':
			options.address_family = AF_INET;
			ಭಙ್ಗ;
		ಪಕ್ಷ '6':
			options.address_family = AF_INET6;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'n':
			options.stdin_null = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'x':
			options.forward_x11 = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'X':
			options.forward_x11 = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'y':
			use_syslog = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'E':
			logfile = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'G':
			config_test = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Z':
			dump_pubkeys = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'g':
			options.fwd_opts.gateway_ports = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			ಯದಿ (options.stdio_forward_host != ರಿಕ್ತ)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			ಅನ್ಯಥಾ ಯದಿ (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			ಯದಿ (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			ಅನ್ಯಥಾ
				fatal("Invalid multiplex command.");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			ಯದಿ (options.tag == ರಿಕ್ತ)
				options.tag = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'Q':
			cp = ರಿಕ್ತ;
			ಯದಿ (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				ಪ್ರತಿ (n = 0; n < len; n++)
					ಯದಿ (cp[n] == ',')
						cp[n] = '\n';
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			ಯದಿ (cp == ರಿಕ್ತ)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			ಮುಕ್ತ(cp);
			exit(0);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'a':
			options.forward_agent = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'A':
			options.forward_agent = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'k':
			options.gss_deleg_creds = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'i':
			p = tilde_expand_filename(optarg, getuid());
			ಯದಿ (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			ಅನ್ಯಥಾ
				add_identity_file(&options, ರಿಕ್ತ, p, 1);
			ಮುಕ್ತ(p);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'I':
#ifdef ENABLE_PKCS11
			ಮುಕ್ತ(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#ಅನ್ಯಥಾ
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			ಭಙ್ಗ;
		ಪಕ್ಷ 'J':
			ಯದಿ (options.jump_host != ರಿಕ್ತ) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			ಯದಿ (options.proxy_command != ರಿಕ್ತ)
				fatal("Cannot specify -J with ProxyCommand");
			ಯದಿ (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			ಯದಿ (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			ಅನ್ಯಥಾ
				options.request_tty = REQUEST_TTY_YES;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			ಯದಿ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ಅನ್ಯಥಾ {
				ಯದಿ (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'w':
			ಯದಿ (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			ಯದಿ (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'W':
			ಯದಿ (options.stdio_forward_host != ರಿಕ್ತ)
				fatal("stdio forward already specified");
			ಯದಿ (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			ಯದಿ (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				ಮುಕ್ತ(fwd.connect_host);
			} ಅನ್ಯಥಾ {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'e':
			ಯದಿ (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			ಅನ್ಯಥಾ ಯದಿ (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			ಅನ್ಯಥಾ ಯದಿ (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			ಅನ್ಯಥಾ {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'c':
			ಯದಿ (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			ಮುಕ್ತ(options.ciphers);
			options.ciphers = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'm':
			ಯದಿ (mac_valid(optarg)) {
				ಮುಕ್ತ(options.macs);
				options.macs = xstrdup(optarg);
			} ಅನ್ಯಥಾ {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'M':
			ಯದಿ (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			ಅನ್ಯಥಾ
				options.control_master = SSHCTL_MASTER_YES;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			ಯದಿ (options.port == -1) {
				options.port = a2port(optarg);
				ಯದಿ (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			ಯದಿ (options.user == ರಿಕ್ತ) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			ಭಙ್ಗ;

		ಪಕ್ಷ 'L':
			ಯದಿ (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			ಅನ್ಯಥಾ {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			ಭಙ್ಗ;

		ಪಕ್ಷ 'R':
			ಯದಿ (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} ಅನ್ಯಥಾ {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			ಭಙ್ಗ;

		ಪಕ್ಷ 'D':
			ಯದಿ (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} ಅನ್ಯಥಾ {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			ಭಙ್ಗ;

		ಪಕ್ಷ 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#ಅನ್ಯಥಾ
			error("Compression not supported, disabling.");
#endif
			ಭಙ್ಗ;
		ಪಕ್ಷ 'N':
			ಯದಿ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			options.request_tty = REQUEST_TTY_NO;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'o':
			ಸಾಲು = xstrdup(optarg);
			ಯದಿ (process_config_ಸಾಲು(&options, pw,
			    host ? host : "", host ? host : "", "", ಸಾಲು,
			    "command-line", 0, ರಿಕ್ತ, SSHCONF_USERCONF) != 0)
				exit(255);
			ಮುಕ್ತ(ಸಾಲು);
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			ಯದಿ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'S':
			ಮುಕ್ತ(options.control_path);
			options.control_path = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'b':
			options.bind_address = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'B':
			options.bind_interface = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'F':
			config = optarg;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
		}
	}

	ಯದಿ (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	ಯದಿ (ac > 0 && !host) {
		ಪೂರ್ಣಾಙ್ಕ tport;
		ವರ್ಣ *tuser;
		ವಿಕಲ್ಪ (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		ಪಕ್ಷ -1:
			usage();
			ಭಙ್ಗ;
		ಪಕ್ಷ 0:
			ಯದಿ (options.user == ರಿಕ್ತ) {
				options.user = tuser;
				tuser = ರಿಕ್ತ;
				user_on_commandline = 1;
			}
			ಮುಕ್ತ(tuser);
			ಯದಿ (options.port == -1 && tport != -1)
				options.port = tport;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			ಯದಿ (cp != ರಿಕ್ತ) {
				ಯದಿ (cp == p)
					usage();
				ಯದಿ (options.user == ರಿಕ್ತ) {
					options.user = p;
					p = ರಿಕ್ತ;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				ಮುಕ್ತ(p);
			} ಅನ್ಯಥಾ
				host = p;
			ಭಙ್ಗ;
		}
		ಯದಿ (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			ಗಚ್ಛ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	ಯದಿ (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	ಯದಿ (options.user != ರಿಕ್ತ && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	ಯದಿ (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	ಯದಿ ((command = sshbuf_new()) == ರಿಕ್ತ)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	ಯದಿ (!ac) {
		/* No command specified - execute shell on a tty. */
		ಯದಿ (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} ಅನ್ಯಥಾ {
		/* A command has been specified.  Store it into the buffer. */
		ಪ್ರತಿ (i = 0; i < ac; i++) {
			ಯದಿ ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	ಯದಿ (use_syslog && logfile != ರಿಕ್ತ)
		fatal("Can't specify both -y and -E");
	ಯದಿ (logfile != ರಿಕ್ತ)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	ಯದಿ (uname(&utsname) != 0) {
		memset(&utsname, 0, ಪರಿಮಾಣ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ಪರಿಮಾಣ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	ಮುಕ್ತ(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	ಯದಿ (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	ಯದಿ (options.hostname != ರಿಕ್ತ) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (ವರ್ಣ *)ರಿಕ್ತ);
		ಮುಕ್ತ(host);
		host = cp;
		ಮುಕ್ತ(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	ಯದಿ ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	ಯದಿ (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
		addrs = resolve_canonicalize(&host, options.port);

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
	ಯದಿ (addrs == ರಿಕ್ತ && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		ಯದಿ ((addrs = resolve_host(host, options.port,
		    direct, cname, ಪರಿಮಾಣ(cname))) == ರಿಕ್ತ) {
			/* Don't fatal proxied host names not in the DNS */
			ಯದಿ (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} ಅನ್ಯಥಾ
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	ಯದಿ (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	ಯದಿ (want_final_pass) {
		debug("re-parsing configuration");
		ಮುಕ್ತ(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ರಿಕ್ತ);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		ಯದಿ (addrs != ರಿಕ್ತ && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	ಯದಿ (fill_default_options(&options) != 0)
		cleanup_exit(255);

	ಯದಿ (options.user == ರಿಕ್ತ) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	ಯದಿ (options.jump_host != ರಿಕ್ತ) {
		ವರ್ಣ port_s[8];
		ಧ್ರುವ ವರ್ಣ *jumpuser = options.jump_user, *sshbin = argv0;
		ಪೂರ್ಣಾಙ್ಕ port = options.port, jumpport = options.jump_port;

		ಯದಿ (port <= 0)
			port = default_ssh_port();
		ಯದಿ (jumpport <= 0)
			jumpport = default_ssh_port();
		ಯದಿ (jumpuser == ರಿಕ್ತ)
			jumpuser = options.user;
		ಯದಿ (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		ಯದಿ (strchr(argv0, '/') != ರಿಕ್ತ && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		ಯದಿ (options.proxy_command != ರಿಕ್ತ &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, ಪರಿಮಾಣ(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ರಿಕ್ತ ? "" : " -l ",
		    options.jump_user == ರಿಕ್ತ ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ರಿಕ್ತ ? "" : " -J ",
		    options.jump_extra == ರಿಕ್ತ ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ರಿಕ್ತ ? "" : " -F ",
		    config == ರಿಕ್ತ ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	ಯದಿ (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	ಯದಿ (options.host_ಕೀಲಿ_alias != ರಿಕ್ತ)
		lowercase(options.host_ಕೀಲಿ_alias);
	ಯದಿ (options.proxy_command != ರಿಕ್ತ &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	ಯದಿ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ಯದಿ (options.control_persist && options.control_path != ರಿಕ್ತ) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} ಅನ್ಯಥಾ ಯದಿ (sshbuf_len(command) != 0 ||
		    options.remote_command != ರಿಕ್ತ ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} ಅನ್ಯಥಾ ಯದಿ (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	ಯದಿ (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	ಯದಿ (sshbuf_len(command) != 0 && options.remote_command != ರಿಕ್ತ)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	ಯದಿ (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ರಿಕ್ತ &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	ಪ್ರತಿ (j = 0; j < options.ಅಂಕೆ_log_verbose; j++) {
		ಯದಿ (strcasecmp(options.log_verbose[j], "none") == 0)
			ಭಙ್ಗ;
		log_verbose_add(options.log_verbose[j]);
	}

	ಯದಿ (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	ಯದಿ (sshbuf_len(command) == 0 && options.remote_command == ರಿಕ್ತ)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	ಯದಿ (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	ಯದಿ ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		ಯದಿ (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, ಪರಿಮಾಣ(*cinfo));
	ಯದಿ (gethostname(thishost, ಪರಿಮಾಣ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_ಕೀಲಿ_alias ?
	    options.host_ಕೀಲಿ_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ರಿಕ್ತ ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	ಯದಿ (!user_on_commandline && !user_was_default) {
		ಯದಿ ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (ವರ್ಣ *)ರಿಕ್ತ)) == ರಿಕ್ತ)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		ಮುಕ್ತ(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	ಯದಿ ((user_on_commandline || user_expanded) &&
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
	ಯದಿ (options.remote_command != ರಿಕ್ತ) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		ಮುಕ್ತ(cp);
		ಯದಿ ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	ಯದಿ (options.control_path != ರಿಕ್ತ) {
		cp = tilde_expand_filename(options.control_path, getuid());
		ಮುಕ್ತ(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		ಮುಕ್ತ(cp);
	}

	ಯದಿ (options.identity_agent != ರಿಕ್ತ) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ಮುಕ್ತ(p);
		ಮುಕ್ತ(options.identity_agent);
		options.identity_agent = cp;
	}

	ಪ್ರತಿ (j = 0; j < options.ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು; j++) {
		p = tilde_expand_filename(options.revoked_host_ಕೀಲಿಗಳು[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ಮುಕ್ತ(p);
		ಮುಕ್ತ(options.revoked_host_ಕೀಲಿಗಳು[j]);
		options.revoked_host_ಕೀಲಿಗಳು[j] = cp;
	}

	ಯದಿ (options.forward_agent_sock_path != ರಿಕ್ತ) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ಮುಕ್ತ(p);
		ಮುಕ್ತ(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		ಯದಿ (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			ಯದಿ (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	ಯದಿ (options.version_addendum != ರಿಕ್ತ) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		ಮುಕ್ತ(options.version_addendum);
		options.version_addendum = cp;
	}

	ಯದಿ (options.ಅಂಕೆ_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		ಯದಿ (options.ಅಂಕೆ_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ಮುಕ್ತ(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ರಿಕ್ತ;
		options.ಅಂಕೆ_system_hostfiles = 0;
	}

	ಯದಿ (options.ಅಂಕೆ_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		ಯದಿ (options.ಅಂಕೆ_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ಮುಕ್ತ(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ರಿಕ್ತ;
		options.ಅಂಕೆ_user_hostfiles = 0;
	}
	ಪ್ರತಿ (j = 0; j < options.ಅಂಕೆ_user_hostfiles; j++) {
		ಯದಿ (options.user_hostfiles[j] == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		ಯದಿ (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		ಮುಕ್ತ(options.user_hostfiles[j]);
		ಮುಕ್ತ(cp);
		options.user_hostfiles[j] = p;
	}

	ಪ್ರತಿ (j = 0; j < options.ಅಂಕೆ_setenv; j++) {
		ವರ್ಣ *name = options.setenv[j], *ಮೌಲ್ಯ;

		ಯದಿ (name == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		/* Expand only the value portion, not the variable name. */
		ಯದಿ ((ಮೌಲ್ಯ = strchr(name, '=')) == ರಿಕ್ತ) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*ಮೌಲ್ಯ++ = '\0';
		cp = default_client_percent_dollar_expand(ಮೌಲ್ಯ, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		ಯದಿ (strcmp(ಮೌಲ್ಯ, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, ಮೌಲ್ಯ, cp);
		}
		ಮುಕ್ತ(options.setenv[j]);
		ಮುಕ್ತ(cp);
		options.setenv[j] = p;
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
		ಯದಿ (options.local_forwards[i].listen_path != ರಿಕ್ತ) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			ಯದಿ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			ಮುಕ್ತ(cp);
		}
		ಯದಿ (options.local_forwards[i].connect_path != ರಿಕ್ತ) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			ಯದಿ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			ಮುಕ್ತ(cp);
		}
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
		ಯದಿ (options.remote_forwards[i].listen_path != ರಿಕ್ತ) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			ಯದಿ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			ಮುಕ್ತ(cp);
		}
		ಯದಿ (options.remote_forwards[i].connect_path != ರಿಕ್ತ) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			ಯದಿ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			ಮುಕ್ತ(cp);
		}
	}

	ಯದಿ (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	ಯದಿ (options.sk_provider != ರಿಕ್ತ && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		ಯದಿ ((cp = getenv(options.sk_provider + 1)) == ರಿಕ್ತ) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			ಮುಕ್ತ(options.sk_provider);
			options.sk_provider = ರಿಕ್ತ;
		} ಅನ್ಯಥಾ {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			ಮುಕ್ತ(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	ಯದಿ (muxclient_command != 0 && options.control_path == ರಿಕ್ತ)
		fatal("No ControlPath specified for \"-O\" command");
	ಯದಿ (options.control_path != ರಿಕ್ತ) {
		ಪೂರ್ಣಾಙ್ಕ sock;
		ಯದಿ ((sock = muxclient(options.control_path)) >= 0) {
			ಯದಿ (ssh_packet_set_connection(ssh, sock, sock) == ರಿಕ್ತ)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			ಗಚ್ಛ skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	ಯದಿ (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		ಯದಿ (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} ಅನ್ಯಥಾ {
			cp = options.identity_agent;
			/* legacy (limited) format */
			ಯದಿ (cp[0] == '$' && cp[1] != '{') {
				ಯದಿ (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				ಯದಿ ((p = getenv(cp + 1)) == ರಿಕ್ತ)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				ಅನ್ಯಥಾ
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} ಅನ್ಯಥಾ {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	ಯದಿ (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	ಯದಿ (addrs == ರಿಕ್ತ && options.proxy_command == ರಿಕ್ತ) {
		debug2("resolving \"%s\" port %d", host, options.port);
		ಯದಿ ((addrs = resolve_host(host, options.port, 1,
		    cname, ಪರಿಮಾಣ(cname))) == ರಿಕ್ತ)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	ಯದಿ (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	ಅನ್ಯಥಾ
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	ಪ್ರತಿ (j = 0; j < options.ಅಂಕೆ_channel_timeouts; j++) {
		ದ್ವಿಗುಣ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		ಯದಿ (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		ಮುಕ್ತ(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	ಯದಿ (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_ಎಣಿಕೆ_max);

	ಯದಿ (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.ಕೀಲಿಗಳು = ರಿಕ್ತ;
	ಯದಿ (options.hostbased_authentication) {
		ಪೂರ್ಣಾಙ್ಕ loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.ಕೀಲಿಗಳು = xcalloc(sensitive_data.nkeys,
		    ಪರಿಮಾಣ(*sensitive_data.ಕೀಲಿಗಳು));

		/* XXX check errors? */
#define L_PUBKEY(p,o) ಕುರು { \
	ಯದಿ ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.ಕೀಲಿಗಳು[o]), ರಿಕ್ತ), \
	    &(sensitive_data.ಕೀಲಿಗಳು[o]), p, "hostbased pubkey"); \
	ಯದಿ (sensitive_data.ಕೀಲಿಗಳು[o] != ರಿಕ್ತ) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ಯಾವತ್ (0)
#define L_CERT(p,o) ಕುರು { \
	ಯದಿ ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.ಕೀಲಿಗಳು[o])), \
	    &(sensitive_data.ಕೀಲಿಗಳು[o]), p, "hostbased cert"); \
	ಯದಿ (sensitive_data.ಕೀಲಿಗಳು[o] != ರಿಕ್ತ) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ಯಾವತ್ (0)

		ಯದಿ (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_ಕೀಲಿ_FILE, 0);
			L_CERT(PATH_HOST_ED25519_ಕೀಲಿ_FILE, 1);
			L_CERT(PATH_HOST_RSA_ಕೀಲಿ_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_ಕೀಲಿ_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_ಕೀಲಿ_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_ಕೀಲಿ_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, 7);
			ಯದಿ (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	ಯದಿ (options.forward_agent && options.forward_agent_sock_path != ರಿಕ್ತ) {
		cp = options.forward_agent_sock_path;
		ಯದಿ (cp[0] == '$') {
			ಯದಿ (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			ಯದಿ ((p = getenv(cp + 1)) != ರಿಕ್ತ)
				forward_agent_sock_path = xstrdup(p);
			ಅನ್ಯಥಾ
				options.forward_agent = 0;
			ಮುಕ್ತ(cp);
		} ಅನ್ಯಥಾ {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.ಅಂಕೆ_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.ಅಂಕೆ_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	ಯದಿ (sensitive_data.nkeys != 0) {
		ಪ್ರತಿ (i = 0; i < sensitive_data.nkeys; i++) {
			ಯದಿ (sensitive_data.ಕೀಲಿಗಳು[i] != ರಿಕ್ತ) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.ಕೀಲಿಗಳು[i]);
				sensitive_data.ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
			}
		}
		ಮುಕ್ತ(sensitive_data.ಕೀಲಿಗಳು);
	}
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_identity_files; i++) {
		ಮುಕ್ತ(options.identity_files[i]);
		options.identity_files[i] = ರಿಕ್ತ;
		ಯದಿ (options.identity_ಕೀಲಿಗಳು[i]) {
			sshkey_free(options.identity_ಕೀಲಿಗಳು[i]);
			options.identity_ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
		}
	}
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_certificate_files; i++) {
		ಮುಕ್ತ(options.certificate_files[i]);
		options.certificate_files[i] = ರಿಕ್ತ;
	}

#ifdef ENABLE_PKCS11
	(ಶೂನ್ಯ)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	ಯದಿ (addrs != ರಿಕ್ತ)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	ಯದಿ (options.control_path != ರಿಕ್ತ && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	ಪ್ರತ್ಯಾಗಮ exit_status;
}

ಸ್ಥಿರ ಶೂನ್ಯ
control_persist_detach(ಶೂನ್ಯ)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	ವಿಕಲ್ಪ ((pid = fork())) {
	ಪಕ್ಷ -1:
		fatal_f("fork: %s", strerror(errno));
	ಪಕ್ಷ 0:
		/* Child: master process continues mainloop */
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (long)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(ಶೂನ್ಯ)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	ಯದಿ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
ಸ್ಥಿರ ಶೂನ್ಯ
fork_postauth(ಶೂನ್ಯ)
{
	ಯದಿ (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	ಯದಿ (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	ಯದಿ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

ಸ್ಥಿರ ಶೂನ್ಯ
forwarding_success(ಶೂನ್ಯ)
{
	ಯದಿ (forward_confirms_pending == -1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		ಯದಿ (options.fork_after_authentication)
			fork_postauth();
	} ಅನ್ಯಥಾ {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

ಸಂರಚನಾ rfwd_confirm_ctx {
	ಪೂರ್ಣಾಙ್ಕ fid;
};

/* Callback for remote forward global requests */
ಸ್ಥಿರ ಶೂನ್ಯ
ssh_confirm_remote_forward(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಶೂನ್ಯ *ctxt)
{
	ಸಂರಚನಾ rfwd_confirm_ctx *rctx = (ಸಂರಚನಾ rfwd_confirm_ctx *)ctxt;
	ಸಂರಚನಾ Forward *rfwd;
	u_int port;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (rctx->fid < 0 || rctx->fid >= options.ಅಂಕೆ_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, ಪರಿಮಾಣ(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	ಯದಿ (rfwd->listen_path == ರಿಕ್ತ && rfwd->listen_port == 0) {
		ಯದಿ (type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS) {
			ಯದಿ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			ಯದಿ (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_ಸಂದೇಶ_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} ಅನ್ಯಥಾ {
				rfwd->allocated_port = (ಪೂರ್ಣಾಙ್ಕ)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} ಅನ್ಯಥಾ {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	ಯದಿ (type == SSH2_ಸಂದೇಶ_REQUEST_FAILURE) {
		ಯದಿ (options.exit_on_forward_failure) {
			ಯದಿ (rfwd->listen_path != ರಿಕ್ತ)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			ಅನ್ಯಥಾ
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} ಅನ್ಯಥಾ {
			ಯದಿ (rfwd->listen_path != ರಿಕ್ತ)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			ಅನ್ಯಥಾ
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_cleanup_stdio_fwd(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ force, ಶೂನ್ಯ *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_stdio_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ success, ಶೂನ್ಯ *arg)
{
	ಯದಿ (!success)
		fatal("stdio forwarding failed");
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_tun_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ success, ಶೂನ್ಯ *arg)
{
	ಯದಿ (!success) {
		error("Tunnel forwarding failed");
		ಯದಿ (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_init_stdio_forwarding(ಸಂರಚನಾ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ in, out;

	ಯದಿ (options.stdio_forward_host == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	ಯದಿ ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	ಯದಿ ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == ರಿಕ್ತ)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_init_forward_permissions(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *what, ವರ್ಣ **opens,
    u_int ಅಂಕೆ_opens)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ port;
	ವರ್ಣ *addr, *arg, *oarg;
	ಪೂರ್ಣಾಙ್ಕ where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ಯದಿ (ಅಂಕೆ_opens == 0)
		ಪ್ರತ್ಯಾಗಮ; /* permit any */

	/* handle keywords: "any" / "none" */
	ಯದಿ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "any") == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ಪ್ರತ್ಯಾಗಮ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		ಯದಿ (addr == ರಿಕ್ತ)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		ಯದಿ (arg == ರಿಕ್ತ || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		ಮುಕ್ತ(oarg);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_init_forwarding(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ **ifname)
{
	ಪೂರ್ಣಾಙ್ಕ success = 0;
	ಪೂರ್ಣಾಙ್ಕ i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.ಅಂಕೆ_permitted_remote_opens);

	ಯದಿ (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != ರಿಕ್ತ) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == ರಿಕ್ತ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != ರಿಕ್ತ) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	ಯದಿ (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	ಯದಿ (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
		ಸಂರಚನಾ rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != ರಿಕ್ತ) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == ರಿಕ್ತ) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != ರಿಕ್ತ) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		ಯದಿ ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, ಪರಿಮಾಣ(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} ಅನ್ಯಥಾ ಯದಿ (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		ಅನ್ಯಥಾ
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	ಯದಿ (options.tun_open != SSH_TUNMODE_NO) {
		ಯದಿ ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ರಿಕ್ತ)) != ರಿಕ್ತ)
			forward_confirms_pending++;
		ಅನ್ಯಥಾ ಯದಿ (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		ಅನ್ಯಥಾ
			error("Could not request tunnel forwarding.");
	}
	ಯದಿ (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_agent_present(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		ಯದಿ ((r = ssh_get_authentication_socket(ರಿಕ್ತ)) != 0) {
			options.forward_agent = 0;
			ಯದಿ (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_session2_setup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ success, ಶೂನ್ಯ *arg)
{
	ಬಾಹ್ಯ ವರ್ಣ **environ;
	ಧ್ರುವ ವರ್ಣ *display, *term;
	ವರ್ಣ *proto = ರಿಕ್ತ, *data = ರಿಕ್ತ;

	ಯದಿ (!success)
		ಪ್ರತ್ಯಾಗಮ; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	ಯದಿ (display == ರಿಕ್ತ && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	ಯದಿ (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &data) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    data, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	ಯದಿ (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	ಯದಿ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.ಅಂಕೆ_setenv)) == ರಿಕ್ತ || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    ರಿಕ್ತ, fileno(stdin), command, environ);
}

/* open new channel for a session */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_session2_open(ಸಂರಚನಾ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಙ್ಕ window, packetmax, in, out, err;

	ಯದಿ (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} ಅನ್ಯಥಾ {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	ಯದಿ (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ಯದಿ (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	ಯದಿ (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	ಯದಿ (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, ರಿಕ್ತ);

	ಪ್ರತ್ಯಾಗಮ c->self;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_session2(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ಪೂರ್ಣಾಙ್ಕ r, id = -1;
	ವರ್ಣ *cp, *tun_fwd_ifname = ರಿಕ್ತ;

	/* XXX should be pre-session */
	ಯದಿ (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	ಯದಿ (options.local_command != ರಿಕ್ತ) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == ರಿಕ್ತ ? "NONE" : tun_fwd_ifname,
		    (ವರ್ಣ *)ರಿಕ್ತ);
		debug3("expanded LocalCommand: %s", options.local_command);
		ಮುಕ್ತ(cp);
	}

	/* Start listening for multiplex clients */
	ಯದಿ (!ssh_packet_get_mux(ssh))
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
	ಯದಿ (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		ಯದಿ ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ರಿಕ್ತ))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	ಯದಿ (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	ಯದಿ (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	ಯದಿ (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	ಯದಿ (options.local_command != ರಿಕ್ತ &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	ಯದಿ (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	ಯದಿ (options.fork_after_authentication) {
		ಯದಿ (options.exit_on_forward_failure &&
		    options.ಅಂಕೆ_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} ಅನ್ಯಥಾ
			fork_postauth();
	}

	ಪ್ರತ್ಯಾಗಮ client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
ಸ್ಥಿರ ಶೂನ್ಯ
load_public_identity_files(ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ವರ್ಣ *filename, *cp;
	ಸಂರಚನಾ sshkey *ಸಾರ್ವಜನಿಕ;
	ಪೂರ್ಣಾಙ್ಕ i;
	u_int n_ids, n_certs;
	ವರ್ಣ *identity_files[SSH_MAX_IDENTITY_FILES];
	ಸಂರಚನಾ sshkey *identity_ಕೀಲಿಗಳು[SSH_MAX_IDENTITY_FILES];
	ಪೂರ್ಣಾಙ್ಕ identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	ವರ್ಣ *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ಸಂರಚನಾ sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	ಪೂರ್ಣಾಙ್ಕ certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	ಸಂರಚನಾ sshkey **ಕೀಲಿಗಳು = ರಿಕ್ತ;
	ವರ್ಣ **comments = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, ಪರಿಮಾಣ(identity_files));
	memset(identity_ಕೀಲಿಗಳು, 0, ಪರಿಮಾಣ(identity_ಕೀಲಿಗಳು));
	memset(identity_file_userprovided, 0,
	    ಪರಿಮಾಣ(identity_file_userprovided));
	memset(certificate_files, 0, ಪರಿಮಾಣ(certificate_files));
	memset(certificates, 0, ಪರಿಮಾಣ(certificates));
	memset(certificate_file_userprovided, 0,
	    ಪರಿಮಾಣ(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	ಯದಿ (options.pkcs11_provider != ರಿಕ್ತ &&
	    options.ಅಂಕೆ_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, ರಿಕ್ತ,
	    &ಕೀಲಿಗಳು, &comments)) > 0) {
		ಪ್ರತಿ (i = 0; i < nkeys; i++) {
			ಯದಿ (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(ಕೀಲಿಗಳು[i]);
				ಮುಕ್ತ(comments[i]);
				ಅನುವರ್ತ;
			}
			identity_ಕೀಲಿಗಳು[n_ids] = ಕೀಲಿಗಳು[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		ಮುಕ್ತ(ಕೀಲಿಗಳು);
		ಮುಕ್ತ(comments);
	}
#endif /* ENABLE_PKCS11 */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_identity_files; i++) {
		ಯದಿ (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			ಮುಕ್ತ(options.identity_files[i]);
			options.identity_files[i] = ರಿಕ್ತ;
			ಅನುವರ್ತ;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ಮುಕ್ತ(cp);
		check_load(sshkey_load_public(filename, &ಸಾರ್ವಜನಿಕ, ರಿಕ್ತ),
		    &ಸಾರ್ವಜನಿಕ, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    ಸಾರ್ವಜನಿಕ ? ಸಾರ್ವಜನಿಕ->type : -1);
		ಮುಕ್ತ(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_ಕೀಲಿಗಳು[n_ids] = ಸಾರ್ವಜನಿಕ;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		ಯದಿ (++n_ids >= SSH_MAX_IDENTITY_FILES)
			ಅನುವರ್ತ;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		ಯದಿ (options.ಅಂಕೆ_certificate_files != 0)
			ಅನುವರ್ತ;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &ಸಾರ್ವಜನಿಕ, ರಿಕ್ತ),
		    &ಸಾರ್ವಜನಿಕ, filename, "identity pubkey");
		ಯದಿ (ಸಾರ್ವಜನಿಕ == ರಿಕ್ತ) {
			ಮುಕ್ತ(cp);
			ಅನುವರ್ತ;
		}
		ಯದಿ (!sshkey_is_cert(ಸಾರ್ವಜನಿಕ)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(ಸಾರ್ವಜನಿಕ));
			sshkey_free(ಸಾರ್ವಜನಿಕ);
			ಮುಕ್ತ(cp);
			ಅನುವರ್ತ;
		}
		ಮುಕ್ತ(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_ಕೀಲಿಗಳು[n_ids] = ಸಾರ್ವಜನಿಕ;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	ಯದಿ (options.ಅಂಕೆ_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ಮುಕ್ತ(cp);

		check_load(sshkey_load_public(filename, &ಸಾರ್ವಜನಿಕ, ರಿಕ್ತ),
		    &ಸಾರ್ವಜನಿಕ, filename, "identity cert");
		ಮುಕ್ತ(options.certificate_files[i]);
		options.certificate_files[i] = ರಿಕ್ತ;
		ಯದಿ (ಸಾರ್ವಜನಿಕ == ರಿಕ್ತ) {
			ಮುಕ್ತ(filename);
			ಅನುವರ್ತ;
		}
		ಯದಿ (!sshkey_is_cert(ಸಾರ್ವಜನಿಕ)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(ಸಾರ್ವಜನಿಕ));
			sshkey_free(ಸಾರ್ವಜನಿಕ);
			ಮುಕ್ತ(filename);
			ಅನುವರ್ತ;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = ಸಾರ್ವಜನಿಕ;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.ಅಂಕೆ_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, ಪರಿಮಾಣ(identity_files));
	memcpy(options.identity_ಕೀಲಿಗಳು, identity_ಕೀಲಿಗಳು, ಪರಿಮಾಣ(identity_ಕೀಲಿಗಳು));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, ಪರಿಮಾಣ(identity_file_userprovided));

	options.ಅಂಕೆ_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, ಪರಿಮಾಣ(certificate_files));
	memcpy(options.certificates, certificates, ಪರಿಮಾಣ(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    ಪರಿಮಾಣ(certificate_file_userprovided));
}

ಸ್ಥಿರ ಶೂನ್ಯ
main_sigchld_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಪೂರ್ಣಾಙ್ಕ save_errno = errno;
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯಾವತ್ ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
