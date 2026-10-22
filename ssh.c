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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/utsname.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <locale.h>

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/err.h>
#endif
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "clientloop.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "sshconnect.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "version.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "utf8.h"

#ifdef ENABLE_PKCS11
#അന്തര്ഭാവ "ssh-pkcs11.h"
#endif

ബാഹ്യ അക്ഷരം *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
സ്ഥിതം അക്ഷരം **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
പൂർണ്ണസംഖ്യ debug_flag = 0;

/* Flag indicating whether a tty should be requested */
പൂർണ്ണസംഖ്യ tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
സ്ഥിതം പൂർണ്ണസംഖ്യ ostdin_null_flag, osession_type, otty_flag, orequest_tty;
സ്ഥിതം പൂർണ്ണസംഖ്യ ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
അക്ഷരം *config = ശൂന്യ;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
അക്ഷരം *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
അക്ഷരം *forward_agent_sock_path = ശൂന്യ;

/* socket address the host resolves to */
ഘടന sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
ഘടന sshbuf *command;

/* # of replies received for global requests */
സ്ഥിതം പൂർണ്ണസംഖ്യ forward_confirms_pending = -1;

/* mux.c */
ബാഹ്യ പൂർണ്ണസംഖ്യ muxserver_sock;
ബാഹ്യ u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
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

സ്ഥിതം പൂർണ്ണസംഖ്യ ssh_session2(ഘടന ssh *, സ്ഥിരം ഘടന ssh_conn_info *);
സ്ഥിതം ശൂന്യം load_public_identity_files(സ്ഥിരം ഘടന ssh_conn_info *);
സ്ഥിതം ശൂന്യം main_sigchld_handler(പൂർണ്ണസംഖ്യ);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
സ്ഥിതം ശൂന്യം
tilde_expand_paths(അക്ഷരം **paths, u_int അക്കം_paths)
{
	u_int i;
	അക്ഷരം *cp;

	വേണ്ടി (i = 0; i < അക്കം_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		സ്വതന്ത്രം(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
സ്ഥിതം അക്ഷരം *
default_client_percent_expand(സ്ഥിരം അക്ഷരം *str,
    സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	തിരികെ percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (അക്ഷരം *)ശൂന്യ);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
സ്ഥിതം അക്ഷരം *
default_client_percent_dollar_expand(സ്ഥിരം അക്ഷരം *str,
    സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	അക്ഷരം *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (അക്ഷരം *)ശൂന്യ);
	എങ്കിൽ (ret == ശൂന്യ)
		fatal("invalid environment variable expansion");
	തിരികെ ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
സ്ഥിതം ഘടന addrinfo *
resolve_host(സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ port, പൂർണ്ണസംഖ്യ logerr, അക്ഷരം *cname, size_t clen)
{
	അക്ഷരം strport[NI_MAXSERV];
	സ്ഥിരം അക്ഷരം *errstr = ശൂന്യ;
	ഘടന addrinfo hints, *res;
	പൂർണ്ണസംഖ്യ gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	എങ്കിൽ (port <= 0)
		port = default_ssh_port();
	എങ്കിൽ (cname != ശൂന്യ)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, വലുപ്പം strport, "%d", port);
	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	എങ്കിൽ (cname != ശൂന്യ)
		hints.ai_flags = AI_CANONNAME;
	എങ്കിൽ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		എങ്കിൽ (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (cname != ശൂന്യ && res->ai_canonname != ശൂന്യ) {
		എങ്കിൽ (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} അല്ലെങ്കിൽ എങ്കിൽ (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			എങ്കിൽ (clen > 0)
				*cname = '\0';
		}
	}
	തിരികെ res;
}

/* Returns non-zero if name can only be an address and not a hostname */
സ്ഥിതം പൂർണ്ണസംഖ്യ
is_addr_fast(സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ (strchr(name, '%') != ശൂന്യ || strchr(name, ':') != ശൂന്യ ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
സ്ഥിതം പൂർണ്ണസംഖ്യ
is_addr(സ്ഥിരം അക്ഷരം *name)
{
	അക്ഷരം strport[NI_MAXSERV];
	ഘടന addrinfo hints, *res;

	എങ്കിൽ (is_addr_fast(name))
		തിരികെ 1;

	snprintf(strport, വലുപ്പം strport, "%u", default_ssh_port());
	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	എങ്കിൽ (getaddrinfo(name, strport, &hints, &res) != 0)
		തിരികെ 0;
	എങ്കിൽ (res == ശൂന്യ || res->ai_next != ശൂന്യ) {
		freeaddrinfo(res);
		തിരികെ 0;
	}
	freeaddrinfo(res);
	തിരികെ 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
സ്ഥിതം ഘടന addrinfo *
resolve_addr(സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ port, അക്ഷരം *caddr, size_t clen)
{
	അക്ഷരം addr[NI_MAXHOST], strport[NI_MAXSERV];
	ഘടന addrinfo hints, *res;
	പൂർണ്ണസംഖ്യ gaierr;

	എങ്കിൽ (port <= 0)
		port = default_ssh_port();
	snprintf(strport, വലുപ്പം strport, "%u", port);
	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	എങ്കിൽ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (res == ശൂന്യ) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (res->ai_next != ശൂന്യ) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		പോകുക fail;
	}
	എങ്കിൽ ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, വലുപ്പം(addr), ശൂന്യ, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		പോകുക fail;
	}
	എങ്കിൽ (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		എങ്കിൽ (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		തിരികെ ശൂന്യ;
	}
	തിരികെ res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_follow_cname(പൂർണ്ണസംഖ്യ direct, അക്ഷരം **namep, സ്ഥിരം അക്ഷരം *cname)
{
	പൂർണ്ണസംഖ്യ i;
	ഘടന allowed_cname *rule;

	എങ്കിൽ (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		തിരികെ 0;
	എങ്കിൽ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		തിരികെ 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	എങ്കിൽ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		തിരികെ 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	വേണ്ടി (i = 0; i < options.അക്കം_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		എങ്കിൽ (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			തുടരുക;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		സ്വതന്ത്രം(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		തിരികെ 1;
	}
	തിരികെ 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
സ്ഥിതം ഘടന addrinfo *
resolve_canonicalize(അക്ഷരം **hostp, പൂർണ്ണസംഖ്യ port)
{
	പൂർണ്ണസംഖ്യ i, direct, ndots;
	അക്ഷരം *cp, *fullhost, newname[NI_MAXHOST];
	ഘടന addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	എങ്കിൽ ((addrs = resolve_addr(*hostp, port,
	    newname, വലുപ്പം(newname))) != ശൂന്യ) {
		debug2_f("hostname %.100s is address", *hostp);
		എങ്കിൽ (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			സ്വതന്ത്രം(*hostp);
			*hostp = xstrdup(newname);
		}
		തിരികെ addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	എങ്കിൽ (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		തിരികെ ശൂന്യ;
	}

	എങ്കിൽ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		തിരികെ ശൂന്യ;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	എങ്കിൽ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		തിരികെ ശൂന്യ;

	/* If domain name is anchored, then resolve it now */
	എങ്കിൽ ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		എങ്കിൽ ((addrs = resolve_host(fullhost, port, 0,
		    newname, വലുപ്പം(newname))) != ശൂന്യ)
			പോകുക found;
		സ്വതന്ത്രം(fullhost);
		പോകുക notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	വേണ്ടി (cp = *hostp; *cp != '\0'; cp++) {
		എങ്കിൽ (*cp == '.')
			ndots++;
	}
	എങ്കിൽ (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		തിരികെ ശൂന്യ;
	}
	/* Attempt each supplied suffix */
	വേണ്ടി (i = 0; i < options.അക്കം_canonical_domains; i++) {
		എങ്കിൽ (strcasecmp(options.canonical_domains[i], "none") == 0)
			നിർത്തുക;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		എങ്കിൽ ((addrs = resolve_host(fullhost, port, 0,
		    newname, വലുപ്പം(newname))) == ശൂന്യ) {
			സ്വതന്ത്രം(fullhost);
			തുടരുക;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		എങ്കിൽ (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		സ്വതന്ത്രം(*hostp);
		*hostp = fullhost;
		തിരികെ addrs;
	}
 notfound:
	എങ്കിൽ (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	തിരികെ ശൂന്യ;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
സ്ഥിതം ശൂന്യം
check_load(പൂർണ്ണസംഖ്യ r, ഘടന sshkey **k, സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *message)
{
	അക്ഷരം *fp;

	തിരഞ്ഞെടുപ്പ് (r) {
	അവസ്ഥ 0:
		എങ്കിൽ (k == ശൂന്യ || *k == ശൂന്യ)
			തിരികെ;
		/* Check RSA keys size and discard if undersized */
		എങ്കിൽ ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			സ്വതന്ത്രം(*k);
			*k = ശൂന്യ;
			നിർത്തുക;
		}
		എങ്കിൽ ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		സ്വതന്ത്രം(fp);
		നിർത്തുക;
	അവസ്ഥ SSH_ERR_INTERNAL_ERROR:
	അവസ്ഥ SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	അവസ്ഥ SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		എങ്കിൽ (errno == ENOENT)
			നിർത്തുക;
		/* FALLTHROUGH */
	സ്ഥിരസ്ഥിതി:
		error_r(r, "load %s \"%s\"", message, path);
		നിർത്തുക;
	}
	എങ്കിൽ (k != ശൂന്യ && *k == ശൂന്യ)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
സ്ഥിതം ശൂന്യം
process_config_files(സ്ഥിരം അക്ഷരം *host_name, ഘടന passwd *pw,
    പൂർണ്ണസംഖ്യ final_pass, പൂർണ്ണസംഖ്യ *want_final_pass)
{
	അക്ഷരം *cmd, buf[PATH_MAX];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((cmd = sshbuf_dup_string(command)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	എങ്കിൽ (config != ശൂന്യ) {
		എങ്കിൽ (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} അല്ലെങ്കിൽ {
		r = snprintf(buf, വലുപ്പം buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		എങ്കിൽ (r > 0 && (size_t)r < വലുപ്പം(buf))
			(ശൂന്യം)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(ശൂന്യം)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	സ്വതന്ത്രം(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
സ്ഥിതം ശൂന്യം
set_addrinfo_port(ഘടന addrinfo *addrs, പൂർണ്ണസംഖ്യ port)
{
	ഘടന addrinfo *addr;

	വേണ്ടി (addr = addrs; addr != ശൂന്യ; addr = addr->ai_next) {
		തിരഞ്ഞെടുപ്പ് (addr->ai_family) {
		അവസ്ഥ AF_INET:
			((ഘടന sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			നിർത്തുക;
		അവസ്ഥ AF_INET6:
			((ഘടന sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			നിർത്തുക;
		}
	}
}

/*
 * Main program for the ssh client.
 */
പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ ac, അക്ഷരം **av)
{
	ഘടന ssh *ssh = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	പൂർണ്ണസംഖ്യ was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	പൂർണ്ണസംഖ്യ user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	അക്ഷരം *p, *cp, *വരി, *argv0, *logfile, *args;
	അക്ഷരം cname[NI_MAXHOST], thishost[NI_MAXHOST];
	ഘടന stat st;
	ഘടന passwd *pw;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind, optreset;
	ബാഹ്യ അക്ഷരം *optarg;
	ഘടന Forward fwd;
	ഘടന addrinfo *addrs = ശൂന്യ;
	size_t n, len;
	u_int j;
	ഘടന utsname utsname;
	ഘടന ssh_conn_info *cinfo = ശൂന്യ;

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
	saved_av = xcalloc(ac + 1, വലുപ്പം(*saved_av));
	വേണ്ടി (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ശൂന്യ;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	എങ്കിൽ (!pw) {
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
	എങ്കിൽ ((ssh = ssh_alloc_session_state()) == ശൂന്യ)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = ശൂന്യ;
	use_syslog = 0;
	logfile = ശൂന്യ;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	ആകുമ്പോൾ ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (opt) {
		അവസ്ഥ '1':
			fatal("SSH protocol v.1 is no longer supported");
			നിർത്തുക;
		അവസ്ഥ '2':
			/* Ignored */
			നിർത്തുക;
		അവസ്ഥ '4':
			options.address_family = AF_INET;
			നിർത്തുക;
		അവസ്ഥ '6':
			options.address_family = AF_INET6;
			നിർത്തുക;
		അവസ്ഥ 'n':
			options.stdin_null = 1;
			നിർത്തുക;
		അവസ്ഥ 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			നിർത്തുക;
		അവസ്ഥ 'x':
			options.forward_x11 = 0;
			നിർത്തുക;
		അവസ്ഥ 'X':
			options.forward_x11 = 1;
			നിർത്തുക;
		അവസ്ഥ 'y':
			use_syslog = 1;
			നിർത്തുക;
		അവസ്ഥ 'E':
			logfile = optarg;
			നിർത്തുക;
		അവസ്ഥ 'G':
			config_test = 1;
			നിർത്തുക;
		അവസ്ഥ 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			നിർത്തുക;
		അവസ്ഥ 'Z':
			dump_pubkeys = 1;
			നിർത്തുക;
		അവസ്ഥ 'g':
			options.fwd_opts.gateway_ports = 1;
			നിർത്തുക;
		അവസ്ഥ 'O':
			എങ്കിൽ (options.stdio_forward_host != ശൂന്യ)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			അല്ലെങ്കിൽ എങ്കിൽ (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			എങ്കിൽ (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			അല്ലെങ്കിൽ
				fatal("Invalid multiplex command.");
			നിർത്തുക;
		അവസ്ഥ 'P':
			എങ്കിൽ (options.tag == ശൂന്യ)
				options.tag = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'Q':
			cp = ശൂന്യ;
			എങ്കിൽ (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				വേണ്ടി (n = 0; n < len; n++)
					എങ്കിൽ (cp[n] == ',')
						cp[n] = '\n';
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			എങ്കിൽ (cp == ശൂന്യ)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			സ്വതന്ത്രം(cp);
			exit(0);
			നിർത്തുക;
		അവസ്ഥ 'a':
			options.forward_agent = 0;
			നിർത്തുക;
		അവസ്ഥ 'A':
			options.forward_agent = 1;
			നിർത്തുക;
		അവസ്ഥ 'k':
			options.gss_deleg_creds = 0;
			നിർത്തുക;
		അവസ്ഥ 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			നിർത്തുക;
		അവസ്ഥ 'i':
			p = tilde_expand_filename(optarg, getuid());
			എങ്കിൽ (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			അല്ലെങ്കിൽ
				add_identity_file(&options, ശൂന്യ, p, 1);
			സ്വതന്ത്രം(p);
			നിർത്തുക;
		അവസ്ഥ 'I':
#ifdef ENABLE_PKCS11
			സ്വതന്ത്രം(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#അല്ലെങ്കിൽ
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			നിർത്തുക;
		അവസ്ഥ 'J':
			എങ്കിൽ (options.jump_host != ശൂന്യ) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			എങ്കിൽ (options.proxy_command != ശൂന്യ)
				fatal("Cannot specify -J with ProxyCommand");
			എങ്കിൽ (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			നിർത്തുക;
		അവസ്ഥ 't':
			എങ്കിൽ (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			അല്ലെങ്കിൽ
				options.request_tty = REQUEST_TTY_YES;
			നിർത്തുക;
		അവസ്ഥ 'v':
			എങ്കിൽ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} അല്ലെങ്കിൽ {
				എങ്കിൽ (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			നിർത്തുക;
		അവസ്ഥ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			നിർത്തുക;
		അവസ്ഥ 'w':
			എങ്കിൽ (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			എങ്കിൽ (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			നിർത്തുക;
		അവസ്ഥ 'W':
			എങ്കിൽ (options.stdio_forward_host != ശൂന്യ)
				fatal("stdio forward already specified");
			എങ്കിൽ (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			എങ്കിൽ (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				സ്വതന്ത്രം(fwd.connect_host);
			} അല്ലെങ്കിൽ {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			നിർത്തുക;
		അവസ്ഥ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			നിർത്തുക;
		അവസ്ഥ 'e':
			എങ്കിൽ (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			അല്ലെങ്കിൽ എങ്കിൽ (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			അല്ലെങ്കിൽ {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			നിർത്തുക;
		അവസ്ഥ 'c':
			എങ്കിൽ (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			സ്വതന്ത്രം(options.ciphers);
			options.ciphers = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'm':
			എങ്കിൽ (mac_valid(optarg)) {
				സ്വതന്ത്രം(options.macs);
				options.macs = xstrdup(optarg);
			} അല്ലെങ്കിൽ {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			നിർത്തുക;
		അവസ്ഥ 'M':
			എങ്കിൽ (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			അല്ലെങ്കിൽ
				options.control_master = SSHCTL_MASTER_YES;
			നിർത്തുക;
		അവസ്ഥ 'p':
			എങ്കിൽ (options.port == -1) {
				options.port = a2port(optarg);
				എങ്കിൽ (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			നിർത്തുക;
		അവസ്ഥ 'l':
			എങ്കിൽ (options.user == ശൂന്യ) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			നിർത്തുക;

		അവസ്ഥ 'L':
			എങ്കിൽ (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			അല്ലെങ്കിൽ {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			നിർത്തുക;

		അവസ്ഥ 'R':
			എങ്കിൽ (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} അല്ലെങ്കിൽ {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			നിർത്തുക;

		അവസ്ഥ 'D':
			എങ്കിൽ (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} അല്ലെങ്കിൽ {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			നിർത്തുക;

		അവസ്ഥ 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#അല്ലെങ്കിൽ
			error("Compression not supported, disabling.");
#endif
			നിർത്തുക;
		അവസ്ഥ 'N':
			എങ്കിൽ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			നിർത്തുക;
		അവസ്ഥ 'T':
			options.request_tty = REQUEST_TTY_NO;
			നിർത്തുക;
		അവസ്ഥ 'o':
			വരി = xstrdup(optarg);
			എങ്കിൽ (process_config_വരി(&options, pw,
			    host ? host : "", host ? host : "", "", വരി,
			    "command-line", 0, ശൂന്യ, SSHCONF_USERCONF) != 0)
				exit(255);
			സ്വതന്ത്രം(വരി);
			നിർത്തുക;
		അവസ്ഥ 's':
			എങ്കിൽ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			നിർത്തുക;
		അവസ്ഥ 'S':
			സ്വതന്ത്രം(options.control_path);
			options.control_path = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'b':
			options.bind_address = optarg;
			നിർത്തുക;
		അവസ്ഥ 'B':
			options.bind_interface = optarg;
			നിർത്തുക;
		അവസ്ഥ 'F':
			config = optarg;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}

	എങ്കിൽ (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	എങ്കിൽ (ac > 0 && !host) {
		പൂർണ്ണസംഖ്യ tport;
		അക്ഷരം *tuser;
		തിരഞ്ഞെടുപ്പ് (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		അവസ്ഥ -1:
			usage();
			നിർത്തുക;
		അവസ്ഥ 0:
			എങ്കിൽ (options.user == ശൂന്യ) {
				options.user = tuser;
				tuser = ശൂന്യ;
				user_on_commandline = 1;
			}
			സ്വതന്ത്രം(tuser);
			എങ്കിൽ (options.port == -1 && tport != -1)
				options.port = tport;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			എങ്കിൽ (cp != ശൂന്യ) {
				എങ്കിൽ (cp == p)
					usage();
				എങ്കിൽ (options.user == ശൂന്യ) {
					options.user = p;
					p = ശൂന്യ;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				സ്വതന്ത്രം(p);
			} അല്ലെങ്കിൽ
				host = p;
			നിർത്തുക;
		}
		എങ്കിൽ (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			പോകുക again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	എങ്കിൽ (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	എങ്കിൽ (options.user != ശൂന്യ && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	എങ്കിൽ (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	എങ്കിൽ ((command = sshbuf_new()) == ശൂന്യ)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	എങ്കിൽ (!ac) {
		/* No command specified - execute shell on a tty. */
		എങ്കിൽ (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} അല്ലെങ്കിൽ {
		/* A command has been specified.  Store it into the buffer. */
		വേണ്ടി (i = 0; i < ac; i++) {
			എങ്കിൽ ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	എങ്കിൽ (use_syslog && logfile != ശൂന്യ)
		fatal("Can't specify both -y and -E");
	എങ്കിൽ (logfile != ശൂന്യ)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	എങ്കിൽ (uname(&utsname) != 0) {
		memset(&utsname, 0, വലുപ്പം(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", വലുപ്പം(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	സ്വതന്ത്രം(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	എങ്കിൽ (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	എങ്കിൽ (options.hostname != ശൂന്യ) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (അക്ഷരം *)ശൂന്യ);
		സ്വതന്ത്രം(host);
		host = cp;
		സ്വതന്ത്രം(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	എങ്കിൽ ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	എങ്കിൽ (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	എങ്കിൽ (addrs == ശൂന്യ && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		എങ്കിൽ ((addrs = resolve_host(host, options.port,
		    direct, cname, വലുപ്പം(cname))) == ശൂന്യ) {
			/* Don't fatal proxied host names not in the DNS */
			എങ്കിൽ (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} അല്ലെങ്കിൽ
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	എങ്കിൽ (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	എങ്കിൽ (want_final_pass) {
		debug("re-parsing configuration");
		സ്വതന്ത്രം(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ശൂന്യ);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		എങ്കിൽ (addrs != ശൂന്യ && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	എങ്കിൽ (fill_default_options(&options) != 0)
		cleanup_exit(255);

	എങ്കിൽ (options.user == ശൂന്യ) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	എങ്കിൽ (options.jump_host != ശൂന്യ) {
		അക്ഷരം port_s[8];
		സ്ഥിരം അക്ഷരം *jumpuser = options.jump_user, *sshbin = argv0;
		പൂർണ്ണസംഖ്യ port = options.port, jumpport = options.jump_port;

		എങ്കിൽ (port <= 0)
			port = default_ssh_port();
		എങ്കിൽ (jumpport <= 0)
			jumpport = default_ssh_port();
		എങ്കിൽ (jumpuser == ശൂന്യ)
			jumpuser = options.user;
		എങ്കിൽ (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		എങ്കിൽ (strchr(argv0, '/') != ശൂന്യ && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		എങ്കിൽ (options.proxy_command != ശൂന്യ &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, വലുപ്പം(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ശൂന്യ ? "" : " -l ",
		    options.jump_user == ശൂന്യ ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ശൂന്യ ? "" : " -J ",
		    options.jump_extra == ശൂന്യ ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ശൂന്യ ? "" : " -F ",
		    config == ശൂന്യ ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	എങ്കിൽ (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	എങ്കിൽ (options.host_താക്കോൽ_alias != ശൂന്യ)
		lowercase(options.host_താക്കോൽ_alias);
	എങ്കിൽ (options.proxy_command != ശൂന്യ &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	എങ്കിൽ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		എങ്കിൽ (options.control_persist && options.control_path != ശൂന്യ) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (sshbuf_len(command) != 0 ||
		    options.remote_command != ശൂന്യ ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	എങ്കിൽ (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	എങ്കിൽ (sshbuf_len(command) != 0 && options.remote_command != ശൂന്യ)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	എങ്കിൽ (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ശൂന്യ &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	വേണ്ടി (j = 0; j < options.അക്കം_log_verbose; j++) {
		എങ്കിൽ (strcasecmp(options.log_verbose[j], "none") == 0)
			നിർത്തുക;
		log_verbose_add(options.log_verbose[j]);
	}

	എങ്കിൽ (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	എങ്കിൽ (sshbuf_len(command) == 0 && options.remote_command == ശൂന്യ)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	എങ്കിൽ (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	എങ്കിൽ ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		എങ്കിൽ (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, വലുപ്പം(*cinfo));
	എങ്കിൽ (gethostname(thishost, വലുപ്പം(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_താക്കോൽ_alias ?
	    options.host_താക്കോൽ_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ശൂന്യ ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	എങ്കിൽ (!user_on_commandline && !user_was_default) {
		എങ്കിൽ ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (അക്ഷരം *)ശൂന്യ)) == ശൂന്യ)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		സ്വതന്ത്രം(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	എങ്കിൽ ((user_on_commandline || user_expanded) &&
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
	എങ്കിൽ (options.remote_command != ശൂന്യ) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		സ്വതന്ത്രം(cp);
		എങ്കിൽ ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	എങ്കിൽ (options.control_path != ശൂന്യ) {
		cp = tilde_expand_filename(options.control_path, getuid());
		സ്വതന്ത്രം(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		സ്വതന്ത്രം(cp);
	}

	എങ്കിൽ (options.identity_agent != ശൂന്യ) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		സ്വതന്ത്രം(p);
		സ്വതന്ത്രം(options.identity_agent);
		options.identity_agent = cp;
	}

	വേണ്ടി (j = 0; j < options.അക്കം_revoked_host_താക്കോലുകൾ; j++) {
		p = tilde_expand_filename(options.revoked_host_താക്കോലുകൾ[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		സ്വതന്ത്രം(p);
		സ്വതന്ത്രം(options.revoked_host_താക്കോലുകൾ[j]);
		options.revoked_host_താക്കോലുകൾ[j] = cp;
	}

	എങ്കിൽ (options.forward_agent_sock_path != ശൂന്യ) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		സ്വതന്ത്രം(p);
		സ്വതന്ത്രം(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		എങ്കിൽ (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			എങ്കിൽ (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	എങ്കിൽ (options.version_addendum != ശൂന്യ) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		സ്വതന്ത്രം(options.version_addendum);
		options.version_addendum = cp;
	}

	എങ്കിൽ (options.അക്കം_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		എങ്കിൽ (options.അക്കം_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		സ്വതന്ത്രം(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ശൂന്യ;
		options.അക്കം_system_hostfiles = 0;
	}

	എങ്കിൽ (options.അക്കം_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		എങ്കിൽ (options.അക്കം_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		സ്വതന്ത്രം(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ശൂന്യ;
		options.അക്കം_user_hostfiles = 0;
	}
	വേണ്ടി (j = 0; j < options.അക്കം_user_hostfiles; j++) {
		എങ്കിൽ (options.user_hostfiles[j] == ശൂന്യ)
			തുടരുക;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		എങ്കിൽ (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		സ്വതന്ത്രം(options.user_hostfiles[j]);
		സ്വതന്ത്രം(cp);
		options.user_hostfiles[j] = p;
	}

	വേണ്ടി (j = 0; j < options.അക്കം_setenv; j++) {
		അക്ഷരം *name = options.setenv[j], *മൂല്യം;

		എങ്കിൽ (name == ശൂന്യ)
			തുടരുക;
		/* Expand only the value portion, not the variable name. */
		എങ്കിൽ ((മൂല്യം = strchr(name, '=')) == ശൂന്യ) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*മൂല്യം++ = '\0';
		cp = default_client_percent_dollar_expand(മൂല്യം, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		എങ്കിൽ (strcmp(മൂല്യം, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, മൂല്യം, cp);
		}
		സ്വതന്ത്രം(options.setenv[j]);
		സ്വതന്ത്രം(cp);
		options.setenv[j] = p;
	}

	വേണ്ടി (i = 0; i < options.അക്കം_local_forwards; i++) {
		എങ്കിൽ (options.local_forwards[i].listen_path != ശൂന്യ) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			എങ്കിൽ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			സ്വതന്ത്രം(cp);
		}
		എങ്കിൽ (options.local_forwards[i].connect_path != ശൂന്യ) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			എങ്കിൽ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			സ്വതന്ത്രം(cp);
		}
	}

	വേണ്ടി (i = 0; i < options.അക്കം_remote_forwards; i++) {
		എങ്കിൽ (options.remote_forwards[i].listen_path != ശൂന്യ) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			എങ്കിൽ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			സ്വതന്ത്രം(cp);
		}
		എങ്കിൽ (options.remote_forwards[i].connect_path != ശൂന്യ) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			എങ്കിൽ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			സ്വതന്ത്രം(cp);
		}
	}

	എങ്കിൽ (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	എങ്കിൽ (options.sk_provider != ശൂന്യ && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		എങ്കിൽ ((cp = getenv(options.sk_provider + 1)) == ശൂന്യ) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			സ്വതന്ത്രം(options.sk_provider);
			options.sk_provider = ശൂന്യ;
		} അല്ലെങ്കിൽ {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			സ്വതന്ത്രം(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	എങ്കിൽ (muxclient_command != 0 && options.control_path == ശൂന്യ)
		fatal("No ControlPath specified for \"-O\" command");
	എങ്കിൽ (options.control_path != ശൂന്യ) {
		പൂർണ്ണസംഖ്യ sock;
		എങ്കിൽ ((sock = muxclient(options.control_path)) >= 0) {
			എങ്കിൽ (ssh_packet_set_connection(ssh, sock, sock) == ശൂന്യ)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			പോകുക skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	എങ്കിൽ (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		എങ്കിൽ (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} അല്ലെങ്കിൽ {
			cp = options.identity_agent;
			/* legacy (limited) format */
			എങ്കിൽ (cp[0] == '$' && cp[1] != '{') {
				എങ്കിൽ (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				എങ്കിൽ ((p = getenv(cp + 1)) == ശൂന്യ)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				അല്ലെങ്കിൽ
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} അല്ലെങ്കിൽ {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	എങ്കിൽ (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	എങ്കിൽ (addrs == ശൂന്യ && options.proxy_command == ശൂന്യ) {
		debug2("resolving \"%s\" port %d", host, options.port);
		എങ്കിൽ ((addrs = resolve_host(host, options.port, 1,
		    cname, വലുപ്പം(cname))) == ശൂന്യ)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	എങ്കിൽ (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	അല്ലെങ്കിൽ
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	വേണ്ടി (j = 0; j < options.അക്കം_channel_timeouts; j++) {
		ഇരട്ട timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		എങ്കിൽ (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		സ്വതന്ത്രം(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	എങ്കിൽ (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_എണ്ണം_max);

	എങ്കിൽ (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.താക്കോലുകൾ = ശൂന്യ;
	എങ്കിൽ (options.hostbased_authentication) {
		പൂർണ്ണസംഖ്യ loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.താക്കോലുകൾ = xcalloc(sensitive_data.nkeys,
		    വലുപ്പം(*sensitive_data.താക്കോലുകൾ));

		/* XXX check errors? */
#define L_PUBKEY(p,o) ചെയ്യുക { \
	എങ്കിൽ ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.താക്കോലുകൾ[o]), ശൂന്യ), \
	    &(sensitive_data.താക്കോലുകൾ[o]), p, "hostbased pubkey"); \
	എങ്കിൽ (sensitive_data.താക്കോലുകൾ[o] != ശൂന്യ) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ആകുമ്പോൾ (0)
#define L_CERT(p,o) ചെയ്യുക { \
	എങ്കിൽ ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.താക്കോലുകൾ[o])), \
	    &(sensitive_data.താക്കോലുകൾ[o]), p, "hostbased cert"); \
	എങ്കിൽ (sensitive_data.താക്കോലുകൾ[o] != ശൂന്യ) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ആകുമ്പോൾ (0)

		എങ്കിൽ (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_താക്കോൽ_FILE, 0);
			L_CERT(PATH_HOST_ED25519_താക്കോൽ_FILE, 1);
			L_CERT(PATH_HOST_RSA_താക്കോൽ_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_താക്കോൽ_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_താക്കോൽ_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_താക്കോൽ_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_താക്കോൽ_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_താക്കോൽ_FILE, 7);
			എങ്കിൽ (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	എങ്കിൽ (options.forward_agent && options.forward_agent_sock_path != ശൂന്യ) {
		cp = options.forward_agent_sock_path;
		എങ്കിൽ (cp[0] == '$') {
			എങ്കിൽ (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			എങ്കിൽ ((p = getenv(cp + 1)) != ശൂന്യ)
				forward_agent_sock_path = xstrdup(p);
			അല്ലെങ്കിൽ
				options.forward_agent = 0;
			സ്വതന്ത്രം(cp);
		} അല്ലെങ്കിൽ {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.അക്കം_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.അക്കം_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	എങ്കിൽ (sensitive_data.nkeys != 0) {
		വേണ്ടി (i = 0; i < sensitive_data.nkeys; i++) {
			എങ്കിൽ (sensitive_data.താക്കോലുകൾ[i] != ശൂന്യ) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.താക്കോലുകൾ[i]);
				sensitive_data.താക്കോലുകൾ[i] = ശൂന്യ;
			}
		}
		സ്വതന്ത്രം(sensitive_data.താക്കോലുകൾ);
	}
	വേണ്ടി (i = 0; i < options.അക്കം_identity_files; i++) {
		സ്വതന്ത്രം(options.identity_files[i]);
		options.identity_files[i] = ശൂന്യ;
		എങ്കിൽ (options.identity_താക്കോലുകൾ[i]) {
			sshkey_free(options.identity_താക്കോലുകൾ[i]);
			options.identity_താക്കോലുകൾ[i] = ശൂന്യ;
		}
	}
	വേണ്ടി (i = 0; i < options.അക്കം_certificate_files; i++) {
		സ്വതന്ത്രം(options.certificate_files[i]);
		options.certificate_files[i] = ശൂന്യ;
	}

#ifdef ENABLE_PKCS11
	(ശൂന്യം)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	എങ്കിൽ (addrs != ശൂന്യ)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	എങ്കിൽ (options.control_path != ശൂന്യ && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	തിരികെ exit_status;
}

സ്ഥിതം ശൂന്യം
control_persist_detach(ശൂന്യം)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	തിരഞ്ഞെടുപ്പ് ((pid = fork())) {
	അവസ്ഥ -1:
		fatal_f("fork: %s", strerror(errno));
	അവസ്ഥ 0:
		/* Child: master process continues mainloop */
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
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
		(ശൂന്യം)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	എങ്കിൽ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
സ്ഥിതം ശൂന്യം
fork_postauth(ശൂന്യം)
{
	എങ്കിൽ (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	എങ്കിൽ (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	എങ്കിൽ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

സ്ഥിതം ശൂന്യം
forwarding_success(ശൂന്യം)
{
	എങ്കിൽ (forward_confirms_pending == -1)
		തിരികെ;
	എങ്കിൽ (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		എങ്കിൽ (options.fork_after_authentication)
			fork_postauth();
	} അല്ലെങ്കിൽ {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

ഘടന rfwd_confirm_ctx {
	പൂർണ്ണസംഖ്യ fid;
};

/* Callback for remote forward global requests */
സ്ഥിതം ശൂന്യം
ssh_confirm_remote_forward(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type, uint32_t seq, ശൂന്യം *ctxt)
{
	ഘടന rfwd_confirm_ctx *rctx = (ഘടന rfwd_confirm_ctx *)ctxt;
	ഘടന Forward *rfwd;
	u_int port;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (rctx->fid < 0 || rctx->fid >= options.അക്കം_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, വലുപ്പം(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_സന്ദേശം_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	എങ്കിൽ (rfwd->listen_path == ശൂന്യ && rfwd->listen_port == 0) {
		എങ്കിൽ (type == SSH2_സന്ദേശം_REQUEST_SUCCESS) {
			എങ്കിൽ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			എങ്കിൽ (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_സന്ദേശം_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} അല്ലെങ്കിൽ {
				rfwd->allocated_port = (പൂർണ്ണസംഖ്യ)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} അല്ലെങ്കിൽ {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	എങ്കിൽ (type == SSH2_സന്ദേശം_REQUEST_FAILURE) {
		എങ്കിൽ (options.exit_on_forward_failure) {
			എങ്കിൽ (rfwd->listen_path != ശൂന്യ)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			അല്ലെങ്കിൽ
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (rfwd->listen_path != ശൂന്യ)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			അല്ലെങ്കിൽ
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

സ്ഥിതം ശൂന്യം
client_cleanup_stdio_fwd(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ force, ശൂന്യം *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

സ്ഥിതം ശൂന്യം
ssh_stdio_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ success, ശൂന്യം *arg)
{
	എങ്കിൽ (!success)
		fatal("stdio forwarding failed");
}

സ്ഥിതം ശൂന്യം
ssh_tun_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ success, ശൂന്യം *arg)
{
	എങ്കിൽ (!success) {
		error("Tunnel forwarding failed");
		എങ്കിൽ (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

സ്ഥിതം ശൂന്യം
ssh_init_stdio_forwarding(ഘടന ssh *ssh)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ in, out;

	എങ്കിൽ (options.stdio_forward_host == ശൂന്യ)
		തിരികെ;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	എങ്കിൽ ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	എങ്കിൽ ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == ശൂന്യ)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, ശൂന്യ);
}

സ്ഥിതം ശൂന്യം
ssh_init_forward_permissions(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *what, അക്ഷരം **opens,
    u_int അക്കം_opens)
{
	u_int i;
	പൂർണ്ണസംഖ്യ port;
	അക്ഷരം *addr, *arg, *oarg;
	പൂർണ്ണസംഖ്യ where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	എങ്കിൽ (അക്കം_opens == 0)
		തിരികെ; /* permit any */

	/* handle keywords: "any" / "none" */
	എങ്കിൽ (അക്കം_opens == 1 && strcmp(opens[0], "any") == 0)
		തിരികെ;
	എങ്കിൽ (അക്കം_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		തിരികെ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	വേണ്ടി (i = 0; i < അക്കം_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		എങ്കിൽ (addr == ശൂന്യ)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		എങ്കിൽ (arg == ശൂന്യ || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		സ്വതന്ത്രം(oarg);
	}
}

സ്ഥിതം ശൂന്യം
ssh_init_forwarding(ഘടന ssh *ssh, അക്ഷരം **ifname)
{
	പൂർണ്ണസംഖ്യ success = 0;
	പൂർണ്ണസംഖ്യ i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.അക്കം_permitted_remote_opens);

	എങ്കിൽ (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	വേണ്ടി (i = 0; i < options.അക്കം_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != ശൂന്യ) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == ശൂന്യ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != ശൂന്യ) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	എങ്കിൽ (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	എങ്കിൽ (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	വേണ്ടി (i = 0; i < options.അക്കം_remote_forwards; i++) {
		ഘടന rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != ശൂന്യ) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == ശൂന്യ) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != ശൂന്യ) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		എങ്കിൽ ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, വലുപ്പം(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} അല്ലെങ്കിൽ എങ്കിൽ (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		അല്ലെങ്കിൽ
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	എങ്കിൽ (options.tun_open != SSH_TUNMODE_NO) {
		എങ്കിൽ ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ശൂന്യ)) != ശൂന്യ)
			forward_confirms_pending++;
		അല്ലെങ്കിൽ എങ്കിൽ (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		അല്ലെങ്കിൽ
			error("Could not request tunnel forwarding.");
	}
	എങ്കിൽ (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

സ്ഥിതം ശൂന്യം
check_agent_present(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		എങ്കിൽ ((r = ssh_get_authentication_socket(ശൂന്യ)) != 0) {
			options.forward_agent = 0;
			എങ്കിൽ (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

സ്ഥിതം ശൂന്യം
ssh_session2_setup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ success, ശൂന്യം *arg)
{
	ബാഹ്യ അക്ഷരം **environ;
	സ്ഥിരം അക്ഷരം *display, *term;
	അക്ഷരം *proto = ശൂന്യ, *data = ശൂന്യ;

	എങ്കിൽ (!success)
		തിരികെ; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	എങ്കിൽ (display == ശൂന്യ && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	എങ്കിൽ (options.forward_x11 && client_x11_get_proto(ssh, display,
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
	എങ്കിൽ (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	എങ്കിൽ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.അക്കം_setenv)) == ശൂന്യ || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    ശൂന്യ, fileno(stdin), command, environ);
}

/* open new channel for a session */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_session2_open(ഘടന ssh *ssh)
{
	Channel *c;
	പൂർണ്ണസംഖ്യ window, packetmax, in, out, err;

	എങ്കിൽ (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} അല്ലെങ്കിൽ {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	എങ്കിൽ (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	എങ്കിൽ (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	എങ്കിൽ (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	എങ്കിൽ (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, ശൂന്യ);

	തിരികെ c->self;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_session2(ഘടന ssh *ssh, സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	പൂർണ്ണസംഖ്യ r, id = -1;
	അക്ഷരം *cp, *tun_fwd_ifname = ശൂന്യ;

	/* XXX should be pre-session */
	എങ്കിൽ (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	എങ്കിൽ (options.local_command != ശൂന്യ) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == ശൂന്യ ? "NONE" : tun_fwd_ifname,
		    (അക്ഷരം *)ശൂന്യ);
		debug3("expanded LocalCommand: %s", options.local_command);
		സ്വതന്ത്രം(cp);
	}

	/* Start listening for multiplex clients */
	എങ്കിൽ (!ssh_packet_get_mux(ssh))
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
	എങ്കിൽ (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		എങ്കിൽ ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ശൂന്യ))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	എങ്കിൽ (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	എങ്കിൽ (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	എങ്കിൽ (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	എങ്കിൽ (options.local_command != ശൂന്യ &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	എങ്കിൽ (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	എങ്കിൽ (options.fork_after_authentication) {
		എങ്കിൽ (options.exit_on_forward_failure &&
		    options.അക്കം_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} അല്ലെങ്കിൽ
			fork_postauth();
	}

	തിരികെ client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
സ്ഥിതം ശൂന്യം
load_public_identity_files(സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	അക്ഷരം *filename, *cp;
	ഘടന sshkey *പൊതു;
	പൂർണ്ണസംഖ്യ i;
	u_int n_ids, n_certs;
	അക്ഷരം *identity_files[SSH_MAX_IDENTITY_FILES];
	ഘടന sshkey *identity_താക്കോലുകൾ[SSH_MAX_IDENTITY_FILES];
	പൂർണ്ണസംഖ്യ identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	അക്ഷരം *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ഘടന sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	പൂർണ്ണസംഖ്യ certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	ഘടന sshkey **താക്കോലുകൾ = ശൂന്യ;
	അക്ഷരം **comments = ശൂന്യ;
	പൂർണ്ണസംഖ്യ nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, വലുപ്പം(identity_files));
	memset(identity_താക്കോലുകൾ, 0, വലുപ്പം(identity_താക്കോലുകൾ));
	memset(identity_file_userprovided, 0,
	    വലുപ്പം(identity_file_userprovided));
	memset(certificate_files, 0, വലുപ്പം(certificate_files));
	memset(certificates, 0, വലുപ്പം(certificates));
	memset(certificate_file_userprovided, 0,
	    വലുപ്പം(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	എങ്കിൽ (options.pkcs11_provider != ശൂന്യ &&
	    options.അക്കം_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, ശൂന്യ,
	    &താക്കോലുകൾ, &comments)) > 0) {
		വേണ്ടി (i = 0; i < nkeys; i++) {
			എങ്കിൽ (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(താക്കോലുകൾ[i]);
				സ്വതന്ത്രം(comments[i]);
				തുടരുക;
			}
			identity_താക്കോലുകൾ[n_ids] = താക്കോലുകൾ[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		സ്വതന്ത്രം(താക്കോലുകൾ);
		സ്വതന്ത്രം(comments);
	}
#endif /* ENABLE_PKCS11 */
	വേണ്ടി (i = 0; i < options.അക്കം_identity_files; i++) {
		എങ്കിൽ (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			സ്വതന്ത്രം(options.identity_files[i]);
			options.identity_files[i] = ശൂന്യ;
			തുടരുക;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		സ്വതന്ത്രം(cp);
		check_load(sshkey_load_public(filename, &പൊതു, ശൂന്യ),
		    &പൊതു, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    പൊതു ? പൊതു->type : -1);
		സ്വതന്ത്രം(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_താക്കോലുകൾ[n_ids] = പൊതു;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		എങ്കിൽ (++n_ids >= SSH_MAX_IDENTITY_FILES)
			തുടരുക;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		എങ്കിൽ (options.അക്കം_certificate_files != 0)
			തുടരുക;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &പൊതു, ശൂന്യ),
		    &പൊതു, filename, "identity pubkey");
		എങ്കിൽ (പൊതു == ശൂന്യ) {
			സ്വതന്ത്രം(cp);
			തുടരുക;
		}
		എങ്കിൽ (!sshkey_is_cert(പൊതു)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(പൊതു));
			sshkey_free(പൊതു);
			സ്വതന്ത്രം(cp);
			തുടരുക;
		}
		സ്വതന്ത്രം(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_താക്കോലുകൾ[n_ids] = പൊതു;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	എങ്കിൽ (options.അക്കം_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	വേണ്ടി (i = 0; i < options.അക്കം_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		സ്വതന്ത്രം(cp);

		check_load(sshkey_load_public(filename, &പൊതു, ശൂന്യ),
		    &പൊതു, filename, "identity cert");
		സ്വതന്ത്രം(options.certificate_files[i]);
		options.certificate_files[i] = ശൂന്യ;
		എങ്കിൽ (പൊതു == ശൂന്യ) {
			സ്വതന്ത്രം(filename);
			തുടരുക;
		}
		എങ്കിൽ (!sshkey_is_cert(പൊതു)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(പൊതു));
			sshkey_free(പൊതു);
			സ്വതന്ത്രം(filename);
			തുടരുക;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = പൊതു;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.അക്കം_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, വലുപ്പം(identity_files));
	memcpy(options.identity_താക്കോലുകൾ, identity_താക്കോലുകൾ, വലുപ്പം(identity_താക്കോലുകൾ));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, വലുപ്പം(identity_file_userprovided));

	options.അക്കം_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, വലുപ്പം(certificate_files));
	memcpy(options.certificates, certificates, വലുപ്പം(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    വലുപ്പം(certificate_file_userprovided));
}

സ്ഥിതം ശൂന്യം
main_sigchld_handler(പൂർണ്ണസംഖ്യ sig)
{
	പൂർണ്ണസംഖ്യ save_errno = errno;
	pid_t pid;
	പൂർണ്ണസംഖ്യ status;

	ആകുമ്പോൾ ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
