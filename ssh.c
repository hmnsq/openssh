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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಆದರೆ_ಅಂತ್ಯ
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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಆದರೆ_ಅಂತ್ಯ

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
ಸ್ಥಿರ ಅಕ್ಷರ **saved_av;
#ಆದರೆ_ಅಂತ್ಯ

/* Flag indicating whether debug mode is on.  May be set on the command line. */
ಪೂರ್ಣಾಂಕ debug_flag = 0;

/* Flag indicating whether a tty should be requested */
ಪೂರ್ಣಾಂಕ tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ostdin_null_flag, osession_type, otty_flag, orequest_tty;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
ಅಕ್ಷರ *config = ಖಾಲಿ;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ಅಕ್ಷರ *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
ಅಕ್ಷರ *forward_agent_sock_ಮಾರ್ಗ = ಖಾಲಿ;

/* socket address the host resolves to */
ರಚನೆ sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_ದತ್ತಾಂಶ;

/* command to be executed */
ರಚನೆ sshbuf *command;

/* # of replies received for global requests */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ forward_confirms_pending = -1;

/* mux.c */
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ muxserver_sock;
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
	ನಿರ್ಗಮಿಸು(255);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ssh_session2(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *);
ಸ್ಥಿರ ಶೂನ್ಯ ತುಂಬು_ಬಹಿರಂಗ_ತಟಸ್ಥ_files(ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *);
ಸ್ಥಿರ ಶೂನ್ಯ main_sigchld_handler(ಪೂರ್ಣಾಂಕ);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
ಸ್ಥಿರ ಶೂನ್ಯ
tilde_expand_paths(ಅಕ್ಷರ **paths, u_int ಅಂಕೆ_paths)
{
	u_int i;
	ಅಕ್ಷರ *cp;

	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		ಬಿಡುಗಡೆ(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
default_client_percent_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಹಿಂತಿರುಗಿ percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು(cinfo),
	    (ಅಕ್ಷರ *)ಖಾಲಿ);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
default_client_percent_dollar_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಅಕ್ಷರ *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು(cinfo),
	    (ಅಕ್ಷರ *)ಖಾಲಿ);
	ಆದರೆ (ret == ಖಾಲಿ)
		fatal("invalid environment variable expansion");
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ರಚನೆ addrinfo *
resolve_host(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಪೂರ್ಣಾಂಕ logerr, ಅಕ್ಷರ *cname, ಗಾತ್ರ_t clen)
{
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = ಖಾಲಿ;
	ರಚನೆ addrinfo hints, *res;
	ಪೂರ್ಣಾಂಕ gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	ಆದರೆ (ಪೋರ್ಟ್ <= 0)
		ಪೋರ್ಟ್ = default_ssh_ಪೋರ್ಟ್();
	ಆದರೆ (cname != ಖಾಲಿ)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, ಪೋರ್ಟ್);

	snprintf(strport, ಗಾತ್ರ strport, "%d", ಪೋರ್ಟ್);
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = options.ವಿಳಾಸ_family == -1 ?
	    AF_UNSPEC : options.ವಿಳಾಸ_family;
	hints.ai_socktype = SOCK_STREAM;
	ಆದರೆ (cname != ಖಾಲಿ)
		hints.ai_flags = AI_CANONNAME;
	ಆದರೆ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		ಆದರೆ (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (cname != ಖಾಲಿ && res->ai_canonname != ಖಾಲಿ) {
		ಆದರೆ (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			ಆದರೆ (clen > 0)
				*cname = '\0';
		}
	}
	ಹಿಂತಿರುಗಿ res;
}

/* Returns non-zero if name can only be an address and not a hostname */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
is_addr_fast(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ (strchr(name, '%') != ಖಾಲಿ || strchr(name, ':') != ಖಾಲಿ ||
	    strspn(name, "0123456789.") == ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name));
}

/* Returns non-zero if name represents a valid, single address */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
is_addr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಅಕ್ಷರ strport[NI_MAXSERV];
	ರಚನೆ addrinfo hints, *res;

	ಆದರೆ (is_addr_fast(name))
		ಹಿಂತಿರುಗಿ 1;

	snprintf(strport, ಗಾತ್ರ strport, "%u", default_ssh_ಪೋರ್ಟ್());
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = options.ವಿಳಾಸ_family == -1 ?
	    AF_UNSPEC : options.ವಿಳಾಸ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ಆದರೆ (getaddrinfo(name, strport, &hints, &res) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (res == ಖಾಲಿ || res->ai_next != ಖಾಲಿ) {
		freeaddrinfo(res);
		ಹಿಂತಿರುಗಿ 0;
	}
	freeaddrinfo(res);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ರಚನೆ addrinfo *
resolve_addr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಅಕ್ಷರ *caddr, ಗಾತ್ರ_t clen)
{
	ಅಕ್ಷರ addr[NI_MAXHOST], strport[NI_MAXSERV];
	ರಚನೆ addrinfo hints, *res;
	ಪೂರ್ಣಾಂಕ gaierr;

	ಆದರೆ (ಪೋರ್ಟ್ <= 0)
		ಪೋರ್ಟ್ = default_ssh_ಪೋರ್ಟ್();
	snprintf(strport, ಗಾತ್ರ strport, "%u", ಪೋರ್ಟ್);
	memset(&hints, 0, ಗಾತ್ರ(hints));
	hints.ai_family = options.ವಿಳಾಸ_family == -1 ?
	    AF_UNSPEC : options.ವಿಳಾಸ_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ಆದರೆ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (res == ಖಾಲಿ) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (res->ai_next != ಖಾಲಿ) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		ಹೋಗು fail;
	}
	ಆದರೆ ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, ಗಾತ್ರ(addr), ಖಾಲಿ, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		ಹೋಗು fail;
	}
	ಆದರೆ (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		ಆದರೆ (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_follow_cname(ಪೂರ್ಣಾಂಕ direct, ಅಕ್ಷರ **namep, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cname)
{
	ಪೂರ್ಣಾಂಕ i;
	ರಚನೆ allowed_cname *ನಿಯಮ;

	ಆದರೆ (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ಹಿಂತಿರುಗಿ 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	ಆದರೆ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ಹಿಂತಿರುಗಿ 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_permitted_cnames; i++) {
		ನಿಯಮ = options.permitted_cnames + i;
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(*namep, ನಿಯಮ->ಮೂಲ_list, 1) != 1 ||
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(cname, ನಿಯಮ->ಗುರಿ_list, 1) != 1)
			ಮುಂದುವರಿ;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		ಬಿಡುಗಡೆ(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
ಸ್ಥಿರ ರಚನೆ addrinfo *
resolve_canonicalize(ಅಕ್ಷರ **hostp, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	ಪೂರ್ಣಾಂಕ i, direct, ndots;
	ಅಕ್ಷರ *cp, *fullhost, newname[NI_MAXHOST];
	ರಚನೆ addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	ಆದರೆ ((addrs = resolve_addr(*hostp, ಪೋರ್ಟ್,
	    newname, ಗಾತ್ರ(newname))) != ಖಾಲಿ) {
		debug2_f("hostname %.100s is address", *hostp);
		ಆದರೆ (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			ಬಿಡುಗಡೆ(*hostp);
			*hostp = xstrdup(newname);
		}
		ಹಿಂತಿರುಗಿ addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	ಆದರೆ (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಆದರೆ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	ಆದರೆ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* If domain name is anchored, then resolve it now */
	ಆದರೆ ((*hostp)[ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		ಆದರೆ ((addrs = resolve_host(fullhost, ಪೋರ್ಟ್, 0,
		    newname, ಗಾತ್ರ(newname))) != ಖಾಲಿ)
			ಹೋಗು ಸಿಕ್ಕಿತು;
		ಬಿಡುಗಡೆ(fullhost);
		ಹೋಗು notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	ಗಾಗಿ (cp = *hostp; *cp != '\0'; cp++) {
		ಆದರೆ (*cp == '.')
			ndots++;
	}
	ಆದರೆ (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	/* Attempt each supplied suffix */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_canonical_domains; i++) {
		ಆದರೆ (strcasecmp(options.canonical_domains[i], "none") == 0)
			ನಿಲ್ಲಿಸು;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		ಆದರೆ ((addrs = resolve_host(fullhost, ಪೋರ್ಟ್, 0,
		    newname, ಗಾತ್ರ(newname))) == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(fullhost);
			ಮುಂದುವರಿ;
		}
 ಸಿಕ್ಕಿತು:
		/* Remove trailing '.' */
		fullhost[ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		ಆದರೆ (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		ಬಿಡುಗಡೆ(*hostp);
		*hostp = fullhost;
		ಹಿಂತಿರುಗಿ addrs;
	}
 notfound:
	ಆದರೆ (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
check_ತುಂಬು(ಪೂರ್ಣಾಂಕ r, ರಚನೆ sshkey **k, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ_2)
{
	ಅಕ್ಷರ *fp;

	ಆಯ್ಕೆ (r) {
	ಸ್ಥಿತಿ 0:
		ಆದರೆ (k == ಖಾಲಿ || *k == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ;
		/* Check RSA keys size and discard if undersized */
		ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(*k,
		    options.required_rsa_ಗಾತ್ರ)) != 0) {
			error_r(r, "load %s \"%s\"", ಸಂದೇಶ_2, ಮಾರ್ಗ);
			ಬಿಡುಗಡೆ(*k);
			*k = ಖಾಲಿ;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), ಸಂದೇಶ_2, ಮಾರ್ಗ);
		}
		debug("loaded %s from %s: %s %s", ಸಂದೇಶ_2, ಮಾರ್ಗ,
		    sshkey_type(*k), fp);
		ಬಿಡುಗಡೆ(fp);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_ERR_ಆಂತರಿಕ_ERROR:
	ಸ್ಥಿತಿ SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", ಸಂದೇಶ_2, ಮಾರ್ಗ);
	ಸ್ಥಿತಿ SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		ಆದರೆ (errno == ENOENT)
			ನಿಲ್ಲಿಸು;
		/* FALLTHROUGH */
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_r(r, "load %s \"%s\"", ಸಂದೇಶ_2, ಮಾರ್ಗ);
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (k != ಖಾಲಿ && *k == ಖಾಲಿ)
		debug("no %s loaded from %s", ಸಂದೇಶ_2, ಮಾರ್ಗ);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
process_config_files(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_name, ರಚನೆ passwd *pw,
    ಪೂರ್ಣಾಂಕ final_pass, ಪೂರ್ಣಾಂಕ *want_final_pass)
{
	ಅಕ್ಷರ *cmd, buf[PATH_MAX];
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((cmd = sshbuf_dup_string(command)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	ಆದರೆ (config != ಖಾಲಿ) {
		ಆದರೆ (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ {
		r = snprintf(buf, ಗಾತ್ರ buf, "%s/%s", pw->pw_dir,
		    ಮಾರ್ಗ_SSH_USER_CONFFILE);
		ಆದರೆ (r > 0 && (ಗಾತ್ರ_t)r < ಗಾತ್ರ(buf))
			(ಶೂನ್ಯ)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(ಶೂನ್ಯ)read_config_file(ಮಾರ್ಗ_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	ಬಿಡುಗಡೆ(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
ಸ್ಥಿರ ಶೂನ್ಯ
ಗಣ_addrinfo_ಪೋರ್ಟ್(ರಚನೆ addrinfo *addrs, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	ರಚನೆ addrinfo *addr;

	ಗಾಗಿ (addr = addrs; addr != ಖಾಲಿ; addr = addr->ai_next) {
		ಆಯ್ಕೆ (addr->ai_family) {
		ಸ್ಥಿತಿ AF_INET:
			((ರಚನೆ sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(ಪೋರ್ಟ್);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AF_INET6:
			((ರಚನೆ sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(ಪೋರ್ಟ್);
			ನಿಲ್ಲಿಸು;
		}
	}
}

/*
 * Main program for the ssh client.
 */
ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ ac, ಅಕ್ಷರ **av)
{
	ರಚನೆ ssh *ssh = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, r, opt, exit_ಸ್ಥಿತಿ, use_syslog, direct, timeout_ms;
	ಪೂರ್ಣಾಂಕ was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	ಪೂರ್ಣಾಂಕ user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	ಅಕ್ಷರ *p, *cp, *ಸಾಲು, *argv0, *logfile, *ವಾದಗಳು;
	ಅಕ್ಷರ cname[NI_MAXHOST], thishost[NI_MAXHOST];
	ರಚನೆ stat st;
	ರಚನೆ passwd *pw;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind, optreset;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ರಚನೆ Forward fwd;
	ರಚನೆ addrinfo *addrs = ಖಾಲಿ;
	ಗಾತ್ರ_t n, len;
	u_int j;
	ರಚನೆ utsname utsname;
	ರಚನೆ ssh_conn_info *cinfo = ಖಾಲಿ;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, ಗಾತ್ರ(*saved_av));
	ಗಾಗಿ (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ಖಾಲಿ;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#ಆದರೆ_ಅಂತ್ಯ

	ಬೀಜ_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	ಆದರೆ (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		ನಿರ್ಗಮಿಸು(255);
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
	ಆದರೆ ((ssh = ssh_alloc_session_state()) == ಖಾಲಿ)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	ವಾದಗಳು = argv_assemble(ac, av); /* logged later */
	host = ಖಾಲಿ;
	use_syslog = 0;
	logfile = ಖಾಲಿ;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	ಆಗ ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		ಆಯ್ಕೆ (opt) {
		ಸ್ಥಿತಿ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '2':
			/* Ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '4':
			options.ವಿಳಾಸ_family = AF_INET;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '6':
			options.ವಿಳಾಸ_family = AF_INET6;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'n':
			options.stdin_null = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'x':
			options.forward_x11 = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'X':
			options.forward_x11 = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'y':
			use_syslog = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'E':
			logfile = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'G':
			config_test = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Z':
			dump_pubkeys = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'g':
			options.fwd_opts.gateway_ports = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			ಆದರೆ (options.stdio_forward_host != ಖಾಲಿ)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			ಆದರೆ (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			ಇಲ್ಲದಿದ್ದರೆ
				fatal("Invalid multiplex command.");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			ಆದರೆ (options.ಟ್ಯಾಗ್ == ಖಾಲಿ)
				options.ಟ್ಯಾಗ್ = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'Q':
			cp = ಖಾಲಿ;
			ಆದರೆ (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp);
				ಗಾಗಿ (n = 0; n < len; n++)
					ಆದರೆ (cp[n] == ',')
						cp[n] = '\n';
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			ಆದರೆ (cp == ಖಾಲಿ)
				fatal("Unsupported query \"%s\"", optarg);
			ಬರೆ("%s\n", cp);
			ಬಿಡುಗಡೆ(cp);
			ನಿರ್ಗಮಿಸು(0);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'a':
			options.forward_agent = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'A':
			options.forward_agent = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'k':
			options.gss_deleg_creds = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'i':
			p = tilde_expand_filename(optarg, getuid());
			ಆದರೆ (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			ಇಲ್ಲದಿದ್ದರೆ
				ಕೂಡಿಸು_ತಟಸ್ಥ_file(&options, ಖಾಲಿ, p, 1);
			ಬಿಡುಗಡೆ(p);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'I':
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
			ಬಿಡುಗಡೆ(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#ಇಲ್ಲದಿದ್ದರೆ
			fprintf(stderr, "no support for PKCS#11.\n");
#ಆದರೆ_ಅಂತ್ಯ
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'J':
			ಆದರೆ (options.jump_host != ಖಾಲಿ) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			ಆದರೆ (options.proxy_command != ಖಾಲಿ)
				fatal("Cannot specify -J with ProxyCommand");
			ಆದರೆ (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			ಆದರೆ (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			ಇಲ್ಲದಿದ್ದರೆ
				options.request_tty = REQUEST_TTY_YES;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			ಆದರೆ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ಇಲ್ಲದಿದ್ದರೆ {
				ಆದರೆ (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_ಆವೃತ್ತಿ);
			ನಿರ್ಗಮಿಸು(0);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'w':
			ಆದರೆ (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			ಆದರೆ (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'W':
			ಆದರೆ (options.stdio_forward_host != ಖಾಲಿ)
				fatal("stdio forward already specified");
			ಆದರೆ (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			ಆದರೆ (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL ?
				    fwd.listen_ಮಾರ್ಗ : fwd.listen_host;
				options.stdio_forward_ಪೋರ್ಟ್ = fwd.listen_ಪೋರ್ಟ್;
				ಬಿಡುಗಡೆ(fwd.connect_host);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'e':
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'c':
			ಆದರೆ (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ಬಿಡುಗಡೆ(options.ciphers);
			options.ciphers = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'm':
			ಆದರೆ (mac_valid(optarg)) {
				ಬಿಡುಗಡೆ(options.macs);
				options.macs = xstrdup(optarg);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'M':
			ಆದರೆ (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			ಇಲ್ಲದಿದ್ದರೆ
				options.control_master = SSHCTL_MASTER_YES;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			ಆದರೆ (options.ಪೋರ್ಟ್ == -1) {
				options.ಪೋರ್ಟ್ = a2port(optarg);
				ಆದರೆ (options.ಪೋರ್ಟ್ <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					ನಿರ್ಗಮಿಸು(255);
				}
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			ಆದರೆ (options.user == ಖಾಲಿ) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'L':
			ಆದರೆ (parse_forward(&fwd, optarg, 0, 0))
				ಕೂಡಿಸು_local_forward(&options, &fwd);
			ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'R':
			ಆದರೆ (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				ಕೂಡಿಸು_remote_forward(&options, &fwd);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'D':
			ಆದರೆ (parse_forward(&fwd, optarg, 1, 0)) {
				ಕೂಡಿಸು_local_forward(&options, &fwd);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				ನಿರ್ಗಮಿಸು(255);
			}
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ 'C':
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
			options.compression = 1;
#ಇಲ್ಲದಿದ್ದರೆ
			error("Compression not supported, disabling.");
#ಆದರೆ_ಅಂತ್ಯ
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'N':
			ಆದರೆ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			options.request_tty = REQUEST_TTY_NO;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'o':
			ಸಾಲು = xstrdup(optarg);
			ಆದರೆ (process_config_ಸಾಲು(&options, pw,
			    host ? host : "", host ? host : "", "", ಸಾಲು,
			    "command-line", 0, ಖಾಲಿ, SSHCONF_USERCONF) != 0)
				ನಿರ್ಗಮಿಸು(255);
			ಬಿಡುಗಡೆ(ಸಾಲು);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			ಆದರೆ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'S':
			ಬಿಡುಗಡೆ(options.control_ಮಾರ್ಗ);
			options.control_ಮಾರ್ಗ = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'b':
			options.bind_ವಿಳಾಸ = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'B':
			options.bind_interface = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'F':
			config = optarg;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}

	ಆದರೆ (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	ಆದರೆ (ac > 0 && !host) {
		ಪೂರ್ಣಾಂಕ tport;
		ಅಕ್ಷರ *tuser;
		ಆಯ್ಕೆ (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		ಸ್ಥಿತಿ -1:
			usage();
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 0:
			ಆದರೆ (options.user == ಖಾಲಿ) {
				options.user = tuser;
				tuser = ಖಾಲಿ;
				user_on_commandline = 1;
			}
			ಬಿಡುಗಡೆ(tuser);
			ಆದರೆ (options.ಪೋರ್ಟ್ == -1 && tport != -1)
				options.ಪೋರ್ಟ್ = tport;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			ಆದರೆ (cp != ಖಾಲಿ) {
				ಆದರೆ (cp == p)
					usage();
				ಆದರೆ (options.user == ಖಾಲಿ) {
					options.user = p;
					p = ಖಾಲಿ;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				ಬಿಡುಗಡೆ(p);
			} ಇಲ್ಲದಿದ್ದರೆ
				host = p;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			ಹೋಗು again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	ಆದರೆ (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	ಆದರೆ (options.user != ಖಾಲಿ && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	ಆದರೆ (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	ಆದರೆ ((command = sshbuf_new()) == ಖಾಲಿ)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	ಆದರೆ (!ac) {
		/* No command specified - execute shell on a tty. */
		ಆದರೆ (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* A command has been specified.  Store it into the buffer. */
		ಗಾಗಿ (i = 0; i < ac; i++) {
			ಆದರೆ ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	ಆದರೆ (use_syslog && logfile != ಖಾಲಿ)
		fatal("Can't specify both -y and -E");
	ಆದರೆ (logfile != ಖಾಲಿ)
		log_redirect_stderr_ಗಮ್ಯ(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_ಗಣ ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_ಗಣ ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_ಆವೃತ್ತಿ);
	ಆದರೆ (uname(&utsname) != 0) {
		memset(&utsname, 0, ಗಾತ್ರ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ಗಾತ್ರ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.ಆವೃತ್ತಿ, utsname.machine);
	debug3("Started with: %s", ವಾದಗಳು);
	ಬಿಡುಗಡೆ(ವಾದಗಳು);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	ಆದರೆ (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	ಆದರೆ (options.hostname != ಖಾಲಿ) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (ಅಕ್ಷರ *)ಖಾಲಿ);
		ಬಿಡುಗಡೆ(host);
		host = cp;
		ಬಿಡುಗಡೆ(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	ಆದರೆ ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	ಆದರೆ (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
		addrs = resolve_canonicalize(&host, options.ಪೋರ್ಟ್);

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
	ಆದರೆ (addrs == ಖಾಲಿ && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		ಆದರೆ ((addrs = resolve_host(host, options.ಪೋರ್ಟ್,
		    direct, cname, ಗಾತ್ರ(cname))) == ಖಾಲಿ) {
			/* Don't fatal proxied host names not in the DNS */
			ಆದರೆ (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} ಇಲ್ಲದಿದ್ದರೆ
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	ಆದರೆ (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	ಆದರೆ (want_final_pass) {
		debug("re-parsing configuration");
		ಬಿಡುಗಡೆ(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ಖಾಲಿ);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		ಆದರೆ (addrs != ಖಾಲಿ && options.ಪೋರ್ಟ್ > 0)
			ಗಣ_addrinfo_ಪೋರ್ಟ್(addrs, options.ಪೋರ್ಟ್);
	}

	/* Fill configuration defaults. */
	ಆದರೆ (fill_default_options(&options) != 0)
		cleanup_exit(255);

	ಆದರೆ (options.user == ಖಾಲಿ) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	ಆದರೆ (options.jump_host != ಖಾಲಿ) {
		ಅಕ್ಷರ ಪೋರ್ಟ್_s[8];
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *jumpuser = options.jump_user, *sshbin = argv0;
		ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್ = options.ಪೋರ್ಟ್, jumpport = options.jump_ಪೋರ್ಟ್;

		ಆದರೆ (ಪೋರ್ಟ್ <= 0)
			ಪೋರ್ಟ್ = default_ssh_ಪೋರ್ಟ್();
		ಆದರೆ (jumpport <= 0)
			jumpport = default_ssh_ಪೋರ್ಟ್();
		ಆದರೆ (jumpuser == ಖಾಲಿ)
			jumpuser = options.user;
		ಆದರೆ (strcmp(options.jump_host, host) == 0 && ಪೋರ್ಟ್ == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		ಆದರೆ (strchr(argv0, '/') != ಖಾಲಿ && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		ಆದರೆ (options.proxy_command != ಖಾಲಿ &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(ಪೋರ್ಟ್_s, ಗಾತ್ರ(ಪೋರ್ಟ್_s), "%d", options.jump_ಪೋರ್ಟ್);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ಖಾಲಿ ? "" : " -l ",
		    options.jump_user == ಖಾಲಿ ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_ಪೋರ್ಟ್ <= 0 ? "" : " -p ",
		    options.jump_ಪೋರ್ಟ್ <= 0 ? "" : ಪೋರ್ಟ್_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ಖಾಲಿ ? "" : " -J ",
		    options.jump_extra == ಖಾಲಿ ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ಖಾಲಿ ? "" : " -F ",
		    config == ಖಾಲಿ ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	ಆದರೆ (options.ಪೋರ್ಟ್ == 0)
		options.ಪೋರ್ಟ್ = default_ssh_ಪೋರ್ಟ್();
	channel_ಗಣ_af(ssh, options.ವಿಳಾಸ_family);
	ssh_packet_ಗಣ_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	ಆದರೆ (options.host_ಕೀಲಿ_alias != ಖಾಲಿ)
		lowercase(options.host_ಕೀಲಿ_alias);
	ಆದರೆ (options.proxy_command != ಖಾಲಿ &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	ಆದರೆ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ಆದರೆ (options.control_persist && options.control_ಮಾರ್ಗ != ಖಾಲಿ) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshbuf_len(command) != 0 ||
		    options.remote_command != ಖಾಲಿ ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	ಆದರೆ (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	ಆದರೆ (sshbuf_len(command) != 0 && options.remote_command != ಖಾಲಿ)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	ಆದರೆ (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ಖಾಲಿ &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_log_verbose; j++) {
		ಆದರೆ (strcasecmp(options.log_verbose[j], "none") == 0)
			ನಿಲ್ಲಿಸು;
		log_verbose_ಕೂಡಿಸು(options.log_verbose[j]);
	}

	ಆದರೆ (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	ಆದರೆ (sshbuf_len(command) == 0 && options.remote_command == ಖಾಲಿ)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	ಆದರೆ (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	ಆದರೆ ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		ಆದರೆ (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, ಗಾತ್ರ(*cinfo));
	ಆದರೆ (gethostname(thishost, ಗಾತ್ರ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.ಪೋರ್ಟ್);
	xasprintf(&cinfo->uidstr, "%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_ಕೀಲಿ_alias ?
	    options.host_ಕೀಲಿ_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ಖಾಲಿ ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	ಆದರೆ (!user_on_commandline && !user_was_default) {
		ಆದರೆ ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು_NOUSER(cinfo),
		    (ಅಕ್ಷರ *)ಖಾಲಿ)) == ಖಾಲಿ)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		ಬಿಡುಗಡೆ(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	ಆದರೆ ((user_on_commandline || user_expanded) &&
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
	ಆದರೆ (options.remote_command != ಖಾಲಿ) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		ಬಿಡುಗಡೆ(cp);
		ಆದರೆ ((r = sshbuf_put(command, options.remote_command,
		    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	ಆದರೆ (options.control_ಮಾರ್ಗ != ಖಾಲಿ) {
		cp = tilde_expand_filename(options.control_ಮಾರ್ಗ, getuid());
		ಬಿಡುಗಡೆ(options.control_ಮಾರ್ಗ);
		options.control_ಮಾರ್ಗ = default_client_percent_dollar_expand(cp,
		    cinfo);
		ಬಿಡುಗಡೆ(cp);
	}

	ಆದರೆ (options.ತಟಸ್ಥ_agent != ಖಾಲಿ) {
		p = tilde_expand_filename(options.ತಟಸ್ಥ_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ಬಿಡುಗಡೆ(p);
		ಬಿಡುಗಡೆ(options.ತಟಸ್ಥ_agent);
		options.ತಟಸ್ಥ_agent = cp;
	}

	ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು; j++) {
		p = tilde_expand_filename(options.revoked_host_ಕೀಲಿಗಳು[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ಬಿಡುಗಡೆ(p);
		ಬಿಡುಗಡೆ(options.revoked_host_ಕೀಲಿಗಳು[j]);
		options.revoked_host_ಕೀಲಿಗಳು[j] = cp;
	}

	ಆದರೆ (options.forward_agent_sock_ಮಾರ್ಗ != ಖಾಲಿ) {
		p = tilde_expand_filename(options.forward_agent_sock_ಮಾರ್ಗ,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ಬಿಡುಗಡೆ(p);
		ಬಿಡುಗಡೆ(options.forward_agent_sock_ಮಾರ್ಗ);
		options.forward_agent_sock_ಮಾರ್ಗ = cp;
		ಆದರೆ (stat(options.forward_agent_sock_ಮಾರ್ಗ, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_ಮಾರ್ಗ, strerror(errno));
			ಆದರೆ (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	ಆದರೆ (options.ಆವೃತ್ತಿ_addendum != ಖಾಲಿ) {
		cp = default_client_percent_dollar_expand(
		    options.ಆವೃತ್ತಿ_addendum, cinfo);
		ಬಿಡುಗಡೆ(options.ಆವೃತ್ತಿ_addendum);
		options.ಆವೃತ್ತಿ_addendum = cp;
	}

	ಆದರೆ (options.ಅಂಕೆ_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		ಆದರೆ (options.ಅಂಕೆ_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ಬಿಡುಗಡೆ(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ಖಾಲಿ;
		options.ಅಂಕೆ_system_hostfiles = 0;
	}

	ಆದರೆ (options.ಅಂಕೆ_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		ಆದರೆ (options.ಅಂಕೆ_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ಬಿಡುಗಡೆ(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ಖಾಲಿ;
		options.ಅಂಕೆ_user_hostfiles = 0;
	}
	ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_user_hostfiles; j++) {
		ಆದರೆ (options.user_hostfiles[j] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		ಆದರೆ (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		ಬಿಡುಗಡೆ(options.user_hostfiles[j]);
		ಬಿಡುಗಡೆ(cp);
		options.user_hostfiles[j] = p;
	}

	ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_setenv; j++) {
		ಅಕ್ಷರ *name = options.setenv[j], *ಮೌಲ್ಯ;

		ಆದರೆ (name == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		/* Expand only the value portion, not the variable name. */
		ಆದರೆ ((ಮೌಲ್ಯ = strchr(name, '=')) == ಖಾಲಿ) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*ಮೌಲ್ಯ++ = '\0';
		cp = default_client_percent_dollar_expand(ಮೌಲ್ಯ, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		ಆದರೆ (strcmp(ಮೌಲ್ಯ, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, ಮೌಲ್ಯ, cp);
		}
		ಬಿಡುಗಡೆ(options.setenv[j]);
		ಬಿಡುಗಡೆ(cp);
		options.setenv[j] = p;
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
		ಆದರೆ (options.local_forwards[i].listen_ಮಾರ್ಗ != ಖಾಲಿ) {
			cp = options.local_forwards[i].listen_ಮಾರ್ಗ;
			p = options.local_forwards[i].listen_ಮಾರ್ಗ =
			    default_client_percent_expand(cp, cinfo);
			ಆದರೆ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			ಬಿಡುಗಡೆ(cp);
		}
		ಆದರೆ (options.local_forwards[i].connect_ಮಾರ್ಗ != ಖಾಲಿ) {
			cp = options.local_forwards[i].connect_ಮಾರ್ಗ;
			p = options.local_forwards[i].connect_ಮಾರ್ಗ =
			    default_client_percent_expand(cp, cinfo);
			ಆದರೆ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			ಬಿಡುಗಡೆ(cp);
		}
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
		ಆದರೆ (options.remote_forwards[i].listen_ಮಾರ್ಗ != ಖಾಲಿ) {
			cp = options.remote_forwards[i].listen_ಮಾರ್ಗ;
			p = options.remote_forwards[i].listen_ಮಾರ್ಗ =
			    default_client_percent_expand(cp, cinfo);
			ಆದರೆ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			ಬಿಡುಗಡೆ(cp);
		}
		ಆದರೆ (options.remote_forwards[i].connect_ಮಾರ್ಗ != ಖಾಲಿ) {
			cp = options.remote_forwards[i].connect_ಮಾರ್ಗ;
			p = options.remote_forwards[i].connect_ಮಾರ್ಗ =
			    default_client_percent_expand(cp, cinfo);
			ಆದರೆ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			ಬಿಡುಗಡೆ(cp);
		}
	}

	ಆದರೆ (config_test) {
		dump_client_config(&options, host);
		ನಿರ್ಗಮಿಸು(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	ಆದರೆ (options.sk_provider != ಖಾಲಿ && *options.sk_provider == '$' &&
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(options.sk_provider) > 1) {
		ಆದರೆ ((cp = getenv(options.sk_provider + 1)) == ಖಾಲಿ) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			ಬಿಡುಗಡೆ(options.sk_provider);
			options.sk_provider = ಖಾಲಿ;
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			ಬಿಡುಗಡೆ(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	ಆದರೆ (muxclient_command != 0 && options.control_ಮಾರ್ಗ == ಖಾಲಿ)
		fatal("No ControlPath specified for \"-O\" command");
	ಆದರೆ (options.control_ಮಾರ್ಗ != ಖಾಲಿ) {
		ಪೂರ್ಣಾಂಕ sock;
		ಆದರೆ ((sock = muxclient(options.control_ಮಾರ್ಗ)) >= 0) {
			ಆದರೆ (ssh_packet_ಗಣ_connection(ssh, sock, sock) == ಖಾಲಿ)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_ಗಣ_mux(ssh);
			ಹೋಗು skip_connect;
		}
	}

	/* load options.identity_files */
	ತುಂಬು_ಬಹಿರಂಗ_ತಟಸ್ಥ_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	ಆದರೆ (options.ತಟಸ್ಥ_agent &&
	    strcmp(options.ತಟಸ್ಥ_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		ಆದರೆ (strcmp(options.ತಟಸ್ಥ_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} ಇಲ್ಲದಿದ್ದರೆ {
			cp = options.ತಟಸ್ಥ_agent;
			/* legacy (limited) format */
			ಆದರೆ (cp[0] == '$' && cp[1] != '{') {
				ಆದರೆ (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				ಆದರೆ ((p = getenv(cp + 1)) == ಖಾಲಿ)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				ಇಲ್ಲದಿದ್ದರೆ
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	ಆದರೆ (dump_pubkeys) {
		pubkey_dump(ssh);
		ನಿರ್ಗಮಿಸು(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	ಆದರೆ (addrs == ಖಾಲಿ && options.proxy_command == ಖಾಲಿ) {
		debug2("resolving \"%s\" port %d", host, options.ಪೋರ್ಟ್);
		ಆದರೆ ((addrs = resolve_host(host, options.ಪೋರ್ಟ್, 1,
		    cname, ಗಾತ್ರ(cname))) == ಖಾಲಿ)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	ಆದರೆ (options.connection_timeout >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ/1000)
		timeout_ms = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
	ಇಲ್ಲದಿದ್ದರೆ
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	ಗಾಗಿ (j = 0; j < options.ಅಂಕೆ_channel_timeouts; j++) {
		ದ್ವಿಗುಣ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		ಆದರೆ (parse_ನಮೂನೆ_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_ಕೂಡಿಸು_timeout(ssh, cp, timeout);
		ಬಿಡುಗಡೆ(cp);
	}
	channel_ಗಣ_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	ಆದರೆ (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.ಪೋರ್ಟ್, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		ನಿರ್ಗಮಿಸು(255);


	ssh_packet_ಗಣ_timeout(ssh, options.server_alive_interval,
	    options.server_alive_ಎಣಿಕೆ_max);

	ಆದರೆ (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_ದತ್ತಾಂಶ.nkeys = 0;
	sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು = ಖಾಲಿ;
	ಆದರೆ (options.hostbased_authentication) {
		ಪೂರ್ಣಾಂಕ loaded = 0;

		sensitive_ದತ್ತಾಂಶ.nkeys = 10;
		sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು = xcalloc(sensitive_ದತ್ತಾಂಶ.nkeys,
		    ಗಾತ್ರ(*sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು));

		/* XXX check errors? */
#ವ್ಯಾಖ್ಯಾನಿಸು L_PUBKEY(p,o) ಮಾಡು { \
	ಆದರೆ ((o) >= sensitive_ದತ್ತಾಂಶ.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_ತುಂಬು(sshkey_ತುಂಬು_ಬಹಿರಂಗ(p, &(sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[o]), ಖಾಲಿ), \
	    &(sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[o]), p, "hostbased pubkey"); \
	ಆದರೆ (sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[o] != ಖಾಲಿ) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ಆಗ (0)
#ವ್ಯಾಖ್ಯಾನಿಸು L_CERT(p,o) ಮಾಡು { \
	ಆದರೆ ((o) >= sensitive_ದತ್ತಾಂಶ.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_ತುಂಬು(sshkey_ತುಂಬು_cert(p, &(sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[o])), \
	    &(sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[o]), p, "hostbased cert"); \
	ಆದರೆ (sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[o] != ಖಾಲಿ) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ಆಗ (0)

		ಆದರೆ (options.hostbased_authentication == 1) {
			L_CERT(ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE, 0);
			L_CERT(ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE, 1);
			L_CERT(ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE, 2);
			L_CERT(ಮಾರ್ಗ_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, 3);
			L_PUBKEY(ಮಾರ್ಗ_HOST_ECDSA_ಕೀಲಿ_FILE, 4);
			L_PUBKEY(ಮಾರ್ಗ_HOST_ED25519_ಕೀಲಿ_FILE, 5);
			L_PUBKEY(ಮಾರ್ಗ_HOST_RSA_ಕೀಲಿ_FILE, 6);
			L_PUBKEY(ಮಾರ್ಗ_HOST_MLDSA44_ED25519_ಕೀಲಿ_FILE, 7);
			ಆದರೆ (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	ಆದರೆ (options.forward_agent && options.forward_agent_sock_ಮಾರ್ಗ != ಖಾಲಿ) {
		cp = options.forward_agent_sock_ಮಾರ್ಗ;
		ಆದರೆ (cp[0] == '$') {
			ಆದರೆ (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			ಆದರೆ ((p = getenv(cp + 1)) != ಖಾಲಿ)
				forward_agent_sock_ಮಾರ್ಗ = xstrdup(p);
			ಇಲ್ಲದಿದ್ದರೆ
				options.forward_agent = 0;
			ಬಿಡುಗಡೆ(cp);
		} ಇಲ್ಲದಿದ್ದರೆ {
			forward_agent_sock_ಮಾರ್ಗ = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.ಅಂಕೆ_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.ಅಂಕೆ_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_ದತ್ತಾಂಶ, host, &hostaddr, options.ಪೋರ್ಟ್,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	ಆದರೆ (sensitive_ದತ್ತಾಂಶ.nkeys != 0) {
		ಗಾಗಿ (i = 0; i < sensitive_ದತ್ತಾಂಶ.nkeys; i++) {
			ಆದರೆ (sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[i] != ಖಾಲಿ) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[i]);
				sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
			}
		}
		ಬಿಡುಗಡೆ(sensitive_ದತ್ತಾಂಶ.ಕೀಲಿಗಳು);
	}
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_ತಟಸ್ಥ_files; i++) {
		ಬಿಡುಗಡೆ(options.ತಟಸ್ಥ_files[i]);
		options.ತಟಸ್ಥ_files[i] = ಖಾಲಿ;
		ಆದರೆ (options.ತಟಸ್ಥ_ಕೀಲಿಗಳು[i]) {
			sshkey_free(options.ತಟಸ್ಥ_ಕೀಲಿಗಳು[i]);
			options.ತಟಸ್ಥ_ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
		}
	}
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_certificate_files; i++) {
		ಬಿಡುಗಡೆ(options.certificate_files[i]);
		options.certificate_files[i] = ಖಾಲಿ;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	(ಶೂನ್ಯ)pkcs11_del_provider(options.pkcs11_provider);
#ಆದರೆ_ಅಂತ್ಯ

 skip_connect:
	ಆದರೆ (addrs != ಖಾಲಿ)
		freeaddrinfo(addrs);
	exit_ಸ್ಥಿತಿ = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	ಆದರೆ (options.control_ಮಾರ್ಗ != ಖಾಲಿ && muxserver_sock != -1)
		unlink(options.control_ಮಾರ್ಗ);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	ಹಿಂತಿರುಗಿ exit_ಸ್ಥಿತಿ;
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
	ಆಯ್ಕೆ ((pid = fork())) {
	ಸ್ಥಿತಿ -1:
		fatal_f("fork: %s", strerror(errno));
	ಸ್ಥಿತಿ 0:
		/* Child: master process continues mainloop */
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (ದೀರ್ಘ)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(ಶೂನ್ಯ)muxclient(options.control_ಮಾರ್ಗ);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	ಆದರೆ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_ಮಾರ್ಗ);
}

/* Do fork() after authentication. Used by "ssh -f" */
ಸ್ಥಿರ ಶೂನ್ಯ
fork_postauth(ಶೂನ್ಯ)
{
	ಆದರೆ (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	ಆದರೆ (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	ಆದರೆ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

ಸ್ಥಿರ ಶೂನ್ಯ
forwarding_success(ಶೂನ್ಯ)
{
	ಆದರೆ (forward_confirms_pending == -1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		ಆದರೆ (options.fork_after_authentication)
			fork_postauth();
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

ರಚನೆ rfwd_confirm_ctx {
	ಪೂರ್ಣಾಂಕ fid;
};

/* Callback for remote forward global requests */
ಸ್ಥಿರ ಶೂನ್ಯ
ssh_confirm_remote_forward(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type, uint32_t seq, ಶೂನ್ಯ *ctxt)
{
	ರಚನೆ rfwd_confirm_ctx *rctx = (ರಚನೆ rfwd_confirm_ctx *)ctxt;
	ರಚನೆ Forward *rfwd;
	u_int ಪೋರ್ಟ್;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (rctx->fid < 0 || rctx->fid >= options.ಅಂಕೆ_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, ಗಾತ್ರ(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_ಮಾರ್ಗ ? rfwd->listen_ಮಾರ್ಗ :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_ಮಾರ್ಗ || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_ಪೋರ್ಟ್, rfwd->connect_ಮಾರ್ಗ ? rfwd->connect_ಮಾರ್ಗ :
	    rfwd->connect_host, rfwd->connect_ಪೋರ್ಟ್);
	ಆದರೆ (rfwd->listen_ಮಾರ್ಗ == ಖಾಲಿ && rfwd->listen_ಪೋರ್ಟ್ == 0) {
		ಆದರೆ (type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS) {
			ಆದರೆ ((r = sshpkt_get_u32(ssh, &ಪೋರ್ಟ್)) != 0)
				fatal_fr(r, "parse packet");
			ಆದರೆ (ಪೋರ್ಟ್ > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", ಪೋರ್ಟ್,
				    rfwd->connect_host, rfwd->connect_ಪೋರ್ಟ್);
				/* Ensure failure processing runs below */
				type = SSH2_ಸಂದೇಶ_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} ಇಲ್ಲದಿದ್ದರೆ {
				rfwd->allocated_ಪೋರ್ಟ್ = (ಪೂರ್ಣಾಂಕ)ಪೋರ್ಟ್;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_ಪೋರ್ಟ್, rfwd->connect_ಮಾರ್ಗ ?
				    rfwd->connect_ಮಾರ್ಗ : rfwd->connect_host,
				    rfwd->connect_ಪೋರ್ಟ್);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_ಪೋರ್ಟ್);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	ಆದರೆ (type == SSH2_ಸಂದೇಶ_REQUEST_FAILURE) {
		ಆದರೆ (options.exit_on_forward_failure) {
			ಆದರೆ (rfwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_ಮಾರ್ಗ);
			ಇಲ್ಲದಿದ್ದರೆ
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_ಪೋರ್ಟ್);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (rfwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_ಮಾರ್ಗ);
			ಇಲ್ಲದಿದ್ದರೆ
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_ಪೋರ್ಟ್);
		}
	}
	forwarding_success();
}

ಸ್ಥಿರ ಶೂನ್ಯ
client_cleanup_stdio_fwd(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ force, ಶೂನ್ಯ *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_stdio_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ success, ಶೂನ್ಯ *arg)
{
	ಆದರೆ (!success)
		fatal("stdio forwarding failed");
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_tun_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ success, ಶೂನ್ಯ *arg)
{
	ಆದರೆ (!success) {
		error("Tunnel forwarding failed");
		ಆದರೆ (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_init_stdio_forwarding(ರಚನೆ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ ಒಳ, ಹೊರಹೋಗು;

	ಆದರೆ (options.stdio_forward_host == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_ಪೋರ್ಟ್);

	ಆದರೆ ((ಒಳ = dup(STDIN_FILENO)) == -1 ||
	    (ಹೊರಹೋಗು = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	ಆದರೆ ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_ಪೋರ್ಟ್, ಒಳ, ಹೊರಹೋಗು,
	    CHANNEL_NONBLOCK_STDIO)) == ಖಾಲಿ)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_ರಿಜಿಸ್ಟರ್_open_confirm(ssh, c->self, ssh_stdio_confirm, ಖಾಲಿ);
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_init_forward_permissions(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what, ಅಕ್ಷರ **opens,
    u_int ಅಂಕೆ_opens)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;
	ಅಕ್ಷರ *addr, *arg, *oarg;
	ಪೂರ್ಣಾಂಕ where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ಆದರೆ (ಅಂಕೆ_opens == 0)
		ಹಿಂತಿರುಗಿ; /* permit any */

	/* handle keywords: "any" / "none" */
	ಆದರೆ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "any") == 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಅಂಕೆ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ಹಿಂತಿರುಗಿ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		ಆದರೆ (addr == ಖಾಲಿ)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		ಆದರೆ (arg == ಖಾಲಿ || ((ಪೋರ್ಟ್ = permitopen_ಪೋರ್ಟ್(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_ಕೂಡಿಸು_permission(ssh, FORWARD_ADM,
		    where, addr, ಪೋರ್ಟ್);
		ಬಿಡುಗಡೆ(oarg);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_init_forwarding(ರಚನೆ ssh *ssh, ಅಕ್ಷರ **ifname)
{
	ಪೂರ್ಣಾಂಕ success = 0;
	ಪೂರ್ಣಾಂಕ i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.ಅಂಕೆ_permitted_remote_opens);

	ಆದರೆ (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_ಮಾರ್ಗ != ಖಾಲಿ) ?
		    options.local_forwards[i].listen_ಮಾರ್ಗ :
		    (options.local_forwards[i].listen_host == ಖಾಲಿ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_ಪೋರ್ಟ್,
		    (options.local_forwards[i].connect_ಮಾರ್ಗ != ಖಾಲಿ) ?
		    options.local_forwards[i].connect_ಮಾರ್ಗ :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_ಪೋರ್ಟ್);
		success += channel_ಸಿದ್ಧತೆ_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	ಆದರೆ (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	ಆದರೆ (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
		ರಚನೆ rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_ಮಾರ್ಗ != ಖಾಲಿ) ?
		    options.remote_forwards[i].listen_ಮಾರ್ಗ :
		    (options.remote_forwards[i].listen_host == ಖಾಲಿ) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_ಪೋರ್ಟ್,
		    (options.remote_forwards[i].connect_ಮಾರ್ಗ != ಖಾಲಿ) ?
		    options.remote_forwards[i].connect_ಮಾರ್ಗ :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_ಪೋರ್ಟ್);
		ಆದರೆ ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, ಗಾತ್ರ(*rctx));
			rctx->fid = i;
			client_ರಿಜಿಸ್ಟರ್_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		ಇಲ್ಲದಿದ್ದರೆ
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	ಆದರೆ (options.tun_open != SSH_TUNMODE_NO) {
		ಆದರೆ ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ಖಾಲಿ)) != ಖಾಲಿ)
			forward_confirms_pending++;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		ಇಲ್ಲದಿದ್ದರೆ
			error("Could not request tunnel forwarding.");
	}
	ಆದರೆ (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
check_agent_present(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		ಆದರೆ ((r = ssh_get_authentication_socket(ಖಾಲಿ)) != 0) {
			options.forward_agent = 0;
			ಆದರೆ (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_session2_ಸಿದ್ಧತೆ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ success, ಶೂನ್ಯ *arg)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display, *ಪದ;
	ಅಕ್ಷರ *proto = ಖಾಲಿ, *ದತ್ತಾಂಶ = ಖಾಲಿ;

	ಆದರೆ (!success)
		ಹಿಂತಿರುಗಿ; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	ಆದರೆ (display == ಖಾಲಿ && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	ಆದರೆ (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &ದತ್ತಾಂಶ) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    ದತ್ತಾಂಶ, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	ಆದರೆ (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	ಆದರೆ ((ಪದ = lookup_env_ಒಳ_list("TERM", options.setenv,
	    options.ಅಂಕೆ_setenv)) == ಖಾಲಿ || *ಪದ == '\0')
		ಪದ = getenv("TERM");
	client_session2_ಸಿದ್ಧತೆ(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, ಪದ,
	    ಖಾಲಿ, fileno(stdin), command, environ);
}

/* open new channel for a session */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_session2_open(ರಚನೆ ssh *ssh)
{
	Channel *c;
	ಪೂರ್ಣಾಂಕ ಕಿಟಕಿ, packetmax, ಒಳ, ಹೊರಹೋಗು, err;

	ಆದರೆ (options.stdin_null) {
		ಒಳ = open(_PATH_DEVNULL, O_RDONLY);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಒಳ = dup(STDIN_FILENO);
	}
	ಹೊರಹೋಗು = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	ಆದರೆ (ಒಳ == -1 || ಹೊರಹೋಗು == -1 || err == -1)
		fatal("dup() in/out/err failed");

	ಕಿಟಕಿ = CHAN_SES_ಕಿಟಕಿ_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ಆದರೆ (tty_flag) {
		ಕಿಟಕಿ >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, ಒಳ, ಹೊರಹೋಗು, err,
	    ಕಿಟಕಿ, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	ಆದರೆ (tty_flag)
		channel_ಗಣ_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	ಆದರೆ (options.session_type != SESSION_TYPE_NONE)
		channel_ರಿಜಿಸ್ಟರ್_open_confirm(ssh, c->self,
		    ssh_session2_ಸಿದ್ಧತೆ, ಖಾಲಿ);

	ಹಿಂತಿರುಗಿ c->self;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_session2(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಪೂರ್ಣಾಂಕ r, id = -1;
	ಅಕ್ಷರ *cp, *tun_fwd_ifname = ಖಾಲಿ;

	/* XXX should be pre-session */
	ಆದರೆ (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	ಆದರೆ (options.local_command != ಖಾಲಿ) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ವಾದಗಳು(cinfo),
		    "T", tun_fwd_ifname == ಖಾಲಿ ? "NONE" : tun_fwd_ifname,
		    (ಅಕ್ಷರ *)ಖಾಲಿ);
		debug3("expanded LocalCommand: %s", options.local_command);
		ಬಿಡುಗಡೆ(cp);
	}

	/* Start listening for multiplex clients */
	ಆದರೆ (!ssh_packet_get_mux(ssh))
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
	ಆದರೆ (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		ಆದರೆ ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ಖಾಲಿ))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	ಆದರೆ (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	ಆದರೆ (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	ಆದರೆ (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	ಆದರೆ (options.local_command != ಖಾಲಿ &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	ಆದರೆ (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	ಆದರೆ (options.fork_after_authentication) {
		ಆದರೆ (options.exit_on_forward_failure &&
		    options.ಅಂಕೆ_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} ಇಲ್ಲದಿದ್ದರೆ
			fork_postauth();
	}

	ಹಿಂತಿರುಗಿ client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
ಸ್ಥಿರ ಶೂನ್ಯ
ತುಂಬು_ಬಹಿರಂಗ_ತಟಸ್ಥ_files(ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಅಕ್ಷರ *filename, *cp;
	ರಚನೆ sshkey *ಸಾರ್ವಜನಿಕ;
	ಪೂರ್ಣಾಂಕ i;
	u_int n_ids, n_certs;
	ಅಕ್ಷರ *ತಟಸ್ಥ_files[SSH_MAX_ತಟಸ್ಥ_FILES];
	ರಚನೆ sshkey *ತಟಸ್ಥ_ಕೀಲಿಗಳು[SSH_MAX_ತಟಸ್ಥ_FILES];
	ಪೂರ್ಣಾಂಕ ತಟಸ್ಥ_file_userprovided[SSH_MAX_ತಟಸ್ಥ_FILES];
	ಅಕ್ಷರ *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ರಚನೆ sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	ಪೂರ್ಣಾಂಕ certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	ರಚನೆ sshkey **ಕೀಲಿಗಳು = ಖಾಲಿ;
	ಅಕ್ಷರ **comments = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ nkeys;
#ಆದರೆ_ಅಂತ್ಯ /* PKCS11 */

	n_ids = n_certs = 0;
	memset(ತಟಸ್ಥ_files, 0, ಗಾತ್ರ(ತಟಸ್ಥ_files));
	memset(ತಟಸ್ಥ_ಕೀಲಿಗಳು, 0, ಗಾತ್ರ(ತಟಸ್ಥ_ಕೀಲಿಗಳು));
	memset(ತಟಸ್ಥ_file_userprovided, 0,
	    ಗಾತ್ರ(ತಟಸ್ಥ_file_userprovided));
	memset(certificate_files, 0, ಗಾತ್ರ(certificate_files));
	memset(certificates, 0, ಗಾತ್ರ(certificates));
	memset(certificate_file_userprovided, 0,
	    ಗಾತ್ರ(certificate_file_userprovided));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	ಆದರೆ (options.pkcs11_provider != ಖಾಲಿ &&
	    options.ಅಂಕೆ_ತಟಸ್ಥ_files < SSH_MAX_ತಟಸ್ಥ_FILES &&
	    (pkcs11_init(!options.batch_ಬಹುಲಕ) == 0) &&
	    (nkeys = pkcs11_ಕೂಡಿಸು_provider(options.pkcs11_provider, ಖಾಲಿ,
	    &ಕೀಲಿಗಳು, &comments)) > 0) {
		ಗಾಗಿ (i = 0; i < nkeys; i++) {
			ಆದರೆ (n_ids >= SSH_MAX_ತಟಸ್ಥ_FILES) {
				sshkey_free(ಕೀಲಿಗಳು[i]);
				ಬಿಡುಗಡೆ(comments[i]);
				ಮುಂದುವರಿ;
			}
			ತಟಸ್ಥ_ಕೀಲಿಗಳು[n_ids] = ಕೀಲಿಗಳು[i];
			ತಟಸ್ಥ_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		ಬಿಡುಗಡೆ(ಕೀಲಿಗಳು);
		ಬಿಡುಗಡೆ(comments);
	}
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_ತಟಸ್ಥ_files; i++) {
		ಆದರೆ (n_ids >= SSH_MAX_ತಟಸ್ಥ_FILES ||
		    strcasecmp(options.ತಟಸ್ಥ_files[i], "none") == 0) {
			ಬಿಡುಗಡೆ(options.ತಟಸ್ಥ_files[i]);
			options.ತಟಸ್ಥ_files[i] = ಖಾಲಿ;
			ಮುಂದುವರಿ;
		}
		cp = tilde_expand_filename(options.ತಟಸ್ಥ_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ಬಿಡುಗಡೆ(cp);
		check_ತುಂಬು(sshkey_ತುಂಬು_ಬಹಿರಂಗ(filename, &ಸಾರ್ವಜನಿಕ, ಖಾಲಿ),
		    &ಸಾರ್ವಜನಿಕ, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    ಸಾರ್ವಜನಿಕ ? ಸಾರ್ವಜನಿಕ->type : -1);
		ಬಿಡುಗಡೆ(options.ತಟಸ್ಥ_files[i]);
		ತಟಸ್ಥ_files[n_ids] = filename;
		ತಟಸ್ಥ_ಕೀಲಿಗಳು[n_ids] = ಸಾರ್ವಜನಿಕ;
		ತಟಸ್ಥ_file_userprovided[n_ids] =
		    options.ತಟಸ್ಥ_file_userprovided[i];
		ಆದರೆ (++n_ids >= SSH_MAX_ತಟಸ್ಥ_FILES)
			ಮುಂದುವರಿ;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		ಆದರೆ (options.ಅಂಕೆ_certificate_files != 0)
			ಮುಂದುವರಿ;
		xasprintf(&cp, "%s-cert", filename);
		check_ತುಂಬು(sshkey_ತುಂಬು_ಬಹಿರಂಗ(cp, &ಸಾರ್ವಜನಿಕ, ಖಾಲಿ),
		    &ಸಾರ್ವಜನಿಕ, filename, "identity pubkey");
		ಆದರೆ (ಸಾರ್ವಜನಿಕ == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(cp);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!sshkey_is_cert(ಸಾರ್ವಜನಿಕ)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(ಸಾರ್ವಜನಿಕ));
			sshkey_free(ಸಾರ್ವಜನಿಕ);
			ಬಿಡುಗಡೆ(cp);
			ಮುಂದುವರಿ;
		}
		ಬಿಡುಗಡೆ(cp);
		/* NB. leave filename pointing to private key */
		ತಟಸ್ಥ_files[n_ids] = xstrdup(filename);
		ತಟಸ್ಥ_ಕೀಲಿಗಳು[n_ids] = ಸಾರ್ವಜನಿಕ;
		ತಟಸ್ಥ_file_userprovided[n_ids] =
		    options.ತಟಸ್ಥ_file_userprovided[i];
		n_ids++;
	}

	ಆದರೆ (options.ಅಂಕೆ_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ಬಿಡುಗಡೆ(cp);

		check_ತುಂಬು(sshkey_ತುಂಬು_ಬಹಿರಂಗ(filename, &ಸಾರ್ವಜನಿಕ, ಖಾಲಿ),
		    &ಸಾರ್ವಜನಿಕ, filename, "identity cert");
		ಬಿಡುಗಡೆ(options.certificate_files[i]);
		options.certificate_files[i] = ಖಾಲಿ;
		ಆದರೆ (ಸಾರ್ವಜನಿಕ == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(filename);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!sshkey_is_cert(ಸಾರ್ವಜನಿಕ)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(ಸಾರ್ವಜನಿಕ));
			sshkey_free(ಸಾರ್ವಜನಿಕ);
			ಬಿಡುಗಡೆ(filename);
			ಮುಂದುವರಿ;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = ಸಾರ್ವಜನಿಕ;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.ಅಂಕೆ_ತಟಸ್ಥ_files = n_ids;
	ಸ್ಮರಣೆ_ನಕಲು(options.ತಟಸ್ಥ_files, ತಟಸ್ಥ_files, ಗಾತ್ರ(ತಟಸ್ಥ_files));
	ಸ್ಮರಣೆ_ನಕಲು(options.ತಟಸ್ಥ_ಕೀಲಿಗಳು, ತಟಸ್ಥ_ಕೀಲಿಗಳು, ಗಾತ್ರ(ತಟಸ್ಥ_ಕೀಲಿಗಳು));
	ಸ್ಮರಣೆ_ನಕಲು(options.ತಟಸ್ಥ_file_userprovided,
	    ತಟಸ್ಥ_file_userprovided, ಗಾತ್ರ(ತಟಸ್ಥ_file_userprovided));

	options.ಅಂಕೆ_certificate_files = n_certs;
	ಸ್ಮರಣೆ_ನಕಲು(options.certificate_files,
	    certificate_files, ಗಾತ್ರ(certificate_files));
	ಸ್ಮರಣೆ_ನಕಲು(options.certificates, certificates, ಗಾತ್ರ(certificates));
	ಸ್ಮರಣೆ_ನಕಲು(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    ಗಾತ್ರ(certificate_file_userprovided));
}

ಸ್ಥಿರ ಶೂನ್ಯ
main_sigchld_handler(ಪೂರ್ಣಾಂಕ sig)
{
	ಪೂರ್ಣಾಂಕ save_errno = errno;
	pid_t pid;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆಗ ((pid = waitpid(-1, &ಸ್ಥಿತಿ_2, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
