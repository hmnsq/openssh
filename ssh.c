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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/utsname.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <locale.h>

#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>
#endif
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "clientloop.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "sshconnect.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "version.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"

#ifdef ENABLE_PKCS11
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"
#endif

ବାହ୍ୟ ଅକ୍ଷର *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
ସ୍ଥିର ଅକ୍ଷର **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag = 0;

/* Flag indicating whether a tty should be requested */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ostdin_null_flag, osession_type, otty_flag, orequest_tty;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
ଅକ୍ଷର *config = ଖାଲି;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
ଅକ୍ଷର *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
ଅକ୍ଷର *forward_agent_sock_path = ଖାଲି;

/* socket address the host resolves to */
ସଂରଚନା sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
ସଂରଚନା sshbuf *command;

/* # of replies received for global requests */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା forward_confirms_pending = -1;

/* mux.c */
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା muxserver_sock;
ବାହ୍ୟ u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
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

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_session2(ସଂରଚନା ssh *, ଅଚଳ ସଂରଚନା ssh_conn_info *);
ସ୍ଥିର ଶୂନ୍ୟ load_public_identity_files(ଅଚଳ ସଂରଚନା ssh_conn_info *);
ସ୍ଥିର ଶୂନ୍ୟ main_sigchld_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
ସ୍ଥିର ଶୂନ୍ୟ
tilde_expand_paths(ଅକ୍ଷର **paths, u_int ଅଙ୍କ_paths)
{
	u_int i;
	ଅକ୍ଷର *cp;

	ପାଇଁ (i = 0; i < ଅଙ୍କ_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		ମୁକ୍ତ(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
ସ୍ଥିର ଅକ୍ଷର *
default_client_percent_expand(ଅଚଳ ଅକ୍ଷର *str,
    ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ଫେରନ୍ତୁ percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (ଅକ୍ଷର *)ଖାଲି);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
ସ୍ଥିର ଅକ୍ଷର *
default_client_percent_dollar_expand(ଅଚଳ ଅକ୍ଷର *str,
    ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ଅକ୍ଷର *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (ଅକ୍ଷର *)ଖାଲି);
	ଯଦି (ret == ଖାଲି)
		fatal("invalid environment variable expansion");
	ଫେରନ୍ତୁ ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ସ୍ଥିର ସଂରଚନା addrinfo *
resolve_host(ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ପୂର୍ଣ୍ଣସଂଖ୍ୟା logerr, ଅକ୍ଷର *cname, size_t clen)
{
	ଅକ୍ଷର strport[NI_MAXSERV];
	ଅଚଳ ଅକ୍ଷର *errstr = ଖାଲି;
	ସଂରଚନା addrinfo hints, *res;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	ଯଦି (port <= 0)
		port = default_ssh_port();
	ଯଦି (cname != ଖାଲି)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, ଆକାର strport, "%d", port);
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	ଯଦି (cname != ଖାଲି)
		hints.ai_flags = AI_CANONNAME;
	ଯଦି ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		ଯଦି (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (cname != ଖାଲି && res->ai_canonname != ଖାଲି) {
		ଯଦି (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} ଅନ୍ୟଥା ଯଦି (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			ଯଦି (clen > 0)
				*cname = '\0';
		}
	}
	ଫେରନ୍ତୁ res;
}

/* Returns non-zero if name can only be an address and not a hostname */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_addr_fast(ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ (strchr(name, '%') != ଖାଲି || strchr(name, ':') != ଖାଲି ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_addr(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅକ୍ଷର strport[NI_MAXSERV];
	ସଂରଚନା addrinfo hints, *res;

	ଯଦି (is_addr_fast(name))
		ଫେରନ୍ତୁ 1;

	snprintf(strport, ଆକାର strport, "%u", default_ssh_port());
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ଯଦି (getaddrinfo(name, strport, &hints, &res) != 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (res == ଖାଲି || res->ai_next != ଖାଲି) {
		freeaddrinfo(res);
		ଫେରନ୍ତୁ 0;
	}
	freeaddrinfo(res);
	ଫେରନ୍ତୁ 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
ସ୍ଥିର ସଂରଚନା addrinfo *
resolve_addr(ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ଅକ୍ଷର *caddr, size_t clen)
{
	ଅକ୍ଷର addr[NI_MAXHOST], strport[NI_MAXSERV];
	ସଂରଚନା addrinfo hints, *res;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା gaierr;

	ଯଦି (port <= 0)
		port = default_ssh_port();
	snprintf(strport, ଆକାର strport, "%u", port);
	memset(&hints, 0, ଆକାର(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ଯଦି ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (res == ଖାଲି) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (res->ai_next != ଖାଲି) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		ଯାଅ fail;
	}
	ଯଦି ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, ଆକାର(addr), ଖାଲି, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		ଯାଅ fail;
	}
	ଯଦି (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		ଯଦି (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_follow_cname(ପୂର୍ଣ୍ଣସଂଖ୍ୟା direct, ଅକ୍ଷର **namep, ଅଚଳ ଅକ୍ଷର *cname)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ସଂରଚନା allowed_cname *rule;

	ଯଦି (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ଫେରନ୍ତୁ 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	ଯଦି (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ଫେରନ୍ତୁ 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		ଯଦି (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			ଜାରି;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		ମୁକ୍ତ(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
ସ୍ଥିର ସଂରଚନା addrinfo *
resolve_canonicalize(ଅକ୍ଷର **hostp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, direct, ndots;
	ଅକ୍ଷର *cp, *fullhost, newname[NI_MAXHOST];
	ସଂରଚନା addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	ଯଦି ((addrs = resolve_addr(*hostp, port,
	    newname, ଆକାର(newname))) != ଖାଲି) {
		debug2_f("hostname %.100s is address", *hostp);
		ଯଦି (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			ମୁକ୍ତ(*hostp);
			*hostp = xstrdup(newname);
		}
		ଫେରନ୍ତୁ addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	ଯଦି (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		ଫେରନ୍ତୁ ଖାଲି;
	}

	ଯଦି (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ଫେରନ୍ତୁ ଖାଲି;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	ଯଦି (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ଫେରନ୍ତୁ ଖାଲି;

	/* If domain name is anchored, then resolve it now */
	ଯଦି ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		ଯଦି ((addrs = resolve_host(fullhost, port, 0,
		    newname, ଆକାର(newname))) != ଖାଲି)
			ଯାଅ found;
		ମୁକ୍ତ(fullhost);
		ଯାଅ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	ପାଇଁ (cp = *hostp; *cp != '\0'; cp++) {
		ଯଦି (*cp == '.')
			ndots++;
	}
	ଯଦି (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	/* Attempt each supplied suffix */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_canonical_domains; i++) {
		ଯଦି (strcasecmp(options.canonical_domains[i], "none") == 0)
			ଭାଙ୍ଗ;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		ଯଦି ((addrs = resolve_host(fullhost, port, 0,
		    newname, ଆକାର(newname))) == ଖାଲି) {
			ମୁକ୍ତ(fullhost);
			ଜାରି;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		ଯଦି (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		ମୁକ୍ତ(*hostp);
		*hostp = fullhost;
		ଫେରନ୍ତୁ addrs;
	}
 notfound:
	ଯଦି (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
ସ୍ଥିର ଶୂନ୍ୟ
check_load(ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ସଂରଚନା sshkey **k, ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *message)
{
	ଅକ୍ଷର *fp;

	ବାଛ (r) {
	ସ୍ଥିତି 0:
		ଯଦି (k == ଖାଲି || *k == ଖାଲି)
			ଫେରନ୍ତୁ;
		/* Check RSA keys size and discard if undersized */
		ଯଦି ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			ମୁକ୍ତ(*k);
			*k = ଖାଲି;
			ଭାଙ୍ଗ;
		}
		ଯଦି ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ଖାଲି) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		ମୁକ୍ତ(fp);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_ERR_INTERNAL_ERROR:
	ସ୍ଥିତି SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	ସ୍ଥିତି SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		ଯଦି (errno == ENOENT)
			ଭାଙ୍ଗ;
		/* FALLTHROUGH */
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_r(r, "load %s \"%s\"", message, path);
		ଭାଙ୍ଗ;
	}
	ଯଦି (k != ଖାଲି && *k == ଖାଲି)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
ସ୍ଥିର ଶୂନ୍ୟ
process_config_files(ଅଚଳ ଅକ୍ଷର *host_name, ସଂରଚନା passwd *pw,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass)
{
	ଅକ୍ଷର *cmd, buf[PATH_MAX];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((cmd = sshbuf_dup_string(command)) == ଖାଲି)
		fatal_f("sshbuf_dup_string failed");
	ଯଦି (config != ଖାଲି) {
		ଯଦି (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} ଅନ୍ୟଥା {
		r = snprintf(buf, ଆକାର buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		ଯଦି (r > 0 && (size_t)r < ଆକାର(buf))
			(ଶୂନ୍ୟ)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(ଶୂନ୍ୟ)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	ମୁକ୍ତ(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
ସ୍ଥିର ଶୂନ୍ୟ
set_addrinfo_port(ସଂରଚନା addrinfo *addrs, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	ସଂରଚନା addrinfo *addr;

	ପାଇଁ (addr = addrs; addr != ଖାଲି; addr = addr->ai_next) {
		ବାଛ (addr->ai_family) {
		ସ୍ଥିତି AF_INET:
			((ସଂରଚନା sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AF_INET6:
			((ସଂରଚନା sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			ଭାଙ୍ଗ;
		}
	}
}

/*
 * Main program for the ssh client.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା ac, ଅକ୍ଷର **av)
{
	ସଂରଚନା ssh *ssh = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	ଅକ୍ଷର *p, *cp, *ଧାଡ଼ି, *argv0, *logfile, *args;
	ଅକ୍ଷର cname[NI_MAXHOST], thishost[NI_MAXHOST];
	ସଂରଚନା stat st;
	ସଂରଚନା passwd *pw;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind, optreset;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ସଂରଚନା Forward fwd;
	ସଂରଚନା addrinfo *addrs = ଖାଲି;
	size_t n, len;
	u_int j;
	ସଂରଚନା utsname utsname;
	ସଂରଚନା ssh_conn_info *cinfo = ଖାଲି;

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
	saved_av = xcalloc(ac + 1, ଆକାର(*saved_av));
	ପାଇଁ (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ଖାଲି;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	ଯଦି (!pw) {
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
	ଯଦି ((ssh = ssh_alloc_session_state()) == ଖାଲି)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = ଖାଲି;
	use_syslog = 0;
	logfile = ଖାଲି;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	ଯେତେବେଳେ ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		ବାଛ (opt) {
		ସ୍ଥିତି '1':
			fatal("SSH protocol v.1 is no longer supported");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '2':
			/* Ignored */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '4':
			options.address_family = AF_INET;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '6':
			options.address_family = AF_INET6;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'n':
			options.stdin_null = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'x':
			options.forward_x11 = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'X':
			options.forward_x11 = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'y':
			use_syslog = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'E':
			logfile = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'G':
			config_test = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Z':
			dump_pubkeys = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'g':
			options.fwd_opts.gateway_ports = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			ଯଦି (options.stdio_forward_host != ଖାଲି)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			ଅନ୍ୟଥା ଯଦି (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			ଯଦି (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			ଅନ୍ୟଥା
				fatal("Invalid multiplex command.");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			ଯଦି (options.tag == ଖାଲି)
				options.tag = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'Q':
			cp = ଖାଲି;
			ଯଦି (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				ପାଇଁ (n = 0; n < len; n++)
					ଯଦି (cp[n] == ',')
						cp[n] = '\n';
			} ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			ଯଦି (cp == ଖାଲି)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			ମୁକ୍ତ(cp);
			exit(0);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'a':
			options.forward_agent = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'A':
			options.forward_agent = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'k':
			options.gss_deleg_creds = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'i':
			p = tilde_expand_filename(optarg, getuid());
			ଯଦି (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			ଅନ୍ୟଥା
				add_identity_file(&options, ଖାଲି, p, 1);
			ମୁକ୍ତ(p);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'I':
#ifdef ENABLE_PKCS11
			ମୁକ୍ତ(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#ଅନ୍ୟଥା
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'J':
			ଯଦି (options.jump_host != ଖାଲି) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			ଯଦି (options.proxy_command != ଖାଲି)
				fatal("Cannot specify -J with ProxyCommand");
			ଯଦି (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			ଯଦି (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			ଅନ୍ୟଥା
				options.request_tty = REQUEST_TTY_YES;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			ଯଦି (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} ଅନ୍ୟଥା {
				ଯଦି (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'w':
			ଯଦି (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			ଯଦି (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'W':
			ଯଦି (options.stdio_forward_host != ଖାଲି)
				fatal("stdio forward already specified");
			ଯଦି (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			ଯଦି (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				ମୁକ୍ତ(fwd.connect_host);
			} ଅନ୍ୟଥା {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'e':
			ଯଦି (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			ଅନ୍ୟଥା ଯଦି (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			ଅନ୍ୟଥା ଯଦି (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			ଅନ୍ୟଥା {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'c':
			ଯଦି (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			ମୁକ୍ତ(options.ciphers);
			options.ciphers = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'm':
			ଯଦି (mac_valid(optarg)) {
				ମୁକ୍ତ(options.macs);
				options.macs = xstrdup(optarg);
			} ଅନ୍ୟଥା {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'M':
			ଯଦି (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			ଅନ୍ୟଥା
				options.control_master = SSHCTL_MASTER_YES;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			ଯଦି (options.port == -1) {
				options.port = a2port(optarg);
				ଯଦି (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			ଯଦି (options.user == ଖାଲି) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'L':
			ଯଦି (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			ଅନ୍ୟଥା {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'R':
			ଯଦି (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} ଅନ୍ୟଥା {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'D':
			ଯଦି (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} ଅନ୍ୟଥା {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			ଭାଙ୍ଗ;

		ସ୍ଥିତି 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#ଅନ୍ୟଥା
			error("Compression not supported, disabling.");
#endif
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'N':
			ଯଦି (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			options.request_tty = REQUEST_TTY_NO;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'o':
			ଧାଡ଼ି = xstrdup(optarg);
			ଯଦି (process_config_ଧାଡ଼ି(&options, pw,
			    host ? host : "", host ? host : "", "", ଧାଡ଼ି,
			    "command-line", 0, ଖାଲି, SSHCONF_USERCONF) != 0)
				exit(255);
			ମୁକ୍ତ(ଧାଡ଼ି);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			ଯଦି (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'S':
			ମୁକ୍ତ(options.control_path);
			options.control_path = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'b':
			options.bind_address = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'B':
			options.bind_interface = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'F':
			config = optarg;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}

	ଯଦି (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	ଯଦି (ac > 0 && !host) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା tport;
		ଅକ୍ଷର *tuser;
		ବାଛ (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		ସ୍ଥିତି -1:
			usage();
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 0:
			ଯଦି (options.user == ଖାଲି) {
				options.user = tuser;
				tuser = ଖାଲି;
				user_on_commandline = 1;
			}
			ମୁକ୍ତ(tuser);
			ଯଦି (options.port == -1 && tport != -1)
				options.port = tport;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			ଯଦି (cp != ଖାଲି) {
				ଯଦି (cp == p)
					usage();
				ଯଦି (options.user == ଖାଲି) {
					options.user = p;
					p = ଖାଲି;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				ମୁକ୍ତ(p);
			} ଅନ୍ୟଥା
				host = p;
			ଭାଙ୍ଗ;
		}
		ଯଦି (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			ଯାଅ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	ଯଦି (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	ଯଦି (options.user != ଖାଲି && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	ଯଦି (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	ଯଦି ((command = sshbuf_new()) == ଖାଲି)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	ଯଦି (!ac) {
		/* No command specified - execute shell on a tty. */
		ଯଦି (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} ଅନ୍ୟଥା {
		/* A command has been specified.  Store it into the buffer. */
		ପାଇଁ (i = 0; i < ac; i++) {
			ଯଦି ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	ଯଦି (use_syslog && logfile != ଖାଲି)
		fatal("Can't specify both -y and -E");
	ଯଦି (logfile != ଖାଲି)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	ଯଦି (uname(&utsname) != 0) {
		memset(&utsname, 0, ଆକାର(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", ଆକାର(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	ମୁକ୍ତ(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	ଯଦି (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	ଯଦି (options.hostname != ଖାଲି) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (ଅକ୍ଷର *)ଖାଲି);
		ମୁକ୍ତ(host);
		host = cp;
		ମୁକ୍ତ(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	ଯଦି ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	ଯଦି (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	ଯଦି (addrs == ଖାଲି && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		ଯଦି ((addrs = resolve_host(host, options.port,
		    direct, cname, ଆକାର(cname))) == ଖାଲି) {
			/* Don't fatal proxied host names not in the DNS */
			ଯଦି (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} ଅନ୍ୟଥା
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	ଯଦି (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	ଯଦି (want_final_pass) {
		debug("re-parsing configuration");
		ମୁକ୍ତ(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ଖାଲି);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		ଯଦି (addrs != ଖାଲି && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	ଯଦି (fill_default_options(&options) != 0)
		cleanup_exit(255);

	ଯଦି (options.user == ଖାଲି) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	ଯଦି (options.jump_host != ଖାଲି) {
		ଅକ୍ଷର port_s[8];
		ଅଚଳ ଅକ୍ଷର *jumpuser = options.jump_user, *sshbin = argv0;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା port = options.port, jumpport = options.jump_port;

		ଯଦି (port <= 0)
			port = default_ssh_port();
		ଯଦି (jumpport <= 0)
			jumpport = default_ssh_port();
		ଯଦି (jumpuser == ଖାଲି)
			jumpuser = options.user;
		ଯଦି (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		ଯଦି (strchr(argv0, '/') != ଖାଲି && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		ଯଦି (options.proxy_command != ଖାଲି &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, ଆକାର(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ଖାଲି ? "" : " -l ",
		    options.jump_user == ଖାଲି ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ଖାଲି ? "" : " -J ",
		    options.jump_extra == ଖାଲି ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ଖାଲି ? "" : " -F ",
		    config == ଖାଲି ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	ଯଦି (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	ଯଦି (options.host_ଚାବି_alias != ଖାଲି)
		lowercase(options.host_ଚାବି_alias);
	ଯଦି (options.proxy_command != ଖାଲି &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	ଯଦି (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ଯଦି (options.control_persist && options.control_path != ଖାଲି) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} ଅନ୍ୟଥା ଯଦି (sshbuf_len(command) != 0 ||
		    options.remote_command != ଖାଲି ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} ଅନ୍ୟଥା ଯଦି (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	ଯଦି (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	ଯଦି (sshbuf_len(command) != 0 && options.remote_command != ଖାଲି)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	ଯଦି (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ଖାଲି &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	ପାଇଁ (j = 0; j < options.ଅଙ୍କ_log_verbose; j++) {
		ଯଦି (strcasecmp(options.log_verbose[j], "none") == 0)
			ଭାଙ୍ଗ;
		log_verbose_add(options.log_verbose[j]);
	}

	ଯଦି (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	ଯଦି (sshbuf_len(command) == 0 && options.remote_command == ଖାଲି)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	ଯଦି (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	ଯଦି ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		ଯଦି (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, ଆକାର(*cinfo));
	ଯଦି (gethostname(thishost, ଆକାର(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_ଚାବି_alias ?
	    options.host_ଚାବି_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ଖାଲି ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	ଯଦି (!user_on_commandline && !user_was_default) {
		ଯଦି ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (ଅକ୍ଷର *)ଖାଲି)) == ଖାଲି)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		ମୁକ୍ତ(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	ଯଦି ((user_on_commandline || user_expanded) &&
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
	ଯଦି (options.remote_command != ଖାଲି) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		ମୁକ୍ତ(cp);
		ଯଦି ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	ଯଦି (options.control_path != ଖାଲି) {
		cp = tilde_expand_filename(options.control_path, getuid());
		ମୁକ୍ତ(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		ମୁକ୍ତ(cp);
	}

	ଯଦି (options.identity_agent != ଖାଲି) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ମୁକ୍ତ(p);
		ମୁକ୍ତ(options.identity_agent);
		options.identity_agent = cp;
	}

	ପାଇଁ (j = 0; j < options.ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ; j++) {
		p = tilde_expand_filename(options.revoked_host_ଚାବିଗୁଡ଼ିକ[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ମୁକ୍ତ(p);
		ମୁକ୍ତ(options.revoked_host_ଚାବିଗୁଡ଼ିକ[j]);
		options.revoked_host_ଚାବିଗୁଡ଼ିକ[j] = cp;
	}

	ଯଦି (options.forward_agent_sock_path != ଖାଲି) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		ମୁକ୍ତ(p);
		ମୁକ୍ତ(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		ଯଦି (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			ଯଦି (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	ଯଦି (options.version_addendum != ଖାଲି) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		ମୁକ୍ତ(options.version_addendum);
		options.version_addendum = cp;
	}

	ଯଦି (options.ଅଙ୍କ_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		ଯଦି (options.ଅଙ୍କ_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ମୁକ୍ତ(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ଖାଲି;
		options.ଅଙ୍କ_system_hostfiles = 0;
	}

	ଯଦି (options.ଅଙ୍କ_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		ଯଦି (options.ଅଙ୍କ_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		ମୁକ୍ତ(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ଖାଲି;
		options.ଅଙ୍କ_user_hostfiles = 0;
	}
	ପାଇଁ (j = 0; j < options.ଅଙ୍କ_user_hostfiles; j++) {
		ଯଦି (options.user_hostfiles[j] == ଖାଲି)
			ଜାରି;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		ଯଦି (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		ମୁକ୍ତ(options.user_hostfiles[j]);
		ମୁକ୍ତ(cp);
		options.user_hostfiles[j] = p;
	}

	ପାଇଁ (j = 0; j < options.ଅଙ୍କ_setenv; j++) {
		ଅକ୍ଷର *name = options.setenv[j], *ମୂଲ୍ୟ;

		ଯଦି (name == ଖାଲି)
			ଜାରି;
		/* Expand only the value portion, not the variable name. */
		ଯଦି ((ମୂଲ୍ୟ = strchr(name, '=')) == ଖାଲି) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*ମୂଲ୍ୟ++ = '\0';
		cp = default_client_percent_dollar_expand(ମୂଲ୍ୟ, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		ଯଦି (strcmp(ମୂଲ୍ୟ, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, ମୂଲ୍ୟ, cp);
		}
		ମୁକ୍ତ(options.setenv[j]);
		ମୁକ୍ତ(cp);
		options.setenv[j] = p;
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_local_forwards; i++) {
		ଯଦି (options.local_forwards[i].listen_path != ଖାଲି) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			ଯଦି (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			ମୁକ୍ତ(cp);
		}
		ଯଦି (options.local_forwards[i].connect_path != ଖାଲି) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			ଯଦି (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			ମୁକ୍ତ(cp);
		}
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_remote_forwards; i++) {
		ଯଦି (options.remote_forwards[i].listen_path != ଖାଲି) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			ଯଦି (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			ମୁକ୍ତ(cp);
		}
		ଯଦି (options.remote_forwards[i].connect_path != ଖାଲି) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			ଯଦି (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			ମୁକ୍ତ(cp);
		}
	}

	ଯଦି (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	ଯଦି (options.sk_provider != ଖାଲି && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		ଯଦି ((cp = getenv(options.sk_provider + 1)) == ଖାଲି) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			ମୁକ୍ତ(options.sk_provider);
			options.sk_provider = ଖାଲି;
		} ଅନ୍ୟଥା {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			ମୁକ୍ତ(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	ଯଦି (muxclient_command != 0 && options.control_path == ଖାଲି)
		fatal("No ControlPath specified for \"-O\" command");
	ଯଦି (options.control_path != ଖାଲି) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock;
		ଯଦି ((sock = muxclient(options.control_path)) >= 0) {
			ଯଦି (ssh_packet_set_connection(ssh, sock, sock) == ଖାଲି)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			ଯାଅ skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	ଯଦି (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		ଯଦି (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} ଅନ୍ୟଥା {
			cp = options.identity_agent;
			/* legacy (limited) format */
			ଯଦି (cp[0] == '$' && cp[1] != '{') {
				ଯଦି (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				ଯଦି ((p = getenv(cp + 1)) == ଖାଲି)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				ଅନ୍ୟଥା
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} ଅନ୍ୟଥା {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	ଯଦି (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	ଯଦି (addrs == ଖାଲି && options.proxy_command == ଖାଲି) {
		debug2("resolving \"%s\" port %d", host, options.port);
		ଯଦି ((addrs = resolve_host(host, options.port, 1,
		    cname, ଆକାର(cname))) == ଖାଲି)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	ଯଦି (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	ଅନ୍ୟଥା
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	ପାଇଁ (j = 0; j < options.ଅଙ୍କ_channel_timeouts; j++) {
		ଦ୍ୱିଗୁଣ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		ଯଦି (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		ମୁକ୍ତ(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	ଯଦି (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_ଗଣନା_max);

	ଯଦି (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.ଚାବିଗୁଡ଼ିକ = ଖାଲି;
	ଯଦି (options.hostbased_authentication) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.ଚାବିଗୁଡ଼ିକ = xcalloc(sensitive_data.nkeys,
		    ଆକାର(*sensitive_data.ଚାବିଗୁଡ଼ିକ));

		/* XXX check errors? */
#define L_PUBKEY(p,o) କର { \
	ଯଦି ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.ଚାବିଗୁଡ଼ିକ[o]), ଖାଲି), \
	    &(sensitive_data.ଚାବିଗୁଡ଼ିକ[o]), p, "hostbased pubkey"); \
	ଯଦି (sensitive_data.ଚାବିଗୁଡ଼ିକ[o] != ଖାଲି) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ଯେତେବେଳେ (0)
#define L_CERT(p,o) କର { \
	ଯଦି ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.ଚାବିଗୁଡ଼ିକ[o])), \
	    &(sensitive_data.ଚାବିଗୁଡ଼ିକ[o]), p, "hostbased cert"); \
	ଯଦି (sensitive_data.ଚାବିଗୁଡ଼ିକ[o] != ଖାଲି) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} ଯେତେବେଳେ (0)

		ଯଦି (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_ଚାବି_FILE, 0);
			L_CERT(PATH_HOST_ED25519_ଚାବି_FILE, 1);
			L_CERT(PATH_HOST_RSA_ଚାବି_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_ଚାବି_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_ଚାବି_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_ଚାବି_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_ଚାବି_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_ଚାବି_FILE, 7);
			ଯଦି (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	ଯଦି (options.forward_agent && options.forward_agent_sock_path != ଖାଲି) {
		cp = options.forward_agent_sock_path;
		ଯଦି (cp[0] == '$') {
			ଯଦି (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			ଯଦି ((p = getenv(cp + 1)) != ଖାଲି)
				forward_agent_sock_path = xstrdup(p);
			ଅନ୍ୟଥା
				options.forward_agent = 0;
			ମୁକ୍ତ(cp);
		} ଅନ୍ୟଥା {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.ଅଙ୍କ_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.ଅଙ୍କ_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	ଯଦି (sensitive_data.nkeys != 0) {
		ପାଇଁ (i = 0; i < sensitive_data.nkeys; i++) {
			ଯଦି (sensitive_data.ଚାବିଗୁଡ଼ିକ[i] != ଖାଲି) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.ଚାବିଗୁଡ଼ିକ[i]);
				sensitive_data.ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
			}
		}
		ମୁକ୍ତ(sensitive_data.ଚାବିଗୁଡ଼ିକ);
	}
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_identity_files; i++) {
		ମୁକ୍ତ(options.identity_files[i]);
		options.identity_files[i] = ଖାଲି;
		ଯଦି (options.identity_ଚାବିଗୁଡ଼ିକ[i]) {
			sshkey_free(options.identity_ଚାବିଗୁଡ଼ିକ[i]);
			options.identity_ଚାବିଗୁଡ଼ିକ[i] = ଖାଲି;
		}
	}
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_certificate_files; i++) {
		ମୁକ୍ତ(options.certificate_files[i]);
		options.certificate_files[i] = ଖାଲି;
	}

#ifdef ENABLE_PKCS11
	(ଶୂନ୍ୟ)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	ଯଦି (addrs != ଖାଲି)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	ଯଦି (options.control_path != ଖାଲି && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	ଫେରନ୍ତୁ exit_status;
}

ସ୍ଥିର ଶୂନ୍ୟ
control_persist_detach(ଶୂନ୍ୟ)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	ବାଛ ((pid = fork())) {
	ସ୍ଥିତି -1:
		fatal_f("fork: %s", strerror(errno));
	ସ୍ଥିତି 0:
		/* Child: master process continues mainloop */
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
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
		(ଶୂନ୍ୟ)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	ଯଦି (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
ସ୍ଥିର ଶୂନ୍ୟ
fork_postauth(ଶୂନ୍ୟ)
{
	ଯଦି (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	ଯଦି (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	ଯଦି (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

ସ୍ଥିର ଶୂନ୍ୟ
forwarding_success(ଶୂନ୍ୟ)
{
	ଯଦି (forward_confirms_pending == -1)
		ଫେରନ୍ତୁ;
	ଯଦି (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		ଯଦି (options.fork_after_authentication)
			fork_postauth();
	} ଅନ୍ୟଥା {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

ସଂରଚନା rfwd_confirm_ctx {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fid;
};

/* Callback for remote forward global requests */
ସ୍ଥିର ଶୂନ୍ୟ
ssh_confirm_remote_forward(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ଶୂନ୍ୟ *ctxt)
{
	ସଂରଚନା rfwd_confirm_ctx *rctx = (ସଂରଚନା rfwd_confirm_ctx *)ctxt;
	ସଂରଚନା Forward *rfwd;
	u_int port;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (rctx->fid < 0 || rctx->fid >= options.ଅଙ୍କ_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, ଆକାର(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_ସନ୍ଦେଶ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	ଯଦି (rfwd->listen_path == ଖାଲି && rfwd->listen_port == 0) {
		ଯଦି (type == SSH2_ସନ୍ଦେଶ_REQUEST_SUCCESS) {
			ଯଦି ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			ଯଦି (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_ସନ୍ଦେଶ_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} ଅନ୍ୟଥା {
				rfwd->allocated_port = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} ଅନ୍ୟଥା {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	ଯଦି (type == SSH2_ସନ୍ଦେଶ_REQUEST_FAILURE) {
		ଯଦି (options.exit_on_forward_failure) {
			ଯଦି (rfwd->listen_path != ଖାଲି)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			ଅନ୍ୟଥା
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} ଅନ୍ୟଥା {
			ଯଦି (rfwd->listen_path != ଖାଲି)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			ଅନ୍ୟଥା
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

ସ୍ଥିର ଶୂନ୍ୟ
client_cleanup_stdio_fwd(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force, ଶୂନ୍ୟ *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_stdio_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, ଶୂନ୍ୟ *arg)
{
	ଯଦି (!success)
		fatal("stdio forwarding failed");
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_tun_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, ଶୂନ୍ୟ *arg)
{
	ଯଦି (!success) {
		error("Tunnel forwarding failed");
		ଯଦି (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_init_stdio_forwarding(ସଂରଚନା ssh *ssh)
{
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା in, out;

	ଯଦି (options.stdio_forward_host == ଖାଲି)
		ଫେରନ୍ତୁ;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	ଯଦି ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	ଯଦି ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == ଖାଲି)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, ଖାଲି);
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_init_forward_permissions(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *what, ଅକ୍ଷର **opens,
    u_int ଅଙ୍କ_opens)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;
	ଅକ୍ଷର *addr, *arg, *oarg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ଯଦି (ଅଙ୍କ_opens == 0)
		ଫେରନ୍ତୁ; /* permit any */

	/* handle keywords: "any" / "none" */
	ଯଦି (ଅଙ୍କ_opens == 1 && strcmp(opens[0], "any") == 0)
		ଫେରନ୍ତୁ;
	ଯଦି (ଅଙ୍କ_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ଫେରନ୍ତୁ;
	}
	/* Otherwise treat it as a list of permitted host:port */
	ପାଇଁ (i = 0; i < ଅଙ୍କ_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		ଯଦି (addr == ଖାଲି)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		ଯଦି (arg == ଖାଲି || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		ମୁକ୍ତ(oarg);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_init_forwarding(ସଂରଚନା ssh *ssh, ଅକ୍ଷର **ifname)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.ଅଙ୍କ_permitted_remote_opens);

	ଯଦି (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != ଖାଲି) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == ଖାଲି) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != ଖାଲି) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	ଯଦି (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	ଯଦି (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_remote_forwards; i++) {
		ସଂରଚନା rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != ଖାଲି) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == ଖାଲି) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != ଖାଲି) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		ଯଦି ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, ଆକାର(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} ଅନ୍ୟଥା ଯଦି (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		ଅନ୍ୟଥା
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	ଯଦି (options.tun_open != SSH_TUNMODE_NO) {
		ଯଦି ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ଖାଲି)) != ଖାଲି)
			forward_confirms_pending++;
		ଅନ୍ୟଥା ଯଦି (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		ଅନ୍ୟଥା
			error("Could not request tunnel forwarding.");
	}
	ଯଦି (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
check_agent_present(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		ଯଦି ((r = ssh_get_authentication_socket(ଖାଲି)) != 0) {
			options.forward_agent = 0;
			ଯଦି (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_session2_setup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, ଶୂନ୍ୟ *arg)
{
	ବାହ୍ୟ ଅକ୍ଷର **environ;
	ଅଚଳ ଅକ୍ଷର *display, *term;
	ଅକ୍ଷର *proto = ଖାଲି, *data = ଖାଲି;

	ଯଦି (!success)
		ଫେରନ୍ତୁ; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	ଯଦି (display == ଖାଲି && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	ଯଦି (options.forward_x11 && client_x11_get_proto(ssh, display,
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
	ଯଦି (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	ଯଦି ((term = lookup_env_in_list("TERM", options.setenv,
	    options.ଅଙ୍କ_setenv)) == ଖାଲି || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    ଖାଲି, fileno(stdin), command, environ);
}

/* open new channel for a session */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_session2_open(ସଂରଚନା ssh *ssh)
{
	Channel *c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା window, packetmax, in, out, err;

	ଯଦି (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} ଅନ୍ୟଥା {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	ଯଦି (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ଯଦି (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	ଯଦି (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	ଯଦି (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, ଖାଲି);

	ଫେରନ୍ତୁ c->self;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_session2(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, id = -1;
	ଅକ୍ଷର *cp, *tun_fwd_ifname = ଖାଲି;

	/* XXX should be pre-session */
	ଯଦି (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	ଯଦି (options.local_command != ଖାଲି) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == ଖାଲି ? "NONE" : tun_fwd_ifname,
		    (ଅକ୍ଷର *)ଖାଲି);
		debug3("expanded LocalCommand: %s", options.local_command);
		ମୁକ୍ତ(cp);
	}

	/* Start listening for multiplex clients */
	ଯଦି (!ssh_packet_get_mux(ssh))
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
	ଯଦି (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		ଯଦି ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ଖାଲି))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	ଯଦି (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	ଯଦି (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	ଯଦି (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	ଯଦି (options.local_command != ଖାଲି &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	ଯଦି (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	ଯଦି (options.fork_after_authentication) {
		ଯଦି (options.exit_on_forward_failure &&
		    options.ଅଙ୍କ_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} ଅନ୍ୟଥା
			fork_postauth();
	}

	ଫେରନ୍ତୁ client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
ସ୍ଥିର ଶୂନ୍ୟ
load_public_identity_files(ଅଚଳ ସଂରଚନା ssh_conn_info *cinfo)
{
	ଅକ୍ଷର *filename, *cp;
	ସଂରଚନା sshkey *ସର୍ବସାଧାରଣ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	u_int n_ids, n_certs;
	ଅକ୍ଷର *identity_files[SSH_MAX_IDENTITY_FILES];
	ସଂରଚନା sshkey *identity_ଚାବିଗୁଡ଼ିକ[SSH_MAX_IDENTITY_FILES];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	ଅକ୍ଷର *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	ସଂରଚନା sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ = ଖାଲି;
	ଅକ୍ଷର **comments = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, ଆକାର(identity_files));
	memset(identity_ଚାବିଗୁଡ଼ିକ, 0, ଆକାର(identity_ଚାବିଗୁଡ଼ିକ));
	memset(identity_file_userprovided, 0,
	    ଆକାର(identity_file_userprovided));
	memset(certificate_files, 0, ଆକାର(certificate_files));
	memset(certificates, 0, ଆକାର(certificates));
	memset(certificate_file_userprovided, 0,
	    ଆକାର(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	ଯଦି (options.pkcs11_provider != ଖାଲି &&
	    options.ଅଙ୍କ_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, ଖାଲି,
	    &ଚାବିଗୁଡ଼ିକ, &comments)) > 0) {
		ପାଇଁ (i = 0; i < nkeys; i++) {
			ଯଦି (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(ଚାବିଗୁଡ଼ିକ[i]);
				ମୁକ୍ତ(comments[i]);
				ଜାରି;
			}
			identity_ଚାବିଗୁଡ଼ିକ[n_ids] = ଚାବିଗୁଡ଼ିକ[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		ମୁକ୍ତ(ଚାବିଗୁଡ଼ିକ);
		ମୁକ୍ତ(comments);
	}
#endif /* ENABLE_PKCS11 */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_identity_files; i++) {
		ଯଦି (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			ମୁକ୍ତ(options.identity_files[i]);
			options.identity_files[i] = ଖାଲି;
			ଜାରି;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ମୁକ୍ତ(cp);
		check_load(sshkey_load_public(filename, &ସର୍ବସାଧାରଣ, ଖାଲି),
		    &ସର୍ବସାଧାରଣ, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    ସର୍ବସାଧାରଣ ? ସର୍ବସାଧାରଣ->type : -1);
		ମୁକ୍ତ(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_ଚାବିଗୁଡ଼ିକ[n_ids] = ସର୍ବସାଧାରଣ;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		ଯଦି (++n_ids >= SSH_MAX_IDENTITY_FILES)
			ଜାରି;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		ଯଦି (options.ଅଙ୍କ_certificate_files != 0)
			ଜାରି;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &ସର୍ବସାଧାରଣ, ଖାଲି),
		    &ସର୍ବସାଧାରଣ, filename, "identity pubkey");
		ଯଦି (ସର୍ବସାଧାରଣ == ଖାଲି) {
			ମୁକ୍ତ(cp);
			ଜାରି;
		}
		ଯଦି (!sshkey_is_cert(ସର୍ବସାଧାରଣ)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(ସର୍ବସାଧାରଣ));
			sshkey_free(ସର୍ବସାଧାରଣ);
			ମୁକ୍ତ(cp);
			ଜାରି;
		}
		ମୁକ୍ତ(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_ଚାବିଗୁଡ଼ିକ[n_ids] = ସର୍ବସାଧାରଣ;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	ଯଦି (options.ଅଙ୍କ_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		ମୁକ୍ତ(cp);

		check_load(sshkey_load_public(filename, &ସର୍ବସାଧାରଣ, ଖାଲି),
		    &ସର୍ବସାଧାରଣ, filename, "identity cert");
		ମୁକ୍ତ(options.certificate_files[i]);
		options.certificate_files[i] = ଖାଲି;
		ଯଦି (ସର୍ବସାଧାରଣ == ଖାଲି) {
			ମୁକ୍ତ(filename);
			ଜାରି;
		}
		ଯଦି (!sshkey_is_cert(ସର୍ବସାଧାରଣ)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(ସର୍ବସାଧାରଣ));
			sshkey_free(ସର୍ବସାଧାରଣ);
			ମୁକ୍ତ(filename);
			ଜାରି;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = ସର୍ବସାଧାରଣ;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.ଅଙ୍କ_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, ଆକାର(identity_files));
	memcpy(options.identity_ଚାବିଗୁଡ଼ିକ, identity_ଚାବିଗୁଡ଼ିକ, ଆକାର(identity_ଚାବିଗୁଡ଼ିକ));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, ଆକାର(identity_file_userprovided));

	options.ଅଙ୍କ_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, ଆକାର(certificate_files));
	memcpy(options.certificates, certificates, ଆକାର(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    ଆକାର(certificate_file_userprovided));
}

ସ୍ଥିର ଶୂନ୍ୟ
main_sigchld_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno = errno;
	pid_t pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;

	ଯେତେବେଳେ ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
