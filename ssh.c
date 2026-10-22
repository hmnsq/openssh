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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/utsname.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <locale.h>

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/err.h>
#అయితే_ముగింపు
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "clientloop.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "sshconnect.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "version.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "utf8.h"

#నిర్వచితమైతే ENABLE_PKCS11
#అన్తర్భావ "ssh-pkcs11.h"
#అయితే_ముగింపు

బాహ్య అక్షరం *__progname;

/* Saves a copy of argv for setproctitle emulation */
#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE
స్థిర అక్షరం **saved_av;
#అయితే_ముగింపు

/* Flag indicating whether debug mode is on.  May be set on the command line. */
పూర్ణాంకం debug_flag = 0;

/* Flag indicating whether a tty should be requested */
పూర్ణాంకం tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
స్థిర పూర్ణాంకం need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
స్థిర పూర్ణాంకం ostdin_null_flag, osession_type, otty_flag, orequest_tty;
స్థిర పూర్ణాంకం ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
అక్షరం *config = ఖాళీ;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
అక్షరం *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
అక్షరం *forward_agent_sock_మార్గం = ఖాళీ;

/* socket address the host resolves to */
నిర్మాణం sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_దత్తాంశం;

/* command to be executed */
నిర్మాణం sshbuf *command;

/* # of replies received for global requests */
స్థిర పూర్ణాంకం forward_confirms_pending = -1;

/* mux.c */
బాహ్య పూర్ణాంకం muxserver_sock;
బాహ్య u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

స్థిర శూన్య
usage(శూన్య)
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
	నిష్క్రమించు(255);
}

స్థిర పూర్ణాంకం ssh_session2(నిర్మాణం ssh *, స్థిరరాశి నిర్మాణం ssh_conn_info *);
స్థిర శూన్య ఎక్కించు_ప్రజా_తటస్థం_files(స్థిరరాశి నిర్మాణం ssh_conn_info *);
స్థిర శూన్య main_sigchld_handler(పూర్ణాంకం);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
స్థిర శూన్య
tilde_expand_paths(అక్షరం **paths, u_int అంకె_paths)
{
	u_int i;
	అక్షరం *cp;

	కొరకు (i = 0; i < అంకె_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		విడుదల(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
స్థిర అక్షరం *
default_client_percent_expand(స్థిరరాశి అక్షరం *str,
    స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	తిరిగి percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు(cinfo),
	    (అక్షరం *)ఖాళీ);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
స్థిర అక్షరం *
default_client_percent_dollar_expand(స్థిరరాశి అక్షరం *str,
    స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	అక్షరం *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు(cinfo),
	    (అక్షరం *)ఖాళీ);
	ఒకవేళ (ret == ఖాళీ)
		fatal("invalid environment variable expansion");
	తిరిగి ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
స్థిర నిర్మాణం addrinfo *
resolve_host(స్థిరరాశి అక్షరం *name, పూర్ణాంకం పోర్టు, పూర్ణాంకం logerr, అక్షరం *cname, కొలత_t clen)
{
	అక్షరం strport[NI_MAXSERV];
	స్థిరరాశి అక్షరం *errstr = ఖాళీ;
	నిర్మాణం addrinfo hints, *res;
	పూర్ణాంకం gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	ఒకవేళ (పోర్టు <= 0)
		పోర్టు = default_ssh_పోర్టు();
	ఒకవేళ (cname != ఖాళీ)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, పోర్టు);

	snprintf(strport, పరిమాణం strport, "%d", పోర్టు);
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = options.చిరునామా_family == -1 ?
	    AF_UNSPEC : options.చిరునామా_family;
	hints.ai_socktype = SOCK_STREAM;
	ఒకవేళ (cname != ఖాళీ)
		hints.ai_flags = AI_CANONNAME;
	ఒకవేళ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		ఒకవేళ (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (cname != ఖాళీ && res->ai_canonname != ఖాళీ) {
		ఒకవేళ (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} లేకపోతే ఒకవేళ (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			ఒకవేళ (clen > 0)
				*cname = '\0';
		}
	}
	తిరిగి res;
}

/* Returns non-zero if name can only be an address and not a hostname */
స్థిర పూర్ణాంకం
is_addr_fast(స్థిరరాశి అక్షరం *name)
{
	తిరిగి (strchr(name, '%') != ఖాళీ || strchr(name, ':') != ఖాళీ ||
	    strspn(name, "0123456789.") == అక్షరశ్రేణి_పొడవు(name));
}

/* Returns non-zero if name represents a valid, single address */
స్థిర పూర్ణాంకం
is_addr(స్థిరరాశి అక్షరం *name)
{
	అక్షరం strport[NI_MAXSERV];
	నిర్మాణం addrinfo hints, *res;

	ఒకవేళ (is_addr_fast(name))
		తిరిగి 1;

	snprintf(strport, పరిమాణం strport, "%u", default_ssh_పోర్టు());
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = options.చిరునామా_family == -1 ?
	    AF_UNSPEC : options.చిరునామా_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ఒకవేళ (getaddrinfo(name, strport, &hints, &res) != 0)
		తిరిగి 0;
	ఒకవేళ (res == ఖాళీ || res->ai_next != ఖాళీ) {
		freeaddrinfo(res);
		తిరిగి 0;
	}
	freeaddrinfo(res);
	తిరిగి 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
స్థిర నిర్మాణం addrinfo *
resolve_addr(స్థిరరాశి అక్షరం *name, పూర్ణాంకం పోర్టు, అక్షరం *caddr, కొలత_t clen)
{
	అక్షరం addr[NI_MAXHOST], strport[NI_MAXSERV];
	నిర్మాణం addrinfo hints, *res;
	పూర్ణాంకం gaierr;

	ఒకవేళ (పోర్టు <= 0)
		పోర్టు = default_ssh_పోర్టు();
	snprintf(strport, పరిమాణం strport, "%u", పోర్టు);
	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = options.చిరునామా_family == -1 ?
	    AF_UNSPEC : options.చిరునామా_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	ఒకవేళ ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (res == ఖాళీ) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (res->ai_next != ఖాళీ) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		వెళ్ళు fail;
	}
	ఒకవేళ ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, పరిమాణం(addr), ఖాళీ, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		వెళ్ళు fail;
	}
	ఒకవేళ (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		ఒకవేళ (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		తిరిగి ఖాళీ;
	}
	తిరిగి res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
స్థిర పూర్ణాంకం
check_follow_cname(పూర్ణాంకం direct, అక్షరం **namep, స్థిరరాశి అక్షరం *cname)
{
	పూర్ణాంకం i;
	నిర్మాణం allowed_cname *నియమం;

	ఒకవేళ (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		తిరిగి 0;
	ఒకవేళ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		తిరిగి 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	ఒకవేళ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		తిరిగి 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	కొరకు (i = 0; i < options.అంకె_permitted_cnames; i++) {
		నియమం = options.permitted_cnames + i;
		ఒకవేళ (సరిపోలిక_నమూనా_list(*namep, నియమం->ఆధారం_list, 1) != 1 ||
		    సరిపోలిక_నమూనా_list(cname, నియమం->లక్ష్యం_list, 1) != 1)
			కొనసాగు;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		విడుదల(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		తిరిగి 1;
	}
	తిరిగి 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
స్థిర నిర్మాణం addrinfo *
resolve_canonicalize(అక్షరం **hostp, పూర్ణాంకం పోర్టు)
{
	పూర్ణాంకం i, direct, ndots;
	అక్షరం *cp, *fullhost, newname[NI_MAXHOST];
	నిర్మాణం addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	ఒకవేళ ((addrs = resolve_addr(*hostp, పోర్టు,
	    newname, పరిమాణం(newname))) != ఖాళీ) {
		debug2_f("hostname %.100s is address", *hostp);
		ఒకవేళ (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			విడుదల(*hostp);
			*hostp = xstrdup(newname);
		}
		తిరిగి addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	ఒకవేళ (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		తిరిగి ఖాళీ;
	}

	ఒకవేళ (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		తిరిగి ఖాళీ;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	ఒకవేళ (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		తిరిగి ఖాళీ;

	/* If domain name is anchored, then resolve it now */
	ఒకవేళ ((*hostp)[అక్షరశ్రేణి_పొడవు(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		ఒకవేళ ((addrs = resolve_host(fullhost, పోర్టు, 0,
		    newname, పరిమాణం(newname))) != ఖాళీ)
			వెళ్ళు దొరికింది;
		విడుదల(fullhost);
		వెళ్ళు notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	కొరకు (cp = *hostp; *cp != '\0'; cp++) {
		ఒకవేళ (*cp == '.')
			ndots++;
	}
	ఒకవేళ (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		తిరిగి ఖాళీ;
	}
	/* Attempt each supplied suffix */
	కొరకు (i = 0; i < options.అంకె_canonical_domains; i++) {
		ఒకవేళ (strcasecmp(options.canonical_domains[i], "none") == 0)
			ఆపు;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		ఒకవేళ ((addrs = resolve_host(fullhost, పోర్టు, 0,
		    newname, పరిమాణం(newname))) == ఖాళీ) {
			విడుదల(fullhost);
			కొనసాగు;
		}
 దొరికింది:
		/* Remove trailing '.' */
		fullhost[అక్షరశ్రేణి_పొడవు(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		ఒకవేళ (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		విడుదల(*hostp);
		*hostp = fullhost;
		తిరిగి addrs;
	}
 notfound:
	ఒకవేళ (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	తిరిగి ఖాళీ;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
స్థిర శూన్య
check_ఎక్కించు(పూర్ణాంకం r, నిర్మాణం sshkey **k, స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *సందేశం_2)
{
	అక్షరం *fp;

	ఎంపిక (r) {
	స్థితి 0:
		ఒకవేళ (k == ఖాళీ || *k == ఖాళీ)
			తిరిగి;
		/* Check RSA keys size and discard if undersized */
		ఒకవేళ ((r = sshkey_check_rsa_నిడివి(*k,
		    options.required_rsa_కొలత)) != 0) {
			error_r(r, "load %s \"%s\"", సందేశం_2, మార్గం);
			విడుదల(*k);
			*k = ఖాళీ;
			ఆపు;
		}
		ఒకవేళ ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), సందేశం_2, మార్గం);
		}
		debug("loaded %s from %s: %s %s", సందేశం_2, మార్గం,
		    sshkey_type(*k), fp);
		విడుదల(fp);
		ఆపు;
	స్థితి SSH_ERR_అంతర్గత_ERROR:
	స్థితి SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", సందేశం_2, మార్గం);
	స్థితి SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		ఒకవేళ (errno == ENOENT)
			ఆపు;
		/* FALLTHROUGH */
	అప్రమేయ:
		error_r(r, "load %s \"%s\"", సందేశం_2, మార్గం);
		ఆపు;
	}
	ఒకవేళ (k != ఖాళీ && *k == ఖాళీ)
		debug("no %s loaded from %s", సందేశం_2, మార్గం);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
స్థిర శూన్య
process_config_files(స్థిరరాశి అక్షరం *host_name, నిర్మాణం passwd *pw,
    పూర్ణాంకం final_pass, పూర్ణాంకం *want_final_pass)
{
	అక్షరం *cmd, buf[PATH_MAX];
	పూర్ణాంకం r;

	ఒకవేళ ((cmd = sshbuf_dup_string(command)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	ఒకవేళ (config != ఖాళీ) {
		ఒకవేళ (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} లేకపోతే {
		r = snprintf(buf, పరిమాణం buf, "%s/%s", pw->pw_dir,
		    మార్గం_SSH_USER_CONFFILE);
		ఒకవేళ (r > 0 && (కొలత_t)r < పరిమాణం(buf))
			(శూన్య)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(శూన్య)read_config_file(మార్గం_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	విడుదల(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
స్థిర శూన్య
సమితి_addrinfo_పోర్టు(నిర్మాణం addrinfo *addrs, పూర్ణాంకం పోర్టు)
{
	నిర్మాణం addrinfo *addr;

	కొరకు (addr = addrs; addr != ఖాళీ; addr = addr->ai_next) {
		ఎంపిక (addr->ai_family) {
		స్థితి AF_INET:
			((నిర్మాణం sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(పోర్టు);
			ఆపు;
		స్థితి AF_INET6:
			((నిర్మాణం sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(పోర్టు);
			ఆపు;
		}
	}
}

/*
 * Main program for the ssh client.
 */
పూర్ణాంకం
ప్రధాన(పూర్ణాంకం ac, అక్షరం **av)
{
	నిర్మాణం ssh *ssh = ఖాళీ;
	పూర్ణాంకం i, r, opt, exit_స్థితి, use_syslog, direct, timeout_ms;
	పూర్ణాంకం was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	పూర్ణాంకం user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	అక్షరం *p, *cp, *పంక్తి, *argv0, *logfile, *వాదనలు;
	అక్షరం cname[NI_MAXHOST], thishost[NI_MAXHOST];
	నిర్మాణం stat st;
	నిర్మాణం passwd *pw;
	బాహ్య పూర్ణాంకం optind, optreset;
	బాహ్య అక్షరం *optarg;
	నిర్మాణం Forward fwd;
	నిర్మాణం addrinfo *addrs = ఖాళీ;
	కొలత_t n, len;
	u_int j;
	నిర్మాణం utsname utsname;
	నిర్మాణం ssh_conn_info *cinfo = ఖాళీ;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#నిర్వచితం_కాకపోతే HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, పరిమాణం(*saved_av));
	కొరకు (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ఖాళీ;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#అయితే_ముగింపు

	విత్తనం_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	ఒకవేళ (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		నిష్క్రమించు(255);
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
	ఒకవేళ ((ssh = ssh_alloc_session_state()) == ఖాళీ)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	వాదనలు = argv_assemble(ac, av); /* logged later */
	host = ఖాళీ;
	use_syslog = 0;
	logfile = ఖాళీ;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	అయితే ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		ఎంపిక (opt) {
		స్థితి '1':
			fatal("SSH protocol v.1 is no longer supported");
			ఆపు;
		స్థితి '2':
			/* Ignored */
			ఆపు;
		స్థితి '4':
			options.చిరునామా_family = AF_INET;
			ఆపు;
		స్థితి '6':
			options.చిరునామా_family = AF_INET6;
			ఆపు;
		స్థితి 'n':
			options.stdin_null = 1;
			ఆపు;
		స్థితి 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			ఆపు;
		స్థితి 'x':
			options.forward_x11 = 0;
			ఆపు;
		స్థితి 'X':
			options.forward_x11 = 1;
			ఆపు;
		స్థితి 'y':
			use_syslog = 1;
			ఆపు;
		స్థితి 'E':
			logfile = optarg;
			ఆపు;
		స్థితి 'G':
			config_test = 1;
			ఆపు;
		స్థితి 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			ఆపు;
		స్థితి 'Z':
			dump_pubkeys = 1;
			ఆపు;
		స్థితి 'g':
			options.fwd_opts.gateway_ports = 1;
			ఆపు;
		స్థితి 'O':
			ఒకవేళ (options.stdio_forward_host != ఖాళీ)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			లేకపోతే ఒకవేళ (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			ఒకవేళ (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			లేకపోతే ఒకవేళ (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			లేకపోతే ఒకవేళ (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			లేకపోతే ఒకవేళ (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			లేకపోతే ఒకవేళ (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			లేకపోతే ఒకవేళ (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			లేకపోతే ఒకవేళ (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			లేకపోతే ఒకవేళ (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			లేకపోతే
				fatal("Invalid multiplex command.");
			ఆపు;
		స్థితి 'P':
			ఒకవేళ (options.ట్యాగ్ == ఖాళీ)
				options.ట్యాగ్ = xstrdup(optarg);
			ఆపు;
		స్థితి 'Q':
			cp = ఖాళీ;
			ఒకవేళ (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			లేకపోతే ఒకవేళ (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			లేకపోతే ఒకవేళ (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			లేకపోతే ఒకవేళ (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			లేకపోతే ఒకవేళ (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = అక్షరశ్రేణి_పొడవు(cp);
				కొరకు (n = 0; n < len; n++)
					ఒకవేళ (cp[n] == ',')
						cp[n] = '\n';
			} లేకపోతే ఒకవేళ (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			ఒకవేళ (cp == ఖాళీ)
				fatal("Unsupported query \"%s\"", optarg);
			రాయి("%s\n", cp);
			విడుదల(cp);
			నిష్క్రమించు(0);
			ఆపు;
		స్థితి 'a':
			options.forward_agent = 0;
			ఆపు;
		స్థితి 'A':
			options.forward_agent = 1;
			ఆపు;
		స్థితి 'k':
			options.gss_deleg_creds = 0;
			ఆపు;
		స్థితి 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			ఆపు;
		స్థితి 'i':
			p = tilde_expand_filename(optarg, getuid());
			ఒకవేళ (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			లేకపోతే
				కూడు_తటస్థం_file(&options, ఖాళీ, p, 1);
			విడుదల(p);
			ఆపు;
		స్థితి 'I':
#నిర్వచితమైతే ENABLE_PKCS11
			విడుదల(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#లేకపోతే
			fprintf(stderr, "no support for PKCS#11.\n");
#అయితే_ముగింపు
			ఆపు;
		స్థితి 'J':
			ఒకవేళ (options.jump_host != ఖాళీ) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			ఒకవేళ (options.proxy_command != ఖాళీ)
				fatal("Cannot specify -J with ProxyCommand");
			ఒకవేళ (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			ఆపు;
		స్థితి 't':
			ఒకవేళ (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			లేకపోతే
				options.request_tty = REQUEST_TTY_YES;
			ఆపు;
		స్థితి 'v':
			ఒకవేళ (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} లేకపోతే {
				ఒకవేళ (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			ఆపు;
		స్థితి 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_సంస్కరణ);
			నిష్క్రమించు(0);
			ఆపు;
		స్థితి 'w':
			ఒకవేళ (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			ఒకవేళ (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				నిష్క్రమించు(255);
			}
			ఆపు;
		స్థితి 'W':
			ఒకవేళ (options.stdio_forward_host != ఖాళీ)
				fatal("stdio forward already specified");
			ఒకవేళ (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			ఒకవేళ (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_పోర్టు == పోర్టు_STREAMLOCAL ?
				    fwd.listen_మార్గం : fwd.listen_host;
				options.stdio_forward_పోర్టు = fwd.listen_పోర్టు;
				విడుదల(fwd.connect_host);
			} లేకపోతే {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				నిష్క్రమించు(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			ఆపు;
		స్థితి 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			ఆపు;
		స్థితి 'e':
			ఒకవేళ (అక్షరశ్రేణి_పొడవు(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పొడవు(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			లేకపోతే ఒకవేళ (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			లేకపోతే {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				నిష్క్రమించు(255);
			}
			ఆపు;
		స్థితి 'c':
			ఒకవేళ (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				నిష్క్రమించు(255);
			}
			విడుదల(options.ciphers);
			options.ciphers = xstrdup(optarg);
			ఆపు;
		స్థితి 'm':
			ఒకవేళ (mac_valid(optarg)) {
				విడుదల(options.macs);
				options.macs = xstrdup(optarg);
			} లేకపోతే {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				నిష్క్రమించు(255);
			}
			ఆపు;
		స్థితి 'M':
			ఒకవేళ (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			లేకపోతే
				options.control_master = SSHCTL_MASTER_YES;
			ఆపు;
		స్థితి 'p':
			ఒకవేళ (options.పోర్టు == -1) {
				options.పోర్టు = a2port(optarg);
				ఒకవేళ (options.పోర్టు <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					నిష్క్రమించు(255);
				}
			}
			ఆపు;
		స్థితి 'l':
			ఒకవేళ (options.user == ఖాళీ) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			ఆపు;

		స్థితి 'L':
			ఒకవేళ (parse_forward(&fwd, optarg, 0, 0))
				కూడు_local_forward(&options, &fwd);
			లేకపోతే {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				నిష్క్రమించు(255);
			}
			ఆపు;

		స్థితి 'R':
			ఒకవేళ (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				కూడు_remote_forward(&options, &fwd);
			} లేకపోతే {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				నిష్క్రమించు(255);
			}
			ఆపు;

		స్థితి 'D':
			ఒకవేళ (parse_forward(&fwd, optarg, 1, 0)) {
				కూడు_local_forward(&options, &fwd);
			} లేకపోతే {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				నిష్క్రమించు(255);
			}
			ఆపు;

		స్థితి 'C':
#నిర్వచితమైతే WITH_ZLIB
			options.compression = 1;
#లేకపోతే
			error("Compression not supported, disabling.");
#అయితే_ముగింపు
			ఆపు;
		స్థితి 'N':
			ఒకవేళ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			ఆపు;
		స్థితి 'T':
			options.request_tty = REQUEST_TTY_NO;
			ఆపు;
		స్థితి 'o':
			పంక్తి = xstrdup(optarg);
			ఒకవేళ (process_config_పంక్తి(&options, pw,
			    host ? host : "", host ? host : "", "", పంక్తి,
			    "command-line", 0, ఖాళీ, SSHCONF_USERCONF) != 0)
				నిష్క్రమించు(255);
			విడుదల(పంక్తి);
			ఆపు;
		స్థితి 's':
			ఒకవేళ (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			ఆపు;
		స్థితి 'S':
			విడుదల(options.control_మార్గం);
			options.control_మార్గం = xstrdup(optarg);
			ఆపు;
		స్థితి 'b':
			options.bind_చిరునామా = optarg;
			ఆపు;
		స్థితి 'B':
			options.bind_interface = optarg;
			ఆపు;
		స్థితి 'F':
			config = optarg;
			ఆపు;
		అప్రమేయ:
			usage();
		}
	}

	ఒకవేళ (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	ఒకవేళ (ac > 0 && !host) {
		పూర్ణాంకం tport;
		అక్షరం *tuser;
		ఎంపిక (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		స్థితి -1:
			usage();
			ఆపు;
		స్థితి 0:
			ఒకవేళ (options.user == ఖాళీ) {
				options.user = tuser;
				tuser = ఖాళీ;
				user_on_commandline = 1;
			}
			విడుదల(tuser);
			ఒకవేళ (options.పోర్టు == -1 && tport != -1)
				options.పోర్టు = tport;
			ఆపు;
		అప్రమేయ:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			ఒకవేళ (cp != ఖాళీ) {
				ఒకవేళ (cp == p)
					usage();
				ఒకవేళ (options.user == ఖాళీ) {
					options.user = p;
					p = ఖాళీ;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				విడుదల(p);
			} లేకపోతే
				host = p;
			ఆపు;
		}
		ఒకవేళ (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			వెళ్ళు again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	ఒకవేళ (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	ఒకవేళ (options.user != ఖాళీ && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	ఒకవేళ (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	ఒకవేళ ((command = sshbuf_new()) == ఖాళీ)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	ఒకవేళ (!ac) {
		/* No command specified - execute shell on a tty. */
		ఒకవేళ (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} లేకపోతే {
		/* A command has been specified.  Store it into the buffer. */
		కొరకు (i = 0; i < ac; i++) {
			ఒకవేళ ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	ఒకవేళ (use_syslog && logfile != ఖాళీ)
		fatal("Can't specify both -y and -E");
	ఒకవేళ (logfile != ఖాళీ)
		log_redirect_stderr_గమ్యం(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_సమితి ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_సమితి ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_సంస్కరణ);
	ఒకవేళ (uname(&utsname) != 0) {
		memset(&utsname, 0, పరిమాణం(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", పరిమాణం(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.సంస్కరణ, utsname.machine);
	debug3("Started with: %s", వాదనలు);
	విడుదల(వాదనలు);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	ఒకవేళ (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	ఒకవేళ (options.hostname != ఖాళీ) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (అక్షరం *)ఖాళీ);
		విడుదల(host);
		host = cp;
		విడుదల(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	ఒకవేళ ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	ఒకవేళ (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
		addrs = resolve_canonicalize(&host, options.పోర్టు);

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
	ఒకవేళ (addrs == ఖాళీ && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		ఒకవేళ ((addrs = resolve_host(host, options.పోర్టు,
		    direct, cname, పరిమాణం(cname))) == ఖాళీ) {
			/* Don't fatal proxied host names not in the DNS */
			ఒకవేళ (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} లేకపోతే
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	ఒకవేళ (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	ఒకవేళ (want_final_pass) {
		debug("re-parsing configuration");
		విడుదల(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ఖాళీ);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		ఒకవేళ (addrs != ఖాళీ && options.పోర్టు > 0)
			సమితి_addrinfo_పోర్టు(addrs, options.పోర్టు);
	}

	/* Fill configuration defaults. */
	ఒకవేళ (fill_default_options(&options) != 0)
		cleanup_exit(255);

	ఒకవేళ (options.user == ఖాళీ) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	ఒకవేళ (options.jump_host != ఖాళీ) {
		అక్షరం పోర్టు_s[8];
		స్థిరరాశి అక్షరం *jumpuser = options.jump_user, *sshbin = argv0;
		పూర్ణాంకం పోర్టు = options.పోర్టు, jumpport = options.jump_పోర్టు;

		ఒకవేళ (పోర్టు <= 0)
			పోర్టు = default_ssh_పోర్టు();
		ఒకవేళ (jumpport <= 0)
			jumpport = default_ssh_పోర్టు();
		ఒకవేళ (jumpuser == ఖాళీ)
			jumpuser = options.user;
		ఒకవేళ (strcmp(options.jump_host, host) == 0 && పోర్టు == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		ఒకవేళ (strchr(argv0, '/') != ఖాళీ && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		ఒకవేళ (options.proxy_command != ఖాళీ &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(పోర్టు_s, పరిమాణం(పోర్టు_s), "%d", options.jump_పోర్టు);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ఖాళీ ? "" : " -l ",
		    options.jump_user == ఖాళీ ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_పోర్టు <= 0 ? "" : " -p ",
		    options.jump_పోర్టు <= 0 ? "" : పోర్టు_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ఖాళీ ? "" : " -J ",
		    options.jump_extra == ఖాళీ ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ఖాళీ ? "" : " -F ",
		    config == ఖాళీ ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	ఒకవేళ (options.పోర్టు == 0)
		options.పోర్టు = default_ssh_పోర్టు();
	channel_సమితి_af(ssh, options.చిరునామా_family);
	ssh_packet_సమితి_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	ఒకవేళ (options.host_కీలకం_alias != ఖాళీ)
		lowercase(options.host_కీలకం_alias);
	ఒకవేళ (options.proxy_command != ఖాళీ &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	ఒకవేళ (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		ఒకవేళ (options.control_persist && options.control_మార్గం != ఖాళీ) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} లేకపోతే ఒకవేళ (sshbuf_len(command) != 0 ||
		    options.remote_command != ఖాళీ ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} లేకపోతే ఒకవేళ (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	ఒకవేళ (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	ఒకవేళ (sshbuf_len(command) != 0 && options.remote_command != ఖాళీ)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	ఒకవేళ (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ఖాళీ &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	కొరకు (j = 0; j < options.అంకె_log_verbose; j++) {
		ఒకవేళ (strcasecmp(options.log_verbose[j], "none") == 0)
			ఆపు;
		log_verbose_కూడు(options.log_verbose[j]);
	}

	ఒకవేళ (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	ఒకవేళ (sshbuf_len(command) == 0 && options.remote_command == ఖాళీ)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	ఒకవేళ (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	ఒకవేళ ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		ఒకవేళ (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, పరిమాణం(*cinfo));
	ఒకవేళ (gethostname(thishost, పరిమాణం(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.పోర్టు);
	xasprintf(&cinfo->uidstr, "%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_కీలకం_alias ?
	    options.host_కీలకం_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ఖాళీ ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	ఒకవేళ (!user_on_commandline && !user_was_default) {
		ఒకవేళ ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు_NOUSER(cinfo),
		    (అక్షరం *)ఖాళీ)) == ఖాళీ)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		విడుదల(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	ఒకవేళ ((user_on_commandline || user_expanded) &&
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
	ఒకవేళ (options.remote_command != ఖాళీ) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		విడుదల(cp);
		ఒకవేళ ((r = sshbuf_put(command, options.remote_command,
		    అక్షరశ్రేణి_పొడవు(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	ఒకవేళ (options.control_మార్గం != ఖాళీ) {
		cp = tilde_expand_filename(options.control_మార్గం, getuid());
		విడుదల(options.control_మార్గం);
		options.control_మార్గం = default_client_percent_dollar_expand(cp,
		    cinfo);
		విడుదల(cp);
	}

	ఒకవేళ (options.తటస్థం_agent != ఖాళీ) {
		p = tilde_expand_filename(options.తటస్థం_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		విడుదల(p);
		విడుదల(options.తటస్థం_agent);
		options.తటస్థం_agent = cp;
	}

	కొరకు (j = 0; j < options.అంకె_revoked_host_కీలకాలు; j++) {
		p = tilde_expand_filename(options.revoked_host_కీలకాలు[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		విడుదల(p);
		విడుదల(options.revoked_host_కీలకాలు[j]);
		options.revoked_host_కీలకాలు[j] = cp;
	}

	ఒకవేళ (options.forward_agent_sock_మార్గం != ఖాళీ) {
		p = tilde_expand_filename(options.forward_agent_sock_మార్గం,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		విడుదల(p);
		విడుదల(options.forward_agent_sock_మార్గం);
		options.forward_agent_sock_మార్గం = cp;
		ఒకవేళ (stat(options.forward_agent_sock_మార్గం, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_మార్గం, strerror(errno));
			ఒకవేళ (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	ఒకవేళ (options.సంస్కరణ_addendum != ఖాళీ) {
		cp = default_client_percent_dollar_expand(
		    options.సంస్కరణ_addendum, cinfo);
		విడుదల(options.సంస్కరణ_addendum);
		options.సంస్కరణ_addendum = cp;
	}

	ఒకవేళ (options.అంకె_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		ఒకవేళ (options.అంకె_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		విడుదల(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ఖాళీ;
		options.అంకె_system_hostfiles = 0;
	}

	ఒకవేళ (options.అంకె_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		ఒకవేళ (options.అంకె_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		విడుదల(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ఖాళీ;
		options.అంకె_user_hostfiles = 0;
	}
	కొరకు (j = 0; j < options.అంకె_user_hostfiles; j++) {
		ఒకవేళ (options.user_hostfiles[j] == ఖాళీ)
			కొనసాగు;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		ఒకవేళ (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		విడుదల(options.user_hostfiles[j]);
		విడుదల(cp);
		options.user_hostfiles[j] = p;
	}

	కొరకు (j = 0; j < options.అంకె_setenv; j++) {
		అక్షరం *name = options.setenv[j], *విలువ;

		ఒకవేళ (name == ఖాళీ)
			కొనసాగు;
		/* Expand only the value portion, not the variable name. */
		ఒకవేళ ((విలువ = strchr(name, '=')) == ఖాళీ) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*విలువ++ = '\0';
		cp = default_client_percent_dollar_expand(విలువ, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		ఒకవేళ (strcmp(విలువ, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, విలువ, cp);
		}
		విడుదల(options.setenv[j]);
		విడుదల(cp);
		options.setenv[j] = p;
	}

	కొరకు (i = 0; i < options.అంకె_local_forwards; i++) {
		ఒకవేళ (options.local_forwards[i].listen_మార్గం != ఖాళీ) {
			cp = options.local_forwards[i].listen_మార్గం;
			p = options.local_forwards[i].listen_మార్గం =
			    default_client_percent_expand(cp, cinfo);
			ఒకవేళ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			విడుదల(cp);
		}
		ఒకవేళ (options.local_forwards[i].connect_మార్గం != ఖాళీ) {
			cp = options.local_forwards[i].connect_మార్గం;
			p = options.local_forwards[i].connect_మార్గం =
			    default_client_percent_expand(cp, cinfo);
			ఒకవేళ (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			విడుదల(cp);
		}
	}

	కొరకు (i = 0; i < options.అంకె_remote_forwards; i++) {
		ఒకవేళ (options.remote_forwards[i].listen_మార్గం != ఖాళీ) {
			cp = options.remote_forwards[i].listen_మార్గం;
			p = options.remote_forwards[i].listen_మార్గం =
			    default_client_percent_expand(cp, cinfo);
			ఒకవేళ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			విడుదల(cp);
		}
		ఒకవేళ (options.remote_forwards[i].connect_మార్గం != ఖాళీ) {
			cp = options.remote_forwards[i].connect_మార్గం;
			p = options.remote_forwards[i].connect_మార్గం =
			    default_client_percent_expand(cp, cinfo);
			ఒకవేళ (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			విడుదల(cp);
		}
	}

	ఒకవేళ (config_test) {
		dump_client_config(&options, host);
		నిష్క్రమించు(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	ఒకవేళ (options.sk_provider != ఖాళీ && *options.sk_provider == '$' &&
	    అక్షరశ్రేణి_పొడవు(options.sk_provider) > 1) {
		ఒకవేళ ((cp = getenv(options.sk_provider + 1)) == ఖాళీ) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			విడుదల(options.sk_provider);
			options.sk_provider = ఖాళీ;
		} లేకపోతే {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			విడుదల(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	ఒకవేళ (muxclient_command != 0 && options.control_మార్గం == ఖాళీ)
		fatal("No ControlPath specified for \"-O\" command");
	ఒకవేళ (options.control_మార్గం != ఖాళీ) {
		పూర్ణాంకం sock;
		ఒకవేళ ((sock = muxclient(options.control_మార్గం)) >= 0) {
			ఒకవేళ (ssh_packet_సమితి_connection(ssh, sock, sock) == ఖాళీ)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_సమితి_mux(ssh);
			వెళ్ళు skip_connect;
		}
	}

	/* load options.identity_files */
	ఎక్కించు_ప్రజా_తటస్థం_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	ఒకవేళ (options.తటస్థం_agent &&
	    strcmp(options.తటస్థం_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		ఒకవేళ (strcmp(options.తటస్థం_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} లేకపోతే {
			cp = options.తటస్థం_agent;
			/* legacy (limited) format */
			ఒకవేళ (cp[0] == '$' && cp[1] != '{') {
				ఒకవేళ (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				ఒకవేళ ((p = getenv(cp + 1)) == ఖాళీ)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				లేకపోతే
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} లేకపోతే {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	ఒకవేళ (dump_pubkeys) {
		pubkey_dump(ssh);
		నిష్క్రమించు(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	ఒకవేళ (addrs == ఖాళీ && options.proxy_command == ఖాళీ) {
		debug2("resolving \"%s\" port %d", host, options.పోర్టు);
		ఒకవేళ ((addrs = resolve_host(host, options.పోర్టు, 1,
		    cname, పరిమాణం(cname))) == ఖాళీ)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	ఒకవేళ (options.connection_timeout >= గరిష్ఠ_పూర్ణాంకం/1000)
		timeout_ms = గరిష్ఠ_పూర్ణాంకం;
	లేకపోతే
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	కొరకు (j = 0; j < options.అంకె_channel_timeouts; j++) {
		ద్విగుణ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		ఒకవేళ (parse_నమూనా_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_కూడు_timeout(ssh, cp, timeout);
		విడుదల(cp);
	}
	channel_సమితి_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	ఒకవేళ (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.పోర్టు, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		నిష్క్రమించు(255);


	ssh_packet_సమితి_timeout(ssh, options.server_alive_interval,
	    options.server_alive_లెక్క_max);

	ఒకవేళ (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_దత్తాంశం.nkeys = 0;
	sensitive_దత్తాంశం.కీలకాలు = ఖాళీ;
	ఒకవేళ (options.hostbased_authentication) {
		పూర్ణాంకం loaded = 0;

		sensitive_దత్తాంశం.nkeys = 10;
		sensitive_దత్తాంశం.కీలకాలు = xcalloc(sensitive_దత్తాంశం.nkeys,
		    పరిమాణం(*sensitive_దత్తాంశం.కీలకాలు));

		/* XXX check errors? */
#నిర్వచించు L_PUBKEY(p,o) చేయి { \
	ఒకవేళ ((o) >= sensitive_దత్తాంశం.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_ఎక్కించు(sshkey_ఎక్కించు_ప్రజా(p, &(sensitive_దత్తాంశం.కీలకాలు[o]), ఖాళీ), \
	    &(sensitive_దత్తాంశం.కీలకాలు[o]), p, "hostbased pubkey"); \
	ఒకవేళ (sensitive_దత్తాంశం.కీలకాలు[o] != ఖాళీ) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} అయితే (0)
#నిర్వచించు L_CERT(p,o) చేయి { \
	ఒకవేళ ((o) >= sensitive_దత్తాంశం.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_ఎక్కించు(sshkey_ఎక్కించు_cert(p, &(sensitive_దత్తాంశం.కీలకాలు[o])), \
	    &(sensitive_దత్తాంశం.కీలకాలు[o]), p, "hostbased cert"); \
	ఒకవేళ (sensitive_దత్తాంశం.కీలకాలు[o] != ఖాళీ) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} అయితే (0)

		ఒకవేళ (options.hostbased_authentication == 1) {
			L_CERT(మార్గం_HOST_ECDSA_కీలకం_FILE, 0);
			L_CERT(మార్గం_HOST_ED25519_కీలకం_FILE, 1);
			L_CERT(మార్గం_HOST_RSA_కీలకం_FILE, 2);
			L_CERT(మార్గం_HOST_MLDSA44_ED25519_కీలకం_FILE, 3);
			L_PUBKEY(మార్గం_HOST_ECDSA_కీలకం_FILE, 4);
			L_PUBKEY(మార్గం_HOST_ED25519_కీలకం_FILE, 5);
			L_PUBKEY(మార్గం_HOST_RSA_కీలకం_FILE, 6);
			L_PUBKEY(మార్గం_HOST_MLDSA44_ED25519_కీలకం_FILE, 7);
			ఒకవేళ (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	ఒకవేళ (options.forward_agent && options.forward_agent_sock_మార్గం != ఖాళీ) {
		cp = options.forward_agent_sock_మార్గం;
		ఒకవేళ (cp[0] == '$') {
			ఒకవేళ (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			ఒకవేళ ((p = getenv(cp + 1)) != ఖాళీ)
				forward_agent_sock_మార్గం = xstrdup(p);
			లేకపోతే
				options.forward_agent = 0;
			విడుదల(cp);
		} లేకపోతే {
			forward_agent_sock_మార్గం = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.అంకె_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.అంకె_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_దత్తాంశం, host, &hostaddr, options.పోర్టు,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	ఒకవేళ (sensitive_దత్తాంశం.nkeys != 0) {
		కొరకు (i = 0; i < sensitive_దత్తాంశం.nkeys; i++) {
			ఒకవేళ (sensitive_దత్తాంశం.కీలకాలు[i] != ఖాళీ) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_దత్తాంశం.కీలకాలు[i]);
				sensitive_దత్తాంశం.కీలకాలు[i] = ఖాళీ;
			}
		}
		విడుదల(sensitive_దత్తాంశం.కీలకాలు);
	}
	కొరకు (i = 0; i < options.అంకె_తటస్థం_files; i++) {
		విడుదల(options.తటస్థం_files[i]);
		options.తటస్థం_files[i] = ఖాళీ;
		ఒకవేళ (options.తటస్థం_కీలకాలు[i]) {
			sshkey_free(options.తటస్థం_కీలకాలు[i]);
			options.తటస్థం_కీలకాలు[i] = ఖాళీ;
		}
	}
	కొరకు (i = 0; i < options.అంకె_certificate_files; i++) {
		విడుదల(options.certificate_files[i]);
		options.certificate_files[i] = ఖాళీ;
	}

#నిర్వచితమైతే ENABLE_PKCS11
	(శూన్య)pkcs11_del_provider(options.pkcs11_provider);
#అయితే_ముగింపు

 skip_connect:
	ఒకవేళ (addrs != ఖాళీ)
		freeaddrinfo(addrs);
	exit_స్థితి = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	ఒకవేళ (options.control_మార్గం != ఖాళీ && muxserver_sock != -1)
		unlink(options.control_మార్గం);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	తిరిగి exit_స్థితి;
}

స్థిర శూన్య
control_persist_detach(శూన్య)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	ఎంపిక ((pid = fork())) {
	స్థితి -1:
		fatal_f("fork: %s", strerror(errno));
	స్థితి 0:
		/* Child: master process continues mainloop */
		ఆపు;
	అప్రమేయ:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (దీర్ఘ)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		close(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(శూన్య)muxclient(options.control_మార్గం);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	ఒకవేళ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_మార్గం);
}

/* Do fork() after authentication. Used by "ssh -f" */
స్థిర శూన్య
fork_postauth(శూన్య)
{
	ఒకవేళ (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	ఒకవేళ (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	ఒకవేళ (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

స్థిర శూన్య
forwarding_success(శూన్య)
{
	ఒకవేళ (forward_confirms_pending == -1)
		తిరిగి;
	ఒకవేళ (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		ఒకవేళ (options.fork_after_authentication)
			fork_postauth();
	} లేకపోతే {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

నిర్మాణం rfwd_confirm_ctx {
	పూర్ణాంకం fid;
};

/* Callback for remote forward global requests */
స్థిర శూన్య
ssh_confirm_remote_forward(నిర్మాణం ssh *ssh, పూర్ణాంకం type, uint32_t seq, శూన్య *ctxt)
{
	నిర్మాణం rfwd_confirm_ctx *rctx = (నిర్మాణం rfwd_confirm_ctx *)ctxt;
	నిర్మాణం Forward *rfwd;
	u_int పోర్టు;
	పూర్ణాంకం r;

	ఒకవేళ (rctx->fid < 0 || rctx->fid >= options.అంకె_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, పరిమాణం(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_సందేశం_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_మార్గం ? rfwd->listen_మార్గం :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_మార్గం || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_పోర్టు, rfwd->connect_మార్గం ? rfwd->connect_మార్గం :
	    rfwd->connect_host, rfwd->connect_పోర్టు);
	ఒకవేళ (rfwd->listen_మార్గం == ఖాళీ && rfwd->listen_పోర్టు == 0) {
		ఒకవేళ (type == SSH2_సందేశం_REQUEST_SUCCESS) {
			ఒకవేళ ((r = sshpkt_get_u32(ssh, &పోర్టు)) != 0)
				fatal_fr(r, "parse packet");
			ఒకవేళ (పోర్టు > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", పోర్టు,
				    rfwd->connect_host, rfwd->connect_పోర్టు);
				/* Ensure failure processing runs below */
				type = SSH2_సందేశం_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} లేకపోతే {
				rfwd->allocated_పోర్టు = (పూర్ణాంకం)పోర్టు;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_పోర్టు, rfwd->connect_మార్గం ?
				    rfwd->connect_మార్గం : rfwd->connect_host,
				    rfwd->connect_పోర్టు);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_పోర్టు);
			}
		} లేకపోతే {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	ఒకవేళ (type == SSH2_సందేశం_REQUEST_FAILURE) {
		ఒకవేళ (options.exit_on_forward_failure) {
			ఒకవేళ (rfwd->listen_మార్గం != ఖాళీ)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_మార్గం);
			లేకపోతే
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_పోర్టు);
		} లేకపోతే {
			ఒకవేళ (rfwd->listen_మార్గం != ఖాళీ)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_మార్గం);
			లేకపోతే
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_పోర్టు);
		}
	}
	forwarding_success();
}

స్థిర శూన్య
client_cleanup_stdio_fwd(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం force, శూన్య *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

స్థిర శూన్య
ssh_stdio_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం success, శూన్య *arg)
{
	ఒకవేళ (!success)
		fatal("stdio forwarding failed");
}

స్థిర శూన్య
ssh_tun_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం success, శూన్య *arg)
{
	ఒకవేళ (!success) {
		error("Tunnel forwarding failed");
		ఒకవేళ (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

స్థిర శూన్య
ssh_init_stdio_forwarding(నిర్మాణం ssh *ssh)
{
	Channel *c;
	పూర్ణాంకం లోపల, బహిర్గతం;

	ఒకవేళ (options.stdio_forward_host == ఖాళీ)
		తిరిగి;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_పోర్టు);

	ఒకవేళ ((లోపల = dup(STDIN_FILENO)) == -1 ||
	    (బహిర్గతం = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	ఒకవేళ ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_పోర్టు, లోపల, బహిర్గతం,
	    CHANNEL_NONBLOCK_STDIO)) == ఖాళీ)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_రిజిస్టరు_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_రిజిస్టరు_open_confirm(ssh, c->self, ssh_stdio_confirm, ఖాళీ);
}

స్థిర శూన్య
ssh_init_forward_permissions(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *what, అక్షరం **opens,
    u_int అంకె_opens)
{
	u_int i;
	పూర్ణాంకం పోర్టు;
	అక్షరం *addr, *arg, *oarg;
	పూర్ణాంకం where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	ఒకవేళ (అంకె_opens == 0)
		తిరిగి; /* permit any */

	/* handle keywords: "any" / "none" */
	ఒకవేళ (అంకె_opens == 1 && strcmp(opens[0], "any") == 0)
		తిరిగి;
	ఒకవేళ (అంకె_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		తిరిగి;
	}
	/* Otherwise treat it as a list of permitted host:port */
	కొరకు (i = 0; i < అంకె_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		ఒకవేళ (addr == ఖాళీ)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		ఒకవేళ (arg == ఖాళీ || ((పోర్టు = permitopen_పోర్టు(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_కూడు_permission(ssh, FORWARD_ADM,
		    where, addr, పోర్టు);
		విడుదల(oarg);
	}
}

స్థిర శూన్య
ssh_init_forwarding(నిర్మాణం ssh *ssh, అక్షరం **ifname)
{
	పూర్ణాంకం success = 0;
	పూర్ణాంకం i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.అంకె_permitted_remote_opens);

	ఒకవేళ (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	కొరకు (i = 0; i < options.అంకె_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_మార్గం != ఖాళీ) ?
		    options.local_forwards[i].listen_మార్గం :
		    (options.local_forwards[i].listen_host == ఖాళీ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_పోర్టు,
		    (options.local_forwards[i].connect_మార్గం != ఖాళీ) ?
		    options.local_forwards[i].connect_మార్గం :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_పోర్టు);
		success += channel_అమరిక_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	ఒకవేళ (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	ఒకవేళ (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	కొరకు (i = 0; i < options.అంకె_remote_forwards; i++) {
		నిర్మాణం rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_మార్గం != ఖాళీ) ?
		    options.remote_forwards[i].listen_మార్గం :
		    (options.remote_forwards[i].listen_host == ఖాళీ) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_పోర్టు,
		    (options.remote_forwards[i].connect_మార్గం != ఖాళీ) ?
		    options.remote_forwards[i].connect_మార్గం :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_పోర్టు);
		ఒకవేళ ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, పరిమాణం(*rctx));
			rctx->fid = i;
			client_రిజిస్టరు_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} లేకపోతే ఒకవేళ (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		లేకపోతే
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	ఒకవేళ (options.tun_open != SSH_TUNMODE_NO) {
		ఒకవేళ ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ఖాళీ)) != ఖాళీ)
			forward_confirms_pending++;
		లేకపోతే ఒకవేళ (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		లేకపోతే
			error("Could not request tunnel forwarding.");
	}
	ఒకవేళ (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

స్థిర శూన్య
check_agent_present(శూన్య)
{
	పూర్ణాంకం r;

	ఒకవేళ (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		ఒకవేళ ((r = ssh_get_authentication_socket(ఖాళీ)) != 0) {
			options.forward_agent = 0;
			ఒకవేళ (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

స్థిర శూన్య
ssh_session2_అమరిక(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం success, శూన్య *arg)
{
	బాహ్య అక్షరం **environ;
	స్థిరరాశి అక్షరం *display, *పదం;
	అక్షరం *proto = ఖాళీ, *దత్తాంశం = ఖాళీ;

	ఒకవేళ (!success)
		తిరిగి; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	ఒకవేళ (display == ఖాళీ && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	ఒకవేళ (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &దత్తాంశం) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    దత్తాంశం, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	ఒకవేళ (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	ఒకవేళ ((పదం = lookup_env_లోపల_list("TERM", options.setenv,
	    options.అంకె_setenv)) == ఖాళీ || *పదం == '\0')
		పదం = getenv("TERM");
	client_session2_అమరిక(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, పదం,
	    ఖాళీ, fileno(stdin), command, environ);
}

/* open new channel for a session */
స్థిర పూర్ణాంకం
ssh_session2_open(నిర్మాణం ssh *ssh)
{
	Channel *c;
	పూర్ణాంకం కిటికీ, packetmax, లోపల, బహిర్గతం, err;

	ఒకవేళ (options.stdin_null) {
		లోపల = open(_PATH_DEVNULL, O_RDONLY);
	} లేకపోతే {
		లోపల = dup(STDIN_FILENO);
	}
	బహిర్గతం = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	ఒకవేళ (లోపల == -1 || బహిర్గతం == -1 || err == -1)
		fatal("dup() in/out/err failed");

	కిటికీ = CHAN_SES_కిటికీ_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ఒకవేళ (tty_flag) {
		కిటికీ >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, లోపల, బహిర్గతం, err,
	    కిటికీ, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	ఒకవేళ (tty_flag)
		channel_సమితి_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	ఒకవేళ (options.session_type != SESSION_TYPE_NONE)
		channel_రిజిస్టరు_open_confirm(ssh, c->self,
		    ssh_session2_అమరిక, ఖాళీ);

	తిరిగి c->self;
}

స్థిర పూర్ణాంకం
ssh_session2(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	పూర్ణాంకం r, id = -1;
	అక్షరం *cp, *tun_fwd_ifname = ఖాళీ;

	/* XXX should be pre-session */
	ఒకవేళ (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	ఒకవేళ (options.local_command != ఖాళీ) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు(cinfo),
		    "T", tun_fwd_ifname == ఖాళీ ? "NONE" : tun_fwd_ifname,
		    (అక్షరం *)ఖాళీ);
		debug3("expanded LocalCommand: %s", options.local_command);
		విడుదల(cp);
	}

	/* Start listening for multiplex clients */
	ఒకవేళ (!ssh_packet_get_mux(ssh))
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
	ఒకవేళ (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		ఒకవేళ ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ఖాళీ))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	ఒకవేళ (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	ఒకవేళ (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	ఒకవేళ (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	ఒకవేళ (options.local_command != ఖాళీ &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	ఒకవేళ (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	ఒకవేళ (options.fork_after_authentication) {
		ఒకవేళ (options.exit_on_forward_failure &&
		    options.అంకె_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} లేకపోతే
			fork_postauth();
	}

	తిరిగి client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
స్థిర శూన్య
ఎక్కించు_ప్రజా_తటస్థం_files(స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	అక్షరం *filename, *cp;
	నిర్మాణం sshkey *బహిరంగ;
	పూర్ణాంకం i;
	u_int n_ids, n_certs;
	అక్షరం *తటస్థం_files[SSH_MAX_తటస్థం_FILES];
	నిర్మాణం sshkey *తటస్థం_కీలకాలు[SSH_MAX_తటస్థం_FILES];
	పూర్ణాంకం తటస్థం_file_userprovided[SSH_MAX_తటస్థం_FILES];
	అక్షరం *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	నిర్మాణం sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	పూర్ణాంకం certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#నిర్వచితమైతే ENABLE_PKCS11
	నిర్మాణం sshkey **కీలకాలు = ఖాళీ;
	అక్షరం **comments = ఖాళీ;
	పూర్ణాంకం nkeys;
#అయితే_ముగింపు /* PKCS11 */

	n_ids = n_certs = 0;
	memset(తటస్థం_files, 0, పరిమాణం(తటస్థం_files));
	memset(తటస్థం_కీలకాలు, 0, పరిమాణం(తటస్థం_కీలకాలు));
	memset(తటస్థం_file_userprovided, 0,
	    పరిమాణం(తటస్థం_file_userprovided));
	memset(certificate_files, 0, పరిమాణం(certificate_files));
	memset(certificates, 0, పరిమాణం(certificates));
	memset(certificate_file_userprovided, 0,
	    పరిమాణం(certificate_file_userprovided));

#నిర్వచితమైతే ENABLE_PKCS11
	ఒకవేళ (options.pkcs11_provider != ఖాళీ &&
	    options.అంకె_తటస్థం_files < SSH_MAX_తటస్థం_FILES &&
	    (pkcs11_init(!options.batch_బహుళకం) == 0) &&
	    (nkeys = pkcs11_కూడు_provider(options.pkcs11_provider, ఖాళీ,
	    &కీలకాలు, &comments)) > 0) {
		కొరకు (i = 0; i < nkeys; i++) {
			ఒకవేళ (n_ids >= SSH_MAX_తటస్థం_FILES) {
				sshkey_free(కీలకాలు[i]);
				విడుదల(comments[i]);
				కొనసాగు;
			}
			తటస్థం_కీలకాలు[n_ids] = కీలకాలు[i];
			తటస్థం_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		విడుదల(కీలకాలు);
		విడుదల(comments);
	}
#అయితే_ముగింపు /* ENABLE_PKCS11 */
	కొరకు (i = 0; i < options.అంకె_తటస్థం_files; i++) {
		ఒకవేళ (n_ids >= SSH_MAX_తటస్థం_FILES ||
		    strcasecmp(options.తటస్థం_files[i], "none") == 0) {
			విడుదల(options.తటస్థం_files[i]);
			options.తటస్థం_files[i] = ఖాళీ;
			కొనసాగు;
		}
		cp = tilde_expand_filename(options.తటస్థం_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		విడుదల(cp);
		check_ఎక్కించు(sshkey_ఎక్కించు_ప్రజా(filename, &బహిరంగ, ఖాళీ),
		    &బహిరంగ, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    బహిరంగ ? బహిరంగ->type : -1);
		విడుదల(options.తటస్థం_files[i]);
		తటస్థం_files[n_ids] = filename;
		తటస్థం_కీలకాలు[n_ids] = బహిరంగ;
		తటస్థం_file_userprovided[n_ids] =
		    options.తటస్థం_file_userprovided[i];
		ఒకవేళ (++n_ids >= SSH_MAX_తటస్థం_FILES)
			కొనసాగు;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		ఒకవేళ (options.అంకె_certificate_files != 0)
			కొనసాగు;
		xasprintf(&cp, "%s-cert", filename);
		check_ఎక్కించు(sshkey_ఎక్కించు_ప్రజా(cp, &బహిరంగ, ఖాళీ),
		    &బహిరంగ, filename, "identity pubkey");
		ఒకవేళ (బహిరంగ == ఖాళీ) {
			విడుదల(cp);
			కొనసాగు;
		}
		ఒకవేళ (!sshkey_is_cert(బహిరంగ)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(బహిరంగ));
			sshkey_free(బహిరంగ);
			విడుదల(cp);
			కొనసాగు;
		}
		విడుదల(cp);
		/* NB. leave filename pointing to private key */
		తటస్థం_files[n_ids] = xstrdup(filename);
		తటస్థం_కీలకాలు[n_ids] = బహిరంగ;
		తటస్థం_file_userprovided[n_ids] =
		    options.తటస్థం_file_userprovided[i];
		n_ids++;
	}

	ఒకవేళ (options.అంకె_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	కొరకు (i = 0; i < options.అంకె_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		విడుదల(cp);

		check_ఎక్కించు(sshkey_ఎక్కించు_ప్రజా(filename, &బహిరంగ, ఖాళీ),
		    &బహిరంగ, filename, "identity cert");
		విడుదల(options.certificate_files[i]);
		options.certificate_files[i] = ఖాళీ;
		ఒకవేళ (బహిరంగ == ఖాళీ) {
			విడుదల(filename);
			కొనసాగు;
		}
		ఒకవేళ (!sshkey_is_cert(బహిరంగ)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(బహిరంగ));
			sshkey_free(బహిరంగ);
			విడుదల(filename);
			కొనసాగు;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = బహిరంగ;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.అంకె_తటస్థం_files = n_ids;
	జ్ఞాపకం_నకలు(options.తటస్థం_files, తటస్థం_files, పరిమాణం(తటస్థం_files));
	జ్ఞాపకం_నకలు(options.తటస్థం_కీలకాలు, తటస్థం_కీలకాలు, పరిమాణం(తటస్థం_కీలకాలు));
	జ్ఞాపకం_నకలు(options.తటస్థం_file_userprovided,
	    తటస్థం_file_userprovided, పరిమాణం(తటస్థం_file_userprovided));

	options.అంకె_certificate_files = n_certs;
	జ్ఞాపకం_నకలు(options.certificate_files,
	    certificate_files, పరిమాణం(certificate_files));
	జ్ఞాపకం_నకలు(options.certificates, certificates, పరిమాణం(certificates));
	జ్ఞాపకం_నకలు(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    పరిమాణం(certificate_file_userprovided));
}

స్థిర శూన్య
main_sigchld_handler(పూర్ణాంకం sig)
{
	పూర్ణాంకం save_errno = errno;
	pid_t pid;
	పూర్ణాంకం స్థితి_2;

	అయితే ((pid = waitpid(-1, &స్థితి_2, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
