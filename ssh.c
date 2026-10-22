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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/utsname.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <locale.h>

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/err.h>
#endif
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "clientloop.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "readconf.h"
#অন্তর্ভাব "sshconnect.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "version.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "utf8.h"

#ifdef ENABLE_PKCS11
#অন্তর্ভাব "ssh-pkcs11.h"
#endif

বাহ্যিক অক্ষর *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
স্থির অক্ষর **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
পূর্ণসংখ্যা debug_flag = 0;

/* Flag indicating whether a tty should be requested */
পূর্ণসংখ্যা tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
স্থির পূর্ণসংখ্যা need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
স্থির পূর্ণসংখ্যা ostdin_null_flag, osession_type, otty_flag, orequest_tty;
স্থির পূর্ণসংখ্যা ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
অক্ষর *config = ফাঁকা;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
অক্ষর *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
অক্ষর *forward_agent_sock_path = ফাঁকা;

/* socket address the host resolves to */
কাঠামো sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_তথ্য;

/* command to be executed */
কাঠামো sshbuf *command;

/* # of replies received for global requests */
স্থির পূর্ণসংখ্যা forward_confirms_pending = -1;

/* mux.c */
বাহ্যিক পূর্ণসংখ্যা muxserver_sock;
বাহ্যিক u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

স্থির শূন্য
usage(শূন্য)
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

স্থির পূর্ণসংখ্যা ssh_session2(কাঠামো ssh *, ধ্রুবক কাঠামো ssh_conn_info *);
স্থির শূন্য load_public_identity_files(ধ্রুবক কাঠামো ssh_conn_info *);
স্থির শূন্য main_sigchld_handler(পূর্ণসংখ্যা);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
স্থির শূন্য
tilde_expand_paths(অক্ষর **paths, u_int অঙ্ক_paths)
{
	u_int i;
	অক্ষর *cp;

	জন্য (i = 0; i < অঙ্ক_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		মুক্ত(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
স্থির অক্ষর *
default_client_percent_expand(ধ্রুবক অক্ষর *str,
    ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	ফেরত percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (অক্ষর *)ফাঁকা);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
স্থির অক্ষর *
default_client_percent_dollar_expand(ধ্রুবক অক্ষর *str,
    ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	অক্ষর *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (অক্ষর *)ফাঁকা);
	যদি (ret == ফাঁকা)
		fatal("invalid environment variable expansion");
	ফেরত ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
স্থির কাঠামো addrinfo *
resolve_host(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা port, পূর্ণসংখ্যা logerr, অক্ষর *cname, আকার_t clen)
{
	অক্ষর strport[NI_MAXSERV];
	ধ্রুবক অক্ষর *errstr = ফাঁকা;
	কাঠামো addrinfo hints, *res;
	পূর্ণসংখ্যা gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	যদি (port <= 0)
		port = default_ssh_port();
	যদি (cname != ফাঁকা)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, আকার strport, "%d", port);
	memset(&hints, 0, আকার(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	যদি (cname != ফাঁকা)
		hints.ai_flags = AI_CANONNAME;
	যদি ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		যদি (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		ফেরত ফাঁকা;
	}
	যদি (cname != ফাঁকা && res->ai_canonname != ফাঁকা) {
		যদি (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} অন্যথা যদি (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			যদি (clen > 0)
				*cname = '\0';
		}
	}
	ফেরত res;
}

/* Returns non-zero if name can only be an address and not a hostname */
স্থির পূর্ণসংখ্যা
is_addr_fast(ধ্রুবক অক্ষর *name)
{
	ফেরত (strchr(name, '%') != ফাঁকা || strchr(name, ':') != ফাঁকা ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
স্থির পূর্ণসংখ্যা
is_addr(ধ্রুবক অক্ষর *name)
{
	অক্ষর strport[NI_MAXSERV];
	কাঠামো addrinfo hints, *res;

	যদি (is_addr_fast(name))
		ফেরত 1;

	snprintf(strport, আকার strport, "%u", default_ssh_port());
	memset(&hints, 0, আকার(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	যদি (getaddrinfo(name, strport, &hints, &res) != 0)
		ফেরত 0;
	যদি (res == ফাঁকা || res->ai_next != ফাঁকা) {
		freeaddrinfo(res);
		ফেরত 0;
	}
	freeaddrinfo(res);
	ফেরত 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
স্থির কাঠামো addrinfo *
resolve_addr(ধ্রুবক অক্ষর *name, পূর্ণসংখ্যা port, অক্ষর *caddr, আকার_t clen)
{
	অক্ষর addr[NI_MAXHOST], strport[NI_MAXSERV];
	কাঠামো addrinfo hints, *res;
	পূর্ণসংখ্যা gaierr;

	যদি (port <= 0)
		port = default_ssh_port();
	snprintf(strport, আকার strport, "%u", port);
	memset(&hints, 0, আকার(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	যদি ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		ফেরত ফাঁকা;
	}
	যদি (res == ফাঁকা) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		ফেরত ফাঁকা;
	}
	যদি (res->ai_next != ফাঁকা) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		যাও fail;
	}
	যদি ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, আকার(addr), ফাঁকা, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		যাও fail;
	}
	যদি (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		যদি (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		ফেরত ফাঁকা;
	}
	ফেরত res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
স্থির পূর্ণসংখ্যা
check_follow_cname(পূর্ণসংখ্যা direct, অক্ষর **namep, ধ্রুবক অক্ষর *cname)
{
	পূর্ণসংখ্যা i;
	কাঠামো allowed_cname *rule;

	যদি (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		ফেরত 0;
	যদি (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ফেরত 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	যদি (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ফেরত 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	জন্য (i = 0; i < options.অঙ্ক_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		যদি (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			চালু;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		মুক্ত(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		ফেরত 1;
	}
	ফেরত 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
স্থির কাঠামো addrinfo *
resolve_canonicalize(অক্ষর **hostp, পূর্ণসংখ্যা port)
{
	পূর্ণসংখ্যা i, direct, ndots;
	অক্ষর *cp, *fullhost, newname[NI_MAXHOST];
	কাঠামো addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	যদি ((addrs = resolve_addr(*hostp, port,
	    newname, আকার(newname))) != ফাঁকা) {
		debug2_f("hostname %.100s is address", *hostp);
		যদি (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			মুক্ত(*hostp);
			*hostp = xstrdup(newname);
		}
		ফেরত addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	যদি (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		ফেরত ফাঁকা;
	}

	যদি (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		ফেরত ফাঁকা;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	যদি (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		ফেরত ফাঁকা;

	/* If domain name is anchored, then resolve it now */
	যদি ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		যদি ((addrs = resolve_host(fullhost, port, 0,
		    newname, আকার(newname))) != ফাঁকা)
			যাও found;
		মুক্ত(fullhost);
		যাও notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	জন্য (cp = *hostp; *cp != '\0'; cp++) {
		যদি (*cp == '.')
			ndots++;
	}
	যদি (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		ফেরত ফাঁকা;
	}
	/* Attempt each supplied suffix */
	জন্য (i = 0; i < options.অঙ্ক_canonical_domains; i++) {
		যদি (strcasecmp(options.canonical_domains[i], "none") == 0)
			বিরতি;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		যদি ((addrs = resolve_host(fullhost, port, 0,
		    newname, আকার(newname))) == ফাঁকা) {
			মুক্ত(fullhost);
			চালু;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		যদি (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		মুক্ত(*hostp);
		*hostp = fullhost;
		ফেরত addrs;
	}
 notfound:
	যদি (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	ফেরত ফাঁকা;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
স্থির শূন্য
check_load(পূর্ণসংখ্যা r, কাঠামো sshkey **k, ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *message)
{
	অক্ষর *fp;

	নির্বাচন (r) {
	ক্ষেত্র 0:
		যদি (k == ফাঁকা || *k == ফাঁকা)
			ফেরত;
		/* Check RSA keys size and discard if undersized */
		যদি ((r = sshkey_check_rsa_দৈর্ঘ্য(*k,
		    options.required_rsa_আকার)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			মুক্ত(*k);
			*k = ফাঁকা;
			বিরতি;
		}
		যদি ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ফাঁকা) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		মুক্ত(fp);
		বিরতি;
	ক্ষেত্র SSH_ERR_INTERNAL_ERROR:
	ক্ষেত্র SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	ক্ষেত্র SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		যদি (errno == ENOENT)
			বিরতি;
		/* FALLTHROUGH */
	পূর্বনির্ধারিত:
		error_r(r, "load %s \"%s\"", message, path);
		বিরতি;
	}
	যদি (k != ফাঁকা && *k == ফাঁকা)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
স্থির শূন্য
process_config_files(ধ্রুবক অক্ষর *host_name, কাঠামো passwd *pw,
    পূর্ণসংখ্যা final_pass, পূর্ণসংখ্যা *want_final_pass)
{
	অক্ষর *cmd, buf[PATH_MAX];
	পূর্ণসংখ্যা r;

	যদি ((cmd = sshbuf_dup_string(command)) == ফাঁকা)
		fatal_f("sshbuf_dup_string failed");
	যদি (config != ফাঁকা) {
		যদি (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} অন্যথা {
		r = snprintf(buf, আকার buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		যদি (r > 0 && (আকার_t)r < আকার(buf))
			(শূন্য)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(শূন্য)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	মুক্ত(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
স্থির শূন্য
set_addrinfo_port(কাঠামো addrinfo *addrs, পূর্ণসংখ্যা port)
{
	কাঠামো addrinfo *addr;

	জন্য (addr = addrs; addr != ফাঁকা; addr = addr->ai_next) {
		নির্বাচন (addr->ai_family) {
		ক্ষেত্র AF_INET:
			((কাঠামো sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			বিরতি;
		ক্ষেত্র AF_INET6:
			((কাঠামো sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			বিরতি;
		}
	}
}

/*
 * Main program for the ssh client.
 */
পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা ac, অক্ষর **av)
{
	কাঠামো ssh *ssh = ফাঁকা;
	পূর্ণসংখ্যা i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	পূর্ণসংখ্যা was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	পূর্ণসংখ্যা user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	অক্ষর *p, *cp, *সারি, *argv0, *logfile, *args;
	অক্ষর cname[NI_MAXHOST], thishost[NI_MAXHOST];
	কাঠামো stat st;
	কাঠামো passwd *pw;
	বাহ্যিক পূর্ণসংখ্যা optind, optreset;
	বাহ্যিক অক্ষর *optarg;
	কাঠামো Forward fwd;
	কাঠামো addrinfo *addrs = ফাঁকা;
	আকার_t n, len;
	u_int j;
	কাঠামো utsname utsname;
	কাঠামো ssh_conn_info *cinfo = ফাঁকা;

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
	saved_av = xcalloc(ac + 1, আকার(*saved_av));
	জন্য (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ফাঁকা;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	যদি (!pw) {
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
	যদি ((ssh = ssh_alloc_session_state()) == ফাঁকা)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = ফাঁকা;
	use_syslog = 0;
	logfile = ফাঁকা;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	যখন ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		নির্বাচন (opt) {
		ক্ষেত্র '1':
			fatal("SSH protocol v.1 is no longer supported");
			বিরতি;
		ক্ষেত্র '2':
			/* Ignored */
			বিরতি;
		ক্ষেত্র '4':
			options.address_family = AF_INET;
			বিরতি;
		ক্ষেত্র '6':
			options.address_family = AF_INET6;
			বিরতি;
		ক্ষেত্র 'n':
			options.stdin_null = 1;
			বিরতি;
		ক্ষেত্র 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			বিরতি;
		ক্ষেত্র 'x':
			options.forward_x11 = 0;
			বিরতি;
		ক্ষেত্র 'X':
			options.forward_x11 = 1;
			বিরতি;
		ক্ষেত্র 'y':
			use_syslog = 1;
			বিরতি;
		ক্ষেত্র 'E':
			logfile = optarg;
			বিরতি;
		ক্ষেত্র 'G':
			config_test = 1;
			বিরতি;
		ক্ষেত্র 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			বিরতি;
		ক্ষেত্র 'Z':
			dump_pubkeys = 1;
			বিরতি;
		ক্ষেত্র 'g':
			options.fwd_opts.gateway_ports = 1;
			বিরতি;
		ক্ষেত্র 'O':
			যদি (options.stdio_forward_host != ফাঁকা)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			অন্যথা যদি (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			যদি (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			অন্যথা যদি (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			অন্যথা যদি (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			অন্যথা যদি (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			অন্যথা যদি (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			অন্যথা যদি (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			অন্যথা যদি (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			অন্যথা যদি (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			অন্যথা
				fatal("Invalid multiplex command.");
			বিরতি;
		ক্ষেত্র 'P':
			যদি (options.tag == ফাঁকা)
				options.tag = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 'Q':
			cp = ফাঁকা;
			যদি (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			অন্যথা যদি (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			অন্যথা যদি (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			অন্যথা যদি (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			অন্যথা যদি (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			অন্যথা যদি (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			অন্যথা যদি (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			অন্যথা যদি (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			অন্যথা যদি (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			অন্যথা যদি (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			অন্যথা যদি (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			অন্যথা যদি (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				জন্য (n = 0; n < len; n++)
					যদি (cp[n] == ',')
						cp[n] = '\n';
			} অন্যথা যদি (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			যদি (cp == ফাঁকা)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			মুক্ত(cp);
			exit(0);
			বিরতি;
		ক্ষেত্র 'a':
			options.forward_agent = 0;
			বিরতি;
		ক্ষেত্র 'A':
			options.forward_agent = 1;
			বিরতি;
		ক্ষেত্র 'k':
			options.gss_deleg_creds = 0;
			বিরতি;
		ক্ষেত্র 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			বিরতি;
		ক্ষেত্র 'i':
			p = tilde_expand_filename(optarg, getuid());
			যদি (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			অন্যথা
				add_identity_file(&options, ফাঁকা, p, 1);
			মুক্ত(p);
			বিরতি;
		ক্ষেত্র 'I':
#ifdef ENABLE_PKCS11
			মুক্ত(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#অন্যথা
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			বিরতি;
		ক্ষেত্র 'J':
			যদি (options.jump_host != ফাঁকা) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			যদি (options.proxy_command != ফাঁকা)
				fatal("Cannot specify -J with ProxyCommand");
			যদি (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			বিরতি;
		ক্ষেত্র 't':
			যদি (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			অন্যথা
				options.request_tty = REQUEST_TTY_YES;
			বিরতি;
		ক্ষেত্র 'v':
			যদি (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} অন্যথা {
				যদি (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			বিরতি;
		ক্ষেত্র 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			বিরতি;
		ক্ষেত্র 'w':
			যদি (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			যদি (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			বিরতি;
		ক্ষেত্র 'W':
			যদি (options.stdio_forward_host != ফাঁকা)
				fatal("stdio forward already specified");
			যদি (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			যদি (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				মুক্ত(fwd.connect_host);
			} অন্যথা {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			বিরতি;
		ক্ষেত্র 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			বিরতি;
		ক্ষেত্র 'e':
			যদি (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			অন্যথা যদি (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			অন্যথা যদি (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			অন্যথা {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			বিরতি;
		ক্ষেত্র 'c':
			যদি (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			মুক্ত(options.ciphers);
			options.ciphers = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 'm':
			যদি (mac_valid(optarg)) {
				মুক্ত(options.macs);
				options.macs = xstrdup(optarg);
			} অন্যথা {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			বিরতি;
		ক্ষেত্র 'M':
			যদি (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			অন্যথা
				options.control_master = SSHCTL_MASTER_YES;
			বিরতি;
		ক্ষেত্র 'p':
			যদি (options.port == -1) {
				options.port = a2port(optarg);
				যদি (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			বিরতি;
		ক্ষেত্র 'l':
			যদি (options.user == ফাঁকা) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			বিরতি;

		ক্ষেত্র 'L':
			যদি (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			অন্যথা {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			বিরতি;

		ক্ষেত্র 'R':
			যদি (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} অন্যথা {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			বিরতি;

		ক্ষেত্র 'D':
			যদি (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} অন্যথা {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			বিরতি;

		ক্ষেত্র 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#অন্যথা
			error("Compression not supported, disabling.");
#endif
			বিরতি;
		ক্ষেত্র 'N':
			যদি (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			বিরতি;
		ক্ষেত্র 'T':
			options.request_tty = REQUEST_TTY_NO;
			বিরতি;
		ক্ষেত্র 'o':
			সারি = xstrdup(optarg);
			যদি (process_config_সারি(&options, pw,
			    host ? host : "", host ? host : "", "", সারি,
			    "command-line", 0, ফাঁকা, SSHCONF_USERCONF) != 0)
				exit(255);
			মুক্ত(সারি);
			বিরতি;
		ক্ষেত্র 's':
			যদি (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			বিরতি;
		ক্ষেত্র 'S':
			মুক্ত(options.control_path);
			options.control_path = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 'b':
			options.bind_address = optarg;
			বিরতি;
		ক্ষেত্র 'B':
			options.bind_interface = optarg;
			বিরতি;
		ক্ষেত্র 'F':
			config = optarg;
			বিরতি;
		পূর্বনির্ধারিত:
			usage();
		}
	}

	যদি (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	যদি (ac > 0 && !host) {
		পূর্ণসংখ্যা tport;
		অক্ষর *tuser;
		নির্বাচন (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		ক্ষেত্র -1:
			usage();
			বিরতি;
		ক্ষেত্র 0:
			যদি (options.user == ফাঁকা) {
				options.user = tuser;
				tuser = ফাঁকা;
				user_on_commandline = 1;
			}
			মুক্ত(tuser);
			যদি (options.port == -1 && tport != -1)
				options.port = tport;
			বিরতি;
		পূর্বনির্ধারিত:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			যদি (cp != ফাঁকা) {
				যদি (cp == p)
					usage();
				যদি (options.user == ফাঁকা) {
					options.user = p;
					p = ফাঁকা;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				মুক্ত(p);
			} অন্যথা
				host = p;
			বিরতি;
		}
		যদি (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			যাও again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	যদি (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	যদি (options.user != ফাঁকা && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	যদি (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	যদি ((command = sshbuf_new()) == ফাঁকা)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	যদি (!ac) {
		/* No command specified - execute shell on a tty. */
		যদি (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} অন্যথা {
		/* A command has been specified.  Store it into the buffer. */
		জন্য (i = 0; i < ac; i++) {
			যদি ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	যদি (use_syslog && logfile != ফাঁকা)
		fatal("Can't specify both -y and -E");
	যদি (logfile != ফাঁকা)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	যদি (uname(&utsname) != 0) {
		memset(&utsname, 0, আকার(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", আকার(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	মুক্ত(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	যদি (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	যদি (options.hostname != ফাঁকা) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (অক্ষর *)ফাঁকা);
		মুক্ত(host);
		host = cp;
		মুক্ত(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	যদি ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	যদি (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	যদি (addrs == ফাঁকা && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		যদি ((addrs = resolve_host(host, options.port,
		    direct, cname, আকার(cname))) == ফাঁকা) {
			/* Don't fatal proxied host names not in the DNS */
			যদি (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} অন্যথা
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	যদি (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	যদি (want_final_pass) {
		debug("re-parsing configuration");
		মুক্ত(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ফাঁকা);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		যদি (addrs != ফাঁকা && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	যদি (fill_default_options(&options) != 0)
		cleanup_exit(255);

	যদি (options.user == ফাঁকা) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	যদি (options.jump_host != ফাঁকা) {
		অক্ষর port_s[8];
		ধ্রুবক অক্ষর *jumpuser = options.jump_user, *sshbin = argv0;
		পূর্ণসংখ্যা port = options.port, jumpport = options.jump_port;

		যদি (port <= 0)
			port = default_ssh_port();
		যদি (jumpport <= 0)
			jumpport = default_ssh_port();
		যদি (jumpuser == ফাঁকা)
			jumpuser = options.user;
		যদি (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		যদি (strchr(argv0, '/') != ফাঁকা && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		যদি (options.proxy_command != ফাঁকা &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, আকার(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ফাঁকা ? "" : " -l ",
		    options.jump_user == ফাঁকা ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ফাঁকা ? "" : " -J ",
		    options.jump_extra == ফাঁকা ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ফাঁকা ? "" : " -F ",
		    config == ফাঁকা ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	যদি (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	যদি (options.host_চাবি_alias != ফাঁকা)
		lowercase(options.host_চাবি_alias);
	যদি (options.proxy_command != ফাঁকা &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	যদি (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		যদি (options.control_persist && options.control_path != ফাঁকা) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} অন্যথা যদি (sshbuf_len(command) != 0 ||
		    options.remote_command != ফাঁকা ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} অন্যথা যদি (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	যদি (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	যদি (sshbuf_len(command) != 0 && options.remote_command != ফাঁকা)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	যদি (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ফাঁকা &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	জন্য (j = 0; j < options.অঙ্ক_log_verbose; j++) {
		যদি (strcasecmp(options.log_verbose[j], "none") == 0)
			বিরতি;
		log_verbose_add(options.log_verbose[j]);
	}

	যদি (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	যদি (sshbuf_len(command) == 0 && options.remote_command == ফাঁকা)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	যদি (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	যদি ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		যদি (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, আকার(*cinfo));
	যদি (gethostname(thishost, আকার(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_চাবি_alias ?
	    options.host_চাবি_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ফাঁকা ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	যদি (!user_on_commandline && !user_was_default) {
		যদি ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (অক্ষর *)ফাঁকা)) == ফাঁকা)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		মুক্ত(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	যদি ((user_on_commandline || user_expanded) &&
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
	যদি (options.remote_command != ফাঁকা) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		মুক্ত(cp);
		যদি ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	যদি (options.control_path != ফাঁকা) {
		cp = tilde_expand_filename(options.control_path, getuid());
		মুক্ত(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		মুক্ত(cp);
	}

	যদি (options.identity_agent != ফাঁকা) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		মুক্ত(p);
		মুক্ত(options.identity_agent);
		options.identity_agent = cp;
	}

	জন্য (j = 0; j < options.অঙ্ক_revoked_host_চাবিগুলি; j++) {
		p = tilde_expand_filename(options.revoked_host_চাবিগুলি[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		মুক্ত(p);
		মুক্ত(options.revoked_host_চাবিগুলি[j]);
		options.revoked_host_চাবিগুলি[j] = cp;
	}

	যদি (options.forward_agent_sock_path != ফাঁকা) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		মুক্ত(p);
		মুক্ত(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		যদি (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			যদি (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	যদি (options.version_addendum != ফাঁকা) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		মুক্ত(options.version_addendum);
		options.version_addendum = cp;
	}

	যদি (options.অঙ্ক_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		যদি (options.অঙ্ক_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		মুক্ত(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ফাঁকা;
		options.অঙ্ক_system_hostfiles = 0;
	}

	যদি (options.অঙ্ক_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		যদি (options.অঙ্ক_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		মুক্ত(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ফাঁকা;
		options.অঙ্ক_user_hostfiles = 0;
	}
	জন্য (j = 0; j < options.অঙ্ক_user_hostfiles; j++) {
		যদি (options.user_hostfiles[j] == ফাঁকা)
			চালু;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		যদি (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		মুক্ত(options.user_hostfiles[j]);
		মুক্ত(cp);
		options.user_hostfiles[j] = p;
	}

	জন্য (j = 0; j < options.অঙ্ক_setenv; j++) {
		অক্ষর *name = options.setenv[j], *মান;

		যদি (name == ফাঁকা)
			চালু;
		/* Expand only the value portion, not the variable name. */
		যদি ((মান = strchr(name, '=')) == ফাঁকা) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*মান++ = '\0';
		cp = default_client_percent_dollar_expand(মান, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		যদি (strcmp(মান, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, মান, cp);
		}
		মুক্ত(options.setenv[j]);
		মুক্ত(cp);
		options.setenv[j] = p;
	}

	জন্য (i = 0; i < options.অঙ্ক_local_forwards; i++) {
		যদি (options.local_forwards[i].listen_path != ফাঁকা) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			যদি (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			মুক্ত(cp);
		}
		যদি (options.local_forwards[i].connect_path != ফাঁকা) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			যদি (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			মুক্ত(cp);
		}
	}

	জন্য (i = 0; i < options.অঙ্ক_remote_forwards; i++) {
		যদি (options.remote_forwards[i].listen_path != ফাঁকা) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			যদি (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			মুক্ত(cp);
		}
		যদি (options.remote_forwards[i].connect_path != ফাঁকা) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			যদি (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			মুক্ত(cp);
		}
	}

	যদি (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	যদি (options.sk_provider != ফাঁকা && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		যদি ((cp = getenv(options.sk_provider + 1)) == ফাঁকা) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			মুক্ত(options.sk_provider);
			options.sk_provider = ফাঁকা;
		} অন্যথা {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			মুক্ত(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	যদি (muxclient_command != 0 && options.control_path == ফাঁকা)
		fatal("No ControlPath specified for \"-O\" command");
	যদি (options.control_path != ফাঁকা) {
		পূর্ণসংখ্যা sock;
		যদি ((sock = muxclient(options.control_path)) >= 0) {
			যদি (ssh_packet_set_connection(ssh, sock, sock) == ফাঁকা)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			যাও skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	যদি (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		যদি (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} অন্যথা {
			cp = options.identity_agent;
			/* legacy (limited) format */
			যদি (cp[0] == '$' && cp[1] != '{') {
				যদি (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				যদি ((p = getenv(cp + 1)) == ফাঁকা)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				অন্যথা
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} অন্যথা {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	যদি (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	যদি (addrs == ফাঁকা && options.proxy_command == ফাঁকা) {
		debug2("resolving \"%s\" port %d", host, options.port);
		যদি ((addrs = resolve_host(host, options.port, 1,
		    cname, আকার(cname))) == ফাঁকা)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	যদি (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	অন্যথা
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	জন্য (j = 0; j < options.অঙ্ক_channel_timeouts; j++) {
		দ্বিগুণ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		যদি (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		মুক্ত(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	যদি (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_গুনতি_max);

	যদি (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_তথ্য.nkeys = 0;
	sensitive_তথ্য.চাবিগুলি = ফাঁকা;
	যদি (options.hostbased_authentication) {
		পূর্ণসংখ্যা loaded = 0;

		sensitive_তথ্য.nkeys = 10;
		sensitive_তথ্য.চাবিগুলি = xcalloc(sensitive_তথ্য.nkeys,
		    আকার(*sensitive_তথ্য.চাবিগুলি));

		/* XXX check errors? */
#define L_PUBKEY(p,o) করো { \
	যদি ((o) >= sensitive_তথ্য.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_তথ্য.চাবিগুলি[o]), ফাঁকা), \
	    &(sensitive_তথ্য.চাবিগুলি[o]), p, "hostbased pubkey"); \
	যদি (sensitive_তথ্য.চাবিগুলি[o] != ফাঁকা) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} যখন (0)
#define L_CERT(p,o) করো { \
	যদি ((o) >= sensitive_তথ্য.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_তথ্য.চাবিগুলি[o])), \
	    &(sensitive_তথ্য.চাবিগুলি[o]), p, "hostbased cert"); \
	যদি (sensitive_তথ্য.চাবিগুলি[o] != ফাঁকা) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} যখন (0)

		যদি (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_চাবি_FILE, 0);
			L_CERT(PATH_HOST_ED25519_চাবি_FILE, 1);
			L_CERT(PATH_HOST_RSA_চাবি_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_চাবি_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_চাবি_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_চাবি_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_চাবি_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_চাবি_FILE, 7);
			যদি (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	যদি (options.forward_agent && options.forward_agent_sock_path != ফাঁকা) {
		cp = options.forward_agent_sock_path;
		যদি (cp[0] == '$') {
			যদি (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			যদি ((p = getenv(cp + 1)) != ফাঁকা)
				forward_agent_sock_path = xstrdup(p);
			অন্যথা
				options.forward_agent = 0;
			মুক্ত(cp);
		} অন্যথা {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.অঙ্ক_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.অঙ্ক_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_তথ্য, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	যদি (sensitive_তথ্য.nkeys != 0) {
		জন্য (i = 0; i < sensitive_তথ্য.nkeys; i++) {
			যদি (sensitive_তথ্য.চাবিগুলি[i] != ফাঁকা) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_তথ্য.চাবিগুলি[i]);
				sensitive_তথ্য.চাবিগুলি[i] = ফাঁকা;
			}
		}
		মুক্ত(sensitive_তথ্য.চাবিগুলি);
	}
	জন্য (i = 0; i < options.অঙ্ক_identity_files; i++) {
		মুক্ত(options.identity_files[i]);
		options.identity_files[i] = ফাঁকা;
		যদি (options.identity_চাবিগুলি[i]) {
			sshkey_free(options.identity_চাবিগুলি[i]);
			options.identity_চাবিগুলি[i] = ফাঁকা;
		}
	}
	জন্য (i = 0; i < options.অঙ্ক_certificate_files; i++) {
		মুক্ত(options.certificate_files[i]);
		options.certificate_files[i] = ফাঁকা;
	}

#ifdef ENABLE_PKCS11
	(শূন্য)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	যদি (addrs != ফাঁকা)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	যদি (options.control_path != ফাঁকা && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	ফেরত exit_status;
}

স্থির শূন্য
control_persist_detach(শূন্য)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	নির্বাচন ((pid = fork())) {
	ক্ষেত্র -1:
		fatal_f("fork: %s", strerror(errno));
	ক্ষেত্র 0:
		/* Child: master process continues mainloop */
		বিরতি;
	পূর্বনির্ধারিত:
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
		(শূন্য)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	যদি (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
স্থির শূন্য
fork_postauth(শূন্য)
{
	যদি (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	যদি (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	যদি (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

স্থির শূন্য
forwarding_success(শূন্য)
{
	যদি (forward_confirms_pending == -1)
		ফেরত;
	যদি (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		যদি (options.fork_after_authentication)
			fork_postauth();
	} অন্যথা {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

কাঠামো rfwd_confirm_ctx {
	পূর্ণসংখ্যা fid;
};

/* Callback for remote forward global requests */
স্থির শূন্য
ssh_confirm_remote_forward(কাঠামো ssh *ssh, পূর্ণসংখ্যা type, uint32_t seq, শূন্য *ctxt)
{
	কাঠামো rfwd_confirm_ctx *rctx = (কাঠামো rfwd_confirm_ctx *)ctxt;
	কাঠামো Forward *rfwd;
	u_int port;
	পূর্ণসংখ্যা r;

	যদি (rctx->fid < 0 || rctx->fid >= options.অঙ্ক_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, আকার(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_বার্তা_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	যদি (rfwd->listen_path == ফাঁকা && rfwd->listen_port == 0) {
		যদি (type == SSH2_বার্তা_REQUEST_SUCCESS) {
			যদি ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			যদি (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_বার্তা_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} অন্যথা {
				rfwd->allocated_port = (পূর্ণসংখ্যা)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} অন্যথা {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	যদি (type == SSH2_বার্তা_REQUEST_FAILURE) {
		যদি (options.exit_on_forward_failure) {
			যদি (rfwd->listen_path != ফাঁকা)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			অন্যথা
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} অন্যথা {
			যদি (rfwd->listen_path != ফাঁকা)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			অন্যথা
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

স্থির শূন্য
client_cleanup_stdio_fwd(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা force, শূন্য *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

স্থির শূন্য
ssh_stdio_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা success, শূন্য *arg)
{
	যদি (!success)
		fatal("stdio forwarding failed");
}

স্থির শূন্য
ssh_tun_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা success, শূন্য *arg)
{
	যদি (!success) {
		error("Tunnel forwarding failed");
		যদি (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

স্থির শূন্য
ssh_init_stdio_forwarding(কাঠামো ssh *ssh)
{
	Channel *c;
	পূর্ণসংখ্যা in, out;

	যদি (options.stdio_forward_host == ফাঁকা)
		ফেরত;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	যদি ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	যদি ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == ফাঁকা)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, ফাঁকা);
}

স্থির শূন্য
ssh_init_forward_permissions(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *what, অক্ষর **opens,
    u_int অঙ্ক_opens)
{
	u_int i;
	পূর্ণসংখ্যা port;
	অক্ষর *addr, *arg, *oarg;
	পূর্ণসংখ্যা where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	যদি (অঙ্ক_opens == 0)
		ফেরত; /* permit any */

	/* handle keywords: "any" / "none" */
	যদি (অঙ্ক_opens == 1 && strcmp(opens[0], "any") == 0)
		ফেরত;
	যদি (অঙ্ক_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		ফেরত;
	}
	/* Otherwise treat it as a list of permitted host:port */
	জন্য (i = 0; i < অঙ্ক_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		যদি (addr == ফাঁকা)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		যদি (arg == ফাঁকা || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		মুক্ত(oarg);
	}
}

স্থির শূন্য
ssh_init_forwarding(কাঠামো ssh *ssh, অক্ষর **ifname)
{
	পূর্ণসংখ্যা success = 0;
	পূর্ণসংখ্যা i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.অঙ্ক_permitted_remote_opens);

	যদি (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	জন্য (i = 0; i < options.অঙ্ক_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != ফাঁকা) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == ফাঁকা) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != ফাঁকা) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	যদি (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	যদি (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	জন্য (i = 0; i < options.অঙ্ক_remote_forwards; i++) {
		কাঠামো rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != ফাঁকা) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == ফাঁকা) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != ফাঁকা) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		যদি ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, আকার(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} অন্যথা যদি (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		অন্যথা
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	যদি (options.tun_open != SSH_TUNMODE_NO) {
		যদি ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ফাঁকা)) != ফাঁকা)
			forward_confirms_pending++;
		অন্যথা যদি (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		অন্যথা
			error("Could not request tunnel forwarding.");
	}
	যদি (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

স্থির শূন্য
check_agent_present(শূন্য)
{
	পূর্ণসংখ্যা r;

	যদি (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		যদি ((r = ssh_get_authentication_socket(ফাঁকা)) != 0) {
			options.forward_agent = 0;
			যদি (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

স্থির শূন্য
ssh_session2_setup(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা success, শূন্য *arg)
{
	বাহ্যিক অক্ষর **environ;
	ধ্রুবক অক্ষর *display, *term;
	অক্ষর *proto = ফাঁকা, *তথ্য = ফাঁকা;

	যদি (!success)
		ফেরত; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	যদি (display == ফাঁকা && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	যদি (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &তথ্য) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    তথ্য, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	যদি (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	যদি ((term = lookup_env_in_list("TERM", options.setenv,
	    options.অঙ্ক_setenv)) == ফাঁকা || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    ফাঁকা, fileno(stdin), command, environ);
}

/* open new channel for a session */
স্থির পূর্ণসংখ্যা
ssh_session2_open(কাঠামো ssh *ssh)
{
	Channel *c;
	পূর্ণসংখ্যা window, packetmax, in, out, err;

	যদি (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} অন্যথা {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	যদি (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	যদি (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	যদি (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	যদি (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, ফাঁকা);

	ফেরত c->self;
}

স্থির পূর্ণসংখ্যা
ssh_session2(কাঠামো ssh *ssh, ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	পূর্ণসংখ্যা r, id = -1;
	অক্ষর *cp, *tun_fwd_ifname = ফাঁকা;

	/* XXX should be pre-session */
	যদি (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	যদি (options.local_command != ফাঁকা) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == ফাঁকা ? "NONE" : tun_fwd_ifname,
		    (অক্ষর *)ফাঁকা);
		debug3("expanded LocalCommand: %s", options.local_command);
		মুক্ত(cp);
	}

	/* Start listening for multiplex clients */
	যদি (!ssh_packet_get_mux(ssh))
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
	যদি (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		যদি ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ফাঁকা))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	যদি (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	যদি (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	যদি (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	যদি (options.local_command != ফাঁকা &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	যদি (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	যদি (options.fork_after_authentication) {
		যদি (options.exit_on_forward_failure &&
		    options.অঙ্ক_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} অন্যথা
			fork_postauth();
	}

	ফেরত client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
স্থির শূন্য
load_public_identity_files(ধ্রুবক কাঠামো ssh_conn_info *cinfo)
{
	অক্ষর *filename, *cp;
	কাঠামো sshkey *সর্বজনীন;
	পূর্ণসংখ্যা i;
	u_int n_ids, n_certs;
	অক্ষর *identity_files[SSH_MAX_IDENTITY_FILES];
	কাঠামো sshkey *identity_চাবিগুলি[SSH_MAX_IDENTITY_FILES];
	পূর্ণসংখ্যা identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	অক্ষর *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	কাঠামো sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	পূর্ণসংখ্যা certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	কাঠামো sshkey **চাবিগুলি = ফাঁকা;
	অক্ষর **comments = ফাঁকা;
	পূর্ণসংখ্যা nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, আকার(identity_files));
	memset(identity_চাবিগুলি, 0, আকার(identity_চাবিগুলি));
	memset(identity_file_userprovided, 0,
	    আকার(identity_file_userprovided));
	memset(certificate_files, 0, আকার(certificate_files));
	memset(certificates, 0, আকার(certificates));
	memset(certificate_file_userprovided, 0,
	    আকার(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	যদি (options.pkcs11_provider != ফাঁকা &&
	    options.অঙ্ক_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, ফাঁকা,
	    &চাবিগুলি, &comments)) > 0) {
		জন্য (i = 0; i < nkeys; i++) {
			যদি (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(চাবিগুলি[i]);
				মুক্ত(comments[i]);
				চালু;
			}
			identity_চাবিগুলি[n_ids] = চাবিগুলি[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		মুক্ত(চাবিগুলি);
		মুক্ত(comments);
	}
#endif /* ENABLE_PKCS11 */
	জন্য (i = 0; i < options.অঙ্ক_identity_files; i++) {
		যদি (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			মুক্ত(options.identity_files[i]);
			options.identity_files[i] = ফাঁকা;
			চালু;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		মুক্ত(cp);
		check_load(sshkey_load_public(filename, &সর্বজনীন, ফাঁকা),
		    &সর্বজনীন, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    সর্বজনীন ? সর্বজনীন->type : -1);
		মুক্ত(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_চাবিগুলি[n_ids] = সর্বজনীন;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		যদি (++n_ids >= SSH_MAX_IDENTITY_FILES)
			চালু;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		যদি (options.অঙ্ক_certificate_files != 0)
			চালু;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &সর্বজনীন, ফাঁকা),
		    &সর্বজনীন, filename, "identity pubkey");
		যদি (সর্বজনীন == ফাঁকা) {
			মুক্ত(cp);
			চালু;
		}
		যদি (!sshkey_is_cert(সর্বজনীন)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(সর্বজনীন));
			sshkey_free(সর্বজনীন);
			মুক্ত(cp);
			চালু;
		}
		মুক্ত(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_চাবিগুলি[n_ids] = সর্বজনীন;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	যদি (options.অঙ্ক_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	জন্য (i = 0; i < options.অঙ্ক_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		মুক্ত(cp);

		check_load(sshkey_load_public(filename, &সর্বজনীন, ফাঁকা),
		    &সর্বজনীন, filename, "identity cert");
		মুক্ত(options.certificate_files[i]);
		options.certificate_files[i] = ফাঁকা;
		যদি (সর্বজনীন == ফাঁকা) {
			মুক্ত(filename);
			চালু;
		}
		যদি (!sshkey_is_cert(সর্বজনীন)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(সর্বজনীন));
			sshkey_free(সর্বজনীন);
			মুক্ত(filename);
			চালু;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = সর্বজনীন;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.অঙ্ক_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, আকার(identity_files));
	memcpy(options.identity_চাবিগুলি, identity_চাবিগুলি, আকার(identity_চাবিগুলি));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, আকার(identity_file_userprovided));

	options.অঙ্ক_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, আকার(certificate_files));
	memcpy(options.certificates, certificates, আকার(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    আকার(certificate_file_userprovided));
}

স্থির শূন্য
main_sigchld_handler(পূর্ণসংখ্যা sig)
{
	পূর্ণসংখ্যা save_errno = errno;
	pid_t pid;
	পূর্ণসংখ্যা status;

	যখন ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
