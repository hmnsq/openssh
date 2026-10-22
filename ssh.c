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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/utsname.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <locale.h>

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/err.h>
#endif
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "clientloop.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "sshconnect.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "version.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "utf8.h"

#ifdef ENABLE_PKCS11
#अन्तर्भाव "ssh-pkcs11.h"
#endif

बाह्य वर्ण *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
स्थिर वर्ण **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
पूर्णाङ्क debug_flag = 0;

/* Flag indicating whether a tty should be requested */
पूर्णाङ्क tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
स्थिर पूर्णाङ्क need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
स्थिर पूर्णाङ्क ostdin_null_flag, osession_type, otty_flag, orequest_tty;
स्थिर पूर्णाङ्क ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
वर्ण *config = रिक्त;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
वर्ण *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
वर्ण *forward_agent_sock_path = रिक्त;

/* socket address the host resolves to */
संरचना sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
संरचना sshbuf *command;

/* # of replies received for global requests */
स्थिर पूर्णाङ्क forward_confirms_pending = -1;

/* mux.c */
बाह्य पूर्णाङ्क muxserver_sock;
बाह्य u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

स्थिर शून्य
usage(शून्य)
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

स्थिर पूर्णाङ्क ssh_session2(संरचना ssh *, ध्रुव संरचना ssh_conn_info *);
स्थिर शून्य load_public_identity_files(ध्रुव संरचना ssh_conn_info *);
स्थिर शून्य main_sigchld_handler(पूर्णाङ्क);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
स्थिर शून्य
tilde_expand_paths(वर्ण **paths, u_int अंक_paths)
{
	u_int i;
	वर्ण *cp;

	प्रति (i = 0; i < अंक_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		मुक्त(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
स्थिर वर्ण *
default_client_percent_expand(ध्रुव वर्ण *str,
    ध्रुव संरचना ssh_conn_info *cinfo)
{
	प्रत्यागम percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (वर्ण *)रिक्त);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
स्थिर वर्ण *
default_client_percent_dollar_expand(ध्रुव वर्ण *str,
    ध्रुव संरचना ssh_conn_info *cinfo)
{
	वर्ण *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (वर्ण *)रिक्त);
	यदि (ret == रिक्त)
		fatal("invalid environment variable expansion");
	प्रत्यागम ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
स्थिर संरचना addrinfo *
resolve_host(ध्रुव वर्ण *name, पूर्णाङ्क port, पूर्णाङ्क logerr, वर्ण *cname, size_t clen)
{
	वर्ण strport[NI_MAXSERV];
	ध्रुव वर्ण *errstr = रिक्त;
	संरचना addrinfo hints, *res;
	पूर्णाङ्क gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	यदि (port <= 0)
		port = default_ssh_port();
	यदि (cname != रिक्त)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, परिमाण strport, "%d", port);
	memset(&hints, 0, परिमाण(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	यदि (cname != रिक्त)
		hints.ai_flags = AI_CANONNAME;
	यदि ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		यदि (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		प्रत्यागम रिक्त;
	}
	यदि (cname != रिक्त && res->ai_canonname != रिक्त) {
		यदि (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} अन्यथा यदि (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			यदि (clen > 0)
				*cname = '\0';
		}
	}
	प्रत्यागम res;
}

/* Returns non-zero if name can only be an address and not a hostname */
स्थिर पूर्णाङ्क
is_addr_fast(ध्रुव वर्ण *name)
{
	प्रत्यागम (strchr(name, '%') != रिक्त || strchr(name, ':') != रिक्त ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
स्थिर पूर्णाङ्क
is_addr(ध्रुव वर्ण *name)
{
	वर्ण strport[NI_MAXSERV];
	संरचना addrinfo hints, *res;

	यदि (is_addr_fast(name))
		प्रत्यागम 1;

	snprintf(strport, परिमाण strport, "%u", default_ssh_port());
	memset(&hints, 0, परिमाण(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	यदि (getaddrinfo(name, strport, &hints, &res) != 0)
		प्रत्यागम 0;
	यदि (res == रिक्त || res->ai_next != रिक्त) {
		freeaddrinfo(res);
		प्रत्यागम 0;
	}
	freeaddrinfo(res);
	प्रत्यागम 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
स्थिर संरचना addrinfo *
resolve_addr(ध्रुव वर्ण *name, पूर्णाङ्क port, वर्ण *caddr, size_t clen)
{
	वर्ण addr[NI_MAXHOST], strport[NI_MAXSERV];
	संरचना addrinfo hints, *res;
	पूर्णाङ्क gaierr;

	यदि (port <= 0)
		port = default_ssh_port();
	snprintf(strport, परिमाण strport, "%u", port);
	memset(&hints, 0, परिमाण(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	यदि ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		प्रत्यागम रिक्त;
	}
	यदि (res == रिक्त) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		प्रत्यागम रिक्त;
	}
	यदि (res->ai_next != रिक्त) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		गच्छ fail;
	}
	यदि ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, परिमाण(addr), रिक्त, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		गच्छ fail;
	}
	यदि (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		यदि (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		प्रत्यागम रिक्त;
	}
	प्रत्यागम res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
स्थिर पूर्णाङ्क
check_follow_cname(पूर्णाङ्क direct, वर्ण **namep, ध्रुव वर्ण *cname)
{
	पूर्णाङ्क i;
	संरचना allowed_cname *rule;

	यदि (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		प्रत्यागम 0;
	यदि (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		प्रत्यागम 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	यदि (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		प्रत्यागम 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	प्रति (i = 0; i < options.अंक_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		यदि (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			अनुवर्त;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		मुक्त(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
स्थिर संरचना addrinfo *
resolve_canonicalize(वर्ण **hostp, पूर्णाङ्क port)
{
	पूर्णाङ्क i, direct, ndots;
	वर्ण *cp, *fullhost, newname[NI_MAXHOST];
	संरचना addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	यदि ((addrs = resolve_addr(*hostp, port,
	    newname, परिमाण(newname))) != रिक्त) {
		debug2_f("hostname %.100s is address", *hostp);
		यदि (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			मुक्त(*hostp);
			*hostp = xstrdup(newname);
		}
		प्रत्यागम addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	यदि (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		प्रत्यागम रिक्त;
	}

	यदि (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		प्रत्यागम रिक्त;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	यदि (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		प्रत्यागम रिक्त;

	/* If domain name is anchored, then resolve it now */
	यदि ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		यदि ((addrs = resolve_host(fullhost, port, 0,
		    newname, परिमाण(newname))) != रिक्त)
			गच्छ found;
		मुक्त(fullhost);
		गच्छ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	प्रति (cp = *hostp; *cp != '\0'; cp++) {
		यदि (*cp == '.')
			ndots++;
	}
	यदि (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		प्रत्यागम रिक्त;
	}
	/* Attempt each supplied suffix */
	प्रति (i = 0; i < options.अंक_canonical_domains; i++) {
		यदि (strcasecmp(options.canonical_domains[i], "none") == 0)
			भङ्ग;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		यदि ((addrs = resolve_host(fullhost, port, 0,
		    newname, परिमाण(newname))) == रिक्त) {
			मुक्त(fullhost);
			अनुवर्त;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		यदि (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		मुक्त(*hostp);
		*hostp = fullhost;
		प्रत्यागम addrs;
	}
 notfound:
	यदि (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	प्रत्यागम रिक्त;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
स्थिर शून्य
check_load(पूर्णाङ्क r, संरचना sshkey **k, ध्रुव वर्ण *path, ध्रुव वर्ण *message)
{
	वर्ण *fp;

	विकल्प (r) {
	पक्ष 0:
		यदि (k == रिक्त || *k == रिक्त)
			प्रत्यागम;
		/* Check RSA keys size and discard if undersized */
		यदि ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			मुक्त(*k);
			*k = रिक्त;
			भङ्ग;
		}
		यदि ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == रिक्त) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		मुक्त(fp);
		भङ्ग;
	पक्ष SSH_ERR_INTERNAL_ERROR:
	पक्ष SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	पक्ष SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		यदि (errno == ENOENT)
			भङ्ग;
		/* FALLTHROUGH */
	स्वभाव:
		error_r(r, "load %s \"%s\"", message, path);
		भङ्ग;
	}
	यदि (k != रिक्त && *k == रिक्त)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
स्थिर शून्य
process_config_files(ध्रुव वर्ण *host_name, संरचना passwd *pw,
    पूर्णाङ्क final_pass, पूर्णाङ्क *want_final_pass)
{
	वर्ण *cmd, buf[PATH_MAX];
	पूर्णाङ्क r;

	यदि ((cmd = sshbuf_dup_string(command)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	यदि (config != रिक्त) {
		यदि (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} अन्यथा {
		r = snprintf(buf, परिमाण buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		यदि (r > 0 && (size_t)r < परिमाण(buf))
			(शून्य)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(शून्य)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	मुक्त(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
स्थिर शून्य
set_addrinfo_port(संरचना addrinfo *addrs, पूर्णाङ्क port)
{
	संरचना addrinfo *addr;

	प्रति (addr = addrs; addr != रिक्त; addr = addr->ai_next) {
		विकल्प (addr->ai_family) {
		पक्ष AF_INET:
			((संरचना sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			भङ्ग;
		पक्ष AF_INET6:
			((संरचना sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			भङ्ग;
		}
	}
}

/*
 * Main program for the ssh client.
 */
पूर्णाङ्क
main(पूर्णाङ्क ac, वर्ण **av)
{
	संरचना ssh *ssh = रिक्त;
	पूर्णाङ्क i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	पूर्णाङ्क was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	पूर्णाङ्क user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	वर्ण *p, *cp, *ओळ, *argv0, *logfile, *args;
	वर्ण cname[NI_MAXHOST], thishost[NI_MAXHOST];
	संरचना stat st;
	संरचना passwd *pw;
	बाह्य पूर्णाङ्क optind, optreset;
	बाह्य वर्ण *optarg;
	संरचना Forward fwd;
	संरचना addrinfo *addrs = रिक्त;
	size_t n, len;
	u_int j;
	संरचना utsname utsname;
	संरचना ssh_conn_info *cinfo = रिक्त;

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
	saved_av = xcalloc(ac + 1, परिमाण(*saved_av));
	प्रति (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = रिक्त;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	यदि (!pw) {
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
	यदि ((ssh = ssh_alloc_session_state()) == रिक्त)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = रिक्त;
	use_syslog = 0;
	logfile = रिक्त;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	यावत् ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		विकल्प (opt) {
		पक्ष '1':
			fatal("SSH protocol v.1 is no longer supported");
			भङ्ग;
		पक्ष '2':
			/* Ignored */
			भङ्ग;
		पक्ष '4':
			options.address_family = AF_INET;
			भङ्ग;
		पक्ष '6':
			options.address_family = AF_INET6;
			भङ्ग;
		पक्ष 'n':
			options.stdin_null = 1;
			भङ्ग;
		पक्ष 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			भङ्ग;
		पक्ष 'x':
			options.forward_x11 = 0;
			भङ्ग;
		पक्ष 'X':
			options.forward_x11 = 1;
			भङ्ग;
		पक्ष 'y':
			use_syslog = 1;
			भङ्ग;
		पक्ष 'E':
			logfile = optarg;
			भङ्ग;
		पक्ष 'G':
			config_test = 1;
			भङ्ग;
		पक्ष 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			भङ्ग;
		पक्ष 'Z':
			dump_pubkeys = 1;
			भङ्ग;
		पक्ष 'g':
			options.fwd_opts.gateway_ports = 1;
			भङ्ग;
		पक्ष 'O':
			यदि (options.stdio_forward_host != रिक्त)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			अन्यथा यदि (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			यदि (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			अन्यथा यदि (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			अन्यथा यदि (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			अन्यथा यदि (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			अन्यथा यदि (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			अन्यथा यदि (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			अन्यथा यदि (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			अन्यथा यदि (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			अन्यथा
				fatal("Invalid multiplex command.");
			भङ्ग;
		पक्ष 'P':
			यदि (options.tag == रिक्त)
				options.tag = xstrdup(optarg);
			भङ्ग;
		पक्ष 'Q':
			cp = रिक्त;
			यदि (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			अन्यथा यदि (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			अन्यथा यदि (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			अन्यथा यदि (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			अन्यथा यदि (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			अन्यथा यदि (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			अन्यथा यदि (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			अन्यथा यदि (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			अन्यथा यदि (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			अन्यथा यदि (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			अन्यथा यदि (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			अन्यथा यदि (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				प्रति (n = 0; n < len; n++)
					यदि (cp[n] == ',')
						cp[n] = '\n';
			} अन्यथा यदि (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			यदि (cp == रिक्त)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			मुक्त(cp);
			exit(0);
			भङ्ग;
		पक्ष 'a':
			options.forward_agent = 0;
			भङ्ग;
		पक्ष 'A':
			options.forward_agent = 1;
			भङ्ग;
		पक्ष 'k':
			options.gss_deleg_creds = 0;
			भङ्ग;
		पक्ष 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			भङ्ग;
		पक्ष 'i':
			p = tilde_expand_filename(optarg, getuid());
			यदि (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			अन्यथा
				add_identity_file(&options, रिक्त, p, 1);
			मुक्त(p);
			भङ्ग;
		पक्ष 'I':
#ifdef ENABLE_PKCS11
			मुक्त(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#अन्यथा
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			भङ्ग;
		पक्ष 'J':
			यदि (options.jump_host != रिक्त) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			यदि (options.proxy_command != रिक्त)
				fatal("Cannot specify -J with ProxyCommand");
			यदि (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			भङ्ग;
		पक्ष 't':
			यदि (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			अन्यथा
				options.request_tty = REQUEST_TTY_YES;
			भङ्ग;
		पक्ष 'v':
			यदि (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा {
				यदि (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			भङ्ग;
		पक्ष 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			भङ्ग;
		पक्ष 'w':
			यदि (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			यदि (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			भङ्ग;
		पक्ष 'W':
			यदि (options.stdio_forward_host != रिक्त)
				fatal("stdio forward already specified");
			यदि (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			यदि (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				मुक्त(fwd.connect_host);
			} अन्यथा {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			भङ्ग;
		पक्ष 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			भङ्ग;
		पक्ष 'e':
			यदि (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			अन्यथा यदि (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			अन्यथा यदि (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			अन्यथा {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			भङ्ग;
		पक्ष 'c':
			यदि (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			मुक्त(options.ciphers);
			options.ciphers = xstrdup(optarg);
			भङ्ग;
		पक्ष 'm':
			यदि (mac_valid(optarg)) {
				मुक्त(options.macs);
				options.macs = xstrdup(optarg);
			} अन्यथा {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			भङ्ग;
		पक्ष 'M':
			यदि (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			अन्यथा
				options.control_master = SSHCTL_MASTER_YES;
			भङ्ग;
		पक्ष 'p':
			यदि (options.port == -1) {
				options.port = a2port(optarg);
				यदि (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			भङ्ग;
		पक्ष 'l':
			यदि (options.user == रिक्त) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			भङ्ग;

		पक्ष 'L':
			यदि (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			अन्यथा {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			भङ्ग;

		पक्ष 'R':
			यदि (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} अन्यथा {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			भङ्ग;

		पक्ष 'D':
			यदि (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} अन्यथा {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			भङ्ग;

		पक्ष 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#अन्यथा
			error("Compression not supported, disabling.");
#endif
			भङ्ग;
		पक्ष 'N':
			यदि (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			भङ्ग;
		पक्ष 'T':
			options.request_tty = REQUEST_TTY_NO;
			भङ्ग;
		पक्ष 'o':
			ओळ = xstrdup(optarg);
			यदि (process_config_ओळ(&options, pw,
			    host ? host : "", host ? host : "", "", ओळ,
			    "command-line", 0, रिक्त, SSHCONF_USERCONF) != 0)
				exit(255);
			मुक्त(ओळ);
			भङ्ग;
		पक्ष 's':
			यदि (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			भङ्ग;
		पक्ष 'S':
			मुक्त(options.control_path);
			options.control_path = xstrdup(optarg);
			भङ्ग;
		पक्ष 'b':
			options.bind_address = optarg;
			भङ्ग;
		पक्ष 'B':
			options.bind_interface = optarg;
			भङ्ग;
		पक्ष 'F':
			config = optarg;
			भङ्ग;
		स्वभाव:
			usage();
		}
	}

	यदि (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	यदि (ac > 0 && !host) {
		पूर्णाङ्क tport;
		वर्ण *tuser;
		विकल्प (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		पक्ष -1:
			usage();
			भङ्ग;
		पक्ष 0:
			यदि (options.user == रिक्त) {
				options.user = tuser;
				tuser = रिक्त;
				user_on_commandline = 1;
			}
			मुक्त(tuser);
			यदि (options.port == -1 && tport != -1)
				options.port = tport;
			भङ्ग;
		स्वभाव:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			यदि (cp != रिक्त) {
				यदि (cp == p)
					usage();
				यदि (options.user == रिक्त) {
					options.user = p;
					p = रिक्त;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				मुक्त(p);
			} अन्यथा
				host = p;
			भङ्ग;
		}
		यदि (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			गच्छ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	यदि (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	यदि (options.user != रिक्त && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	यदि (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	यदि ((command = sshbuf_new()) == रिक्त)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	यदि (!ac) {
		/* No command specified - execute shell on a tty. */
		यदि (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} अन्यथा {
		/* A command has been specified.  Store it into the buffer. */
		प्रति (i = 0; i < ac; i++) {
			यदि ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	यदि (use_syslog && logfile != रिक्त)
		fatal("Can't specify both -y and -E");
	यदि (logfile != रिक्त)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	यदि (uname(&utsname) != 0) {
		memset(&utsname, 0, परिमाण(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", परिमाण(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	मुक्त(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	यदि (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	यदि (options.hostname != रिक्त) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (वर्ण *)रिक्त);
		मुक्त(host);
		host = cp;
		मुक्त(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	यदि ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	यदि (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	यदि (addrs == रिक्त && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		यदि ((addrs = resolve_host(host, options.port,
		    direct, cname, परिमाण(cname))) == रिक्त) {
			/* Don't fatal proxied host names not in the DNS */
			यदि (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} अन्यथा
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	यदि (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	यदि (want_final_pass) {
		debug("re-parsing configuration");
		मुक्त(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, रिक्त);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		यदि (addrs != रिक्त && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	यदि (fill_default_options(&options) != 0)
		cleanup_exit(255);

	यदि (options.user == रिक्त) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	यदि (options.jump_host != रिक्त) {
		वर्ण port_s[8];
		ध्रुव वर्ण *jumpuser = options.jump_user, *sshbin = argv0;
		पूर्णाङ्क port = options.port, jumpport = options.jump_port;

		यदि (port <= 0)
			port = default_ssh_port();
		यदि (jumpport <= 0)
			jumpport = default_ssh_port();
		यदि (jumpuser == रिक्त)
			jumpuser = options.user;
		यदि (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		यदि (strchr(argv0, '/') != रिक्त && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		यदि (options.proxy_command != रिक्त &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, परिमाण(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == रिक्त ? "" : " -l ",
		    options.jump_user == रिक्त ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == रिक्त ? "" : " -J ",
		    options.jump_extra == रिक्त ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == रिक्त ? "" : " -F ",
		    config == रिक्त ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	यदि (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	यदि (options.host_किल्ली_alias != रिक्त)
		lowercase(options.host_किल्ली_alias);
	यदि (options.proxy_command != रिक्त &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	यदि (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		यदि (options.control_persist && options.control_path != रिक्त) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} अन्यथा यदि (sshbuf_len(command) != 0 ||
		    options.remote_command != रिक्त ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} अन्यथा यदि (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	यदि (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	यदि (sshbuf_len(command) != 0 && options.remote_command != रिक्त)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	यदि (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == रिक्त &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	प्रति (j = 0; j < options.अंक_log_verbose; j++) {
		यदि (strcasecmp(options.log_verbose[j], "none") == 0)
			भङ्ग;
		log_verbose_add(options.log_verbose[j]);
	}

	यदि (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	यदि (sshbuf_len(command) == 0 && options.remote_command == रिक्त)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	यदि (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	यदि ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		यदि (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, परिमाण(*cinfo));
	यदि (gethostname(thishost, परिमाण(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_किल्ली_alias ?
	    options.host_किल्ली_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == रिक्त ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	यदि (!user_on_commandline && !user_was_default) {
		यदि ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (वर्ण *)रिक्त)) == रिक्त)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		मुक्त(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	यदि ((user_on_commandline || user_expanded) &&
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
	यदि (options.remote_command != रिक्त) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		मुक्त(cp);
		यदि ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	यदि (options.control_path != रिक्त) {
		cp = tilde_expand_filename(options.control_path, getuid());
		मुक्त(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		मुक्त(cp);
	}

	यदि (options.identity_agent != रिक्त) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		मुक्त(p);
		मुक्त(options.identity_agent);
		options.identity_agent = cp;
	}

	प्रति (j = 0; j < options.अंक_revoked_host_किल्ल्या; j++) {
		p = tilde_expand_filename(options.revoked_host_किल्ल्या[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		मुक्त(p);
		मुक्त(options.revoked_host_किल्ल्या[j]);
		options.revoked_host_किल्ल्या[j] = cp;
	}

	यदि (options.forward_agent_sock_path != रिक्त) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		मुक्त(p);
		मुक्त(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		यदि (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			यदि (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	यदि (options.version_addendum != रिक्त) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		मुक्त(options.version_addendum);
		options.version_addendum = cp;
	}

	यदि (options.अंक_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		यदि (options.अंक_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		मुक्त(options.system_hostfiles[0]);
		options.system_hostfiles[0] = रिक्त;
		options.अंक_system_hostfiles = 0;
	}

	यदि (options.अंक_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		यदि (options.अंक_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		मुक्त(options.user_hostfiles[0]);
		options.user_hostfiles[0] = रिक्त;
		options.अंक_user_hostfiles = 0;
	}
	प्रति (j = 0; j < options.अंक_user_hostfiles; j++) {
		यदि (options.user_hostfiles[j] == रिक्त)
			अनुवर्त;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		यदि (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		मुक्त(options.user_hostfiles[j]);
		मुक्त(cp);
		options.user_hostfiles[j] = p;
	}

	प्रति (j = 0; j < options.अंक_setenv; j++) {
		वर्ण *name = options.setenv[j], *मूल्य;

		यदि (name == रिक्त)
			अनुवर्त;
		/* Expand only the value portion, not the variable name. */
		यदि ((मूल्य = strchr(name, '=')) == रिक्त) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*मूल्य++ = '\0';
		cp = default_client_percent_dollar_expand(मूल्य, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		यदि (strcmp(मूल्य, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, मूल्य, cp);
		}
		मुक्त(options.setenv[j]);
		मुक्त(cp);
		options.setenv[j] = p;
	}

	प्रति (i = 0; i < options.अंक_local_forwards; i++) {
		यदि (options.local_forwards[i].listen_path != रिक्त) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			यदि (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
		यदि (options.local_forwards[i].connect_path != रिक्त) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			यदि (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
	}

	प्रति (i = 0; i < options.अंक_remote_forwards; i++) {
		यदि (options.remote_forwards[i].listen_path != रिक्त) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			यदि (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
		यदि (options.remote_forwards[i].connect_path != रिक्त) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			यदि (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
	}

	यदि (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	यदि (options.sk_provider != रिक्त && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		यदि ((cp = getenv(options.sk_provider + 1)) == रिक्त) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			मुक्त(options.sk_provider);
			options.sk_provider = रिक्त;
		} अन्यथा {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			मुक्त(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	यदि (muxclient_command != 0 && options.control_path == रिक्त)
		fatal("No ControlPath specified for \"-O\" command");
	यदि (options.control_path != रिक्त) {
		पूर्णाङ्क sock;
		यदि ((sock = muxclient(options.control_path)) >= 0) {
			यदि (ssh_packet_set_connection(ssh, sock, sock) == रिक्त)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			गच्छ skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	यदि (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		यदि (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} अन्यथा {
			cp = options.identity_agent;
			/* legacy (limited) format */
			यदि (cp[0] == '$' && cp[1] != '{') {
				यदि (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				यदि ((p = getenv(cp + 1)) == रिक्त)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				अन्यथा
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} अन्यथा {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	यदि (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	यदि (addrs == रिक्त && options.proxy_command == रिक्त) {
		debug2("resolving \"%s\" port %d", host, options.port);
		यदि ((addrs = resolve_host(host, options.port, 1,
		    cname, परिमाण(cname))) == रिक्त)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	यदि (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	अन्यथा
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	प्रति (j = 0; j < options.अंक_channel_timeouts; j++) {
		द्विगुण timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		यदि (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		मुक्त(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	यदि (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_मोजणी_max);

	यदि (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.किल्ल्या = रिक्त;
	यदि (options.hostbased_authentication) {
		पूर्णाङ्क loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.किल्ल्या = xcalloc(sensitive_data.nkeys,
		    परिमाण(*sensitive_data.किल्ल्या));

		/* XXX check errors? */
#define L_PUBKEY(p,o) कुरु { \
	यदि ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.किल्ल्या[o]), रिक्त), \
	    &(sensitive_data.किल्ल्या[o]), p, "hostbased pubkey"); \
	यदि (sensitive_data.किल्ल्या[o] != रिक्त) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} यावत् (0)
#define L_CERT(p,o) कुरु { \
	यदि ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.किल्ल्या[o])), \
	    &(sensitive_data.किल्ल्या[o]), p, "hostbased cert"); \
	यदि (sensitive_data.किल्ल्या[o] != रिक्त) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} यावत् (0)

		यदि (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_किल्ली_FILE, 0);
			L_CERT(PATH_HOST_ED25519_किल्ली_FILE, 1);
			L_CERT(PATH_HOST_RSA_किल्ली_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_किल्ली_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_किल्ली_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_किल्ली_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_किल्ली_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_किल्ली_FILE, 7);
			यदि (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	यदि (options.forward_agent && options.forward_agent_sock_path != रिक्त) {
		cp = options.forward_agent_sock_path;
		यदि (cp[0] == '$') {
			यदि (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			यदि ((p = getenv(cp + 1)) != रिक्त)
				forward_agent_sock_path = xstrdup(p);
			अन्यथा
				options.forward_agent = 0;
			मुक्त(cp);
		} अन्यथा {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.अंक_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.अंक_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	यदि (sensitive_data.nkeys != 0) {
		प्रति (i = 0; i < sensitive_data.nkeys; i++) {
			यदि (sensitive_data.किल्ल्या[i] != रिक्त) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.किल्ल्या[i]);
				sensitive_data.किल्ल्या[i] = रिक्त;
			}
		}
		मुक्त(sensitive_data.किल्ल्या);
	}
	प्रति (i = 0; i < options.अंक_identity_files; i++) {
		मुक्त(options.identity_files[i]);
		options.identity_files[i] = रिक्त;
		यदि (options.identity_किल्ल्या[i]) {
			sshkey_free(options.identity_किल्ल्या[i]);
			options.identity_किल्ल्या[i] = रिक्त;
		}
	}
	प्रति (i = 0; i < options.अंक_certificate_files; i++) {
		मुक्त(options.certificate_files[i]);
		options.certificate_files[i] = रिक्त;
	}

#ifdef ENABLE_PKCS11
	(शून्य)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	यदि (addrs != रिक्त)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	यदि (options.control_path != रिक्त && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	प्रत्यागम exit_status;
}

स्थिर शून्य
control_persist_detach(शून्य)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	विकल्प ((pid = fork())) {
	पक्ष -1:
		fatal_f("fork: %s", strerror(errno));
	पक्ष 0:
		/* Child: master process continues mainloop */
		भङ्ग;
	स्वभाव:
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
		(शून्य)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	यदि (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
स्थिर शून्य
fork_postauth(शून्य)
{
	यदि (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	यदि (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	यदि (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

स्थिर शून्य
forwarding_success(शून्य)
{
	यदि (forward_confirms_pending == -1)
		प्रत्यागम;
	यदि (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		यदि (options.fork_after_authentication)
			fork_postauth();
	} अन्यथा {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

संरचना rfwd_confirm_ctx {
	पूर्णाङ्क fid;
};

/* Callback for remote forward global requests */
स्थिर शून्य
ssh_confirm_remote_forward(संरचना ssh *ssh, पूर्णाङ्क type, uint32_t seq, शून्य *ctxt)
{
	संरचना rfwd_confirm_ctx *rctx = (संरचना rfwd_confirm_ctx *)ctxt;
	संरचना Forward *rfwd;
	u_int port;
	पूर्णाङ्क r;

	यदि (rctx->fid < 0 || rctx->fid >= options.अंक_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, परिमाण(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_संदेश_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	यदि (rfwd->listen_path == रिक्त && rfwd->listen_port == 0) {
		यदि (type == SSH2_संदेश_REQUEST_SUCCESS) {
			यदि ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			यदि (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_संदेश_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} अन्यथा {
				rfwd->allocated_port = (पूर्णाङ्क)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} अन्यथा {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	यदि (type == SSH2_संदेश_REQUEST_FAILURE) {
		यदि (options.exit_on_forward_failure) {
			यदि (rfwd->listen_path != रिक्त)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			अन्यथा
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} अन्यथा {
			यदि (rfwd->listen_path != रिक्त)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			अन्यथा
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

स्थिर शून्य
client_cleanup_stdio_fwd(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क force, शून्य *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

स्थिर शून्य
ssh_stdio_confirm(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क success, शून्य *arg)
{
	यदि (!success)
		fatal("stdio forwarding failed");
}

स्थिर शून्य
ssh_tun_confirm(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क success, शून्य *arg)
{
	यदि (!success) {
		error("Tunnel forwarding failed");
		यदि (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

स्थिर शून्य
ssh_init_stdio_forwarding(संरचना ssh *ssh)
{
	Channel *c;
	पूर्णाङ्क in, out;

	यदि (options.stdio_forward_host == रिक्त)
		प्रत्यागम;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	यदि ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	यदि ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == रिक्त)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, रिक्त);
}

स्थिर शून्य
ssh_init_forward_permissions(संरचना ssh *ssh, ध्रुव वर्ण *what, वर्ण **opens,
    u_int अंक_opens)
{
	u_int i;
	पूर्णाङ्क port;
	वर्ण *addr, *arg, *oarg;
	पूर्णाङ्क where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	यदि (अंक_opens == 0)
		प्रत्यागम; /* permit any */

	/* handle keywords: "any" / "none" */
	यदि (अंक_opens == 1 && strcmp(opens[0], "any") == 0)
		प्रत्यागम;
	यदि (अंक_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		प्रत्यागम;
	}
	/* Otherwise treat it as a list of permitted host:port */
	प्रति (i = 0; i < अंक_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		यदि (addr == रिक्त)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		यदि (arg == रिक्त || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		मुक्त(oarg);
	}
}

स्थिर शून्य
ssh_init_forwarding(संरचना ssh *ssh, वर्ण **ifname)
{
	पूर्णाङ्क success = 0;
	पूर्णाङ्क i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.अंक_permitted_remote_opens);

	यदि (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	प्रति (i = 0; i < options.अंक_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != रिक्त) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == रिक्त) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != रिक्त) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	यदि (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	यदि (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	प्रति (i = 0; i < options.अंक_remote_forwards; i++) {
		संरचना rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != रिक्त) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == रिक्त) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != रिक्त) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		यदि ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, परिमाण(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} अन्यथा यदि (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		अन्यथा
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	यदि (options.tun_open != SSH_TUNMODE_NO) {
		यदि ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, रिक्त)) != रिक्त)
			forward_confirms_pending++;
		अन्यथा यदि (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		अन्यथा
			error("Could not request tunnel forwarding.");
	}
	यदि (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

स्थिर शून्य
check_agent_present(शून्य)
{
	पूर्णाङ्क r;

	यदि (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		यदि ((r = ssh_get_authentication_socket(रिक्त)) != 0) {
			options.forward_agent = 0;
			यदि (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

स्थिर शून्य
ssh_session2_setup(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क success, शून्य *arg)
{
	बाह्य वर्ण **environ;
	ध्रुव वर्ण *display, *term;
	वर्ण *proto = रिक्त, *data = रिक्त;

	यदि (!success)
		प्रत्यागम; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	यदि (display == रिक्त && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	यदि (options.forward_x11 && client_x11_get_proto(ssh, display,
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
	यदि (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	यदि ((term = lookup_env_in_list("TERM", options.setenv,
	    options.अंक_setenv)) == रिक्त || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    रिक्त, fileno(stdin), command, environ);
}

/* open new channel for a session */
स्थिर पूर्णाङ्क
ssh_session2_open(संरचना ssh *ssh)
{
	Channel *c;
	पूर्णाङ्क window, packetmax, in, out, err;

	यदि (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} अन्यथा {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	यदि (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	यदि (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	यदि (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	यदि (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, रिक्त);

	प्रत्यागम c->self;
}

स्थिर पूर्णाङ्क
ssh_session2(संरचना ssh *ssh, ध्रुव संरचना ssh_conn_info *cinfo)
{
	पूर्णाङ्क r, id = -1;
	वर्ण *cp, *tun_fwd_ifname = रिक्त;

	/* XXX should be pre-session */
	यदि (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	यदि (options.local_command != रिक्त) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == रिक्त ? "NONE" : tun_fwd_ifname,
		    (वर्ण *)रिक्त);
		debug3("expanded LocalCommand: %s", options.local_command);
		मुक्त(cp);
	}

	/* Start listening for multiplex clients */
	यदि (!ssh_packet_get_mux(ssh))
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
	यदि (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		यदि ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != रिक्त))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	यदि (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	यदि (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	यदि (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		यदि ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	यदि (options.local_command != रिक्त &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	यदि (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	यदि (options.fork_after_authentication) {
		यदि (options.exit_on_forward_failure &&
		    options.अंक_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} अन्यथा
			fork_postauth();
	}

	प्रत्यागम client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
स्थिर शून्य
load_public_identity_files(ध्रुव संरचना ssh_conn_info *cinfo)
{
	वर्ण *filename, *cp;
	संरचना sshkey *सार्वजनिक;
	पूर्णाङ्क i;
	u_int n_ids, n_certs;
	वर्ण *identity_files[SSH_MAX_IDENTITY_FILES];
	संरचना sshkey *identity_किल्ल्या[SSH_MAX_IDENTITY_FILES];
	पूर्णाङ्क identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	वर्ण *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	संरचना sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	पूर्णाङ्क certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	संरचना sshkey **किल्ल्या = रिक्त;
	वर्ण **comments = रिक्त;
	पूर्णाङ्क nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, परिमाण(identity_files));
	memset(identity_किल्ल्या, 0, परिमाण(identity_किल्ल्या));
	memset(identity_file_userprovided, 0,
	    परिमाण(identity_file_userprovided));
	memset(certificate_files, 0, परिमाण(certificate_files));
	memset(certificates, 0, परिमाण(certificates));
	memset(certificate_file_userprovided, 0,
	    परिमाण(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	यदि (options.pkcs11_provider != रिक्त &&
	    options.अंक_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, रिक्त,
	    &किल्ल्या, &comments)) > 0) {
		प्रति (i = 0; i < nkeys; i++) {
			यदि (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(किल्ल्या[i]);
				मुक्त(comments[i]);
				अनुवर्त;
			}
			identity_किल्ल्या[n_ids] = किल्ल्या[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		मुक्त(किल्ल्या);
		मुक्त(comments);
	}
#endif /* ENABLE_PKCS11 */
	प्रति (i = 0; i < options.अंक_identity_files; i++) {
		यदि (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			मुक्त(options.identity_files[i]);
			options.identity_files[i] = रिक्त;
			अनुवर्त;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		मुक्त(cp);
		check_load(sshkey_load_public(filename, &सार्वजनिक, रिक्त),
		    &सार्वजनिक, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    सार्वजनिक ? सार्वजनिक->type : -1);
		मुक्त(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_किल्ल्या[n_ids] = सार्वजनिक;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		यदि (++n_ids >= SSH_MAX_IDENTITY_FILES)
			अनुवर्त;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		यदि (options.अंक_certificate_files != 0)
			अनुवर्त;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &सार्वजनिक, रिक्त),
		    &सार्वजनिक, filename, "identity pubkey");
		यदि (सार्वजनिक == रिक्त) {
			मुक्त(cp);
			अनुवर्त;
		}
		यदि (!sshkey_is_cert(सार्वजनिक)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(सार्वजनिक));
			sshkey_free(सार्वजनिक);
			मुक्त(cp);
			अनुवर्त;
		}
		मुक्त(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_किल्ल्या[n_ids] = सार्वजनिक;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	यदि (options.अंक_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	प्रति (i = 0; i < options.अंक_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		मुक्त(cp);

		check_load(sshkey_load_public(filename, &सार्वजनिक, रिक्त),
		    &सार्वजनिक, filename, "identity cert");
		मुक्त(options.certificate_files[i]);
		options.certificate_files[i] = रिक्त;
		यदि (सार्वजनिक == रिक्त) {
			मुक्त(filename);
			अनुवर्त;
		}
		यदि (!sshkey_is_cert(सार्वजनिक)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(सार्वजनिक));
			sshkey_free(सार्वजनिक);
			मुक्त(filename);
			अनुवर्त;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = सार्वजनिक;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.अंक_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, परिमाण(identity_files));
	memcpy(options.identity_किल्ल्या, identity_किल्ल्या, परिमाण(identity_किल्ल्या));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, परिमाण(identity_file_userprovided));

	options.अंक_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, परिमाण(certificate_files));
	memcpy(options.certificates, certificates, परिमाण(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    परिमाण(certificate_file_userprovided));
}

स्थिर शून्य
main_sigchld_handler(पूर्णाङ्क sig)
{
	पूर्णाङ्क save_errno = errno;
	pid_t pid;
	पूर्णाङ्क status;

	यावत् ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
