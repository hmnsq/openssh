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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/utsname.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <locale.h>

#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/err.h>
#endif
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "clientloop.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "sshconnect.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "version.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "utf8.h"

#ifdef ENABLE_PKCS11
#அந்தர்பாவ "ssh-pkcs11.h"
#endif

வெளி எழுத்து *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
நிலையான எழுத்து **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
முழு debug_flag = 0;

/* Flag indicating whether a tty should be requested */
முழு tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
நிலையான முழு need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
நிலையான முழு ostdin_null_flag, osession_type, otty_flag, orequest_tty;
நிலையான முழு ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
எழுத்து *config = வெற்று;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
எழுத்து *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
எழுத்து *forward_agent_sock_path = வெற்று;

/* socket address the host resolves to */
கட்டமைப்பு sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
கட்டமைப்பு sshbuf *command;

/* # of replies received for global requests */
நிலையான முழு forward_confirms_pending = -1;

/* mux.c */
வெளி முழு muxserver_sock;
வெளி u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

நிலையான வெறுமை
usage(வெறுமை)
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

நிலையான முழு ssh_session2(கட்டமைப்பு ssh *, மாறிலி கட்டமைப்பு ssh_conn_info *);
நிலையான வெறுமை load_public_identity_files(மாறிலி கட்டமைப்பு ssh_conn_info *);
நிலையான வெறுமை main_sigchld_handler(முழு);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
நிலையான வெறுமை
tilde_expand_paths(எழுத்து **paths, u_int இலக்கம்_paths)
{
	u_int i;
	எழுத்து *cp;

	க்கு (i = 0; i < இலக்கம்_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		விடுவி(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
நிலையான எழுத்து *
default_client_percent_expand(மாறிலி எழுத்து *str,
    மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	திரும்பு percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (எழுத்து *)வெற்று);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
நிலையான எழுத்து *
default_client_percent_dollar_expand(மாறிலி எழுத்து *str,
    மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	எழுத்து *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (எழுத்து *)வெற்று);
	எனில் (ret == வெற்று)
		fatal("invalid environment variable expansion");
	திரும்பு ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
நிலையான கட்டமைப்பு addrinfo *
resolve_host(மாறிலி எழுத்து *name, முழு port, முழு logerr, எழுத்து *cname, size_t clen)
{
	எழுத்து strport[NI_MAXSERV];
	மாறிலி எழுத்து *errstr = வெற்று;
	கட்டமைப்பு addrinfo hints, *res;
	முழு gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	எனில் (port <= 0)
		port = default_ssh_port();
	எனில் (cname != வெற்று)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, அளவு strport, "%d", port);
	memset(&hints, 0, அளவு(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	எனில் (cname != வெற்று)
		hints.ai_flags = AI_CANONNAME;
	எனில் ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		எனில் (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		திரும்பு வெற்று;
	}
	எனில் (cname != வெற்று && res->ai_canonname != வெற்று) {
		எனில் (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} இல்லையெனில் எனில் (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			எனில் (clen > 0)
				*cname = '\0';
		}
	}
	திரும்பு res;
}

/* Returns non-zero if name can only be an address and not a hostname */
நிலையான முழு
is_addr_fast(மாறிலி எழுத்து *name)
{
	திரும்பு (strchr(name, '%') != வெற்று || strchr(name, ':') != வெற்று ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
நிலையான முழு
is_addr(மாறிலி எழுத்து *name)
{
	எழுத்து strport[NI_MAXSERV];
	கட்டமைப்பு addrinfo hints, *res;

	எனில் (is_addr_fast(name))
		திரும்பு 1;

	snprintf(strport, அளவு strport, "%u", default_ssh_port());
	memset(&hints, 0, அளவு(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	எனில் (getaddrinfo(name, strport, &hints, &res) != 0)
		திரும்பு 0;
	எனில் (res == வெற்று || res->ai_next != வெற்று) {
		freeaddrinfo(res);
		திரும்பு 0;
	}
	freeaddrinfo(res);
	திரும்பு 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
நிலையான கட்டமைப்பு addrinfo *
resolve_addr(மாறிலி எழுத்து *name, முழு port, எழுத்து *caddr, size_t clen)
{
	எழுத்து addr[NI_MAXHOST], strport[NI_MAXSERV];
	கட்டமைப்பு addrinfo hints, *res;
	முழு gaierr;

	எனில் (port <= 0)
		port = default_ssh_port();
	snprintf(strport, அளவு strport, "%u", port);
	memset(&hints, 0, அளவு(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	எனில் ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		திரும்பு வெற்று;
	}
	எனில் (res == வெற்று) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		திரும்பு வெற்று;
	}
	எனில் (res->ai_next != வெற்று) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		செல் fail;
	}
	எனில் ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, அளவு(addr), வெற்று, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		செல் fail;
	}
	எனில் (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		எனில் (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		திரும்பு வெற்று;
	}
	திரும்பு res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
நிலையான முழு
check_follow_cname(முழு direct, எழுத்து **namep, மாறிலி எழுத்து *cname)
{
	முழு i;
	கட்டமைப்பு allowed_cname *rule;

	எனில் (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		திரும்பு 0;
	எனில் (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		திரும்பு 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	எனில் (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		திரும்பு 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	க்கு (i = 0; i < options.இலக்கம்_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		எனில் (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			தொடர்;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		விடுவி(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		திரும்பு 1;
	}
	திரும்பு 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
நிலையான கட்டமைப்பு addrinfo *
resolve_canonicalize(எழுத்து **hostp, முழு port)
{
	முழு i, direct, ndots;
	எழுத்து *cp, *fullhost, newname[NI_MAXHOST];
	கட்டமைப்பு addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	எனில் ((addrs = resolve_addr(*hostp, port,
	    newname, அளவு(newname))) != வெற்று) {
		debug2_f("hostname %.100s is address", *hostp);
		எனில் (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			விடுவி(*hostp);
			*hostp = xstrdup(newname);
		}
		திரும்பு addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	எனில் (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		திரும்பு வெற்று;
	}

	எனில் (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		திரும்பு வெற்று;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	எனில் (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		திரும்பு வெற்று;

	/* If domain name is anchored, then resolve it now */
	எனில் ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		எனில் ((addrs = resolve_host(fullhost, port, 0,
		    newname, அளவு(newname))) != வெற்று)
			செல் found;
		விடுவி(fullhost);
		செல் notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	க்கு (cp = *hostp; *cp != '\0'; cp++) {
		எனில் (*cp == '.')
			ndots++;
	}
	எனில் (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		திரும்பு வெற்று;
	}
	/* Attempt each supplied suffix */
	க்கு (i = 0; i < options.இலக்கம்_canonical_domains; i++) {
		எனில் (strcasecmp(options.canonical_domains[i], "none") == 0)
			நிறுத்து;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		எனில் ((addrs = resolve_host(fullhost, port, 0,
		    newname, அளவு(newname))) == வெற்று) {
			விடுவி(fullhost);
			தொடர்;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		எனில் (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		விடுவி(*hostp);
		*hostp = fullhost;
		திரும்பு addrs;
	}
 notfound:
	எனில் (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	திரும்பு வெற்று;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
நிலையான வெறுமை
check_load(முழு r, கட்டமைப்பு sshkey **k, மாறிலி எழுத்து *path, மாறிலி எழுத்து *message)
{
	எழுத்து *fp;

	தேர்வு (r) {
	நிலை 0:
		எனில் (k == வெற்று || *k == வெற்று)
			திரும்பு;
		/* Check RSA keys size and discard if undersized */
		எனில் ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			விடுவி(*k);
			*k = வெற்று;
			நிறுத்து;
		}
		எனில் ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == வெற்று) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		விடுவி(fp);
		நிறுத்து;
	நிலை SSH_ERR_INTERNAL_ERROR:
	நிலை SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	நிலை SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		எனில் (errno == ENOENT)
			நிறுத்து;
		/* FALLTHROUGH */
	இயல்பு:
		error_r(r, "load %s \"%s\"", message, path);
		நிறுத்து;
	}
	எனில் (k != வெற்று && *k == வெற்று)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
நிலையான வெறுமை
process_config_files(மாறிலி எழுத்து *host_name, கட்டமைப்பு passwd *pw,
    முழு final_pass, முழு *want_final_pass)
{
	எழுத்து *cmd, buf[PATH_MAX];
	முழு r;

	எனில் ((cmd = sshbuf_dup_string(command)) == வெற்று)
		fatal_f("sshbuf_dup_string failed");
	எனில் (config != வெற்று) {
		எனில் (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} இல்லையெனில் {
		r = snprintf(buf, அளவு buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		எனில் (r > 0 && (size_t)r < அளவு(buf))
			(வெறுமை)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(வெறுமை)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	விடுவி(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
நிலையான வெறுமை
set_addrinfo_port(கட்டமைப்பு addrinfo *addrs, முழு port)
{
	கட்டமைப்பு addrinfo *addr;

	க்கு (addr = addrs; addr != வெற்று; addr = addr->ai_next) {
		தேர்வு (addr->ai_family) {
		நிலை AF_INET:
			((கட்டமைப்பு sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			நிறுத்து;
		நிலை AF_INET6:
			((கட்டமைப்பு sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			நிறுத்து;
		}
	}
}

/*
 * Main program for the ssh client.
 */
முழு
முதன்மை(முழு ac, எழுத்து **av)
{
	கட்டமைப்பு ssh *ssh = வெற்று;
	முழு i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	முழு was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	முழு user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	எழுத்து *p, *cp, *வரி, *argv0, *logfile, *args;
	எழுத்து cname[NI_MAXHOST], thishost[NI_MAXHOST];
	கட்டமைப்பு stat st;
	கட்டமைப்பு passwd *pw;
	வெளி முழு optind, optreset;
	வெளி எழுத்து *optarg;
	கட்டமைப்பு Forward fwd;
	கட்டமைப்பு addrinfo *addrs = வெற்று;
	size_t n, len;
	u_int j;
	கட்டமைப்பு utsname utsname;
	கட்டமைப்பு ssh_conn_info *cinfo = வெற்று;

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
	saved_av = xcalloc(ac + 1, அளவு(*saved_av));
	க்கு (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = வெற்று;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	எனில் (!pw) {
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
	எனில் ((ssh = ssh_alloc_session_state()) == வெற்று)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = வெற்று;
	use_syslog = 0;
	logfile = வெற்று;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	போது ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		தேர்வு (opt) {
		நிலை '1':
			fatal("SSH protocol v.1 is no longer supported");
			நிறுத்து;
		நிலை '2':
			/* Ignored */
			நிறுத்து;
		நிலை '4':
			options.address_family = AF_INET;
			நிறுத்து;
		நிலை '6':
			options.address_family = AF_INET6;
			நிறுத்து;
		நிலை 'n':
			options.stdin_null = 1;
			நிறுத்து;
		நிலை 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			நிறுத்து;
		நிலை 'x':
			options.forward_x11 = 0;
			நிறுத்து;
		நிலை 'X':
			options.forward_x11 = 1;
			நிறுத்து;
		நிலை 'y':
			use_syslog = 1;
			நிறுத்து;
		நிலை 'E':
			logfile = optarg;
			நிறுத்து;
		நிலை 'G':
			config_test = 1;
			நிறுத்து;
		நிலை 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			நிறுத்து;
		நிலை 'Z':
			dump_pubkeys = 1;
			நிறுத்து;
		நிலை 'g':
			options.fwd_opts.gateway_ports = 1;
			நிறுத்து;
		நிலை 'O':
			எனில் (options.stdio_forward_host != வெற்று)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			இல்லையெனில் எனில் (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			எனில் (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			இல்லையெனில் எனில் (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			இல்லையெனில் எனில் (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			இல்லையெனில் எனில் (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			இல்லையெனில் எனில் (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			இல்லையெனில் எனில் (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			இல்லையெனில் எனில் (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			இல்லையெனில் எனில் (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			இல்லையெனில்
				fatal("Invalid multiplex command.");
			நிறுத்து;
		நிலை 'P':
			எனில் (options.tag == வெற்று)
				options.tag = xstrdup(optarg);
			நிறுத்து;
		நிலை 'Q':
			cp = வெற்று;
			எனில் (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			இல்லையெனில் எனில் (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			இல்லையெனில் எனில் (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			இல்லையெனில் எனில் (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			இல்லையெனில் எனில் (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			இல்லையெனில் எனில் (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			இல்லையெனில் எனில் (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			இல்லையெனில் எனில் (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			இல்லையெனில் எனில் (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			இல்லையெனில் எனில் (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			இல்லையெனில் எனில் (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			இல்லையெனில் எனில் (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				க்கு (n = 0; n < len; n++)
					எனில் (cp[n] == ',')
						cp[n] = '\n';
			} இல்லையெனில் எனில் (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			எனில் (cp == வெற்று)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			விடுவி(cp);
			exit(0);
			நிறுத்து;
		நிலை 'a':
			options.forward_agent = 0;
			நிறுத்து;
		நிலை 'A':
			options.forward_agent = 1;
			நிறுத்து;
		நிலை 'k':
			options.gss_deleg_creds = 0;
			நிறுத்து;
		நிலை 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			நிறுத்து;
		நிலை 'i':
			p = tilde_expand_filename(optarg, getuid());
			எனில் (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			இல்லையெனில்
				add_identity_file(&options, வெற்று, p, 1);
			விடுவி(p);
			நிறுத்து;
		நிலை 'I':
#ifdef ENABLE_PKCS11
			விடுவி(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#இல்லையெனில்
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			நிறுத்து;
		நிலை 'J':
			எனில் (options.jump_host != வெற்று) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			எனில் (options.proxy_command != வெற்று)
				fatal("Cannot specify -J with ProxyCommand");
			எனில் (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			நிறுத்து;
		நிலை 't':
			எனில் (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			இல்லையெனில்
				options.request_tty = REQUEST_TTY_YES;
			நிறுத்து;
		நிலை 'v':
			எனில் (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} இல்லையெனில் {
				எனில் (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			நிறுத்து;
		நிலை 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			நிறுத்து;
		நிலை 'w':
			எனில் (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			எனில் (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			நிறுத்து;
		நிலை 'W':
			எனில் (options.stdio_forward_host != வெற்று)
				fatal("stdio forward already specified");
			எனில் (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			எனில் (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				விடுவி(fwd.connect_host);
			} இல்லையெனில் {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			நிறுத்து;
		நிலை 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			நிறுத்து;
		நிலை 'e':
			எனில் (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			இல்லையெனில் எனில் (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			இல்லையெனில் எனில் (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			இல்லையெனில் {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			நிறுத்து;
		நிலை 'c':
			எனில் (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			விடுவி(options.ciphers);
			options.ciphers = xstrdup(optarg);
			நிறுத்து;
		நிலை 'm':
			எனில் (mac_valid(optarg)) {
				விடுவி(options.macs);
				options.macs = xstrdup(optarg);
			} இல்லையெனில் {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			நிறுத்து;
		நிலை 'M':
			எனில் (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			இல்லையெனில்
				options.control_master = SSHCTL_MASTER_YES;
			நிறுத்து;
		நிலை 'p':
			எனில் (options.port == -1) {
				options.port = a2port(optarg);
				எனில் (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			நிறுத்து;
		நிலை 'l':
			எனில் (options.user == வெற்று) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			நிறுத்து;

		நிலை 'L':
			எனில் (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			இல்லையெனில் {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			நிறுத்து;

		நிலை 'R':
			எனில் (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} இல்லையெனில் {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			நிறுத்து;

		நிலை 'D':
			எனில் (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} இல்லையெனில் {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			நிறுத்து;

		நிலை 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#இல்லையெனில்
			error("Compression not supported, disabling.");
#endif
			நிறுத்து;
		நிலை 'N':
			எனில் (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			நிறுத்து;
		நிலை 'T':
			options.request_tty = REQUEST_TTY_NO;
			நிறுத்து;
		நிலை 'o':
			வரி = xstrdup(optarg);
			எனில் (process_config_வரி(&options, pw,
			    host ? host : "", host ? host : "", "", வரி,
			    "command-line", 0, வெற்று, SSHCONF_USERCONF) != 0)
				exit(255);
			விடுவி(வரி);
			நிறுத்து;
		நிலை 's':
			எனில் (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			நிறுத்து;
		நிலை 'S':
			விடுவி(options.control_path);
			options.control_path = xstrdup(optarg);
			நிறுத்து;
		நிலை 'b':
			options.bind_address = optarg;
			நிறுத்து;
		நிலை 'B':
			options.bind_interface = optarg;
			நிறுத்து;
		நிலை 'F':
			config = optarg;
			நிறுத்து;
		இயல்பு:
			usage();
		}
	}

	எனில் (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	எனில் (ac > 0 && !host) {
		முழு tport;
		எழுத்து *tuser;
		தேர்வு (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		நிலை -1:
			usage();
			நிறுத்து;
		நிலை 0:
			எனில் (options.user == வெற்று) {
				options.user = tuser;
				tuser = வெற்று;
				user_on_commandline = 1;
			}
			விடுவி(tuser);
			எனில் (options.port == -1 && tport != -1)
				options.port = tport;
			நிறுத்து;
		இயல்பு:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			எனில் (cp != வெற்று) {
				எனில் (cp == p)
					usage();
				எனில் (options.user == வெற்று) {
					options.user = p;
					p = வெற்று;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				விடுவி(p);
			} இல்லையெனில்
				host = p;
			நிறுத்து;
		}
		எனில் (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			செல் again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	எனில் (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	எனில் (options.user != வெற்று && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	எனில் (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	எனில் ((command = sshbuf_new()) == வெற்று)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	எனில் (!ac) {
		/* No command specified - execute shell on a tty. */
		எனில் (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} இல்லையெனில் {
		/* A command has been specified.  Store it into the buffer. */
		க்கு (i = 0; i < ac; i++) {
			எனில் ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	எனில் (use_syslog && logfile != வெற்று)
		fatal("Can't specify both -y and -E");
	எனில் (logfile != வெற்று)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	எனில் (uname(&utsname) != 0) {
		memset(&utsname, 0, அளவு(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", அளவு(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	விடுவி(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	எனில் (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	எனில் (options.hostname != வெற்று) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (எழுத்து *)வெற்று);
		விடுவி(host);
		host = cp;
		விடுவி(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	எனில் ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	எனில் (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	எனில் (addrs == வெற்று && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		எனில் ((addrs = resolve_host(host, options.port,
		    direct, cname, அளவு(cname))) == வெற்று) {
			/* Don't fatal proxied host names not in the DNS */
			எனில் (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} இல்லையெனில்
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	எனில் (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	எனில் (want_final_pass) {
		debug("re-parsing configuration");
		விடுவி(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, வெற்று);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		எனில் (addrs != வெற்று && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	எனில் (fill_default_options(&options) != 0)
		cleanup_exit(255);

	எனில் (options.user == வெற்று) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	எனில் (options.jump_host != வெற்று) {
		எழுத்து port_s[8];
		மாறிலி எழுத்து *jumpuser = options.jump_user, *sshbin = argv0;
		முழு port = options.port, jumpport = options.jump_port;

		எனில் (port <= 0)
			port = default_ssh_port();
		எனில் (jumpport <= 0)
			jumpport = default_ssh_port();
		எனில் (jumpuser == வெற்று)
			jumpuser = options.user;
		எனில் (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		எனில் (strchr(argv0, '/') != வெற்று && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		எனில் (options.proxy_command != வெற்று &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, அளவு(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == வெற்று ? "" : " -l ",
		    options.jump_user == வெற்று ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == வெற்று ? "" : " -J ",
		    options.jump_extra == வெற்று ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == வெற்று ? "" : " -F ",
		    config == வெற்று ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	எனில் (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	எனில் (options.host_சாவி_alias != வெற்று)
		lowercase(options.host_சாவி_alias);
	எனில் (options.proxy_command != வெற்று &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	எனில் (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		எனில் (options.control_persist && options.control_path != வெற்று) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} இல்லையெனில் எனில் (sshbuf_len(command) != 0 ||
		    options.remote_command != வெற்று ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} இல்லையெனில் எனில் (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	எனில் (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	எனில் (sshbuf_len(command) != 0 && options.remote_command != வெற்று)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	எனில் (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == வெற்று &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	க்கு (j = 0; j < options.இலக்கம்_log_verbose; j++) {
		எனில் (strcasecmp(options.log_verbose[j], "none") == 0)
			நிறுத்து;
		log_verbose_add(options.log_verbose[j]);
	}

	எனில் (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	எனில் (sshbuf_len(command) == 0 && options.remote_command == வெற்று)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	எனில் (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	எனில் ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		எனில் (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, அளவு(*cinfo));
	எனில் (gethostname(thishost, அளவு(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_சாவி_alias ?
	    options.host_சாவி_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == வெற்று ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	எனில் (!user_on_commandline && !user_was_default) {
		எனில் ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (எழுத்து *)வெற்று)) == வெற்று)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		விடுவி(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	எனில் ((user_on_commandline || user_expanded) &&
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
	எனில் (options.remote_command != வெற்று) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		விடுவி(cp);
		எனில் ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	எனில் (options.control_path != வெற்று) {
		cp = tilde_expand_filename(options.control_path, getuid());
		விடுவி(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		விடுவி(cp);
	}

	எனில் (options.identity_agent != வெற்று) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		விடுவி(p);
		விடுவி(options.identity_agent);
		options.identity_agent = cp;
	}

	க்கு (j = 0; j < options.இலக்கம்_revoked_host_சாவிகள்; j++) {
		p = tilde_expand_filename(options.revoked_host_சாவிகள்[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		விடுவி(p);
		விடுவி(options.revoked_host_சாவிகள்[j]);
		options.revoked_host_சாவிகள்[j] = cp;
	}

	எனில் (options.forward_agent_sock_path != வெற்று) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		விடுவி(p);
		விடுவி(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		எனில் (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			எனில் (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	எனில் (options.version_addendum != வெற்று) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		விடுவி(options.version_addendum);
		options.version_addendum = cp;
	}

	எனில் (options.இலக்கம்_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		எனில் (options.இலக்கம்_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		விடுவி(options.system_hostfiles[0]);
		options.system_hostfiles[0] = வெற்று;
		options.இலக்கம்_system_hostfiles = 0;
	}

	எனில் (options.இலக்கம்_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		எனில் (options.இலக்கம்_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		விடுவி(options.user_hostfiles[0]);
		options.user_hostfiles[0] = வெற்று;
		options.இலக்கம்_user_hostfiles = 0;
	}
	க்கு (j = 0; j < options.இலக்கம்_user_hostfiles; j++) {
		எனில் (options.user_hostfiles[j] == வெற்று)
			தொடர்;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		எனில் (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		விடுவி(options.user_hostfiles[j]);
		விடுவி(cp);
		options.user_hostfiles[j] = p;
	}

	க்கு (j = 0; j < options.இலக்கம்_setenv; j++) {
		எழுத்து *name = options.setenv[j], *மதிப்பு;

		எனில் (name == வெற்று)
			தொடர்;
		/* Expand only the value portion, not the variable name. */
		எனில் ((மதிப்பு = strchr(name, '=')) == வெற்று) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*மதிப்பு++ = '\0';
		cp = default_client_percent_dollar_expand(மதிப்பு, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		எனில் (strcmp(மதிப்பு, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, மதிப்பு, cp);
		}
		விடுவி(options.setenv[j]);
		விடுவி(cp);
		options.setenv[j] = p;
	}

	க்கு (i = 0; i < options.இலக்கம்_local_forwards; i++) {
		எனில் (options.local_forwards[i].listen_path != வெற்று) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			எனில் (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			விடுவி(cp);
		}
		எனில் (options.local_forwards[i].connect_path != வெற்று) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			எனில் (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			விடுவி(cp);
		}
	}

	க்கு (i = 0; i < options.இலக்கம்_remote_forwards; i++) {
		எனில் (options.remote_forwards[i].listen_path != வெற்று) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			எனில் (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			விடுவி(cp);
		}
		எனில் (options.remote_forwards[i].connect_path != வெற்று) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			எனில் (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			விடுவி(cp);
		}
	}

	எனில் (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	எனில் (options.sk_provider != வெற்று && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		எனில் ((cp = getenv(options.sk_provider + 1)) == வெற்று) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			விடுவி(options.sk_provider);
			options.sk_provider = வெற்று;
		} இல்லையெனில் {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			விடுவி(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	எனில் (muxclient_command != 0 && options.control_path == வெற்று)
		fatal("No ControlPath specified for \"-O\" command");
	எனில் (options.control_path != வெற்று) {
		முழு sock;
		எனில் ((sock = muxclient(options.control_path)) >= 0) {
			எனில் (ssh_packet_set_connection(ssh, sock, sock) == வெற்று)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			செல் skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	எனில் (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		எனில் (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} இல்லையெனில் {
			cp = options.identity_agent;
			/* legacy (limited) format */
			எனில் (cp[0] == '$' && cp[1] != '{') {
				எனில் (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				எனில் ((p = getenv(cp + 1)) == வெற்று)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				இல்லையெனில்
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} இல்லையெனில் {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	எனில் (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	எனில் (addrs == வெற்று && options.proxy_command == வெற்று) {
		debug2("resolving \"%s\" port %d", host, options.port);
		எனில் ((addrs = resolve_host(host, options.port, 1,
		    cname, அளவு(cname))) == வெற்று)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	எனில் (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	இல்லையெனில்
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	க்கு (j = 0; j < options.இலக்கம்_channel_timeouts; j++) {
		இரட்டை timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		எனில் (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		விடுவி(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	எனில் (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_மொத்தம்_max);

	எனில் (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.சாவிகள் = வெற்று;
	எனில் (options.hostbased_authentication) {
		முழு loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.சாவிகள் = xcalloc(sensitive_data.nkeys,
		    அளவு(*sensitive_data.சாவிகள்));

		/* XXX check errors? */
#define L_PUBKEY(p,o) செய் { \
	எனில் ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.சாவிகள்[o]), வெற்று), \
	    &(sensitive_data.சாவிகள்[o]), p, "hostbased pubkey"); \
	எனில் (sensitive_data.சாவிகள்[o] != வெற்று) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} போது (0)
#define L_CERT(p,o) செய் { \
	எனில் ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.சாவிகள்[o])), \
	    &(sensitive_data.சாவிகள்[o]), p, "hostbased cert"); \
	எனில் (sensitive_data.சாவிகள்[o] != வெற்று) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} போது (0)

		எனில் (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_சாவி_FILE, 0);
			L_CERT(PATH_HOST_ED25519_சாவி_FILE, 1);
			L_CERT(PATH_HOST_RSA_சாவி_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_சாவி_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_சாவி_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_சாவி_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_சாவி_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_சாவி_FILE, 7);
			எனில் (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	எனில் (options.forward_agent && options.forward_agent_sock_path != வெற்று) {
		cp = options.forward_agent_sock_path;
		எனில் (cp[0] == '$') {
			எனில் (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			எனில் ((p = getenv(cp + 1)) != வெற்று)
				forward_agent_sock_path = xstrdup(p);
			இல்லையெனில்
				options.forward_agent = 0;
			விடுவி(cp);
		} இல்லையெனில் {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.இலக்கம்_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.இலக்கம்_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	எனில் (sensitive_data.nkeys != 0) {
		க்கு (i = 0; i < sensitive_data.nkeys; i++) {
			எனில் (sensitive_data.சாவிகள்[i] != வெற்று) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.சாவிகள்[i]);
				sensitive_data.சாவிகள்[i] = வெற்று;
			}
		}
		விடுவி(sensitive_data.சாவிகள்);
	}
	க்கு (i = 0; i < options.இலக்கம்_identity_files; i++) {
		விடுவி(options.identity_files[i]);
		options.identity_files[i] = வெற்று;
		எனில் (options.identity_சாவிகள்[i]) {
			sshkey_free(options.identity_சாவிகள்[i]);
			options.identity_சாவிகள்[i] = வெற்று;
		}
	}
	க்கு (i = 0; i < options.இலக்கம்_certificate_files; i++) {
		விடுவி(options.certificate_files[i]);
		options.certificate_files[i] = வெற்று;
	}

#ifdef ENABLE_PKCS11
	(வெறுமை)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	எனில் (addrs != வெற்று)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	எனில் (options.control_path != வெற்று && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	திரும்பு exit_status;
}

நிலையான வெறுமை
control_persist_detach(வெறுமை)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	தேர்வு ((pid = fork())) {
	நிலை -1:
		fatal_f("fork: %s", strerror(errno));
	நிலை 0:
		/* Child: master process continues mainloop */
		நிறுத்து;
	இயல்பு:
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
		(வெறுமை)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	எனில் (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
நிலையான வெறுமை
fork_postauth(வெறுமை)
{
	எனில் (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	எனில் (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	எனில் (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

நிலையான வெறுமை
forwarding_success(வெறுமை)
{
	எனில் (forward_confirms_pending == -1)
		திரும்பு;
	எனில் (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		எனில் (options.fork_after_authentication)
			fork_postauth();
	} இல்லையெனில் {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

கட்டமைப்பு rfwd_confirm_ctx {
	முழு fid;
};

/* Callback for remote forward global requests */
நிலையான வெறுமை
ssh_confirm_remote_forward(கட்டமைப்பு ssh *ssh, முழு type, uint32_t seq, வெறுமை *ctxt)
{
	கட்டமைப்பு rfwd_confirm_ctx *rctx = (கட்டமைப்பு rfwd_confirm_ctx *)ctxt;
	கட்டமைப்பு Forward *rfwd;
	u_int port;
	முழு r;

	எனில் (rctx->fid < 0 || rctx->fid >= options.இலக்கம்_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, அளவு(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_செய்தி_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	எனில் (rfwd->listen_path == வெற்று && rfwd->listen_port == 0) {
		எனில் (type == SSH2_செய்தி_REQUEST_SUCCESS) {
			எனில் ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			எனில் (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_செய்தி_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} இல்லையெனில் {
				rfwd->allocated_port = (முழு)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} இல்லையெனில் {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	எனில் (type == SSH2_செய்தி_REQUEST_FAILURE) {
		எனில் (options.exit_on_forward_failure) {
			எனில் (rfwd->listen_path != வெற்று)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			இல்லையெனில்
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} இல்லையெனில் {
			எனில் (rfwd->listen_path != வெற்று)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			இல்லையெனில்
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

நிலையான வெறுமை
client_cleanup_stdio_fwd(கட்டமைப்பு ssh *ssh, முழு id, முழு force, வெறுமை *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

நிலையான வெறுமை
ssh_stdio_confirm(கட்டமைப்பு ssh *ssh, முழு id, முழு success, வெறுமை *arg)
{
	எனில் (!success)
		fatal("stdio forwarding failed");
}

நிலையான வெறுமை
ssh_tun_confirm(கட்டமைப்பு ssh *ssh, முழு id, முழு success, வெறுமை *arg)
{
	எனில் (!success) {
		error("Tunnel forwarding failed");
		எனில் (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

நிலையான வெறுமை
ssh_init_stdio_forwarding(கட்டமைப்பு ssh *ssh)
{
	Channel *c;
	முழு in, out;

	எனில் (options.stdio_forward_host == வெற்று)
		திரும்பு;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	எனில் ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	எனில் ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == வெற்று)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, வெற்று);
}

நிலையான வெறுமை
ssh_init_forward_permissions(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *what, எழுத்து **opens,
    u_int இலக்கம்_opens)
{
	u_int i;
	முழு port;
	எழுத்து *addr, *arg, *oarg;
	முழு where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	எனில் (இலக்கம்_opens == 0)
		திரும்பு; /* permit any */

	/* handle keywords: "any" / "none" */
	எனில் (இலக்கம்_opens == 1 && strcmp(opens[0], "any") == 0)
		திரும்பு;
	எனில் (இலக்கம்_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		திரும்பு;
	}
	/* Otherwise treat it as a list of permitted host:port */
	க்கு (i = 0; i < இலக்கம்_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		எனில் (addr == வெற்று)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		எனில் (arg == வெற்று || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		விடுவி(oarg);
	}
}

நிலையான வெறுமை
ssh_init_forwarding(கட்டமைப்பு ssh *ssh, எழுத்து **ifname)
{
	முழு success = 0;
	முழு i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.இலக்கம்_permitted_remote_opens);

	எனில் (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	க்கு (i = 0; i < options.இலக்கம்_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != வெற்று) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == வெற்று) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != வெற்று) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	எனில் (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	எனில் (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	க்கு (i = 0; i < options.இலக்கம்_remote_forwards; i++) {
		கட்டமைப்பு rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != வெற்று) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == வெற்று) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != வெற்று) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		எனில் ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, அளவு(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} இல்லையெனில் எனில் (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		இல்லையெனில்
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	எனில் (options.tun_open != SSH_TUNMODE_NO) {
		எனில் ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, வெற்று)) != வெற்று)
			forward_confirms_pending++;
		இல்லையெனில் எனில் (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		இல்லையெனில்
			error("Could not request tunnel forwarding.");
	}
	எனில் (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

நிலையான வெறுமை
check_agent_present(வெறுமை)
{
	முழு r;

	எனில் (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		எனில் ((r = ssh_get_authentication_socket(வெற்று)) != 0) {
			options.forward_agent = 0;
			எனில் (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

நிலையான வெறுமை
ssh_session2_setup(கட்டமைப்பு ssh *ssh, முழு id, முழு success, வெறுமை *arg)
{
	வெளி எழுத்து **environ;
	மாறிலி எழுத்து *display, *term;
	எழுத்து *proto = வெற்று, *data = வெற்று;

	எனில் (!success)
		திரும்பு; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	எனில் (display == வெற்று && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	எனில் (options.forward_x11 && client_x11_get_proto(ssh, display,
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
	எனில் (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	எனில் ((term = lookup_env_in_list("TERM", options.setenv,
	    options.இலக்கம்_setenv)) == வெற்று || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    வெற்று, fileno(stdin), command, environ);
}

/* open new channel for a session */
நிலையான முழு
ssh_session2_open(கட்டமைப்பு ssh *ssh)
{
	Channel *c;
	முழு window, packetmax, in, out, err;

	எனில் (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} இல்லையெனில் {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	எனில் (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	எனில் (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	எனில் (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	எனில் (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, வெற்று);

	திரும்பு c->self;
}

நிலையான முழு
ssh_session2(கட்டமைப்பு ssh *ssh, மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	முழு r, id = -1;
	எழுத்து *cp, *tun_fwd_ifname = வெற்று;

	/* XXX should be pre-session */
	எனில் (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	எனில் (options.local_command != வெற்று) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == வெற்று ? "NONE" : tun_fwd_ifname,
		    (எழுத்து *)வெற்று);
		debug3("expanded LocalCommand: %s", options.local_command);
		விடுவி(cp);
	}

	/* Start listening for multiplex clients */
	எனில் (!ssh_packet_get_mux(ssh))
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
	எனில் (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		எனில் ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != வெற்று))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	எனில் (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	எனில் (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	எனில் (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	எனில் (options.local_command != வெற்று &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	எனில் (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	எனில் (options.fork_after_authentication) {
		எனில் (options.exit_on_forward_failure &&
		    options.இலக்கம்_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} இல்லையெனில்
			fork_postauth();
	}

	திரும்பு client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
நிலையான வெறுமை
load_public_identity_files(மாறிலி கட்டமைப்பு ssh_conn_info *cinfo)
{
	எழுத்து *filename, *cp;
	கட்டமைப்பு sshkey *பொது;
	முழு i;
	u_int n_ids, n_certs;
	எழுத்து *identity_files[SSH_MAX_IDENTITY_FILES];
	கட்டமைப்பு sshkey *identity_சாவிகள்[SSH_MAX_IDENTITY_FILES];
	முழு identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	எழுத்து *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	கட்டமைப்பு sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	முழு certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	கட்டமைப்பு sshkey **சாவிகள் = வெற்று;
	எழுத்து **comments = வெற்று;
	முழு nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, அளவு(identity_files));
	memset(identity_சாவிகள், 0, அளவு(identity_சாவிகள்));
	memset(identity_file_userprovided, 0,
	    அளவு(identity_file_userprovided));
	memset(certificate_files, 0, அளவு(certificate_files));
	memset(certificates, 0, அளவு(certificates));
	memset(certificate_file_userprovided, 0,
	    அளவு(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	எனில் (options.pkcs11_provider != வெற்று &&
	    options.இலக்கம்_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, வெற்று,
	    &சாவிகள், &comments)) > 0) {
		க்கு (i = 0; i < nkeys; i++) {
			எனில் (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(சாவிகள்[i]);
				விடுவி(comments[i]);
				தொடர்;
			}
			identity_சாவிகள்[n_ids] = சாவிகள்[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		விடுவி(சாவிகள்);
		விடுவி(comments);
	}
#endif /* ENABLE_PKCS11 */
	க்கு (i = 0; i < options.இலக்கம்_identity_files; i++) {
		எனில் (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			விடுவி(options.identity_files[i]);
			options.identity_files[i] = வெற்று;
			தொடர்;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		விடுவி(cp);
		check_load(sshkey_load_public(filename, &பொது, வெற்று),
		    &பொது, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    பொது ? பொது->type : -1);
		விடுவி(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_சாவிகள்[n_ids] = பொது;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		எனில் (++n_ids >= SSH_MAX_IDENTITY_FILES)
			தொடர்;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		எனில் (options.இலக்கம்_certificate_files != 0)
			தொடர்;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &பொது, வெற்று),
		    &பொது, filename, "identity pubkey");
		எனில் (பொது == வெற்று) {
			விடுவி(cp);
			தொடர்;
		}
		எனில் (!sshkey_is_cert(பொது)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(பொது));
			sshkey_free(பொது);
			விடுவி(cp);
			தொடர்;
		}
		விடுவி(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_சாவிகள்[n_ids] = பொது;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	எனில் (options.இலக்கம்_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	க்கு (i = 0; i < options.இலக்கம்_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		விடுவி(cp);

		check_load(sshkey_load_public(filename, &பொது, வெற்று),
		    &பொது, filename, "identity cert");
		விடுவி(options.certificate_files[i]);
		options.certificate_files[i] = வெற்று;
		எனில் (பொது == வெற்று) {
			விடுவி(filename);
			தொடர்;
		}
		எனில் (!sshkey_is_cert(பொது)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(பொது));
			sshkey_free(பொது);
			விடுவி(filename);
			தொடர்;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = பொது;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.இலக்கம்_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, அளவு(identity_files));
	memcpy(options.identity_சாவிகள், identity_சாவிகள், அளவு(identity_சாவிகள்));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, அளவு(identity_file_userprovided));

	options.இலக்கம்_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, அளவு(certificate_files));
	memcpy(options.certificates, certificates, அளவு(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    அளவு(certificate_file_userprovided));
}

நிலையான வெறுமை
main_sigchld_handler(முழு sig)
{
	முழு save_errno = errno;
	pid_t pid;
	முழு status;

	போது ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
