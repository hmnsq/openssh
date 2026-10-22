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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/utsname.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <locale.h>

#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/err.h>
#endif
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "clientloop.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "sshconnect.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "version.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "utf8.h"

#ifdef ENABLE_PKCS11
#અન્તર્ભાવ "ssh-pkcs11.h"
#endif

બાહ્ય અક્ષર *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
સ્થિર અક્ષર **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
પૂર્ણાંક debug_flag = 0;

/* Flag indicating whether a tty should be requested */
પૂર્ણાંક tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
સ્થિર પૂર્ણાંક need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
સ્થિર પૂર્ણાંક ostdin_null_flag, osession_type, otty_flag, orequest_tty;
સ્થિર પૂર્ણાંક ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
અક્ષર *config = ખાલી;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
અક્ષર *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
અક્ષર *forward_agent_sock_path = ખાલી;

/* socket address the host resolves to */
સંરચના sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* command to be executed */
સંરચના sshbuf *command;

/* # of replies received for global requests */
સ્થિર પૂર્ણાંક forward_confirms_pending = -1;

/* mux.c */
બાહ્ય પૂર્ણાંક muxserver_sock;
બાહ્ય u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

સ્થિર શૂન્ય
usage(શૂન્ય)
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

સ્થિર પૂર્ણાંક ssh_session2(સંરચના ssh *, અચલ સંરચના ssh_conn_info *);
સ્થિર શૂન્ય load_public_identity_files(અચલ સંરચના ssh_conn_info *);
સ્થિર શૂન્ય main_sigchld_handler(પૂર્ણાંક);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
સ્થિર શૂન્ય
tilde_expand_paths(અક્ષર **paths, u_int અંક_paths)
{
	u_int i;
	અક્ષર *cp;

	માટે (i = 0; i < અંક_paths; i++) {
		cp = tilde_expand_filename(paths[i], getuid());
		મુક્ત(paths[i]);
		paths[i] = cp;
	}
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * in the client that support percent expansion.
 * Caller must free returned string.
 */
સ્થિર અક્ષર *
default_client_percent_expand(અચલ અક્ષર *str,
    અચલ સંરચના ssh_conn_info *cinfo)
{
	પાછા percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (અક્ષર *)ખાલી);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
સ્થિર અક્ષર *
default_client_percent_dollar_expand(અચલ અક્ષર *str,
    અચલ સંરચના ssh_conn_info *cinfo)
{
	અક્ષર *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (અક્ષર *)ખાલી);
	જો (ret == ખાલી)
		fatal("invalid environment variable expansion");
	પાછા ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
સ્થિર સંરચના addrinfo *
resolve_host(અચલ અક્ષર *name, પૂર્ણાંક port, પૂર્ણાંક logerr, અક્ષર *cname, size_t clen)
{
	અક્ષર strport[NI_MAXSERV];
	અચલ અક્ષર *errstr = ખાલી;
	સંરચના addrinfo hints, *res;
	પૂર્ણાંક gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	જો (port <= 0)
		port = default_ssh_port();
	જો (cname != ખાલી)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, કદ strport, "%d", port);
	memset(&hints, 0, કદ(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	જો (cname != ખાલી)
		hints.ai_flags = AI_CANONNAME;
	જો ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		જો (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		પાછા ખાલી;
	}
	જો (cname != ખાલી && res->ai_canonname != ખાલી) {
		જો (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} નહીંતર જો (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			જો (clen > 0)
				*cname = '\0';
		}
	}
	પાછા res;
}

/* Returns non-zero if name can only be an address and not a hostname */
સ્થિર પૂર્ણાંક
is_addr_fast(અચલ અક્ષર *name)
{
	પાછા (strchr(name, '%') != ખાલી || strchr(name, ':') != ખાલી ||
	    strspn(name, "0123456789.") == strlen(name));
}

/* Returns non-zero if name represents a valid, single address */
સ્થિર પૂર્ણાંક
is_addr(અચલ અક્ષર *name)
{
	અક્ષર strport[NI_MAXSERV];
	સંરચના addrinfo hints, *res;

	જો (is_addr_fast(name))
		પાછા 1;

	snprintf(strport, કદ strport, "%u", default_ssh_port());
	memset(&hints, 0, કદ(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	જો (getaddrinfo(name, strport, &hints, &res) != 0)
		પાછા 0;
	જો (res == ખાલી || res->ai_next != ખાલી) {
		freeaddrinfo(res);
		પાછા 0;
	}
	freeaddrinfo(res);
	પાછા 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
સ્થિર સંરચના addrinfo *
resolve_addr(અચલ અક્ષર *name, પૂર્ણાંક port, અક્ષર *caddr, size_t clen)
{
	અક્ષર addr[NI_MAXHOST], strport[NI_MAXSERV];
	સંરચના addrinfo hints, *res;
	પૂર્ણાંક gaierr;

	જો (port <= 0)
		port = default_ssh_port();
	snprintf(strport, કદ strport, "%u", port);
	memset(&hints, 0, કદ(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	જો ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		પાછા ખાલી;
	}
	જો (res == ખાલી) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		પાછા ખાલી;
	}
	જો (res->ai_next != ખાલી) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		જાઓ fail;
	}
	જો ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, કદ(addr), ખાલી, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		જાઓ fail;
	}
	જો (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		જો (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		પાછા ખાલી;
	}
	પાછા res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
સ્થિર પૂર્ણાંક
check_follow_cname(પૂર્ણાંક direct, અક્ષર **namep, અચલ અક્ષર *cname)
{
	પૂર્ણાંક i;
	સંરચના allowed_cname *rule;

	જો (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    strcmp(*namep, cname) == 0)
		પાછા 0;
	જો (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		પાછા 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	જો (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		પાછા 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	માટે (i = 0; i < options.અંક_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		જો (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			ચાલુ;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		મુક્ત(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		પાછા 1;
	}
	પાછા 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
સ્થિર સંરચના addrinfo *
resolve_canonicalize(અક્ષર **hostp, પૂર્ણાંક port)
{
	પૂર્ણાંક i, direct, ndots;
	અક્ષર *cp, *fullhost, newname[NI_MAXHOST];
	સંરચના addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	જો ((addrs = resolve_addr(*hostp, port,
	    newname, કદ(newname))) != ખાલી) {
		debug2_f("hostname %.100s is address", *hostp);
		જો (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			મુક્ત(*hostp);
			*hostp = xstrdup(newname);
		}
		પાછા addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	જો (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		પાછા ખાલી;
	}

	જો (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		પાછા ખાલી;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	જો (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		પાછા ખાલી;

	/* If domain name is anchored, then resolve it now */
	જો ((*hostp)[strlen(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		જો ((addrs = resolve_host(fullhost, port, 0,
		    newname, કદ(newname))) != ખાલી)
			જાઓ found;
		મુક્ત(fullhost);
		જાઓ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	માટે (cp = *hostp; *cp != '\0'; cp++) {
		જો (*cp == '.')
			ndots++;
	}
	જો (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		પાછા ખાલી;
	}
	/* Attempt each supplied suffix */
	માટે (i = 0; i < options.અંક_canonical_domains; i++) {
		જો (strcasecmp(options.canonical_domains[i], "none") == 0)
			તોડો;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		જો ((addrs = resolve_host(fullhost, port, 0,
		    newname, કદ(newname))) == ખાલી) {
			મુક્ત(fullhost);
			ચાલુ;
		}
 found:
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		જો (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		મુક્ત(*hostp);
		*hostp = fullhost;
		પાછા addrs;
	}
 notfound:
	જો (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	પાછા ખાલી;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
સ્થિર શૂન્ય
check_load(પૂર્ણાંક r, સંરચના sshkey **k, અચલ અક્ષર *path, અચલ અક્ષર *message)
{
	અક્ષર *fp;

	પસંદગી (r) {
	સ્થિતિ 0:
		જો (k == ખાલી || *k == ખાલી)
			પાછા;
		/* Check RSA keys size and discard if undersized */
		જો ((r = sshkey_check_rsa_length(*k,
		    options.required_rsa_size)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			મુક્ત(*k);
			*k = ખાલી;
			તોડો;
		}
		જો ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ખાલી) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		મુક્ત(fp);
		તોડો;
	સ્થિતિ SSH_ERR_INTERNAL_ERROR:
	સ્થિતિ SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	સ્થિતિ SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		જો (errno == ENOENT)
			તોડો;
		/* FALLTHROUGH */
	મૂળભૂત:
		error_r(r, "load %s \"%s\"", message, path);
		તોડો;
	}
	જો (k != ખાલી && *k == ખાલી)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
સ્થિર શૂન્ય
process_config_files(અચલ અક્ષર *host_name, સંરચના passwd *pw,
    પૂર્ણાંક final_pass, પૂર્ણાંક *want_final_pass)
{
	અક્ષર *cmd, buf[PATH_MAX];
	પૂર્ણાંક r;

	જો ((cmd = sshbuf_dup_string(command)) == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	જો (config != ખાલી) {
		જો (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} નહીંતર {
		r = snprintf(buf, કદ buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		જો (r > 0 && (size_t)r < કદ(buf))
			(શૂન્ય)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(શૂન્ય)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	મુક્ત(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
સ્થિર શૂન્ય
set_addrinfo_port(સંરચના addrinfo *addrs, પૂર્ણાંક port)
{
	સંરચના addrinfo *addr;

	માટે (addr = addrs; addr != ખાલી; addr = addr->ai_next) {
		પસંદગી (addr->ai_family) {
		સ્થિતિ AF_INET:
			((સંરચના sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			તોડો;
		સ્થિતિ AF_INET6:
			((સંરચના sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			તોડો;
		}
	}
}

/*
 * Main program for the ssh client.
 */
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક ac, અક્ષર **av)
{
	સંરચના ssh *ssh = ખાલી;
	પૂર્ણાંક i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	પૂર્ણાંક was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	પૂર્ણાંક user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	અક્ષર *p, *cp, *લીટી, *argv0, *logfile, *args;
	અક્ષર cname[NI_MAXHOST], thishost[NI_MAXHOST];
	સંરચના stat st;
	સંરચના passwd *pw;
	બાહ્ય પૂર્ણાંક optind, optreset;
	બાહ્ય અક્ષર *optarg;
	સંરચના Forward fwd;
	સંરચના addrinfo *addrs = ખાલી;
	size_t n, len;
	u_int j;
	સંરચના utsname utsname;
	સંરચના ssh_conn_info *cinfo = ખાલી;

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
	saved_av = xcalloc(ac + 1, કદ(*saved_av));
	માટે (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = ખાલી;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	જો (!pw) {
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
	જો ((ssh = ssh_alloc_session_state()) == ખાલી)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = ખાલી;
	use_syslog = 0;
	logfile = ખાલી;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	જ્યારે ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		પસંદગી (opt) {
		સ્થિતિ '1':
			fatal("SSH protocol v.1 is no longer supported");
			તોડો;
		સ્થિતિ '2':
			/* Ignored */
			તોડો;
		સ્થિતિ '4':
			options.address_family = AF_INET;
			તોડો;
		સ્થિતિ '6':
			options.address_family = AF_INET6;
			તોડો;
		સ્થિતિ 'n':
			options.stdin_null = 1;
			તોડો;
		સ્થિતિ 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			તોડો;
		સ્થિતિ 'x':
			options.forward_x11 = 0;
			તોડો;
		સ્થિતિ 'X':
			options.forward_x11 = 1;
			તોડો;
		સ્થિતિ 'y':
			use_syslog = 1;
			તોડો;
		સ્થિતિ 'E':
			logfile = optarg;
			તોડો;
		સ્થિતિ 'G':
			config_test = 1;
			તોડો;
		સ્થિતિ 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			તોડો;
		સ્થિતિ 'Z':
			dump_pubkeys = 1;
			તોડો;
		સ્થિતિ 'g':
			options.fwd_opts.gateway_ports = 1;
			તોડો;
		સ્થિતિ 'O':
			જો (options.stdio_forward_host != ખાલી)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			નહીંતર જો (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			જો (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			નહીંતર જો (strcmp(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			નહીંતર જો (strcmp(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			નહીંતર જો (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			નહીંતર જો (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			નહીંતર જો (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			નહીંતર જો (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			નહીંતર જો (strcmp(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			નહીંતર
				fatal("Invalid multiplex command.");
			તોડો;
		સ્થિતિ 'P':
			જો (options.tag == ખાલી)
				options.tag = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'Q':
			cp = ખાલી;
			જો (strcmp(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			નહીંતર જો (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			નહીંતર જો (strcmp(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			નહીંતર જો (strcmp(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			નહીંતર જો (strcmp(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			નહીંતર જો (strcmp(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			નહીંતર જો (strcmp(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			નહીંતર જો (strcmp(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			નહીંતર જો (strcmp(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			નહીંતર જો (strcmp(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			નહીંતર જો (strcmp(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			નહીંતર જો (strcmp(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = strlen(cp);
				માટે (n = 0; n < len; n++)
					જો (cp[n] == ',')
						cp[n] = '\n';
			} નહીંતર જો (strcmp(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			જો (cp == ખાલી)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			મુક્ત(cp);
			exit(0);
			તોડો;
		સ્થિતિ 'a':
			options.forward_agent = 0;
			તોડો;
		સ્થિતિ 'A':
			options.forward_agent = 1;
			તોડો;
		સ્થિતિ 'k':
			options.gss_deleg_creds = 0;
			તોડો;
		સ્થિતિ 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			તોડો;
		સ્થિતિ 'i':
			p = tilde_expand_filename(optarg, getuid());
			જો (stat(p, &st) == -1)
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    strerror(errno));
			નહીંતર
				add_identity_file(&options, ખાલી, p, 1);
			મુક્ત(p);
			તોડો;
		સ્થિતિ 'I':
#ifdef ENABLE_PKCS11
			મુક્ત(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#નહીંતર
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			તોડો;
		સ્થિતિ 'J':
			જો (options.jump_host != ખાલી) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			જો (options.proxy_command != ખાલી)
				fatal("Cannot specify -J with ProxyCommand");
			જો (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			તોડો;
		સ્થિતિ 't':
			જો (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			નહીંતર
				options.request_tty = REQUEST_TTY_YES;
			તોડો;
		સ્થિતિ 'v':
			જો (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} નહીંતર {
				જો (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			તોડો;
		સ્થિતિ 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			exit(0);
			તોડો;
		સ્થિતિ 'w':
			જો (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			જો (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			તોડો;
		સ્થિતિ 'W':
			જો (options.stdio_forward_host != ખાલી)
				fatal("stdio forward already specified");
			જો (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			જો (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				મુક્ત(fwd.connect_host);
			} નહીંતર {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			તોડો;
		સ્થિતિ 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			તોડો;
		સ્થિતિ 'e':
			જો (strlen(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			નહીંતર જો (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			નહીંતર જો (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			નહીંતર {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			તોડો;
		સ્થિતિ 'c':
			જો (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			મુક્ત(options.ciphers);
			options.ciphers = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'm':
			જો (mac_valid(optarg)) {
				મુક્ત(options.macs);
				options.macs = xstrdup(optarg);
			} નહીંતર {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			તોડો;
		સ્થિતિ 'M':
			જો (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			નહીંતર
				options.control_master = SSHCTL_MASTER_YES;
			તોડો;
		સ્થિતિ 'p':
			જો (options.port == -1) {
				options.port = a2port(optarg);
				જો (options.port <= 0) {
					fprintf(stderr, "Bad port '%s'\n",
					    optarg);
					exit(255);
				}
			}
			તોડો;
		સ્થિતિ 'l':
			જો (options.user == ખાલી) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			તોડો;

		સ્થિતિ 'L':
			જો (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			નહીંતર {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			તોડો;

		સ્થિતિ 'R':
			જો (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} નહીંતર {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			તોડો;

		સ્થિતિ 'D':
			જો (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} નહીંતર {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			તોડો;

		સ્થિતિ 'C':
#ifdef WITH_ZLIB
			options.compression = 1;
#નહીંતર
			error("Compression not supported, disabling.");
#endif
			તોડો;
		સ્થિતિ 'N':
			જો (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			તોડો;
		સ્થિતિ 'T':
			options.request_tty = REQUEST_TTY_NO;
			તોડો;
		સ્થિતિ 'o':
			લીટી = xstrdup(optarg);
			જો (process_config_લીટી(&options, pw,
			    host ? host : "", host ? host : "", "", લીટી,
			    "command-line", 0, ખાલી, SSHCONF_USERCONF) != 0)
				exit(255);
			મુક્ત(લીટી);
			તોડો;
		સ્થિતિ 's':
			જો (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			તોડો;
		સ્થિતિ 'S':
			મુક્ત(options.control_path);
			options.control_path = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'b':
			options.bind_address = optarg;
			તોડો;
		સ્થિતિ 'B':
			options.bind_interface = optarg;
			તોડો;
		સ્થિતિ 'F':
			config = optarg;
			તોડો;
		મૂળભૂત:
			usage();
		}
	}

	જો (optind > 1 && strcmp(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	જો (ac > 0 && !host) {
		પૂર્ણાંક tport;
		અક્ષર *tuser;
		પસંદગી (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		સ્થિતિ -1:
			usage();
			તોડો;
		સ્થિતિ 0:
			જો (options.user == ખાલી) {
				options.user = tuser;
				tuser = ખાલી;
				user_on_commandline = 1;
			}
			મુક્ત(tuser);
			જો (options.port == -1 && tport != -1)
				options.port = tport;
			તોડો;
		મૂળભૂત:
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			જો (cp != ખાલી) {
				જો (cp == p)
					usage();
				જો (options.user == ખાલી) {
					options.user = p;
					p = ખાલી;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				મુક્ત(p);
			} નહીંતર
				host = p;
			તોડો;
		}
		જો (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			જાઓ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	જો (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	જો (options.user != ખાલી && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	જો (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	જો ((command = sshbuf_new()) == ખાલી)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	જો (!ac) {
		/* No command specified - execute shell on a tty. */
		જો (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} નહીંતર {
		/* A command has been specified.  Store it into the buffer. */
		માટે (i = 0; i < ac; i++) {
			જો ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	જો (use_syslog && logfile != ખાલી)
		fatal("Can't specify both -y and -E");
	જો (logfile != ખાલી)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	જો (uname(&utsname) != 0) {
		memset(&utsname, 0, કદ(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", કદ(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	મુક્ત(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	જો (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	જો (options.hostname != ખાલી) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (અક્ષર *)ખાલી);
		મુક્ત(host);
		host = cp;
		મુક્ત(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	જો ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	જો (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	જો (addrs == ખાલી && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		જો ((addrs = resolve_host(host, options.port,
		    direct, cname, કદ(cname))) == ખાલી) {
			/* Don't fatal proxied host names not in the DNS */
			જો (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} નહીંતર
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	જો (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	જો (want_final_pass) {
		debug("re-parsing configuration");
		મુક્ત(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, ખાલી);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		જો (addrs != ખાલી && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	જો (fill_default_options(&options) != 0)
		cleanup_exit(255);

	જો (options.user == ખાલી) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	જો (options.jump_host != ખાલી) {
		અક્ષર port_s[8];
		અચલ અક્ષર *jumpuser = options.jump_user, *sshbin = argv0;
		પૂર્ણાંક port = options.port, jumpport = options.jump_port;

		જો (port <= 0)
			port = default_ssh_port();
		જો (jumpport <= 0)
			jumpport = default_ssh_port();
		જો (jumpuser == ખાલી)
			jumpuser = options.user;
		જો (strcmp(options.jump_host, host) == 0 && port == jumpport &&
		    strcmp(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		જો (strchr(argv0, '/') != ખાલી && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		જો (options.proxy_command != ખાલી &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, કદ(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == ખાલી ? "" : " -l ",
		    options.jump_user == ખાલી ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == ખાલી ? "" : " -J ",
		    options.jump_extra == ખાલી ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == ખાલી ? "" : " -F ",
		    config == ખાલી ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	જો (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	જો (options.host_ચાવી_alias != ખાલી)
		lowercase(options.host_ચાવી_alias);
	જો (options.proxy_command != ખાલી &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	જો (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		જો (options.control_persist && options.control_path != ખાલી) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} નહીંતર જો (sshbuf_len(command) != 0 ||
		    options.remote_command != ખાલી ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} નહીંતર જો (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	જો (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	જો (sshbuf_len(command) != 0 && options.remote_command != ખાલી)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	જો (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == ખાલી &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	માટે (j = 0; j < options.અંક_log_verbose; j++) {
		જો (strcasecmp(options.log_verbose[j], "none") == 0)
			તોડો;
		log_verbose_add(options.log_verbose[j]);
	}

	જો (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	જો (sshbuf_len(command) == 0 && options.remote_command == ખાલી)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	જો (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	જો ((!isatty(fileno(stdin)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		જો (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, કદ(*cinfo));
	જો (gethostname(thishost, કદ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	cinfo->thishost = xstrdup(thishost);
	thishost[strcspn(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (unsigned long long)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_ચાવી_alias ?
	    options.host_ચાવી_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == ખાલી ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	જો (!user_on_commandline && !user_was_default) {
		જો ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (અક્ષર *)ખાલી)) == ખાલી)
			fatal("invalid environment variable expansion");
		user_expanded = strcmp(p, options.user) != 0;
		મુક્ત(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	જો ((user_on_commandline || user_expanded) &&
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
	જો (options.remote_command != ખાલી) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		મુક્ત(cp);
		જો ((r = sshbuf_put(command, options.remote_command,
		    strlen(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	જો (options.control_path != ખાલી) {
		cp = tilde_expand_filename(options.control_path, getuid());
		મુક્ત(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		મુક્ત(cp);
	}

	જો (options.identity_agent != ખાલી) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		મુક્ત(p);
		મુક્ત(options.identity_agent);
		options.identity_agent = cp;
	}

	માટે (j = 0; j < options.અંક_revoked_host_ચાવીઓ; j++) {
		p = tilde_expand_filename(options.revoked_host_ચાવીઓ[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		મુક્ત(p);
		મુક્ત(options.revoked_host_ચાવીઓ[j]);
		options.revoked_host_ચાવીઓ[j] = cp;
	}

	જો (options.forward_agent_sock_path != ખાલી) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		મુક્ત(p);
		મુક્ત(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		જો (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, strerror(errno));
			જો (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	જો (options.version_addendum != ખાલી) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		મુક્ત(options.version_addendum);
		options.version_addendum = cp;
	}

	જો (options.અંક_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		જો (options.અંક_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		મુક્ત(options.system_hostfiles[0]);
		options.system_hostfiles[0] = ખાલી;
		options.અંક_system_hostfiles = 0;
	}

	જો (options.અંક_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		જો (options.અંક_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		મુક્ત(options.user_hostfiles[0]);
		options.user_hostfiles[0] = ખાલી;
		options.અંક_user_hostfiles = 0;
	}
	માટે (j = 0; j < options.અંક_user_hostfiles; j++) {
		જો (options.user_hostfiles[j] == ખાલી)
			ચાલુ;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		જો (strcmp(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		મુક્ત(options.user_hostfiles[j]);
		મુક્ત(cp);
		options.user_hostfiles[j] = p;
	}

	માટે (j = 0; j < options.અંક_setenv; j++) {
		અક્ષર *name = options.setenv[j], *કિંમત;

		જો (name == ખાલી)
			ચાલુ;
		/* Expand only the value portion, not the variable name. */
		જો ((કિંમત = strchr(name, '=')) == ખાલી) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*કિંમત++ = '\0';
		cp = default_client_percent_dollar_expand(કિંમત, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		જો (strcmp(કિંમત, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, કિંમત, cp);
		}
		મુક્ત(options.setenv[j]);
		મુક્ત(cp);
		options.setenv[j] = p;
	}

	માટે (i = 0; i < options.અંક_local_forwards; i++) {
		જો (options.local_forwards[i].listen_path != ખાલી) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			જો (strcmp(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			મુક્ત(cp);
		}
		જો (options.local_forwards[i].connect_path != ખાલી) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			જો (strcmp(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			મુક્ત(cp);
		}
	}

	માટે (i = 0; i < options.અંક_remote_forwards; i++) {
		જો (options.remote_forwards[i].listen_path != ખાલી) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			જો (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			મુક્ત(cp);
		}
		જો (options.remote_forwards[i].connect_path != ખાલી) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			જો (strcmp(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			મુક્ત(cp);
		}
	}

	જો (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	જો (options.sk_provider != ખાલી && *options.sk_provider == '$' &&
	    strlen(options.sk_provider) > 1) {
		જો ((cp = getenv(options.sk_provider + 1)) == ખાલી) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			મુક્ત(options.sk_provider);
			options.sk_provider = ખાલી;
		} નહીંતર {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			મુક્ત(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	જો (muxclient_command != 0 && options.control_path == ખાલી)
		fatal("No ControlPath specified for \"-O\" command");
	જો (options.control_path != ખાલી) {
		પૂર્ણાંક sock;
		જો ((sock = muxclient(options.control_path)) >= 0) {
			જો (ssh_packet_set_connection(ssh, sock, sock) == ખાલી)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			જાઓ skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	જો (options.identity_agent &&
	    strcmp(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		જો (strcmp(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} નહીંતર {
			cp = options.identity_agent;
			/* legacy (limited) format */
			જો (cp[0] == '$' && cp[1] != '{') {
				જો (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				જો ((p = getenv(cp + 1)) == ખાલી)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				નહીંતર
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} નહીંતર {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	જો (dump_pubkeys) {
		pubkey_dump(ssh);
		exit(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	જો (addrs == ખાલી && options.proxy_command == ખાલી) {
		debug2("resolving \"%s\" port %d", host, options.port);
		જો ((addrs = resolve_host(host, options.port, 1,
		    cname, કદ(cname))) == ખાલી)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	જો (options.connection_timeout >= INT_MAX/1000)
		timeout_ms = INT_MAX;
	નહીંતર
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	માટે (j = 0; j < options.અંક_channel_timeouts; j++) {
		દ્વિગુણ timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		જો (parse_pattern_interval(options.channel_timeouts[j],
		    &cp, &timeout) != 0) {
			fatal_f("internal error: bad timeout %s",
			    options.channel_timeouts[j]);
		}
		channel_add_timeout(ssh, cp, timeout);
		મુક્ત(cp);
	}
	channel_set_tcp_keepalives(ssh,
	    options.tcp_keep_alive == SSH_KEEPALIVES_ALL);

	/* Open a connection to the remote host. */
	જો (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		exit(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_ગણતરી_max);

	જો (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.ચાવીઓ = ખાલી;
	જો (options.hostbased_authentication) {
		પૂર્ણાંક loaded = 0;

		sensitive_data.nkeys = 10;
		sensitive_data.ચાવીઓ = xcalloc(sensitive_data.nkeys,
		    કદ(*sensitive_data.ચાવીઓ));

		/* XXX check errors? */
#define L_PUBKEY(p,o) કરો { \
	જો ((o) >= sensitive_data.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_data.ચાવીઓ[o]), ખાલી), \
	    &(sensitive_data.ચાવીઓ[o]), p, "hostbased pubkey"); \
	જો (sensitive_data.ચાવીઓ[o] != ખાલી) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} જ્યારે (0)
#define L_CERT(p,o) કરો { \
	જો ((o) >= sensitive_data.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_data.ચાવીઓ[o])), \
	    &(sensitive_data.ચાવીઓ[o]), p, "hostbased cert"); \
	જો (sensitive_data.ચાવીઓ[o] != ખાલી) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} જ્યારે (0)

		જો (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_ચાવી_FILE, 0);
			L_CERT(PATH_HOST_ED25519_ચાવી_FILE, 1);
			L_CERT(PATH_HOST_RSA_ચાવી_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_ચાવી_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_ચાવી_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_ચાવી_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_ચાવી_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_ચાવી_FILE, 7);
			જો (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	જો (options.forward_agent && options.forward_agent_sock_path != ખાલી) {
		cp = options.forward_agent_sock_path;
		જો (cp[0] == '$') {
			જો (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			જો ((p = getenv(cp + 1)) != ખાલી)
				forward_agent_sock_path = xstrdup(p);
			નહીંતર
				options.forward_agent = 0;
			મુક્ત(cp);
		} નહીંતર {
			forward_agent_sock_path = cp;
		}
	}

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.અંક_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.અંક_user_hostfiles);

	ssh_signal(SIGCHLD, main_sigchld_handler);

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(ssh, &sensitive_data, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	જો (sensitive_data.nkeys != 0) {
		માટે (i = 0; i < sensitive_data.nkeys; i++) {
			જો (sensitive_data.ચાવીઓ[i] != ખાલી) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_data.ચાવીઓ[i]);
				sensitive_data.ચાવીઓ[i] = ખાલી;
			}
		}
		મુક્ત(sensitive_data.ચાવીઓ);
	}
	માટે (i = 0; i < options.અંક_identity_files; i++) {
		મુક્ત(options.identity_files[i]);
		options.identity_files[i] = ખાલી;
		જો (options.identity_ચાવીઓ[i]) {
			sshkey_free(options.identity_ચાવીઓ[i]);
			options.identity_ચાવીઓ[i] = ખાલી;
		}
	}
	માટે (i = 0; i < options.અંક_certificate_files; i++) {
		મુક્ત(options.certificate_files[i]);
		options.certificate_files[i] = ખાલી;
	}

#ifdef ENABLE_PKCS11
	(શૂન્ય)pkcs11_del_provider(options.pkcs11_provider);
#endif

 skip_connect:
	જો (addrs != ખાલી)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	જો (options.control_path != ખાલી && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	પાછા exit_status;
}

સ્થિર શૂન્ય
control_persist_detach(શૂન્ય)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	પસંદગી ((pid = fork())) {
	સ્થિતિ -1:
		fatal_f("fork: %s", strerror(errno));
	સ્થિતિ 0:
		/* Child: master process continues mainloop */
		તોડો;
	મૂળભૂત:
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
		(શૂન્ય)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	જો (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
સ્થિર શૂન્ય
fork_postauth(શૂન્ય)
{
	જો (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	જો (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", strerror(errno));
	જો (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

સ્થિર શૂન્ય
forwarding_success(શૂન્ય)
{
	જો (forward_confirms_pending == -1)
		પાછા;
	જો (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		જો (options.fork_after_authentication)
			fork_postauth();
	} નહીંતર {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

સંરચના rfwd_confirm_ctx {
	પૂર્ણાંક fid;
};

/* Callback for remote forward global requests */
સ્થિર શૂન્ય
ssh_confirm_remote_forward(સંરચના ssh *ssh, પૂર્ણાંક type, uint32_t seq, શૂન્ય *ctxt)
{
	સંરચના rfwd_confirm_ctx *rctx = (સંરચના rfwd_confirm_ctx *)ctxt;
	સંરચના Forward *rfwd;
	u_int port;
	પૂર્ણાંક r;

	જો (rctx->fid < 0 || rctx->fid >= options.અંક_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, કદ(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_સંદેશ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	જો (rfwd->listen_path == ખાલી && rfwd->listen_port == 0) {
		જો (type == SSH2_સંદેશ_REQUEST_SUCCESS) {
			જો ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			જો (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_સંદેશ_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} નહીંતર {
				rfwd->allocated_port = (પૂર્ણાંક)port;
				logit("Allocated port %u for remote "
				    "forward to %s:%d",
				    rfwd->allocated_port, rfwd->connect_path ?
				    rfwd->connect_path : rfwd->connect_host,
				    rfwd->connect_port);
				channel_update_permission(ssh,
				    rfwd->handle, rfwd->allocated_port);
			}
		} નહીંતર {
			channel_update_permission(ssh, rfwd->handle, -1);
		}
	}

	જો (type == SSH2_સંદેશ_REQUEST_FAILURE) {
		જો (options.exit_on_forward_failure) {
			જો (rfwd->listen_path != ખાલી)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			નહીંતર
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} નહીંતર {
			જો (rfwd->listen_path != ખાલી)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			નહીંતર
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

સ્થિર શૂન્ય
client_cleanup_stdio_fwd(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક force, શૂન્ય *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

સ્થિર શૂન્ય
ssh_stdio_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક success, શૂન્ય *arg)
{
	જો (!success)
		fatal("stdio forwarding failed");
}

સ્થિર શૂન્ય
ssh_tun_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક success, શૂન્ય *arg)
{
	જો (!success) {
		error("Tunnel forwarding failed");
		જો (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

સ્થિર શૂન્ય
ssh_init_stdio_forwarding(સંરચના ssh *ssh)
{
	Channel *c;
	પૂર્ણાંક in, out;

	જો (options.stdio_forward_host == ખાલી)
		પાછા;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	જો ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	જો ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == ખાલી)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, ખાલી);
}

સ્થિર શૂન્ય
ssh_init_forward_permissions(સંરચના ssh *ssh, અચલ અક્ષર *what, અક્ષર **opens,
    u_int અંક_opens)
{
	u_int i;
	પૂર્ણાંક port;
	અક્ષર *addr, *arg, *oarg;
	પૂર્ણાંક where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	જો (અંક_opens == 0)
		પાછા; /* permit any */

	/* handle keywords: "any" / "none" */
	જો (અંક_opens == 1 && strcmp(opens[0], "any") == 0)
		પાછા;
	જો (અંક_opens == 1 && strcmp(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		પાછા;
	}
	/* Otherwise treat it as a list of permitted host:port */
	માટે (i = 0; i < અંક_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		જો (addr == ખાલી)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		જો (arg == ખાલી || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		મુક્ત(oarg);
	}
}

સ્થિર શૂન્ય
ssh_init_forwarding(સંરચના ssh *ssh, અક્ષર **ifname)
{
	પૂર્ણાંક success = 0;
	પૂર્ણાંક i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.અંક_permitted_remote_opens);

	જો (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	માટે (i = 0; i < options.અંક_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != ખાલી) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == ખાલી) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != ખાલી) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	જો (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	જો (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	માટે (i = 0; i < options.અંક_remote_forwards; i++) {
		સંરચના rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != ખાલી) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == ખાલી) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != ખાલી) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		જો ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, કદ(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} નહીંતર જો (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		નહીંતર
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	જો (options.tun_open != SSH_TUNMODE_NO) {
		જો ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, ખાલી)) != ખાલી)
			forward_confirms_pending++;
		નહીંતર જો (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		નહીંતર
			error("Could not request tunnel forwarding.");
	}
	જો (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

સ્થિર શૂન્ય
check_agent_present(શૂન્ય)
{
	પૂર્ણાંક r;

	જો (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		જો ((r = ssh_get_authentication_socket(ખાલી)) != 0) {
			options.forward_agent = 0;
			જો (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

સ્થિર શૂન્ય
ssh_session2_setup(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક success, શૂન્ય *arg)
{
	બાહ્ય અક્ષર **environ;
	અચલ અક્ષર *display, *term;
	અક્ષર *proto = ખાલી, *data = ખાલી;

	જો (!success)
		પાછા; /* No need for error message, channels code sends one */

	display = getenv("DISPLAY");
	જો (display == ખાલી && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	જો (options.forward_x11 && client_x11_get_proto(ssh, display,
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
	જો (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	જો ((term = lookup_env_in_list("TERM", options.setenv,
	    options.અંક_setenv)) == ખાલી || *term == '\0')
		term = getenv("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    ખાલી, fileno(stdin), command, environ);
}

/* open new channel for a session */
સ્થિર પૂર્ણાંક
ssh_session2_open(સંરચના ssh *ssh)
{
	Channel *c;
	પૂર્ણાંક window, packetmax, in, out, err;

	જો (options.stdin_null) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} નહીંતર {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	જો (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	જો (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	જો (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	જો (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, ખાલી);

	પાછા c->self;
}

સ્થિર પૂર્ણાંક
ssh_session2(સંરચના ssh *ssh, અચલ સંરચના ssh_conn_info *cinfo)
{
	પૂર્ણાંક r, id = -1;
	અક્ષર *cp, *tun_fwd_ifname = ખાલી;

	/* XXX should be pre-session */
	જો (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	જો (options.local_command != ખાલી) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == ખાલી ? "NONE" : tun_fwd_ifname,
		    (અક્ષર *)ખાલી);
		debug3("expanded LocalCommand: %s", options.local_command);
		મુક્ત(cp);
	}

	/* Start listening for multiplex clients */
	જો (!ssh_packet_get_mux(ssh))
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
	જો (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		જો ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != ખાલી))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	જો (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	જો (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	જો (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	જો (options.local_command != ખાલી &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	જો (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	જો (options.fork_after_authentication) {
		જો (options.exit_on_forward_failure &&
		    options.અંક_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} નહીંતર
			fork_postauth();
	}

	પાછા client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
સ્થિર શૂન્ય
load_public_identity_files(અચલ સંરચના ssh_conn_info *cinfo)
{
	અક્ષર *filename, *cp;
	સંરચના sshkey *જાહેર;
	પૂર્ણાંક i;
	u_int n_ids, n_certs;
	અક્ષર *identity_files[SSH_MAX_IDENTITY_FILES];
	સંરચના sshkey *identity_ચાવીઓ[SSH_MAX_IDENTITY_FILES];
	પૂર્ણાંક identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	અક્ષર *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	સંરચના sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	પૂર્ણાંક certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#ifdef ENABLE_PKCS11
	સંરચના sshkey **ચાવીઓ = ખાલી;
	અક્ષર **comments = ખાલી;
	પૂર્ણાંક nkeys;
#endif /* PKCS11 */

	n_ids = n_certs = 0;
	memset(identity_files, 0, કદ(identity_files));
	memset(identity_ચાવીઓ, 0, કદ(identity_ચાવીઓ));
	memset(identity_file_userprovided, 0,
	    કદ(identity_file_userprovided));
	memset(certificate_files, 0, કદ(certificate_files));
	memset(certificates, 0, કદ(certificates));
	memset(certificate_file_userprovided, 0,
	    કદ(certificate_file_userprovided));

#ifdef ENABLE_PKCS11
	જો (options.pkcs11_provider != ખાલી &&
	    options.અંક_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, ખાલી,
	    &ચાવીઓ, &comments)) > 0) {
		માટે (i = 0; i < nkeys; i++) {
			જો (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(ચાવીઓ[i]);
				મુક્ત(comments[i]);
				ચાલુ;
			}
			identity_ચાવીઓ[n_ids] = ચાવીઓ[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		મુક્ત(ચાવીઓ);
		મુક્ત(comments);
	}
#endif /* ENABLE_PKCS11 */
	માટે (i = 0; i < options.અંક_identity_files; i++) {
		જો (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			મુક્ત(options.identity_files[i]);
			options.identity_files[i] = ખાલી;
			ચાલુ;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		મુક્ત(cp);
		check_load(sshkey_load_public(filename, &જાહેર, ખાલી),
		    &જાહેર, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    જાહેર ? જાહેર->type : -1);
		મુક્ત(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_ચાવીઓ[n_ids] = જાહેર;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		જો (++n_ids >= SSH_MAX_IDENTITY_FILES)
			ચાલુ;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		જો (options.અંક_certificate_files != 0)
			ચાલુ;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &જાહેર, ખાલી),
		    &જાહેર, filename, "identity pubkey");
		જો (જાહેર == ખાલી) {
			મુક્ત(cp);
			ચાલુ;
		}
		જો (!sshkey_is_cert(જાહેર)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(જાહેર));
			sshkey_free(જાહેર);
			મુક્ત(cp);
			ચાલુ;
		}
		મુક્ત(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_ચાવીઓ[n_ids] = જાહેર;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	જો (options.અંક_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	માટે (i = 0; i < options.અંક_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		મુક્ત(cp);

		check_load(sshkey_load_public(filename, &જાહેર, ખાલી),
		    &જાહેર, filename, "identity cert");
		મુક્ત(options.certificate_files[i]);
		options.certificate_files[i] = ખાલી;
		જો (જાહેર == ખાલી) {
			મુક્ત(filename);
			ચાલુ;
		}
		જો (!sshkey_is_cert(જાહેર)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(જાહેર));
			sshkey_free(જાહેર);
			મુક્ત(filename);
			ચાલુ;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = જાહેર;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.અંક_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, કદ(identity_files));
	memcpy(options.identity_ચાવીઓ, identity_ચાવીઓ, કદ(identity_ચાવીઓ));
	memcpy(options.identity_file_userprovided,
	    identity_file_userprovided, કદ(identity_file_userprovided));

	options.અંક_certificate_files = n_certs;
	memcpy(options.certificate_files,
	    certificate_files, કદ(certificate_files));
	memcpy(options.certificates, certificates, કદ(certificates));
	memcpy(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    કદ(certificate_file_userprovided));
}

સ્થિર શૂન્ય
main_sigchld_handler(પૂર્ણાંક sig)
{
	પૂર્ણાંક save_errno = errno;
	pid_t pid;
	પૂર્ણાંક status;

	જ્યારે ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}
