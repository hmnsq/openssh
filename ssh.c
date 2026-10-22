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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/stat.h>
#समावेश <sys/wait.h>
#समावेश <sys/utsname.h>

#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stddef.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <locale.h>

#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/evp.h>
#समावेश <openssl/err.h>
#पूर्ण_अगर
#समावेश "openbsd-compat/openssl-compat.h"

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "compat.h"
#समावेश "cipher.h"
#समावेश "packet.h"
#समावेश "sshbuf.h"
#समावेश "channels.h"
#समावेश "sshkey.h"
#समावेश "authfd.h"
#समावेश "authfile.h"
#समावेश "pathnames.h"
#समावेश "clientloop.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "readconf.h"
#समावेश "sshconnect.h"
#समावेश "kex.h"
#समावेश "mac.h"
#समावेश "match.h"
#समावेश "version.h"
#समावेश "ssherr.h"
#समावेश "utf8.h"

#अगर_घोषित ENABLE_PKCS11
#समावेश "ssh-pkcs11.h"
#पूर्ण_अगर

बाह्य अक्षर *__progname;

/* Saves a copy of argv for setproctitle emulation */
#अगर_अघोषित HAVE_SETPROCTITLE
अटल अक्षर **saved_av;
#पूर्ण_अगर

/* Flag indicating whether debug mode is on.  May be set on the command line. */
पूर्णांक debug_flag = 0;

/* Flag indicating whether a tty should be requested */
पूर्णांक tty_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new mux-client launched in the foreground for ControlPersist.
 */
अटल पूर्णांक need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground mux-client */
अटल पूर्णांक ostdin_null_flag, osession_type, otty_flag, orequest_tty;
अटल पूर्णांक ofork_after_authentication;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
अक्षर *config = शून्य;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the Hostname specified for the user-supplied name in a
 * configuration file.
 */
अक्षर *host;

/*
 * A config can specify a path to forward, overriding SSH_AUTH_SOCK. If this is
 * not NULL, forward the socket at this path instead.
 */
अक्षर *forward_agent_sock_path = शून्य;

/* socket address the host resolves to */
काष्ठा sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_तथ्य;

/* command to be executed */
काष्ठा sshbuf *command;

/* # of replies received for global requests */
अटल पूर्णांक forward_confirms_pending = -1;

/* mux.c */
बाह्य पूर्णांक muxserver_sock;
बाह्य u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि,
"usage: ssh [-46AaCfGgKkMNnqsTtVvXxYyZ] [-B bind_interface] [-b bind_address]\n"
"           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n"
"           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n"
"           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n"
"           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n"
"           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n"
"           destination [command [argument ...]]\n"
"       ssh [-Q query_option]\n"
	);
	निकास(255);
}

अटल पूर्णांक ssh_session2(काष्ठा ssh *, स्थिर काष्ठा ssh_conn_info *);
अटल व्योम load_public_identity_files(स्थिर काष्ठा ssh_conn_info *);
अटल व्योम main_sigchld_handler(पूर्णांक);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
अटल व्योम
tilde_expand_paths(अक्षर **paths, u_int अंक_paths)
{
	u_int i;
	अक्षर *cp;

	क्रम (i = 0; i < अंक_paths; i++) {
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
अटल अक्षर *
default_client_percent_expand(स्थिर अक्षर *str,
    स्थिर काष्ठा ssh_conn_info *cinfo)
{
	वापस percent_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (अक्षर *)शून्य);
}

/*
 * Expands the set of percent_expand options used by the majority of keywords
 * AND perform environment variable substitution.
 * Caller must free returned string.
 */
अटल अक्षर *
default_client_percent_dollar_expand(स्थिर अक्षर *str,
    स्थिर काष्ठा ssh_conn_info *cinfo)
{
	अक्षर *ret;

	ret = percent_dollar_expand(str,
	    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
	    (अक्षर *)शून्य);
	अगर (ret == शून्य)
		fatal("invalid environment variable expansion");
	वापस ret;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
अटल काष्ठा addrinfo *
resolve_host(स्थिर अक्षर *name, पूर्णांक port, पूर्णांक logerr, अक्षर *cname, माप_प्रकार clen)
{
	अक्षर strport[NI_MAXSERV];
	स्थिर अक्षर *errstr = शून्य;
	काष्ठा addrinfo hints, *res;
	पूर्णांक gaierr;
	LogLevel loglevel = SYSLOG_LEVEL_DEBUG1;

	अगर (port <= 0)
		port = default_ssh_port();
	अगर (cname != शून्य)
		*cname = '\0';
	debug3_f("lookup %s:%d", name, port);

	snprintf(strport, माप strport, "%d", port);
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	अगर (cname != शून्य)
		hints.ai_flags = AI_CANONNAME;
	अगर ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		अगर (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		वापस शून्य;
	}
	अगर (cname != शून्य && res->ai_canonname != शून्य) {
		अगर (!valid_domain(res->ai_canonname, 0, &errstr)) {
			error("ignoring bad CNAME \"%s\" for host \"%s\": %s",
			    res->ai_canonname, name, errstr);
		} अन्यथा अगर (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error_f("host \"%s\" cname \"%s\" too long (max %lu)",
			    name,  res->ai_canonname, (u_long)clen);
			अगर (clen > 0)
				*cname = '\0';
		}
	}
	वापस res;
}

/* Returns non-zero if name can only be an address and not a hostname */
अटल पूर्णांक
is_addr_fast(स्थिर अक्षर *name)
{
	वापस (म_अक्षर(name, '%') != शून्य || म_अक्षर(name, ':') != शून्य ||
	    म_अखोज(name, "0123456789.") == म_माप(name));
}

/* Returns non-zero if name represents a valid, single address */
अटल पूर्णांक
is_addr(स्थिर अक्षर *name)
{
	अक्षर strport[NI_MAXSERV];
	काष्ठा addrinfo hints, *res;

	अगर (is_addr_fast(name))
		वापस 1;

	snprintf(strport, माप strport, "%u", default_ssh_port());
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	अगर (getaddrinfo(name, strport, &hints, &res) != 0)
		वापस 0;
	अगर (res == शून्य || res->ai_next != शून्य) {
		freeaddrinfo(res);
		वापस 0;
	}
	freeaddrinfo(res);
	वापस 1;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
अटल काष्ठा addrinfo *
resolve_addr(स्थिर अक्षर *name, पूर्णांक port, अक्षर *caddr, माप_प्रकार clen)
{
	अक्षर addr[NI_MAXHOST], strport[NI_MAXSERV];
	काष्ठा addrinfo hints, *res;
	पूर्णांक gaierr;

	अगर (port <= 0)
		port = default_ssh_port();
	snprintf(strport, माप strport, "%u", port);
	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	अगर ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2_f("could not resolve name %.100s as address: %s",
		    name, ssh_gai_strerror(gaierr));
		वापस शून्य;
	}
	अगर (res == शून्य) {
		debug_f("getaddrinfo %.100s returned no addresses", name);
		वापस शून्य;
	}
	अगर (res->ai_next != शून्य) {
		debug_f("getaddrinfo %.100s returned multiple addresses", name);
		जाओ fail;
	}
	अगर ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, माप(addr), शून्य, 0, NI_NUMERICHOST)) != 0) {
		debug_f("Could not format address for name %.100s: %s",
		    name, ssh_gai_strerror(gaierr));
		जाओ fail;
	}
	अगर (strlcpy(caddr, addr, clen) >= clen) {
		error_f("host \"%s\" addr \"%s\" too long (max %lu)",
		    name,  addr, (u_long)clen);
		अगर (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		वापस शून्य;
	}
	वापस res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
अटल पूर्णांक
check_follow_cname(पूर्णांक direct, अक्षर **namep, स्थिर अक्षर *cname)
{
	पूर्णांक i;
	काष्ठा allowed_cname *rule;

	अगर (*cname == '\0' || !config_has_permitted_cnames(&options) ||
	    म_भेद(*namep, cname) == 0)
		वापस 0;
	अगर (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		वापस 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy or jump host unless the user specifically requests so.
	 */
	अगर (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		वापस 0;
	debug3_f("check \"%s\" CNAME \"%s\"", *namep, cname);
	क्रम (i = 0; i < options.अंक_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		अगर (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			जारी;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		मुक्त(*namep);
		*namep = xstrdup(cname);
		lowercase(*namep);
		वापस 1;
	}
	वापस 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
अटल काष्ठा addrinfo *
resolve_canonicalize(अक्षर **hostp, पूर्णांक port)
{
	पूर्णांक i, direct, ndots;
	अक्षर *cp, *fullhost, newname[NI_MAXHOST];
	काष्ठा addrinfo *addrs;

	/*
	 * Attempt to canonicalise addresses, regardless of
	 * whether hostname canonicalisation was requested
	 */
	अगर ((addrs = resolve_addr(*hostp, port,
	    newname, माप(newname))) != शून्य) {
		debug2_f("hostname %.100s is address", *hostp);
		अगर (strcasecmp(*hostp, newname) != 0) {
			debug2_f("canonicalised address \"%s\" => \"%s\"",
			    *hostp, newname);
			मुक्त(*hostp);
			*hostp = xstrdup(newname);
		}
		वापस addrs;
	}

	/*
	 * If this looks like an address but didn't parse as one, it might
	 * be an address with an invalid interface scope. Skip further
	 * attempts at canonicalisation.
	 */
	अगर (is_addr_fast(*hostp)) {
		debug_f("hostname %.100s is an unrecognised address", *hostp);
		वापस शून्य;
	}

	अगर (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		वापस शून्य;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	direct = option_clear_or_none(options.proxy_command) &&
	    option_clear_or_none(options.jump_host);
	अगर (!direct &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		वापस शून्य;

	/* If domain name is anchored, then resolve it now */
	अगर ((*hostp)[म_माप(*hostp) - 1] == '.') {
		debug3_f("name is fully qualified");
		fullhost = xstrdup(*hostp);
		अगर ((addrs = resolve_host(fullhost, port, 0,
		    newname, माप(newname))) != शून्य)
			जाओ found;
		मुक्त(fullhost);
		जाओ notfound;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	क्रम (cp = *hostp; *cp != '\0'; cp++) {
		अगर (*cp == '.')
			ndots++;
	}
	अगर (ndots > options.canonicalize_max_dots) {
		debug3_f("not canonicalizing hostname \"%s\" (max dots %d)",
		    *hostp, options.canonicalize_max_dots);
		वापस शून्य;
	}
	/* Attempt each supplied suffix */
	क्रम (i = 0; i < options.अंक_canonical_domains; i++) {
		अगर (strcasecmp(options.canonical_domains[i], "none") == 0)
			अवरोध;
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3_f("attempting \"%s\" => \"%s\"", *hostp, fullhost);
		अगर ((addrs = resolve_host(fullhost, port, 0,
		    newname, माप(newname))) == शून्य) {
			मुक्त(fullhost);
			जारी;
		}
 found:
		/* Remove trailing '.' */
		fullhost[म_माप(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		अगर (!check_follow_cname(direct, &fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		मुक्त(*hostp);
		*hostp = fullhost;
		वापस addrs;
	}
 notfound:
	अगर (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2_f("host %s not found in any suffix", *hostp);
	वापस शून्य;
}

/*
 * Check the result of hostkey loading, ignoring some errors and either
 * discarding the key or fatal()ing for others.
 */
अटल व्योम
check_load(पूर्णांक r, काष्ठा sshkey **k, स्थिर अक्षर *path, स्थिर अक्षर *message)
{
	अक्षर *fp;

	चयन (r) {
	हाल 0:
		अगर (k == शून्य || *k == शून्य)
			वापस;
		/* Check RSA keys size and discard if undersized */
		अगर ((r = sshkey_check_rsa_लंबाई(*k,
		    options.required_rsa_आकार)) != 0) {
			error_r(r, "load %s \"%s\"", message, path);
			मुक्त(*k);
			*k = शून्य;
			अवरोध;
		}
		अगर ((fp = sshkey_fingerprint(*k,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == शून्य) {
			fatal_f("failed to fingerprint %s %s key from %s",
			    sshkey_type(*k), message, path);
		}
		debug("loaded %s from %s: %s %s", message, path,
		    sshkey_type(*k), fp);
		मुक्त(fp);
		अवरोध;
	हाल SSH_ERR_INTERNAL_ERROR:
	हाल SSH_ERR_ALLOC_FAIL:
		fatal_r(r, "load %s \"%s\"", message, path);
	हाल SSH_ERR_SYSTEM_ERROR:
		/* Ignore missing files */
		अगर (त्रुटि_सं == ENOENT)
			अवरोध;
		/* FALLTHROUGH */
	शेष:
		error_r(r, "load %s \"%s\"", message, path);
		अवरोध;
	}
	अगर (k != शून्य && *k == शून्य)
		debug("no %s loaded from %s", message, path);
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
अटल व्योम
process_config_files(स्थिर अक्षर *host_name, काष्ठा passwd *pw,
    पूर्णांक final_pass, पूर्णांक *want_final_pass)
{
	अक्षर *cmd, buf[PATH_MAX];
	पूर्णांक r;

	अगर ((cmd = sshbuf_dup_string(command)) == शून्य)
		fatal_f("sshbuf_dup_string failed");
	अगर (config != शून्य) {
		अगर (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_name, cmd,
		    &options,
		    SSHCONF_USERCONF | (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, म_त्रुटि(त्रुटि_सं));
	} अन्यथा {
		r = snprintf(buf, माप buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		अगर (r > 0 && (माप_प्रकार)r < माप(buf))
			(व्योम)read_config_file(buf, pw, host, host_name, cmd,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0), want_final_pass);

		/* Read systemwide configuration file after user config. */
		(व्योम)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_name, cmd, &options,
		    final_pass ? SSHCONF_FINAL : 0, want_final_pass);
	}
	मुक्त(cmd);
}

/* Rewrite the port number in an addrinfo list of addresses */
अटल व्योम
set_addrinfo_port(काष्ठा addrinfo *addrs, पूर्णांक port)
{
	काष्ठा addrinfo *addr;

	क्रम (addr = addrs; addr != शून्य; addr = addr->ai_next) {
		चयन (addr->ai_family) {
		हाल AF_INET:
			((काष्ठा sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			अवरोध;
		हाल AF_INET6:
			((काष्ठा sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			अवरोध;
		}
	}
}

/*
 * Main program for the ssh client.
 */
पूर्णांक
मुख्य(पूर्णांक ac, अक्षर **av)
{
	काष्ठा ssh *ssh = शून्य;
	पूर्णांक i, r, opt, exit_status, use_syslog, direct, timeout_ms;
	पूर्णांक was_addr, config_test = 0, dump_pubkeys = 0, opt_terminated = 0, want_final_pass = 0;
	पूर्णांक user_on_commandline = 0, user_was_default = 0, user_expanded = 0;
	अक्षर *p, *cp, *पंक्ति, *argv0, *logfile, *args;
	अक्षर cname[NI_MAXHOST], thishost[NI_MAXHOST];
	काष्ठा stat st;
	काष्ठा passwd *pw;
	बाह्य पूर्णांक optind, optreset;
	बाह्य अक्षर *optarg;
	काष्ठा Forward fwd;
	काष्ठा addrinfo *addrs = शून्य;
	माप_प्रकार n, len;
	u_int j;
	काष्ठा utsname utsname;
	काष्ठा ssh_conn_info *cinfo = शून्य;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	__progname = ssh_get_progname(av[0]);

#अगर_अघोषित HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, माप(*saved_av));
	क्रम (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = शून्य;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#पूर्ण_अगर

	seed_rng();

	/* Get user data. */
	pw = getpwuid(getuid());
	अगर (!pw) {
		logit("No user exists for uid %lu", (u_long)getuid());
		निकास(255);
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
	अगर ((ssh = ssh_alloc_session_state()) == शून्य)
		fatal("Couldn't allocate session state");
	channel_init_channels(ssh);

	/* Parse command-line arguments. */
	args = argv_assemble(ac, av); /* logged later */
	host = शून्य;
	use_syslog = 0;
	logfile = शून्य;
	argv0 = av[0];

 again:
	/* remaining: HUdhjruz */
	जबतक ((opt = getopt(ac, av, "1246ACGKMNTVXYZafgknqstvxy"
	    "B:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:")) != -1) {
		चयन (opt) {
		हाल '1':
			fatal("SSH protocol v.1 is no longer supported");
			अवरोध;
		हाल '2':
			/* Ignored */
			अवरोध;
		हाल '4':
			options.address_family = AF_INET;
			अवरोध;
		हाल '6':
			options.address_family = AF_INET6;
			अवरोध;
		हाल 'n':
			options.stdin_null = 1;
			अवरोध;
		हाल 'f':
			options.fork_after_authentication = 1;
			options.stdin_null = 1;
			अवरोध;
		हाल 'x':
			options.forward_x11 = 0;
			अवरोध;
		हाल 'X':
			options.forward_x11 = 1;
			अवरोध;
		हाल 'y':
			use_syslog = 1;
			अवरोध;
		हाल 'E':
			logfile = optarg;
			अवरोध;
		हाल 'G':
			config_test = 1;
			अवरोध;
		हाल 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			अवरोध;
		हाल 'Z':
			dump_pubkeys = 1;
			अवरोध;
		हाल 'g':
			options.fwd_opts.gateway_ports = 1;
			अवरोध;
		हाल 'O':
			अगर (options.stdio_forward_host != शून्य)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			अन्यथा अगर (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			अगर (म_भेद(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			अन्यथा अगर (म_भेद(optarg, "conninfo") == 0)
				muxclient_command = SSHMUX_COMMAND_CONNINFO;
			अन्यथा अगर (म_भेद(optarg, "channels") == 0)
				muxclient_command = SSHMUX_COMMAND_CHANINFO;
			अन्यथा अगर (म_भेद(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			अन्यथा अगर (म_भेद(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			अन्यथा अगर (म_भेद(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			अन्यथा अगर (म_भेद(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			अन्यथा अगर (म_भेद(optarg, "proxy") == 0)
				muxclient_command = SSHMUX_COMMAND_PROXY;
			अन्यथा
				fatal("Invalid multiplex command.");
			अवरोध;
		हाल 'P':
			अगर (options.tag == शून्य)
				options.tag = xstrdup(optarg);
			अवरोध;
		हाल 'Q':
			cp = शून्य;
			अगर (म_भेद(optarg, "cipher") == 0 ||
			    strcasecmp(optarg, "Ciphers") == 0)
				cp = cipher_alg_list('\n', 0);
			अन्यथा अगर (म_भेद(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			अन्यथा अगर (म_भेद(optarg, "mac") == 0 ||
			    strcasecmp(optarg, "MACs") == 0)
				cp = mac_alg_list('\n');
			अन्यथा अगर (म_भेद(optarg, "kex") == 0 ||
			    strcasecmp(optarg, "KexAlgorithms") == 0)
				cp = kex_alg_list('\n');
			अन्यथा अगर (म_भेद(optarg, "key") == 0)
				cp = sshkey_alg_list(0, 0, 0, '\n');
			अन्यथा अगर (म_भेद(optarg, "key-cert") == 0)
				cp = sshkey_alg_list(1, 0, 0, '\n');
			अन्यथा अगर (म_भेद(optarg, "key-plain") == 0)
				cp = sshkey_alg_list(0, 1, 0, '\n');
			अन्यथा अगर (म_भेद(optarg, "key-ca-sign") == 0 ||
			    strcasecmp(optarg, "CASignatureAlgorithms") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			अन्यथा अगर (म_भेद(optarg, "key-sig") == 0 ||
			    strcasecmp(optarg, "PubkeyAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "PubkeyAcceptedAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostKeyAlgorithms") == 0 ||
			    strcasecmp(optarg, "HostbasedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedKeyTypes") == 0 || /* deprecated name */
			    strcasecmp(optarg, "HostbasedAcceptedAlgorithms") == 0)
				cp = sshkey_alg_list(0, 0, 1, '\n');
			अन्यथा अगर (म_भेद(optarg, "sig") == 0)
				cp = sshkey_alg_list(0, 1, 1, '\n');
			अन्यथा अगर (म_भेद(optarg, "protocol-version") == 0)
				cp = xstrdup("2");
			अन्यथा अगर (म_भेद(optarg, "compression") == 0) {
				cp = xstrdup(compression_alg_list(0));
				len = म_माप(cp);
				क्रम (n = 0; n < len; n++)
					अगर (cp[n] == ',')
						cp[n] = '\n';
			} अन्यथा अगर (म_भेद(optarg, "help") == 0) {
				cp = xstrdup(
				    "cipher\ncipher-auth\ncompression\nkex\n"
				    "key\nkey-cert\nkey-plain\nkey-sig\nmac\n"
				    "protocol-version\nsig");
			}
			अगर (cp == शून्य)
				fatal("Unsupported query \"%s\"", optarg);
			म_लिखो("%s\n", cp);
			मुक्त(cp);
			निकास(0);
			अवरोध;
		हाल 'a':
			options.forward_agent = 0;
			अवरोध;
		हाल 'A':
			options.forward_agent = 1;
			अवरोध;
		हाल 'k':
			options.gss_deleg_creds = 0;
			अवरोध;
		हाल 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			अवरोध;
		हाल 'i':
			p = tilde_expand_filename(optarg, getuid());
			अगर (stat(p, &st) == -1)
				ख_लिखो(मानक_त्रुटि, "Warning: Identity file %s "
				    "not accessible: %s.\n", p,
				    म_त्रुटि(त्रुटि_सं));
			अन्यथा
				add_identity_file(&options, शून्य, p, 1);
			मुक्त(p);
			अवरोध;
		हाल 'I':
#अगर_घोषित ENABLE_PKCS11
			मुक्त(options.pkcs11_provider);
			options.pkcs11_provider = xstrdup(optarg);
#अन्यथा
			ख_लिखो(मानक_त्रुटि, "no support for PKCS#11.\n");
#पूर्ण_अगर
			अवरोध;
		हाल 'J':
			अगर (options.jump_host != शून्य) {
				fatal("Only a single -J option is permitted "
				    "(use commas to separate multiple "
				    "jump hops)");
			}
			अगर (options.proxy_command != शून्य)
				fatal("Cannot specify -J with ProxyCommand");
			अगर (parse_jump(optarg, &options, 1, 1) == -1)

				fatal("Invalid -J argument");
			अवरोध;
		हाल 't':
			अगर (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			अन्यथा
				options.request_tty = REQUEST_TTY_YES;
			अवरोध;
		हाल 'v':
			अगर (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} अन्यथा {
				अगर (options.log_level < SYSLOG_LEVEL_DEBUG3) {
					debug_flag++;
					options.log_level++;
				}
			}
			अवरोध;
		हाल 'V':
			ख_लिखो(मानक_त्रुटि, "%s, %s\n",
			    SSH_RELEASE, SSH_OPENSSL_VERSION);
			निकास(0);
			अवरोध;
		हाल 'w':
			अगर (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			अगर (options.tun_local == SSH_TUNID_ERR) {
				ख_लिखो(मानक_त्रुटि,
				    "Bad tun device '%s'\n", optarg);
				निकास(255);
			}
			अवरोध;
		हाल 'W':
			अगर (options.stdio_forward_host != शून्य)
				fatal("stdio forward already specified");
			अगर (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			अगर (parse_forward(&fwd, optarg, 1, 0)) {
				options.stdio_forward_host =
				    fwd.listen_port == PORT_STREAMLOCAL ?
				    fwd.listen_path : fwd.listen_host;
				options.stdio_forward_port = fwd.listen_port;
				मुक्त(fwd.connect_host);
			} अन्यथा {
				ख_लिखो(मानक_त्रुटि,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				निकास(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			options.session_type = SESSION_TYPE_NONE;
			अवरोध;
		हाल 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			अवरोध;
		हाल 'e':
			अगर (म_माप(optarg) == 2 && optarg[0] == '^' &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			अन्यथा अगर (म_माप(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			अन्यथा अगर (म_भेद(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			अन्यथा {
				ख_लिखो(मानक_त्रुटि, "Bad escape character '%s'.\n",
				    optarg);
				निकास(255);
			}
			अवरोध;
		हाल 'c':
			अगर (!ciphers_valid(*optarg == '+' || *optarg == '^' ?
			    optarg + 1 : optarg)) {
				ख_लिखो(मानक_त्रुटि, "Unknown cipher type '%s'\n",
				    optarg);
				निकास(255);
			}
			मुक्त(options.ciphers);
			options.ciphers = xstrdup(optarg);
			अवरोध;
		हाल 'm':
			अगर (mac_valid(optarg)) {
				मुक्त(options.macs);
				options.macs = xstrdup(optarg);
			} अन्यथा {
				ख_लिखो(मानक_त्रुटि, "Unknown mac type '%s'\n",
				    optarg);
				निकास(255);
			}
			अवरोध;
		हाल 'M':
			अगर (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			अन्यथा
				options.control_master = SSHCTL_MASTER_YES;
			अवरोध;
		हाल 'p':
			अगर (options.port == -1) {
				options.port = a2port(optarg);
				अगर (options.port <= 0) {
					ख_लिखो(मानक_त्रुटि, "Bad port '%s'\n",
					    optarg);
					निकास(255);
				}
			}
			अवरोध;
		हाल 'l':
			अगर (options.user == शून्य) {
				options.user = xstrdup(optarg);
				user_on_commandline = 1;
			}
			अवरोध;

		हाल 'L':
			अगर (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			अन्यथा {
				ख_लिखो(मानक_त्रुटि,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				निकास(255);
			}
			अवरोध;

		हाल 'R':
			अगर (parse_forward(&fwd, optarg, 0, 1) ||
			    parse_forward(&fwd, optarg, 1, 1)) {
				add_remote_forward(&options, &fwd);
			} अन्यथा {
				ख_लिखो(मानक_त्रुटि,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				निकास(255);
			}
			अवरोध;

		हाल 'D':
			अगर (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} अन्यथा {
				ख_लिखो(मानक_त्रुटि,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				निकास(255);
			}
			अवरोध;

		हाल 'C':
#अगर_घोषित WITH_ZLIB
			options.compression = 1;
#अन्यथा
			error("Compression not supported, disabling.");
#पूर्ण_अगर
			अवरोध;
		हाल 'N':
			अगर (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_NONE)
				fatal("Cannot specify -N with -s/SessionType");
			options.session_type = SESSION_TYPE_NONE;
			options.request_tty = REQUEST_TTY_NO;
			अवरोध;
		हाल 'T':
			options.request_tty = REQUEST_TTY_NO;
			अवरोध;
		हाल 'o':
			पंक्ति = xstrdup(optarg);
			अगर (process_config_पंक्ति(&options, pw,
			    host ? host : "", host ? host : "", "", पंक्ति,
			    "command-line", 0, शून्य, SSHCONF_USERCONF) != 0)
				निकास(255);
			मुक्त(पंक्ति);
			अवरोध;
		हाल 's':
			अगर (options.session_type != -1 &&
			    options.session_type != SESSION_TYPE_SUBSYSTEM)
				fatal("Cannot specify -s with -N/SessionType");
			options.session_type = SESSION_TYPE_SUBSYSTEM;
			अवरोध;
		हाल 'S':
			मुक्त(options.control_path);
			options.control_path = xstrdup(optarg);
			अवरोध;
		हाल 'b':
			options.bind_address = optarg;
			अवरोध;
		हाल 'B':
			options.bind_interface = optarg;
			अवरोध;
		हाल 'F':
			config = optarg;
			अवरोध;
		शेष:
			usage();
		}
	}

	अगर (optind > 1 && म_भेद(av[optind - 1], "--") == 0)
		opt_terminated = 1;

	ac -= optind;
	av += optind;

	अगर (ac > 0 && !host) {
		पूर्णांक tport;
		अक्षर *tuser;
		चयन (parse_ssh_uri(*av, &tuser, &host, &tport)) {
		हाल -1:
			usage();
			अवरोध;
		हाल 0:
			अगर (options.user == शून्य) {
				options.user = tuser;
				tuser = शून्य;
				user_on_commandline = 1;
			}
			मुक्त(tuser);
			अगर (options.port == -1 && tport != -1)
				options.port = tport;
			अवरोध;
		शेष:
			p = xstrdup(*av);
			cp = म_खोजप(p, '@');
			अगर (cp != शून्य) {
				अगर (cp == p)
					usage();
				अगर (options.user == शून्य) {
					options.user = p;
					p = शून्य;
					user_on_commandline = 1;
				}
				*cp++ = '\0';
				host = xstrdup(cp);
				मुक्त(p);
			} अन्यथा
				host = p;
			अवरोध;
		}
		अगर (ac > 1 && !opt_terminated) {
			optind = optreset = 1;
			जाओ again;
		}
		ac--, av++;
	}

	/* Check that we got a host name. */
	अगर (!host)
		usage();

	/*
	 * Validate commandline-specified values that end up in %tokens
	 * before they are used in config parsing.
	 */
	अगर (options.user != शून्य && !ssh_valid_ruser(options.user))
		fatal("remote username contains invalid characters");
	अगर (!ssh_valid_hostname(host))
		fatal("hostname contains invalid characters");

	options.host_arg = xstrdup(host);

	/* Initialize the command to execute on remote host. */
	अगर ((command = sshbuf_new()) == शून्य)
		fatal("sshbuf_new failed");

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	अगर (!ac) {
		/* No command specified - execute shell on a tty. */
		अगर (options.session_type == SESSION_TYPE_SUBSYSTEM) {
			ख_लिखो(मानक_त्रुटि,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} अन्यथा {
		/* A command has been specified.  Store it into the buffer. */
		क्रम (i = 0; i < ac; i++) {
			अगर ((r = sshbuf_putf(command, "%s%s",
			    i ? " " : "", av[i])) != 0)
				fatal_fr(r, "buffer error");
		}
	}

	ssh_signal(SIGPIPE, संक_छोड़ो); /* ignore SIGPIPE early */

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	अगर (use_syslog && logfile != शून्य)
		fatal("Can't specify both -y and -E");
	अगर (logfile != शून्य)
		log_redirect_stderr_to(logfile);
	log_init(argv0,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_USER : options.log_facility,
	    !use_syslog);

	debug("%s, %s", SSH_RELEASE, SSH_OPENSSL_VERSION);
	अगर (uname(&utsname) != 0) {
		स_रखो(&utsname, 0, माप(utsname));
		strlcpy(utsname.sysname, "UNKNOWN", माप(utsname.sysname));
	}
	debug3("Running on %s %s %s %s", utsname.sysname, utsname.release,
	    utsname.version, utsname.machine);
	debug3("Started with: %s", args);
	मुक्त(args);

	/* Parse the configuration files */
	process_config_files(options.host_arg, pw, 0, &want_final_pass);
	अगर (want_final_pass)
		debug("configuration requests final Match pass");

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	अगर (options.hostname != शून्य) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (अक्षर *)शून्य);
		मुक्त(host);
		host = cp;
		मुक्त(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* Don't lowercase addresses, they will be explicitly canonicalised */
	अगर ((was_addr = is_addr(host)) == 0)
		lowercase(host);

	/*
	 * Try to canonicalize if requested by configuration or the
	 * hostname is an address.
	 */
	अगर (options.canonicalize_hostname != SSH_CANONICALISE_NO || was_addr)
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
	अगर (addrs == शून्य && config_has_permitted_cnames(&options) && (direct ||
	    options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		अगर ((addrs = resolve_host(host, options.port,
		    direct, cname, माप(cname))) == शून्य) {
			/* Don't fatal proxied host names not in the DNS */
			अगर (direct)
				cleanup_exit(255); /* logged in resolve_host */
		} अन्यथा
			check_follow_cname(direct, &host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	अगर (options.canonicalize_hostname != 0 && !want_final_pass) {
		debug("hostname canonicalisation enabled, "
		    "will re-parse configuration");
		want_final_pass = 1;
	}

	अगर (want_final_pass) {
		debug("re-parsing configuration");
		मुक्त(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(options.host_arg, pw, 1, शून्य);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		अगर (addrs != शून्य && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	अगर (fill_default_options(&options) != 0)
		cleanup_exit(255);

	अगर (options.user == शून्य) {
		user_was_default = 1;
		options.user = xstrdup(pw->pw_name);
	}

	/*
	 * If ProxyJump option specified, then construct a ProxyCommand now.
	 */
	अगर (options.jump_host != शून्य) {
		अक्षर port_s[8];
		स्थिर अक्षर *jumpuser = options.jump_user, *sshbin = argv0;
		पूर्णांक port = options.port, jumpport = options.jump_port;

		अगर (port <= 0)
			port = default_ssh_port();
		अगर (jumpport <= 0)
			jumpport = default_ssh_port();
		अगर (jumpuser == शून्य)
			jumpuser = options.user;
		अगर (म_भेद(options.jump_host, host) == 0 && port == jumpport &&
		    म_भेद(options.user, jumpuser) == 0)
			fatal("jumphost loop via %s", options.jump_host);

		/*
		 * Try to use SSH indicated by argv[0], but fall back to
		 * "ssh" if it appears unavailable.
		 */
		अगर (म_अक्षर(argv0, '/') != शून्य && access(argv0, X_OK) != 0)
			sshbin = "ssh";

		/* Consistency check */
		अगर (options.proxy_command != शून्य &&
		    strcasecmp(options.proxy_command, "none") != 0)
			fatal("inconsistent options: ProxyCommand+ProxyJump");
		/* Never use FD passing for ProxyJump */
		options.proxy_use_fdpass = 0;
		snprintf(port_s, माप(port_s), "%d", options.jump_port);
		xasprintf(&options.proxy_command,
		    "%s%s%s%s%s%s%s%s%s%s%.*s -W '[%%h]:%%p' %s",
		    sshbin,
		    /* Optional "-l user" argument if jump_user set */
		    options.jump_user == शून्य ? "" : " -l ",
		    options.jump_user == शून्य ? "" : options.jump_user,
		    /* Optional "-p port" argument if jump_port set */
		    options.jump_port <= 0 ? "" : " -p ",
		    options.jump_port <= 0 ? "" : port_s,
		    /* Optional additional jump hosts ",..." */
		    options.jump_extra == शून्य ? "" : " -J ",
		    options.jump_extra == शून्य ? "" : options.jump_extra,
		    /* Optional "-F" argument if -F specified */
		    config == शून्य ? "" : " -F ",
		    config == शून्य ? "" : config,
		    /* Optional "-v" arguments if -v set */
		    debug_flag ? " -" : "",
		    debug_flag, "vvv",
		    /* Mandatory hostname */
		    options.jump_host);
		debug("Setting implicit ProxyCommand from ProxyJump: %s",
		    options.proxy_command);
	}

	अगर (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(ssh, options.address_family);
	ssh_packet_set_qos(ssh, options.ip_qos_interactive,
	    options.ip_qos_bulk);

	/* Tidy and check options */
	अगर (options.host_कुंजी_alias != शून्य)
		lowercase(options.host_कुंजी_alias);
	अगर (options.proxy_command != शून्य &&
	    म_भेद(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	अगर (options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		अगर (options.control_persist && options.control_path != शून्य) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "ControlPersist; disabling");
			options.update_hostkeys = 0;
		} अन्यथा अगर (sshbuf_len(command) != 0 ||
		    options.remote_command != शून्य ||
		    options.request_tty == REQUEST_TTY_NO) {
			debug("UpdateHostKeys=ask is incompatible with "
			    "remote command execution; disabling");
			options.update_hostkeys = 0;
		} अन्यथा अगर (options.log_level < SYSLOG_LEVEL_INFO) {
			/* no point logging anything; user won't see it */
			options.update_hostkeys = 0;
		}
	}
	अगर (options.connection_attempts <= 0)
		fatal("Invalid number of ConnectionAttempts");

	अगर (sshbuf_len(command) != 0 && options.remote_command != शून्य)
		fatal("Cannot execute command-line and remote command.");

	/* Cannot fork to background if no command. */
	अगर (options.fork_after_authentication && sshbuf_len(command) == 0 &&
	    options.remote_command == शून्य &&
	    options.session_type != SESSION_TYPE_NONE)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/* reinit */
	log_init(argv0, options.log_level, options.log_facility, !use_syslog);
	क्रम (j = 0; j < options.अंक_log_verbose; j++) {
		अगर (strcasecmp(options.log_verbose[j], "none") == 0)
			अवरोध;
		log_verbose_add(options.log_verbose[j]);
	}

	अगर (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	अगर (sshbuf_len(command) == 0 && options.remote_command == शून्य)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	अगर (options.request_tty == REQUEST_TTY_NO ||
	    (muxclient_command && muxclient_command != SSHMUX_COMMAND_PROXY) ||
	    options.session_type == SESSION_TYPE_NONE)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	अगर ((!isatty(fileno(मानक_निवेश)) || options.stdin_null) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		अगर (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	/* Set up strings used to percent_expand() arguments */
	cinfo = xcalloc(1, माप(*cinfo));
	अगर (gethostname(thishost, माप(thishost)) == -1)
		fatal("gethostname: %s", म_त्रुटि(त्रुटि_सं));
	cinfo->thishost = xstrdup(thishost);
	thishost[म_खोज(thishost, ".")] = '\0';
	cinfo->shorthost = xstrdup(thishost);
	xasprintf(&cinfo->portstr, "%d", options.port);
	xasprintf(&cinfo->uidstr, "%llu",
	    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
	cinfo->keyalias = xstrdup(options.host_कुंजी_alias ?
	    options.host_कुंजी_alias : options.host_arg);
	cinfo->host_arg = xstrdup(options.host_arg);
	cinfo->remhost = xstrdup(host);
	cinfo->homedir = xstrdup(pw->pw_dir);
	cinfo->locuser = xstrdup(pw->pw_name);
	cinfo->jmphost = xstrdup(options.jump_host == शून्य ?
	    "" : options.jump_host);

	/*
	 * If the user was specified via a configuration directive then attempt
	 * to expand it. It cannot contain %r (itself) or %C since User is
	 * a component of the hash.
	 */
	अगर (!user_on_commandline && !user_was_default) {
		अगर ((p = percent_dollar_expand(options.user,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(cinfo),
		    (अक्षर *)शून्य)) == शून्य)
			fatal("invalid environment variable expansion");
		user_expanded = म_भेद(p, options.user) != 0;
		मुक्त(options.user);
		options.user = p;
	}

	/*
	 * Usernames specified on the commandline or expanded from the
	 * configuration file must be validated.
	 * Conversely, usernames from getpwnam(3) or specified as literals
	 * via configuration (i.e. not expanded) are not subject to validation.
	 */
	अगर ((user_on_commandline || user_expanded) &&
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
	अगर (options.remote_command != शून्य) {
		debug3("expanding RemoteCommand: %s", options.remote_command);
		cp = options.remote_command;
		options.remote_command = default_client_percent_expand(cp,
		    cinfo);
		debug3("expanded RemoteCommand: %s", options.remote_command);
		मुक्त(cp);
		अगर ((r = sshbuf_put(command, options.remote_command,
		    म_माप(options.remote_command))) != 0)
			fatal_fr(r, "buffer error");
	}

	अगर (options.control_path != शून्य) {
		cp = tilde_expand_filename(options.control_path, getuid());
		मुक्त(options.control_path);
		options.control_path = default_client_percent_dollar_expand(cp,
		    cinfo);
		मुक्त(cp);
	}

	अगर (options.identity_agent != शून्य) {
		p = tilde_expand_filename(options.identity_agent, getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		मुक्त(p);
		मुक्त(options.identity_agent);
		options.identity_agent = cp;
	}

	क्रम (j = 0; j < options.अंक_revoked_host_कुंजियाँ; j++) {
		p = tilde_expand_filename(options.revoked_host_कुंजियाँ[j],
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		मुक्त(p);
		मुक्त(options.revoked_host_कुंजियाँ[j]);
		options.revoked_host_कुंजियाँ[j] = cp;
	}

	अगर (options.forward_agent_sock_path != शून्य) {
		p = tilde_expand_filename(options.forward_agent_sock_path,
		    getuid());
		cp = default_client_percent_dollar_expand(p, cinfo);
		मुक्त(p);
		मुक्त(options.forward_agent_sock_path);
		options.forward_agent_sock_path = cp;
		अगर (stat(options.forward_agent_sock_path, &st) != 0) {
			error("Cannot forward agent socket path \"%s\": %s",
			    options.forward_agent_sock_path, म_त्रुटि(त्रुटि_सं));
			अगर (options.exit_on_forward_failure)
				cleanup_exit(255);
		}
	}

	अगर (options.version_addendum != शून्य) {
		cp = default_client_percent_dollar_expand(
		    options.version_addendum, cinfo);
		मुक्त(options.version_addendum);
		options.version_addendum = cp;
	}

	अगर (options.अंक_system_hostfiles > 0 &&
	    strcasecmp(options.system_hostfiles[0], "none") == 0) {
		अगर (options.अंक_system_hostfiles > 1)
			fatal("Invalid GlobalKnownHostsFiles: \"none\" "
			    "appears with other entries");
		मुक्त(options.system_hostfiles[0]);
		options.system_hostfiles[0] = शून्य;
		options.अंक_system_hostfiles = 0;
	}

	अगर (options.अंक_user_hostfiles > 0 &&
	    strcasecmp(options.user_hostfiles[0], "none") == 0) {
		अगर (options.अंक_user_hostfiles > 1)
			fatal("Invalid UserKnownHostsFiles: \"none\" "
			    "appears with other entries");
		मुक्त(options.user_hostfiles[0]);
		options.user_hostfiles[0] = शून्य;
		options.अंक_user_hostfiles = 0;
	}
	क्रम (j = 0; j < options.अंक_user_hostfiles; j++) {
		अगर (options.user_hostfiles[j] == शून्य)
			जारी;
		cp = tilde_expand_filename(options.user_hostfiles[j], getuid());
		p = default_client_percent_dollar_expand(cp, cinfo);
		अगर (म_भेद(options.user_hostfiles[j], p) != 0)
			debug3("expanded UserKnownHostsFile '%s' -> "
			    "'%s'", options.user_hostfiles[j], p);
		मुक्त(options.user_hostfiles[j]);
		मुक्त(cp);
		options.user_hostfiles[j] = p;
	}

	क्रम (j = 0; j < options.अंक_setenv; j++) {
		अक्षर *name = options.setenv[j], *मूल्य;

		अगर (name == शून्य)
			जारी;
		/* Expand only the value portion, not the variable name. */
		अगर ((मूल्य = म_अक्षर(name, '=')) == शून्य) {
			/* shouldn't happen; vars are checked in readconf.c */
			fatal("Invalid config SetEnv: %s", name);
		}
		*मूल्य++ = '\0';
		cp = default_client_percent_dollar_expand(मूल्य, cinfo);
		xasprintf(&p, "%s=%s", name, cp);
		अगर (म_भेद(मूल्य, p) != 0) {
			debug3("expanded SetEnv '%s' '%s' -> '%s'",
			    name, मूल्य, cp);
		}
		मुक्त(options.setenv[j]);
		मुक्त(cp);
		options.setenv[j] = p;
	}

	क्रम (i = 0; i < options.अंक_local_forwards; i++) {
		अगर (options.local_forwards[i].listen_path != शून्य) {
			cp = options.local_forwards[i].listen_path;
			p = options.local_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			अगर (म_भेद(cp, p) != 0)
				debug3("expanded LocalForward listen path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
		अगर (options.local_forwards[i].connect_path != शून्य) {
			cp = options.local_forwards[i].connect_path;
			p = options.local_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			अगर (म_भेद(cp, p) != 0)
				debug3("expanded LocalForward connect path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
	}

	क्रम (i = 0; i < options.अंक_remote_forwards; i++) {
		अगर (options.remote_forwards[i].listen_path != शून्य) {
			cp = options.remote_forwards[i].listen_path;
			p = options.remote_forwards[i].listen_path =
			    default_client_percent_expand(cp, cinfo);
			अगर (म_भेद(cp, p) != 0)
				debug3("expanded RemoteForward listen path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
		अगर (options.remote_forwards[i].connect_path != शून्य) {
			cp = options.remote_forwards[i].connect_path;
			p = options.remote_forwards[i].connect_path =
			    default_client_percent_expand(cp, cinfo);
			अगर (म_भेद(cp, p) != 0)
				debug3("expanded RemoteForward connect path "
				    "'%s' -> '%s'", cp, p);
			मुक्त(cp);
		}
	}

	अगर (config_test) {
		dump_client_config(&options, host);
		निकास(0);
	}

	/* Expand SecurityKeyProvider if it refers to an environment variable */
	अगर (options.sk_provider != शून्य && *options.sk_provider == '$' &&
	    म_माप(options.sk_provider) > 1) {
		अगर ((cp = दो_पर्या(options.sk_provider + 1)) == शून्य) {
			debug("Authenticator provider %s did not resolve; "
			    "disabling", options.sk_provider);
			मुक्त(options.sk_provider);
			options.sk_provider = शून्य;
		} अन्यथा {
			debug2("resolved SecurityKeyProvider %s => %s",
			    options.sk_provider, cp);
			मुक्त(options.sk_provider);
			options.sk_provider = xstrdup(cp);
		}
	}

	अगर (muxclient_command != 0 && options.control_path == शून्य)
		fatal("No ControlPath specified for \"-O\" command");
	अगर (options.control_path != शून्य) {
		पूर्णांक sock;
		अगर ((sock = muxclient(options.control_path)) >= 0) {
			अगर (ssh_packet_set_connection(ssh, sock, sock) == शून्य)
				fatal("ssh_packet_set_connection failed");
			ssh_packet_set_mux(ssh);
			जाओ skip_connect;
		}
	}

	/* load options.identity_files */
	load_public_identity_files(cinfo);

	/* optionally set the SSH_AUTHSOCKET_ENV_NAME variable */
	अगर (options.identity_agent &&
	    म_भेद(options.identity_agent, SSH_AUTHSOCKET_ENV_NAME) != 0) {
		अगर (म_भेद(options.identity_agent, "none") == 0) {
			unsetenv(SSH_AUTHSOCKET_ENV_NAME);
		} अन्यथा {
			cp = options.identity_agent;
			/* legacy (limited) format */
			अगर (cp[0] == '$' && cp[1] != '{') {
				अगर (!valid_env_name(cp + 1)) {
					fatal("Invalid IdentityAgent "
					    "environment variable name %s", cp);
				}
				अगर ((p = दो_पर्या(cp + 1)) == शून्य)
					unsetenv(SSH_AUTHSOCKET_ENV_NAME);
				अन्यथा
					setenv(SSH_AUTHSOCKET_ENV_NAME, p, 1);
			} अन्यथा {
				/* identity_agent specifies a path directly */
				setenv(SSH_AUTHSOCKET_ENV_NAME, cp, 1);
			}
		}
	}

	अगर (dump_pubkeys) {
		pubkey_dump(ssh);
		निकास(0);
	}

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	अगर (addrs == शून्य && options.proxy_command == शून्य) {
		debug2("resolving \"%s\" port %d", host, options.port);
		अगर ((addrs = resolve_host(host, options.port, 1,
		    cname, माप(cname))) == शून्य)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	अगर (options.connection_timeout >= पूर्णांक_उच्च/1000)
		timeout_ms = पूर्णांक_उच्च;
	अन्यथा
		timeout_ms = options.connection_timeout * 1000;

	/* Apply channels timeouts, if set */
	channel_clear_timeouts(ssh);
	क्रम (j = 0; j < options.अंक_channel_timeouts; j++) {
		द्विगुन timeout;

		debug3("applying channel timeout %s",
		    options.channel_timeouts[j]);
		अगर (parse_pattern_interval(options.channel_timeouts[j],
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
	अगर (ssh_connect(ssh, host, options.host_arg, addrs, &hostaddr,
	    options.port, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive) != 0)
		निकास(255);


	ssh_packet_set_timeout(ssh, options.server_alive_interval,
	    options.server_alive_गिनती_max);

	अगर (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection and we have hostbased auth
	 * enabled, load the public keys so we can later use the ssh-keysign
	 * helper to sign challenges.
	 */
	sensitive_तथ्य.nkeys = 0;
	sensitive_तथ्य.कुंजियाँ = शून्य;
	अगर (options.hostbased_authentication) {
		पूर्णांक loaded = 0;

		sensitive_तथ्य.nkeys = 10;
		sensitive_तथ्य.कुंजियाँ = xcalloc(sensitive_तथ्य.nkeys,
		    माप(*sensitive_तथ्य.कुंजियाँ));

		/* XXX check errors? */
#घोषणा L_PUBKEY(p,o) करो { \
	अगर ((o) >= sensitive_तथ्य.nkeys) \
		fatal_f("pubkey out of array bounds"); \
	check_load(sshkey_load_public(p, &(sensitive_तथ्य.कुंजियाँ[o]), शून्य), \
	    &(sensitive_तथ्य.कुंजियाँ[o]), p, "hostbased pubkey"); \
	अगर (sensitive_तथ्य.कुंजियाँ[o] != शून्य) { \
		debug2("hostbased pubkey \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} जबतक (0)
#घोषणा L_CERT(p,o) करो { \
	अगर ((o) >= sensitive_तथ्य.nkeys) \
		fatal_f("cert out of array bounds"); \
	check_load(sshkey_load_cert(p, &(sensitive_तथ्य.कुंजियाँ[o])), \
	    &(sensitive_तथ्य.कुंजियाँ[o]), p, "hostbased cert"); \
	अगर (sensitive_तथ्य.कुंजियाँ[o] != शून्य) { \
		debug2("hostbased cert \"%s\" in slot %d", p, o); \
		loaded++; \
	} \
} जबतक (0)

		अगर (options.hostbased_authentication == 1) {
			L_CERT(PATH_HOST_ECDSA_कुंजी_FILE, 0);
			L_CERT(PATH_HOST_ED25519_कुंजी_FILE, 1);
			L_CERT(PATH_HOST_RSA_कुंजी_FILE, 2);
			L_CERT(PATH_HOST_MLDSA44_ED25519_कुंजी_FILE, 3);
			L_PUBKEY(PATH_HOST_ECDSA_कुंजी_FILE, 4);
			L_PUBKEY(PATH_HOST_ED25519_कुंजी_FILE, 5);
			L_PUBKEY(PATH_HOST_RSA_कुंजी_FILE, 6);
			L_PUBKEY(PATH_HOST_MLDSA44_ED25519_कुंजी_FILE, 7);
			अगर (loaded == 0)
				debug("HostbasedAuthentication enabled but no "
				   "local public host keys could be loaded.");
		}
	}

	अगर (options.forward_agent && options.forward_agent_sock_path != शून्य) {
		cp = options.forward_agent_sock_path;
		अगर (cp[0] == '$') {
			अगर (!valid_env_name(cp + 1)) {
				fatal("Invalid ForwardAgent environment variable name %s", cp);
			}
			अगर ((p = दो_पर्या(cp + 1)) != शून्य)
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
	ssh_login(ssh, &sensitive_तथ्य, host, &hostaddr, options.port,
	    pw, timeout_ms, cinfo);

	/* We no longer need the private host keys.  Clear them now. */
	अगर (sensitive_तथ्य.nkeys != 0) {
		क्रम (i = 0; i < sensitive_तथ्य.nkeys; i++) {
			अगर (sensitive_तथ्य.कुंजियाँ[i] != शून्य) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				sshkey_free(sensitive_तथ्य.कुंजियाँ[i]);
				sensitive_तथ्य.कुंजियाँ[i] = शून्य;
			}
		}
		मुक्त(sensitive_तथ्य.कुंजियाँ);
	}
	क्रम (i = 0; i < options.अंक_identity_files; i++) {
		मुक्त(options.identity_files[i]);
		options.identity_files[i] = शून्य;
		अगर (options.identity_कुंजियाँ[i]) {
			sshkey_free(options.identity_कुंजियाँ[i]);
			options.identity_कुंजियाँ[i] = शून्य;
		}
	}
	क्रम (i = 0; i < options.अंक_certificate_files; i++) {
		मुक्त(options.certificate_files[i]);
		options.certificate_files[i] = शून्य;
	}

#अगर_घोषित ENABLE_PKCS11
	(व्योम)pkcs11_del_provider(options.pkcs11_provider);
#पूर्ण_अगर

 skip_connect:
	अगर (addrs != शून्य)
		freeaddrinfo(addrs);
	exit_status = ssh_session2(ssh, cinfo);
	ssh_conn_info_free(cinfo);
	channel_free_channels(ssh);
	ssh_packet_free(ssh);
	pwfree(pw);

	अगर (options.control_path != शून्य && muxserver_sock != -1)
		unlink(options.control_path);

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();

	वापस exit_status;
}

अटल व्योम
control_persist_detach(व्योम)
{
	pid_t pid;

	debug_f("backgrounding master process");

	/*
	 * master (current process) into the background, and make the
	 * foreground process a client of the backgrounded master.
	 */
	चयन ((pid = विभाजन())) {
	हाल -1:
		fatal_f("fork: %s", म_त्रुटि(त्रुटि_सं));
	हाल 0:
		/* Child: master process continues mainloop */
		अवरोध;
	शेष:
		/*
		 * Parent: set up mux client to connect to backgrounded
		 * master.
		 */
		debug2_f("background process is %ld", (दीर्घ)pid);
		options.stdin_null = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
		options.fork_after_authentication = ofork_after_authentication;
		options.session_type = osession_type;
		बंद(muxserver_sock);
		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
		(व्योम)muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
		fatal("Failed to connect to new control master");
	}
	अगर (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
}

/* Do fork() after authentication. Used by "ssh -f" */
अटल व्योम
fork_postauth(व्योम)
{
	अगर (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	options.fork_after_authentication = 0;
	अगर (daemon(1, 1) == -1)
		fatal("daemon() failed: %.200s", म_त्रुटि(त्रुटि_सं));
	अगर (stdfd_devnull(1, 1, !(log_is_on_stderr() && debug_flag)) == -1)
		error_f("stdfd_devnull failed");
}

अटल व्योम
forwarding_success(व्योम)
{
	अगर (forward_confirms_pending == -1)
		वापस;
	अगर (--forward_confirms_pending == 0) {
		debug_f("all expected forwarding replies received");
		अगर (options.fork_after_authentication)
			fork_postauth();
	} अन्यथा {
		debug2_f("%d expected forwarding replies remaining",
		    forward_confirms_pending);
	}
}

काष्ठा rfwd_confirm_ctx {
	पूर्णांक fid;
};

/* Callback for remote forward global requests */
अटल व्योम
ssh_confirm_remote_forward(काष्ठा ssh *ssh, पूर्णांक type, uint32_t seq, व्योम *ctxt)
{
	काष्ठा rfwd_confirm_ctx *rctx = (काष्ठा rfwd_confirm_ctx *)ctxt;
	काष्ठा Forward *rfwd;
	u_int port;
	पूर्णांक r;

	अगर (rctx->fid < 0 || rctx->fid >= options.अंक_remote_forwards)
		fatal_f("invalid forwarding ID %d", rctx->fid);
	rfwd = &options.remote_forwards[rctx->fid];
	freezero(rctx, माप(*rctx));

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_संदेश_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	अगर (rfwd->listen_path == शून्य && rfwd->listen_port == 0) {
		अगर (type == SSH2_संदेश_REQUEST_SUCCESS) {
			अगर ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse packet");
			अगर (port > 65535) {
				error("Invalid allocated port %u for remote "
				    "forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
				/* Ensure failure processing runs below */
				type = SSH2_संदेश_REQUEST_FAILURE;
				channel_update_permission(ssh,
				    rfwd->handle, -1);
			} अन्यथा {
				rfwd->allocated_port = (पूर्णांक)port;
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

	अगर (type == SSH2_संदेश_REQUEST_FAILURE) {
		अगर (options.exit_on_forward_failure) {
			अगर (rfwd->listen_path != शून्य)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			अन्यथा
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} अन्यथा {
			अगर (rfwd->listen_path != शून्य)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			अन्यथा
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	forwarding_success();
}

अटल व्योम
client_cleanup_stdio_fwd(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक force, व्योम *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

अटल व्योम
ssh_stdio_confirm(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक success, व्योम *arg)
{
	अगर (!success)
		fatal("stdio forwarding failed");
}

अटल व्योम
ssh_tun_confirm(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक success, व्योम *arg)
{
	अगर (!success) {
		error("Tunnel forwarding failed");
		अगर (options.exit_on_forward_failure)
			cleanup_exit(255);
	}

	debug_f("tunnel forward established, id=%d", id);
	forwarding_success();
}

अटल व्योम
ssh_init_stdio_forwarding(काष्ठा ssh *ssh)
{
	Channel *c;
	पूर्णांक in, out;

	अगर (options.stdio_forward_host == शून्य)
		वापस;

	debug3_f("%s:%d", options.stdio_forward_host,
	    options.stdio_forward_port);

	अगर ((in = dup(STDIN_FILENO)) == -1 ||
	    (out = dup(STDOUT_FILENO)) == -1)
		fatal_f("dup() in/out failed");
	अगर ((c = channel_connect_stdio_fwd(ssh, options.stdio_forward_host,
	    options.stdio_forward_port, in, out,
	    CHANNEL_NONBLOCK_STDIO)) == शून्य)
		fatal_f("channel_connect_stdio_fwd failed");
	channel_register_cleanup(ssh, c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(ssh, c->self, ssh_stdio_confirm, शून्य);
}

अटल व्योम
ssh_init_forward_permissions(काष्ठा ssh *ssh, स्थिर अक्षर *what, अक्षर **opens,
    u_int अंक_opens)
{
	u_int i;
	पूर्णांक port;
	अक्षर *addr, *arg, *oarg;
	पूर्णांक where = FORWARD_LOCAL;

	channel_clear_permission(ssh, FORWARD_ADM, where);
	अगर (अंक_opens == 0)
		वापस; /* permit any */

	/* handle keywords: "any" / "none" */
	अगर (अंक_opens == 1 && म_भेद(opens[0], "any") == 0)
		वापस;
	अगर (अंक_opens == 1 && म_भेद(opens[0], "none") == 0) {
		channel_disable_admin(ssh, where);
		वापस;
	}
	/* Otherwise treat it as a list of permitted host:port */
	क्रम (i = 0; i < अंक_opens; i++) {
		oarg = arg = xstrdup(opens[i]);
		addr = hpdelim(&arg);
		अगर (addr == शून्य)
			fatal_f("missing host in %s", what);
		addr = cleanhostname(addr);
		अगर (arg == शून्य || ((port = permitopen_port(arg)) < 0))
			fatal_f("bad port number in %s", what);
		/* Send it to channels layer */
		channel_add_permission(ssh, FORWARD_ADM,
		    where, addr, port);
		मुक्त(oarg);
	}
}

अटल व्योम
ssh_init_forwarding(काष्ठा ssh *ssh, अक्षर **ifname)
{
	पूर्णांक success = 0;
	पूर्णांक i;

	ssh_init_forward_permissions(ssh, "permitremoteopen",
	    options.permitted_remote_opens,
	    options.अंक_permitted_remote_opens);

	अगर (options.exit_on_forward_failure)
		forward_confirms_pending = 0; /* track pending requests */
	/* Initiate local TCP/IP port forwardings. */
	क्रम (i = 0; i < options.अंक_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != शून्य) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == शून्य) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != शून्य) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(ssh,
		    &options.local_forwards[i], &options.fwd_opts);
	}
	अगर (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	अगर (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	क्रम (i = 0; i < options.अंक_remote_forwards; i++) {
		काष्ठा rfwd_confirm_ctx *rctx;

		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != शून्य) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == शून्य) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != शून्य) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		अगर ((options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(ssh,
		    &options.remote_forwards[i])) >= 0) {
			rctx = xcalloc(1, माप(*rctx));
			rctx->fid = i;
			client_register_global_confirm(
			    ssh_confirm_remote_forward, rctx);
			forward_confirms_pending++;
		} अन्यथा अगर (options.exit_on_forward_failure)
			fatal("Could not request remote forwarding.");
		अन्यथा
			logit("Warning: Could not request remote forwarding.");
	}

	/* Initiate tunnel forwarding. */
	अगर (options.tun_open != SSH_TUNMODE_NO) {
		अगर ((*ifname = client_request_tun_fwd(ssh,
		    options.tun_open, options.tun_local,
		    options.tun_remote, ssh_tun_confirm, शून्य)) != शून्य)
			forward_confirms_pending++;
		अन्यथा अगर (options.exit_on_forward_failure)
			fatal("Could not request tunnel forwarding.");
		अन्यथा
			error("Could not request tunnel forwarding.");
	}
	अगर (forward_confirms_pending > 0) {
		debug_f("expecting replies for %d forwards",
		    forward_confirms_pending);
	}
}

अटल व्योम
check_agent_present(व्योम)
{
	पूर्णांक r;

	अगर (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		अगर ((r = ssh_get_authentication_socket(शून्य)) != 0) {
			options.forward_agent = 0;
			अगर (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug_r(r, "ssh_get_authentication_socket");
		}
	}
}

अटल व्योम
ssh_session2_setup(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक success, व्योम *arg)
{
	बाह्य अक्षर **environ;
	स्थिर अक्षर *display, *term;
	अक्षर *proto = शून्य, *तथ्य = शून्य;

	अगर (!success)
		वापस; /* No need for error message, channels code sends one */

	display = दो_पर्या("DISPLAY");
	अगर (display == शून्य && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	अगर (options.forward_x11 && client_x11_get_proto(ssh, display,
	    options.xauth_location, options.forward_x11_trusted,
	    options.forward_x11_timeout, &proto, &तथ्य) == 0) {
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(ssh, id, display, proto,
		    तथ्य, 1);
		client_expect_confirm(ssh, id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
	}

	check_agent_present();
	अगर (options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	अगर ((term = lookup_env_in_list("TERM", options.setenv,
	    options.अंक_setenv)) == शून्य || *term == '\0')
		term = दो_पर्या("TERM");
	client_session2_setup(ssh, id, tty_flag,
	    options.session_type == SESSION_TYPE_SUBSYSTEM, term,
	    शून्य, fileno(मानक_निवेश), command, environ);
}

/* open new channel for a session */
अटल पूर्णांक
ssh_session2_open(काष्ठा ssh *ssh)
{
	Channel *c;
	पूर्णांक window, packetmax, in, out, err;

	अगर (options.stdin_null) {
		in = खोलो(_PATH_DEVNULL, O_RDONLY);
	} अन्यथा {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	अगर (in == -1 || out == -1 || err == -1)
		fatal("dup() in/out/err failed");

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	अगर (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	c = channel_new(ssh,
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", CHANNEL_NONBLOCK_STDIO);
	अगर (tty_flag)
		channel_set_tty(ssh, c);
	debug3_f("channel_new: %d%s", c->self, tty_flag ? " (tty)" : "");

	channel_send_open(ssh, c->self);
	अगर (options.session_type != SESSION_TYPE_NONE)
		channel_register_open_confirm(ssh, c->self,
		    ssh_session2_setup, शून्य);

	वापस c->self;
}

अटल पूर्णांक
ssh_session2(काष्ठा ssh *ssh, स्थिर काष्ठा ssh_conn_info *cinfo)
{
	पूर्णांक r, id = -1;
	अक्षर *cp, *tun_fwd_ifname = शून्य;

	/* XXX should be pre-session */
	अगर (!options.control_persist)
		ssh_init_stdio_forwarding(ssh);

	ssh_init_forwarding(ssh, &tun_fwd_ifname);

	अगर (options.local_command != शून्य) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(cinfo),
		    "T", tun_fwd_ifname == शून्य ? "NONE" : tun_fwd_ifname,
		    (अक्षर *)शून्य);
		debug3("expanded LocalCommand: %s", options.local_command);
		मुक्त(cp);
	}

	/* Start listening for multiplex clients */
	अगर (!ssh_packet_get_mux(ssh))
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
	अगर (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = options.stdin_null;
		osession_type = options.session_type;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
		ofork_after_authentication = options.fork_after_authentication;
		options.stdin_null = 1;
		options.session_type = SESSION_TYPE_NONE;
		tty_flag = 0;
		अगर ((osession_type != SESSION_TYPE_NONE ||
		    options.stdio_forward_host != शून्य))
			need_controlpersist_detach = 1;
		options.fork_after_authentication = 1;
	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	अगर (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding(ssh);

	अगर (options.session_type != SESSION_TYPE_NONE)
		id = ssh_session2_open(ssh);

	/* If we don't expect to open a new session, then disallow it */
	अगर (options.control_master == SSHCTL_MASTER_NO &&
	    (ssh->compat & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		अगर ((r = sshpkt_start(ssh, SSH2_संदेश_GLOBAL_REQUEST)) != 0 ||
		    (r = sshpkt_put_cstring(ssh,
		    "no-more-sessions@openssh.com")) != 0 ||
		    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send packet");
	}

	/* Execute a local command */
	अगर (options.local_command != शून्य &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * stdout is now owned by the session channel; clobber it here
	 * so future channel closes are propagated to the local fd.
	 * NB. this can only happen after LocalCommand has completed,
	 * as it may want to write to stdout.
	 */
	अगर (!need_controlpersist_detach && stdfd_devnull(0, 1, 0) == -1)
		error_f("stdfd_devnull failed");

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	अगर (options.fork_after_authentication) {
		अगर (options.exit_on_forward_failure &&
		    options.अंक_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} अन्यथा
			fork_postauth();
	}

	वापस client_loop(ssh, tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

/* Loads all IdentityFile and CertificateFile keys */
अटल व्योम
load_public_identity_files(स्थिर काष्ठा ssh_conn_info *cinfo)
{
	अक्षर *filename, *cp;
	काष्ठा sshkey *खुला;
	पूर्णांक i;
	u_int n_ids, n_certs;
	अक्षर *identity_files[SSH_MAX_IDENTITY_FILES];
	काष्ठा sshkey *identity_कुंजियाँ[SSH_MAX_IDENTITY_FILES];
	पूर्णांक identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	अक्षर *certificate_files[SSH_MAX_CERTIFICATE_FILES];
	काष्ठा sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];
	पूर्णांक certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
#अगर_घोषित ENABLE_PKCS11
	काष्ठा sshkey **कुंजियाँ = शून्य;
	अक्षर **comments = शून्य;
	पूर्णांक nkeys;
#पूर्ण_अगर /* PKCS11 */

	n_ids = n_certs = 0;
	स_रखो(identity_files, 0, माप(identity_files));
	स_रखो(identity_कुंजियाँ, 0, माप(identity_कुंजियाँ));
	स_रखो(identity_file_userprovided, 0,
	    माप(identity_file_userprovided));
	स_रखो(certificate_files, 0, माप(certificate_files));
	स_रखो(certificates, 0, माप(certificates));
	स_रखो(certificate_file_userprovided, 0,
	    माप(certificate_file_userprovided));

#अगर_घोषित ENABLE_PKCS11
	अगर (options.pkcs11_provider != शून्य &&
	    options.अंक_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, शून्य,
	    &कुंजियाँ, &comments)) > 0) {
		क्रम (i = 0; i < nkeys; i++) {
			अगर (n_ids >= SSH_MAX_IDENTITY_FILES) {
				sshkey_free(कुंजियाँ[i]);
				मुक्त(comments[i]);
				जारी;
			}
			identity_कुंजियाँ[n_ids] = कुंजियाँ[i];
			identity_files[n_ids] = comments[i]; /* transferred */
			n_ids++;
		}
		मुक्त(कुंजियाँ);
		मुक्त(comments);
	}
#पूर्ण_अगर /* ENABLE_PKCS11 */
	क्रम (i = 0; i < options.अंक_identity_files; i++) {
		अगर (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			मुक्त(options.identity_files[i]);
			options.identity_files[i] = शून्य;
			जारी;
		}
		cp = tilde_expand_filename(options.identity_files[i], getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		मुक्त(cp);
		check_load(sshkey_load_public(filename, &खुला, शून्य),
		    &खुला, filename, "pubkey");
		debug("identity file %s type %d", filename,
		    खुला ? खुला->type : -1);
		मुक्त(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_कुंजियाँ[n_ids] = खुला;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		अगर (++n_ids >= SSH_MAX_IDENTITY_FILES)
			जारी;

		/*
		 * If no certificates have been explicitly listed then try
		 * to add the default certificate variant too.
		 */
		अगर (options.अंक_certificate_files != 0)
			जारी;
		xasprintf(&cp, "%s-cert", filename);
		check_load(sshkey_load_public(cp, &खुला, शून्य),
		    &खुला, filename, "identity pubkey");
		अगर (खुला == शून्य) {
			मुक्त(cp);
			जारी;
		}
		अगर (!sshkey_is_cert(खुला)) {
			debug_f("key %s type %s is not a certificate",
			    cp, sshkey_type(खुला));
			sshkey_free(खुला);
			मुक्त(cp);
			जारी;
		}
		मुक्त(cp);
		/* NB. leave filename pointing to private key */
		identity_files[n_ids] = xstrdup(filename);
		identity_कुंजियाँ[n_ids] = खुला;
		identity_file_userprovided[n_ids] =
		    options.identity_file_userprovided[i];
		n_ids++;
	}

	अगर (options.अंक_certificate_files > SSH_MAX_CERTIFICATE_FILES)
		fatal_f("too many certificates");
	क्रम (i = 0; i < options.अंक_certificate_files; i++) {
		cp = tilde_expand_filename(options.certificate_files[i],
		    getuid());
		filename = default_client_percent_dollar_expand(cp, cinfo);
		मुक्त(cp);

		check_load(sshkey_load_public(filename, &खुला, शून्य),
		    &खुला, filename, "identity cert");
		मुक्त(options.certificate_files[i]);
		options.certificate_files[i] = शून्य;
		अगर (खुला == शून्य) {
			मुक्त(filename);
			जारी;
		}
		अगर (!sshkey_is_cert(खुला)) {
			debug_f("key %s type %s is not a certificate",
			    filename, sshkey_type(खुला));
			sshkey_free(खुला);
			मुक्त(filename);
			जारी;
		}
		certificate_files[n_certs] = filename;
		certificates[n_certs] = खुला;
		certificate_file_userprovided[n_certs] =
		    options.certificate_file_userprovided[i];
		++n_certs;
	}

	options.अंक_identity_files = n_ids;
	स_नकल(options.identity_files, identity_files, माप(identity_files));
	स_नकल(options.identity_कुंजियाँ, identity_कुंजियाँ, माप(identity_कुंजियाँ));
	स_नकल(options.identity_file_userprovided,
	    identity_file_userprovided, माप(identity_file_userprovided));

	options.अंक_certificate_files = n_certs;
	स_नकल(options.certificate_files,
	    certificate_files, माप(certificate_files));
	स_नकल(options.certificates, certificates, माप(certificates));
	स_नकल(options.certificate_file_userprovided,
	    certificate_file_userprovided,
	    माप(certificate_file_userprovided));
}

अटल व्योम
main_sigchld_handler(पूर्णांक sig)
{
	पूर्णांक save_errno = त्रुटि_सं;
	pid_t pid;
	पूर्णांक status;

	जबतक ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && त्रुटि_सं == EINTR))
		;
	त्रुटि_सं = save_errno;
}
