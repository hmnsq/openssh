/* $OpenBSD: readconf.c,v 1.419 2026/10/05 06:03:40 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/wait.h>
#ضمن <sys/un.h>

#ضمن <net/if.h>
#ضمن <netinet/in.h>
#ضمن <netinet/ip.h>
#ضمن <arpa/inet.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <glob.h>
#ضمن <ifaddrs.h>
#ضمن <limits.h>
#ضمن <netdb.h>
#ضمن <paths.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <unistd.h>
#ضمن <util.h>
#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "cipher.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "sshkey.h"
#ضمن "misc.h"
#ضمن "readconf.h"
#ضمن "match.h"
#ضمن "kex.h"
#ضمن "mac.h"
#ضمن "myproposal.h"
#ضمن "digest.h"
#ضمن "version.h"

/* Format of the configuration file:

   # Configuration data is parsed as follows:
   #  1. command line options
   #  2. user-specific file
   #  3. system-wide file
   # Any configuration value is only changed the first time it is set.
   # Thus, host-specific definitions should be at the beginning of the
   # configuration file, and defaults at the end.

   # Host-specific declarations.  These may override anything above.  A single
   # host may match multiple declarations; these are processed in the order
   # that they are given in.

   Host *.ngs.fi ngs.fi
     User foo

   Host fake.com
     Hostname another.host.name.real.org
     User blaah
     Port 34289
     ForwardX11 no
     ForwardAgent no

   Host books.com
     RemoteForward 9999 shadows.cs.hut.fi:9999
     Ciphers 3des-cbc

   Host fascist.blob.com
     Port 23123
     User tylonen
     PasswordAuthentication no

   Host puukko.hut.fi
     User t35124p
     ProxyCommand ssh-proxy %h %p

   Host *.fr
     PublicKeyAuthentication no

   Host *.su
     Ciphers aes128-ctr
     PasswordAuthentication no

   Host vpn.fake.com
     Tunnel yes
     TunnelDevice 3

   # Defaults for various options
   Host *
     ForwardAgent no
     ForwardX11 no
     PasswordAuthentication yes
     StrictHostKeyChecking yes
     TcpKeepAlive no
     IdentityFile ~/.ssh/identity
     Port 22
     EscapeChar ~

*/

ساكن صحيح read_config_file_depth(ثابت حرف *filename, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحيح flags, صحيح *activep, صحيح *want_final_pass, صحيح depth);
ساكن صحيح process_config_قۇر_depth(Options *options, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    حرف *قۇر, ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags,
    صحيح *want_final_pass, صحيح depth);

/* Keyword tokens. */

تعريفنوع تعداد {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_ئاچقۇچلار_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_ئاچقۇچ_Checking, oCompression,
	oTCPKeepAlive, o_سان_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_ئاچقۇچ_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_ئاچقۇچ_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_ئاچقۇچ_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_سانى_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_ئاچقۇچ,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_ئاچقۇچلار,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_ئاچقۇچ_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ساكن بنية {
	ثابت حرف *name;
	OpCodes opcode;
} keywords[] = {
	/* Deprecated options */
	{ "protocol", oIgnore }, /* NB. silently ignored */
	{ "cipher", oDeprecated },
	{ "fallbacktorsh", oDeprecated },
	{ "globalknownhostsfile2", oDeprecated },
	{ "rhostsauthentication", oDeprecated },
	{ "userknownhostsfile2", oDeprecated },
	{ "useroaming", oDeprecated },
	{ "usersh", oDeprecated },
	{ "useprivilegedport", oDeprecated },

	/* Unsupported options */
	{ "afstokenpassing", oUnsupported },
	{ "kerberosauthentication", oUnsupported },
	{ "kerberostgtpassing", oUnsupported },
	{ "rsaauthentication", oUnsupported },
	{ "rhostsrsaauthentication", oUnsupported },
	{ "compressionlevel", oUnsupported },

	/* Sometimes-unsupported options */
#إذا defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# وإلا
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# وإلا
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#endif

	{ "forwardagent", oForwardAgent },
	{ "forwardx11", oForwardX11 },
	{ "forwardx11trusted", oForwardX11Trusted },
	{ "forwardx11timeout", oForwardX11Timeout },
	{ "exitonforwardfailure", oExitOnForwardFailure },
	{ "xauthlocation", oXAuthLocation },
	{ "gatewayports", oGatewayPorts },
	{ "passwordauthentication", oPasswordAuthentication },
	{ "kbdinteractiveauthentication", oKbdInteractiveAuthentication },
	{ "kbdinteractivedevices", oKbdInteractiveDevices },
	{ "challengeresponseauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "skeyauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "tisauthentication", oKbdInteractiveAuthentication },  /* alias */
	{ "pubkeyauthentication", oPubkeyAuthentication },
	{ "dsaauthentication", oPubkeyAuthentication },		    /* alias */
	{ "hostbasedauthentication", oHostbasedAuthentication },
	{ "identityfile", oIdentityFile },
	{ "identityfile2", oIdentityFile },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_Add_ئاچقۇچلار_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_ئاچقۇچ_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", oPort },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", oMatch },
	{ "tag", oTag },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", oGlobalKnownHostsFile },
	{ "userknownhostsfile", oUserKnownHostsFile },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", oBatchMode },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_ئاچقۇچ_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_سان_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_ئاچقۇچ_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_ئاچقۇچ_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_سانى_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", oSetEnv },
	{ "controlpath", oControlPath },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", oHashKnownHosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_ئاچقۇچ },
	{ "kexalgorithms", oKexAlgorithms },
	{ "ipqos", oIPQoS },
	{ "requesttty", oRequestTTY },
	{ "sessiontype", oSessionType },
	{ "stdinnull", oStdinNull },
	{ "forkafterauthentication", oForkAfterAuthentication },
	{ "proxyusefdpass", oProxyUseFdpass },
	{ "canonicaldomains", oCanonicalDomains },
	{ "canonicalizefallbacklocal", oCanonicalizeFallbackLocal },
	{ "canonicalizehostname", oCanonicalizeHostname },
	{ "canonicalizemaxdots", oCanonicalizeMaxDots },
	{ "canonicalizepermittedcnames", oCanonicalizePermittedCNAMEs },
	{ "streamlocalbindmask", oStreamLocalBindMask },
	{ "streamlocalbindunlink", oStreamLocalBindUnlink },
	{ "revokedhostkeys", o_Revoked_Host_ئاچقۇچلار },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_ئاچقۇچ_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ عدم, oBadOption }
};

ساكن ثابت حرف *lookup_opcode_name(OpCodes code);

ثابت حرف *
kex_default_pk_alg(فراغ)
{
	ساكن حرف *pkalgs;

	إذا (pkalgs == عدم) {
		حرف *all_ئاچقۇچ;

		all_ئاچقۇچ = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ئاچقۇچ);
		حرر(all_ئاچقۇچ);
	}
	أرجع pkalgs;
}

حرف *
ssh_connection_hash(ثابت حرف *thishost, ثابت حرف *host, ثابت حرف *portstr,
    ثابت حرف *user, ثابت حرف *jumphost)
{
	بنية ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	إذا ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == عدم ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, حجم(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	أرجع tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

فراغ
add_local_forward(Options *options, ثابت بنية Forward *newfwd)
{
	بنية Forward *fwd;
	صحيح i;

	/* Don't add duplicates */
	لكل (i = 0; i < options->رەقەم_local_forwards; i++) {
		إذا (forward_equals(newfwd, options->local_forwards + i))
			أرجع;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->رەقەم_local_forwards + 1,
	    حجم(*options->local_forwards));
	fwd = &options->local_forwards[options->رەقەم_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

فراغ
add_remote_forward(Options *options, ثابت بنية Forward *newfwd)
{
	بنية Forward *fwd;
	صحيح i;

	/* Don't add duplicates */
	لكل (i = 0; i < options->رەقەم_remote_forwards; i++) {
		إذا (forward_equals(newfwd, options->remote_forwards + i))
			أرجع;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->رەقەم_remote_forwards + 1,
	    حجم(*options->remote_forwards));
	fwd = &options->remote_forwards[options->رەقەم_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

ساكن فراغ
clear_forwardings(Options *options)
{
	صحيح i;

	لكل (i = 0; i < options->رەقەم_local_forwards; i++) {
		حرر(options->local_forwards[i].listen_host);
		حرر(options->local_forwards[i].listen_path);
		حرر(options->local_forwards[i].connect_host);
		حرر(options->local_forwards[i].connect_path);
	}
	إذا (options->رەقەم_local_forwards > 0) {
		حرر(options->local_forwards);
		options->local_forwards = عدم;
	}
	options->رەقەم_local_forwards = 0;
	لكل (i = 0; i < options->رەقەم_remote_forwards; i++) {
		حرر(options->remote_forwards[i].listen_host);
		حرر(options->remote_forwards[i].listen_path);
		حرر(options->remote_forwards[i].connect_host);
		حرر(options->remote_forwards[i].connect_path);
	}
	إذا (options->رەقەم_remote_forwards > 0) {
		حرر(options->remote_forwards);
		options->remote_forwards = عدم;
	}
	options->رەقەم_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

فراغ
add_certificate_file(Options *options, ثابت حرف *path, صحيح userprovided)
{
	صحيح i;

	إذا (options->رەقەم_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	لكل (i = 0; i < options->رەقەم_certificate_files; i++) {
		إذا (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			أرجع;
		}
	}

	options->certificate_file_userprovided[options->رەقەم_certificate_files] =
	    userprovided;
	options->certificate_files[options->رەقەم_certificate_files++] =
	    xstrdup(path);
}

فراغ
add_identity_file(Options *options, ثابت حرف *dir, ثابت حرف *filename,
    صحيح userprovided)
{
	حرف *path;
	صحيح i;

	إذا (options->رەقەم_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	إذا (dir == عدم) /* no dir, filename is absolute */
		path = xstrdup(filename);
	وإلا إذا (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	لكل (i = 0; i < options->رەقەم_identity_files; i++) {
		إذا (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			حرر(path);
			أرجع;
		}
	}

	options->identity_file_userprovided[options->رەقەم_identity_files] =
	    userprovided;
	options->identity_files[options->رەقەم_identity_files++] = path;
}

صحيح
default_ssh_port(فراغ)
{
	ساكن صحيح port;
	بنية servent *sp;

	إذا (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	أرجع port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ساكن صحيح
execute_in_shell(ثابت حرف *cmd)
{
	حرف *shell;
	pid_t pid;
	صحيح status;

	إذا ((shell = getenv("SHELL")) == عدم)
		shell = _PATH_BSHELL;

	إذا (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	إذا ((pid = fork()) == 0) {
		حرف *argv[4];

		إذا (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = عدم;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	إذا (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	طالما (waitpid(pid, &status, 0) == -1) {
		إذا (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	إذا (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		أرجع -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	أرجع WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ساكن صحيح
check_match_ifaddrs(ثابت حرف *addrlist)
{
#ifdef HAVE_IFADDRS_H
	بنية ifaddrs *ifa, *ifaddrs = عدم;
	صحيح r, found = 0;
	حرف addr[NI_MAXHOST];
	socklen_t salen;

	إذا (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		أرجع 0;
	}
	لكل (ifa = ifaddrs; ifa != عدم; ifa = ifa->ifa_next) {
		إذا (ifa->ifa_addr == عدم || ifa->ifa_name == عدم ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			استمر;
		بدل (ifa->ifa_addr->sa_family) {
		حالة AF_INET:
			salen = حجم(بنية sockaddr_in);
			اكسر;
		حالة AF_INET6:
			salen = حجم(بنية sockaddr_in6);
			اكسر;
#ifdef AF_LINK
		حالة AF_LINK:
			/* ignore */
			استمر;
#endif /* AF_LINK */
		افتراضي:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			استمر;
		}
		إذا ((r = getnameinfo(ifa->ifa_addr, salen, addr, حجم(addr),
		    عدم, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			استمر;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		إذا (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			اكسر;
		}
	}
	freeifaddrs(ifaddrs);
	أرجع found;
#وإلا /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	أرجع 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ساكن حرف *
expand_match_exec_or_include_path(ثابت حرف *path, Options *options,
    بنية passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    صحيح final_pass, صحيح is_include_path)
{
	حرف thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	حرف uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	حرف *host, *ret;
	صحيح port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == عدم ? pw->pw_name : options->user;
	إذا (final_pass) {
		host = xstrdup(options->hostname);
	} وإلا إذا (options->hostname != عدم) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (حرف *)عدم);
	} وإلا {
		host = xstrdup(host_arg);
	}
	إذا (gethostname(thishost, حجم(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, حجم(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, حجم(portstr), "%d", port);
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_ئاچقۇچ_alias ?  options->host_ئاچقۇچ_alias : host;

	ret = (is_include_path ? percent_dollar_expand : percent_expand)(path,
	    "C", conn_hash_hex,
	    "L", shorthost,
	    "d", pw->pw_dir,
	    "h", host,
	    "k", keyalias,
	    "l", thishost,
	    "n", original_host,
	    "p", portstr,
	    "r", ruser,
	    "u", pw->pw_name,
	    "i", uidstr,
	    "j", jmphost,
	    (حرف *)عدم);
	حرر(host);
	حرر(conn_hash_hex);
	أرجع ret;
}

/*
 * Parse and execute a Match directive.
 */
ساكن صحيح
match_cfg_قۇر(Options *options, ثابت حرف *full_قۇر, صحيح *acp, حرف ***avp,
    بنية passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    ثابت حرف *remote_command, صحيح final_pass, صحيح *want_final_pass,
    ثابت حرف *filename, صحيح linenum)
{
	حرف *arg, *oattrib = عدم, *attrib = عدم, *cmd, *host, *criteria;
	ثابت حرف *ruser;
	صحيح r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == عدم ? pw->pw_name : options->user;
	إذا (final_pass) {
		host = xstrdup(options->hostname);
	} وإلا إذا (options->hostname != عدم) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (حرف *)عدم);
	} وإلا {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_قۇر, host, original_host);
	طالما ((attrib = argv_next(acp, avp)) != عدم) {
		/* Terminate on comment */
		إذا (*attrib == '#') {
			argv_consume(acp);
			اكسر;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = عدم;
		this_result = 1;
		إذا ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		إذا (strcasecmp(attrib, "all") == 0) {
			إذا (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != عدم &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				اذهب out;
			}
			إذا (arg != عدم && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			إذا (result)
				result = negate ? 0 : 1;
			اذهب out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		إذا (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			إذا (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != عدم)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			اذهب next;
		}

		/* Keep this list in sync with below */
		إذا (strprefix(attrib, "host=", 1)  != عدم ||
		    strprefix(attrib, "originalhost=", 1) != عدم ||
		    strprefix(attrib, "user=", 1) != عدم ||
		    strprefix(attrib, "localuser=", 1) != عدم ||
		    strprefix(attrib, "localnetwork=", 1) != عدم ||
		    strprefix(attrib, "version=", 1) != عدم ||
		    strprefix(attrib, "tagged=", 1) != عدم ||
		    strprefix(attrib, "command=", 1) != عدم ||
		    strprefix(attrib, "exec=", 1) != عدم) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} وإلا إذا ((arg = argv_next(acp, avp)) == عدم) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			اذهب out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		إذا (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = عدم;
		إذا (arg == عدم || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			اذهب out;
		}
		إذا (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "localnetwork") == 0) {
			إذا (addr_match_cidr_list(عدم, arg) == -1) {
				/* Error already printed */
				result = -1;
				اذهب out;
			}
			r = check_match_ifaddrs(arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == عدم ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == عدم ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "sessiontype") == 0) {
			إذا (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			وإلا إذا (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			وإلا إذا (remote_command != عدم &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			وإلا
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا إذا (strcasecmp(attrib, "exec") == 0) {
			إذا ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == عدم) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			إذا (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				حرر(cmd);
				اذهب next;
			}
			r = execute_in_shell(cmd);
			إذا (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			حرر(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			إذا (r == (negate ? 1 : 0))
				this_result = result = 0;
		} وإلا {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			اذهب out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == عدم ? "" : " \"",
		    criteria == عدم ? "" : criteria,
		    criteria == عدم ? "" : "\"");
 next:
		حرر(criteria);
		حرر(oattrib);
		oattrib = attrib = عدم;
	}
	إذا (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		اذهب out;
	}
 out:
	إذا (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	حرر(oattrib);
	حرر(host);
	أرجع result;
}

/* Remove environment variable by pattern */
ساكن فراغ
rm_env(Options *options, ثابت حرف *arg, ثابت حرف *filename, صحيح linenum)
{
	u_int i, j, onum_send_env = options->رەقەم_send_env;

	/* Remove an environment variable */
	لكل (i = 0; i < options->رەقەم_send_env; ) {
		إذا (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			استمر;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		حرر(options->send_env[i]);
		options->send_env[i] = عدم;
		لكل (j = i; j < options->رەقەم_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = عدم;
		}
		options->رەقەم_send_env--;
		/* NB. don't increment i */
	}
	إذا (onum_send_env != options->رەقەم_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->رەقەم_send_env,
		    حجم(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ساكن OpCodes
parse_token(ثابت حرف *cp, ثابت حرف *filename, صحيح linenum,
    ثابت حرف *ignored_unknown)
{
	صحيح i;

	لكل (i = 0; keywords[i].name; i++)
		إذا (strcmp(cp, keywords[i].name) == 0)
			أرجع keywords[i].opcode;
	إذا (ignored_unknown != عدم &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		أرجع oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	أرجع oBadOption;
}

ساكن فراغ
free_canon_cnames(بنية allowed_cname *cnames, u_int n)
{
	u_int i;

	إذا (cnames == عدم || n == 0)
		أرجع;
	لكل (i = 0; i < n; i++) {
		حرر(cnames[i].source_list);
		حرر(cnames[i].target_list);
	}
	حرر(cnames);
}

/* Multistate option parsing */
بنية multistate {
	حرف *ئاچقۇچ;
	صحيح قىممەت;
};
ساكن ثابت بنية multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ عدم, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ساكن ثابت بنية multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ عدم, -1 }
};

ساكن صحيح
parse_multistate_قىممەت(ثابت حرف *arg, ثابت حرف *filename, صحيح linenum,
    ثابت بنية multistate *multistate_ptr)
{
	صحيح i;

	إذا (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		أرجع -1;
	}
	لكل (i = 0; multistate_ptr[i].ئاچقۇچ != عدم; i++) {
		إذا (strcasecmp(arg, multistate_ptr[i].ئاچقۇچ) == 0)
			أرجع multistate_ptr[i].قىممەت;
	}
	أرجع -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
صحيح
process_config_قۇر(Options *options, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *قۇر,
    ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags)
{
	أرجع process_config_قۇر_depth(options, pw, host, original_host,
	    remote_command, قۇر, filename, linenum, activep, flags, عدم, 0);
}

#define WHITESPACE " \t\r\n"
ساكن صحيح
process_config_قۇر_depth(Options *options, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *قۇر,
    ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags,
    صحيح *want_final_pass, صحيح depth)
{
	حرف *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	حرف **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	صحيح r, oactive, negated, opcode, *intptr, قىممەت, value2, cmdline = 0;
	صحيح remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	بنية Forward fwd;
	ثابت بنية multistate *multistate_ptr;
	glob_t gl;
	ثابت حرف *errstr;
	حرف **oav = عدم, **av;
	صحيح oac = 0, ac;
	صحيح ret = -1;
	بنية allowed_cname *cnames = عدم;
	u_int ncnames = 0;
	حرف **strs = عدم; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	إذا (activep == عدم) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	إذا ((len = strlen(قۇر)) == 0)
		أرجع 0;
	لكل (len--; len > 0; len--) {
		إذا (strchr(WHITESPACE "\f", قۇر[len]) == عدم)
			اكسر;
		قۇر[len] = '\0';
	}

	str = قۇر;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	إذا ((keyword = strdelim(&str)) == عدم)
		أرجع 0;
	/* Ignore leading whitespace. */
	إذا (*keyword == '\0')
		keyword = strdelim(&str);
	إذا (keyword == عدم || !*keyword || *keyword == '\n' || *keyword == '#')
		أرجع 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	إذا (str != عدم)
		str += strspn(str, WHITESPACE);
	إذا (str == عدم || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		أرجع -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	إذا (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		أرجع -1;
	}
	ac = oac;
	av = oav;

	بدل (opcode) {
	حالة oBadOption:
		/* don't panic, but count bad options */
		اذهب out;
	حالة oIgnore:
		argv_consume(&ac);
		اكسر;
	حالة oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		اكسر;
	حالة oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			اذهب out;
		}
		إذا (strcmp(arg, "none") == 0)
			قىممەت = -1;
		وإلا إذا ((قىممەت = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قىممەت;
		اكسر;

	حالة oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			اذهب out;
		}

		قىممەت = -1;
		multistate_ptr = multistate_flag;
		لكل (i = 0; multistate_ptr[i].ئاچقۇچ != عدم; i++) {
			إذا (strcasecmp(arg, multistate_ptr[i].ئاچقۇچ) == 0) {
				قىممەت = multistate_ptr[i].قىممەت;
				اكسر;
			}
		}
		إذا (قىممەت != -1) {
			إذا (*activep && *intptr == -1)
				*intptr = قىممەت;
			اكسر;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		إذا (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		اذهب parse_agent_path;

	حالة oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		إذا ((قىممەت = parse_multistate_قىممەت(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			اذهب out;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قىممەت;
		اكسر;

	حالة oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		اذهب parse_flag;

	حالة oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		اذهب parse_time;

	حالة oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		اذهب parse_flag;

	حالة oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		اذهب parse_flag;

	حالة oPasswordAuthentication:
		intptr = &options->password_authentication;
		اذهب parse_flag;

	حالة oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		اذهب parse_flag;

	حالة oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		اذهب parse_string;

	حالة oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		اذهب parse_multistate;

	حالة oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		اذهب parse_flag;

	حالة oGssAuthentication:
		intptr = &options->gss_authentication;
		اذهب parse_flag;

	حالة oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		اذهب parse_flag;

	حالة oBatchMode:
		intptr = &options->batch_mode;
		اذهب parse_flag;

	حالة oCheckHostIP:
		intptr = &options->check_host_ip;
		اذهب parse_flag;

	حالة o_Verify_Host_ئاچقۇچ_DNS:
		intptr = &options->verify_host_ئاچقۇچ_dns;
		multistate_ptr = multistate_yesnoask;
		اذهب parse_multistate;

	حالة o_Strict_Host_ئاچقۇچ_Checking:
		intptr = &options->strict_host_ئاچقۇچ_checking;
		multistate_ptr = multistate_strict_hostkey;
		اذهب parse_multistate;

	حالة oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		اذهب parse_multistate;

	حالة oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		اذهب parse_multistate;

	حالة oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		اذهب parse_flag;

	حالة o_سان_Of_Password_Prompts:
		intptr = &options->سان_of_password_prompts;
		اذهب parse_int;

	حالة oRekeyLimit:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			اذهب out;
		}
		إذا (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وإلا {
			إذا (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				اذهب out;
			}
			إذا (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				اذهب out;
			}
		}
		إذا (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		إذا (ac != 0) { /* optional rekey interval present */
			إذا (strcmp(av[0], "none") == 0) {
				(فراغ)argv_next(&ac, &av);	/* discard */
				اكسر;
			}
			intptr = &options->rekey_interval;
			اذهب parse_time;
		}
		اكسر;

	حالة oIdentityFile:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep) {
			intptr = &options->رەقەم_identity_files;
			إذا (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				اذهب out;
			}
			add_identity_file(options, عدم,
			    arg, flags & SSHCONF_USERCONF);
		}
		اكسر;

	حالة oCertificateFile:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep) {
			intptr = &options->رەقەم_certificate_files;
			إذا (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				اذهب out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		اكسر;

	حالة oXAuthLocation:
		charptr=&options->xauth_location;
		اذهب parse_string;

	حالة oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة oGlobalKnownHostsFile:
		cpptr = (حرف **)&options->system_hostfiles;
		uintptr = &options->رەقەم_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		قىممەت = *uintptr == 0; /* was array empty when we started? */
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			}
			i++;
			إذا (*activep && قىممەت) {
				إذا ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					اذهب out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		اكسر;

	حالة oUserKnownHostsFile:
		cpptr = (حرف **)&options->user_hostfiles;
		uintptr = &options->رەقەم_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		اذهب parse_char_array;

	حالة oHostname:
		charptr = &options->hostname;
		اذهب parse_string;

	حالة oTag:
		charptr = &options->tag;
		اذهب parse_string;

	حالة o_Host_ئاچقۇچ_Alias:
		charptr = &options->host_ئاچقۇچ_alias;
		اذهب parse_string;

	حالة oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		اذهب parse_string;

	حالة oBindAddress:
		charptr = &options->bind_address;
		اذهب parse_string;

	حالة oBindInterface:
		charptr = &options->bind_interface;
		اذهب parse_string;

	حالة oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		اذهب parse_string;

	حالة o_Security_ئاچقۇچ_Provider:
		charptr = &options->sk_provider;
		اذهب parse_string;

	حالة oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		اذهب parse_command;

	حالة oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		إذا (str == عدم) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		len = strspn(str, WHITESPACE "=");
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		اكسر;

	حالة oProxyJump:
		إذا (str == عدم) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		إذا (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			اذهب out;
		}
		argv_consume(&ac);
		اكسر;

	حالة oPort:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		قىممەت = a2port(arg);
		إذا (قىممەت <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			اذهب out;
		}
		إذا (*activep && options->port == -1)
			options->port = قىممەت;
		اكسر;

	حالة oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		إذا ((errstr = atoi_err(arg, &قىممەت)) != عدم) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			اذهب out;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قىممەت;
		اكسر;

	حالة oCiphers:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب out;
		}
		إذا (*activep && options->ciphers == عدم)
			options->ciphers = xstrdup(arg);
		اكسر;

	حالة oMacs:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب out;
		}
		إذا (*activep && options->macs == عدم)
			options->macs = xstrdup(arg);
		اكسر;

	حالة oKexAlgorithms:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب out;
		}
		إذا (*activep && options->kex_algorithms == عدم)
			options->kex_algorithms = xstrdup(arg);
		اكسر;

	حالة o_Host_ئاچقۇچ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب out;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		اذهب parse_pubkey_algos;

	حالة oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		قىممەت = log_level_سان(arg);
		إذا (قىممەت == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب out;
		}
		إذا (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) قىممەت;
		اكسر;

	حالة oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		قىممەت = log_facility_سان(arg);
		إذا (قىممەت == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب out;
		}
		إذا (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) قىممەت;
		اكسر;

	حالة oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->رەقەم_log_verbose;
		i = 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			}
			i++;
			إذا (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, حجم(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		اكسر;

	حالة oLocalForward:
	حالة oRemoteForward:
	حالة oDynamicForward:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		إذا (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			إذا (arg2 == عدم || *arg2 == '\0') {
				إذا (remotefwd)
					dynamicfwd = 1;
				وإلا {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					اذهب out;
				}
			} وإلا {
				/* construct a string for parse_forward */
				snprintf(fwdarg, حجم(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		إذا (dynamicfwd)
			strlcpy(fwdarg, arg, حجم(fwdarg));

		إذا (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			اذهب out;
		}

		إذا (*activep) {
			إذا (remotefwd) {
				add_remote_forward(options, &fwd);
			} وإلا {
				add_local_forward(options, &fwd);
			}
		}
		اكسر;

	حالة oPermitRemoteOpen:
		uintptr = &options->رەقەم_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			إذا (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					حرر(arg2);
					اذهب out;
				}
			} وإلا {
				p = hpdelim(&arg);
				إذا (p == عدم) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				إذا (arg == عدم || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			حرر(arg2);
		}
		إذا (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		إذا (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oClearAllForwardings:
		intptr = &options->clear_forwardings;
		اذهب parse_flag;

	حالة oHost:
		إذا (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			اذهب out;
		}
		*activep = 0;
		arg2 = عدم;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			إذا ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				اكسر;
			}
			negated = *arg == '!';
			إذا (negated)
				arg++;
			إذا (match_pattern(host, arg)) {
				إذا (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					اكسر;
				}
				إذا (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		إذا (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		اكسر;

	حالة oMatch:
		إذا (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			اذهب out;
		}
		قىممەت = match_cfg_قۇر(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		إذا (قىممەت < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			اذهب out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : قىممەت;
		اكسر;

	حالة oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (strcmp(arg, "none") == 0)
			قىممەت = SSH_ESCAPECHAR_NONE;
		وإلا إذا (arg[1] == '\0')
			قىممەت = (u_char) arg[0];
		وإلا إذا (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			قىممەت = (u_char) arg[1] & 31;
		وإلا {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قىممەت;
		اكسر;

	حالة oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		اذهب parse_multistate;

	حالة oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		اذهب parse_flag;

	حالة oIdentitiesOnly:
		intptr = &options->identities_only;
		اذهب parse_flag;

	حالة oServerAliveInterval:
		intptr = &options->server_alive_interval;
		اذهب parse_time;

	حالة o_Server_Alive_سانى_Max:
		intptr = &options->server_alive_سانى_max;
		اذهب parse_int;

	حالة oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') != عدم) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				اذهب out;
			}
			found = 1;
			إذا (!*activep)
				استمر;
			إذا (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				استمر;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->رەقەم_send_env, arg);
		}
		إذا (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة oSetEnv:
		found = options->رەقەم_setenv == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (strchr(arg, '=') == عدم) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				اذهب out;
			}
			إذا (lookup_setenv_in_list(arg, strs, nstrs) != عدم) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				استمر;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (found && *activep) {
			options->setenv = strs;
			options->رەقەم_setenv = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oControlPath:
		charptr = &options->control_path;
		اذهب parse_string;

	حالة oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		اذهب parse_multistate;

	حالة oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			اذهب out;
		}
		قىممەت = 0;
		value2 = 0;	/* timeout */
		إذا (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			قىممەت = 0;
		وإلا إذا (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			قىممەت = 1;
		وإلا إذا ((value2 = convtime(arg)) >= 0)
			قىممەت = 1;
		وإلا {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep && *intptr == -1) {
			*intptr = قىممەت;
			options->control_persist_timeout = value2;
		}
		اكسر;

	حالة oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		اذهب parse_flag;

	حالة oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		اذهب parse_multistate;

	حالة oTunnelDevice:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		قىممەت = a2tun(arg, &value2);
		إذا (قىممەت == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep && options->tun_local == -1) {
			options->tun_local = قىممەت;
			options->tun_remote = value2;
		}
		اكسر;

	حالة oLocalCommand:
		charptr = &options->local_command;
		اذهب parse_command;

	حالة oPermitLocalCommand:
		intptr = &options->permit_local_command;
		اذهب parse_flag;

	حالة oRemoteCommand:
		charptr = &options->remote_command;
		اذهب parse_command;

	حالة o_Visual_Host_ئاچقۇچ:
		intptr = &options->visual_host_ئاچقۇچ;
		اذهب parse_flag;

	حالة oInclude:
		إذا (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			اذهب out;
		}
		قىممەت = 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			/* Expand %tokens and environment variables */
			إذا ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == عدم) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				استمر;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			إذا (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				اذهب out;
			}
			إذا (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} وإلا {
				arg2 = xstrdup(p);
			}
			حرر(p);
			memset(&gl, 0, حجم(gl));
			r = glob(arg2, GLOB_TILDE, عدم, &gl);
			إذا (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				حرر(arg2);
				استمر;
			} وإلا إذا (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				اذهب out;
			}
			حرر(arg2);
			oactive = *activep;
			لكل (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				إذا (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					اذهب out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				إذا (r != 1)
					قىممەت = -1;
			}
			globfree(&gl);
		}
		إذا (قىممەت != 0)
			ret = قىممەت;
		اكسر;

	حالة oIPQoS:
		arg = argv_next(&ac, &av);
		إذا ((قىممەت = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			اذهب out;
		}
		إذا (قىممەت == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			قىممەت = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		إذا (arg == عدم)
			value2 = قىممەت;
		وإلا إذا ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			اذهب out;
		}
		إذا (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		إذا (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = قىممەت;
			options->ip_qos_bulk = value2;
		}
		اكسر;

	حالة oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		اذهب parse_multistate;

	حالة oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		اذهب parse_multistate;

	حالة oStdinNull:
		intptr = &options->stdin_null;
		اذهب parse_flag;

	حالة oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		اذهب parse_flag;

	حالة oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		اذهب parse_string;

	حالة oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		اذهب parse_flag;

	حالة oCanonicalDomains:
		found = options->رەقەم_canonical_domains == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			}
			إذا (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				اذهب out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (found && *activep) {
			options->canonical_domains = strs;
			options->رەقەم_canonical_domains = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oCanonicalizePermittedCNAMEs:
		found = options->رەقەم_permitted_cnames == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
				arg2 = "";
			} وإلا إذا (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} وإلا {
				lowercase(arg);
				إذا ((arg2 = strchr(arg, ':')) == عدم ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					اذهب out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    حجم(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		إذا (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (found && *activep) {
			options->permitted_cnames = cnames;
			options->رەقەم_permitted_cnames = ncnames;
			cnames = عدم; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		اكسر;

	حالة oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		اذهب parse_multistate;

	حالة oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		اذهب parse_int;

	حالة oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		اذهب parse_flag;

	حالة oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			اذهب out;
		}
		/* Parse mode in octal format */
		قىممەت = strtol(arg, &endofnumber, 8);
		إذا (arg == endofnumber || قىممەت < 0 || قىممەت > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			اذهب out;
		}
		إذا (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)قىممەت;
		اكسر;

	حالة oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		اذهب parse_flag;

	حالة o_Revoked_Host_ئاچقۇچلار:
		uintptr = &options->رەقەم_revoked_host_ئاچقۇچلار;
		cppptr = &options->revoked_host_ئاچقۇچلار;
		found = *uintptr == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا ((قىممەت = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			اذهب out;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قىممەت;
		اكسر;

	حالة oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		اذهب parse_multistate;

	حالة oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة o_Add_ئاچقۇچلار_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		قىممەت = parse_multistate_قىممەت(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		إذا (قىممەت == 3 && arg2 != عدم) {
			/* allow "AddKeysToAgent confirm 5m" */
			إذا ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				اذهب out;
			}
		} وإلا إذا (قىممەت == -1 && arg2 == عدم) {
			إذا ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				اذهب out;
			}
			قىممەت = 1; /* yes */
		} وإلا إذا (قىممەت == -1 || arg2 != عدم) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep && options->add_ئاچقۇچلار_to_agent == -1) {
			options->add_ئاچقۇچلار_to_agent = قىممەت;
			options->add_ئاچقۇچلار_to_agent_lifespan = value2;
		}
		اكسر;

	حالة oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		إذا ((arg2 = dollar_expand(&r, arg)) == عدم || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			اذهب out;
		}
		حرر(arg2);
		/* check for legacy environment format */
		إذا (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			اذهب out;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		اذهب parse_flag;

	حالة oRequiredRSASize:
		intptr = &options->required_rsa_size;
		اذهب parse_int;

	حالة oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		اذهب parse_multistate;

	حالة oObscureKeystrokeTiming:
		قىممەت = -1;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			إذا (قىممەت != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				اذهب out;
			}
			إذا (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				قىممەت = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			وإلا إذا (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				قىممەت = 0;
			وإلا إذا (strncmp(arg, "interval:", 9) == 0) {
				إذا ((errstr = atoi_err(arg + 9,
				    &قىممەت)) != عدم) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					اذهب out;
				}
				إذا (قىممەت <= 0 || قىممەت > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					اذهب out;
				}
			} وإلا {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				اذهب out;
			}
		}
		إذا (قىممەت == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			اذهب out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		إذا (*activep && *intptr == -1)
			*intptr = قىممەت;
		اكسر;

	حالة oChannelTimeout:
		found = options->رەقەم_channel_timeouts == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			} وإلا إذا (parse_pattern_interval(arg,
			    عدم, عدم) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (found && *activep) {
			options->channel_timeouts = strs;
			options->رەقەم_channel_timeouts = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oVersionAddendum:
		إذا (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		إذا (strchr(str + len, '\r') != عدم) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		إذا ((arg = strchr(قۇر, '#')) != عدم) {
			*arg = '\0';
			rtrim(قۇر);
		}
		إذا (*activep && options->version_addendum == عدم) {
			إذا (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			وإلا
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		اكسر;

	حالة oRefuseConnection:
		arg = argv_next(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب out;
		}
		إذا (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		اكسر;

	حالة oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		اكسر;

	حالة oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		اكسر;

	افتراضي:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		اذهب out;
	}

	/* Check that there is no garbage at end of line. */
	إذا (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		اذهب out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, عدم, nstrs);
	argv_free(oav, oac);
	أرجع ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
صحيح
read_config_file(ثابت حرف *filename, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, Options *options, صحيح flags,
    صحيح *want_final_pass)
{
	صحيح active = 1;

	أرجع read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
ساكن صحيح
read_config_file_depth(ثابت حرف *filename, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحيح flags, صحيح *activep, صحيح *want_final_pass, صحيح depth)
{
	FILE *f;
	حرف *قۇر = عدم;
	size_t linesize = 0;
	صحيح linenum;
	صحيح bad_options = 0;

	إذا (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	إذا ((f = fopen(filename, "r")) == عدم)
		أرجع 0;

	إذا (flags & SSHCONF_CHECKPERM) {
		بنية stat sb;

		إذا (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		إذا (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	طالما (getline(&قۇر, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		إذا (process_config_قۇر_depth(options, pw, host, original_host,
		    remote_command, قۇر, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	حرر(قۇر);
	fclose(f);
	إذا (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	أرجع 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
صحيح
option_clear_or_none(ثابت حرف *o)
{
	أرجع o == عدم || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
صحيح
config_has_permitted_cnames(Options *options)
{
	إذا (options->رەقەم_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		أرجع 0;
	أرجع options->رەقەم_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

فراغ
initialize_options(Options * options)
{
	memset(options, 'X', حجم(*options));
	options->host_arg = عدم;
	options->forward_agent = -1;
	options->forward_agent_sock_path = عدم;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = عدم;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = عدم;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = عدم;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_ئاچقۇچ_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->سان_of_password_prompts = -1;
	options->ciphers = عدم;
	options->macs = عدم;
	options->kex_algorithms = عدم;
	options->hostkeyalgorithms = عدم;
	options->ca_sign_algorithms = عدم;
	options->رەقەم_identity_files = 0;
	memset(options->identity_ئاچقۇچلار, 0, حجم(options->identity_ئاچقۇچلار));
	options->رەقەم_certificate_files = 0;
	memset(options->certificates, 0, حجم(options->certificates));
	options->hostname = عدم;
	options->host_ئاچقۇچ_alias = عدم;
	options->proxy_command = عدم;
	options->jump_user = عدم;
	options->jump_host = عدم;
	options->jump_port = -1;
	options->jump_extra = عدم;
	options->user = عدم;
	options->escape_char = -1;
	options->رەقەم_system_hostfiles = 0;
	options->رەقەم_user_hostfiles = 0;
	options->local_forwards = عدم;
	options->رەقەم_local_forwards = 0;
	options->remote_forwards = عدم;
	options->رەقەم_remote_forwards = 0;
	options->permitted_remote_opens = عدم;
	options->رەقەم_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->رەقەم_log_verbose = 0;
	options->log_verbose = عدم;
	options->preferred_authentications = عدم;
	options->bind_address = عدم;
	options->bind_interface = عدم;
	options->pkcs11_provider = عدم;
	options->sk_provider = عدم;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_ئاچقۇچ_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_سانى_max = -1;
	options->send_env = عدم;
	options->رەقەم_send_env = 0;
	options->setenv = عدم;
	options->رەقەم_setenv = 0;
	options->control_path = عدم;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = عدم;
	options->permit_local_command = -1;
	options->remote_command = عدم;
	options->add_ئاچقۇچلار_to_agent = -1;
	options->add_ئاچقۇچلار_to_agent_lifespan = -1;
	options->identity_agent = عدم;
	options->visual_host_ئاچقۇچ = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = عدم;
	options->رەقەم_canonical_domains = 0;
	options->رەقەم_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_ئاچقۇچلار = عدم;
	options->رەقەم_revoked_host_ئاچقۇچلار = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = عدم;
	options->pubkey_accepted_algos = عدم;
	options->known_hosts_command = عدم;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = عدم;
	options->channel_timeouts = عدم;
	options->رەقەم_channel_timeouts = 0;
	options->version_addendum = عدم;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
فراغ
fill_default_options_for_canonicalization(Options *options)
{
	إذا (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	إذا (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	إذا (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
صحيح
fill_default_options(Options * options)
{
	حرف *all_cipher, *all_mac, *all_kex, *all_ئاچقۇچ, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_ئاچقۇچ, *def_sig;
	صحيح ret = -1, r;

	إذا (options->forward_agent == -1)
		options->forward_agent = 0;
	إذا (options->forward_x11 == -1)
		options->forward_x11 = 0;
	إذا (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	إذا (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	إذا (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != عدم ? 1 : 0;
	إذا (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != عدم ? 1 : 0;
	إذا (options->clear_forwardings == 1)
		clear_forwardings(options);

	إذا (options->xauth_location == عدم)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	إذا (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	إذا (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	إذا (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	إذا (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	إذا (options->gss_authentication == -1)
		options->gss_authentication = 0;
	إذا (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	إذا (options->password_authentication == -1)
		options->password_authentication = 1;
	إذا (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	إذا (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	إذا (options->batch_mode == -1)
		options->batch_mode = 0;
	إذا (options->check_host_ip == -1)
		options->check_host_ip = 0;
	إذا (options->strict_host_ئاچقۇچ_checking == -1)
		options->strict_host_ئاچقۇچ_checking = SSH_STRICT_HOSTKEY_ASK;
	إذا (options->compression == -1)
		options->compression = 0;
	إذا (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	إذا (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	إذا (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	إذا (options->connection_attempts == -1)
		options->connection_attempts = 1;
	إذا (options->سان_of_password_prompts == -1)
		options->سان_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	إذا (options->add_ئاچقۇچلار_to_agent == -1) {
		options->add_ئاچقۇچلار_to_agent = 0;
		options->add_ئاچقۇچلار_to_agent_lifespan = 0;
	}
	إذا (options->رەقەم_identity_files == 0) {
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_RSA, 0);
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ECDSA, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ECDSA_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	إذا (options->escape_char == -1)
		options->escape_char = '~';
	إذا (options->رەقەم_system_hostfiles == 0) {
		options->system_hostfiles[options->رەقەم_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->رەقەم_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	إذا (options->update_hostkeys == -1) {
		إذا (options->verify_host_ئاچقۇچ_dns <= 0 &&
		    (options->رەقەم_user_hostfiles == 0 ||
		    (options->رەقەم_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		وإلا
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	إذا (options->رەقەم_user_hostfiles == 0) {
		options->user_hostfiles[options->رەقەم_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->رەقەم_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	إذا (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	إذا (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	إذا (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	إذا (options->identities_only == -1)
		options->identities_only = 0;
	إذا (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	إذا (options->rekey_limit == -1)
		options->rekey_limit = 0;
	إذا (options->rekey_interval == -1)
		options->rekey_interval = 0;
	إذا (options->verify_host_ئاچقۇچ_dns == -1)
		options->verify_host_ئاچقۇچ_dns = 0;
	إذا (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	إذا (options->server_alive_سانى_max == -1)
		options->server_alive_سانى_max = 3;
	إذا (options->control_master == -1)
		options->control_master = 0;
	إذا (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	إذا (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	إذا (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	إذا (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	إذا (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	إذا (options->permit_local_command == -1)
		options->permit_local_command = 0;
	إذا (options->visual_host_ئاچقۇچ == -1)
		options->visual_host_ئاچقۇچ = 0;
	إذا (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	إذا (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	إذا (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	إذا (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	إذا (options->stdin_null == -1)
		options->stdin_null = 0;
	إذا (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	إذا (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	إذا (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	إذا (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	إذا (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	إذا (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("internal");
#وإلا
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	إذا (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	إذا (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	إذا (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	إذا (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ئاچقۇچ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_ئاچقۇچ = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ئاچقۇچ);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	افعل { \
		إذا ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			اذهب fail; \
		} \
	} طالما (0)
	options->kex_algorithms_set = options->kex_algorithms != عدم;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_ئاچقۇچ, all_ئاچقۇچ);
	ASSEMBLE(pubkey_accepted_algos, def_ئاچقۇچ, all_ئاچقۇچ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	افعل { \
		إذا (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			حرر(options->v[0]); \
			حرر(options->v); \
			options->v = عدم; \
			options->nv = 0; \
		} \
	} طالما (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, رەقەم_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_ئاچقۇچلار, رەقەم_revoked_host_ئاچقۇچلار, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	إذا (options->jump_host != عدم &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == عدم) {
		حرر(options->jump_host);
		options->jump_host = عدم;
	}
	إذا (options->رەقەم_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		حرر(options->permitted_cnames[0].source_list);
		حرر(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    حجم(*options->permitted_cnames));
		options->رەقەم_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	حرر(all_cipher);
	حرر(all_mac);
	حرر(all_kex);
	حرر(all_ئاچقۇچ);
	حرر(all_sig);
	حرر(def_cipher);
	حرر(def_mac);
	حرر(def_kex);
	حرر(def_ئاچقۇچ);
	حرر(def_sig);
	أرجع ret;
}

فراغ
free_options(Options *o)
{
	صحيح i;

	إذا (o == عدم)
		أرجع;

#define FREE_ARRAY(type, n, a) \
	افعل { \
		type _i; \
		لكل (_i = 0; _i < (n); _i++) \
			حرر((a)[_i]); \
	} طالما (0)

	حرر(o->forward_agent_sock_path);
	حرر(o->xauth_location);
	FREE_ARRAY(u_int, o->رەقەم_log_verbose, o->log_verbose);
	حرر(o->log_verbose);
	حرر(o->ciphers);
	حرر(o->macs);
	حرر(o->hostkeyalgorithms);
	حرر(o->kex_algorithms);
	حرر(o->ca_sign_algorithms);
	حرر(o->hostname);
	حرر(o->host_ئاچقۇچ_alias);
	حرر(o->proxy_command);
	حرر(o->user);
	FREE_ARRAY(u_int, o->رەقەم_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->رەقەم_user_hostfiles, o->user_hostfiles);
	حرر(o->preferred_authentications);
	حرر(o->bind_address);
	حرر(o->bind_interface);
	حرر(o->pkcs11_provider);
	حرر(o->sk_provider);
	لكل (i = 0; i < o->رەقەم_identity_files; i++) {
		حرر(o->identity_files[i]);
		sshkey_free(o->identity_ئاچقۇچلار[i]);
	}
	لكل (i = 0; i < o->رەقەم_certificate_files; i++) {
		حرر(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	حرر(o->identity_agent);
	لكل (i = 0; i < o->رەقەم_local_forwards; i++) {
		حرر(o->local_forwards[i].listen_host);
		حرر(o->local_forwards[i].listen_path);
		حرر(o->local_forwards[i].connect_host);
		حرر(o->local_forwards[i].connect_path);
	}
	حرر(o->local_forwards);
	لكل (i = 0; i < o->رەقەم_remote_forwards; i++) {
		حرر(o->remote_forwards[i].listen_host);
		حرر(o->remote_forwards[i].listen_path);
		حرر(o->remote_forwards[i].connect_host);
		حرر(o->remote_forwards[i].connect_path);
	}
	حرر(o->remote_forwards);
	حرر(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->رەقەم_send_env, o->send_env);
	حرر(o->send_env);
	FREE_ARRAY(u_int, o->رەقەم_setenv, o->setenv);
	حرر(o->setenv);
	حرر(o->control_path);
	حرر(o->local_command);
	حرر(o->remote_command);
	FREE_ARRAY(صحيح, o->رەقەم_canonical_domains, o->canonical_domains);
	لكل (i = 0; i < o->رەقەم_permitted_cnames; i++) {
		حرر(o->permitted_cnames[i].source_list);
		حرر(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->رەقەم_revoked_host_ئاچقۇچلار, o->revoked_host_ئاچقۇچلار);
	حرر(o->revoked_host_ئاچقۇچلار);
	حرر(o->hostbased_accepted_algos);
	حرر(o->pubkey_accepted_algos);
	حرر(o->jump_user);
	حرر(o->jump_host);
	حرر(o->jump_extra);
	حرر(o->ignored_unknown);
	explicit_bzero(o, حجم(*o));
#undef FREE_ARRAY
}

بنية fwdarg {
	حرف *arg;
	صحيح ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ساكن صحيح
parse_fwd_field(حرف **p, بنية fwdarg *fwd)
{
	حرف *ep, *cp = *p;
	صحيح ispath = 0;

	إذا (*cp == '\0') {
		*p = عدم;
		أرجع -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	إذا (*cp == '[') {
		/* find matching ']' */
		لكل (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			إذا (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		إذا (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			أرجع -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		إذا (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		أرجع 0;
	}

	لكل (cp = *p; *cp != '\0'; cp++) {
		بدل (*cp) {
		حالة '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			إذا (*cp == '\0')
				أرجع -1;
			اكسر;
		حالة '/':
			ispath = 1;
			اكسر;
		حالة ':':
			*cp++ = '\0';
			اذهب done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	أرجع 0;
}

/*
 * parse_forward
 * parses a string containing a port forwarding specification of the form:
 *   dynamicfwd == 0
 *	[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
 *	listenpath:connectpath
 *   dynamicfwd == 1
 *	[listenhost:]listenport
 * returns number of arguments parsed or zero on error
 */
صحيح
parse_forward(بنية Forward *fwd, ثابت حرف *fwdspec, صحيح dynamicfwd, صحيح remotefwd)
{
	بنية fwdarg fwdargs[4];
	حرف *p, *cp;
	صحيح i, err;

	memset(fwd, 0, حجم(*fwd));
	memset(fwdargs, 0, حجم(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	إذا (p == عدم || err)
		أرجع 0;

	/* skip leading spaces */
	طالما (isspace((u_char)*cp))
		cp++;

	لكل (i = 0; i < 4; ++i) {
		إذا (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			اكسر;
	}

	/* Check for trailing garbage */
	إذا (cp != عدم && *cp != '\0') {
		i = 0;	/* failure */
	}

	بدل (i) {
	حالة 1:
		إذا (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = عدم;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		اكسر;

	حالة 2:
		إذا (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} وإلا إذا (fwdargs[1].ispath) {
			fwd->listen_host = عدم;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		اكسر;

	حالة 3:
		إذا (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} وإلا إذا (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = عدم;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		اكسر;

	حالة 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		اكسر;
	افتراضي:
		i = 0; /* failure */
	}

	حرر(p);

	إذا (dynamicfwd) {
		إذا (!(i == 1 || i == 2))
			اذهب fail_free;
	} وإلا {
		إذا (!(i == 3 || i == 4)) {
			إذا (fwd->connect_path == عدم &&
			    fwd->listen_path == عدم)
				اذهب fail_free;
		}
		إذا (fwd->connect_port <= 0 && fwd->connect_path == عدم)
			اذهب fail_free;
	}

	إذا ((fwd->listen_port < 0 && fwd->listen_path == عدم) ||
	    (!remotefwd && fwd->listen_port == 0))
		اذهب fail_free;
	إذا (fwd->connect_host != عدم &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		اذهب fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	إذا (fwd->connect_path != عدم &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		اذهب fail_free;
	إذا (fwd->listen_host != عدم &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		اذهب fail_free;
	إذا (fwd->listen_path != عدم &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		اذهب fail_free;

	أرجع (i);

 fail_free:
	حرر(fwd->connect_host);
	fwd->connect_host = عدم;
	حرر(fwd->connect_path);
	fwd->connect_path = عدم;
	حرر(fwd->listen_host);
	fwd->listen_host = عدم;
	حرر(fwd->listen_path);
	fwd->listen_path = عدم;
	أرجع (0);
}

صحيح
ssh_valid_hostname(ثابت حرف *s)
{
	size_t i;

	إذا (*s == '-')
		أرجع 0;
	لكل (i = 0; s[i] != 0; i++) {
		إذا (strchr("'`\"$\\;&<>|(){},", s[i]) != عدم ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			أرجع 0;
	}
	أرجع 1;
}

صحيح
ssh_valid_ruser(ثابت حرف *s)
{
	size_t i;

	إذا (*s == '-')
		أرجع 0;
	لكل (i = 0; s[i] != 0; i++) {
		إذا (iscntrl((u_char)s[i]))
			أرجع 0;
		إذا (strchr("'`\";&<>|(){}$\\", s[i]) != عدم)
			أرجع 0;
		/* Disallow '-' after whitespace */
		إذا (isspace((u_char)s[i]) && s[i + 1] == '-')
			أرجع 0;
	}
	أرجع 1;
}

صحيح
parse_jump(ثابت حرف *s, Options *o, صحيح strict, صحيح active)
{
	حرف *orig = عدم, *sdup = عدم, *cp;
	حرف *tmp_user = عدم, *tmp_host = عدم, *host = عدم, *user = عدم;
	صحيح r, ret = -1, tmp_port = -1, port = -1, first = 1;

	إذا (strcasecmp(s, "none") == 0) {
		إذا (active && o->jump_host == عدم) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		أرجع 0;
	}

	orig = xstrdup(s);
	إذا ((cp = strchr(orig, '#')) != عدم)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == عدم && o->jump_host == عدم;
	sdup = xstrdup(orig);
	افعل {
		/* Work backwards through string */
		إذا ((cp = strrchr(sdup, ',')) == عدم)
			cp = sdup; /* last */
		وإلا
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		إذا (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			اذهب out; /* error already logged */
		إذا (strict) {
			إذا (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				اذهب out;
			}
			إذا (tmp_user != عدم && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				اذهب out;
			}
		}
		إذا (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = عدم; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		حرر(tmp_user);
		حرر(tmp_host);
		tmp_user = tmp_host = عدم;
		tmp_port = -1;
	} طالما (cp != sdup);

	/* success */
	إذا (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = عدم; /* transferred */
		إذا (orig != عدم && (cp = strrchr(orig, ',')) != عدم) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	حرر(orig);
	حرر(sdup);
	حرر(tmp_user);
	حرر(tmp_host);
	حرر(user);
	حرر(host);
	أرجع ret;
}

صحيح
parse_ssh_uri(ثابت حرف *uri, حرف **userp, حرف **hostp, صحيح *portp)
{
	حرف *user = عدم, *host = عدم, *path = عدم;
	صحيح r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	إذا (r == 0 && path != عدم)
		r = -1;		/* path not allowed */
	إذا (r == 0) {
		إذا (userp != عدم) {
			*userp = user;
			user = عدم;
		}
		إذا (hostp != عدم) {
			*hostp = host;
			host = عدم;
		}
		إذا (portp != عدم)
			*portp = port;
	}
	حرر(user);
	حرر(host);
	حرر(path);
	أرجع r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ساكن ثابت حرف *
fmt_multistate_int(صحيح val, ثابت بنية multistate *m)
{
	u_int i;

	لكل (i = 0; m[i].ئاچقۇچ != عدم; i++) {
		إذا (m[i].قىممەت == val)
			أرجع m[i].ئاچقۇچ;
	}
	أرجع "UNKNOWN";
}

ساكن ثابت حرف *
fmt_intarg(OpCodes code, صحيح val)
{
	إذا (val == -1)
		أرجع "unset";
	بدل (code) {
	حالة oAddressFamily:
		أرجع fmt_multistate_int(val, multistate_addressfamily);
	حالة oCompression:
		أرجع fmt_multistate_int(val, multistate_compression);
	حالة o_Verify_Host_ئاچقۇچ_DNS:
	حالة oUpdateHostkeys:
		أرجع fmt_multistate_int(val, multistate_yesnoask);
	حالة o_Strict_Host_ئاچقۇچ_Checking:
		أرجع fmt_multistate_int(val, multistate_strict_hostkey);
	حالة oControlMaster:
		أرجع fmt_multistate_int(val, multistate_controlmaster);
	حالة oTunnel:
		أرجع fmt_multistate_int(val, multistate_tunnel);
	حالة oRequestTTY:
		أرجع fmt_multistate_int(val, multistate_requesttty);
	حالة oSessionType:
		أرجع fmt_multistate_int(val, multistate_sessiontype);
	حالة oCanonicalizeHostname:
		أرجع fmt_multistate_int(val, multistate_canonicalizehostname);
	حالة o_Add_ئاچقۇچلار_To_Agent:
		أرجع fmt_multistate_int(val, multistate_yesnoaskconfirm);
	حالة oPubkeyAuthentication:
		أرجع fmt_multistate_int(val, multistate_pubkey_auth);
	حالة oTCPKeepAlive:
		أرجع fmt_multistate_int(val, multistate_keepalives);
	حالة oFingerprintHash:
		أرجع ssh_digest_alg_name(val);
	افتراضي:
		بدل (val) {
		حالة 0:
			أرجع "no";
		حالة 1:
			أرجع "yes";
		افتراضي:
			أرجع "UNKNOWN";
		}
	}
}

ساكن ثابت حرف *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	لكل (i = 0; keywords[i].name != عدم; i++)
		إذا (keywords[i].opcode == code)
			أرجع(keywords[i].name);
	أرجع "UNKNOWN";
}

ساكن فراغ
dump_cfg_int(OpCodes code, صحيح val)
{
	إذا (code == oObscureKeystrokeTiming) {
		إذا (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			أرجع;
		} وإلا إذا (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			أرجع;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ساكن فراغ
dump_cfg_fmtint(OpCodes code, صحيح val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ساكن فراغ
dump_cfg_string(OpCodes code, ثابت حرف *val)
{
	إذا (val == عدم)
		أرجع;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

ساكن فراغ
dump_cfg_strarray(OpCodes code, u_int سانى, حرف **vals)
{
	u_int i;

	لكل (i = 0; i < سانى; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ساكن فراغ
dump_cfg_strarray_oneline(OpCodes code, u_int سانى, حرف **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	إذا (سانى == 0)
		printf(" none");
	لكل (i = 0; i < سانى; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

ساكن فراغ
dump_cfg_forwards(OpCodes code, u_int سانى, ثابت بنية Forward *fwds)
{
	ثابت بنية Forward *fwd;
	u_int i;

	/* oDynamicForward */
	لكل (i = 0; i < سانى; i++) {
		fwd = &fwds[i];
		إذا (code == oDynamicForward && fwd->connect_host != عدم &&
		    strcmp(fwd->connect_host, "socks") != 0)
			استمر;
		إذا (code == oLocalForward && fwd->connect_host != عدم &&
		    strcmp(fwd->connect_host, "socks") == 0)
			استمر;
		printf("%s", lookup_opcode_name(code));
		إذا (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		وإلا إذا (fwd->listen_host == عدم)
			printf(" %d", fwd->listen_port);
		وإلا {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		إذا (code != oDynamicForward) {
			إذا (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			وإلا إذا (fwd->connect_host == عدم)
				printf(" %d", fwd->connect_port);
			وإلا {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

فراغ
dump_client_config(Options *o, ثابت حرف *host)
{
	صحيح i, r;
	حرف buf[8], *all_ئاچقۇچ;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_ئاچقۇچ = sshkey_alg_list(0, 0, 1, ',');
	إذا ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_ئاچقۇچ)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	حرر(all_ئاچقۇچ);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(oPort, o->port);

	/* Flag options */
	dump_cfg_fmtint(oAddressFamily, o->address_family);
	dump_cfg_fmtint(oBatchMode, o->batch_mode);
	dump_cfg_fmtint(oCanonicalizeFallbackLocal, o->canonicalize_fallback_local);
	dump_cfg_fmtint(oCanonicalizeHostname, o->canonicalize_hostname);
	dump_cfg_fmtint(oCheckHostIP, o->check_host_ip);
	dump_cfg_fmtint(oCompression, o->compression);
	dump_cfg_fmtint(oControlMaster, o->control_master);
	dump_cfg_fmtint(oEnableSSHKeysign, o->enable_ssh_keysign);
	dump_cfg_fmtint(oClearAllForwardings, o->clear_forwardings);
	dump_cfg_fmtint(oExitOnForwardFailure, o->exit_on_forward_failure);
	dump_cfg_fmtint(oFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(oForwardX11, o->forward_x11);
	dump_cfg_fmtint(oForwardX11Trusted, o->forward_x11_trusted);
	dump_cfg_fmtint(oGatewayPorts, o->fwd_opts.gateway_ports);
#ifdef GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#endif /* GSSAPI */
	dump_cfg_fmtint(oHashKnownHosts, o->hash_known_hosts);
	dump_cfg_fmtint(oHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(oIdentitiesOnly, o->identities_only);
	dump_cfg_fmtint(oKbdInteractiveAuthentication, o->kbd_interactive_authentication);
	dump_cfg_fmtint(oNoHostAuthenticationForLocalhost, o->no_host_authentication_for_localhost);
	dump_cfg_fmtint(oPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(oPermitLocalCommand, o->permit_local_command);
	dump_cfg_fmtint(oProxyUseFdpass, o->proxy_use_fdpass);
	dump_cfg_fmtint(oPubkeyAuthentication, o->pubkey_authentication);
	dump_cfg_fmtint(oRequestTTY, o->request_tty);
	dump_cfg_fmtint(oSessionType, o->session_type);
	dump_cfg_fmtint(oStdinNull, o->stdin_null);
	dump_cfg_fmtint(oForkAfterAuthentication, o->fork_after_authentication);
	dump_cfg_fmtint(oStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_ئاچقۇچ_Checking, o->strict_host_ئاچقۇچ_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_ئاچقۇچ_DNS, o->verify_host_ئاچقۇچ_dns);
	dump_cfg_fmtint(o_Visual_Host_ئاچقۇچ, o->visual_host_ئاچقۇچ);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_سان_Of_Password_Prompts, o->سان_of_password_prompts);
	dump_cfg_int(o_Server_Alive_سانى_Max, o->server_alive_سانى_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_ئاچقۇچ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_ئاچقۇچ_Alias, o->host_ئاچقۇچ_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(oIdentityAgent, o->identity_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ifdef ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#endif
	dump_cfg_string(o_Security_ئاچقۇچ_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->رەقەم_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->رەقەم_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->رەقەم_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->رەقەم_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->رەقەم_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->رەقەم_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->رەقەم_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->رەقەم_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_ئاچقۇچلار, o->رەقەم_revoked_host_ئاچقۇچلار, o->revoked_host_ئاچقۇچلار);
	dump_cfg_strarray(oSendEnv, o->رەقەم_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->رەقەم_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->رەقەم_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->رەقەم_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	إذا (o->رەقەم_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	وإلا
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->رەقەم_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	إذا (o->add_ئاچقۇچلار_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_ئاچقۇچلار_To_Agent, o->add_ئاچقۇچلار_to_agent);
	وإلا {
		printf("addkeystoagent%s %d\n",
		    o->add_ئاچقۇچلار_to_agent == 3 ? " confirm" : "",
		    o->add_ئاچقۇچلار_to_agent_lifespan);
	}

	/* oForwardAgent */
	إذا (o->forward_agent_sock_path == عدم)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	وإلا
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	إذا (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	وإلا
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	إذا (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	وإلا
		printf(" %d", o->tun_local);
	إذا (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	وإلا
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	إذا (o->رەقەم_permitted_cnames == 0)
		printf(" none");
	لكل (i = 0; i < o->رەقەم_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	إذا (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	وإلا
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	إذا (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	وإلا {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		printf("escapechar %s\n", buf);
	}

	/* oIPQoS */
	printf("ipqos %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	printf("rekeylimit %llu %d\n",
	    (unsigned long long)o->rekey_limit, o->rekey_interval);

	/* oStreamLocalBindMask */
	printf("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_mask);

	/* oLogFacility */
	printf("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	إذا (o->jump_host == عدم)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	وإلا {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != عدم ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, حجم(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == عدم ? "" : o->jump_extra,
		    o->jump_extra == عدم ? "" : ",",
		    /* optional user */
		    o->jump_user == عدم ? "" : o->jump_user,
		    o->jump_user == عدم ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_port <= 0 ? "" : ":",
		    o->jump_port <= 0 ? "" : buf);
	}
}
