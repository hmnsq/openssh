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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <util.h>
#ប្រសិនបើ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "cipher.h"
#include "pathnames.h"
#include "log.h"
#include "sshkey.h"
#include "misc.h"
#include "readconf.h"
#include "match.h"
#include "kex.h"
#include "mac.h"
#include "myproposal.h"
#include "digest.h"
#include "version.h"

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

static ចំនួនគត់ read_config_file_depth(const var_na *filename, sa_nracanaa passwd *pw,
    const var_na *host, const var_na *original_host, const var_na *remote_command,
    Options *options, ចំនួនគត់ flags, ចំនួនគត់ *activep, ចំនួនគត់ *want_final_pass, ចំនួនគត់ depth);
static ចំនួនគត់ process_config_line_depth(Options *options, sa_nracanaa passwd *pw,
    const var_na *host, const var_na *original_host, const var_na *remote_command,
    var_na *line, const var_na *filename, ចំនួនគត់ linenum, ចំនួនគត់ *activep, ចំនួនគត់ flags,
    ចំនួនគត់ *want_final_pass, ចំនួនគត់ depth);

/* Keyword tokens. */

typedef ga_nanaa {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, oAddKeysToAgent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, oStrictHostKeyChecking, oCompression,
	oTCPKeepAlive, oNumberOfPasswordPrompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, oHostKeyAlias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	oHostKeyAlgorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, oVerifyHostKeyDNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, oServerAliveCountMax, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	oVisualHostKey,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, oRevokedHostKeys,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	oSecurityKeyProvider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

static sa_nracanaa {
	const var_na *name;
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
#ប្រសិនបើ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# បើមិនដូច្នេះ
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# បើមិនដូច្នេះ
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
	{ "addkeystoagent", oAddKeysToAgent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", oHostKeyAlias },
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
	{ "stricthostkeychecking", oStrictHostKeyChecking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", oNumberOfPasswordPrompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", oHostKeyAlgorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", oVerifyHostKeyDNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", oServerAliveCountMax },
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
	{ "visualhostkey", oVisualHostKey },
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
	{ "revokedhostkeys", oRevokedHostKeys },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", oSecurityKeyProvider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ NULL, oBadOption }
};

static const var_na *lookup_opcode_name(OpCodes code);

const var_na *
kex_default_pk_alg(void)
{
	static var_na *pkalgs;

	ប្រសិនបើ (pkalgs == NULL) {
		var_na *all_key;

		all_key = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_key);
		free(all_key);
	}
	ត្រឡប់ pkalgs;
}

var_na *
ssh_connection_hash(const var_na *thishost, const var_na *host, const var_na *portstr,
    const var_na *user, const var_na *jumphost)
{
	sa_nracanaa ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	ប្រសិនបើ ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == NULL ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, parimaa_na(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ត្រឡប់ tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

void
add_local_forward(Options *options, const sa_nracanaa Forward *newfwd)
{
	sa_nracanaa Forward *fwd;
	ចំនួនគត់ i;

	/* Don't add duplicates */
	សម្រាប់ (i = 0; i < options->num_local_forwards; i++) {
		ប្រសិនបើ (forward_equals(newfwd, options->local_forwards + i))
			ត្រឡប់;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->num_local_forwards + 1,
	    parimaa_na(*options->local_forwards));
	fwd = &options->local_forwards[options->num_local_forwards++];

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

void
add_remote_forward(Options *options, const sa_nracanaa Forward *newfwd)
{
	sa_nracanaa Forward *fwd;
	ចំនួនគត់ i;

	/* Don't add duplicates */
	សម្រាប់ (i = 0; i < options->num_remote_forwards; i++) {
		ប្រសិនបើ (forward_equals(newfwd, options->remote_forwards + i))
			ត្រឡប់;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->num_remote_forwards + 1,
	    parimaa_na(*options->remote_forwards));
	fwd = &options->remote_forwards[options->num_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

static void
clear_forwardings(Options *options)
{
	ចំនួនគត់ i;

	សម្រាប់ (i = 0; i < options->num_local_forwards; i++) {
		free(options->local_forwards[i].listen_host);
		free(options->local_forwards[i].listen_path);
		free(options->local_forwards[i].connect_host);
		free(options->local_forwards[i].connect_path);
	}
	ប្រសិនបើ (options->num_local_forwards > 0) {
		free(options->local_forwards);
		options->local_forwards = NULL;
	}
	options->num_local_forwards = 0;
	សម្រាប់ (i = 0; i < options->num_remote_forwards; i++) {
		free(options->remote_forwards[i].listen_host);
		free(options->remote_forwards[i].listen_path);
		free(options->remote_forwards[i].connect_host);
		free(options->remote_forwards[i].connect_path);
	}
	ប្រសិនបើ (options->num_remote_forwards > 0) {
		free(options->remote_forwards);
		options->remote_forwards = NULL;
	}
	options->num_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

void
add_certificate_file(Options *options, const var_na *path, ចំនួនគត់ userprovided)
{
	ចំនួនគត់ i;

	ប្រសិនបើ (options->num_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	សម្រាប់ (i = 0; i < options->num_certificate_files; i++) {
		ប្រសិនបើ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ត្រឡប់;
		}
	}

	options->certificate_file_userprovided[options->num_certificate_files] =
	    userprovided;
	options->certificate_files[options->num_certificate_files++] =
	    xstrdup(path);
}

void
add_identity_file(Options *options, const var_na *dir, const var_na *filename,
    ចំនួនគត់ userprovided)
{
	var_na *path;
	ចំនួនគត់ i;

	ប្រសិនបើ (options->num_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	ប្រសិនបើ (dir == NULL) /* no dir, filename is absolute */
		path = xstrdup(filename);
	បើមិនដូច្នេះ ប្រសិនបើ (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	សម្រាប់ (i = 0; i < options->num_identity_files; i++) {
		ប្រសិនបើ (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			free(path);
			ត្រឡប់;
		}
	}

	options->identity_file_userprovided[options->num_identity_files] =
	    userprovided;
	options->identity_files[options->num_identity_files++] = path;
}

ចំនួនគត់
default_ssh_port(void)
{
	static ចំនួនគត់ port;
	sa_nracanaa servent *sp;

	ប្រសិនបើ (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	ត្រឡប់ port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
static ចំនួនគត់
execute_in_shell(const var_na *cmd)
{
	var_na *shell;
	pid_t pid;
	ចំនួនគត់ status;

	ប្រសិនបើ ((shell = getenv("SHELL")) == NULL)
		shell = _PATH_BSHELL;

	ប្រសិនបើ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	ប្រសិនបើ ((pid = fork()) == 0) {
		var_na *argv[4];

		ប្រសិនបើ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = NULL;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	ប្រសិនបើ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	ខណៈពេល (waitpid(pid, &status, 0) == -1) {
		ប្រសិនបើ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	ប្រសិនបើ (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		ត្រឡប់ -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	ត្រឡប់ WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
static ចំនួនគត់
check_match_ifaddrs(const var_na *addrlist)
{
#ifdef HAVE_IFADDRS_H
	sa_nracanaa ifaddrs *ifa, *ifaddrs = NULL;
	ចំនួនគត់ r, found = 0;
	var_na addr[NI_MAXHOST];
	socklen_t salen;

	ប្រសិនបើ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ត្រឡប់ 0;
	}
	សម្រាប់ (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		ប្រសិនបើ (ifa->ifa_addr == NULL || ifa->ifa_name == NULL ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			continue;
		switch (ifa->ifa_addr->sa_family) {
		pak_sa AF_INET:
			salen = parimaa_na(sa_nracanaa sockaddr_in);
			bha_nga;
		pak_sa AF_INET6:
			salen = parimaa_na(sa_nracanaa sockaddr_in6);
			bha_nga;
#ifdef AF_LINK
		pak_sa AF_LINK:
			/* ignore */
			continue;
#endif /* AF_LINK */
		default:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			continue;
		}
		ប្រសិនបើ ((r = getnameinfo(ifa->ifa_addr, salen, addr, parimaa_na(addr),
		    NULL, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			continue;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		ប្រសិនបើ (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			bha_nga;
		}
	}
	freeifaddrs(ifaddrs);
	ត្រឡប់ found;
#បើមិនដូច្នេះ /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ត្រឡប់ 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
static var_na *
expand_match_exec_or_include_path(const var_na *path, Options *options,
    sa_nracanaa passwd *pw, const var_na *host_arg, const var_na *original_host,
    ចំនួនគត់ final_pass, ចំនួនគត់ is_include_path)
{
	var_na thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	var_na uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	var_na *host, *ret;
	ចំនួនគត់ port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == NULL ? pw->pw_name : options->user;
	ប្រសិនបើ (final_pass) {
		host = xstrdup(options->hostname);
	} បើមិនដូច្នេះ ប្រសិនបើ (options->hostname != NULL) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (var_na *)NULL);
	} បើមិនដូច្នេះ {
		host = xstrdup(host_arg);
	}
	ប្រសិនបើ (gethostname(thishost, parimaa_na(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, parimaa_na(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, parimaa_na(portstr), "%d", port);
	snprintf(uidstr, parimaa_na(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_key_alias ?  options->host_key_alias : host;

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
	    (var_na *)NULL);
	free(host);
	free(conn_hash_hex);
	ត្រឡប់ ret;
}

/*
 * Parse and execute a Match directive.
 */
static ចំនួនគត់
match_cfg_line(Options *options, const var_na *full_line, ចំនួនគត់ *acp, var_na ***avp,
    sa_nracanaa passwd *pw, const var_na *host_arg, const var_na *original_host,
    const var_na *remote_command, ចំនួនគត់ final_pass, ចំនួនគត់ *want_final_pass,
    const var_na *filename, ចំនួនគត់ linenum)
{
	var_na *arg, *oattrib = NULL, *attrib = NULL, *cmd, *host, *criteria;
	const var_na *ruser;
	ចំនួនគត់ r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == NULL ? pw->pw_name : options->user;
	ប្រសិនបើ (final_pass) {
		host = xstrdup(options->hostname);
	} បើមិនដូច្នេះ ប្រសិនបើ (options->hostname != NULL) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (var_na *)NULL);
	} បើមិនដូច្នេះ {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_line, host, original_host);
	ខណៈពេល ((attrib = argv_next(acp, avp)) != NULL) {
		/* Terminate on comment */
		ប្រសិនបើ (*attrib == '#') {
			argv_consume(acp);
			bha_nga;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = NULL;
		this_result = 1;
		ប្រសិនបើ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		ប្រសិនបើ (strcasecmp(attrib, "all") == 0) {
			ប្រសិនបើ (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != NULL &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				goto out;
			}
			ប្រសិនបើ (arg != NULL && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ប្រសិនបើ (result)
				result = negate ? 0 : 1;
			goto out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		ប្រសិនបើ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			ប្រសិនបើ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != NULL)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			goto next;
		}

		/* Keep this list in sync with below */
		ប្រសិនបើ (strprefix(attrib, "host=", 1)  != NULL ||
		    strprefix(attrib, "originalhost=", 1) != NULL ||
		    strprefix(attrib, "user=", 1) != NULL ||
		    strprefix(attrib, "localuser=", 1) != NULL ||
		    strprefix(attrib, "localnetwork=", 1) != NULL ||
		    strprefix(attrib, "version=", 1) != NULL ||
		    strprefix(attrib, "tagged=", 1) != NULL ||
		    strprefix(attrib, "command=", 1) != NULL ||
		    strprefix(attrib, "exec=", 1) != NULL) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} បើមិនដូច្នេះ ប្រសិនបើ ((arg = argv_next(acp, avp)) == NULL) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			goto out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		ប្រសិនបើ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = NULL;
		ប្រសិនបើ (arg == NULL || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			goto out;
		}
		ប្រសិនបើ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "localnetwork") == 0) {
			ប្រសិនបើ (addr_match_cidr_list(NULL, arg) == -1) {
				/* Error already printed */
				result = -1;
				goto out;
			}
			r = check_match_ifaddrs(arg) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == NULL ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == NULL ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "sessiontype") == 0) {
			ប្រសិនបើ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			បើមិនដូច្នេះ ប្រសិនបើ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			បើមិនដូច្នេះ ប្រសិនបើ (remote_command != NULL &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			បើមិនដូច្នេះ
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ ប្រសិនបើ (strcasecmp(attrib, "exec") == 0) {
			ប្រសិនបើ ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == NULL) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			ប្រសិនបើ (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				free(cmd);
				goto next;
			}
			r = execute_in_shell(cmd);
			ប្រសិនបើ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			free(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			ប្រសិនបើ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} បើមិនដូច្នេះ {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			goto out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == NULL ? "" : " \"",
		    criteria == NULL ? "" : criteria,
		    criteria == NULL ? "" : "\"");
 next:
		free(criteria);
		free(oattrib);
		oattrib = attrib = NULL;
	}
	ប្រសិនបើ (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		goto out;
	}
 out:
	ប្រសិនបើ (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	free(oattrib);
	free(host);
	ត្រឡប់ result;
}

/* Remove environment variable by pattern */
static void
rm_env(Options *options, const var_na *arg, const var_na *filename, ចំនួនគត់ linenum)
{
	u_int i, j, onum_send_env = options->num_send_env;

	/* Remove an environment variable */
	សម្រាប់ (i = 0; i < options->num_send_env; ) {
		ប្រសិនបើ (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			continue;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		free(options->send_env[i]);
		options->send_env[i] = NULL;
		សម្រាប់ (j = i; j < options->num_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = NULL;
		}
		options->num_send_env--;
		/* NB. don't increment i */
	}
	ប្រសិនបើ (onum_send_env != options->num_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->num_send_env,
		    parimaa_na(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
static OpCodes
parse_token(const var_na *cp, const var_na *filename, ចំនួនគត់ linenum,
    const var_na *ignored_unknown)
{
	ចំនួនគត់ i;

	សម្រាប់ (i = 0; keywords[i].name; i++)
		ប្រសិនបើ (strcmp(cp, keywords[i].name) == 0)
			ត្រឡប់ keywords[i].opcode;
	ប្រសិនបើ (ignored_unknown != NULL &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		ត្រឡប់ oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ត្រឡប់ oBadOption;
}

static void
free_canon_cnames(sa_nracanaa allowed_cname *cnames, u_int n)
{
	u_int i;

	ប្រសិនបើ (cnames == NULL || n == 0)
		ត្រឡប់;
	សម្រាប់ (i = 0; i < n; i++) {
		free(cnames[i].source_list);
		free(cnames[i].target_list);
	}
	free(cnames);
}

/* Multistate option parsing */
sa_nracanaa multistate {
	var_na *key;
	ចំនួនគត់ value;
};
static const sa_nracanaa multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ NULL, -1 }
};
static const sa_nracanaa multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ NULL, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
static const sa_nracanaa multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ NULL, -1 }
};

static ចំនួនគត់
parse_multistate_value(const var_na *arg, const var_na *filename, ចំនួនគត់ linenum,
    const sa_nracanaa multistate *multistate_ptr)
{
	ចំនួនគត់ i;

	ប្រសិនបើ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ត្រឡប់ -1;
	}
	សម្រាប់ (i = 0; multistate_ptr[i].key != NULL; i++) {
		ប្រសិនបើ (strcasecmp(arg, multistate_ptr[i].key) == 0)
			ត្រឡប់ multistate_ptr[i].value;
	}
	ត្រឡប់ -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
ចំនួនគត់
process_config_line(Options *options, sa_nracanaa passwd *pw, const var_na *host,
    const var_na *original_host, const var_na *remote_command, var_na *line,
    const var_na *filename, ចំនួនគត់ linenum, ចំនួនគត់ *activep, ចំនួនគត់ flags)
{
	ត្រឡប់ process_config_line_depth(options, pw, host, original_host,
	    remote_command, line, filename, linenum, activep, flags, NULL, 0);
}

#define WHITESPACE " \t\r\n"
static ចំនួនគត់
process_config_line_depth(Options *options, sa_nracanaa passwd *pw, const var_na *host,
    const var_na *original_host, const var_na *remote_command, var_na *line,
    const var_na *filename, ចំនួនគត់ linenum, ចំនួនគត់ *activep, ចំនួនគត់ flags,
    ចំនួនគត់ *want_final_pass, ចំនួនគត់ depth)
{
	var_na *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	var_na **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	ចំនួនគត់ r, oactive, negated, opcode, *intptr, value, value2, cmdline = 0;
	ចំនួនគត់ remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	sa_nracanaa Forward fwd;
	const sa_nracanaa multistate *multistate_ptr;
	glob_t gl;
	const var_na *errstr;
	var_na **oav = NULL, **av;
	ចំនួនគត់ oac = 0, ac;
	ចំនួនគត់ ret = -1;
	sa_nracanaa allowed_cname *cnames = NULL;
	u_int ncnames = 0;
	var_na **strs = NULL; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	ប្រសិនបើ (activep == NULL) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ប្រសិនបើ ((len = strlen(line)) == 0)
		ត្រឡប់ 0;
	សម្រាប់ (len--; len > 0; len--) {
		ប្រសិនបើ (strchr(WHITESPACE "\f", line[len]) == NULL)
			bha_nga;
		line[len] = '\0';
	}

	str = line;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	ប្រសិនបើ ((keyword = strdelim(&str)) == NULL)
		ត្រឡប់ 0;
	/* Ignore leading whitespace. */
	ប្រសិនបើ (*keyword == '\0')
		keyword = strdelim(&str);
	ប្រសិនបើ (keyword == NULL || !*keyword || *keyword == '\n' || *keyword == '#')
		ត្រឡប់ 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	ប្រសិនបើ (str != NULL)
		str += strspn(str, WHITESPACE);
	ប្រសិនបើ (str == NULL || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ត្រឡប់ -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	ប្រសិនបើ (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ត្រឡប់ -1;
	}
	ac = oac;
	av = oav;

	switch (opcode) {
	pak_sa oBadOption:
		/* don't panic, but count bad options */
		goto out;
	pak_sa oIgnore:
		argv_consume(&ac);
		bha_nga;
	pak_sa oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		bha_nga;
	pak_sa oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (strcmp(arg, "none") == 0)
			value = -1;
		បើមិនដូច្នេះ ប្រសិនបើ ((value = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			goto out;
		}

		value = -1;
		multistate_ptr = multistate_flag;
		សម្រាប់ (i = 0; multistate_ptr[i].key != NULL; i++) {
			ប្រសិនបើ (strcasecmp(arg, multistate_ptr[i].key) == 0) {
				value = multistate_ptr[i].value;
				bha_nga;
			}
		}
		ប្រសិនបើ (value != -1) {
			ប្រសិនបើ (*activep && *intptr == -1)
				*intptr = value;
			bha_nga;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		goto parse_agent_path;

	pak_sa oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ ((value = parse_multistate_value(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			goto out;
		}
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		goto parse_flag;

	pak_sa oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		goto parse_time;

	pak_sa oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		goto parse_flag;

	pak_sa oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		goto parse_flag;

	pak_sa oPasswordAuthentication:
		intptr = &options->password_authentication;
		goto parse_flag;

	pak_sa oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		goto parse_flag;

	pak_sa oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		goto parse_string;

	pak_sa oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		goto parse_multistate;

	pak_sa oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		goto parse_flag;

	pak_sa oGssAuthentication:
		intptr = &options->gss_authentication;
		goto parse_flag;

	pak_sa oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		goto parse_flag;

	pak_sa oBatchMode:
		intptr = &options->batch_mode;
		goto parse_flag;

	pak_sa oCheckHostIP:
		intptr = &options->check_host_ip;
		goto parse_flag;

	pak_sa oVerifyHostKeyDNS:
		intptr = &options->verify_host_key_dns;
		multistate_ptr = multistate_yesnoask;
		goto parse_multistate;

	pak_sa oStrictHostKeyChecking:
		intptr = &options->strict_host_key_checking;
		multistate_ptr = multistate_strict_hostkey;
		goto parse_multistate;

	pak_sa oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		goto parse_multistate;

	pak_sa oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		goto parse_multistate;

	pak_sa oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		goto parse_flag;

	pak_sa oNumberOfPasswordPrompts:
		intptr = &options->number_of_password_prompts;
		goto parse_int;

	pak_sa oRekeyLimit:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			goto out;
		}
		ប្រសិនបើ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} បើមិនដូច្នេះ {
			ប្រសិនបើ (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				goto out;
			}
			ប្រសិនបើ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				goto out;
			}
		}
		ប្រសិនបើ (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		ប្រសិនបើ (ac != 0) { /* optional rekey interval present */
			ប្រសិនបើ (strcmp(av[0], "none") == 0) {
				(void)argv_next(&ac, &av);	/* discard */
				bha_nga;
			}
			intptr = &options->rekey_interval;
			goto parse_time;
		}
		bha_nga;

	pak_sa oIdentityFile:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep) {
			intptr = &options->num_identity_files;
			ប្រសិនបើ (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				goto out;
			}
			add_identity_file(options, NULL,
			    arg, flags & SSHCONF_USERCONF);
		}
		bha_nga;

	pak_sa oCertificateFile:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep) {
			intptr = &options->num_certificate_files;
			ប្រសិនបើ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				goto out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		bha_nga;

	pak_sa oXAuthLocation:
		charptr=&options->xauth_location;
		goto parse_string;

	pak_sa oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa oGlobalKnownHostsFile:
		cpptr = (var_na **)&options->system_hostfiles;
		uintptr = &options->num_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		value = *uintptr == 0; /* was array empty when we started? */
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0) {
				ប្រសិនបើ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			i++;
			ប្រសិនបើ (*activep && value) {
				ប្រសិនបើ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					goto out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		bha_nga;

	pak_sa oUserKnownHostsFile:
		cpptr = (var_na **)&options->user_hostfiles;
		uintptr = &options->num_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		goto parse_char_array;

	pak_sa oHostname:
		charptr = &options->hostname;
		goto parse_string;

	pak_sa oTag:
		charptr = &options->tag;
		goto parse_string;

	pak_sa oHostKeyAlias:
		charptr = &options->host_key_alias;
		goto parse_string;

	pak_sa oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		goto parse_string;

	pak_sa oBindAddress:
		charptr = &options->bind_address;
		goto parse_string;

	pak_sa oBindInterface:
		charptr = &options->bind_interface;
		goto parse_string;

	pak_sa oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		goto parse_string;

	pak_sa oSecurityKeyProvider:
		charptr = &options->sk_provider;
		goto parse_string;

	pak_sa oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		goto parse_command;

	pak_sa oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		ប្រសិនបើ (str == NULL) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		len = strspn(str, WHITESPACE "=");
		ប្រសិនបើ (*activep && *charptr == NULL)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		bha_nga;

	pak_sa oProxyJump:
		ប្រសិនបើ (str == NULL) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		ប្រសិនបើ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			goto out;
		}
		argv_consume(&ac);
		bha_nga;

	pak_sa oPort:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		value = a2port(arg);
		ប្រសិនបើ (value <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			goto out;
		}
		ប្រសិនបើ (*activep && options->port == -1)
			options->port = value;
		bha_nga;

	pak_sa oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ ((errstr = atoi_err(arg, &value)) != NULL) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			goto out;
		}
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa oCiphers:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		ប្រសិនបើ (*activep && options->ciphers == NULL)
			options->ciphers = xstrdup(arg);
		bha_nga;

	pak_sa oMacs:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		ប្រសិនបើ (*activep && options->macs == NULL)
			options->macs = xstrdup(arg);
		bha_nga;

	pak_sa oKexAlgorithms:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		ប្រសិនបើ (*activep && options->kex_algorithms == NULL)
			options->kex_algorithms = xstrdup(arg);
		bha_nga;

	pak_sa oHostKeyAlgorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		ប្រសិនបើ (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		goto parse_pubkey_algos;

	pak_sa oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		value = log_level_number(arg);
		ប្រសិនបើ (value == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		ប្រសិនបើ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) value;
		bha_nga;

	pak_sa oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		value = log_facility_number(arg);
		ប្រសិនបើ (value == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		ប្រសិនបើ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) value;
		bha_nga;

	pak_sa oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->num_log_verbose;
		i = 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0) {
				ប្រសិនបើ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			i++;
			ប្រសិនបើ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, parimaa_na(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		bha_nga;

	pak_sa oLocalForward:
	pak_sa oRemoteForward:
	pak_sa oDynamicForward:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		ប្រសិនបើ (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			ប្រសិនបើ (arg2 == NULL || *arg2 == '\0') {
				ប្រសិនបើ (remotefwd)
					dynamicfwd = 1;
				បើមិនដូច្នេះ {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					goto out;
				}
			} បើមិនដូច្នេះ {
				/* construct a string for parse_forward */
				snprintf(fwdarg, parimaa_na(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		ប្រសិនបើ (dynamicfwd)
			strlcpy(fwdarg, arg, parimaa_na(fwdarg));

		ប្រសិនបើ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			goto out;
		}

		ប្រសិនបើ (*activep) {
			ប្រសិនបើ (remotefwd) {
				add_remote_forward(options, &fwd);
			} បើមិនដូច្នេះ {
				add_local_forward(options, &fwd);
			}
		}
		bha_nga;

	pak_sa oPermitRemoteOpen:
		uintptr = &options->num_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				ប្រសិនបើ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					free(arg2);
					goto out;
				}
			} បើមិនដូច្នេះ {
				p = hpdelim(&arg);
				ប្រសិនបើ (p == NULL) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				ប្រសិនបើ (arg == NULL || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			free(arg2);
		}
		ប្រសិនបើ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		ប្រសិនបើ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa oClearAllForwardings:
		intptr = &options->clear_forwardings;
		goto parse_flag;

	pak_sa oHost:
		ប្រសិនបើ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			goto out;
		}
		*activep = 0;
		arg2 = NULL;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			ប្រសិនបើ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				bha_nga;
			}
			negated = *arg == '!';
			ប្រសិនបើ (negated)
				arg++;
			ប្រសិនបើ (match_pattern(host, arg)) {
				ប្រសិនបើ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					bha_nga;
				}
				ប្រសិនបើ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		ប្រសិនបើ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		bha_nga;

	pak_sa oMatch:
		ប្រសិនបើ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			goto out;
		}
		value = match_cfg_line(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		ប្រសិនបើ (value < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			goto out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : value;
		bha_nga;

	pak_sa oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (strcmp(arg, "none") == 0)
			value = SSH_ESCAPECHAR_NONE;
		បើមិនដូច្នេះ ប្រសិនបើ (arg[1] == '\0')
			value = (u_char) arg[0];
		បើមិនដូច្នេះ ប្រសិនបើ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			value = (u_char) arg[1] & 31;
		បើមិនដូច្នេះ {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		goto parse_multistate;

	pak_sa oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		goto parse_flag;

	pak_sa oIdentitiesOnly:
		intptr = &options->identities_only;
		goto parse_flag;

	pak_sa oServerAliveInterval:
		intptr = &options->server_alive_interval;
		goto parse_time;

	pak_sa oServerAliveCountMax:
		intptr = &options->server_alive_count_max;
		goto parse_int;

	pak_sa oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (*arg == '\0' || strchr(arg, '=') != NULL) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				goto out;
			}
			found = 1;
			ប្រសិនបើ (!*activep)
				continue;
			ប្រសិនបើ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				continue;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->num_send_env, arg);
		}
		ប្រសិនបើ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		bha_nga;

	pak_sa oSetEnv:
		found = options->num_setenv == 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (strchr(arg, '=') == NULL) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				goto out;
			}
			ប្រសិនបើ (lookup_setenv_in_list(arg, strs, nstrs) != NULL) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				continue;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		ប្រសិនបើ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ប្រសិនបើ (found && *activep) {
			options->setenv = strs;
			options->num_setenv = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa oControlPath:
		charptr = &options->control_path;
		goto parse_string;

	pak_sa oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		goto parse_multistate;

	pak_sa oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			goto out;
		}
		value = 0;
		value2 = 0;	/* timeout */
		ប្រសិនបើ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			value = 0;
		បើមិនដូច្នេះ ប្រសិនបើ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			value = 1;
		បើមិនដូច្នេះ ប្រសិនបើ ((value2 = convtime(arg)) >= 0)
			value = 1;
		បើមិនដូច្នេះ {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep && *intptr == -1) {
			*intptr = value;
			options->control_persist_timeout = value2;
		}
		bha_nga;

	pak_sa oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		goto parse_flag;

	pak_sa oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		goto parse_multistate;

	pak_sa oTunnelDevice:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		value = a2tun(arg, &value2);
		ប្រសិនបើ (value == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep && options->tun_local == -1) {
			options->tun_local = value;
			options->tun_remote = value2;
		}
		bha_nga;

	pak_sa oLocalCommand:
		charptr = &options->local_command;
		goto parse_command;

	pak_sa oPermitLocalCommand:
		intptr = &options->permit_local_command;
		goto parse_flag;

	pak_sa oRemoteCommand:
		charptr = &options->remote_command;
		goto parse_command;

	pak_sa oVisualHostKey:
		intptr = &options->visual_host_key;
		goto parse_flag;

	pak_sa oInclude:
		ប្រសិនបើ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			goto out;
		}
		value = 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Expand %tokens and environment variables */
			ប្រសិនបើ ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == NULL) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				continue;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			ប្រសិនបើ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				goto out;
			}
			ប្រសិនបើ (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} បើមិនដូច្នេះ {
				arg2 = xstrdup(p);
			}
			free(p);
			memset(&gl, 0, parimaa_na(gl));
			r = glob(arg2, GLOB_TILDE, NULL, &gl);
			ប្រសិនបើ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				free(arg2);
				continue;
			} បើមិនដូច្នេះ ប្រសិនបើ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				goto out;
			}
			free(arg2);
			oactive = *activep;
			សម្រាប់ (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				ប្រសិនបើ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					goto out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				ប្រសិនបើ (r != 1)
					value = -1;
			}
			globfree(&gl);
		}
		ប្រសិនបើ (value != 0)
			ret = value;
		bha_nga;

	pak_sa oIPQoS:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ ((value = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			goto out;
		}
		ប្រសិនបើ (value == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (arg == NULL)
			value2 = value;
		បើមិនដូច្នេះ ប្រសិនបើ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			goto out;
		}
		ប្រសិនបើ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		ប្រសិនបើ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = value;
			options->ip_qos_bulk = value2;
		}
		bha_nga;

	pak_sa oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		goto parse_multistate;

	pak_sa oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		goto parse_multistate;

	pak_sa oStdinNull:
		intptr = &options->stdin_null;
		goto parse_flag;

	pak_sa oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		goto parse_flag;

	pak_sa oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		goto parse_string;

	pak_sa oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		goto parse_flag;

	pak_sa oCanonicalDomains:
		found = options->num_canonical_domains == 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			/* Allow "none" only in first position */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0) {
				ប្រសិនបើ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			ប្រសិនបើ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				goto out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ប្រសិនបើ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ប្រសិនបើ (found && *activep) {
			options->canonical_domains = strs;
			options->num_canonical_domains = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa oCanonicalizePermittedCNAMEs:
		found = options->num_permitted_cnames == 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0) {
				ប្រសិនបើ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
				arg2 = "";
			} បើមិនដូច្នេះ ប្រសិនបើ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} បើមិនដូច្នេះ {
				lowercase(arg);
				ប្រសិនបើ ((arg2 = strchr(arg, ':')) == NULL ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					goto out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    parimaa_na(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		ប្រសិនបើ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ប្រសិនបើ (found && *activep) {
			options->permitted_cnames = cnames;
			options->num_permitted_cnames = ncnames;
			cnames = NULL; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		bha_nga;

	pak_sa oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		goto parse_multistate;

	pak_sa oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		goto parse_int;

	pak_sa oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		goto parse_flag;

	pak_sa oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			goto out;
		}
		/* Parse mode in octal format */
		value = strtol(arg, &endofnumber, 8);
		ប្រសិនបើ (arg == endofnumber || value < 0 || value > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)value;
		bha_nga;

	pak_sa oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		goto parse_flag;

	pak_sa oRevokedHostKeys:
		uintptr = &options->num_revoked_host_keys;
		cppptr = &options->revoked_host_keys;
		found = *uintptr == 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0) {
				ប្រសិនបើ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ប្រសិនបើ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ប្រសិនបើ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ ((value = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			goto out;
		}
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		goto parse_multistate;

	pak_sa oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		goto parse_pubkey_algos;

	pak_sa oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		goto parse_pubkey_algos;

	pak_sa oAddKeysToAgent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		value = parse_multistate_value(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		ប្រសិនបើ (value == 3 && arg2 != NULL) {
			/* allow "AddKeysToAgent confirm 5m" */
			ប្រសិនបើ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				goto out;
			}
		} បើមិនដូច្នេះ ប្រសិនបើ (value == -1 && arg2 == NULL) {
			ប្រសិនបើ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				goto out;
			}
			value = 1; /* yes */
		} បើមិនដូច្នេះ ប្រសិនបើ (value == -1 || arg2 != NULL) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep && options->add_keys_to_agent == -1) {
			options->add_keys_to_agent = value;
			options->add_keys_to_agent_lifespan = value2;
		}
		bha_nga;

	pak_sa oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		ប្រសិនបើ ((arg2 = dollar_expand(&r, arg)) == NULL || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			goto out;
		}
		free(arg2);
		/* check for legacy environment format */
		ប្រសិនបើ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			goto out;
		}
		ប្រសិនបើ (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		bha_nga;

	pak_sa oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		goto parse_flag;

	pak_sa oRequiredRSASize:
		intptr = &options->required_rsa_size;
		goto parse_int;

	pak_sa oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		goto parse_multistate;

	pak_sa oObscureKeystrokeTiming:
		value = -1;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			ប្រសិនបើ (value != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				goto out;
			}
			ប្រសិនបើ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				value = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			បើមិនដូច្នេះ ប្រសិនបើ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				value = 0;
			បើមិនដូច្នេះ ប្រសិនបើ (strncmp(arg, "interval:", 9) == 0) {
				ប្រសិនបើ ((errstr = atoi_err(arg + 9,
				    &value)) != NULL) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					goto out;
				}
				ប្រសិនបើ (value <= 0 || value > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					goto out;
				}
			} បើមិនដូច្នេះ {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				goto out;
			}
		}
		ប្រសិនបើ (value == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			goto out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		ប្រសិនបើ (*activep && *intptr == -1)
			*intptr = value;
		bha_nga;

	pak_sa oChannelTimeout:
		found = options->num_channel_timeouts == 0;
		ខណៈពេល ((arg = argv_next(&ac, &av)) != NULL) {
			/* Allow "none" only in first position */
			ប្រសិនបើ (strcasecmp(arg, "none") == 0) {
				ប្រសិនបើ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			} បើមិនដូច្នេះ ប្រសិនបើ (parse_pattern_interval(arg,
			    NULL, NULL) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ប្រសិនបើ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ប្រសិនបើ (found && *activep) {
			options->channel_timeouts = strs;
			options->num_channel_timeouts = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		bha_nga;

	pak_sa oVersionAddendum:
		ប្រសិនបើ (str == NULL || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ប្រសិនបើ (strchr(str + len, '\r') != NULL) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ប្រសិនបើ ((arg = strchr(line, '#')) != NULL) {
			*arg = '\0';
			rtrim(line);
		}
		ប្រសិនបើ (*activep && options->version_addendum == NULL) {
			ប្រសិនបើ (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			បើមិនដូច្នេះ
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		bha_nga;

	pak_sa oRefuseConnection:
		arg = argv_next(&ac, &av);
		ប្រសិនបើ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			goto out;
		}
		ប្រសិនបើ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		bha_nga;

	pak_sa oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		bha_nga;

	pak_sa oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		bha_nga;

	default:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		goto out;
	}

	/* Check that there is no garbage at end of line. */
	ប្រសិនបើ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		goto out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, NULL, nstrs);
	argv_free(oav, oac);
	ត្រឡប់ ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
ចំនួនគត់
read_config_file(const var_na *filename, sa_nracanaa passwd *pw, const var_na *host,
    const var_na *original_host, const var_na *remote_command, Options *options, ចំនួនគត់ flags,
    ចំនួនគត់ *want_final_pass)
{
	ចំនួនគត់ active = 1;

	ត្រឡប់ read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
static ចំនួនគត់
read_config_file_depth(const var_na *filename, sa_nracanaa passwd *pw,
    const var_na *host, const var_na *original_host, const var_na *remote_command,
    Options *options, ចំនួនគត់ flags, ចំនួនគត់ *activep, ចំនួនគត់ *want_final_pass, ចំនួនគត់ depth)
{
	FILE *f;
	var_na *line = NULL;
	size_t linesize = 0;
	ចំនួនគត់ linenum;
	ចំនួនគត់ bad_options = 0;

	ប្រសិនបើ (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	ប្រសិនបើ ((f = fopen(filename, "r")) == NULL)
		ត្រឡប់ 0;

	ប្រសិនបើ (flags & SSHCONF_CHECKPERM) {
		sa_nracanaa stat sb;

		ប្រសិនបើ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		ប្រសិនបើ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	ខណៈពេល (getline(&line, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		ប្រសិនបើ (process_config_line_depth(options, pw, host, original_host,
		    remote_command, line, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	free(line);
	fclose(f);
	ប្រសិនបើ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ត្រឡប់ 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ចំនួនគត់
option_clear_or_none(const var_na *o)
{
	ត្រឡប់ o == NULL || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
ចំនួនគត់
config_has_permitted_cnames(Options *options)
{
	ប្រសិនបើ (options->num_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		ត្រឡប់ 0;
	ត្រឡប់ options->num_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

void
initialize_options(Options * options)
{
	memset(options, 'X', parimaa_na(*options));
	options->host_arg = NULL;
	options->forward_agent = -1;
	options->forward_agent_sock_path = NULL;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = NULL;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = NULL;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = NULL;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_key_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->number_of_password_prompts = -1;
	options->ciphers = NULL;
	options->macs = NULL;
	options->kex_algorithms = NULL;
	options->hostkeyalgorithms = NULL;
	options->ca_sign_algorithms = NULL;
	options->num_identity_files = 0;
	memset(options->identity_keys, 0, parimaa_na(options->identity_keys));
	options->num_certificate_files = 0;
	memset(options->certificates, 0, parimaa_na(options->certificates));
	options->hostname = NULL;
	options->host_key_alias = NULL;
	options->proxy_command = NULL;
	options->jump_user = NULL;
	options->jump_host = NULL;
	options->jump_port = -1;
	options->jump_extra = NULL;
	options->user = NULL;
	options->escape_char = -1;
	options->num_system_hostfiles = 0;
	options->num_user_hostfiles = 0;
	options->local_forwards = NULL;
	options->num_local_forwards = 0;
	options->remote_forwards = NULL;
	options->num_remote_forwards = 0;
	options->permitted_remote_opens = NULL;
	options->num_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->num_log_verbose = 0;
	options->log_verbose = NULL;
	options->preferred_authentications = NULL;
	options->bind_address = NULL;
	options->bind_interface = NULL;
	options->pkcs11_provider = NULL;
	options->sk_provider = NULL;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_key_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_count_max = -1;
	options->send_env = NULL;
	options->num_send_env = 0;
	options->setenv = NULL;
	options->num_setenv = 0;
	options->control_path = NULL;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = NULL;
	options->permit_local_command = -1;
	options->remote_command = NULL;
	options->add_keys_to_agent = -1;
	options->add_keys_to_agent_lifespan = -1;
	options->identity_agent = NULL;
	options->visual_host_key = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = NULL;
	options->num_canonical_domains = 0;
	options->num_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_keys = NULL;
	options->num_revoked_host_keys = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = NULL;
	options->pubkey_accepted_algos = NULL;
	options->known_hosts_command = NULL;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = NULL;
	options->channel_timeouts = NULL;
	options->num_channel_timeouts = 0;
	options->version_addendum = NULL;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
void
fill_default_options_for_canonicalization(Options *options)
{
	ប្រសិនបើ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ប្រសិនបើ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ប្រសិនបើ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
ចំនួនគត់
fill_default_options(Options * options)
{
	var_na *all_cipher, *all_mac, *all_kex, *all_key, *all_sig;
	var_na *def_cipher, *def_mac, *def_kex, *def_key, *def_sig;
	ចំនួនគត់ ret = -1, r;

	ប្រសិនបើ (options->forward_agent == -1)
		options->forward_agent = 0;
	ប្រសិនបើ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	ប្រសិនបើ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	ប្រសិនបើ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	ប្រសិនបើ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != NULL ? 1 : 0;
	ប្រសិនបើ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != NULL ? 1 : 0;
	ប្រសិនបើ (options->clear_forwardings == 1)
		clear_forwardings(options);

	ប្រសិនបើ (options->xauth_location == NULL)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	ប្រសិនបើ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ប្រសិនបើ (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	ប្រសិនបើ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ប្រសិនបើ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	ប្រសិនបើ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	ប្រសិនបើ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	ប្រសិនបើ (options->password_authentication == -1)
		options->password_authentication = 1;
	ប្រសិនបើ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	ប្រសិនបើ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	ប្រសិនបើ (options->batch_mode == -1)
		options->batch_mode = 0;
	ប្រសិនបើ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	ប្រសិនបើ (options->strict_host_key_checking == -1)
		options->strict_host_key_checking = SSH_STRICT_HOSTKEY_ASK;
	ប្រសិនបើ (options->compression == -1)
		options->compression = 0;
	ប្រសិនបើ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	ប្រសិនបើ (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	ប្រសិនបើ (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	ប្រសិនបើ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	ប្រសិនបើ (options->number_of_password_prompts == -1)
		options->number_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	ប្រសិនបើ (options->add_keys_to_agent == -1) {
		options->add_keys_to_agent = 0;
		options->add_keys_to_agent_lifespan = 0;
	}
	ប្រសិនបើ (options->num_identity_files == 0) {
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
	ប្រសិនបើ (options->escape_char == -1)
		options->escape_char = '~';
	ប្រសិនបើ (options->num_system_hostfiles == 0) {
		options->system_hostfiles[options->num_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->num_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	ប្រសិនបើ (options->update_hostkeys == -1) {
		ប្រសិនបើ (options->verify_host_key_dns <= 0 &&
		    (options->num_user_hostfiles == 0 ||
		    (options->num_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		បើមិនដូច្នេះ
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	ប្រសិនបើ (options->num_user_hostfiles == 0) {
		options->user_hostfiles[options->num_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->num_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	ប្រសិនបើ (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	ប្រសិនបើ (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	ប្រសិនបើ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	ប្រសិនបើ (options->identities_only == -1)
		options->identities_only = 0;
	ប្រសិនបើ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	ប្រសិនបើ (options->rekey_limit == -1)
		options->rekey_limit = 0;
	ប្រសិនបើ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ប្រសិនបើ (options->verify_host_key_dns == -1)
		options->verify_host_key_dns = 0;
	ប្រសិនបើ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	ប្រសិនបើ (options->server_alive_count_max == -1)
		options->server_alive_count_max = 3;
	ប្រសិនបើ (options->control_master == -1)
		options->control_master = 0;
	ប្រសិនបើ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	ប្រសិនបើ (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	ប្រសិនបើ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	ប្រសិនបើ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	ប្រសិនបើ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	ប្រសិនបើ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	ប្រសិនបើ (options->visual_host_key == -1)
		options->visual_host_key = 0;
	ប្រសិនបើ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ប្រសិនបើ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ប្រសិនបើ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	ប្រសិនបើ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	ប្រសិនបើ (options->stdin_null == -1)
		options->stdin_null = 0;
	ប្រសិនបើ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	ប្រសិនបើ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	ប្រសិនបើ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ប្រសិនបើ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ប្រសិនបើ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	ប្រសិនបើ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	ប្រសិនបើ (options->sk_provider == NULL)
		options->sk_provider = xstrdup("internal");
#បើមិនដូច្នេះ
	ប្រសិនបើ (options->sk_provider == NULL)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	ប្រសិនបើ (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	ប្រសិនបើ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	ប្រសិនបើ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	ប្រសិនបើ (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_key = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_key = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_key);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	do { \
		ប្រសិនបើ ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			goto fail; \
		} \
	} ខណៈពេល (0)
	options->kex_algorithms_set = options->kex_algorithms != NULL;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_key, all_key);
	ASSEMBLE(pubkey_accepted_algos, def_key, all_key);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	do { \
		ប្រសិនបើ (option_clear_or_none(v)) { \
			free(v); \
			v = NULL; \
		} \
	} ខណៈពេល(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	do { \
		ប្រសិនបើ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			free(options->v[0]); \
			free(options->v); \
			options->v = NULL; \
			options->nv = 0; \
		} \
	} ខណៈពេល (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, num_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_keys, num_revoked_host_keys, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	ប្រសិនបើ (options->jump_host != NULL &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == NULL) {
		free(options->jump_host);
		options->jump_host = NULL;
	}
	ប្រសិនបើ (options->num_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		free(options->permitted_cnames[0].source_list);
		free(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    parimaa_na(*options->permitted_cnames));
		options->num_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	free(all_cipher);
	free(all_mac);
	free(all_kex);
	free(all_key);
	free(all_sig);
	free(def_cipher);
	free(def_mac);
	free(def_kex);
	free(def_key);
	free(def_sig);
	ត្រឡប់ ret;
}

void
free_options(Options *o)
{
	ចំនួនគត់ i;

	ប្រសិនបើ (o == NULL)
		ត្រឡប់;

#define FREE_ARRAY(type, n, a) \
	do { \
		type _i; \
		សម្រាប់ (_i = 0; _i < (n); _i++) \
			free((a)[_i]); \
	} ខណៈពេល (0)

	free(o->forward_agent_sock_path);
	free(o->xauth_location);
	FREE_ARRAY(u_int, o->num_log_verbose, o->log_verbose);
	free(o->log_verbose);
	free(o->ciphers);
	free(o->macs);
	free(o->hostkeyalgorithms);
	free(o->kex_algorithms);
	free(o->ca_sign_algorithms);
	free(o->hostname);
	free(o->host_key_alias);
	free(o->proxy_command);
	free(o->user);
	FREE_ARRAY(u_int, o->num_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->num_user_hostfiles, o->user_hostfiles);
	free(o->preferred_authentications);
	free(o->bind_address);
	free(o->bind_interface);
	free(o->pkcs11_provider);
	free(o->sk_provider);
	សម្រាប់ (i = 0; i < o->num_identity_files; i++) {
		free(o->identity_files[i]);
		sshkey_free(o->identity_keys[i]);
	}
	សម្រាប់ (i = 0; i < o->num_certificate_files; i++) {
		free(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	free(o->identity_agent);
	សម្រាប់ (i = 0; i < o->num_local_forwards; i++) {
		free(o->local_forwards[i].listen_host);
		free(o->local_forwards[i].listen_path);
		free(o->local_forwards[i].connect_host);
		free(o->local_forwards[i].connect_path);
	}
	free(o->local_forwards);
	សម្រាប់ (i = 0; i < o->num_remote_forwards; i++) {
		free(o->remote_forwards[i].listen_host);
		free(o->remote_forwards[i].listen_path);
		free(o->remote_forwards[i].connect_host);
		free(o->remote_forwards[i].connect_path);
	}
	free(o->remote_forwards);
	free(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->num_send_env, o->send_env);
	free(o->send_env);
	FREE_ARRAY(u_int, o->num_setenv, o->setenv);
	free(o->setenv);
	free(o->control_path);
	free(o->local_command);
	free(o->remote_command);
	FREE_ARRAY(ចំនួនគត់, o->num_canonical_domains, o->canonical_domains);
	សម្រាប់ (i = 0; i < o->num_permitted_cnames; i++) {
		free(o->permitted_cnames[i].source_list);
		free(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->num_revoked_host_keys, o->revoked_host_keys);
	free(o->revoked_host_keys);
	free(o->hostbased_accepted_algos);
	free(o->pubkey_accepted_algos);
	free(o->jump_user);
	free(o->jump_host);
	free(o->jump_extra);
	free(o->ignored_unknown);
	explicit_bzero(o, parimaa_na(*o));
#undef FREE_ARRAY
}

sa_nracanaa fwdarg {
	var_na *arg;
	ចំនួនគត់ ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
static ចំនួនគត់
parse_fwd_field(var_na **p, sa_nracanaa fwdarg *fwd)
{
	var_na *ep, *cp = *p;
	ចំនួនគត់ ispath = 0;

	ប្រសិនបើ (*cp == '\0') {
		*p = NULL;
		ត្រឡប់ -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	ប្រសិនបើ (*cp == '[') {
		/* find matching ']' */
		សម្រាប់ (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			ប្រសិនបើ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		ប្រសិនបើ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ត្រឡប់ -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		ប្រសិនបើ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ត្រឡប់ 0;
	}

	សម្រាប់ (cp = *p; *cp != '\0'; cp++) {
		switch (*cp) {
		pak_sa '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			ប្រសិនបើ (*cp == '\0')
				ត្រឡប់ -1;
			bha_nga;
		pak_sa '/':
			ispath = 1;
			bha_nga;
		pak_sa ':':
			*cp++ = '\0';
			goto done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ត្រឡប់ 0;
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
ចំនួនគត់
parse_forward(sa_nracanaa Forward *fwd, const var_na *fwdspec, ចំនួនគត់ dynamicfwd, ចំនួនគត់ remotefwd)
{
	sa_nracanaa fwdarg fwdargs[4];
	var_na *p, *cp;
	ចំនួនគត់ i, err;

	memset(fwd, 0, parimaa_na(*fwd));
	memset(fwdargs, 0, parimaa_na(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	ប្រសិនបើ (p == NULL || err)
		ត្រឡប់ 0;

	/* skip leading spaces */
	ខណៈពេល (isspace((u_char)*cp))
		cp++;

	សម្រាប់ (i = 0; i < 4; ++i) {
		ប្រសិនបើ (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			bha_nga;
	}

	/* Check for trailing garbage */
	ប្រសិនបើ (cp != NULL && *cp != '\0') {
		i = 0;	/* failure */
	}

	switch (i) {
	pak_sa 1:
		ប្រសិនបើ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} បើមិនដូច្នេះ {
			fwd->listen_host = NULL;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		bha_nga;

	pak_sa 2:
		ប្រសិនបើ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} បើមិនដូច្នេះ ប្រសិនបើ (fwdargs[1].ispath) {
			fwd->listen_host = NULL;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} បើមិនដូច្នេះ {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		bha_nga;

	pak_sa 3:
		ប្រសិនបើ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} បើមិនដូច្នេះ ប្រសិនបើ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} បើមិនដូច្នេះ {
			fwd->listen_host = NULL;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		bha_nga;

	pak_sa 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		bha_nga;
	default:
		i = 0; /* failure */
	}

	free(p);

	ប្រសិនបើ (dynamicfwd) {
		ប្រសិនបើ (!(i == 1 || i == 2))
			goto fail_free;
	} បើមិនដូច្នេះ {
		ប្រសិនបើ (!(i == 3 || i == 4)) {
			ប្រសិនបើ (fwd->connect_path == NULL &&
			    fwd->listen_path == NULL)
				goto fail_free;
		}
		ប្រសិនបើ (fwd->connect_port <= 0 && fwd->connect_path == NULL)
			goto fail_free;
	}

	ប្រសិនបើ ((fwd->listen_port < 0 && fwd->listen_path == NULL) ||
	    (!remotefwd && fwd->listen_port == 0))
		goto fail_free;
	ប្រសិនបើ (fwd->connect_host != NULL &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		goto fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	ប្រសិនបើ (fwd->connect_path != NULL &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		goto fail_free;
	ប្រសិនបើ (fwd->listen_host != NULL &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		goto fail_free;
	ប្រសិនបើ (fwd->listen_path != NULL &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		goto fail_free;

	ត្រឡប់ (i);

 fail_free:
	free(fwd->connect_host);
	fwd->connect_host = NULL;
	free(fwd->connect_path);
	fwd->connect_path = NULL;
	free(fwd->listen_host);
	fwd->listen_host = NULL;
	free(fwd->listen_path);
	fwd->listen_path = NULL;
	ត្រឡប់ (0);
}

ចំនួនគត់
ssh_valid_hostname(const var_na *s)
{
	size_t i;

	ប្រសិនបើ (*s == '-')
		ត្រឡប់ 0;
	សម្រាប់ (i = 0; s[i] != 0; i++) {
		ប្រសិនបើ (strchr("'`\"$\\;&<>|(){},", s[i]) != NULL ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			ត្រឡប់ 0;
	}
	ត្រឡប់ 1;
}

ចំនួនគត់
ssh_valid_ruser(const var_na *s)
{
	size_t i;

	ប្រសិនបើ (*s == '-')
		ត្រឡប់ 0;
	សម្រាប់ (i = 0; s[i] != 0; i++) {
		ប្រសិនបើ (iscntrl((u_char)s[i]))
			ត្រឡប់ 0;
		ប្រសិនបើ (strchr("'`\";&<>|(){}$\\", s[i]) != NULL)
			ត្រឡប់ 0;
		/* Disallow '-' after whitespace */
		ប្រសិនបើ (isspace((u_char)s[i]) && s[i + 1] == '-')
			ត្រឡប់ 0;
	}
	ត្រឡប់ 1;
}

ចំនួនគត់
parse_jump(const var_na *s, Options *o, ចំនួនគត់ strict, ចំនួនគត់ active)
{
	var_na *orig = NULL, *sdup = NULL, *cp;
	var_na *tmp_user = NULL, *tmp_host = NULL, *host = NULL, *user = NULL;
	ចំនួនគត់ r, ret = -1, tmp_port = -1, port = -1, first = 1;

	ប្រសិនបើ (strcasecmp(s, "none") == 0) {
		ប្រសិនបើ (active && o->jump_host == NULL) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		ត្រឡប់ 0;
	}

	orig = xstrdup(s);
	ប្រសិនបើ ((cp = strchr(orig, '#')) != NULL)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == NULL && o->jump_host == NULL;
	sdup = xstrdup(orig);
	do {
		/* Work backwards through string */
		ប្រសិនបើ ((cp = strrchr(sdup, ',')) == NULL)
			cp = sdup; /* last */
		បើមិនដូច្នេះ
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		ប្រសិនបើ (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			goto out; /* error already logged */
		ប្រសិនបើ (strict) {
			ប្រសិនបើ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				goto out;
			}
			ប្រសិនបើ (tmp_user != NULL && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				goto out;
			}
		}
		ប្រសិនបើ (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = NULL; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		free(tmp_user);
		free(tmp_host);
		tmp_user = tmp_host = NULL;
		tmp_port = -1;
	} ខណៈពេល (cp != sdup);

	/* success */
	ប្រសិនបើ (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = NULL; /* transferred */
		ប្រសិនបើ (orig != NULL && (cp = strrchr(orig, ',')) != NULL) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	free(orig);
	free(sdup);
	free(tmp_user);
	free(tmp_host);
	free(user);
	free(host);
	ត្រឡប់ ret;
}

ចំនួនគត់
parse_ssh_uri(const var_na *uri, var_na **userp, var_na **hostp, ចំនួនគត់ *portp)
{
	var_na *user = NULL, *host = NULL, *path = NULL;
	ចំនួនគត់ r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	ប្រសិនបើ (r == 0 && path != NULL)
		r = -1;		/* path not allowed */
	ប្រសិនបើ (r == 0) {
		ប្រសិនបើ (userp != NULL) {
			*userp = user;
			user = NULL;
		}
		ប្រសិនបើ (hostp != NULL) {
			*hostp = host;
			host = NULL;
		}
		ប្រសិនបើ (portp != NULL)
			*portp = port;
	}
	free(user);
	free(host);
	free(path);
	ត្រឡប់ r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
static const var_na *
fmt_multistate_int(ចំនួនគត់ val, const sa_nracanaa multistate *m)
{
	u_int i;

	សម្រាប់ (i = 0; m[i].key != NULL; i++) {
		ប្រសិនបើ (m[i].value == val)
			ត្រឡប់ m[i].key;
	}
	ត្រឡប់ "UNKNOWN";
}

static const var_na *
fmt_intarg(OpCodes code, ចំនួនគត់ val)
{
	ប្រសិនបើ (val == -1)
		ត្រឡប់ "unset";
	switch (code) {
	pak_sa oAddressFamily:
		ត្រឡប់ fmt_multistate_int(val, multistate_addressfamily);
	pak_sa oCompression:
		ត្រឡប់ fmt_multistate_int(val, multistate_compression);
	pak_sa oVerifyHostKeyDNS:
	pak_sa oUpdateHostkeys:
		ត្រឡប់ fmt_multistate_int(val, multistate_yesnoask);
	pak_sa oStrictHostKeyChecking:
		ត្រឡប់ fmt_multistate_int(val, multistate_strict_hostkey);
	pak_sa oControlMaster:
		ត្រឡប់ fmt_multistate_int(val, multistate_controlmaster);
	pak_sa oTunnel:
		ត្រឡប់ fmt_multistate_int(val, multistate_tunnel);
	pak_sa oRequestTTY:
		ត្រឡប់ fmt_multistate_int(val, multistate_requesttty);
	pak_sa oSessionType:
		ត្រឡប់ fmt_multistate_int(val, multistate_sessiontype);
	pak_sa oCanonicalizeHostname:
		ត្រឡប់ fmt_multistate_int(val, multistate_canonicalizehostname);
	pak_sa oAddKeysToAgent:
		ត្រឡប់ fmt_multistate_int(val, multistate_yesnoaskconfirm);
	pak_sa oPubkeyAuthentication:
		ត្រឡប់ fmt_multistate_int(val, multistate_pubkey_auth);
	pak_sa oTCPKeepAlive:
		ត្រឡប់ fmt_multistate_int(val, multistate_keepalives);
	pak_sa oFingerprintHash:
		ត្រឡប់ ssh_digest_alg_name(val);
	default:
		switch (val) {
		pak_sa 0:
			ត្រឡប់ "no";
		pak_sa 1:
			ត្រឡប់ "yes";
		default:
			ត្រឡប់ "UNKNOWN";
		}
	}
}

static const var_na *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	សម្រាប់ (i = 0; keywords[i].name != NULL; i++)
		ប្រសិនបើ (keywords[i].opcode == code)
			ត្រឡប់(keywords[i].name);
	ត្រឡប់ "UNKNOWN";
}

static void
dump_cfg_int(OpCodes code, ចំនួនគត់ val)
{
	ប្រសិនបើ (code == oObscureKeystrokeTiming) {
		ប្រសិនបើ (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			ត្រឡប់;
		} បើមិនដូច្នេះ ប្រសិនបើ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			ត្រឡប់;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

static void
dump_cfg_fmtint(OpCodes code, ចំនួនគត់ val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

static void
dump_cfg_string(OpCodes code, const var_na *val)
{
	ប្រសិនបើ (val == NULL)
		ត្រឡប់;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

static void
dump_cfg_strarray(OpCodes code, u_int count, var_na **vals)
{
	u_int i;

	សម្រាប់ (i = 0; i < count; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

static void
dump_cfg_strarray_oneline(OpCodes code, u_int count, var_na **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	ប្រសិនបើ (count == 0)
		printf(" none");
	សម្រាប់ (i = 0; i < count; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

static void
dump_cfg_forwards(OpCodes code, u_int count, const sa_nracanaa Forward *fwds)
{
	const sa_nracanaa Forward *fwd;
	u_int i;

	/* oDynamicForward */
	សម្រាប់ (i = 0; i < count; i++) {
		fwd = &fwds[i];
		ប្រសិនបើ (code == oDynamicForward && fwd->connect_host != NULL &&
		    strcmp(fwd->connect_host, "socks") != 0)
			continue;
		ប្រសិនបើ (code == oLocalForward && fwd->connect_host != NULL &&
		    strcmp(fwd->connect_host, "socks") == 0)
			continue;
		printf("%s", lookup_opcode_name(code));
		ប្រសិនបើ (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		បើមិនដូច្នេះ ប្រសិនបើ (fwd->listen_host == NULL)
			printf(" %d", fwd->listen_port);
		បើមិនដូច្នេះ {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		ប្រសិនបើ (code != oDynamicForward) {
			ប្រសិនបើ (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			បើមិនដូច្នេះ ប្រសិនបើ (fwd->connect_host == NULL)
				printf(" %d", fwd->connect_port);
			បើមិនដូច្នេះ {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

void
dump_client_config(Options *o, const var_na *host)
{
	ចំនួនគត់ i, r;
	var_na buf[8], *all_key;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_key = sshkey_alg_list(0, 0, 1, ',');
	ប្រសិនបើ ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_key)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	free(all_key);

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
	dump_cfg_fmtint(oStrictHostKeyChecking, o->strict_host_key_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(oVerifyHostKeyDNS, o->verify_host_key_dns);
	dump_cfg_fmtint(oVisualHostKey, o->visual_host_key);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(oNumberOfPasswordPrompts, o->number_of_password_prompts);
	dump_cfg_int(oServerAliveCountMax, o->server_alive_count_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(oHostKeyAlgorithms, o->hostkeyalgorithms);
	dump_cfg_string(oHostKeyAlias, o->host_key_alias);
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
	dump_cfg_string(oSecurityKeyProvider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->num_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->num_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->num_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->num_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->num_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->num_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->num_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->num_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(oRevokedHostKeys, o->num_revoked_host_keys, o->revoked_host_keys);
	dump_cfg_strarray(oSendEnv, o->num_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->num_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->num_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->num_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	ប្រសិនបើ (o->num_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	បើមិនដូច្នេះ
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->num_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	ប្រសិនបើ (o->add_keys_to_agent_lifespan <= 0)
		dump_cfg_fmtint(oAddKeysToAgent, o->add_keys_to_agent);
	បើមិនដូច្នេះ {
		printf("addkeystoagent%s %d\n",
		    o->add_keys_to_agent == 3 ? " confirm" : "",
		    o->add_keys_to_agent_lifespan);
	}

	/* oForwardAgent */
	ប្រសិនបើ (o->forward_agent_sock_path == NULL)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	បើមិនដូច្នេះ
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	ប្រសិនបើ (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	បើមិនដូច្នេះ
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	ប្រសិនបើ (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	បើមិនដូច្នេះ
		printf(" %d", o->tun_local);
	ប្រសិនបើ (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	បើមិនដូច្នេះ
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	ប្រសិនបើ (o->num_permitted_cnames == 0)
		printf(" none");
	សម្រាប់ (i = 0; i < o->num_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	ប្រសិនបើ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	បើមិនដូច្នេះ
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	ប្រសិនបើ (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	បើមិនដូច្នេះ {
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
	ប្រសិនបើ (o->jump_host == NULL)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	បើមិនដូច្នេះ {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != NULL ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, parimaa_na(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == NULL ? "" : o->jump_extra,
		    o->jump_extra == NULL ? "" : ",",
		    /* optional user */
		    o->jump_user == NULL ? "" : o->jump_user,
		    o->jump_user == NULL ? "" : "@",
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
