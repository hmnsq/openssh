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
#جے_انت

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

ساكن صحيح read_config_file_ڈونگھائی(ثابت حرف *filename, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحيح flags, صحيح *activep, صحيح *want_final_pass, صحيح ڈونگھائی);
ساكن صحيح process_config_سطر_ڈونگھائی(Options *options, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    حرف *سطر, ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags,
    صحيح *want_final_pass, صحيح ڈونگھائی);

/* Keyword tokens. */

تعريفنوع تعداد {
	oBadOption,
	oHost, o_میل, oInclude, o_ٹیگ,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_پچھان_تت_File, oHostname, o_پورٹ, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_جوڑو_کلیدیں_منزل_Agent, o_پچھان_تت_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_معلوم_Hosts_File, o_User_معلوم_Hosts_File, oConnectionAttempts,
	o_Batch_منوال, oCheckHostIP, o_Strict_Host_کلید_Checking, oCompression,
	oTCPKeepAlive, o_نمبر_دا_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_کلید_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_کلید_Algorithms, o_Bind_پتہ, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_حد_بندی, o_Verify_Host_کلید_DNS, oConnectTimeout,
	o_پتہ_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_گنتی_Max, oIdentitiesOnly,
	oSendEnv, o_سیٹ_Env, o_Control_رستہ, oControlMaster, oControlPersist,
	o_Hash_معلوم_Hosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_کلید,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	o_دھارا_Local_Bind_نقاب, o_دھارا_Local_Bind_Unlink, o_Revoked_Host_کلیدیں,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_کلید_Provider, o_معلوم_Hosts_Command, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	o_نسخہ_Addendum, oRefuseConnection, oWarnWeakCrypto,
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
#جے_انت
#جے_تعریف_شدہ ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# وإلا
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#جے_انت

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
	{ "identityfile", o_پچھان_تت_File },
	{ "identityfile2", o_پچھان_تت_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_جوڑو_کلیدیں_منزل_Agent },
	{ "identityagent", o_پچھان_تت_Agent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_کلید_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", o_پورٹ },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", o_میل },
	{ "tag", o_ٹیگ },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", o_Global_معلوم_Hosts_File },
	{ "userknownhostsfile", o_User_معلوم_Hosts_File },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", o_Batch_منوال },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_کلید_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_نمبر_دا_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_کلید_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", o_Bind_پتہ },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_کلید_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", o_Rekey_حد_بندی },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", o_پتہ_Family },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_گنتی_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", o_سیٹ_Env },
	{ "controlpath", o_Control_رستہ },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", o_Hash_معلوم_Hosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_کلید },
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
	{ "streamlocalbindmask", o_دھارا_Local_Bind_نقاب },
	{ "streamlocalbindunlink", o_دھارا_Local_Bind_Unlink },
	{ "revokedhostkeys", o_Revoked_Host_کلیدیں },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_کلید_Provider },
	{ "knownhostscommand", o_معلوم_Hosts_Command },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", o_نسخہ_Addendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ عدم, oBadOption }
};

ساكن ثابت حرف *lookup_opcode_name(OpCodes کوڈ);

ثابت حرف *
kex_default_pk_alg(فراغ)
{
	ساكن حرف *pkalgs;

	إذا (pkalgs == عدم) {
		حرف *all_کلید;

		all_کلید = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = میل_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
		حرر(all_کلید);
	}
	أرجع pkalgs;
}

حرف *
ssh_connection_hash(ثابت حرف *thishost, ثابت حرف *host, ثابت حرف *portstr,
    ثابت حرف *user, ثابت حرف *jumphost)
{
	بنية ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_لمائی];

	إذا ((md = ssh_digest_شروع(SSH_DIGEST_SHA1)) == عدم ||
	    ssh_digest_update(md, thishost, لڑی_لمبائی(thishost)) < 0 ||
	    ssh_digest_update(md, host, لڑی_لمبائی(host)) < 0 ||
	    ssh_digest_update(md, portstr, لڑی_لمبائی(portstr)) < 0 ||
	    ssh_digest_update(md, user, لڑی_لمبائی(user)) < 0 ||
	    ssh_digest_update(md, jumphost, لڑی_لمبائی(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, حجم(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	أرجع tohex(conn_hash, ssh_digest_بائٹاں(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

فراغ
جوڑو_local_forward(Options *options, ثابت بنية Forward *newfwd)
{
	بنية Forward *fwd;
	صحيح i;

	/* Don't add duplicates */
	لكل (i = 0; i < options->عدد_local_forwards; i++) {
		إذا (forward_equals(newfwd, options->local_forwards + i))
			أرجع;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->عدد_local_forwards + 1,
	    حجم(*options->local_forwards));
	fwd = &options->local_forwards[options->عدد_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_پورٹ = newfwd->listen_پورٹ;
	fwd->listen_رستہ = newfwd->listen_رستہ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_پورٹ = newfwd->connect_پورٹ;
	fwd->connect_رستہ = newfwd->connect_رستہ;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

فراغ
جوڑو_remote_forward(Options *options, ثابت بنية Forward *newfwd)
{
	بنية Forward *fwd;
	صحيح i;

	/* Don't add duplicates */
	لكل (i = 0; i < options->عدد_remote_forwards; i++) {
		إذا (forward_equals(newfwd, options->remote_forwards + i))
			أرجع;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->عدد_remote_forwards + 1,
	    حجم(*options->remote_forwards));
	fwd = &options->remote_forwards[options->عدد_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_پورٹ = newfwd->listen_پورٹ;
	fwd->listen_رستہ = newfwd->listen_رستہ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_پورٹ = newfwd->connect_پورٹ;
	fwd->connect_رستہ = newfwd->connect_رستہ;
	fwd->handle = newfwd->handle;
	fwd->allocated_پورٹ = 0;
}

ساكن فراغ
clear_forwardings(Options *options)
{
	صحيح i;

	لكل (i = 0; i < options->عدد_local_forwards; i++) {
		حرر(options->local_forwards[i].listen_host);
		حرر(options->local_forwards[i].listen_رستہ);
		حرر(options->local_forwards[i].connect_host);
		حرر(options->local_forwards[i].connect_رستہ);
	}
	إذا (options->عدد_local_forwards > 0) {
		حرر(options->local_forwards);
		options->local_forwards = عدم;
	}
	options->عدد_local_forwards = 0;
	لكل (i = 0; i < options->عدد_remote_forwards; i++) {
		حرر(options->remote_forwards[i].listen_host);
		حرر(options->remote_forwards[i].listen_رستہ);
		حرر(options->remote_forwards[i].connect_host);
		حرر(options->remote_forwards[i].connect_رستہ);
	}
	إذا (options->عدد_remote_forwards > 0) {
		حرر(options->remote_forwards);
		options->remote_forwards = عدم;
	}
	options->عدد_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

فراغ
جوڑو_certificate_file(Options *options, ثابت حرف *رستہ, صحيح userprovided)
{
	صحيح i;

	إذا (options->عدد_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	لكل (i = 0; i < options->عدد_certificate_files; i++) {
		إذا (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], رستہ) == 0) {
			debug2_f("ignoring duplicate key %s", رستہ);
			أرجع;
		}
	}

	options->certificate_file_userprovided[options->عدد_certificate_files] =
	    userprovided;
	options->certificate_files[options->عدد_certificate_files++] =
	    xstrdup(رستہ);
}

فراغ
جوڑو_پچھان_تت_file(Options *options, ثابت حرف *dir, ثابت حرف *filename,
    صحيح userprovided)
{
	حرف *رستہ;
	صحيح i;

	إذا (options->عدد_پچھان_تت_files >= SSH_MAX_پچھان_تت_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_پچھان_تت_FILES);

	إذا (dir == عدم) /* no dir, filename is absolute */
		رستہ = xstrdup(filename);
	وإلا إذا (xasprintf(&رستہ, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", رستہ);

	/* Avoid registering duplicates */
	لكل (i = 0; i < options->عدد_پچھان_تت_files; i++) {
		إذا (options->پچھان_تت_file_userprovided[i] == userprovided &&
		    strcmp(options->پچھان_تت_files[i], رستہ) == 0) {
			debug2_f("ignoring duplicate key %s", رستہ);
			حرر(رستہ);
			أرجع;
		}
	}

	options->پچھان_تت_file_userprovided[options->عدد_پچھان_تت_files] =
	    userprovided;
	options->پچھان_تت_files[options->عدد_پچھان_تت_files++] = رستہ;
}

صحيح
default_ssh_پورٹ(فراغ)
{
	ساكن صحيح پورٹ;
	بنية servent *sp;

	إذا (پورٹ == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		پورٹ = sp ? ntohs(sp->s_port) : SSH_DEFAULT_پورٹ;
	}
	أرجع پورٹ;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ساكن صحيح
execute_وچ_shell(ثابت حرف *cmd)
{
	حرف *shell;
	pid_t pid;
	صحيح حالت;

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

	طالما (waitpid(pid, &حالت, 0) == -1) {
		إذا (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	إذا (!WIFEXITED(حالت)) {
		error("command '%.100s' exited abnormally", cmd);
		أرجع -1;
	}
	debug3("command returned status %d", WEXITSTATUS(حالت));
	أرجع WEXITSTATUS(حالت);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ساكن صحيح
check_میل_ifaddrs(ثابت حرف *addrlist)
{
#جے_تعریف_شدہ HAVE_IFADDRS_H
	بنية ifaddrs *ifa, *ifaddrs = عدم;
	صحيح r, لبھیا = 0;
	حرف addr[NI_MAXHOST];
	socklen_t salen;

	إذا (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		أرجع 0;
	}
	لكل (ifa = ifaddrs; ifa != عدم; ifa = ifa->ifa_اگلا) {
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
#جے_تعریف_شدہ AF_LINK
		حالة AF_LINK:
			/* ignore */
			استمر;
#جے_انت /* AF_LINK */
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
		إذا (addr_میل_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			لبھیا = 1;
			اكسر;
		}
	}
	freeifaddrs(ifaddrs);
	أرجع لبھیا;
#وإلا /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	أرجع 0;
#جے_انت /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ساكن حرف *
expand_میل_exec_or_include_رستہ(ثابت حرف *رستہ, Options *options,
    بنية passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    صحيح final_pass, صحيح is_include_رستہ)
{
	حرف thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	حرف uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	حرف *host, *ret;
	صحيح پورٹ;

	پورٹ = options->پورٹ <= 0 ? default_ssh_پورٹ() : options->پورٹ;
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
	snprintf(portstr, حجم(portstr), "%d", پورٹ);
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (بنانشانی لما لما)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_کلید_alias ?  options->host_کلید_alias : host;

	ret = (is_include_رستہ ? percent_dollar_expand : percent_expand)(رستہ,
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
میل_cfg_سطر(Options *options, ثابت حرف *بھریا_سطر, صحيح *acp, حرف ***avp,
    بنية passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    ثابت حرف *remote_command, صحيح final_pass, صحيح *want_final_pass,
    ثابت حرف *filename, صحيح linenum)
{
	حرف *arg, *oattrib = عدم, *attrib = عدم, *cmd, *host, *criteria;
	ثابت حرف *ruser;
	صحيح r, this_نتیجہ, نتیجہ = 1, گن = 0, negate;

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
	    بھریا_سطر, host, original_host);
	طالما ((attrib = argv_اگلا(acp, avp)) != عدم) {
		/* Terminate on comment */
		إذا (*attrib == '#') {
			argv_consume(acp);
			اكسر;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = عدم;
		this_نتیجہ = 1;
		إذا ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		إذا (strcasecmp(attrib, "all") == 0) {
			إذا (گن > 1 ||
			    ((arg = argv_اگلا(acp, avp)) != عدم &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				نتیجہ = -1;
				اذهب باہرلا;
			}
			إذا (arg != عدم && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			إذا (نتیجہ)
				نتیجہ = negate ? 0 : 1;
			اذهب باہرلا;
		}
		گن++;
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
				this_نتیجہ = نتیجہ = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_نتیجہ ? "" : "not ", oattrib);
			اذهب اگلا;
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
		} وإلا إذا ((arg = argv_اگلا(acp, avp)) == عدم) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			نتیجہ = -1;
			اذهب باہرلا;
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
			نتیجہ = -1;
			اذهب باہرلا;
		}
		إذا (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = میل_hostname(host, arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = میل_hostname(original_host, arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = میل_نمونہ_list(ruser, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = میل_نمونہ_list(pw->pw_name, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "localnetwork") == 0) {
			إذا (addr_میل_cidr_list(عدم, arg) == -1) {
				/* Error already printed */
				نتیجہ = -1;
				اذهب باہرلا;
			}
			r = check_میل_ifaddrs(arg) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = میل_نمونہ_list(SSH_RELEASE, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->ٹیگ == عدم ? "" :
			    options->ٹیگ);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    میل_نمونہ_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == عدم ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    میل_نمونہ_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
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
			r = میل_نمونہ_list(criteria, arg, 0) == 1;
			إذا (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} وإلا إذا (strcasecmp(attrib, "exec") == 0) {
			إذا ((cmd = expand_میل_exec_or_include_رستہ(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == عدم) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			إذا (نتیجہ != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				حرر(cmd);
				اذهب اگلا;
			}
			r = execute_وچ_shell(cmd);
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
				this_نتیجہ = نتیجہ = 0;
		} وإلا {
			error("Unsupported Match attribute %s", attrib);
			نتیجہ = -1;
			اذهب باہرلا;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_نتیجہ ? "": "not ", oattrib,
		    criteria == عدم ? "" : " \"",
		    criteria == عدم ? "" : criteria,
		    criteria == عدم ? "" : "\"");
 اگلا:
		حرر(criteria);
		حرر(oattrib);
		oattrib = attrib = عدم;
	}
	إذا (گن == 0) {
		error("One or more attributes required for Match");
		نتیجہ = -1;
		اذهب باہرلا;
	}
 باہرلا:
	إذا (نتیجہ != -1)
		debug2("match %sfound", نتیجہ ? "" : "not ");
	حرر(oattrib);
	حرر(host);
	أرجع نتیجہ;
}

/* Remove environment variable by pattern */
ساكن فراغ
rm_env(Options *options, ثابت حرف *arg, ثابت حرف *filename, صحيح linenum)
{
	u_int i, j, onum_send_env = options->عدد_send_env;

	/* Remove an environment variable */
	لكل (i = 0; i < options->عدد_send_env; ) {
		إذا (!میل_نمونہ(options->send_env[i], arg + 1)) {
			i++;
			استمر;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		حرر(options->send_env[i]);
		options->send_env[i] = عدم;
		لكل (j = i; j < options->عدد_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = عدم;
		}
		options->عدد_send_env--;
		/* NB. don't increment i */
	}
	إذا (onum_send_env != options->عدد_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->عدد_send_env,
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
	    میل_نمونہ_list(cp, ignored_unknown, 1) == 1)
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
		حرر(cnames[i].سروت_list);
		حرر(cnames[i].نشانہ_list);
	}
	حرر(cnames);
}

/* Multistate option parsing */
بنية multistate {
	حرف *کلید;
	صحيح قدر;
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
#جے_تعریف_شدہ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#جے_انت
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
parse_multistate_قدر(ثابت حرف *arg, ثابت حرف *filename, صحيح linenum,
    ثابت بنية multistate *multistate_ptr)
{
	صحيح i;

	إذا (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		أرجع -1;
	}
	لكل (i = 0; multistate_ptr[i].کلید != عدم; i++) {
		إذا (strcasecmp(arg, multistate_ptr[i].کلید) == 0)
			أرجع multistate_ptr[i].قدر;
	}
	أرجع -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
صحيح
process_config_سطر(Options *options, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *سطر,
    ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags)
{
	أرجع process_config_سطر_ڈونگھائی(options, pw, host, original_host,
	    remote_command, سطر, filename, linenum, activep, flags, عدم, 0);
}

#تعریف_کرو WHITESPACE " \t\r\n"
ساكن صحيح
process_config_سطر_ڈونگھائی(Options *options, بنية passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *سطر,
    ثابت حرف *filename, صحيح linenum, صحيح *activep, صحيح flags,
    صحيح *want_final_pass, صحيح ڈونگھائی)
{
	حرف *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	حرف **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	صحيح r, oactive, negated, opcode, *intptr, قدر, value2, cmdline = 0;
	صحيح remotefwd, dynamicfwd, ca_only = 0, لبھیا = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	لما لما val64;
	ناپ_t len;
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
	إذا ((len = لڑی_لمبائی(سطر)) == 0)
		أرجع 0;
	لكل (len--; len > 0; len--) {
		إذا (strchr(WHITESPACE "\f", سطر[len]) == عدم)
			اكسر;
		سطر[len] = '\0';
	}

	str = سطر;
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
	إذا (argv_ونڈو(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		أرجع -1;
	}
	ac = oac;
	av = oav;

	بدل (opcode) {
	حالة oBadOption:
		/* don't panic, but count bad options */
		اذهب باہرلا;
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
parse_ویلا:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (strcmp(arg, "none") == 0)
			قدر = -1;
		وإلا إذا ((قدر = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}

		قدر = -1;
		multistate_ptr = multistate_flag;
		لكل (i = 0; multistate_ptr[i].کلید != عدم; i++) {
			إذا (strcasecmp(arg, multistate_ptr[i].کلید) == 0) {
				قدر = multistate_ptr[i].قدر;
				اكسر;
			}
		}
		إذا (قدر != -1) {
			إذا (*activep && *intptr == -1)
				*intptr = قدر;
			اكسر;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		إذا (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_رستہ;
		اذهب parse_agent_رستہ;

	حالة oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_اگلا(&ac, &av);
		إذا ((قدر = parse_multistate_قدر(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			اذهب باہرلا;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		اذهب parse_flag;

	حالة oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		اذهب parse_ویلا;

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

	حالة o_Batch_منوال:
		intptr = &options->batch_منوال;
		اذهب parse_flag;

	حالة oCheckHostIP:
		intptr = &options->check_host_ip;
		اذهب parse_flag;

	حالة o_Verify_Host_کلید_DNS:
		intptr = &options->verify_host_کلید_dns;
		multistate_ptr = multistate_yesnoask;
		اذهب parse_multistate;

	حالة o_Strict_Host_کلید_Checking:
		intptr = &options->strict_host_کلید_checking;
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

	حالة o_نمبر_دا_Password_Prompts:
		intptr = &options->نمبر_دا_password_prompts;
		اذهب parse_int;

	حالة o_Rekey_حد_بندی:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			اذهب باہرلا;
		}
		إذا (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وإلا {
			إذا (جانچ_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				اذهب باہرلا;
			}
			إذا (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				اذهب باہرلا;
			}
		}
		إذا (*activep && options->rekey_حد_بندی == -1)
			options->rekey_حد_بندی = val64;
		إذا (ac != 0) { /* optional rekey interval present */
			إذا (strcmp(av[0], "none") == 0) {
				(فراغ)argv_اگلا(&ac, &av);	/* discard */
				اكسر;
			}
			intptr = &options->rekey_interval;
			اذهب parse_ویلا;
		}
		اكسر;

	حالة o_پچھان_تت_File:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep) {
			intptr = &options->عدد_پچھان_تت_files;
			إذا (*intptr >= SSH_MAX_پچھان_تت_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_پچھان_تت_FILES);
				اذهب باہرلا;
			}
			جوڑو_پچھان_تت_file(options, عدم,
			    arg, flags & SSHCONF_USERCONF);
		}
		اكسر;

	حالة oCertificateFile:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep) {
			intptr = &options->عدد_certificate_files;
			إذا (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				اذهب باہرلا;
			}
			جوڑو_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		اكسر;

	حالة oXAuthLocation:
		charptr=&options->xauth_location;
		اذهب parse_string;

	حالة oUser:
		charptr = &options->user;
parse_string:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة o_Global_معلوم_Hosts_File:
		cpptr = (حرف **)&options->system_hostfiles;
		uintptr = &options->عدد_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		قدر = *uintptr == 0; /* was array empty when we started? */
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب باہرلا;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب باہرلا;
				}
			}
			i++;
			إذا (*activep && قدر) {
				إذا ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					اذهب باہرلا;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		اكسر;

	حالة o_User_معلوم_Hosts_File:
		cpptr = (حرف **)&options->user_hostfiles;
		uintptr = &options->عدد_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		اذهب parse_char_array;

	حالة oHostname:
		charptr = &options->hostname;
		اذهب parse_string;

	حالة o_ٹیگ:
		charptr = &options->ٹیگ;
		اذهب parse_string;

	حالة o_Host_کلید_Alias:
		charptr = &options->host_کلید_alias;
		اذهب parse_string;

	حالة oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		اذهب parse_string;

	حالة o_Bind_پتہ:
		charptr = &options->bind_پتہ;
		اذهب parse_string;

	حالة oBindInterface:
		charptr = &options->bind_interface;
		اذهب parse_string;

	حالة oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		اذهب parse_string;

	حالة o_Security_کلید_Provider:
		charptr = &options->sk_provider;
		اذهب parse_string;

	حالة o_معلوم_Hosts_Command:
		charptr = &options->معلوم_hosts_command;
		اذهب parse_command;

	حالة oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		إذا (str == عدم) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
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
			اذهب باہرلا;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		إذا (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			اذهب باہرلا;
		}
		argv_consume(&ac);
		اكسر;

	حالة o_پورٹ:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		قدر = a2port(arg);
		إذا (قدر <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			اذهب باہرلا;
		}
		إذا (*activep && options->پورٹ == -1)
			options->پورٹ = قدر;
		اكسر;

	حالة oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_اگلا(&ac, &av);
		إذا ((errstr = atoi_err(arg, &قدر)) != عدم) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			اذهب باہرلا;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة oCiphers:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب باہرلا;
		}
		إذا (*activep && options->ciphers == عدم)
			options->ciphers = xstrdup(arg);
		اكسر;

	حالة oMacs:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب باہرلا;
		}
		إذا (*activep && options->macs == عدم)
			options->macs = xstrdup(arg);
		اكسر;

	حالة oKexAlgorithms:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*arg != '-' &&
		    !kex_ناں_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب باہرلا;
		}
		إذا (*activep && options->kex_algorithms == عدم)
			options->kex_algorithms = xstrdup(arg);
		اكسر;

	حالة o_Host_کلید_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*arg != '-' &&
		    !sshkey_ناں_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب باہرلا;
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
		arg = argv_اگلا(&ac, &av);
		قدر = log_level_نمبر(arg);
		إذا (قدر == SYSLOG_LEVEL_NOT_سیٹ) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب باہرلا;
		}
		إذا (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_سیٹ)
			*log_level_ptr = (LogLevel) قدر;
		اكسر;

	حالة oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_اگلا(&ac, &av);
		قدر = log_facility_نمبر(arg);
		إذا (قدر == SYSLOG_FACILITY_NOT_سیٹ) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			اذهب باہرلا;
		}
		إذا (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) قدر;
		اكسر;

	حالة oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->عدد_log_verbose;
		i = 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب باہرلا;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب باہرلا;
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
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		إذا (!dynamicfwd) {
			arg2 = argv_اگلا(&ac, &av);
			إذا (arg2 == عدم || *arg2 == '\0') {
				إذا (remotefwd)
					dynamicfwd = 1;
				وإلا {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					اذهب باہرلا;
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
			اذهب باہرلا;
		}

		إذا (*activep) {
			إذا (remotefwd) {
				جوڑو_remote_forward(options, &fwd);
			} وإلا {
				جوڑو_local_forward(options, &fwd);
			}
		}
		اكسر;

	حالة oPermitRemoteOpen:
		uintptr = &options->عدد_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		لبھیا = *uintptr == 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			إذا (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					حرر(arg2);
					اذهب باہرلا;
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
		إذا (لبھیا && *activep) {
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
			اذهب باہرلا;
		}
		*activep = 0;
		arg2 = عدم;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب باہرلا;
			}
			إذا ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				اكسر;
			}
			negated = *arg == '!';
			إذا (negated)
				arg++;
			إذا (میل_نمونہ(host, arg)) {
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

	حالة o_میل:
		إذا (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			اذهب باہرلا;
		}
		قدر = میل_cfg_سطر(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		إذا (قدر < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			اذهب باہرلا;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : قدر;
		اكسر;

	حالة oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (strcmp(arg, "none") == 0)
			قدر = SSH_ESCAPECHAR_NONE;
		وإلا إذا (arg[1] == '\0')
			قدر = (u_char) arg[0];
		وإلا إذا (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			قدر = (u_char) arg[1] & 31;
		وإلا {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة o_پتہ_Family:
		intptr = &options->پتہ_family;
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
		اذهب parse_ویلا;

	حالة o_Server_Alive_گنتی_Max:
		intptr = &options->server_alive_گنتی_max;
		اذهب parse_int;

	حالة oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (*arg == '\0' || strchr(arg, '=') != عدم) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				اذهب باہرلا;
			}
			لبھیا = 1;
			إذا (!*activep)
				استمر;
			إذا (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				استمر;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->عدد_send_env, arg);
		}
		إذا (!لبھیا) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة o_سیٹ_Env:
		لبھیا = options->عدد_setenv == 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (strchr(arg, '=') == عدم) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				اذهب باہرلا;
			}
			إذا (lookup_setenv_وچ_list(arg, strs, nstrs) != عدم) {
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
		إذا (لبھیا && *activep) {
			options->setenv = strs;
			options->عدد_setenv = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة o_Control_رستہ:
		charptr = &options->control_رستہ;
		اذهب parse_string;

	حالة oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		اذهب parse_multistate;

	حالة oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			اذهب باہرلا;
		}
		قدر = 0;
		value2 = 0;	/* timeout */
		إذا (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			قدر = 0;
		وإلا إذا (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			قدر = 1;
		وإلا إذا ((value2 = convtime(arg)) >= 0)
			قدر = 1;
		وإلا {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep && *intptr == -1) {
			*intptr = قدر;
			options->control_persist_timeout = value2;
		}
		اكسر;

	حالة o_Hash_معلوم_Hosts:
		intptr = &options->hash_معلوم_hosts;
		اذهب parse_flag;

	حالة oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		اذهب parse_multistate;

	حالة oTunnelDevice:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		قدر = a2tun(arg, &value2);
		إذا (قدر == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep && options->tun_local == -1) {
			options->tun_local = قدر;
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

	حالة o_Visual_Host_کلید:
		intptr = &options->visual_host_کلید;
		اذهب parse_flag;

	حالة oInclude:
		إذا (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			اذهب باہرلا;
		}
		قدر = 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب باہرلا;
			}
			/* Expand %tokens and environment variables */
			إذا ((p = expand_میل_exec_or_include_رستہ(arg,
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
				اذهب باہرلا;
			}
			إذا (!رستہ_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" رستہ_SSH_USER_DIR : SSHDIR, p);
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
				اذهب باہرلا;
			}
			حرر(arg2);
			oactive = *activep;
			لكل (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], ڈونگھائی,
				    oactive ? "" : " (parse only)");
				r = read_config_file_ڈونگھائی(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, ڈونگھائی + 1);
				إذا (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					اذهب باہرلا;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				إذا (r != 1)
					قدر = -1;
			}
			globfree(&gl);
		}
		إذا (قدر != 0)
			ret = قدر;
		اكسر;

	حالة oIPQoS:
		arg = argv_اگلا(&ac, &av);
		إذا ((قدر = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			اذهب باہرلا;
		}
		إذا (قدر == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			قدر = ودھ_توں_ودھ_عدد;
		}
		arg = argv_اگلا(&ac, &av);
		إذا (arg == عدم)
			value2 = قدر;
		وإلا إذا ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			اذهب باہرلا;
		}
		إذا (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = ودھ_توں_ودھ_عدد;
		}
		إذا (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = قدر;
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
		لبھیا = options->عدد_canonical_domains == 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب باہرلا;
				}
			}
			إذا (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				اذهب باہرلا;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (لبھیا && *activep) {
			options->canonical_domains = strs;
			options->عدد_canonical_domains = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oCanonicalizePermittedCNAMEs:
		لبھیا = options->عدد_permitted_cnames == 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب باہرلا;
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
					اذهب باہرلا;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    حجم(*cnames));
			cnames[ncnames].سروت_list = xstrdup(arg);
			cnames[ncnames].نشانہ_list = xstrdup(arg2);
			ncnames++;
		}
		إذا (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (لبھیا && *activep) {
			options->permitted_cnames = cnames;
			options->عدد_permitted_cnames = ncnames;
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

	حالة o_دھارا_Local_Bind_نقاب:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			اذهب باہرلا;
		}
		/* Parse mode in octal format */
		قدر = strtol(arg, &endofnumber, 8);
		إذا (arg == endofnumber || قدر < 0 || قدر > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep &&
		    options->fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1)
			options->fwd_opts.streamlocal_bind_نقاب = (منوال_t)قدر;
		اكسر;

	حالة o_دھارا_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		اذهب parse_flag;

	حالة o_Revoked_Host_کلیدیں:
		uintptr = &options->عدد_revoked_host_کلیدیں;
		cppptr = &options->revoked_host_کلیدیں;
		لبھیا = *uintptr == 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب باہرلا;
			}
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب باہرلا;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		إذا (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		إذا (لبھیا && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا ((قدر = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			اذهب باہرلا;
		}
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
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

	حالة o_جوڑو_کلیدیں_منزل_Agent:
		arg = argv_اگلا(&ac, &av);
		arg2 = argv_اگلا(&ac, &av);
		قدر = parse_multistate_قدر(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		إذا (قدر == 3 && arg2 != عدم) {
			/* allow "AddKeysToAgent confirm 5m" */
			إذا ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				اذهب باہرلا;
			}
		} وإلا إذا (قدر == -1 && arg2 == عدم) {
			إذا ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				اذهب باہرلا;
			}
			قدر = 1; /* yes */
		} وإلا إذا (قدر == -1 || arg2 != عدم) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			اذهب باہرلا;
		}
		إذا (*activep && options->جوڑو_کلیدیں_منزل_agent == -1) {
			options->جوڑو_کلیدیں_منزل_agent = قدر;
			options->جوڑو_کلیدیں_منزل_agent_lifespan = value2;
		}
		اكسر;

	حالة o_پچھان_تت_Agent:
		charptr = &options->پچھان_تت_agent;
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
		}
  parse_agent_رستہ:
		/* Extra validation if the string represents an env var. */
		إذا ((arg2 = dollar_expand(&r, arg)) == عدم || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			اذهب باہرلا;
		}
		حرر(arg2);
		/* check for legacy environment format */
		إذا (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			اذهب باہرلا;
		}
		إذا (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		اذهب parse_flag;

	حالة oRequiredRSASize:
		intptr = &options->required_rsa_ناپ;
		اذهب parse_int;

	حالة oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		اذهب parse_multistate;

	حالة oObscureKeystrokeTiming:
		قدر = -1;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			إذا (قدر != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				اذهب باہرلا;
			}
			إذا (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				قدر = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			وإلا إذا (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				قدر = 0;
			وإلا إذا (لڑی_مقابلہ(arg, "interval:", 9) == 0) {
				إذا ((errstr = atoi_err(arg + 9,
				    &قدر)) != عدم) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					اذهب باہرلا;
				}
				إذا (قدر <= 0 || قدر > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					اذهب باہرلا;
				}
			} وإلا {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				اذهب باہرلا;
			}
		}
		إذا (قدر == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			اذهب باہرلا;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		إذا (*activep && *intptr == -1)
			*intptr = قدر;
		اكسر;

	حالة oChannelTimeout:
		لبھیا = options->عدد_channel_timeouts == 0;
		طالما ((arg = argv_اگلا(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			إذا (strcasecmp(arg, "none") == 0) {
				إذا (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب باہرلا;
				}
			} وإلا إذا (parse_نمونہ_interval(arg,
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
		إذا (لبھیا && *activep) {
			options->channel_timeouts = strs;
			options->عدد_channel_timeouts = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة o_نسخہ_Addendum:
		إذا (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		إذا (strchr(str + len, '\r') != عدم) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		إذا ((arg = strchr(سطر, '#')) != عدم) {
			*arg = '\0';
			rtrim(سطر);
		}
		إذا (*activep && options->نسخہ_addendum == عدم) {
			إذا (strcasecmp(str + len, "none") == 0)
				options->نسخہ_addendum = xstrdup("");
			وإلا
				options->نسخہ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		اكسر;

	حالة oRefuseConnection:
		arg = argv_اگلا(&ac, &av);
		إذا (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			اذهب باہرلا;
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
		اذهب باہرلا;
	}

	/* Check that there is no garbage at end of line. */
	إذا (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		اذهب باہرلا;
	}

	/* success */
	ret = 0;
 باہرلا:
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
	صحيح سرگرم = 1;

	أرجع read_config_file_ڈونگھائی(filename, pw, host, original_host,
	    remote_command, options, flags, &سرگرم, want_final_pass, 0);
}

#تعریف_کرو READCONF_MAX_ڈونگھائی	16
ساكن صحيح
read_config_file_ڈونگھائی(ثابت حرف *filename, بنية passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحيح flags, صحيح *activep, صحيح *want_final_pass, صحيح ڈونگھائی)
{
	FILE *f;
	حرف *سطر = عدم;
	ناپ_t linesize = 0;
	صحيح linenum;
	صحيح bad_options = 0;

	إذا (ڈونگھائی < 0 || ڈونگھائی > READCONF_MAX_ڈونگھائی)
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
	طالما (getline(&سطر, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		إذا (process_config_سطر_ڈونگھائی(options, pw, host, original_host,
		    remote_command, سطر, filename, linenum, activep, flags,
		    want_final_pass, ڈونگھائی) != 0)
			bad_options++;
	}
	حرر(سطر);
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
	إذا (options->عدد_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].سروت_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].نشانہ_list, "") == 0)
		أرجع 0;
	أرجع options->عدد_permitted_cnames > 0;
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
	options->forward_agent_sock_رستہ = عدم;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = عدم;
	options->stdio_forward_پورٹ = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = عدم;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_نقاب = (منوال_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = عدم;
	options->hostbased_authentication = -1;
	options->batch_منوال = -1;
	options->check_host_ip = -1;
	options->strict_host_کلید_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->پورٹ = -1;
	options->پتہ_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->نمبر_دا_password_prompts = -1;
	options->ciphers = عدم;
	options->macs = عدم;
	options->kex_algorithms = عدم;
	options->hostkeyalgorithms = عدم;
	options->ca_sign_algorithms = عدم;
	options->عدد_پچھان_تت_files = 0;
	memset(options->پچھان_تت_کلیدیں, 0, حجم(options->پچھان_تت_کلیدیں));
	options->عدد_certificate_files = 0;
	memset(options->certificates, 0, حجم(options->certificates));
	options->hostname = عدم;
	options->host_کلید_alias = عدم;
	options->proxy_command = عدم;
	options->jump_user = عدم;
	options->jump_host = عدم;
	options->jump_پورٹ = -1;
	options->jump_extra = عدم;
	options->user = عدم;
	options->escape_char = -1;
	options->عدد_system_hostfiles = 0;
	options->عدد_user_hostfiles = 0;
	options->local_forwards = عدم;
	options->عدد_local_forwards = 0;
	options->remote_forwards = عدم;
	options->عدد_remote_forwards = 0;
	options->permitted_remote_opens = عدم;
	options->عدد_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_سیٹ;
	options->log_level = SYSLOG_LEVEL_NOT_سیٹ;
	options->عدد_log_verbose = 0;
	options->log_verbose = عدم;
	options->preferred_authentications = عدم;
	options->bind_پتہ = عدم;
	options->bind_interface = عدم;
	options->pkcs11_provider = عدم;
	options->sk_provider = عدم;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_حد_بندی = -1;
	options->rekey_interval = -1;
	options->verify_host_کلید_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_گنتی_max = -1;
	options->send_env = عدم;
	options->عدد_send_env = 0;
	options->setenv = عدم;
	options->عدد_setenv = 0;
	options->control_رستہ = عدم;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_معلوم_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = عدم;
	options->permit_local_command = -1;
	options->remote_command = عدم;
	options->جوڑو_کلیدیں_منزل_agent = -1;
	options->جوڑو_کلیدیں_منزل_agent_lifespan = -1;
	options->پچھان_تت_agent = عدم;
	options->visual_host_کلید = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = عدم;
	options->عدد_canonical_domains = 0;
	options->عدد_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_کلیدیں = عدم;
	options->عدد_revoked_host_کلیدیں = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = عدم;
	options->pubkey_accepted_algos = عدم;
	options->معلوم_hosts_command = عدم;
	options->required_rsa_ناپ = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->ٹیگ = عدم;
	options->channel_timeouts = عدم;
	options->عدد_channel_timeouts = 0;
	options->نسخہ_addendum = عدم;
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
	حرف *all_cipher, *all_mac, *all_kex, *all_کلید, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_کلید, *def_sig;
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
		options->xauth_location = xstrdup(رستہ_XAUTH);
	إذا (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	إذا (options->fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1)
		options->fwd_opts.streamlocal_bind_نقاب = 0177;
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
	إذا (options->batch_منوال == -1)
		options->batch_منوال = 0;
	إذا (options->check_host_ip == -1)
		options->check_host_ip = 0;
	إذا (options->strict_host_کلید_checking == -1)
		options->strict_host_کلید_checking = SSH_STRICT_HOSTKEY_ASK;
	إذا (options->compression == -1)
		options->compression = 0;
	إذا (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	إذا (options->پورٹ == -1)
		options->پورٹ = 0;	/* Filled in ssh_connect. */
	إذا (options->پتہ_family == -1)
		options->پتہ_family = AF_UNSPEC;
	إذا (options->connection_attempts == -1)
		options->connection_attempts = 1;
	إذا (options->نمبر_دا_password_prompts == -1)
		options->نمبر_دا_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	إذا (options->جوڑو_کلیدیں_منزل_agent == -1) {
		options->جوڑو_کلیدیں_منزل_agent = 0;
		options->جوڑو_کلیدیں_منزل_agent_lifespan = 0;
	}
	إذا (options->عدد_پچھان_تت_files == 0) {
		جوڑو_پچھان_تت_file(options, "~/", رستہ_SSH_CLIENT_ID_RSA, 0);
		جوڑو_پچھان_تت_file(options, "~/", رستہ_SSH_CLIENT_ID_ECDSA, 0);
		جوڑو_پچھان_تت_file(options, "~/",
		    رستہ_SSH_CLIENT_ID_ECDSA_SK, 0);
		جوڑو_پچھان_تت_file(options, "~/",
		    رستہ_SSH_CLIENT_ID_ED25519, 0);
		جوڑو_پچھان_تت_file(options, "~/",
		    رستہ_SSH_CLIENT_ID_ED25519_SK, 0);
		جوڑو_پچھان_تت_file(options, "~/",
		    رستہ_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	إذا (options->escape_char == -1)
		options->escape_char = '~';
	إذا (options->عدد_system_hostfiles == 0) {
		options->system_hostfiles[options->عدد_system_hostfiles++] =
		    xstrdup(رستہ_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->عدد_system_hostfiles++] =
		    xstrdup(رستہ_SSH_SYSTEM_HOSTFILE2);
	}
	إذا (options->update_hostkeys == -1) {
		إذا (options->verify_host_کلید_dns <= 0 &&
		    (options->عدد_user_hostfiles == 0 ||
		    (options->عدد_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], رستہ_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		وإلا
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	إذا (options->عدد_user_hostfiles == 0) {
		options->user_hostfiles[options->عدد_user_hostfiles++] =
		    xstrdup(رستہ_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->عدد_user_hostfiles++] =
		    xstrdup(رستہ_SSH_USER_HOSTFILE2);
	}
	إذا (options->log_level == SYSLOG_LEVEL_NOT_سیٹ)
		options->log_level = SYSLOG_LEVEL_INFO;
	إذا (options->log_facility == SYSLOG_FACILITY_NOT_سیٹ)
		options->log_facility = SYSLOG_FACILITY_USER;
	إذا (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	إذا (options->identities_only == -1)
		options->identities_only = 0;
	إذا (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	إذا (options->rekey_حد_بندی == -1)
		options->rekey_حد_بندی = 0;
	إذا (options->rekey_interval == -1)
		options->rekey_interval = 0;
	إذا (options->verify_host_کلید_dns == -1)
		options->verify_host_کلید_dns = 0;
	إذا (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	إذا (options->server_alive_گنتی_max == -1)
		options->server_alive_گنتی_max = 3;
	إذا (options->control_master == -1)
		options->control_master = 0;
	إذا (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	إذا (options->hash_معلوم_hosts == -1)
		options->hash_معلوم_hosts = 0;
	إذا (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	إذا (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	إذا (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	إذا (options->permit_local_command == -1)
		options->permit_local_command = 0;
	إذا (options->visual_host_کلید == -1)
		options->visual_host_کلید = 0;
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
#جے_تعریف_شدہ ENABLE_SK_اندرونی
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("internal");
#وإلا
	إذا (options->sk_provider == عدم)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#جے_انت
	إذا (options->required_rsa_ناپ == -1)
		options->required_rsa_ناپ = SSH_RSA_MINIMUM_MODULUS_ناپ;
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
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = میل_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = میل_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = میل_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_کلید = میل_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
	def_sig = میل_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#تعریف_کرو ASSEMBLE(what, defaults, all) \
	افعل { \
		إذا ((r = kex_assemble_ناں(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			اذهب fail; \
		} \
	} طالما (0)
	options->kex_algorithms_سیٹ = options->kex_algorithms != عدم;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(pubkey_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#تعریف_رد ASSEMBLE

#تعریف_کرو CLEAR_ON_NONE(v) \
	افعل { \
		إذا (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
#تعریف_کرو CLEAR_ON_NONE_ARRAY(v, nv, none) \
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
	CLEAR_ON_NONE(options->control_رستہ);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->معلوم_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, عدد_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_کلیدیں, عدد_revoked_host_کلیدیں, "none");
#تعریف_رد CLEAR_ON_NONE
#تعریف_رد CLEAR_ON_NONE_ARRAY
	إذا (options->jump_host != عدم &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_پورٹ == 0 && options->jump_user == عدم) {
		حرر(options->jump_host);
		options->jump_host = عدم;
	}
	إذا (options->عدد_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		حرر(options->permitted_cnames[0].سروت_list);
		حرر(options->permitted_cnames[0].نشانہ_list);
		memset(options->permitted_cnames, '\0',
		    حجم(*options->permitted_cnames));
		options->عدد_permitted_cnames = 0;
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
	حرر(all_کلید);
	حرر(all_sig);
	حرر(def_cipher);
	حرر(def_mac);
	حرر(def_kex);
	حرر(def_کلید);
	حرر(def_sig);
	أرجع ret;
}

فراغ
free_options(Options *o)
{
	صحيح i;

	إذا (o == عدم)
		أرجع;

#تعریف_کرو FREE_ARRAY(type, n, a) \
	افعل { \
		type _i; \
		لكل (_i = 0; _i < (n); _i++) \
			حرر((a)[_i]); \
	} طالما (0)

	حرر(o->forward_agent_sock_رستہ);
	حرر(o->xauth_location);
	FREE_ARRAY(u_int, o->عدد_log_verbose, o->log_verbose);
	حرر(o->log_verbose);
	حرر(o->ciphers);
	حرر(o->macs);
	حرر(o->hostkeyalgorithms);
	حرر(o->kex_algorithms);
	حرر(o->ca_sign_algorithms);
	حرر(o->hostname);
	حرر(o->host_کلید_alias);
	حرر(o->proxy_command);
	حرر(o->user);
	FREE_ARRAY(u_int, o->عدد_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->عدد_user_hostfiles, o->user_hostfiles);
	حرر(o->preferred_authentications);
	حرر(o->bind_پتہ);
	حرر(o->bind_interface);
	حرر(o->pkcs11_provider);
	حرر(o->sk_provider);
	لكل (i = 0; i < o->عدد_پچھان_تت_files; i++) {
		حرر(o->پچھان_تت_files[i]);
		sshkey_free(o->پچھان_تت_کلیدیں[i]);
	}
	لكل (i = 0; i < o->عدد_certificate_files; i++) {
		حرر(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	حرر(o->پچھان_تت_agent);
	لكل (i = 0; i < o->عدد_local_forwards; i++) {
		حرر(o->local_forwards[i].listen_host);
		حرر(o->local_forwards[i].listen_رستہ);
		حرر(o->local_forwards[i].connect_host);
		حرر(o->local_forwards[i].connect_رستہ);
	}
	حرر(o->local_forwards);
	لكل (i = 0; i < o->عدد_remote_forwards; i++) {
		حرر(o->remote_forwards[i].listen_host);
		حرر(o->remote_forwards[i].listen_رستہ);
		حرر(o->remote_forwards[i].connect_host);
		حرر(o->remote_forwards[i].connect_رستہ);
	}
	حرر(o->remote_forwards);
	حرر(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->عدد_send_env, o->send_env);
	حرر(o->send_env);
	FREE_ARRAY(u_int, o->عدد_setenv, o->setenv);
	حرر(o->setenv);
	حرر(o->control_رستہ);
	حرر(o->local_command);
	حرر(o->remote_command);
	FREE_ARRAY(صحيح, o->عدد_canonical_domains, o->canonical_domains);
	لكل (i = 0; i < o->عدد_permitted_cnames; i++) {
		حرر(o->permitted_cnames[i].سروت_list);
		حرر(o->permitted_cnames[i].نشانہ_list);
	}
	FREE_ARRAY(u_int, o->عدد_revoked_host_کلیدیں, o->revoked_host_کلیدیں);
	حرر(o->revoked_host_کلیدیں);
	حرر(o->hostbased_accepted_algos);
	حرر(o->pubkey_accepted_algos);
	حرر(o->jump_user);
	حرر(o->jump_host);
	حرر(o->jump_extra);
	حرر(o->ignored_unknown);
	explicit_bzero(o, حجم(*o));
#تعریف_رد FREE_ARRAY
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
parse_fwd_میدان(حرف **p, بنية fwdarg *fwd)
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
			memmove(cp, cp + 1, لڑی_لمبائی(cp + 1) + 1);
			إذا (*cp == '\0')
				أرجع -1;
			اكسر;
		حالة '/':
			ispath = 1;
			اكسر;
		حالة ':':
			*cp++ = '\0';
			اذهب پورا;
		}
	}
پورا:
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
	طالما (خلا_اے((u_char)*cp))
		cp++;

	لكل (i = 0; i < 4; ++i) {
		إذا (parse_fwd_میدان(&cp, &fwdargs[i]) != 0)
			اكسر;
	}

	/* Check for trailing garbage */
	إذا (cp != عدم && *cp != '\0') {
		i = 0;	/* failure */
	}

	بدل (i) {
	حالة 1:
		إذا (fwdargs[0].ispath) {
			fwd->listen_رستہ = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = پورٹ_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = عدم;
			fwd->listen_پورٹ = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		اكسر;

	حالة 2:
		إذا (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_رستہ = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = پورٹ_STREAMLOCAL;
			fwd->connect_رستہ = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = پورٹ_STREAMLOCAL;
		} وإلا إذا (fwdargs[1].ispath) {
			fwd->listen_host = عدم;
			fwd->listen_پورٹ = a2port(fwdargs[0].arg);
			fwd->connect_رستہ = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = پورٹ_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		اكسر;

	حالة 3:
		إذا (fwdargs[0].ispath) {
			fwd->listen_رستہ = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = پورٹ_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = a2port(fwdargs[2].arg);
		} وإلا إذا (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = a2port(fwdargs[1].arg);
			fwd->connect_رستہ = xstrdup(fwdargs[2].arg);
			fwd->connect_پورٹ = پورٹ_STREAMLOCAL;
		} وإلا {
			fwd->listen_host = عدم;
			fwd->listen_پورٹ = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = a2port(fwdargs[2].arg);
		}
		اكسر;

	حالة 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_پورٹ = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_پورٹ = a2port(fwdargs[3].arg);
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
			إذا (fwd->connect_رستہ == عدم &&
			    fwd->listen_رستہ == عدم)
				اذهب fail_free;
		}
		إذا (fwd->connect_پورٹ <= 0 && fwd->connect_رستہ == عدم)
			اذهب fail_free;
	}

	إذا ((fwd->listen_پورٹ < 0 && fwd->listen_رستہ == عدم) ||
	    (!remotefwd && fwd->listen_پورٹ == 0))
		اذهب fail_free;
	إذا (fwd->connect_host != عدم &&
	    لڑی_لمبائی(fwd->connect_host) >= NI_MAXHOST)
		اذهب fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	إذا (fwd->connect_رستہ != عدم &&
	    لڑی_لمبائی(fwd->connect_رستہ) >= رستہ_MAX_SUN)
		اذهب fail_free;
	إذا (fwd->listen_host != عدم &&
	    لڑی_لمبائی(fwd->listen_host) >= NI_MAXHOST)
		اذهب fail_free;
	إذا (fwd->listen_رستہ != عدم &&
	    لڑی_لمبائی(fwd->listen_رستہ) >= رستہ_MAX_SUN)
		اذهب fail_free;

	أرجع (i);

 fail_free:
	حرر(fwd->connect_host);
	fwd->connect_host = عدم;
	حرر(fwd->connect_رستہ);
	fwd->connect_رستہ = عدم;
	حرر(fwd->listen_host);
	fwd->listen_host = عدم;
	حرر(fwd->listen_رستہ);
	fwd->listen_رستہ = عدم;
	أرجع (0);
}

صحيح
ssh_valid_hostname(ثابت حرف *s)
{
	ناپ_t i;

	إذا (*s == '-')
		أرجع 0;
	لكل (i = 0; s[i] != 0; i++) {
		إذا (strchr("'`\"$\\;&<>|(){},", s[i]) != عدم ||
		    خلا_اے((u_char)s[i]) || iscntrl((u_char)s[i]))
			أرجع 0;
	}
	أرجع 1;
}

صحيح
ssh_valid_ruser(ثابت حرف *s)
{
	ناپ_t i;

	إذا (*s == '-')
		أرجع 0;
	لكل (i = 0; s[i] != 0; i++) {
		إذا (iscntrl((u_char)s[i]))
			أرجع 0;
		إذا (strchr("'`\";&<>|(){}$\\", s[i]) != عدم)
			أرجع 0;
		/* Disallow '-' after whitespace */
		إذا (خلا_اے((u_char)s[i]) && s[i + 1] == '-')
			أرجع 0;
	}
	أرجع 1;
}

صحيح
parse_jump(ثابت حرف *s, Options *o, صحيح strict, صحيح سرگرم)
{
	حرف *orig = عدم, *sdup = عدم, *cp;
	حرف *tmp_user = عدم, *tmp_host = عدم, *host = عدم, *user = عدم;
	صحيح r, ret = -1, tmp_پورٹ = -1, پورٹ = -1, پہلا = 1;

	إذا (strcasecmp(s, "none") == 0) {
		إذا (سرگرم && o->jump_host == عدم) {
			o->jump_host = xstrdup("none");
			o->jump_پورٹ = 0;
		}
		أرجع 0;
	}

	orig = xstrdup(s);
	إذا ((cp = strchr(orig, '#')) != عدم)
		*cp = '\0';
	rtrim(orig);

	سرگرم &= o->proxy_command == عدم && o->jump_host == عدم;
	sdup = xstrdup(orig);
	افعل {
		/* Work backwards through string */
		إذا ((cp = strrchr(sdup, ',')) == عدم)
			cp = sdup; /*آخری*/
		وإلا
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_پورٹ);
		إذا (r == -1 || (r == 1 && parse_user_host_پورٹ(cp,
		    &tmp_user, &tmp_host, &tmp_پورٹ) != 0))
			اذهب باہرلا; /* error already logged */
		إذا (strict) {
			إذا (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				اذهب باہرلا;
			}
			إذا (tmp_user != عدم && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				اذهب باہرلا;
			}
		}
		إذا (پہلا) {
			user = tmp_user;
			host = tmp_host;
			پورٹ = tmp_پورٹ;
			tmp_user = tmp_host = عدم; /* transferred */
		}
		پہلا = 0; /* only check syntax for subsequent hosts */
		حرر(tmp_user);
		حرر(tmp_host);
		tmp_user = tmp_host = عدم;
		tmp_پورٹ = -1;
	} طالما (cp != sdup);

	/* success */
	إذا (سرگرم) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_پورٹ = پورٹ;
		o->proxy_command = xstrdup("none");
		user = host = عدم; /* transferred */
		إذا (orig != عدم && (cp = strrchr(orig, ',')) != عدم) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 باہرلا:
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
	حرف *user = عدم, *host = عدم, *رستہ = عدم;
	صحيح r, پورٹ;

	r = parse_uri("ssh", uri, &user, &host, &پورٹ, &رستہ);
	إذا (r == 0 && رستہ != عدم)
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
			*portp = پورٹ;
	}
	حرر(user);
	حرر(host);
	حرر(رستہ);
	أرجع r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ساكن ثابت حرف *
fmt_multistate_int(صحيح val, ثابت بنية multistate *m)
{
	u_int i;

	لكل (i = 0; m[i].کلید != عدم; i++) {
		إذا (m[i].قدر == val)
			أرجع m[i].کلید;
	}
	أرجع "UNKNOWN";
}

ساكن ثابت حرف *
fmt_intarg(OpCodes کوڈ, صحيح val)
{
	إذا (val == -1)
		أرجع "unset";
	بدل (کوڈ) {
	حالة o_پتہ_Family:
		أرجع fmt_multistate_int(val, multistate_addressfamily);
	حالة oCompression:
		أرجع fmt_multistate_int(val, multistate_compression);
	حالة o_Verify_Host_کلید_DNS:
	حالة oUpdateHostkeys:
		أرجع fmt_multistate_int(val, multistate_yesnoask);
	حالة o_Strict_Host_کلید_Checking:
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
	حالة o_جوڑو_کلیدیں_منزل_Agent:
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
lookup_opcode_name(OpCodes کوڈ)
{
	u_int i;

	لكل (i = 0; keywords[i].name != عدم; i++)
		إذا (keywords[i].opcode == کوڈ)
			أرجع(keywords[i].name);
	أرجع "UNKNOWN";
}

ساكن فراغ
dump_cfg_int(OpCodes کوڈ, صحيح val)
{
	إذا (کوڈ == oObscureKeystrokeTiming) {
		إذا (val == 0) {
			لکھو("%s no\n", lookup_opcode_name(کوڈ));
			أرجع;
		} وإلا إذا (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			لکھو("%s yes\n", lookup_opcode_name(کوڈ));
			أرجع;
		}
		/* FALLTHROUGH */
	}
	لکھو("%s %d\n", lookup_opcode_name(کوڈ), val);
}

ساكن فراغ
dump_cfg_fmtint(OpCodes کوڈ, صحيح val)
{
	لکھو("%s %s\n", lookup_opcode_name(کوڈ), fmt_intarg(کوڈ, val));
}

ساكن فراغ
dump_cfg_string(OpCodes کوڈ, ثابت حرف *val)
{
	إذا (val == عدم)
		أرجع;
	لکھو("%s %s\n", lookup_opcode_name(کوڈ), val);
}

ساكن فراغ
dump_cfg_strarray(OpCodes کوڈ, u_int گنتی, حرف **vals)
{
	u_int i;

	لكل (i = 0; i < گنتی; i++)
		لکھو("%s %s\n", lookup_opcode_name(کوڈ), vals[i]);
}

ساكن فراغ
dump_cfg_strarray_oneline(OpCodes کوڈ, u_int گنتی, حرف **vals)
{
	u_int i;

	لکھو("%s", lookup_opcode_name(کوڈ));
	إذا (گنتی == 0)
		لکھو(" none");
	لكل (i = 0; i < گنتی; i++)
		لکھو(" %s",  vals[i]);
	لکھو("\n");
}

ساكن فراغ
dump_cfg_forwards(OpCodes کوڈ, u_int گنتی, ثابت بنية Forward *fwds)
{
	ثابت بنية Forward *fwd;
	u_int i;

	/* oDynamicForward */
	لكل (i = 0; i < گنتی; i++) {
		fwd = &fwds[i];
		إذا (کوڈ == oDynamicForward && fwd->connect_host != عدم &&
		    strcmp(fwd->connect_host, "socks") != 0)
			استمر;
		إذا (کوڈ == oLocalForward && fwd->connect_host != عدم &&
		    strcmp(fwd->connect_host, "socks") == 0)
			استمر;
		لکھو("%s", lookup_opcode_name(کوڈ));
		إذا (fwd->listen_پورٹ == پورٹ_STREAMLOCAL)
			لکھو(" %s", fwd->listen_رستہ);
		وإلا إذا (fwd->listen_host == عدم)
			لکھو(" %d", fwd->listen_پورٹ);
		وإلا {
			لکھو(" [%s]:%d",
			    fwd->listen_host, fwd->listen_پورٹ);
		}
		إذا (کوڈ != oDynamicForward) {
			إذا (fwd->connect_پورٹ == پورٹ_STREAMLOCAL)
				لکھو(" %s", fwd->connect_رستہ);
			وإلا إذا (fwd->connect_host == عدم)
				لکھو(" %d", fwd->connect_پورٹ);
			وإلا {
				لکھو(" [%s]:%d",
				    fwd->connect_host, fwd->connect_پورٹ);
			}
		}
		لکھو("\n");
	}
}

فراغ
dump_client_config(Options *o, ثابت حرف *host)
{
	صحيح i, r;
	حرف buf[8], *all_کلید;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	إذا ((r = kex_assemble_ناں(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_کلید)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	حرر(all_کلید);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(o_پورٹ, o->پورٹ);

	/* Flag options */
	dump_cfg_fmtint(o_پتہ_Family, o->پتہ_family);
	dump_cfg_fmtint(o_Batch_منوال, o->batch_منوال);
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
#جے_تعریف_شدہ GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#جے_انت /* GSSAPI */
	dump_cfg_fmtint(o_Hash_معلوم_Hosts, o->hash_معلوم_hosts);
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
	dump_cfg_fmtint(o_دھارا_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_کلید_Checking, o->strict_host_کلید_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_کلید_DNS, o->verify_host_کلید_dns);
	dump_cfg_fmtint(o_Visual_Host_کلید, o->visual_host_کلید);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_نمبر_دا_Password_Prompts, o->نمبر_دا_password_prompts);
	dump_cfg_int(o_Server_Alive_گنتی_Max, o->server_alive_گنتی_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_ناپ);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_پتہ, o->bind_پتہ);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_رستہ, o->control_رستہ);
	dump_cfg_string(o_Host_کلید_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_کلید_Alias, o->host_کلید_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_پچھان_تت_Agent, o->پچھان_تت_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#جے_تعریف_شدہ ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#جے_انت
	dump_cfg_string(o_Security_کلید_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_معلوم_Hosts_Command, o->معلوم_hosts_command);
	dump_cfg_string(o_ٹیگ, o->ٹیگ);
	dump_cfg_string(o_نسخہ_Addendum, o->نسخہ_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->عدد_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->عدد_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->عدد_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_پچھان_تت_File, o->عدد_پچھان_تت_files, o->پچھان_تت_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->عدد_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->عدد_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(o_Global_معلوم_Hosts_File, o->عدد_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(o_User_معلوم_Hosts_File, o->عدد_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_کلیدیں, o->عدد_revoked_host_کلیدیں, o->revoked_host_کلیدیں);
	dump_cfg_strarray(oSendEnv, o->عدد_send_env, o->send_env);
	dump_cfg_strarray(o_سیٹ_Env, o->عدد_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->عدد_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->عدد_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	إذا (o->عدد_permitted_remote_opens == 0)
		لکھو("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	وإلا
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->عدد_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	إذا (o->جوڑو_کلیدیں_منزل_agent_lifespan <= 0)
		dump_cfg_fmtint(o_جوڑو_کلیدیں_منزل_Agent, o->جوڑو_کلیدیں_منزل_agent);
	وإلا {
		لکھو("addkeystoagent%s %d\n",
		    o->جوڑو_کلیدیں_منزل_agent == 3 ? " confirm" : "",
		    o->جوڑو_کلیدیں_منزل_agent_lifespan);
	}

	/* oForwardAgent */
	إذا (o->forward_agent_sock_رستہ == عدم)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	وإلا
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_رستہ);

	/* oConnectTimeout */
	إذا (o->connection_timeout == -1)
		لکھو("connecttimeout none\n");
	وإلا
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	لکھو("tunneldevice");
	إذا (o->tun_local == SSH_TUNID_ANY)
		لکھو(" any");
	وإلا
		لکھو(" %d", o->tun_local);
	إذا (o->tun_remote == SSH_TUNID_ANY)
		لکھو(":any");
	وإلا
		لکھو(":%d", o->tun_remote);
	لکھو("\n");

	/* oCanonicalizePermittedCNAMEs */
	لکھو("canonicalizepermittedcnames");
	إذا (o->عدد_permitted_cnames == 0)
		لکھو(" none");
	لكل (i = 0; i < o->عدد_permitted_cnames; i++) {
		لکھو(" %s:%s", o->permitted_cnames[i].سروت_list,
		    o->permitted_cnames[i].نشانہ_list);
	}
	لکھو("\n");

	/* oControlPersist */
	إذا (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	وإلا
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	إذا (o->escape_char == SSH_ESCAPECHAR_NONE)
		لکھو("escapechar none\n");
	وإلا {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		لکھو("escapechar %s\n", buf);
	}

	/* oIPQoS */
	لکھو("ipqos %s ", iptos2str(o->ip_qos_interactive));
	لکھو("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	لکھو("rekeylimit %llu %d\n",
	    (بنانشانی لما لما)o->rekey_حد_بندی, o->rekey_interval);

	/* oStreamLocalBindMask */
	لکھو("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_نقاب);

	/* oLogFacility */
	لکھو("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	إذا (o->jump_host == عدم)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	وإلا {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != عدم ||
		    strspn(o->jump_host, "1234567890.") == لڑی_لمبائی(o->jump_host);
		snprintf(buf, حجم(buf), "%d", o->jump_پورٹ);
		لکھو("proxyjump %s%s%s%s%s%s%s%s%s\n",
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
		    o->jump_پورٹ <= 0 ? "" : ":",
		    o->jump_پورٹ <= 0 ? "" : buf);
	}
}
