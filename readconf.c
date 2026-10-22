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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/wait.h>
#شامل <sys/un.h>

#شامل <net/if.h>
#شامل <netinet/in.h>
#شامل <netinet/ip.h>
#شامل <arpa/inet.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <glob.h>
#شامل <ifaddrs.h>
#شامل <limits.h>
#شامل <netdb.h>
#شامل <paths.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <util.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#اگر_ختم

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "cipher.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "sshkey.h"
#شامل "misc.h"
#شامل "readconf.h"
#شامل "match.h"
#شامل "kex.h"
#شامل "mac.h"
#شامل "myproposal.h"
#شامل "digest.h"
#شامل "version.h"

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

ساکن صحیح read_config_file_گہرائی(ثابت حرف *filename, ساخت passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحیح flags, صحیح *activep, صحیح *want_final_pass, صحیح گہرائی);
ساکن صحیح process_config_سطر_گہرائی(Options *options, ساخت passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    حرف *سطر, ثابت حرف *filename, صحیح linenum, صحیح *activep, صحیح flags,
    صحیح *want_final_pass, صحیح گہرائی);

/* Keyword tokens. */

قسمتعریف شمار {
	oBadOption,
	oHost, o_مطابقت, oInclude, o_لیبل,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_شناختی_عنصر_File, oHostname, o_پورٹ, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_جوڑو_کلیدیں_مقصد_Agent, o_شناختی_عنصر_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_معلوم_Hosts_File, o_User_معلوم_Hosts_File, oConnectionAttempts,
	o_Batch_منوال, oCheckHostIP, o_Strict_Host_کلید_Checking, oCompression,
	oTCPKeepAlive, o_نمبر_کا_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_کلید_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_کلید_Algorithms, o_Bind_پتہ, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_حد_بندی, o_Verify_Host_کلید_DNS, oConnectTimeout,
	o_پتہ_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_گنتی_Max, oIdentitiesOnly,
	oSendEnv, o_سیٹ_Env, o_Control_راستہ, oControlMaster, oControlPersist,
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

ساکن ساخت {
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
#اگر defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# ورنہ
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#اگر_ختم
#اگر_تعریف_شدہ ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# ورنہ
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#اگر_ختم

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
	{ "identityfile", o_شناختی_عنصر_File },
	{ "identityfile2", o_شناختی_عنصر_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_جوڑو_کلیدیں_مقصد_Agent },
	{ "identityagent", o_شناختی_عنصر_Agent },
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
	{ "match", o_مطابقت },
	{ "tag", o_لیبل },
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
	{ "numberofpasswordprompts", o_نمبر_کا_Password_Prompts },
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
	{ "controlpath", o_Control_راستہ },
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

	{ تہی, oBadOption }
};

ساکن ثابت حرف *lookup_opcode_name(OpCodes رمز);

ثابت حرف *
kex_default_pk_alg(خالی)
{
	ساکن حرف *pkalgs;

	اگر (pkalgs == تہی) {
		حرف *all_کلید;

		all_کلید = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = مطابقت_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
		آزاد(all_کلید);
	}
	واپس pkalgs;
}

حرف *
ssh_connection_hash(ثابت حرف *thishost, ثابت حرف *host, ثابت حرف *portstr,
    ثابت حرف *user, ثابت حرف *jumphost)
{
	ساخت ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_لمبائی];

	اگر ((md = ssh_digest_آغاز(SSH_DIGEST_SHA1)) == تہی ||
	    ssh_digest_update(md, thishost, لڑی_لمبائی(thishost)) < 0 ||
	    ssh_digest_update(md, host, لڑی_لمبائی(host)) < 0 ||
	    ssh_digest_update(md, portstr, لڑی_لمبائی(portstr)) < 0 ||
	    ssh_digest_update(md, user, لڑی_لمبائی(user)) < 0 ||
	    ssh_digest_update(md, jumphost, لڑی_لمبائی(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, حجم(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	واپس tohex(conn_hash, ssh_digest_بائٹیں(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

خالی
جوڑو_local_forward(Options *options, ثابت ساخت Forward *newfwd)
{
	ساخت Forward *fwd;
	صحیح i;

	/* Don't add duplicates */
	برائے (i = 0; i < options->عدد_local_forwards; i++) {
		اگر (forward_equals(newfwd, options->local_forwards + i))
			واپس;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->عدد_local_forwards + 1,
	    حجم(*options->local_forwards));
	fwd = &options->local_forwards[options->عدد_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_پورٹ = newfwd->listen_پورٹ;
	fwd->listen_راستہ = newfwd->listen_راستہ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_پورٹ = newfwd->connect_پورٹ;
	fwd->connect_راستہ = newfwd->connect_راستہ;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

خالی
جوڑو_remote_forward(Options *options, ثابت ساخت Forward *newfwd)
{
	ساخت Forward *fwd;
	صحیح i;

	/* Don't add duplicates */
	برائے (i = 0; i < options->عدد_remote_forwards; i++) {
		اگر (forward_equals(newfwd, options->remote_forwards + i))
			واپس;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->عدد_remote_forwards + 1,
	    حجم(*options->remote_forwards));
	fwd = &options->remote_forwards[options->عدد_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_پورٹ = newfwd->listen_پورٹ;
	fwd->listen_راستہ = newfwd->listen_راستہ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_پورٹ = newfwd->connect_پورٹ;
	fwd->connect_راستہ = newfwd->connect_راستہ;
	fwd->handle = newfwd->handle;
	fwd->allocated_پورٹ = 0;
}

ساکن خالی
clear_forwardings(Options *options)
{
	صحیح i;

	برائے (i = 0; i < options->عدد_local_forwards; i++) {
		آزاد(options->local_forwards[i].listen_host);
		آزاد(options->local_forwards[i].listen_راستہ);
		آزاد(options->local_forwards[i].connect_host);
		آزاد(options->local_forwards[i].connect_راستہ);
	}
	اگر (options->عدد_local_forwards > 0) {
		آزاد(options->local_forwards);
		options->local_forwards = تہی;
	}
	options->عدد_local_forwards = 0;
	برائے (i = 0; i < options->عدد_remote_forwards; i++) {
		آزاد(options->remote_forwards[i].listen_host);
		آزاد(options->remote_forwards[i].listen_راستہ);
		آزاد(options->remote_forwards[i].connect_host);
		آزاد(options->remote_forwards[i].connect_راستہ);
	}
	اگر (options->عدد_remote_forwards > 0) {
		آزاد(options->remote_forwards);
		options->remote_forwards = تہی;
	}
	options->عدد_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

خالی
جوڑو_certificate_file(Options *options, ثابت حرف *راستہ, صحیح userprovided)
{
	صحیح i;

	اگر (options->عدد_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	برائے (i = 0; i < options->عدد_certificate_files; i++) {
		اگر (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], راستہ) == 0) {
			debug2_f("ignoring duplicate key %s", راستہ);
			واپس;
		}
	}

	options->certificate_file_userprovided[options->عدد_certificate_files] =
	    userprovided;
	options->certificate_files[options->عدد_certificate_files++] =
	    xstrdup(راستہ);
}

خالی
جوڑو_شناختی_عنصر_file(Options *options, ثابت حرف *dir, ثابت حرف *filename,
    صحیح userprovided)
{
	حرف *راستہ;
	صحیح i;

	اگر (options->عدد_شناختی_عنصر_files >= SSH_MAX_شناختی_عنصر_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_شناختی_عنصر_FILES);

	اگر (dir == تہی) /* no dir, filename is absolute */
		راستہ = xstrdup(filename);
	ورنہ اگر (xasprintf(&راستہ, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", راستہ);

	/* Avoid registering duplicates */
	برائے (i = 0; i < options->عدد_شناختی_عنصر_files; i++) {
		اگر (options->شناختی_عنصر_file_userprovided[i] == userprovided &&
		    strcmp(options->شناختی_عنصر_files[i], راستہ) == 0) {
			debug2_f("ignoring duplicate key %s", راستہ);
			آزاد(راستہ);
			واپس;
		}
	}

	options->شناختی_عنصر_file_userprovided[options->عدد_شناختی_عنصر_files] =
	    userprovided;
	options->شناختی_عنصر_files[options->عدد_شناختی_عنصر_files++] = راستہ;
}

صحیح
default_ssh_پورٹ(خالی)
{
	ساکن صحیح پورٹ;
	ساخت servent *sp;

	اگر (پورٹ == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		پورٹ = sp ? ntohs(sp->s_port) : SSH_DEFAULT_پورٹ;
	}
	واپس پورٹ;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ساکن صحیح
execute_اندر_shell(ثابت حرف *cmd)
{
	حرف *shell;
	pid_t pid;
	صحیح حالت_2;

	اگر ((shell = getenv("SHELL")) == تہی)
		shell = _PATH_BSHELL;

	اگر (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	اگر ((pid = fork()) == 0) {
		حرف *argv[4];

		اگر (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = تہی;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	اگر (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	جب (waitpid(pid, &حالت_2, 0) == -1) {
		اگر (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	اگر (!WIFEXITED(حالت_2)) {
		error("command '%.100s' exited abnormally", cmd);
		واپس -1;
	}
	debug3("command returned status %d", WEXITSTATUS(حالت_2));
	واپس WEXITSTATUS(حالت_2);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ساکن صحیح
check_مطابقت_ifaddrs(ثابت حرف *addrlist)
{
#اگر_تعریف_شدہ HAVE_IFADDRS_H
	ساخت ifaddrs *ifa, *ifaddrs = تہی;
	صحیح r, ملا = 0;
	حرف addr[NI_MAXHOST];
	socklen_t salen;

	اگر (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		واپس 0;
	}
	برائے (ifa = ifaddrs; ifa != تہی; ifa = ifa->ifa_اگلا) {
		اگر (ifa->ifa_addr == تہی || ifa->ifa_name == تہی ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			جاری;
		انتخاب (ifa->ifa_addr->sa_family) {
		حالت AF_INET:
			salen = حجم(ساخت sockaddr_in);
			توڑو;
		حالت AF_INET6:
			salen = حجم(ساخت sockaddr_in6);
			توڑو;
#اگر_تعریف_شدہ AF_LINK
		حالت AF_LINK:
			/* ignore */
			جاری;
#اگر_ختم /* AF_LINK */
		طےشدہ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			جاری;
		}
		اگر ((r = getnameinfo(ifa->ifa_addr, salen, addr, حجم(addr),
		    تہی, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			جاری;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		اگر (addr_مطابقت_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			ملا = 1;
			توڑو;
		}
	}
	freeifaddrs(ifaddrs);
	واپس ملا;
#ورنہ /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	واپس 0;
#اگر_ختم /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ساکن حرف *
expand_مطابقت_exec_or_include_راستہ(ثابت حرف *راستہ, Options *options,
    ساخت passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    صحیح final_pass, صحیح is_include_راستہ)
{
	حرف thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	حرف uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	حرف *host, *ret;
	صحیح پورٹ;

	پورٹ = options->پورٹ <= 0 ? default_ssh_پورٹ() : options->پورٹ;
	ruser = options->user == تہی ? pw->pw_name : options->user;
	اگر (final_pass) {
		host = xstrdup(options->hostname);
	} ورنہ اگر (options->hostname != تہی) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (حرف *)تہی);
	} ورنہ {
		host = xstrdup(host_arg);
	}
	اگر (gethostname(thishost, حجم(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, حجم(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, حجم(portstr), "%d", پورٹ);
	snprintf(uidstr, حجم(uidstr), "%llu",
	    (غیرعلامتی طویل طویل)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_کلید_alias ?  options->host_کلید_alias : host;

	ret = (is_include_راستہ ? percent_dollar_expand : percent_expand)(راستہ,
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
	    (حرف *)تہی);
	آزاد(host);
	آزاد(conn_hash_hex);
	واپس ret;
}

/*
 * Parse and execute a Match directive.
 */
ساکن صحیح
مطابقت_cfg_سطر(Options *options, ثابت حرف *بھرا_سطر, صحیح *acp, حرف ***avp,
    ساخت passwd *pw, ثابت حرف *host_arg, ثابت حرف *original_host,
    ثابت حرف *remote_command, صحیح final_pass, صحیح *want_final_pass,
    ثابت حرف *filename, صحیح linenum)
{
	حرف *arg, *oattrib = تہی, *attrib = تہی, *cmd, *host, *criteria;
	ثابت حرف *ruser;
	صحیح r, this_نتیجہ, نتیجہ = 1, اوصاف = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == تہی ? pw->pw_name : options->user;
	اگر (final_pass) {
		host = xstrdup(options->hostname);
	} ورنہ اگر (options->hostname != تہی) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (حرف *)تہی);
	} ورنہ {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    بھرا_سطر, host, original_host);
	جب ((attrib = argv_اگلا(acp, avp)) != تہی) {
		/* Terminate on comment */
		اگر (*attrib == '#') {
			argv_consume(acp);
			توڑو;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = تہی;
		this_نتیجہ = 1;
		اگر ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		اگر (strcasecmp(attrib, "all") == 0) {
			اگر (اوصاف > 1 ||
			    ((arg = argv_اگلا(acp, avp)) != تہی &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				نتیجہ = -1;
				جاؤ برآمد;
			}
			اگر (arg != تہی && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			اگر (نتیجہ)
				نتیجہ = negate ? 0 : 1;
			جاؤ برآمد;
		}
		اوصاف++;
		/* criteria "final" and "canonical" have no argument */
		اگر (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			اگر (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != تہی)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_نتیجہ ? "" : "not ", oattrib);
			جاؤ اگلا;
		}

		/* Keep this list in sync with below */
		اگر (strprefix(attrib, "host=", 1)  != تہی ||
		    strprefix(attrib, "originalhost=", 1) != تہی ||
		    strprefix(attrib, "user=", 1) != تہی ||
		    strprefix(attrib, "localuser=", 1) != تہی ||
		    strprefix(attrib, "localnetwork=", 1) != تہی ||
		    strprefix(attrib, "version=", 1) != تہی ||
		    strprefix(attrib, "tagged=", 1) != تہی ||
		    strprefix(attrib, "command=", 1) != تہی ||
		    strprefix(attrib, "exec=", 1) != تہی) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ورنہ اگر ((arg = argv_اگلا(acp, avp)) == تہی) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			نتیجہ = -1;
			جاؤ برآمد;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		اگر (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = تہی;
		اگر (arg == تہی || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			نتیجہ = -1;
			جاؤ برآمد;
		}
		اگر (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = مطابقت_hostname(host, arg) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = مطابقت_hostname(original_host, arg) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = مطابقت_نمونہ_list(ruser, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = مطابقت_نمونہ_list(pw->pw_name, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "localnetwork") == 0) {
			اگر (addr_مطابقت_cidr_list(تہی, arg) == -1) {
				/* Error already printed */
				نتیجہ = -1;
				جاؤ برآمد;
			}
			r = check_مطابقت_ifaddrs(arg) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = مطابقت_نمونہ_list(SSH_RELEASE, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->لیبل == تہی ? "" :
			    options->لیبل);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    مطابقت_نمونہ_list(criteria, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == تہی ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    مطابقت_نمونہ_list(criteria, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "sessiontype") == 0) {
			اگر (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			ورنہ اگر (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			ورنہ اگر (remote_command != تہی &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			ورنہ
				criteria = xstrdup("shell");
			r = مطابقت_نمونہ_list(criteria, arg, 0) == 1;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ اگر (strcasecmp(attrib, "exec") == 0) {
			اگر ((cmd = expand_مطابقت_exec_or_include_راستہ(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == تہی) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			اگر (نتیجہ != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				آزاد(cmd);
				جاؤ اگلا;
			}
			r = execute_اندر_shell(cmd);
			اگر (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			آزاد(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			اگر (r == (negate ? 1 : 0))
				this_نتیجہ = نتیجہ = 0;
		} ورنہ {
			error("Unsupported Match attribute %s", attrib);
			نتیجہ = -1;
			جاؤ برآمد;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_نتیجہ ? "": "not ", oattrib,
		    criteria == تہی ? "" : " \"",
		    criteria == تہی ? "" : criteria,
		    criteria == تہی ? "" : "\"");
 اگلا:
		آزاد(criteria);
		آزاد(oattrib);
		oattrib = attrib = تہی;
	}
	اگر (اوصاف == 0) {
		error("One or more attributes required for Match");
		نتیجہ = -1;
		جاؤ برآمد;
	}
 برآمد:
	اگر (نتیجہ != -1)
		debug2("match %sfound", نتیجہ ? "" : "not ");
	آزاد(oattrib);
	آزاد(host);
	واپس نتیجہ;
}

/* Remove environment variable by pattern */
ساکن خالی
rm_env(Options *options, ثابت حرف *arg, ثابت حرف *filename, صحیح linenum)
{
	u_int i, j, onum_send_env = options->عدد_send_env;

	/* Remove an environment variable */
	برائے (i = 0; i < options->عدد_send_env; ) {
		اگر (!مطابقت_نمونہ(options->send_env[i], arg + 1)) {
			i++;
			جاری;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		آزاد(options->send_env[i]);
		options->send_env[i] = تہی;
		برائے (j = i; j < options->عدد_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = تہی;
		}
		options->عدد_send_env--;
		/* NB. don't increment i */
	}
	اگر (onum_send_env != options->عدد_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->عدد_send_env,
		    حجم(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ساکن OpCodes
parse_token(ثابت حرف *cp, ثابت حرف *filename, صحیح linenum,
    ثابت حرف *ignored_unknown)
{
	صحیح i;

	برائے (i = 0; keywords[i].name; i++)
		اگر (strcmp(cp, keywords[i].name) == 0)
			واپس keywords[i].opcode;
	اگر (ignored_unknown != تہی &&
	    مطابقت_نمونہ_list(cp, ignored_unknown, 1) == 1)
		واپس oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	واپس oBadOption;
}

ساکن خالی
free_canon_cnames(ساخت allowed_cname *cnames, u_int n)
{
	u_int i;

	اگر (cnames == تہی || n == 0)
		واپس;
	برائے (i = 0; i < n; i++) {
		آزاد(cnames[i].ماخذ_list);
		آزاد(cnames[i].ہدف_list);
	}
	آزاد(cnames);
}

/* Multistate option parsing */
ساخت multistate {
	حرف *کلید;
	صحیح قدر;
};
ساکن ثابت ساخت multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_compression[] = {
#اگر_تعریف_شدہ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#اگر_ختم
	{ "no",				COMP_NONE },
	{ تہی, -1 }
};
ساکن ثابت ساخت multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ تہی, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ساکن ثابت ساخت multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ تہی, -1 }
};

ساکن صحیح
parse_multistate_قدر(ثابت حرف *arg, ثابت حرف *filename, صحیح linenum,
    ثابت ساخت multistate *multistate_ptr)
{
	صحیح i;

	اگر (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		واپس -1;
	}
	برائے (i = 0; multistate_ptr[i].کلید != تہی; i++) {
		اگر (strcasecmp(arg, multistate_ptr[i].کلید) == 0)
			واپس multistate_ptr[i].قدر;
	}
	واپس -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
صحیح
process_config_سطر(Options *options, ساخت passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *سطر,
    ثابت حرف *filename, صحیح linenum, صحیح *activep, صحیح flags)
{
	واپس process_config_سطر_گہرائی(options, pw, host, original_host,
	    remote_command, سطر, filename, linenum, activep, flags, تہی, 0);
}

#تعریف_کرو WHITESPACE " \t\r\n"
ساکن صحیح
process_config_سطر_گہرائی(Options *options, ساخت passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, حرف *سطر,
    ثابت حرف *filename, صحیح linenum, صحیح *activep, صحیح flags,
    صحیح *want_final_pass, صحیح گہرائی)
{
	حرف *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	حرف **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	صحیح r, oactive, negated, opcode, *intptr, قدر, value2, cmdline = 0;
	صحیح remotefwd, dynamicfwd, ca_only = 0, ملا = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	طویل طویل val64;
	سائز_t len;
	ساخت Forward fwd;
	ثابت ساخت multistate *multistate_ptr;
	glob_t gl;
	ثابت حرف *errstr;
	حرف **oav = تہی, **av;
	صحیح oac = 0, ac;
	صحیح ret = -1;
	ساخت allowed_cname *cnames = تہی;
	u_int ncnames = 0;
	حرف **strs = تہی; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	اگر (activep == تہی) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	اگر ((len = لڑی_لمبائی(سطر)) == 0)
		واپس 0;
	برائے (len--; len > 0; len--) {
		اگر (strchr(WHITESPACE "\f", سطر[len]) == تہی)
			توڑو;
		سطر[len] = '\0';
	}

	str = سطر;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	اگر ((keyword = strdelim(&str)) == تہی)
		واپس 0;
	/* Ignore leading whitespace. */
	اگر (*keyword == '\0')
		keyword = strdelim(&str);
	اگر (keyword == تہی || !*keyword || *keyword == '\n' || *keyword == '#')
		واپس 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	اگر (str != تہی)
		str += strspn(str, WHITESPACE);
	اگر (str == تہی || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		واپس -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	اگر (argv_بانٹو(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		واپس -1;
	}
	ac = oac;
	av = oav;

	انتخاب (opcode) {
	حالت oBadOption:
		/* don't panic, but count bad options */
		جاؤ برآمد;
	حالت oIgnore:
		argv_consume(&ac);
		توڑو;
	حالت oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		توڑو;
	حالت oConnectTimeout:
		intptr = &options->connection_timeout;
parse_وقت:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (strcmp(arg, "none") == 0)
			قدر = -1;
		ورنہ اگر ((قدر = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}

		قدر = -1;
		multistate_ptr = multistate_flag;
		برائے (i = 0; multistate_ptr[i].کلید != تہی; i++) {
			اگر (strcasecmp(arg, multistate_ptr[i].کلید) == 0) {
				قدر = multistate_ptr[i].قدر;
				توڑو;
			}
		}
		اگر (قدر != -1) {
			اگر (*activep && *intptr == -1)
				*intptr = قدر;
			توڑو;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		اگر (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_راستہ;
		جاؤ parse_agent_راستہ;

	حالت oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_اگلا(&ac, &av);
		اگر ((قدر = parse_multistate_قدر(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			جاؤ برآمد;
		}
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		جاؤ parse_flag;

	حالت oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		جاؤ parse_وقت;

	حالت oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		جاؤ parse_flag;

	حالت oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		جاؤ parse_flag;

	حالت oPasswordAuthentication:
		intptr = &options->password_authentication;
		جاؤ parse_flag;

	حالت oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		جاؤ parse_flag;

	حالت oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		جاؤ parse_string;

	حالت oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		جاؤ parse_multistate;

	حالت oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		جاؤ parse_flag;

	حالت oGssAuthentication:
		intptr = &options->gss_authentication;
		جاؤ parse_flag;

	حالت oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		جاؤ parse_flag;

	حالت o_Batch_منوال:
		intptr = &options->batch_منوال;
		جاؤ parse_flag;

	حالت oCheckHostIP:
		intptr = &options->check_host_ip;
		جاؤ parse_flag;

	حالت o_Verify_Host_کلید_DNS:
		intptr = &options->verify_host_کلید_dns;
		multistate_ptr = multistate_yesnoask;
		جاؤ parse_multistate;

	حالت o_Strict_Host_کلید_Checking:
		intptr = &options->strict_host_کلید_checking;
		multistate_ptr = multistate_strict_hostkey;
		جاؤ parse_multistate;

	حالت oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		جاؤ parse_multistate;

	حالت oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		جاؤ parse_multistate;

	حالت oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		جاؤ parse_flag;

	حالت o_نمبر_کا_Password_Prompts:
		intptr = &options->نمبر_کا_password_prompts;
		جاؤ parse_int;

	حالت o_Rekey_حد_بندی:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			جاؤ برآمد;
		}
		اگر (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ورنہ {
			اگر (جائزہ_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				جاؤ برآمد;
			}
			اگر (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				جاؤ برآمد;
			}
		}
		اگر (*activep && options->rekey_حد_بندی == -1)
			options->rekey_حد_بندی = val64;
		اگر (ac != 0) { /* optional rekey interval present */
			اگر (strcmp(av[0], "none") == 0) {
				(خالی)argv_اگلا(&ac, &av);	/* discard */
				توڑو;
			}
			intptr = &options->rekey_interval;
			جاؤ parse_وقت;
		}
		توڑو;

	حالت o_شناختی_عنصر_File:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep) {
			intptr = &options->عدد_شناختی_عنصر_files;
			اگر (*intptr >= SSH_MAX_شناختی_عنصر_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_شناختی_عنصر_FILES);
				جاؤ برآمد;
			}
			جوڑو_شناختی_عنصر_file(options, تہی,
			    arg, flags & SSHCONF_USERCONF);
		}
		توڑو;

	حالت oCertificateFile:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep) {
			intptr = &options->عدد_certificate_files;
			اگر (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				جاؤ برآمد;
			}
			جوڑو_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		توڑو;

	حالت oXAuthLocation:
		charptr=&options->xauth_location;
		جاؤ parse_string;

	حالت oUser:
		charptr = &options->user;
parse_string:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت o_Global_معلوم_Hosts_File:
		cpptr = (حرف **)&options->system_hostfiles;
		uintptr = &options->عدد_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		قدر = *uintptr == 0; /* was array empty when we started? */
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			}
			i++;
			اگر (*activep && قدر) {
				اگر ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					جاؤ برآمد;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		توڑو;

	حالت o_User_معلوم_Hosts_File:
		cpptr = (حرف **)&options->user_hostfiles;
		uintptr = &options->عدد_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		جاؤ parse_char_array;

	حالت oHostname:
		charptr = &options->hostname;
		جاؤ parse_string;

	حالت o_لیبل:
		charptr = &options->لیبل;
		جاؤ parse_string;

	حالت o_Host_کلید_Alias:
		charptr = &options->host_کلید_alias;
		جاؤ parse_string;

	حالت oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		جاؤ parse_string;

	حالت o_Bind_پتہ:
		charptr = &options->bind_پتہ;
		جاؤ parse_string;

	حالت oBindInterface:
		charptr = &options->bind_interface;
		جاؤ parse_string;

	حالت oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		جاؤ parse_string;

	حالت o_Security_کلید_Provider:
		charptr = &options->sk_provider;
		جاؤ parse_string;

	حالت o_معلوم_Hosts_Command:
		charptr = &options->معلوم_hosts_command;
		جاؤ parse_command;

	حالت oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		اگر (str == تہی) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		len = strspn(str, WHITESPACE "=");
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		توڑو;

	حالت oProxyJump:
		اگر (str == تہی) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		اگر (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			جاؤ برآمد;
		}
		argv_consume(&ac);
		توڑو;

	حالت o_پورٹ:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		قدر = a2port(arg);
		اگر (قدر <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			جاؤ برآمد;
		}
		اگر (*activep && options->پورٹ == -1)
			options->پورٹ = قدر;
		توڑو;

	حالت oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_اگلا(&ac, &av);
		اگر ((errstr = atoi_err(arg, &قدر)) != تہی) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			جاؤ برآمد;
		}
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت oCiphers:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			جاؤ برآمد;
		}
		اگر (*activep && options->ciphers == تہی)
			options->ciphers = xstrdup(arg);
		توڑو;

	حالت oMacs:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			جاؤ برآمد;
		}
		اگر (*activep && options->macs == تہی)
			options->macs = xstrdup(arg);
		توڑو;

	حالت oKexAlgorithms:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*arg != '-' &&
		    !kex_نام_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			جاؤ برآمد;
		}
		اگر (*activep && options->kex_algorithms == تہی)
			options->kex_algorithms = xstrdup(arg);
		توڑو;

	حالت o_Host_کلید_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*arg != '-' &&
		    !sshkey_نام_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			جاؤ برآمد;
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		جاؤ parse_pubkey_algos;

	حالت oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_اگلا(&ac, &av);
		قدر = log_level_نمبر(arg);
		اگر (قدر == SYSLOG_LEVEL_NOT_سیٹ) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			جاؤ برآمد;
		}
		اگر (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_سیٹ)
			*log_level_ptr = (LogLevel) قدر;
		توڑو;

	حالت oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_اگلا(&ac, &av);
		قدر = log_facility_نمبر(arg);
		اگر (قدر == SYSLOG_FACILITY_NOT_سیٹ) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			جاؤ برآمد;
		}
		اگر (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) قدر;
		توڑو;

	حالت oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->عدد_log_verbose;
		i = 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			}
			i++;
			اگر (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, حجم(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		توڑو;

	حالت oLocalForward:
	حالت oRemoteForward:
	حالت oDynamicForward:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		اگر (!dynamicfwd) {
			arg2 = argv_اگلا(&ac, &av);
			اگر (arg2 == تہی || *arg2 == '\0') {
				اگر (remotefwd)
					dynamicfwd = 1;
				ورنہ {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					جاؤ برآمد;
				}
			} ورنہ {
				/* construct a string for parse_forward */
				snprintf(fwdarg, حجم(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		اگر (dynamicfwd)
			strlcpy(fwdarg, arg, حجم(fwdarg));

		اگر (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			جاؤ برآمد;
		}

		اگر (*activep) {
			اگر (remotefwd) {
				جوڑو_remote_forward(options, &fwd);
			} ورنہ {
				جوڑو_local_forward(options, &fwd);
			}
		}
		توڑو;

	حالت oPermitRemoteOpen:
		uintptr = &options->عدد_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		ملا = *uintptr == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			اگر (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					آزاد(arg2);
					جاؤ برآمد;
				}
			} ورنہ {
				p = hpdelim(&arg);
				اگر (p == تہی) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				اگر (arg == تہی || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			آزاد(arg2);
		}
		اگر (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		اگر (ملا && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت oClearAllForwardings:
		intptr = &options->clear_forwardings;
		جاؤ parse_flag;

	حالت oHost:
		اگر (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			جاؤ برآمد;
		}
		*activep = 0;
		arg2 = تہی;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			اگر ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				توڑو;
			}
			negated = *arg == '!';
			اگر (negated)
				arg++;
			اگر (مطابقت_نمونہ(host, arg)) {
				اگر (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					توڑو;
				}
				اگر (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		اگر (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		توڑو;

	حالت o_مطابقت:
		اگر (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			جاؤ برآمد;
		}
		قدر = مطابقت_cfg_سطر(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		اگر (قدر < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			جاؤ برآمد;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : قدر;
		توڑو;

	حالت oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (strcmp(arg, "none") == 0)
			قدر = SSH_ESCAPECHAR_NONE;
		ورنہ اگر (arg[1] == '\0')
			قدر = (u_char) arg[0];
		ورنہ اگر (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			قدر = (u_char) arg[1] & 31;
		ورنہ {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت o_پتہ_Family:
		intptr = &options->پتہ_family;
		multistate_ptr = multistate_addressfamily;
		جاؤ parse_multistate;

	حالت oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		جاؤ parse_flag;

	حالت oIdentitiesOnly:
		intptr = &options->identities_only;
		جاؤ parse_flag;

	حالت oServerAliveInterval:
		intptr = &options->server_alive_interval;
		جاؤ parse_وقت;

	حالت o_Server_Alive_گنتی_Max:
		intptr = &options->server_alive_گنتی_max;
		جاؤ parse_int;

	حالت oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0' || strchr(arg, '=') != تہی) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				جاؤ برآمد;
			}
			ملا = 1;
			اگر (!*activep)
				جاری;
			اگر (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				جاری;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->عدد_send_env, arg);
		}
		اگر (!ملا) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		توڑو;

	حالت o_سیٹ_Env:
		ملا = options->عدد_setenv == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (strchr(arg, '=') == تہی) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				جاؤ برآمد;
			}
			اگر (lookup_setenv_اندر_list(arg, strs, nstrs) != تہی) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				جاری;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->setenv = strs;
			options->عدد_setenv = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت o_Control_راستہ:
		charptr = &options->control_راستہ;
		جاؤ parse_string;

	حالت oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		جاؤ parse_multistate;

	حالت oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			جاؤ برآمد;
		}
		قدر = 0;
		value2 = 0;	/* timeout */
		اگر (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			قدر = 0;
		ورنہ اگر (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			قدر = 1;
		ورنہ اگر ((value2 = convtime(arg)) >= 0)
			قدر = 1;
		ورنہ {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep && *intptr == -1) {
			*intptr = قدر;
			options->control_persist_timeout = value2;
		}
		توڑو;

	حالت o_Hash_معلوم_Hosts:
		intptr = &options->hash_معلوم_hosts;
		جاؤ parse_flag;

	حالت oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		جاؤ parse_multistate;

	حالت oTunnelDevice:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		قدر = a2tun(arg, &value2);
		اگر (قدر == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep && options->tun_local == -1) {
			options->tun_local = قدر;
			options->tun_remote = value2;
		}
		توڑو;

	حالت oLocalCommand:
		charptr = &options->local_command;
		جاؤ parse_command;

	حالت oPermitLocalCommand:
		intptr = &options->permit_local_command;
		جاؤ parse_flag;

	حالت oRemoteCommand:
		charptr = &options->remote_command;
		جاؤ parse_command;

	حالت o_Visual_Host_کلید:
		intptr = &options->visual_host_کلید;
		جاؤ parse_flag;

	حالت oInclude:
		اگر (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			جاؤ برآمد;
		}
		قدر = 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			/* Expand %tokens and environment variables */
			اگر ((p = expand_مطابقت_exec_or_include_راستہ(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == تہی) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				جاری;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			اگر (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				جاؤ برآمد;
			}
			اگر (!راستہ_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" راستہ_SSH_USER_DIR : SSHDIR, p);
			} ورنہ {
				arg2 = xstrdup(p);
			}
			آزاد(p);
			memset(&gl, 0, حجم(gl));
			r = glob(arg2, GLOB_TILDE, تہی, &gl);
			اگر (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				آزاد(arg2);
				جاری;
			} ورنہ اگر (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				جاؤ برآمد;
			}
			آزاد(arg2);
			oactive = *activep;
			برائے (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], گہرائی,
				    oactive ? "" : " (parse only)");
				r = read_config_file_گہرائی(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, گہرائی + 1);
				اگر (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					جاؤ برآمد;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				اگر (r != 1)
					قدر = -1;
			}
			globfree(&gl);
		}
		اگر (قدر != 0)
			ret = قدر;
		توڑو;

	حالت oIPQoS:
		arg = argv_اگلا(&ac, &av);
		اگر ((قدر = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			جاؤ برآمد;
		}
		اگر (قدر == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			قدر = زیادہ_سے_زیادہ_عدد;
		}
		arg = argv_اگلا(&ac, &av);
		اگر (arg == تہی)
			value2 = قدر;
		ورنہ اگر ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			جاؤ برآمد;
		}
		اگر (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = زیادہ_سے_زیادہ_عدد;
		}
		اگر (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = قدر;
			options->ip_qos_bulk = value2;
		}
		توڑو;

	حالت oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		جاؤ parse_multistate;

	حالت oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		جاؤ parse_multistate;

	حالت oStdinNull:
		intptr = &options->stdin_null;
		جاؤ parse_flag;

	حالت oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		جاؤ parse_flag;

	حالت oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		جاؤ parse_string;

	حالت oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		جاؤ parse_flag;

	حالت oCanonicalDomains:
		ملا = options->عدد_canonical_domains == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			}
			اگر (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				جاؤ برآمد;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->canonical_domains = strs;
			options->عدد_canonical_domains = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت oCanonicalizePermittedCNAMEs:
		ملا = options->عدد_permitted_cnames == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
				arg2 = "";
			} ورنہ اگر (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} ورنہ {
				lowercase(arg);
				اگر ((arg2 = strchr(arg, ':')) == تہی ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					جاؤ برآمد;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    حجم(*cnames));
			cnames[ncnames].ماخذ_list = xstrdup(arg);
			cnames[ncnames].ہدف_list = xstrdup(arg2);
			ncnames++;
		}
		اگر (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->permitted_cnames = cnames;
			options->عدد_permitted_cnames = ncnames;
			cnames = تہی; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		توڑو;

	حالت oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		جاؤ parse_multistate;

	حالت oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		جاؤ parse_int;

	حالت oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		جاؤ parse_flag;

	حالت o_دھارا_Local_Bind_نقاب:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			جاؤ برآمد;
		}
		/* Parse mode in octal format */
		قدر = strtol(arg, &endofnumber, 8);
		اگر (arg == endofnumber || قدر < 0 || قدر > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep &&
		    options->fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1)
			options->fwd_opts.streamlocal_bind_نقاب = (منوال_t)قدر;
		توڑو;

	حالت o_دھارا_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		جاؤ parse_flag;

	حالت o_Revoked_Host_کلیدیں:
		uintptr = &options->عدد_revoked_host_کلیدیں;
		cppptr = &options->revoked_host_کلیدیں;
		ملا = *uintptr == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				جاؤ برآمد;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر ((قدر = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			جاؤ برآمد;
		}
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		جاؤ parse_multistate;

	حالت oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		جاؤ parse_pubkey_algos;

	حالت oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		جاؤ parse_pubkey_algos;

	حالت o_جوڑو_کلیدیں_مقصد_Agent:
		arg = argv_اگلا(&ac, &av);
		arg2 = argv_اگلا(&ac, &av);
		قدر = parse_multistate_قدر(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		اگر (قدر == 3 && arg2 != تہی) {
			/* allow "AddKeysToAgent confirm 5m" */
			اگر ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				جاؤ برآمد;
			}
		} ورنہ اگر (قدر == -1 && arg2 == تہی) {
			اگر ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				جاؤ برآمد;
			}
			قدر = 1; /* yes */
		} ورنہ اگر (قدر == -1 || arg2 != تہی) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep && options->جوڑو_کلیدیں_مقصد_agent == -1) {
			options->جوڑو_کلیدیں_مقصد_agent = قدر;
			options->جوڑو_کلیدیں_مقصد_agent_lifespan = value2;
		}
		توڑو;

	حالت o_شناختی_عنصر_Agent:
		charptr = &options->شناختی_عنصر_agent;
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
  parse_agent_راستہ:
		/* Extra validation if the string represents an env var. */
		اگر ((arg2 = dollar_expand(&r, arg)) == تہی || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			جاؤ برآمد;
		}
		آزاد(arg2);
		/* check for legacy environment format */
		اگر (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			جاؤ برآمد;
		}
		اگر (*activep && *charptr == تہی)
			*charptr = xstrdup(arg);
		توڑو;

	حالت oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		جاؤ parse_flag;

	حالت oRequiredRSASize:
		intptr = &options->required_rsa_سائز;
		جاؤ parse_int;

	حالت oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		جاؤ parse_multistate;

	حالت oObscureKeystrokeTiming:
		قدر = -1;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			اگر (قدر != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				جاؤ برآمد;
			}
			اگر (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				قدر = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			ورنہ اگر (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				قدر = 0;
			ورنہ اگر (لڑی_موازنہ(arg, "interval:", 9) == 0) {
				اگر ((errstr = atoi_err(arg + 9,
				    &قدر)) != تہی) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					جاؤ برآمد;
				}
				اگر (قدر <= 0 || قدر > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					جاؤ برآمد;
				}
			} ورنہ {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				جاؤ برآمد;
			}
		}
		اگر (قدر == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			جاؤ برآمد;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		اگر (*activep && *intptr == -1)
			*intptr = قدر;
		توڑو;

	حالت oChannelTimeout:
		ملا = options->عدد_channel_timeouts == 0;
		جب ((arg = argv_اگلا(&ac, &av)) != تہی) {
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					جاؤ برآمد;
				}
			} ورنہ اگر (parse_نمونہ_interval(arg,
			    تہی, تہی) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (ملا && *activep) {
			options->channel_timeouts = strs;
			options->عدد_channel_timeouts = nstrs;
			strs = تہی; /* transferred */
			nstrs = 0;
		}
		توڑو;

	حالت o_نسخہ_Addendum:
		اگر (str == تہی || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		اگر (strchr(str + len, '\r') != تہی) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		اگر ((arg = strchr(سطر, '#')) != تہی) {
			*arg = '\0';
			rtrim(سطر);
		}
		اگر (*activep && options->نسخہ_addendum == تہی) {
			اگر (strcasecmp(str + len, "none") == 0)
				options->نسخہ_addendum = xstrdup("");
			ورنہ
				options->نسخہ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		توڑو;

	حالت oRefuseConnection:
		arg = argv_اگلا(&ac, &av);
		اگر (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			جاؤ برآمد;
		}
		اگر (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		توڑو;

	حالت oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		توڑو;

	حالت oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		توڑو;

	طےشدہ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		جاؤ برآمد;
	}

	/* Check that there is no garbage at end of line. */
	اگر (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		جاؤ برآمد;
	}

	/* success */
	ret = 0;
 برآمد:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, تہی, nstrs);
	argv_free(oav, oac);
	واپس ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
صحیح
read_config_file(ثابت حرف *filename, ساخت passwd *pw, ثابت حرف *host,
    ثابت حرف *original_host, ثابت حرف *remote_command, Options *options, صحیح flags,
    صحیح *want_final_pass)
{
	صحیح فعال = 1;

	واپس read_config_file_گہرائی(filename, pw, host, original_host,
	    remote_command, options, flags, &فعال, want_final_pass, 0);
}

#تعریف_کرو READCONF_MAX_گہرائی	16
ساکن صحیح
read_config_file_گہرائی(ثابت حرف *filename, ساخت passwd *pw,
    ثابت حرف *host, ثابت حرف *original_host, ثابت حرف *remote_command,
    Options *options, صحیح flags, صحیح *activep, صحیح *want_final_pass, صحیح گہرائی)
{
	FILE *f;
	حرف *سطر = تہی;
	سائز_t linesize = 0;
	صحیح linenum;
	صحیح bad_options = 0;

	اگر (گہرائی < 0 || گہرائی > READCONF_MAX_گہرائی)
		fatal("Too many recursive configuration includes");

	اگر ((f = fopen(filename, "r")) == تہی)
		واپس 0;

	اگر (flags & SSHCONF_CHECKPERM) {
		ساخت stat sb;

		اگر (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		اگر (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	جب (getline(&سطر, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		اگر (process_config_سطر_گہرائی(options, pw, host, original_host,
		    remote_command, سطر, filename, linenum, activep, flags,
		    want_final_pass, گہرائی) != 0)
			bad_options++;
	}
	آزاد(سطر);
	fclose(f);
	اگر (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	واپس 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
صحیح
option_clear_or_none(ثابت حرف *o)
{
	واپس o == تہی || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
صحیح
config_has_permitted_cnames(Options *options)
{
	اگر (options->عدد_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].ماخذ_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].ہدف_list, "") == 0)
		واپس 0;
	واپس options->عدد_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

خالی
initialize_options(Options * options)
{
	memset(options, 'X', حجم(*options));
	options->host_arg = تہی;
	options->forward_agent = -1;
	options->forward_agent_sock_راستہ = تہی;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = تہی;
	options->stdio_forward_پورٹ = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = تہی;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_نقاب = (منوال_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = تہی;
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
	options->نمبر_کا_password_prompts = -1;
	options->ciphers = تہی;
	options->macs = تہی;
	options->kex_algorithms = تہی;
	options->hostkeyalgorithms = تہی;
	options->ca_sign_algorithms = تہی;
	options->عدد_شناختی_عنصر_files = 0;
	memset(options->شناختی_عنصر_کلیدیں, 0, حجم(options->شناختی_عنصر_کلیدیں));
	options->عدد_certificate_files = 0;
	memset(options->certificates, 0, حجم(options->certificates));
	options->hostname = تہی;
	options->host_کلید_alias = تہی;
	options->proxy_command = تہی;
	options->jump_user = تہی;
	options->jump_host = تہی;
	options->jump_پورٹ = -1;
	options->jump_extra = تہی;
	options->user = تہی;
	options->escape_char = -1;
	options->عدد_system_hostfiles = 0;
	options->عدد_user_hostfiles = 0;
	options->local_forwards = تہی;
	options->عدد_local_forwards = 0;
	options->remote_forwards = تہی;
	options->عدد_remote_forwards = 0;
	options->permitted_remote_opens = تہی;
	options->عدد_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_سیٹ;
	options->log_level = SYSLOG_LEVEL_NOT_سیٹ;
	options->عدد_log_verbose = 0;
	options->log_verbose = تہی;
	options->preferred_authentications = تہی;
	options->bind_پتہ = تہی;
	options->bind_interface = تہی;
	options->pkcs11_provider = تہی;
	options->sk_provider = تہی;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_حد_بندی = -1;
	options->rekey_interval = -1;
	options->verify_host_کلید_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_گنتی_max = -1;
	options->send_env = تہی;
	options->عدد_send_env = 0;
	options->setenv = تہی;
	options->عدد_setenv = 0;
	options->control_راستہ = تہی;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_معلوم_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = تہی;
	options->permit_local_command = -1;
	options->remote_command = تہی;
	options->جوڑو_کلیدیں_مقصد_agent = -1;
	options->جوڑو_کلیدیں_مقصد_agent_lifespan = -1;
	options->شناختی_عنصر_agent = تہی;
	options->visual_host_کلید = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = تہی;
	options->عدد_canonical_domains = 0;
	options->عدد_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_کلیدیں = تہی;
	options->عدد_revoked_host_کلیدیں = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = تہی;
	options->pubkey_accepted_algos = تہی;
	options->معلوم_hosts_command = تہی;
	options->required_rsa_سائز = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->لیبل = تہی;
	options->channel_timeouts = تہی;
	options->عدد_channel_timeouts = 0;
	options->نسخہ_addendum = تہی;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
خالی
fill_default_options_for_canonicalization(Options *options)
{
	اگر (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	اگر (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	اگر (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
صحیح
fill_default_options(Options * options)
{
	حرف *all_cipher, *all_mac, *all_kex, *all_کلید, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_کلید, *def_sig;
	صحیح ret = -1, r;

	اگر (options->forward_agent == -1)
		options->forward_agent = 0;
	اگر (options->forward_x11 == -1)
		options->forward_x11 = 0;
	اگر (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	اگر (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	اگر (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != تہی ? 1 : 0;
	اگر (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != تہی ? 1 : 0;
	اگر (options->clear_forwardings == 1)
		clear_forwardings(options);

	اگر (options->xauth_location == تہی)
		options->xauth_location = xstrdup(راستہ_XAUTH);
	اگر (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	اگر (options->fwd_opts.streamlocal_bind_نقاب == (منوال_t)-1)
		options->fwd_opts.streamlocal_bind_نقاب = 0177;
	اگر (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	اگر (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	اگر (options->gss_authentication == -1)
		options->gss_authentication = 0;
	اگر (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	اگر (options->password_authentication == -1)
		options->password_authentication = 1;
	اگر (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	اگر (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	اگر (options->batch_منوال == -1)
		options->batch_منوال = 0;
	اگر (options->check_host_ip == -1)
		options->check_host_ip = 0;
	اگر (options->strict_host_کلید_checking == -1)
		options->strict_host_کلید_checking = SSH_STRICT_HOSTKEY_ASK;
	اگر (options->compression == -1)
		options->compression = 0;
	اگر (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	اگر (options->پورٹ == -1)
		options->پورٹ = 0;	/* Filled in ssh_connect. */
	اگر (options->پتہ_family == -1)
		options->پتہ_family = AF_UNSPEC;
	اگر (options->connection_attempts == -1)
		options->connection_attempts = 1;
	اگر (options->نمبر_کا_password_prompts == -1)
		options->نمبر_کا_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	اگر (options->جوڑو_کلیدیں_مقصد_agent == -1) {
		options->جوڑو_کلیدیں_مقصد_agent = 0;
		options->جوڑو_کلیدیں_مقصد_agent_lifespan = 0;
	}
	اگر (options->عدد_شناختی_عنصر_files == 0) {
		جوڑو_شناختی_عنصر_file(options, "~/", راستہ_SSH_CLIENT_ID_RSA, 0);
		جوڑو_شناختی_عنصر_file(options, "~/", راستہ_SSH_CLIENT_ID_ECDSA, 0);
		جوڑو_شناختی_عنصر_file(options, "~/",
		    راستہ_SSH_CLIENT_ID_ECDSA_SK, 0);
		جوڑو_شناختی_عنصر_file(options, "~/",
		    راستہ_SSH_CLIENT_ID_ED25519, 0);
		جوڑو_شناختی_عنصر_file(options, "~/",
		    راستہ_SSH_CLIENT_ID_ED25519_SK, 0);
		جوڑو_شناختی_عنصر_file(options, "~/",
		    راستہ_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	اگر (options->escape_char == -1)
		options->escape_char = '~';
	اگر (options->عدد_system_hostfiles == 0) {
		options->system_hostfiles[options->عدد_system_hostfiles++] =
		    xstrdup(راستہ_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->عدد_system_hostfiles++] =
		    xstrdup(راستہ_SSH_SYSTEM_HOSTFILE2);
	}
	اگر (options->update_hostkeys == -1) {
		اگر (options->verify_host_کلید_dns <= 0 &&
		    (options->عدد_user_hostfiles == 0 ||
		    (options->عدد_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], راستہ_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		ورنہ
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	اگر (options->عدد_user_hostfiles == 0) {
		options->user_hostfiles[options->عدد_user_hostfiles++] =
		    xstrdup(راستہ_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->عدد_user_hostfiles++] =
		    xstrdup(راستہ_SSH_USER_HOSTFILE2);
	}
	اگر (options->log_level == SYSLOG_LEVEL_NOT_سیٹ)
		options->log_level = SYSLOG_LEVEL_INFO;
	اگر (options->log_facility == SYSLOG_FACILITY_NOT_سیٹ)
		options->log_facility = SYSLOG_FACILITY_USER;
	اگر (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	اگر (options->identities_only == -1)
		options->identities_only = 0;
	اگر (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	اگر (options->rekey_حد_بندی == -1)
		options->rekey_حد_بندی = 0;
	اگر (options->rekey_interval == -1)
		options->rekey_interval = 0;
	اگر (options->verify_host_کلید_dns == -1)
		options->verify_host_کلید_dns = 0;
	اگر (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	اگر (options->server_alive_گنتی_max == -1)
		options->server_alive_گنتی_max = 3;
	اگر (options->control_master == -1)
		options->control_master = 0;
	اگر (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	اگر (options->hash_معلوم_hosts == -1)
		options->hash_معلوم_hosts = 0;
	اگر (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	اگر (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	اگر (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	اگر (options->permit_local_command == -1)
		options->permit_local_command = 0;
	اگر (options->visual_host_کلید == -1)
		options->visual_host_کلید = 0;
	اگر (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	اگر (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	اگر (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	اگر (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	اگر (options->stdin_null == -1)
		options->stdin_null = 0;
	اگر (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	اگر (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	اگر (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	اگر (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	اگر (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	اگر (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#اگر_تعریف_شدہ ENABLE_SK_اندرونی
	اگر (options->sk_provider == تہی)
		options->sk_provider = xstrdup("internal");
#ورنہ
	اگر (options->sk_provider == تہی)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#اگر_ختم
	اگر (options->required_rsa_سائز == -1)
		options->required_rsa_سائز = SSH_RSA_MINIMUM_MODULUS_سائز;
	اگر (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	اگر (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	اگر (options->obscure_keystroke_timing_interval == -1) {
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
	def_cipher = مطابقت_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = مطابقت_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = مطابقت_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_کلید = مطابقت_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
	def_sig = مطابقت_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#تعریف_کرو ASSEMBLE(what, defaults, all) \
	کرو { \
		اگر ((r = kex_assemble_نام(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			جاؤ fail; \
		} \
	} جب (0)
	options->kex_algorithms_سیٹ = options->kex_algorithms != تہی;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(pubkey_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#تعریف_منسوخ ASSEMBLE

#تعریف_کرو CLEAR_ON_NONE(v) \
	کرو { \
		اگر (option_clear_or_none(v)) { \
			آزاد(v); \
			v = تہی; \
		} \
	} جب(0)
#تعریف_کرو CLEAR_ON_NONE_ARRAY(v, nv, none) \
	کرو { \
		اگر (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			آزاد(options->v[0]); \
			آزاد(options->v); \
			options->v = تہی; \
			options->nv = 0; \
		} \
	} جب (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_راستہ);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->معلوم_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, عدد_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_کلیدیں, عدد_revoked_host_کلیدیں, "none");
#تعریف_منسوخ CLEAR_ON_NONE
#تعریف_منسوخ CLEAR_ON_NONE_ARRAY
	اگر (options->jump_host != تہی &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_پورٹ == 0 && options->jump_user == تہی) {
		آزاد(options->jump_host);
		options->jump_host = تہی;
	}
	اگر (options->عدد_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		آزاد(options->permitted_cnames[0].ماخذ_list);
		آزاد(options->permitted_cnames[0].ہدف_list);
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
	آزاد(all_cipher);
	آزاد(all_mac);
	آزاد(all_kex);
	آزاد(all_کلید);
	آزاد(all_sig);
	آزاد(def_cipher);
	آزاد(def_mac);
	آزاد(def_kex);
	آزاد(def_کلید);
	آزاد(def_sig);
	واپس ret;
}

خالی
free_options(Options *o)
{
	صحیح i;

	اگر (o == تہی)
		واپس;

#تعریف_کرو FREE_ARRAY(type, n, a) \
	کرو { \
		type _i; \
		برائے (_i = 0; _i < (n); _i++) \
			آزاد((a)[_i]); \
	} جب (0)

	آزاد(o->forward_agent_sock_راستہ);
	آزاد(o->xauth_location);
	FREE_ARRAY(u_int, o->عدد_log_verbose, o->log_verbose);
	آزاد(o->log_verbose);
	آزاد(o->ciphers);
	آزاد(o->macs);
	آزاد(o->hostkeyalgorithms);
	آزاد(o->kex_algorithms);
	آزاد(o->ca_sign_algorithms);
	آزاد(o->hostname);
	آزاد(o->host_کلید_alias);
	آزاد(o->proxy_command);
	آزاد(o->user);
	FREE_ARRAY(u_int, o->عدد_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->عدد_user_hostfiles, o->user_hostfiles);
	آزاد(o->preferred_authentications);
	آزاد(o->bind_پتہ);
	آزاد(o->bind_interface);
	آزاد(o->pkcs11_provider);
	آزاد(o->sk_provider);
	برائے (i = 0; i < o->عدد_شناختی_عنصر_files; i++) {
		آزاد(o->شناختی_عنصر_files[i]);
		sshkey_free(o->شناختی_عنصر_کلیدیں[i]);
	}
	برائے (i = 0; i < o->عدد_certificate_files; i++) {
		آزاد(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	آزاد(o->شناختی_عنصر_agent);
	برائے (i = 0; i < o->عدد_local_forwards; i++) {
		آزاد(o->local_forwards[i].listen_host);
		آزاد(o->local_forwards[i].listen_راستہ);
		آزاد(o->local_forwards[i].connect_host);
		آزاد(o->local_forwards[i].connect_راستہ);
	}
	آزاد(o->local_forwards);
	برائے (i = 0; i < o->عدد_remote_forwards; i++) {
		آزاد(o->remote_forwards[i].listen_host);
		آزاد(o->remote_forwards[i].listen_راستہ);
		آزاد(o->remote_forwards[i].connect_host);
		آزاد(o->remote_forwards[i].connect_راستہ);
	}
	آزاد(o->remote_forwards);
	آزاد(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->عدد_send_env, o->send_env);
	آزاد(o->send_env);
	FREE_ARRAY(u_int, o->عدد_setenv, o->setenv);
	آزاد(o->setenv);
	آزاد(o->control_راستہ);
	آزاد(o->local_command);
	آزاد(o->remote_command);
	FREE_ARRAY(صحیح, o->عدد_canonical_domains, o->canonical_domains);
	برائے (i = 0; i < o->عدد_permitted_cnames; i++) {
		آزاد(o->permitted_cnames[i].ماخذ_list);
		آزاد(o->permitted_cnames[i].ہدف_list);
	}
	FREE_ARRAY(u_int, o->عدد_revoked_host_کلیدیں, o->revoked_host_کلیدیں);
	آزاد(o->revoked_host_کلیدیں);
	آزاد(o->hostbased_accepted_algos);
	آزاد(o->pubkey_accepted_algos);
	آزاد(o->jump_user);
	آزاد(o->jump_host);
	آزاد(o->jump_extra);
	آزاد(o->ignored_unknown);
	explicit_bzero(o, حجم(*o));
#تعریف_منسوخ FREE_ARRAY
}

ساخت fwdarg {
	حرف *arg;
	صحیح ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ساکن صحیح
parse_fwd_میدان(حرف **p, ساخت fwdarg *fwd)
{
	حرف *ep, *cp = *p;
	صحیح ispath = 0;

	اگر (*cp == '\0') {
		*p = تہی;
		واپس -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	اگر (*cp == '[') {
		/* find matching ']' */
		برائے (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			اگر (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		اگر (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			واپس -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		اگر (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		واپس 0;
	}

	برائے (cp = *p; *cp != '\0'; cp++) {
		انتخاب (*cp) {
		حالت '\\':
			memmove(cp, cp + 1, لڑی_لمبائی(cp + 1) + 1);
			اگر (*cp == '\0')
				واپس -1;
			توڑو;
		حالت '/':
			ispath = 1;
			توڑو;
		حالت ':':
			*cp++ = '\0';
			جاؤ مکمل;
		}
	}
مکمل:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	واپس 0;
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
صحیح
parse_forward(ساخت Forward *fwd, ثابت حرف *fwdspec, صحیح dynamicfwd, صحیح remotefwd)
{
	ساخت fwdarg fwdargs[4];
	حرف *p, *cp;
	صحیح i, err;

	memset(fwd, 0, حجم(*fwd));
	memset(fwdargs, 0, حجم(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	اگر (p == تہی || err)
		واپس 0;

	/* skip leading spaces */
	جب (خلا_ہے((u_char)*cp))
		cp++;

	برائے (i = 0; i < 4; ++i) {
		اگر (parse_fwd_میدان(&cp, &fwdargs[i]) != 0)
			توڑو;
	}

	/* Check for trailing garbage */
	اگر (cp != تہی && *cp != '\0') {
		i = 0;	/* failure */
	}

	انتخاب (i) {
	حالت 1:
		اگر (fwdargs[0].ispath) {
			fwd->listen_راستہ = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = پورٹ_STREAMLOCAL;
		} ورنہ {
			fwd->listen_host = تہی;
			fwd->listen_پورٹ = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		توڑو;

	حالت 2:
		اگر (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_راستہ = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = پورٹ_STREAMLOCAL;
			fwd->connect_راستہ = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = پورٹ_STREAMLOCAL;
		} ورنہ اگر (fwdargs[1].ispath) {
			fwd->listen_host = تہی;
			fwd->listen_پورٹ = a2port(fwdargs[0].arg);
			fwd->connect_راستہ = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = پورٹ_STREAMLOCAL;
		} ورنہ {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		توڑو;

	حالت 3:
		اگر (fwdargs[0].ispath) {
			fwd->listen_راستہ = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = پورٹ_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = a2port(fwdargs[2].arg);
		} ورنہ اگر (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_پورٹ = a2port(fwdargs[1].arg);
			fwd->connect_راستہ = xstrdup(fwdargs[2].arg);
			fwd->connect_پورٹ = پورٹ_STREAMLOCAL;
		} ورنہ {
			fwd->listen_host = تہی;
			fwd->listen_پورٹ = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_پورٹ = a2port(fwdargs[2].arg);
		}
		توڑو;

	حالت 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_پورٹ = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_پورٹ = a2port(fwdargs[3].arg);
		توڑو;
	طےشدہ:
		i = 0; /* failure */
	}

	آزاد(p);

	اگر (dynamicfwd) {
		اگر (!(i == 1 || i == 2))
			جاؤ fail_free;
	} ورنہ {
		اگر (!(i == 3 || i == 4)) {
			اگر (fwd->connect_راستہ == تہی &&
			    fwd->listen_راستہ == تہی)
				جاؤ fail_free;
		}
		اگر (fwd->connect_پورٹ <= 0 && fwd->connect_راستہ == تہی)
			جاؤ fail_free;
	}

	اگر ((fwd->listen_پورٹ < 0 && fwd->listen_راستہ == تہی) ||
	    (!remotefwd && fwd->listen_پورٹ == 0))
		جاؤ fail_free;
	اگر (fwd->connect_host != تہی &&
	    لڑی_لمبائی(fwd->connect_host) >= NI_MAXHOST)
		جاؤ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	اگر (fwd->connect_راستہ != تہی &&
	    لڑی_لمبائی(fwd->connect_راستہ) >= راستہ_MAX_SUN)
		جاؤ fail_free;
	اگر (fwd->listen_host != تہی &&
	    لڑی_لمبائی(fwd->listen_host) >= NI_MAXHOST)
		جاؤ fail_free;
	اگر (fwd->listen_راستہ != تہی &&
	    لڑی_لمبائی(fwd->listen_راستہ) >= راستہ_MAX_SUN)
		جاؤ fail_free;

	واپس (i);

 fail_free:
	آزاد(fwd->connect_host);
	fwd->connect_host = تہی;
	آزاد(fwd->connect_راستہ);
	fwd->connect_راستہ = تہی;
	آزاد(fwd->listen_host);
	fwd->listen_host = تہی;
	آزاد(fwd->listen_راستہ);
	fwd->listen_راستہ = تہی;
	واپس (0);
}

صحیح
ssh_valid_hostname(ثابت حرف *s)
{
	سائز_t i;

	اگر (*s == '-')
		واپس 0;
	برائے (i = 0; s[i] != 0; i++) {
		اگر (strchr("'`\"$\\;&<>|(){},", s[i]) != تہی ||
		    خلا_ہے((u_char)s[i]) || iscntrl((u_char)s[i]))
			واپس 0;
	}
	واپس 1;
}

صحیح
ssh_valid_ruser(ثابت حرف *s)
{
	سائز_t i;

	اگر (*s == '-')
		واپس 0;
	برائے (i = 0; s[i] != 0; i++) {
		اگر (iscntrl((u_char)s[i]))
			واپس 0;
		اگر (strchr("'`\";&<>|(){}$\\", s[i]) != تہی)
			واپس 0;
		/* Disallow '-' after whitespace */
		اگر (خلا_ہے((u_char)s[i]) && s[i + 1] == '-')
			واپس 0;
	}
	واپس 1;
}

صحیح
parse_jump(ثابت حرف *s, Options *o, صحیح strict, صحیح فعال)
{
	حرف *orig = تہی, *sdup = تہی, *cp;
	حرف *tmp_user = تہی, *tmp_host = تہی, *host = تہی, *user = تہی;
	صحیح r, ret = -1, tmp_پورٹ = -1, پورٹ = -1, پہلا = 1;

	اگر (strcasecmp(s, "none") == 0) {
		اگر (فعال && o->jump_host == تہی) {
			o->jump_host = xstrdup("none");
			o->jump_پورٹ = 0;
		}
		واپس 0;
	}

	orig = xstrdup(s);
	اگر ((cp = strchr(orig, '#')) != تہی)
		*cp = '\0';
	rtrim(orig);

	فعال &= o->proxy_command == تہی && o->jump_host == تہی;
	sdup = xstrdup(orig);
	کرو {
		/* Work backwards through string */
		اگر ((cp = strrchr(sdup, ',')) == تہی)
			cp = sdup; /*آخری*/
		ورنہ
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_پورٹ);
		اگر (r == -1 || (r == 1 && parse_user_host_پورٹ(cp,
		    &tmp_user, &tmp_host, &tmp_پورٹ) != 0))
			جاؤ برآمد; /* error already logged */
		اگر (strict) {
			اگر (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				جاؤ برآمد;
			}
			اگر (tmp_user != تہی && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				جاؤ برآمد;
			}
		}
		اگر (پہلا) {
			user = tmp_user;
			host = tmp_host;
			پورٹ = tmp_پورٹ;
			tmp_user = tmp_host = تہی; /* transferred */
		}
		پہلا = 0; /* only check syntax for subsequent hosts */
		آزاد(tmp_user);
		آزاد(tmp_host);
		tmp_user = tmp_host = تہی;
		tmp_پورٹ = -1;
	} جب (cp != sdup);

	/* success */
	اگر (فعال) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_پورٹ = پورٹ;
		o->proxy_command = xstrdup("none");
		user = host = تہی; /* transferred */
		اگر (orig != تہی && (cp = strrchr(orig, ',')) != تہی) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 برآمد:
	آزاد(orig);
	آزاد(sdup);
	آزاد(tmp_user);
	آزاد(tmp_host);
	آزاد(user);
	آزاد(host);
	واپس ret;
}

صحیح
parse_ssh_uri(ثابت حرف *uri, حرف **userp, حرف **hostp, صحیح *portp)
{
	حرف *user = تہی, *host = تہی, *راستہ = تہی;
	صحیح r, پورٹ;

	r = parse_uri("ssh", uri, &user, &host, &پورٹ, &راستہ);
	اگر (r == 0 && راستہ != تہی)
		r = -1;		/* path not allowed */
	اگر (r == 0) {
		اگر (userp != تہی) {
			*userp = user;
			user = تہی;
		}
		اگر (hostp != تہی) {
			*hostp = host;
			host = تہی;
		}
		اگر (portp != تہی)
			*portp = پورٹ;
	}
	آزاد(user);
	آزاد(host);
	آزاد(راستہ);
	واپس r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ساکن ثابت حرف *
fmt_multistate_int(صحیح val, ثابت ساخت multistate *m)
{
	u_int i;

	برائے (i = 0; m[i].کلید != تہی; i++) {
		اگر (m[i].قدر == val)
			واپس m[i].کلید;
	}
	واپس "UNKNOWN";
}

ساکن ثابت حرف *
fmt_intarg(OpCodes رمز, صحیح val)
{
	اگر (val == -1)
		واپس "unset";
	انتخاب (رمز) {
	حالت o_پتہ_Family:
		واپس fmt_multistate_int(val, multistate_addressfamily);
	حالت oCompression:
		واپس fmt_multistate_int(val, multistate_compression);
	حالت o_Verify_Host_کلید_DNS:
	حالت oUpdateHostkeys:
		واپس fmt_multistate_int(val, multistate_yesnoask);
	حالت o_Strict_Host_کلید_Checking:
		واپس fmt_multistate_int(val, multistate_strict_hostkey);
	حالت oControlMaster:
		واپس fmt_multistate_int(val, multistate_controlmaster);
	حالت oTunnel:
		واپس fmt_multistate_int(val, multistate_tunnel);
	حالت oRequestTTY:
		واپس fmt_multistate_int(val, multistate_requesttty);
	حالت oSessionType:
		واپس fmt_multistate_int(val, multistate_sessiontype);
	حالت oCanonicalizeHostname:
		واپس fmt_multistate_int(val, multistate_canonicalizehostname);
	حالت o_جوڑو_کلیدیں_مقصد_Agent:
		واپس fmt_multistate_int(val, multistate_yesnoaskconfirm);
	حالت oPubkeyAuthentication:
		واپس fmt_multistate_int(val, multistate_pubkey_auth);
	حالت oTCPKeepAlive:
		واپس fmt_multistate_int(val, multistate_keepalives);
	حالت oFingerprintHash:
		واپس ssh_digest_alg_name(val);
	طےشدہ:
		انتخاب (val) {
		حالت 0:
			واپس "no";
		حالت 1:
			واپس "yes";
		طےشدہ:
			واپس "UNKNOWN";
		}
	}
}

ساکن ثابت حرف *
lookup_opcode_name(OpCodes رمز)
{
	u_int i;

	برائے (i = 0; keywords[i].name != تہی; i++)
		اگر (keywords[i].opcode == رمز)
			واپس(keywords[i].name);
	واپس "UNKNOWN";
}

ساکن خالی
dump_cfg_int(OpCodes رمز, صحیح val)
{
	اگر (رمز == oObscureKeystrokeTiming) {
		اگر (val == 0) {
			لکھو("%s no\n", lookup_opcode_name(رمز));
			واپس;
		} ورنہ اگر (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			لکھو("%s yes\n", lookup_opcode_name(رمز));
			واپس;
		}
		/* FALLTHROUGH */
	}
	لکھو("%s %d\n", lookup_opcode_name(رمز), val);
}

ساکن خالی
dump_cfg_fmtint(OpCodes رمز, صحیح val)
{
	لکھو("%s %s\n", lookup_opcode_name(رمز), fmt_intarg(رمز, val));
}

ساکن خالی
dump_cfg_string(OpCodes رمز, ثابت حرف *val)
{
	اگر (val == تہی)
		واپس;
	لکھو("%s %s\n", lookup_opcode_name(رمز), val);
}

ساکن خالی
dump_cfg_strarray(OpCodes رمز, u_int گنتی, حرف **vals)
{
	u_int i;

	برائے (i = 0; i < گنتی; i++)
		لکھو("%s %s\n", lookup_opcode_name(رمز), vals[i]);
}

ساکن خالی
dump_cfg_strarray_oneline(OpCodes رمز, u_int گنتی, حرف **vals)
{
	u_int i;

	لکھو("%s", lookup_opcode_name(رمز));
	اگر (گنتی == 0)
		لکھو(" none");
	برائے (i = 0; i < گنتی; i++)
		لکھو(" %s",  vals[i]);
	لکھو("\n");
}

ساکن خالی
dump_cfg_forwards(OpCodes رمز, u_int گنتی, ثابت ساخت Forward *fwds)
{
	ثابت ساخت Forward *fwd;
	u_int i;

	/* oDynamicForward */
	برائے (i = 0; i < گنتی; i++) {
		fwd = &fwds[i];
		اگر (رمز == oDynamicForward && fwd->connect_host != تہی &&
		    strcmp(fwd->connect_host, "socks") != 0)
			جاری;
		اگر (رمز == oLocalForward && fwd->connect_host != تہی &&
		    strcmp(fwd->connect_host, "socks") == 0)
			جاری;
		لکھو("%s", lookup_opcode_name(رمز));
		اگر (fwd->listen_پورٹ == پورٹ_STREAMLOCAL)
			لکھو(" %s", fwd->listen_راستہ);
		ورنہ اگر (fwd->listen_host == تہی)
			لکھو(" %d", fwd->listen_پورٹ);
		ورنہ {
			لکھو(" [%s]:%d",
			    fwd->listen_host, fwd->listen_پورٹ);
		}
		اگر (رمز != oDynamicForward) {
			اگر (fwd->connect_پورٹ == پورٹ_STREAMLOCAL)
				لکھو(" %s", fwd->connect_راستہ);
			ورنہ اگر (fwd->connect_host == تہی)
				لکھو(" %d", fwd->connect_پورٹ);
			ورنہ {
				لکھو(" [%s]:%d",
				    fwd->connect_host, fwd->connect_پورٹ);
			}
		}
		لکھو("\n");
	}
}

خالی
dump_client_config(Options *o, ثابت حرف *host)
{
	صحیح i, r;
	حرف buf[8], *all_کلید;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	اگر ((r = kex_assemble_نام(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_کلید)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	آزاد(all_کلید);

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
#اگر_تعریف_شدہ GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#اگر_ختم /* GSSAPI */
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
	dump_cfg_int(o_نمبر_کا_Password_Prompts, o->نمبر_کا_password_prompts);
	dump_cfg_int(o_Server_Alive_گنتی_Max, o->server_alive_گنتی_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_سائز);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_پتہ, o->bind_پتہ);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_راستہ, o->control_راستہ);
	dump_cfg_string(o_Host_کلید_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_کلید_Alias, o->host_کلید_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_شناختی_عنصر_Agent, o->شناختی_عنصر_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#اگر_تعریف_شدہ ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#اگر_ختم
	dump_cfg_string(o_Security_کلید_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_معلوم_Hosts_Command, o->معلوم_hosts_command);
	dump_cfg_string(o_لیبل, o->لیبل);
	dump_cfg_string(o_نسخہ_Addendum, o->نسخہ_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->عدد_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->عدد_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->عدد_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_شناختی_عنصر_File, o->عدد_شناختی_عنصر_files, o->شناختی_عنصر_files);
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
	اگر (o->عدد_permitted_remote_opens == 0)
		لکھو("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	ورنہ
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->عدد_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	اگر (o->جوڑو_کلیدیں_مقصد_agent_lifespan <= 0)
		dump_cfg_fmtint(o_جوڑو_کلیدیں_مقصد_Agent, o->جوڑو_کلیدیں_مقصد_agent);
	ورنہ {
		لکھو("addkeystoagent%s %d\n",
		    o->جوڑو_کلیدیں_مقصد_agent == 3 ? " confirm" : "",
		    o->جوڑو_کلیدیں_مقصد_agent_lifespan);
	}

	/* oForwardAgent */
	اگر (o->forward_agent_sock_راستہ == تہی)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	ورنہ
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_راستہ);

	/* oConnectTimeout */
	اگر (o->connection_timeout == -1)
		لکھو("connecttimeout none\n");
	ورنہ
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	لکھو("tunneldevice");
	اگر (o->tun_local == SSH_TUNID_ANY)
		لکھو(" any");
	ورنہ
		لکھو(" %d", o->tun_local);
	اگر (o->tun_remote == SSH_TUNID_ANY)
		لکھو(":any");
	ورنہ
		لکھو(":%d", o->tun_remote);
	لکھو("\n");

	/* oCanonicalizePermittedCNAMEs */
	لکھو("canonicalizepermittedcnames");
	اگر (o->عدد_permitted_cnames == 0)
		لکھو(" none");
	برائے (i = 0; i < o->عدد_permitted_cnames; i++) {
		لکھو(" %s:%s", o->permitted_cnames[i].ماخذ_list,
		    o->permitted_cnames[i].ہدف_list);
	}
	لکھو("\n");

	/* oControlPersist */
	اگر (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	ورنہ
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	اگر (o->escape_char == SSH_ESCAPECHAR_NONE)
		لکھو("escapechar none\n");
	ورنہ {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		لکھو("escapechar %s\n", buf);
	}

	/* oIPQoS */
	لکھو("ipqos %s ", iptos2str(o->ip_qos_interactive));
	لکھو("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	لکھو("rekeylimit %llu %d\n",
	    (غیرعلامتی طویل طویل)o->rekey_حد_بندی, o->rekey_interval);

	/* oStreamLocalBindMask */
	لکھو("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_نقاب);

	/* oLogFacility */
	لکھو("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	اگر (o->jump_host == تہی)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	ورنہ {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != تہی ||
		    strspn(o->jump_host, "1234567890.") == لڑی_لمبائی(o->jump_host);
		snprintf(buf, حجم(buf), "%d", o->jump_پورٹ);
		لکھو("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == تہی ? "" : o->jump_extra,
		    o->jump_extra == تہی ? "" : ",",
		    /* optional user */
		    o->jump_user == تہی ? "" : o->jump_user,
		    o->jump_user == تہی ? "" : "@",
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
