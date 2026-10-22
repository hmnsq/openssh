/* $OpenBSD: pathnames.h,v 1.38 2026/09/16 00:25:50 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#تعریف_کړه ETCDIR				"/etc"

#که_نه_تعریف_شوی SSHDIR
#تعریف_کړه SSHDIR				ETCDIR "/ssh"
#د_که_پای

#که_نه_تعریف_شوی لار_SSH_PIDDIR
#تعریف_کړه لار_SSH_PIDDIR		"/var/run"
#د_که_پای

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#تعریف_کړه لار_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#تعریف_کړه لار_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#تعریف_کړه لار_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#تعریف_کړه لار_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#تعریف_کړه لار_HOST_ECDSA_کلی_FILE	SSHDIR "/ssh_host_ecdsa_key"
#تعریف_کړه لار_HOST_RSA_کلی_FILE		SSHDIR "/ssh_host_rsa_key"
#تعریف_کړه لار_HOST_ED25519_کلی_FILE	SSHDIR "/ssh_host_ed25519_key"
#تعریف_کړه لار_HOST_MLDSA44_ED25519_کلی_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#تعریف_کړه لار_DH_MODULI			SSHDIR "/moduli"

#که_نه_تعریف_شوی لار_SSH_پروګرام
#تعریف_کړه لار_SSH_پروګرام		"/usr/bin/ssh"
#د_که_پای

/* Binary paths for the sshd components */
#که_نه_تعریف_شوی لار_SSHD_SESSION
#تعریف_کړه لار_SSHD_SESSION		"/usr/libexec/sshd-session"
#د_که_پای
#که_نه_تعریف_شوی لار_SSHD_AUTH
#تعریف_کړه لار_SSHD_AUTH			"/usr/libexec/sshd-auth"
#د_که_پای

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#تعریف_کړه لار_SSH_DAEMON_PID_FILE	لار_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#تعریف_کړه لار_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#تعریف_کړه لار_SSH_AGENT_SOCKET_DIR	"user:" لار_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#تعریف_کړه لار_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#تعریف_کړه لار_SSH_USER_HOSTFILE		"~/" لار_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#تعریف_کړه لار_SSH_USER_HOSTFILE2	"~/" لار_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#تعریف_کړه لار_SSH_CLIENT_ID_ECDSA	لار_SSH_USER_DIR "/id_ecdsa"
#تعریف_کړه لار_SSH_CLIENT_ID_RSA		لار_SSH_USER_DIR "/id_rsa"
#تعریف_کړه لار_SSH_CLIENT_ID_ED25519	لار_SSH_USER_DIR "/id_ed25519"
#تعریف_کړه لار_SSH_CLIENT_ID_ECDSA_SK	لار_SSH_USER_DIR "/id_ecdsa_sk"
#تعریف_کړه لار_SSH_CLIENT_ID_ED25519_SK	لار_SSH_USER_DIR "/id_ed25519_sk"
#تعریف_کړه لار_SSH_CLIENT_ID_MLDSA44_ED25519 لار_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#تعریف_کړه لار_SSH_USER_CONFFILE		لار_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#تعریف_کړه لار_SSH_USER_PERMITTED_کلیګانې	لار_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#تعریف_کړه لار_SSH_USER_PERMITTED_KEYS2	لار_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#تعریف_کړه لار_SSH_USER_RC		لار_SSH_USER_DIR "/rc"
#تعریف_کړه لار_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#تعریف_کړه لار_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#تعریف_کړه لار_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#که_نه_تعریف_شوی لار_SSH_ASKPASS_DEFAULT
#تعریف_کړه لار_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#د_که_پای

/* Location of ssh-keysign for hostbased authentication */
#که_نه_تعریف_شوی لار_SSH_کلی_SIGN
#تعریف_کړه لار_SSH_کلی_SIGN		"/usr/libexec/ssh-keysign"
#د_که_پای

/* Location of ssh-pkcs11-helper to support keys in tokens */
#که_نه_تعریف_شوی لار_SSH_PKCS11_HELPER
#تعریف_کړه لار_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#د_که_پای

/* Location of ssh-sk-helper to support keys in security keys */
#که_نه_تعریف_شوی لار_SSH_SK_HELPER
#تعریف_کړه لار_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#د_که_پای

/* xauth for X11 forwarding */
#که_نه_تعریف_شوی لار_XAUTH
#تعریف_کړه لار_XAUTH			"/usr/X11R6/bin/xauth"
#د_که_پای

/* UNIX domain socket for X11 server; displaynum will replace %u */
#که_نه_تعریف_شوی لار_UNIX_X
#تعریف_کړه لار_UNIX_X "/tmp/.X11-unix/X%u"
#د_که_پای

/* for scp */
#که_نه_تعریف_شوی لار_CP
#تعریف_کړه لار_CP			"cp"
#د_که_پای

/* for sftp */
#که_نه_تعریف_شوی لار_SFTP_SERVER
#تعریف_کړه لار_SFTP_SERVER		"/usr/libexec/sftp-server"
#د_که_پای
#که_نه_تعریف_شوی لار_LS
#تعریف_کړه لار_LS			"ls"
#د_که_پای

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#که_نه_تعریف_شوی لار_PRIVSEP_CHROOT_DIR
#تعریف_کړه لار_PRIVSEP_CHROOT_DIR	"/var/empty"
#د_که_پای

/* for passwd change */
#که_نه_تعریف_شوی لار_PASSWD_PROG
#تعریف_کړه لار_PASSWD_PROG		"/usr/bin/passwd"
#د_که_پای

/* Askpass program define */
#که_نه_تعریف_شوی ASKPASS_پروګرام
#تعریف_کړه ASKPASS_پروګرام         "/usr/lib/ssh/ssh-askpass"
#د_که_پای /* ASKPASS_PROGRAM */
