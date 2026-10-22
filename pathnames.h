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

#وصف_ڪريو ETCDIR				"/etc"

#جيڪڏهن_وصف_نه_ٿيل SSHDIR
#وصف_ڪريو SSHDIR				ETCDIR "/ssh"
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل رستو_SSH_PIDDIR
#وصف_ڪريو رستو_SSH_PIDDIR		"/var/run"
#جيڪڏهن_پورو

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#وصف_ڪريو رستو_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#وصف_ڪريو رستو_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#وصف_ڪريو رستو_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#وصف_ڪريو رستو_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#وصف_ڪريو رستو_HOST_ECDSA_ڪنجي_FILE	SSHDIR "/ssh_host_ecdsa_key"
#وصف_ڪريو رستو_HOST_RSA_ڪنجي_FILE		SSHDIR "/ssh_host_rsa_key"
#وصف_ڪريو رستو_HOST_ED25519_ڪنجي_FILE	SSHDIR "/ssh_host_ed25519_key"
#وصف_ڪريو رستو_HOST_MLDSA44_ED25519_ڪنجي_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#وصف_ڪريو رستو_DH_MODULI			SSHDIR "/moduli"

#جيڪڏهن_وصف_نه_ٿيل رستو_SSH_پروگرام
#وصف_ڪريو رستو_SSH_پروگرام		"/usr/bin/ssh"
#جيڪڏهن_پورو

/* Binary paths for the sshd components */
#جيڪڏهن_وصف_نه_ٿيل رستو_SSHD_SESSION
#وصف_ڪريو رستو_SSHD_SESSION		"/usr/libexec/sshd-session"
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل رستو_SSHD_AUTH
#وصف_ڪريو رستو_SSHD_AUTH			"/usr/libexec/sshd-auth"
#جيڪڏهن_پورو

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#وصف_ڪريو رستو_SSH_DAEMON_PID_FILE	رستو_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#وصف_ڪريو رستو_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#وصف_ڪريو رستو_SSH_AGENT_SOCKET_DIR	"user:" رستو_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#وصف_ڪريو رستو_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#وصف_ڪريو رستو_SSH_USER_HOSTFILE		"~/" رستو_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#وصف_ڪريو رستو_SSH_USER_HOSTFILE2	"~/" رستو_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#وصف_ڪريو رستو_SSH_CLIENT_ID_ECDSA	رستو_SSH_USER_DIR "/id_ecdsa"
#وصف_ڪريو رستو_SSH_CLIENT_ID_RSA		رستو_SSH_USER_DIR "/id_rsa"
#وصف_ڪريو رستو_SSH_CLIENT_ID_ED25519	رستو_SSH_USER_DIR "/id_ed25519"
#وصف_ڪريو رستو_SSH_CLIENT_ID_ECDSA_SK	رستو_SSH_USER_DIR "/id_ecdsa_sk"
#وصف_ڪريو رستو_SSH_CLIENT_ID_ED25519_SK	رستو_SSH_USER_DIR "/id_ed25519_sk"
#وصف_ڪريو رستو_SSH_CLIENT_ID_MLDSA44_ED25519 رستو_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#وصف_ڪريو رستو_SSH_USER_CONFFILE		رستو_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#وصف_ڪريو رستو_SSH_USER_PERMITTED_ڪنجيون	رستو_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#وصف_ڪريو رستو_SSH_USER_PERMITTED_KEYS2	رستو_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#وصف_ڪريو رستو_SSH_USER_RC		رستو_SSH_USER_DIR "/rc"
#وصف_ڪريو رستو_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#وصف_ڪريو رستو_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#وصف_ڪريو رستو_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#جيڪڏهن_وصف_نه_ٿيل رستو_SSH_ASKPASS_DEFAULT
#وصف_ڪريو رستو_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#جيڪڏهن_پورو

/* Location of ssh-keysign for hostbased authentication */
#جيڪڏهن_وصف_نه_ٿيل رستو_SSH_ڪنجي_SIGN
#وصف_ڪريو رستو_SSH_ڪنجي_SIGN		"/usr/libexec/ssh-keysign"
#جيڪڏهن_پورو

/* Location of ssh-pkcs11-helper to support keys in tokens */
#جيڪڏهن_وصف_نه_ٿيل رستو_SSH_PKCS11_HELPER
#وصف_ڪريو رستو_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#جيڪڏهن_پورو

/* Location of ssh-sk-helper to support keys in security keys */
#جيڪڏهن_وصف_نه_ٿيل رستو_SSH_SK_HELPER
#وصف_ڪريو رستو_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#جيڪڏهن_پورو

/* xauth for X11 forwarding */
#جيڪڏهن_وصف_نه_ٿيل رستو_XAUTH
#وصف_ڪريو رستو_XAUTH			"/usr/X11R6/bin/xauth"
#جيڪڏهن_پورو

/* UNIX domain socket for X11 server; displaynum will replace %u */
#جيڪڏهن_وصف_نه_ٿيل رستو_UNIX_X
#وصف_ڪريو رستو_UNIX_X "/tmp/.X11-unix/X%u"
#جيڪڏهن_پورو

/* for scp */
#جيڪڏهن_وصف_نه_ٿيل رستو_CP
#وصف_ڪريو رستو_CP			"cp"
#جيڪڏهن_پورو

/* for sftp */
#جيڪڏهن_وصف_نه_ٿيل رستو_SFTP_SERVER
#وصف_ڪريو رستو_SFTP_SERVER		"/usr/libexec/sftp-server"
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل رستو_LS
#وصف_ڪريو رستو_LS			"ls"
#جيڪڏهن_پورو

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#جيڪڏهن_وصف_نه_ٿيل رستو_PRIVSEP_CHROOT_DIR
#وصف_ڪريو رستو_PRIVSEP_CHROOT_DIR	"/var/empty"
#جيڪڏهن_پورو

/* for passwd change */
#جيڪڏهن_وصف_نه_ٿيل رستو_PASSWD_PROG
#وصف_ڪريو رستو_PASSWD_PROG		"/usr/bin/passwd"
#جيڪڏهن_پورو

/* Askpass program define */
#جيڪڏهن_وصف_نه_ٿيل ASKPASS_پروگرام
#وصف_ڪريو ASKPASS_پروگرام         "/usr/lib/ssh/ssh-askpass"
#جيڪڏهن_پورو /* ASKPASS_PROGRAM */
