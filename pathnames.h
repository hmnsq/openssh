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

#تعریف_کرو ETCDIR				"/etc"

#اگر_غیر_تعریف_شدہ SSHDIR
#تعریف_کرو SSHDIR				ETCDIR "/ssh"
#اگر_ختم

#اگر_غیر_تعریف_شدہ راستہ_SSH_PIDDIR
#تعریف_کرو راستہ_SSH_PIDDIR		"/var/run"
#اگر_ختم

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#تعریف_کرو راستہ_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#تعریف_کرو راستہ_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#تعریف_کرو راستہ_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#تعریف_کرو راستہ_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#تعریف_کرو راستہ_HOST_ECDSA_کلید_FILE	SSHDIR "/ssh_host_ecdsa_key"
#تعریف_کرو راستہ_HOST_RSA_کلید_FILE		SSHDIR "/ssh_host_rsa_key"
#تعریف_کرو راستہ_HOST_ED25519_کلید_FILE	SSHDIR "/ssh_host_ed25519_key"
#تعریف_کرو راستہ_HOST_MLDSA44_ED25519_کلید_FILE SSHDIR "/ssh_host_mldsa44_ed25519_key"
#تعریف_کرو راستہ_DH_MODULI			SSHDIR "/moduli"

#اگر_غیر_تعریف_شدہ راستہ_SSH_پروگرام
#تعریف_کرو راستہ_SSH_پروگرام		"/usr/bin/ssh"
#اگر_ختم

/* Binary paths for the sshd components */
#اگر_غیر_تعریف_شدہ راستہ_SSHD_SESSION
#تعریف_کرو راستہ_SSHD_SESSION		"/usr/libexec/sshd-session"
#اگر_ختم
#اگر_غیر_تعریف_شدہ راستہ_SSHD_AUTH
#تعریف_کرو راستہ_SSHD_AUTH			"/usr/libexec/sshd-auth"
#اگر_ختم

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#تعریف_کرو راستہ_SSH_DAEMON_PID_FILE	راستہ_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#تعریف_کرو راستہ_SSH_USER_DIR		".ssh"


/*
 * Directory spec for ssh-agent sockets and agent sockets forwarded by
 * sshd reside. This directory should not be world-readable.
 */
#تعریف_کرو راستہ_SSH_AGENT_SOCKET_DIR	"user:" راستہ_SSH_USER_DIR "/agent"

/* Directory spec for ssh-agent sockets in /tmp */
#تعریف_کرو راستہ_SSH_AGENT_SOCKET_TMPDIR	"shared:/tmp"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#تعریف_کرو راستہ_SSH_USER_HOSTFILE		"~/" راستہ_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#تعریف_کرو راستہ_SSH_USER_HOSTFILE2	"~/" راستہ_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#تعریف_کرو راستہ_SSH_CLIENT_ID_ECDSA	راستہ_SSH_USER_DIR "/id_ecdsa"
#تعریف_کرو راستہ_SSH_CLIENT_ID_RSA		راستہ_SSH_USER_DIR "/id_rsa"
#تعریف_کرو راستہ_SSH_CLIENT_ID_ED25519	راستہ_SSH_USER_DIR "/id_ed25519"
#تعریف_کرو راستہ_SSH_CLIENT_ID_ECDSA_SK	راستہ_SSH_USER_DIR "/id_ecdsa_sk"
#تعریف_کرو راستہ_SSH_CLIENT_ID_ED25519_SK	راستہ_SSH_USER_DIR "/id_ed25519_sk"
#تعریف_کرو راستہ_SSH_CLIENT_ID_MLDSA44_ED25519 راستہ_SSH_USER_DIR "/id_mldsa44_ed25519"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#تعریف_کرو راستہ_SSH_USER_CONFFILE		راستہ_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#تعریف_کرو راستہ_SSH_USER_PERMITTED_کلیدیں	راستہ_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#تعریف_کرو راستہ_SSH_USER_PERMITTED_KEYS2	راستہ_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#تعریف_کرو راستہ_SSH_USER_RC		راستہ_SSH_USER_DIR "/rc"
#تعریف_کرو راستہ_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#تعریف_کرو راستہ_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#تعریف_کرو راستہ_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#اگر_غیر_تعریف_شدہ راستہ_SSH_ASKPASS_DEFAULT
#تعریف_کرو راستہ_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#اگر_ختم

/* Location of ssh-keysign for hostbased authentication */
#اگر_غیر_تعریف_شدہ راستہ_SSH_کلید_SIGN
#تعریف_کرو راستہ_SSH_کلید_SIGN		"/usr/libexec/ssh-keysign"
#اگر_ختم

/* Location of ssh-pkcs11-helper to support keys in tokens */
#اگر_غیر_تعریف_شدہ راستہ_SSH_PKCS11_HELPER
#تعریف_کرو راستہ_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#اگر_ختم

/* Location of ssh-sk-helper to support keys in security keys */
#اگر_غیر_تعریف_شدہ راستہ_SSH_SK_HELPER
#تعریف_کرو راستہ_SSH_SK_HELPER		"/usr/libexec/ssh-sk-helper"
#اگر_ختم

/* xauth for X11 forwarding */
#اگر_غیر_تعریف_شدہ راستہ_XAUTH
#تعریف_کرو راستہ_XAUTH			"/usr/X11R6/bin/xauth"
#اگر_ختم

/* UNIX domain socket for X11 server; displaynum will replace %u */
#اگر_غیر_تعریف_شدہ راستہ_UNIX_X
#تعریف_کرو راستہ_UNIX_X "/tmp/.X11-unix/X%u"
#اگر_ختم

/* for scp */
#اگر_غیر_تعریف_شدہ راستہ_CP
#تعریف_کرو راستہ_CP			"cp"
#اگر_ختم

/* for sftp */
#اگر_غیر_تعریف_شدہ راستہ_SFTP_SERVER
#تعریف_کرو راستہ_SFTP_SERVER		"/usr/libexec/sftp-server"
#اگر_ختم
#اگر_غیر_تعریف_شدہ راستہ_LS
#تعریف_کرو راستہ_LS			"ls"
#اگر_ختم

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#اگر_غیر_تعریف_شدہ راستہ_PRIVSEP_CHROOT_DIR
#تعریف_کرو راستہ_PRIVSEP_CHROOT_DIR	"/var/empty"
#اگر_ختم

/* for passwd change */
#اگر_غیر_تعریف_شدہ راستہ_PASSWD_PROG
#تعریف_کرو راستہ_PASSWD_PROG		"/usr/bin/passwd"
#اگر_ختم

/* Askpass program define */
#اگر_غیر_تعریف_شدہ ASKPASS_پروگرام
#تعریف_کرو ASKPASS_پروگرام         "/usr/lib/ssh/ssh-askpass"
#اگر_ختم /* ASKPASS_PROGRAM */
