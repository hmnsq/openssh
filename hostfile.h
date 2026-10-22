/* $OpenBSD: hostfile.h,v 1.29 2021/01/26 00:51:30 djm Exp $ */

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
#ifndef HOSTFILE_H
#define HOSTFILE_H

തരനിർവചനം എണ്ണൽ {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

തരനിർവചനം എണ്ണൽ {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ഘടന hostkey_entry {
	അക്ഷരം *host;
	അക്ഷരം *file;
	u_long വരി;
	ഘടന sshkey *താക്കോൽ;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ഘടന hostkeys {
	ഘടന hostkey_entry *entries;
	u_int അക്കം_entries;
};

ഘടന hostkeys *init_hostkeys(ശൂന്യം);
ശൂന്യം	 load_hostkeys(ഘടന hostkeys *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, u_int);
ശൂന്യം	 load_hostkeys_file(ഘടന hostkeys *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, FILE *, u_int note);
ശൂന്യം	 free_hostkeys(ഘടന hostkeys *);

HostStatus check_താക്കോൽ_in_hostkeys(ഘടന hostkeys *, ഘടന sshkey *,
    സ്ഥിരം ഘടന hostkey_entry **);
പൂർണ്ണസംഖ്യ	 lookup_താക്കോൽ_in_hostkeys_by_type(ഘടന hostkeys *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    സ്ഥിരം ഘടന hostkey_entry **);
പൂർണ്ണസംഖ്യ	 lookup_marker_in_hostkeys(ഘടന hostkeys *, പൂർണ്ണസംഖ്യ);

പൂർണ്ണസംഖ്യ	 hostfile_read_താക്കോൽ(അക്ഷരം **, u_int *, ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 add_host_to_hostfile(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം ഘടന sshkey *, പൂർണ്ണസംഖ്യ);

പൂർണ്ണസംഖ്യ	 hostfile_replace_entries(സ്ഥിരം അക്ഷരം *filename,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip, ഘടന sshkey **താക്കോലുകൾ, size_t nkeys,
    പൂർണ്ണസംഖ്യ store_hash, പൂർണ്ണസംഖ്യ quiet, പൂർണ്ണസംഖ്യ hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

അക്ഷരം	*host_hash(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_താക്കോൽ	(1<<1)	/* need key parsed */

#define HKF_STATUS_OK		0	/* Line parsed, didn't match host */
#define HKF_STATUS_INVALID	1	/* line had parse error */
#define HKF_STATUS_COMMENT	2	/* valid line contained no key */
#define HKF_STATUS_MATCHED	3	/* hostname or IP matched */

#define HKF_MATCH_HOST		(1)	/* hostname matched */
#define HKF_MATCH_IP		(1<<1)	/* address matched */
#define HKF_MATCH_HOST_HASHED	(1<<2)	/* hostname was hashed */
#define HKF_MATCH_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
ഘടന hostkey_foreach_വരി {
	സ്ഥിരം അക്ഷരം *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	അക്ഷരം *വരി;	/* Entire key line; mutable by callback */
	പൂർണ്ണസംഖ്യ marker;	/* CA/revocation markers; indicated by MRK_* value */
	സ്ഥിരം അക്ഷരം *hosts; /* Raw hosts text, may be hashed or list multiple */
	സ്ഥിരം അക്ഷരം *rawkey; /* Text of key and any comment following it */
	പൂർണ്ണസംഖ്യ keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ഘടന sshkey *താക്കോൽ; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	സ്ഥിരം അക്ഷരം *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
തരനിർവചനം പൂർണ്ണസംഖ്യ hostkeys_foreach_fn(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *ctx);

/* Iterate over a hostkeys file */
പൂർണ്ണസംഖ്യ hostkeys_foreach(സ്ഥിരം അക്ഷരം *path,
    hostkeys_foreach_fn *callback, ശൂന്യം *ctx,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip, u_int options, u_int note);
പൂർണ്ണസംഖ്യ hostkeys_foreach_file(സ്ഥിരം അക്ഷരം *path, FILE *f,
    hostkeys_foreach_fn *callback, ശൂന്യം *ctx,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ip, u_int options, u_int note);

ശൂന്യം hostfile_create_user_ssh_dir(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);

#endif
