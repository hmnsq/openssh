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

પ્રકારવ્યાખ્યા ગણના {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

પ્રકારવ્યાખ્યા ગણના {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

સંરચના hostkey_entry {
	અક્ષર *host;
	અક્ષર *file;
	u_long લીટી;
	સંરચના sshkey *ચાવી;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
સંરચના hostkeys {
	સંરચના hostkey_entry *entries;
	u_int અંક_entries;
};

સંરચના hostkeys *init_hostkeys(શૂન્ય);
શૂન્ય	 load_hostkeys(સંરચના hostkeys *, અચલ અક્ષર *,
    અચલ અક્ષર *, u_int);
શૂન્ય	 load_hostkeys_file(સંરચના hostkeys *, અચલ અક્ષર *,
    અચલ અક્ષર *, FILE *, u_int note);
શૂન્ય	 free_hostkeys(સંરચના hostkeys *);

HostStatus check_ચાવી_in_hostkeys(સંરચના hostkeys *, સંરચના sshkey *,
    અચલ સંરચના hostkey_entry **);
પૂર્ણાંક	 lookup_ચાવી_in_hostkeys_by_type(સંરચના hostkeys *, પૂર્ણાંક, પૂર્ણાંક,
    અચલ સંરચના hostkey_entry **);
પૂર્ણાંક	 lookup_marker_in_hostkeys(સંરચના hostkeys *, પૂર્ણાંક);

પૂર્ણાંક	 hostfile_read_ચાવી(અક્ષર **, u_int *, સંરચના sshkey *);
પૂર્ણાંક	 add_host_to_hostfile(અચલ અક્ષર *, અચલ અક્ષર *,
    અચલ સંરચના sshkey *, પૂર્ણાંક);

પૂર્ણાંક	 hostfile_replace_entries(અચલ અક્ષર *filename,
    અચલ અક્ષર *host, અચલ અક્ષર *ip, સંરચના sshkey **ચાવીઓ, size_t nkeys,
    પૂર્ણાંક store_hash, પૂર્ણાંક quiet, પૂર્ણાંક hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

અક્ષર	*host_hash(અચલ અક્ષર *, અચલ અક્ષર *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_ચાવી	(1<<1)	/* need key parsed */

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
સંરચના hostkey_foreach_લીટી {
	અચલ અક્ષર *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	અક્ષર *લીટી;	/* Entire key line; mutable by callback */
	પૂર્ણાંક marker;	/* CA/revocation markers; indicated by MRK_* value */
	અચલ અક્ષર *hosts; /* Raw hosts text, may be hashed or list multiple */
	અચલ અક્ષર *rawkey; /* Text of key and any comment following it */
	પૂર્ણાંક keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	સંરચના sshkey *ચાવી; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	અચલ અક્ષર *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
પ્રકારવ્યાખ્યા પૂર્ણાંક hostkeys_foreach_fn(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *ctx);

/* Iterate over a hostkeys file */
પૂર્ણાંક hostkeys_foreach(અચલ અક્ષર *path,
    hostkeys_foreach_fn *callback, શૂન્ય *ctx,
    અચલ અક્ષર *host, અચલ અક્ષર *ip, u_int options, u_int note);
પૂર્ણાંક hostkeys_foreach_file(અચલ અક્ષર *path, FILE *f,
    hostkeys_foreach_fn *callback, શૂન્ય *ctx,
    અચલ અક્ષર *host, અચલ અક્ષર *ip, u_int options, u_int note);

શૂન્ય hostfile_create_user_ssh_dir(અચલ અક્ષર *, પૂર્ણાંક);

#endif
