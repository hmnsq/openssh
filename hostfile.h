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

வகைவரை எண்ணிக்கை {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

வகைவரை எண்ணிக்கை {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

கட்டமைப்பு hostkey_entry {
	எழுத்து *host;
	எழுத்து *file;
	u_long வரி;
	கட்டமைப்பு sshkey *சாவி;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
கட்டமைப்பு hostkeys {
	கட்டமைப்பு hostkey_entry *entries;
	u_int இலக்கம்_entries;
};

கட்டமைப்பு hostkeys *init_hostkeys(வெறுமை);
வெறுமை	 load_hostkeys(கட்டமைப்பு hostkeys *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, u_int);
வெறுமை	 load_hostkeys_file(கட்டமைப்பு hostkeys *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, FILE *, u_int note);
வெறுமை	 free_hostkeys(கட்டமைப்பு hostkeys *);

HostStatus check_சாவி_in_hostkeys(கட்டமைப்பு hostkeys *, கட்டமைப்பு sshkey *,
    மாறிலி கட்டமைப்பு hostkey_entry **);
முழு	 lookup_சாவி_in_hostkeys_by_type(கட்டமைப்பு hostkeys *, முழு, முழு,
    மாறிலி கட்டமைப்பு hostkey_entry **);
முழு	 lookup_marker_in_hostkeys(கட்டமைப்பு hostkeys *, முழு);

முழு	 hostfile_read_சாவி(எழுத்து **, u_int *, கட்டமைப்பு sshkey *);
முழு	 add_host_to_hostfile(மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    மாறிலி கட்டமைப்பு sshkey *, முழு);

முழு	 hostfile_replace_entries(மாறிலி எழுத்து *filename,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *ip, கட்டமைப்பு sshkey **சாவிகள், size_t nkeys,
    முழு store_hash, முழு quiet, முழு hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

எழுத்து	*host_hash(மாறிலி எழுத்து *, மாறிலி எழுத்து *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_சாவி	(1<<1)	/* need key parsed */

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
கட்டமைப்பு hostkey_foreach_வரி {
	மாறிலி எழுத்து *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	எழுத்து *வரி;	/* Entire key line; mutable by callback */
	முழு marker;	/* CA/revocation markers; indicated by MRK_* value */
	மாறிலி எழுத்து *hosts; /* Raw hosts text, may be hashed or list multiple */
	மாறிலி எழுத்து *rawkey; /* Text of key and any comment following it */
	முழு keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	கட்டமைப்பு sshkey *சாவி; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	மாறிலி எழுத்து *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
வகைவரை முழு hostkeys_foreach_fn(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *ctx);

/* Iterate over a hostkeys file */
முழு hostkeys_foreach(மாறிலி எழுத்து *path,
    hostkeys_foreach_fn *callback, வெறுமை *ctx,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *ip, u_int options, u_int note);
முழு hostkeys_foreach_file(மாறிலி எழுத்து *path, FILE *f,
    hostkeys_foreach_fn *callback, வெறுமை *ctx,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *ip, u_int options, u_int note);

வெறுமை hostfile_create_user_ssh_dir(மாறிலி எழுத்து *, முழு);

#endif
