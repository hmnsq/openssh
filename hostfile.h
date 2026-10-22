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

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଗଣନା {
	HOST_OK, HOST_NEW, HOST_CHANGED, HOST_REVOKED, HOST_FOUND
}       HostStatus;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଗଣନା {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ସଂରଚନା hostkey_entry {
	ଅକ୍ଷର *host;
	ଅକ୍ଷର *file;
	u_long ଧାଡ଼ି;
	ସଂରଚନା sshkey *ଚାବି;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ସଂରଚନା hostkeys {
	ସଂରଚନା hostkey_entry *entries;
	u_int ଅଙ୍କ_entries;
};

ସଂରଚନା hostkeys *init_hostkeys(ଶୂନ୍ୟ);
ଶୂନ୍ୟ	 load_hostkeys(ସଂରଚନା hostkeys *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, u_int);
ଶୂନ୍ୟ	 load_hostkeys_file(ସଂରଚନା hostkeys *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, FILE *, u_int note);
ଶୂନ୍ୟ	 free_hostkeys(ସଂରଚନା hostkeys *);

HostStatus check_ଚାବି_in_hostkeys(ସଂରଚନା hostkeys *, ସଂରଚନା sshkey *,
    ଅଚଳ ସଂରଚନା hostkey_entry **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 lookup_ଚାବି_in_hostkeys_by_type(ସଂରଚନା hostkeys *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ଅଚଳ ସଂରଚନା hostkey_entry **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 lookup_marker_in_hostkeys(ସଂରଚନା hostkeys *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 hostfile_read_ଚାବି(ଅକ୍ଷର **, u_int *, ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 add_host_to_hostfile(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 hostfile_replace_entries(ଅଚଳ ଅକ୍ଷର *filename,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip, ସଂରଚନା sshkey **ଚାବିଗୁଡ଼ିକ, size_t nkeys,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା store_hash, ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg);

#define HASH_MAGIC	"|1|"
#define HASH_DELIM	'|'

#define CA_MARKER	"@cert-authority"
#define REVOKE_MARKER	"@revoked"

ଅକ୍ଷର	*host_hash(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#define HKF_WANT_MATCH		(1)	/* return only matching hosts/addrs */
#define HKF_WANT_PARSE_ଚାବି	(1<<1)	/* need key parsed */

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
ସଂରଚନା hostkey_foreach_ଧାଡ଼ି {
	ଅଚଳ ଅକ୍ଷର *path; /* Path of file */
	u_long linenum;	/* Line number */
	u_int status;	/* One of HKF_STATUS_* */
	u_int match;	/* Zero or more of HKF_MATCH_* OR'd together */
	ଅକ୍ଷର *ଧାଡ଼ି;	/* Entire key line; mutable by callback */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା marker;	/* CA/revocation markers; indicated by MRK_* value */
	ଅଚଳ ଅକ୍ଷର *hosts; /* Raw hosts text, may be hashed or list multiple */
	ଅଚଳ ଅକ୍ଷର *rawkey; /* Text of key and any comment following it */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ସଂରଚନା sshkey *ଚାବି; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ଅଚଳ ଅକ୍ଷର *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostkeys_foreach_fn(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *ctx);

/* Iterate over a hostkeys file */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostkeys_foreach(ଅଚଳ ଅକ୍ଷର *path,
    hostkeys_foreach_fn *callback, ଶୂନ୍ୟ *ctx,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip, u_int options, u_int note);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostkeys_foreach_file(ଅଚଳ ଅକ୍ଷର *path, FILE *f,
    hostkeys_foreach_fn *callback, ଶୂନ୍ୟ *ctx,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ip, u_int options, u_int note);

ଶୂନ୍ୟ hostfile_create_user_ssh_dir(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

#endif
