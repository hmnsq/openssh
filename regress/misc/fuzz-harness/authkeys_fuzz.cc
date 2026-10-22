#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>
#ضمن <pwd.h>
#ضمن <unistd.h>

خارجي "C" {

#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"
#ضمن "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ثابت حرف *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ثابت حرف *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
فراغ auth_debug_add(ثابت حرف *fmt,...)
{
}

فراغ
auth_log_authopts(ثابت حرف *loc, ثابت بنية sshauthopt *opts, صحيح do_remote)
{
}

صحيح LLVMFuzzerTestOneInput(ثابت uint8_t* data, size_t size)
{
	حرف *tmp, *o, *cp = (حرف *)malloc(size + 1 + strlen(pubkey) + 1);
	بنية sshauthopt *opts = عدم;
	بنية passwd *pw = getpwuid(getuid());
	ساكن بنية sshkey *key, *cert;

	ܐܢ (key == عدم) {
		ܐܢ ((key = sshkey_new(KEY_UNSPEC)) == عدم ||
		    (cert = sshkey_new(KEY_UNSPEC)) == عدم)
			abort();
		ܐܢ ((o = tmp = strdup(pubkey)) == عدم ||
		    sshkey_read(key, &tmp) != 0)
			abort();
		حرر(o);
		ܐܢ ((o = tmp = strdup(certtext)) == عدم ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		حرر(o);
	}
	ܐܢ (cp == عدم || pw == عدم || key == عدم || cert == عدم)
		abort();

	// Cleanup whitespace at input EOL.
	لكل (; size > 0 && strchr(" \t\r\n", data[size - 1]) != عدم; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	ܐܢ ((tmp = strdup(cp)) == عدم)
		abort();
	(فراغ) auth_check_authkey_line(pw, key, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	حرر(tmp);
	sshauthopt_free(opts);

	// Try cert.
	ܐܢ ((tmp = strdup(cp)) == عدم)
		abort();
	(فراغ) auth_check_authkey_line(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	حرر(tmp);
	sshauthopt_free(opts);

	حرر(cp);
	ܦܢܐ 0;
}

} // extern "C"
