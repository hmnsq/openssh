#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>
#شامل <pwd.h>
#شامل <unistd.h>

بیرونی "C" {

#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"
#شامل "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ثابت نویسه *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ثابت نویسه *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
تهی auth_debug_add(ثابت نویسه *fmt,...)
{
}

تهی
auth_log_authopts(ثابت نویسه *loc, ثابت ساختار sshauthopt *opts, صحیح do_remote)
{
}

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* data, size_t size)
{
	نویسه *tmp, *o, *cp = (نویسه *)malloc(size + 1 + strlen(pubkey) + 1);
	ساختار sshauthopt *opts = پوچ;
	ساختار passwd *pw = getpwuid(getuid());
	ایستا ساختار sshkey *کلید, *cert;

	اگر (کلید == پوچ) {
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ ||
		    (cert = sshkey_new(کلید_UNSPEC)) == پوچ)
			abort();
		اگر ((o = tmp = strdup(pubkey)) == پوچ ||
		    sshkey_read(کلید, &tmp) != 0)
			abort();
		آزاد(o);
		اگر ((o = tmp = strdup(certtext)) == پوچ ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		آزاد(o);
	}
	اگر (cp == پوچ || pw == پوچ || کلید == پوچ || cert == پوچ)
		abort();

	// Cleanup whitespace at input EOL.
	برای (; size > 0 && strchr(" \t\r\n", data[size - 1]) != پوچ; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	اگر ((tmp = strdup(cp)) == پوچ)
		abort();
	(تهی) auth_check_authkey_سطر(pw, کلید, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	آزاد(tmp);
	sshauthopt_free(opts);

	// Try cert.
	اگر ((tmp = strdup(cp)) == پوچ)
		abort();
	(تهی) auth_check_authkey_سطر(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	آزاد(tmp);
	sshauthopt_free(opts);

	آزاد(cp);
	بازگشت 0;
}

} // extern "C"
