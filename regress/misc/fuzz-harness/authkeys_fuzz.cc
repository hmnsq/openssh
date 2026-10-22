#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ಧ್ರುವ ವರ್ಣ *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ಧ್ರುವ ವರ್ಣ *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
ಶೂನ್ಯ auth_debug_add(ಧ್ರುವ ವರ್ಣ *fmt,...)
{
}

ಶೂನ್ಯ
auth_log_authopts(ಧ್ರುವ ವರ್ಣ *loc, ಧ್ರುವ ಸಂರಚನಾ sshauthopt *opts, ಪೂರ್ಣಾಙ್ಕ do_remote)
{
}

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* data, size_t size)
{
	ವರ್ಣ *tmp, *o, *cp = (ವರ್ಣ *)malloc(size + 1 + strlen(pubkey) + 1);
	ಸಂರಚನಾ sshauthopt *opts = ರಿಕ್ತ;
	ಸಂರಚನಾ passwd *pw = getpwuid(getuid());
	ಸ್ಥಿರ ಸಂರಚನಾ sshkey *ಕೀಲಿ, *cert;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) {
		ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ ||
		    (cert = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
			abort();
		ಯದಿ ((o = tmp = strdup(pubkey)) == ರಿಕ್ತ ||
		    sshkey_read(ಕೀಲಿ, &tmp) != 0)
			abort();
		ಮುಕ್ತ(o);
		ಯದಿ ((o = tmp = strdup(certtext)) == ರಿಕ್ತ ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		ಮುಕ್ತ(o);
	}
	ಯದಿ (cp == ರಿಕ್ತ || pw == ರಿಕ್ತ || ಕೀಲಿ == ರಿಕ್ತ || cert == ರಿಕ್ತ)
		abort();

	// Cleanup whitespace at input EOL.
	ಪ್ರತಿ (; size > 0 && strchr(" \t\r\n", data[size - 1]) != ರಿಕ್ತ; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	ಯದಿ ((tmp = strdup(cp)) == ರಿಕ್ತ)
		abort();
	(ಶೂನ್ಯ) auth_check_authkey_ಸಾಲು(pw, ಕೀಲಿ, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ಮುಕ್ತ(tmp);
	sshauthopt_free(opts);

	// Try cert.
	ಯದಿ ((tmp = strdup(cp)) == ರಿಕ್ತ)
		abort();
	(ಶೂನ್ಯ) auth_check_authkey_ಸಾಲು(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ಮುಕ್ತ(tmp);
	sshauthopt_free(opts);

	ಮುಕ್ತ(cp);
	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern "C"
