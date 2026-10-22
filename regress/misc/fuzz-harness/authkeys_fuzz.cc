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
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
ಶೂನ್ಯ auth_debug_ಕೂಡಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
{
}

ಶೂನ್ಯ
auth_log_authopts(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *loc, ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *opts, ಪೂರ್ಣಾಂಕ do_remote)
{
}

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಅಕ್ಷರ *tmp, *o, *cp = (ಅಕ್ಷರ *)ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ_2 + 1 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pubkey) + 1);
	ರಚನೆ sshauthopt *opts = ಖಾಲಿ;
	ರಚನೆ passwd *pw = getpwuid(getuid());
	ಸ್ಥಿರ ರಚನೆ sshkey *ಕೀಲಿ, *cert;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) {
		ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ ||
		    (cert = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
			abort();
		ಆದರೆ ((o = tmp = strdup(pubkey)) == ಖಾಲಿ ||
		    sshkey_read(ಕೀಲಿ, &tmp) != 0)
			abort();
		ಬಿಡುಗಡೆ(o);
		ಆದರೆ ((o = tmp = strdup(certtext)) == ಖಾಲಿ ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		ಬಿಡುಗಡೆ(o);
	}
	ಆದರೆ (cp == ಖಾಲಿ || pw == ಖಾಲಿ || ಕೀಲಿ == ಖಾಲಿ || cert == ಖಾಲಿ)
		abort();

	// Cleanup whitespace at input EOL.
	ಗಾಗಿ (; ಗಾತ್ರ_2 > 0 && strchr(" \t\r\n", ದತ್ತಾಂಶ[ಗಾತ್ರ_2 - 1]) != ಖಾಲಿ; ಗಾತ್ರ_2--) ;

	// Append a pubkey that will match.
	ಸ್ಮರಣೆ_ನಕಲು(cp, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	cp[ಗಾತ್ರ_2] = ' ';
	ಸ್ಮರಣೆ_ನಕಲು(cp + ಗಾತ್ರ_2 + 1, pubkey, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pubkey) + 1);

	// Try key.
	ಆದರೆ ((tmp = strdup(cp)) == ಖಾಲಿ)
		abort();
	(ಶೂನ್ಯ) auth_check_authkey_ಸಾಲು(pw, ಕೀಲಿ, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ಬಿಡುಗಡೆ(tmp);
	sshauthopt_free(opts);

	// Try cert.
	ಆದರೆ ((tmp = strdup(cp)) == ಖಾಲಿ)
		abort();
	(ಶೂನ್ಯ) auth_check_authkey_ಸಾಲು(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ಬಿಡುಗಡೆ(tmp);
	sshauthopt_free(opts);

	ಬಿಡುಗಡೆ(cp);
	ಹಿಂತಿರುಗಿ 0;
}

} // extern "C"
