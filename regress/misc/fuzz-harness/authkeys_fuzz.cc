#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ਅਚਲ ਅੱਖਰ *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ਅਚਲ ਅੱਖਰ *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
ਖਾਲੀ auth_debug_ਜੋੜੋ(ਅਚਲ ਅੱਖਰ *fmt,...)
{
}

ਖਾਲੀ
auth_log_authopts(ਅਚਲ ਅੱਖਰ *loc, ਅਚਲ ਬਣਤਰ sshauthopt *opts, ਪੂਰਨ do_remote)
{
}

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਅੱਖਰ *tmp, *o, *cp = (ਅੱਖਰ *)ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਮਾਪ + 1 + ਲੜੀ_ਲੰਬਾਈ(pubkey) + 1);
	ਬਣਤਰ sshauthopt *opts = ਨਿਰਾ;
	ਬਣਤਰ passwd *pw = getpwuid(getuid());
	ਸਥਿਰ ਬਣਤਰ sshkey *ਕੁੰਜੀ, *cert;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) {
		ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ ||
		    (cert = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
			abort();
		ਜੇ ((o = tmp = strdup(pubkey)) == ਨਿਰਾ ||
		    sshkey_read(ਕੁੰਜੀ, &tmp) != 0)
			abort();
		ਮੁਕਤ(o);
		ਜੇ ((o = tmp = strdup(certtext)) == ਨਿਰਾ ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		ਮੁਕਤ(o);
	}
	ਜੇ (cp == ਨਿਰਾ || pw == ਨਿਰਾ || ਕੁੰਜੀ == ਨਿਰਾ || cert == ਨਿਰਾ)
		abort();

	// Cleanup whitespace at input EOL.
	ਲਈ (; ਮਾਪ > 0 && strchr(" \t\r\n", ਅੰਕੜੇ[ਮਾਪ - 1]) != ਨਿਰਾ; ਮਾਪ--) ;

	// Append a pubkey that will match.
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp, ਅੰਕੜੇ, ਮਾਪ);
	cp[ਮਾਪ] = ' ';
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp + ਮਾਪ + 1, pubkey, ਲੜੀ_ਲੰਬਾਈ(pubkey) + 1);

	// Try key.
	ਜੇ ((tmp = strdup(cp)) == ਨਿਰਾ)
		abort();
	(ਖਾਲੀ) auth_check_authkey_ਸਤਰ(pw, ਕੁੰਜੀ, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ਮੁਕਤ(tmp);
	sshauthopt_free(opts);

	// Try cert.
	ਜੇ ((tmp = strdup(cp)) == ਨਿਰਾ)
		abort();
	(ਖਾਲੀ) auth_check_authkey_ਸਤਰ(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	ਮੁਕਤ(tmp);
	sshauthopt_free(opts);

	ਮੁਕਤ(cp);
	ਵਾਪਸ 0;
}

} // extern "C"
