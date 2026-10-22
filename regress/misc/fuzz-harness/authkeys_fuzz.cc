#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <unistd.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
സ്ഥിരം അക്ഷരം *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
സ്ഥിരം അക്ഷരം *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
ശൂന്യം auth_debug_add(സ്ഥിരം അക്ഷരം *fmt,...)
{
}

ശൂന്യം
auth_log_authopts(സ്ഥിരം അക്ഷരം *loc, സ്ഥിരം ഘടന sshauthopt *opts, പൂർണ്ണസംഖ്യ do_remote)
{
}

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* data, size_t size)
{
	അക്ഷരം *tmp, *o, *cp = (അക്ഷരം *)malloc(size + 1 + strlen(pubkey) + 1);
	ഘടന sshauthopt *opts = ശൂന്യ;
	ഘടന passwd *pw = getpwuid(getuid());
	സ്ഥിതം ഘടന sshkey *താക്കോൽ, *cert;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ) {
		എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ ||
		    (cert = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
			abort();
		എങ്കിൽ ((o = tmp = strdup(pubkey)) == ശൂന്യ ||
		    sshkey_read(താക്കോൽ, &tmp) != 0)
			abort();
		സ്വതന്ത്രം(o);
		എങ്കിൽ ((o = tmp = strdup(certtext)) == ശൂന്യ ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		സ്വതന്ത്രം(o);
	}
	എങ്കിൽ (cp == ശൂന്യ || pw == ശൂന്യ || താക്കോൽ == ശൂന്യ || cert == ശൂന്യ)
		abort();

	// Cleanup whitespace at input EOL.
	വേണ്ടി (; size > 0 && strchr(" \t\r\n", data[size - 1]) != ശൂന്യ; size--) ;

	// Append a pubkey that will match.
	memcpy(cp, data, size);
	cp[size] = ' ';
	memcpy(cp + size + 1, pubkey, strlen(pubkey) + 1);

	// Try key.
	എങ്കിൽ ((tmp = strdup(cp)) == ശൂന്യ)
		abort();
	(ശൂന്യം) auth_check_authkey_വരി(pw, താക്കോൽ, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	സ്വതന്ത്രം(tmp);
	sshauthopt_free(opts);

	// Try cert.
	എങ്കിൽ ((tmp = strdup(cp)) == ശൂന്യ)
		abort();
	(ശൂന്യം) auth_check_authkey_വരി(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	സ്വതന്ത്രം(tmp);
	sshauthopt_free(opts);

	സ്വതന്ത്രം(cp);
	തിരികെ 0;
}

} // extern "C"
