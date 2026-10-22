#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <unistd.h>

बाह्य "C" {

#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
ध्रुव वर्ण *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
ध्रुव वर्ण *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
शून्य auth_debug_सङ्कलय(ध्रुव वर्ण *fmt,...)
{
}

शून्य
auth_log_authopts(ध्रुव वर्ण *loc, ध्रुव संरचना sshauthopt *opts, पूर्णाङ्क do_remote)
{
}

पूर्णाङ्क LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t* दत्त, आकार_t आकार)
{
	वर्ण *tmp, *o, *cp = (वर्ण *)स्मृतिं_देहि(आकार + 1 + वाक्यदैर्घ्यम्(pubkey) + 1);
	संरचना sshauthopt *opts = रिक्त;
	संरचना passwd *pw = getpwuid(getuid());
	स्थिर संरचना sshkey *कुञ्चिका, *cert;

	यदि (कुञ्चिका == रिक्त) {
		यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त ||
		    (cert = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
			abort();
		यदि ((o = tmp = strdup(pubkey)) == रिक्त ||
		    sshkey_read(कुञ्चिका, &tmp) != 0)
			abort();
		मुक्त(o);
		यदि ((o = tmp = strdup(certtext)) == रिक्त ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		मुक्त(o);
	}
	यदि (cp == रिक्त || pw == रिक्त || कुञ्चिका == रिक्त || cert == रिक्त)
		abort();

	// Cleanup whitespace at input EOL.
	प्रति (; आकार > 0 && strchr(" \t\r\n", दत्त[आकार - 1]) != रिक्त; आकार--) ;

	// Append a pubkey that will match.
	स्मृतिं_प्रतिलिख(cp, दत्त, आकार);
	cp[आकार] = ' ';
	स्मृतिं_प्रतिलिख(cp + आकार + 1, pubkey, वाक्यदैर्घ्यम्(pubkey) + 1);

	// Try key.
	यदि ((tmp = strdup(cp)) == रिक्त)
		abort();
	(शून्य) auth_check_authkey_पङ्क्तिः(pw, कुञ्चिका, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	// Try cert.
	यदि ((tmp = strdup(cp)) == रिक्त)
		abort();
	(शून्य) auth_check_authkey_पङ्क्तिः(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	मुक्त(cp);
	प्रत्यागम 0;
}

} // extern "C"
