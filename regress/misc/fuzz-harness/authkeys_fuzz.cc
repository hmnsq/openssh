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
स्थिरांक अक्षर *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
स्थिरांक अक्षर *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
शून्य auth_debug_add(स्थिरांक अक्षर *fmt,...)
{
}

शून्य
auth_log_authopts(स्थिरांक अक्षर *loc, स्थिरांक संरचना sshauthopt *opts, पूर्णांक do_remote)
{
}

पूर्णांक LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t* data, माप_प्रकार size)
{
	अक्षर *tmp, *o, *cp = (अक्षर *)दो_स्मृति(size + 1 + म_माप(pubkey) + 1);
	संरचना sshauthopt *opts = रिक्त;
	संरचना passwd *pw = getpwuid(getuid());
	स्थिर संरचना sshkey *किल्ली, *cert;

	जर (किल्ली == रिक्त) {
		जर ((किल्ली = sshkey_new(किल्ली_UNSPEC)) == रिक्त ||
		    (cert = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
			पात();
		जर ((o = tmp = strdup(pubkey)) == रिक्त ||
		    sshkey_read(किल्ली, &tmp) != 0)
			पात();
		मुक्त(o);
		जर ((o = tmp = strdup(certtext)) == रिक्त ||
		    sshkey_read(cert, &tmp) != 0)
			पात();
		मुक्त(o);
	}
	जर (cp == रिक्त || pw == रिक्त || किल्ली == रिक्त || cert == रिक्त)
		पात();

	// Cleanup whitespace at input EOL.
	साठी (; size > 0 && म_अक्षर(" \t\r\n", data[size - 1]) != रिक्त; size--) ;

	// Append a pubkey that will match.
	स_नकल(cp, data, size);
	cp[size] = ' ';
	स_नकल(cp + size + 1, pubkey, म_माप(pubkey) + 1);

	// Try key.
	जर ((tmp = strdup(cp)) == रिक्त)
		पात();
	(शून्य) auth_check_authkey_ओळ(pw, किल्ली, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	// Try cert.
	जर ((tmp = strdup(cp)) == रिक्त)
		पात();
	(शून्य) auth_check_authkey_ओळ(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	मुक्त(tmp);
	sshauthopt_free(opts);

	मुक्त(cp);
	परत 0;
}

} // extern "C"
