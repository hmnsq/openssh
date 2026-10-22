#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <unistd.h>

బాహ్య "C" {

#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "sshkey.h"

// testdata/id_ed25519.pub and testdata/id_ed25519-cert.pub
స్థిరరాశి అక్షరం *pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"; 
స్థిరరాశి అక్షరం *certtext = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMDQjYH6XRzH3j3MW1DdjCoAfvrHfgjnVGF+sLK0pBfqAAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMDAAAAAAAAA+sAAAABAAAAB3VseXNzZXMAAAAXAAAAB3VseXNzZXMAAAAIb2R5c3NldXMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgM9BeYRUxUuZ4VHJp8oxVaA8OS/z+5EFPCZwQNq1nMwMAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBj0og+s09/HpwdHZbzN0twooKPDWWrxGfnP1Joy6cDnY2BCSQ7zg9vbq11kLF8H/sKOTZWAQrUZ7LlChOu9Ogw= id_ed25519.pub";

// stubs
శూన్య auth_debug_కూడు(స్థిరరాశి అక్షరం *fmt,...)
{
}

శూన్య
auth_log_authopts(స్థిరరాశి అక్షరం *loc, స్థిరరాశి నిర్మాణం sshauthopt *opts, పూర్ణాంకం do_remote)
{
}

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* దత్తాంశం, కొలత_t కొలత)
{
	అక్షరం *tmp, *o, *cp = (అక్షరం *)జ్ఞాపకం_ఇవ్వు(కొలత + 1 + అక్షరశ్రేణి_పొడవు(pubkey) + 1);
	నిర్మాణం sshauthopt *opts = ఖాళీ;
	నిర్మాణం passwd *pw = getpwuid(getuid());
	స్థిర నిర్మాణం sshkey *కీలకం, *cert;

	ఒకవేళ (కీలకం == ఖాళీ) {
		ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ ||
		    (cert = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
			abort();
		ఒకవేళ ((o = tmp = strdup(pubkey)) == ఖాళీ ||
		    sshkey_read(కీలకం, &tmp) != 0)
			abort();
		విడుదల(o);
		ఒకవేళ ((o = tmp = strdup(certtext)) == ఖాళీ ||
		    sshkey_read(cert, &tmp) != 0)
			abort();
		విడుదల(o);
	}
	ఒకవేళ (cp == ఖాళీ || pw == ఖాళీ || కీలకం == ఖాళీ || cert == ఖాళీ)
		abort();

	// Cleanup whitespace at input EOL.
	కొరకు (; కొలత > 0 && strchr(" \t\r\n", దత్తాంశం[కొలత - 1]) != ఖాళీ; కొలత--) ;

	// Append a pubkey that will match.
	జ్ఞాపకం_నకలు(cp, దత్తాంశం, కొలత);
	cp[కొలత] = ' ';
	జ్ఞాపకం_నకలు(cp + కొలత + 1, pubkey, అక్షరశ్రేణి_పొడవు(pubkey) + 1);

	// Try key.
	ఒకవేళ ((tmp = strdup(cp)) == ఖాళీ)
		abort();
	(శూన్య) auth_check_authkey_పంక్తి(pw, కీలకం, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	విడుదల(tmp);
	sshauthopt_free(opts);

	// Try cert.
	ఒకవేళ ((tmp = strdup(cp)) == ఖాళీ)
		abort();
	(శూన్య) auth_check_authkey_పంక్తి(pw, cert, tmp, "127.0.0.1", "localhost",
	    "fuzz", &opts);
	విడుదల(tmp);
	sshauthopt_free(opts);

	విడుదల(cp);
	తిరిగి 0;
}

} // extern "C"
