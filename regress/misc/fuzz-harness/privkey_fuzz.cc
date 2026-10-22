#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>

బాహ్య "C" {

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* దత్తాంశం, కొలత_t కొలత)
{
	నిర్మాణం sshkey *k = ఖాళీ;
	నిర్మాణం sshbuf *b = sshbuf_from(దత్తాంశం, కొలత);
	(శూన్య)sshkey_వ్యక్తిగత_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	తిరిగి 0;
}

} // extern

