#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>

బాహ్య "C" {

#అన్తర్భావ "sshkey.h"

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* దత్తాంశం, కొలత_t కొలత)
{
	నిర్మాణం sshkey *k = ఖాళీ;
	పూర్ణాంకం r = sshkey_from_blob(దత్తాంశం, కొలత, &k);
	ఒకవేళ (r == 0) sshkey_free(k);
	తిరిగి 0;
}

} // extern

