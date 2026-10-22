#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>

బాహ్య "C" {

#అన్తర్భావ "auth-options.h"

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* దత్తాంశం, కొలత_t కొలత)
{
	అక్షరం *cp = (అక్షరం *)జ్ఞాపకం_ఇవ్వు(కొలత + 1);
	నిర్మాణం sshauthopt *opts = ఖాళీ, *విలీనం = ఖాళీ, *కూడు = sshauthopt_new();

	ఒకవేళ (cp == ఖాళీ || కూడు == ఖాళీ)
		వెళ్ళు బహిర్గతం;
	జ్ఞాపకం_నకలు(cp, దత్తాంశం, కొలత);
	cp[కొలత] = '\0';
	ఒకవేళ ((opts = sshauthopt_parse(cp, ఖాళీ)) == ఖాళీ)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((విలీనం = sshauthopt_విలీనం(opts, కూడు, ఖాళీ)) == ఖాళీ)
		వెళ్ళు బహిర్గతం;

 బహిర్గతం:
	విడుదల(cp);
	sshauthopt_free(కూడు);
	sshauthopt_free(opts);
	sshauthopt_free(విలీనం);
	తిరిగి 0;
}

} // extern "C"
