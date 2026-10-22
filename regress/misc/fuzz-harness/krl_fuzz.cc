// libfuzzer driver for krl parse fuzzing.

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>

బాహ్య "C" {
#అన్తర్భావ "includes.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "krl.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "authfile.h"
}

స్థిర పూర్ణాంకం initialised = 0;
స్థిర FILE *null_file;
స్థిర నిర్మాణం sshkey *కీలకం = ఖాళీ;

బాహ్య "C" పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత) {
    // single initialisation
    ఒకవేళ (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        ఒకవేళ ((null_file = fopen("/dev/null", "w")) == ఖాళీ) తిరిగి 0;

        ఒకవేళ (sshkey_generate(కీలకం_ED25519, 0, &కీలకం) != 0) తిరిగి 0;

        initialised = 1;
    }

    // Reject empty corpus
    ఒకవేళ (కొలత < 4) తిరిగి 0;

    // Convert fuzzer data to ssh buffer
    నిర్మాణం sshbuf *buf = sshbuf_from(దత్తాంశం, కొలత);
    ఒకవేళ (!buf) తిరిగి 0;

    // Parse the ssh buffer as krl, early exit if failed
    నిర్మాణం ssh_krl *krl = ఖాళీ;
    పూర్ణాంకం ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    ఒకవేళ (ret != 0) తిరిగి 0;

    // Fuzz serailisation roundtrip
    నిర్మాణం sshbuf *output = sshbuf_new();
    నిర్మాణం ssh_krl *krl2 = ఖాళీ;
    ssh_krl_గమ్యం_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_కీలకం(krl, కీలకం);

    ssh_krl_free(krl);
    తిరిగి 0;
}
