// libfuzzer driver for krl parse fuzzing.

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>

বাহ্যিক "C" {
#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "krl.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "authfile.h"
}

স্থির পূর্ণসংখ্যা initialised = 0;
স্থির FILE *null_file;
স্থির কাঠামো sshkey *চাবি = ফাঁকা;

বাহ্যিক "C" পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2) {
    // single initialisation
    যদি (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        যদি ((null_file = fopen("/dev/null", "w")) == ফাঁকা) ফেরত 0;

        যদি (sshkey_generate(চাবি_ED25519, 0, &চাবি) != 0) ফেরত 0;

        initialised = 1;
    }

    // Reject empty corpus
    যদি (আকার_2 < 4) ফেরত 0;

    // Convert fuzzer data to ssh buffer
    কাঠামো sshbuf *buf = sshbuf_from(তথ্য, আকার_2);
    যদি (!buf) ফেরত 0;

    // Parse the ssh buffer as krl, early exit if failed
    কাঠামো ssh_krl *krl = ফাঁকা;
    পূর্ণসংখ্যা ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    যদি (ret != 0) ফেরত 0;

    // Fuzz serailisation roundtrip
    কাঠামো sshbuf *output = sshbuf_new();
    কাঠামো ssh_krl *krl2 = ফাঁকা;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_চাবি(krl, চাবি);

    ssh_krl_free(krl);
    ফেরত 0;
}
