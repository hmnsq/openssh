// libfuzzer driver for krl parse fuzzing.

#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>

बाह्य "C" {
#समावेश "includes.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "krl.h"
#समावेश "log.h"
#समावेश "authfile.h"
}

अटल पूर्णांक initialised = 0;
अटल खाता *null_file;
अटल काष्ठा sshkey *कुंजी = शून्य;

बाह्य "C" पूर्णांक LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार) {
    // single initialisation
    अगर (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        अगर ((null_file = ख_खोलो("/dev/null", "w")) == शून्य) वापस 0;

        अगर (sshkey_generate(कुंजी_ED25519, 0, &कुंजी) != 0) वापस 0;

        initialised = 1;
    }

    // Reject empty corpus
    अगर (आकार < 4) वापस 0;

    // Convert fuzzer data to ssh buffer
    काष्ठा sshbuf *buf = sshbuf_from(तथ्य, आकार);
    अगर (!buf) वापस 0;

    // Parse the ssh buffer as krl, early exit if failed
    काष्ठा ssh_krl *krl = शून्य;
    पूर्णांक ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    अगर (ret != 0) वापस 0;

    // Fuzz serailisation roundtrip
    काष्ठा sshbuf *output = sshbuf_new();
    काष्ठा ssh_krl *krl2 = शून्य;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_कुंजी(krl, कुंजी);

    ssh_krl_free(krl);
    वापस 0;
}
