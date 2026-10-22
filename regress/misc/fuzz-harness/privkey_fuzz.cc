#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = sshbuf_from(ਅੰਕੜੇ, ਮਾਪ);
	(ਖਾਲੀ)sshkey_ਨਿੱਜੀ_deserialize(b, &k);
	sshkey_free(k);
	sshbuf_free(b);
	ਵਾਪਸ 0;
}

} // extern

