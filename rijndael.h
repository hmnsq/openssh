/*	$OpenBSD: rijndael.h,v 1.15 2021/09/28 11:14:50 dtucker Exp $ */

/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਨਿੱਜੀ_RIJNDAEL_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨਿੱਜੀ_RIJNDAEL_H

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AES_MAXKEYBITS	(256)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)
/* for 256-bit keys, fewer for less */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AES_MAXROUNDS	14

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ	u8;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਛੋਟਾ	u16;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ	u32;

ਪੂਰਨ	rijndael_ਕੁੰਜੀ_ਤਿਆਰੀ_Enc(ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ [], ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ [], ਪੂਰਨ);
ਖਾਲੀ	rijndaelEncrypt(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ [], ਪੂਰਨ, ਅਚਲ u8 [16], u8 [16]);

/*  The structure for key information */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
	ਪੂਰਨ	decrypt;
	ਪੂਰਨ	Nr;		/* key-length-dependent number of rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u32	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

ਖਾਲੀ	 rijndael_ਸੈੱਟ_ਕੁੰਜੀ(rijndael_ctx *, u_char *, ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ	 rijndael_decrypt(rijndael_ctx *, u_char *, u_char *);
ਖਾਲੀ	 rijndael_encrypt(rijndael_ctx *, u_char *, u_char *);

#ਜੇ_ਅੰਤ /* _PRIVATE_RIJNDAEL_H */
