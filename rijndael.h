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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಖಾಸಗಿ_RIJNDAEL_H
#ವ್ಯಾಖ್ಯಾನಿಸು ಖಾಸಗಿ_RIJNDAEL_H

#ವ್ಯಾಖ್ಯಾನಿಸು AES_MAXKEYBITS	(256)
#ವ್ಯಾಖ್ಯಾನಿಸು AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)
/* for 256-bit keys, fewer for less */
#ವ್ಯಾಖ್ಯಾನಿಸು AES_MAXROUNDS	14

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ	u8;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಗಿಡ್ಡ	u16;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ	u32;

ಪೂರ್ಣಾಂಕ	rijndael_ಕೀಲಿ_ಸಿದ್ಧತೆ_Enc(ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ [], ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ [], ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	rijndaelEncrypt(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ [], ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ u8 [16], u8 [16]);

/*  The structure for key information */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
	ಪೂರ್ಣಾಂಕ	decrypt;
	ಪೂರ್ಣಾಂಕ	Nr;		/* key-length-dependent number of rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u32	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

ಶೂನ್ಯ	 rijndael_ಗಣ_ಕೀಲಿ(rijndael_ctx *, u_char *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 rijndael_decrypt(rijndael_ctx *, u_char *, u_char *);
ಶೂನ್ಯ	 rijndael_encrypt(rijndael_ctx *, u_char *, u_char *);

#ಆದರೆ_ಅಂತ್ಯ /* _PRIVATE_RIJNDAEL_H */
