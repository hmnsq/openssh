/*	$OpenBSD: tree.h,v 1.13 2011/07/09 00:19:45 pirofti Exp $	*/
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: sys/sys/tree.h */

#ਅਨ੍ਤਰ੍ਭਾਵ "config.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ	SYS_ਰੁੱਖ_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SYS_ਰੁੱਖ_H

/*
 * This file defines data structures for different types of trees:
 * splay trees and red-black trees.
 *
 * A splay tree is a self-organizing data structure.  Every operation
 * on the tree causes a splay to happen.  The splay moves the requested
 * node to the root of the tree and partly rebalances it.
 *
 * This has the benefit that request locality causes faster lookups as
 * the requested nodes move to the top of the tree.  On the other hand,
 * every lookup causes memory writes.
 *
 * The Balance Theorem bounds the total access time for m operations
 * and n inserts on an initially empty tree as O((m + n)lg n).  The
 * amortized cost for a sequence of m accesses to a splay tree is O(lg n);
 *
 * A red-black tree is a binary search tree with the node color as an
 * extra attribute.  It fulfills a set of conditions:
 *	- every search path from the root to a leaf consists of the
 *	  same number of black nodes,
 *	- each red node (except for the root) has a black parent,
 *	- each leaf node is black.
 *
 * Every operation on a red-black tree is bounded as O(lg n).
 * The maximum height of a red-black tree is 2lg (n+1).
 */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਸਿਰ(name, type)						\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *sph_ਜੜ੍ਹ; /* root of the tree */			\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_INITIALIZER(ਜੜ੍ਹ)						\
	{ ਨਿਰਾ }

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_INIT(ਜੜ੍ਹ) ਕਰੋ {						\
	(ਜੜ੍ਹ)->sph_ਜੜ੍ਹ = ਨਿਰਾ;					\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਇੰਦਰਾਜ(type)						\
ਬਣਤਰ {								\
	ਬਣਤਰ type *spe_ਖੱਬਾ; /* left element */			\
	ਬਣਤਰ type *spe_ਸੱਜਾ; /* right element */			\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਖੱਬਾ(elm, ਖੇਤਰ)		(elm)->ਖੇਤਰ.spe_ਖੱਬਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਸੱਜਾ(elm, ਖੇਤਰ)		(elm)->ਖੇਤਰ.spe_ਸੱਜਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਜੜ੍ਹ(ਸਿਰ)		(ਸਿਰ)->sph_ਜੜ੍ਹ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਖਾਲੀ_ਥਾਵਾਂ(ਸਿਰ)		(SPLAY_ਜੜ੍ਹ(ਸਿਰ) == ਨਿਰਾ)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ROTATE_ਸੱਜਾ(ਸਿਰ, tmp, ਖੇਤਰ) ਕਰੋ {			\
	SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = SPLAY_ਸੱਜਾ(tmp, ਖੇਤਰ);	\
	SPLAY_ਸੱਜਾ(tmp, ਖੇਤਰ) = (ਸਿਰ)->sph_ਜੜ੍ਹ;			\
	(ਸਿਰ)->sph_ਜੜ੍ਹ = tmp;						\
} ਜਦੋਂ (0)
	
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ROTATE_ਖੱਬਾ(ਸਿਰ, tmp, ਖੇਤਰ) ਕਰੋ {			\
	SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = SPLAY_ਖੱਬਾ(tmp, ਖੇਤਰ);	\
	SPLAY_ਖੱਬਾ(tmp, ਖੇਤਰ) = (ਸਿਰ)->sph_ਜੜ੍ਹ;			\
	(ਸਿਰ)->sph_ਜੜ੍ਹ = tmp;						\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_LINKLEFT(ਸਿਰ, tmp, ਖੇਤਰ) ਕਰੋ {				\
	SPLAY_ਖੱਬਾ(tmp, ਖੇਤਰ) = (ਸਿਰ)->sph_ਜੜ੍ਹ;			\
	tmp = (ਸਿਰ)->sph_ਜੜ੍ਹ;						\
	(ਸਿਰ)->sph_ਜੜ੍ਹ = SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);		\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_LINKRIGHT(ਸਿਰ, tmp, ਖੇਤਰ) ਕਰੋ {				\
	SPLAY_ਸੱਜਾ(tmp, ਖੇਤਰ) = (ਸਿਰ)->sph_ਜੜ੍ਹ;			\
	tmp = (ਸਿਰ)->sph_ਜੜ੍ਹ;						\
	(ਸਿਰ)->sph_ਜੜ੍ਹ = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ASSEMBLE(ਸਿਰ, ਗੰਢ, ਖੱਬਾ, ਸੱਜਾ, ਖੇਤਰ) ਕਰੋ {		\
	SPLAY_ਸੱਜਾ(ਖੱਬਾ, ਖੇਤਰ) = SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
	SPLAY_ਖੱਬਾ(ਸੱਜਾ, ਖੇਤਰ) = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);\
	SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = SPLAY_ਸੱਜਾ(ਗੰਢ, ਖੇਤਰ);	\
	SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = SPLAY_ਖੱਬਾ(ਗੰਢ, ਖੇਤਰ);	\
} ਜਦੋਂ (0)

/* Generates prototypes and inline functions */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_PROTOTYPE(name, type, ਖੇਤਰ, cmp)				\
ਖਾਲੀ name##_SPLAY(ਬਣਤਰ name *, ਬਣਤਰ type *);			\
ਖਾਲੀ name##_SPLAY_MINMAX(ਬਣਤਰ name *, ਪੂਰਨ);				\
ਬਣਤਰ type *name##_SPLAY_INSERT(ਬਣਤਰ name *, ਬਣਤਰ type *);		\
ਬਣਤਰ type *name##_SPLAY_REMOVE(ਬਣਤਰ name *, ਬਣਤਰ type *);		\
									\
/* Finds the node with the same key as elm */				\
ਸਥਿਰ __inline ਬਣਤਰ type *						\
name##_SPLAY_FIND(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	ਜੇ (SPLAY_ਖਾਲੀ_ਥਾਵਾਂ(ਸਿਰ))						\
		ਵਾਪਸ(ਨਿਰਾ);						\
	name##_SPLAY(ਸਿਰ, elm);					\
	ਜੇ ((cmp)(elm, (ਸਿਰ)->sph_ਜੜ੍ਹ) == 0)				\
		ਵਾਪਸ (ਸਿਰ->sph_ਜੜ੍ਹ);				\
	ਵਾਪਸ (ਨਿਰਾ);							\
}									\
									\
ਸਥਿਰ __inline ਬਣਤਰ type *						\
name##_SPLAY_NEXT(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	name##_SPLAY(ਸਿਰ, elm);					\
	ਜੇ (SPLAY_ਸੱਜਾ(elm, ਖੇਤਰ) != ਨਿਰਾ) {				\
		elm = SPLAY_ਸੱਜਾ(elm, ਖੇਤਰ);				\
		ਜਦੋਂ (SPLAY_ਖੱਬਾ(elm, ਖੇਤਰ) != ਨਿਰਾ) {		\
			elm = SPLAY_ਖੱਬਾ(elm, ਖੇਤਰ);			\
		}							\
	} ਨਹੀਂਤਾਂ								\
		elm = ਨਿਰਾ;						\
	ਵਾਪਸ (elm);							\
}									\
									\
ਸਥਿਰ __inline ਬਣਤਰ type *						\
name##_SPLAY_MIN_MAX(ਬਣਤਰ name *ਸਿਰ, ਪੂਰਨ val)			\
{									\
	name##_SPLAY_MINMAX(ਸਿਰ, val);					\
        ਵਾਪਸ (SPLAY_ਜੜ੍ਹ(ਸਿਰ));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_GENERATE(name, type, ਖੇਤਰ, cmp)				\
ਬਣਤਰ type *								\
name##_SPLAY_INSERT(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)		\
{									\
    ਜੇ (SPLAY_ਖਾਲੀ_ਥਾਵਾਂ(ਸਿਰ)) {						\
	    SPLAY_ਖੱਬਾ(elm, ਖੇਤਰ) = SPLAY_ਸੱਜਾ(elm, ਖੇਤਰ) = ਨਿਰਾ;	\
    } ਨਹੀਂਤਾਂ {								\
	    ਪੂਰਨ __comp;							\
	    name##_SPLAY(ਸਿਰ, elm);					\
	    __comp = (cmp)(elm, (ਸਿਰ)->sph_ਜੜ੍ਹ);			\
	    ਜੇ(__comp < 0) {						\
		    SPLAY_ਖੱਬਾ(elm, ਖੇਤਰ) = SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);\
		    SPLAY_ਸੱਜਾ(elm, ਖੇਤਰ) = (ਸਿਰ)->sph_ਜੜ੍ਹ;		\
		    SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = ਨਿਰਾ;		\
	    } ਨਹੀਂਤਾਂ ਜੇ (__comp > 0) {					\
		    SPLAY_ਸੱਜਾ(elm, ਖੇਤਰ) = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);\
		    SPLAY_ਖੱਬਾ(elm, ਖੇਤਰ) = (ਸਿਰ)->sph_ਜੜ੍ਹ;		\
		    SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = ਨਿਰਾ;	\
	    } ਨਹੀਂਤਾਂ							\
		    ਵਾਪਸ ((ਸਿਰ)->sph_ਜੜ੍ਹ);				\
    }									\
    (ਸਿਰ)->sph_ਜੜ੍ਹ = (elm);						\
    ਵਾਪਸ (ਨਿਰਾ);							\
}									\
									\
ਬਣਤਰ type *								\
name##_SPLAY_REMOVE(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)		\
{									\
	ਬਣਤਰ type *__tmp;						\
	ਜੇ (SPLAY_ਖਾਲੀ_ਥਾਵਾਂ(ਸਿਰ))						\
		ਵਾਪਸ (ਨਿਰਾ);						\
	name##_SPLAY(ਸਿਰ, elm);					\
	ਜੇ ((cmp)(elm, (ਸਿਰ)->sph_ਜੜ੍ਹ) == 0) {			\
		ਜੇ (SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) == ਨਿਰਾ) {	\
			(ਸਿਰ)->sph_ਜੜ੍ਹ = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);\
		} ਨਹੀਂਤਾਂ {						\
			__tmp = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
			(ਸਿਰ)->sph_ਜੜ੍ਹ = SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);\
			name##_SPLAY(ਸਿਰ, elm);			\
			SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) = __tmp;	\
		}							\
		ਵਾਪਸ (elm);						\
	}								\
	ਵਾਪਸ (ਨਿਰਾ);							\
}									\
									\
ਖਾਲੀ									\
name##_SPLAY(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	ਬਣਤਰ type __node, *__left, *__right, *__tmp;			\
	ਪੂਰਨ __comp;							\
\
	SPLAY_ਖੱਬਾ(&__node, ਖੇਤਰ) = SPLAY_ਸੱਜਾ(&__node, ਖੇਤਰ) = ਨਿਰਾ;\
	__left = __right = &__node;					\
\
	ਜਦੋਂ ((__comp = (cmp)(elm, (ਸਿਰ)->sph_ਜੜ੍ਹ))) {		\
		ਜੇ (__comp < 0) {					\
			__tmp = SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
			ਜੇ (__tmp == ਨਿਰਾ)				\
				ਰੋਕੋ;					\
			ਜੇ ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_ਸੱਜਾ(ਸਿਰ, __tmp, ਖੇਤਰ);	\
				ਜੇ (SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) == ਨਿਰਾ)\
					ਰੋਕੋ;				\
			}						\
			SPLAY_LINKLEFT(ਸਿਰ, __right, ਖੇਤਰ);		\
		} ਨਹੀਂਤਾਂ ਜੇ (__comp > 0) {				\
			__tmp = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
			ਜੇ (__tmp == ਨਿਰਾ)				\
				ਰੋਕੋ;					\
			ਜੇ ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ਖੱਬਾ(ਸਿਰ, __tmp, ਖੇਤਰ);	\
				ਜੇ (SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) == ਨਿਰਾ)\
					ਰੋਕੋ;				\
			}						\
			SPLAY_LINKRIGHT(ਸਿਰ, __left, ਖੇਤਰ);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(ਸਿਰ, &__node, __left, __right, ਖੇਤਰ);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
ਖਾਲੀ name##_SPLAY_MINMAX(ਬਣਤਰ name *ਸਿਰ, ਪੂਰਨ __comp) \
{									\
	ਬਣਤਰ type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ਖੱਬਾ(&__node, ਖੇਤਰ) = SPLAY_ਸੱਜਾ(&__node, ਖੇਤਰ) = ਨਿਰਾ;\
	__left = __right = &__node;					\
\
	ਜਦੋਂ (1) {							\
		ਜੇ (__comp < 0) {					\
			__tmp = SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
			ਜੇ (__tmp == ਨਿਰਾ)				\
				ਰੋਕੋ;					\
			ਜੇ (__comp < 0){				\
				SPLAY_ROTATE_ਸੱਜਾ(ਸਿਰ, __tmp, ਖੇਤਰ);	\
				ਜੇ (SPLAY_ਖੱਬਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) == ਨਿਰਾ)\
					ਰੋਕੋ;				\
			}						\
			SPLAY_LINKLEFT(ਸਿਰ, __right, ਖੇਤਰ);		\
		} ਨਹੀਂਤਾਂ ਜੇ (__comp > 0) {				\
			__tmp = SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ);	\
			ਜੇ (__tmp == ਨਿਰਾ)				\
				ਰੋਕੋ;					\
			ਜੇ (__comp > 0) {				\
				SPLAY_ROTATE_ਖੱਬਾ(ਸਿਰ, __tmp, ਖੇਤਰ);	\
				ਜੇ (SPLAY_ਸੱਜਾ((ਸਿਰ)->sph_ਜੜ੍ਹ, ਖੇਤਰ) == ਨਿਰਾ)\
					ਰੋਕੋ;				\
			}						\
			SPLAY_LINKRIGHT(ਸਿਰ, __left, ਖੇਤਰ);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(ਸਿਰ, &__node, __left, __right, ਖੇਤਰ);		\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_NEGINF	-1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_INF	1

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਪਾਓ(name, x, y)	name##_SPLAY_INSERT(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਲੱਭੋ(name, x, y)		name##_SPLAY_FIND(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_ਅਗਲਾ(name, x, y)		name##_SPLAY_NEXT(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_MIN(name, x)		(SPLAY_ਖਾਲੀ_ਥਾਵਾਂ(x) ? ਨਿਰਾ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_MAX(name, x)		(SPLAY_ਖਾਲੀ_ਥਾਵਾਂ(x) ? ਨਿਰਾ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SPLAY_FOREACH(x, name, ਸਿਰ)					\
	ਲਈ ((x) = SPLAY_MIN(name, ਸਿਰ);				\
	     (x) != ਨਿਰਾ;						\
	     (x) = SPLAY_ਅਗਲਾ(name, ਸਿਰ, x))

/* Macros that define a red-black tree */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਸਿਰ(name, type)						\
ਬਣਤਰ name {								\
	ਬਣਤਰ type *rbh_ਜੜ੍ਹ; /* root of the tree */			\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_INITIALIZER(ਜੜ੍ਹ)						\
	{ ਨਿਰਾ }

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_INIT(ਜੜ੍ਹ) ਕਰੋ {						\
	(ਜੜ੍ਹ)->rbh_ਜੜ੍ਹ = ਨਿਰਾ;					\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_BLACK	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_RED		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਇੰਦਰਾਜ(type)							\
ਬਣਤਰ {								\
	ਬਣਤਰ type *rbe_ਖੱਬਾ;		/* left element */		\
	ਬਣਤਰ type *rbe_ਸੱਜਾ;		/* right element */		\
	ਬਣਤਰ type *rbe_ਮਾਪਾ;	/* parent element */		\
	ਪੂਰਨ rbe_color;			/* node color */		\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਖੱਬਾ(elm, ਖੇਤਰ)		(elm)->ਖੇਤਰ.rbe_ਖੱਬਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਸੱਜਾ(elm, ਖੇਤਰ)		(elm)->ਖੇਤਰ.rbe_ਸੱਜਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਮਾਪਾ(elm, ਖੇਤਰ)		(elm)->ਖੇਤਰ.rbe_ਮਾਪਾ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_COLOR(elm, ਖੇਤਰ)		(elm)->ਖੇਤਰ.rbe_color
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਜੜ੍ਹ(ਸਿਰ)			(ਸਿਰ)->rbh_ਜੜ੍ਹ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਖਾਲੀ_ਥਾਵਾਂ(ਸਿਰ)			(RB_ਜੜ੍ਹ(ਸਿਰ) == ਨਿਰਾ)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਸੈੱਟ(elm, ਮਾਪਾ, ਖੇਤਰ) ਕਰੋ {					\
	RB_ਮਾਪਾ(elm, ਖੇਤਰ) = ਮਾਪਾ;					\
	RB_ਖੱਬਾ(elm, ਖੇਤਰ) = RB_ਸੱਜਾ(elm, ਖੇਤਰ) = ਨਿਰਾ;		\
	RB_COLOR(elm, ਖੇਤਰ) = RB_RED;					\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਸੈੱਟ_BLACKRED(black, red, ਖੇਤਰ) ਕਰੋ {				\
	RB_COLOR(black, ਖੇਤਰ) = RB_BLACK;				\
	RB_COLOR(red, ਖੇਤਰ) = RB_RED;					\
} ਜਦੋਂ (0)

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ RB_AUGMENT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_AUGMENT(x)	ਕਰੋ {} ਜਦੋਂ (0)
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ROTATE_ਖੱਬਾ(ਸਿਰ, elm, tmp, ਖੇਤਰ) ਕਰੋ {			\
	(tmp) = RB_ਸੱਜਾ(elm, ਖੇਤਰ);					\
	ਜੇ ((RB_ਸੱਜਾ(elm, ਖੇਤਰ) = RB_ਖੱਬਾ(tmp, ਖੇਤਰ))) {		\
		RB_ਮਾਪਾ(RB_ਖੱਬਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ਜੇ ((RB_ਮਾਪਾ(tmp, ਖੇਤਰ) = RB_ਮਾਪਾ(elm, ਖੇਤਰ))) {		\
		ਜੇ ((elm) == RB_ਖੱਬਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ))	\
			RB_ਖੱਬਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ) = (tmp);	\
		ਨਹੀਂਤਾਂ							\
			RB_ਸੱਜਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ) = (tmp);	\
	} ਨਹੀਂਤਾਂ								\
		(ਸਿਰ)->rbh_ਜੜ੍ਹ = (tmp);				\
	RB_ਖੱਬਾ(tmp, ਖੇਤਰ) = (elm);					\
	RB_ਮਾਪਾ(elm, ਖੇਤਰ) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ਜੇ ((RB_ਮਾਪਾ(tmp, ਖੇਤਰ)))					\
		RB_AUGMENT(RB_ਮਾਪਾ(tmp, ਖੇਤਰ));			\
} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ROTATE_ਸੱਜਾ(ਸਿਰ, elm, tmp, ਖੇਤਰ) ਕਰੋ {			\
	(tmp) = RB_ਖੱਬਾ(elm, ਖੇਤਰ);					\
	ਜੇ ((RB_ਖੱਬਾ(elm, ਖੇਤਰ) = RB_ਸੱਜਾ(tmp, ਖੇਤਰ))) {		\
		RB_ਮਾਪਾ(RB_ਸੱਜਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	ਜੇ ((RB_ਮਾਪਾ(tmp, ਖੇਤਰ) = RB_ਮਾਪਾ(elm, ਖੇਤਰ))) {		\
		ਜੇ ((elm) == RB_ਖੱਬਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ))	\
			RB_ਖੱਬਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ) = (tmp);	\
		ਨਹੀਂਤਾਂ							\
			RB_ਸੱਜਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ) = (tmp);	\
	} ਨਹੀਂਤਾਂ								\
		(ਸਿਰ)->rbh_ਜੜ੍ਹ = (tmp);				\
	RB_ਸੱਜਾ(tmp, ਖੇਤਰ) = (elm);					\
	RB_ਮਾਪਾ(elm, ਖੇਤਰ) = (tmp);					\
	RB_AUGMENT(tmp);						\
	ਜੇ ((RB_ਮਾਪਾ(tmp, ਖੇਤਰ)))					\
		RB_AUGMENT(RB_ਮਾਪਾ(tmp, ਖੇਤਰ));			\
} ਜਦੋਂ (0)

/* Generates prototypes and inline functions */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RB_PROTOTYPE(name, type, ਖੇਤਰ, cmp)				\
	RB_PROTOTYPE_ਅੰਦਰੂਨੀ(name, type, ਖੇਤਰ, cmp,)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RB_PROTOTYPE_STATIC(name, type, ਖੇਤਰ, cmp)			\
	RB_PROTOTYPE_ਅੰਦਰੂਨੀ(name, type, ਖੇਤਰ, cmp, __attribute__((__unused__)) ਸਥਿਰ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_PROTOTYPE_ਅੰਦਰੂਨੀ(name, type, ਖੇਤਰ, cmp, attr)		\
attr ਖਾਲੀ name##_RB_INSERT_COLOR(ਬਣਤਰ name *, ਬਣਤਰ type *);		\
attr ਖਾਲੀ name##_RB_REMOVE_COLOR(ਬਣਤਰ name *, ਬਣਤਰ type *, ਬਣਤਰ type *);\
attr ਬਣਤਰ type *name##_RB_REMOVE(ਬਣਤਰ name *, ਬਣਤਰ type *);	\
attr ਬਣਤਰ type *name##_RB_INSERT(ਬਣਤਰ name *, ਬਣਤਰ type *);	\
attr ਬਣਤਰ type *name##_RB_FIND(ਬਣਤਰ name *, ਬਣਤਰ type *);		\
attr ਬਣਤਰ type *name##_RB_NFIND(ਬਣਤਰ name *, ਬਣਤਰ type *);	\
attr ਬਣਤਰ type *name##_RB_NEXT(ਬਣਤਰ type *);			\
attr ਬਣਤਰ type *name##_RB_PREV(ਬਣਤਰ type *);			\
attr ਬਣਤਰ type *name##_RB_MINMAX(ਬਣਤਰ name *, ਪੂਰਨ);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RB_GENERATE(name, type, ਖੇਤਰ, cmp)				\
	RB_GENERATE_ਅੰਦਰੂਨੀ(name, type, ਖੇਤਰ, cmp,)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RB_GENERATE_STATIC(name, type, ਖੇਤਰ, cmp)			\
	RB_GENERATE_ਅੰਦਰੂਨੀ(name, type, ਖੇਤਰ, cmp, __attribute__((__unused__)) ਸਥਿਰ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_GENERATE_ਅੰਦਰੂਨੀ(name, type, ਖੇਤਰ, cmp, attr)		\
attr ਖਾਲੀ								\
name##_RB_INSERT_COLOR(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)		\
{									\
	ਬਣਤਰ type *ਮਾਪਾ, *gparent, *tmp;				\
	ਜਦੋਂ ((ਮਾਪਾ = RB_ਮਾਪਾ(elm, ਖੇਤਰ)) &&			\
	    RB_COLOR(ਮਾਪਾ, ਖੇਤਰ) == RB_RED) {			\
		gparent = RB_ਮਾਪਾ(ਮਾਪਾ, ਖੇਤਰ);			\
		ਜੇ (ਮਾਪਾ == RB_ਖੱਬਾ(gparent, ਖੇਤਰ)) {		\
			tmp = RB_ਸੱਜਾ(gparent, ਖੇਤਰ);			\
			ਜੇ (tmp && RB_COLOR(tmp, ਖੇਤਰ) == RB_RED) {	\
				RB_COLOR(tmp, ਖੇਤਰ) = RB_BLACK;	\
				RB_ਸੈੱਟ_BLACKRED(ਮਾਪਾ, gparent, ਖੇਤਰ);\
				elm = gparent;				\
				ਜਾਰੀ;				\
			}						\
			ਜੇ (RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ) == elm) {		\
				RB_ROTATE_ਖੱਬਾ(ਸਿਰ, ਮਾਪਾ, tmp, ਖੇਤਰ);\
				tmp = ਮਾਪਾ;				\
				ਮਾਪਾ = elm;				\
				elm = tmp;				\
			}						\
			RB_ਸੈੱਟ_BLACKRED(ਮਾਪਾ, gparent, ਖੇਤਰ);	\
			RB_ROTATE_ਸੱਜਾ(ਸਿਰ, gparent, tmp, ਖੇਤਰ);	\
		} ਨਹੀਂਤਾਂ {						\
			tmp = RB_ਖੱਬਾ(gparent, ਖੇਤਰ);			\
			ਜੇ (tmp && RB_COLOR(tmp, ਖੇਤਰ) == RB_RED) {	\
				RB_COLOR(tmp, ਖੇਤਰ) = RB_BLACK;	\
				RB_ਸੈੱਟ_BLACKRED(ਮਾਪਾ, gparent, ਖੇਤਰ);\
				elm = gparent;				\
				ਜਾਰੀ;				\
			}						\
			ਜੇ (RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) == elm) {		\
				RB_ROTATE_ਸੱਜਾ(ਸਿਰ, ਮਾਪਾ, tmp, ਖੇਤਰ);\
				tmp = ਮਾਪਾ;				\
				ਮਾਪਾ = elm;				\
				elm = tmp;				\
			}						\
			RB_ਸੈੱਟ_BLACKRED(ਮਾਪਾ, gparent, ਖੇਤਰ);	\
			RB_ROTATE_ਖੱਬਾ(ਸਿਰ, gparent, tmp, ਖੇਤਰ);	\
		}							\
	}								\
	RB_COLOR(ਸਿਰ->rbh_ਜੜ੍ਹ, ਖੇਤਰ) = RB_BLACK;			\
}									\
									\
attr ਖਾਲੀ								\
name##_RB_REMOVE_COLOR(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *ਮਾਪਾ, ਬਣਤਰ type *elm) \
{									\
	ਬਣਤਰ type *tmp;						\
	ਜਦੋਂ ((elm == ਨਿਰਾ || RB_COLOR(elm, ਖੇਤਰ) == RB_BLACK) &&	\
	    elm != RB_ਜੜ੍ਹ(ਸਿਰ)) {					\
		ਜੇ (RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) == elm) {			\
			tmp = RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ);			\
			ਜੇ (RB_COLOR(tmp, ਖੇਤਰ) == RB_RED) {		\
				RB_ਸੈੱਟ_BLACKRED(tmp, ਮਾਪਾ, ਖੇਤਰ);	\
				RB_ROTATE_ਖੱਬਾ(ਸਿਰ, ਮਾਪਾ, tmp, ਖੇਤਰ);\
				tmp = RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ);		\
			}						\
			ਜੇ ((RB_ਖੱਬਾ(tmp, ਖੇਤਰ) == ਨਿਰਾ ||		\
			    RB_COLOR(RB_ਖੱਬਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) == RB_BLACK) &&\
			    (RB_ਸੱਜਾ(tmp, ਖੇਤਰ) == ਨਿਰਾ ||		\
			    RB_COLOR(RB_ਸੱਜਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) == RB_BLACK)) {\
				RB_COLOR(tmp, ਖੇਤਰ) = RB_RED;		\
				elm = ਮਾਪਾ;				\
				ਮਾਪਾ = RB_ਮਾਪਾ(elm, ਖੇਤਰ);		\
			} ਨਹੀਂਤਾਂ {					\
				ਜੇ (RB_ਸੱਜਾ(tmp, ਖੇਤਰ) == ਨਿਰਾ ||	\
				    RB_COLOR(RB_ਸੱਜਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) == RB_BLACK) {\
					ਬਣਤਰ type *oleft;		\
					ਜੇ ((oleft = RB_ਖੱਬਾ(tmp, ਖੇਤਰ)))\
						RB_COLOR(oleft, ਖੇਤਰ) = RB_BLACK;\
					RB_COLOR(tmp, ਖੇਤਰ) = RB_RED;	\
					RB_ROTATE_ਸੱਜਾ(ਸਿਰ, tmp, oleft, ਖੇਤਰ);\
					tmp = RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ);	\
				}					\
				RB_COLOR(tmp, ਖੇਤਰ) = RB_COLOR(ਮਾਪਾ, ਖੇਤਰ);\
				RB_COLOR(ਮਾਪਾ, ਖੇਤਰ) = RB_BLACK;	\
				ਜੇ (RB_ਸੱਜਾ(tmp, ਖੇਤਰ))		\
					RB_COLOR(RB_ਸੱਜਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) = RB_BLACK;\
				RB_ROTATE_ਖੱਬਾ(ਸਿਰ, ਮਾਪਾ, tmp, ਖੇਤਰ);\
				elm = RB_ਜੜ੍ਹ(ਸਿਰ);			\
				ਰੋਕੋ;					\
			}						\
		} ਨਹੀਂਤਾਂ {						\
			tmp = RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ);			\
			ਜੇ (RB_COLOR(tmp, ਖੇਤਰ) == RB_RED) {		\
				RB_ਸੈੱਟ_BLACKRED(tmp, ਮਾਪਾ, ਖੇਤਰ);	\
				RB_ROTATE_ਸੱਜਾ(ਸਿਰ, ਮਾਪਾ, tmp, ਖੇਤਰ);\
				tmp = RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ);		\
			}						\
			ਜੇ ((RB_ਖੱਬਾ(tmp, ਖੇਤਰ) == ਨਿਰਾ ||		\
			    RB_COLOR(RB_ਖੱਬਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) == RB_BLACK) &&\
			    (RB_ਸੱਜਾ(tmp, ਖੇਤਰ) == ਨਿਰਾ ||		\
			    RB_COLOR(RB_ਸੱਜਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) == RB_BLACK)) {\
				RB_COLOR(tmp, ਖੇਤਰ) = RB_RED;		\
				elm = ਮਾਪਾ;				\
				ਮਾਪਾ = RB_ਮਾਪਾ(elm, ਖੇਤਰ);		\
			} ਨਹੀਂਤਾਂ {					\
				ਜੇ (RB_ਖੱਬਾ(tmp, ਖੇਤਰ) == ਨਿਰਾ ||	\
				    RB_COLOR(RB_ਖੱਬਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) == RB_BLACK) {\
					ਬਣਤਰ type *oright;		\
					ਜੇ ((oright = RB_ਸੱਜਾ(tmp, ਖੇਤਰ)))\
						RB_COLOR(oright, ਖੇਤਰ) = RB_BLACK;\
					RB_COLOR(tmp, ਖੇਤਰ) = RB_RED;	\
					RB_ROTATE_ਖੱਬਾ(ਸਿਰ, tmp, oright, ਖੇਤਰ);\
					tmp = RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ);	\
				}					\
				RB_COLOR(tmp, ਖੇਤਰ) = RB_COLOR(ਮਾਪਾ, ਖੇਤਰ);\
				RB_COLOR(ਮਾਪਾ, ਖੇਤਰ) = RB_BLACK;	\
				ਜੇ (RB_ਖੱਬਾ(tmp, ਖੇਤਰ))		\
					RB_COLOR(RB_ਖੱਬਾ(tmp, ਖੇਤਰ), ਖੇਤਰ) = RB_BLACK;\
				RB_ROTATE_ਸੱਜਾ(ਸਿਰ, ਮਾਪਾ, tmp, ਖੇਤਰ);\
				elm = RB_ਜੜ੍ਹ(ਸਿਰ);			\
				ਰੋਕੋ;					\
			}						\
		}							\
	}								\
	ਜੇ (elm)							\
		RB_COLOR(elm, ਖੇਤਰ) = RB_BLACK;			\
}									\
									\
attr ਬਣਤਰ type *							\
name##_RB_REMOVE(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	ਬਣਤਰ type *ਬੱਚਾ, *ਮਾਪਾ, *old = elm;			\
	ਪੂਰਨ color;							\
	ਜੇ (RB_ਖੱਬਾ(elm, ਖੇਤਰ) == ਨਿਰਾ)				\
		ਬੱਚਾ = RB_ਸੱਜਾ(elm, ਖੇਤਰ);				\
	ਨਹੀਂਤਾਂ ਜੇ (RB_ਸੱਜਾ(elm, ਖੇਤਰ) == ਨਿਰਾ)				\
		ਬੱਚਾ = RB_ਖੱਬਾ(elm, ਖੇਤਰ);				\
	ਨਹੀਂਤਾਂ {								\
		ਬਣਤਰ type *ਖੱਬਾ;					\
		elm = RB_ਸੱਜਾ(elm, ਖੇਤਰ);				\
		ਜਦੋਂ ((ਖੱਬਾ = RB_ਖੱਬਾ(elm, ਖੇਤਰ)))			\
			elm = ਖੱਬਾ;					\
		ਬੱਚਾ = RB_ਸੱਜਾ(elm, ਖੇਤਰ);				\
		ਮਾਪਾ = RB_ਮਾਪਾ(elm, ਖੇਤਰ);				\
		color = RB_COLOR(elm, ਖੇਤਰ);				\
		ਜੇ (ਬੱਚਾ)						\
			RB_ਮਾਪਾ(ਬੱਚਾ, ਖੇਤਰ) = ਮਾਪਾ;		\
		ਜੇ (ਮਾਪਾ) {						\
			ਜੇ (RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) == elm)		\
				RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) = ਬੱਚਾ;		\
			ਨਹੀਂਤਾਂ						\
				RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ) = ਬੱਚਾ;	\
			RB_AUGMENT(ਮਾਪਾ);				\
		} ਨਹੀਂਤਾਂ							\
			RB_ਜੜ੍ਹ(ਸਿਰ) = ਬੱਚਾ;				\
		ਜੇ (RB_ਮਾਪਾ(elm, ਖੇਤਰ) == old)			\
			ਮਾਪਾ = elm;					\
		(elm)->ਖੇਤਰ = (old)->ਖੇਤਰ;				\
		ਜੇ (RB_ਮਾਪਾ(old, ਖੇਤਰ)) {				\
			ਜੇ (RB_ਖੱਬਾ(RB_ਮਾਪਾ(old, ਖੇਤਰ), ਖੇਤਰ) == old)\
				RB_ਖੱਬਾ(RB_ਮਾਪਾ(old, ਖੇਤਰ), ਖੇਤਰ) = elm;\
			ਨਹੀਂਤਾਂ						\
				RB_ਸੱਜਾ(RB_ਮਾਪਾ(old, ਖੇਤਰ), ਖੇਤਰ) = elm;\
			RB_AUGMENT(RB_ਮਾਪਾ(old, ਖੇਤਰ));		\
		} ਨਹੀਂਤਾਂ							\
			RB_ਜੜ੍ਹ(ਸਿਰ) = elm;				\
		RB_ਮਾਪਾ(RB_ਖੱਬਾ(old, ਖੇਤਰ), ਖੇਤਰ) = elm;		\
		ਜੇ (RB_ਸੱਜਾ(old, ਖੇਤਰ))				\
			RB_ਮਾਪਾ(RB_ਸੱਜਾ(old, ਖੇਤਰ), ਖੇਤਰ) = elm;	\
		ਜੇ (ਮਾਪਾ) {						\
			ਖੱਬਾ = ਮਾਪਾ;					\
			ਕਰੋ {						\
				RB_AUGMENT(ਖੱਬਾ);			\
			} ਜਦੋਂ ((ਖੱਬਾ = RB_ਮਾਪਾ(ਖੱਬਾ, ਖੇਤਰ)));	\
		}							\
		ਜਾਓ color;						\
	}								\
	ਮਾਪਾ = RB_ਮਾਪਾ(elm, ਖੇਤਰ);					\
	color = RB_COLOR(elm, ਖੇਤਰ);					\
	ਜੇ (ਬੱਚਾ)							\
		RB_ਮਾਪਾ(ਬੱਚਾ, ਖੇਤਰ) = ਮਾਪਾ;			\
	ਜੇ (ਮਾਪਾ) {							\
		ਜੇ (RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) == elm)			\
			RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) = ਬੱਚਾ;			\
		ਨਹੀਂਤਾਂ							\
			RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ) = ਬੱਚਾ;		\
		RB_AUGMENT(ਮਾਪਾ);					\
	} ਨਹੀਂਤਾਂ								\
		RB_ਜੜ੍ਹ(ਸਿਰ) = ਬੱਚਾ;					\
color:									\
	ਜੇ (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(ਸਿਰ, ਮਾਪਾ, ਬੱਚਾ);		\
	ਵਾਪਸ (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ਬਣਤਰ type *							\
name##_RB_INSERT(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	ਬਣਤਰ type *tmp;						\
	ਬਣਤਰ type *ਮਾਪਾ = ਨਿਰਾ;					\
	ਪੂਰਨ comp = 0;							\
	tmp = RB_ਜੜ੍ਹ(ਸਿਰ);						\
	ਜਦੋਂ (tmp) {							\
		ਮਾਪਾ = tmp;						\
		comp = (cmp)(elm, ਮਾਪਾ);				\
		ਜੇ (comp < 0)						\
			tmp = RB_ਖੱਬਾ(tmp, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ ਜੇ (comp > 0)					\
			tmp = RB_ਸੱਜਾ(tmp, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ							\
			ਵਾਪਸ (tmp);					\
	}								\
	RB_ਸੈੱਟ(elm, ਮਾਪਾ, ਖੇਤਰ);					\
	ਜੇ (ਮਾਪਾ != ਨਿਰਾ) {						\
		ਜੇ (comp < 0)						\
			RB_ਖੱਬਾ(ਮਾਪਾ, ਖੇਤਰ) = elm;			\
		ਨਹੀਂਤਾਂ							\
			RB_ਸੱਜਾ(ਮਾਪਾ, ਖੇਤਰ) = elm;			\
		RB_AUGMENT(ਮਾਪਾ);					\
	} ਨਹੀਂਤਾਂ								\
		RB_ਜੜ੍ਹ(ਸਿਰ) = elm;					\
	name##_RB_INSERT_COLOR(ਸਿਰ, elm);				\
	ਵਾਪਸ (ਨਿਰਾ);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ਬਣਤਰ type *							\
name##_RB_FIND(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	ਬਣਤਰ type *tmp = RB_ਜੜ੍ਹ(ਸਿਰ);				\
	ਪੂਰਨ comp;							\
	ਜਦੋਂ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ਜੇ (comp < 0)						\
			tmp = RB_ਖੱਬਾ(tmp, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ ਜੇ (comp > 0)					\
			tmp = RB_ਸੱਜਾ(tmp, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ							\
			ਵਾਪਸ (tmp);					\
	}								\
	ਵਾਪਸ (ਨਿਰਾ);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ਬਣਤਰ type *							\
name##_RB_NFIND(ਬਣਤਰ name *ਸਿਰ, ਬਣਤਰ type *elm)			\
{									\
	ਬਣਤਰ type *tmp = RB_ਜੜ੍ਹ(ਸਿਰ);				\
	ਬਣਤਰ type *res = ਨਿਰਾ;					\
	ਪੂਰਨ comp;							\
	ਜਦੋਂ (tmp) {							\
		comp = cmp(elm, tmp);					\
		ਜੇ (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ਖੱਬਾ(tmp, ਖੇਤਰ);			\
		}							\
		ਨਹੀਂਤਾਂ ਜੇ (comp > 0)					\
			tmp = RB_ਸੱਜਾ(tmp, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ							\
			ਵਾਪਸ (tmp);					\
	}								\
	ਵਾਪਸ (res);							\
}									\
									\
/* ARGSUSED */								\
attr ਬਣਤਰ type *							\
name##_RB_NEXT(ਬਣਤਰ type *elm)					\
{									\
	ਜੇ (RB_ਸੱਜਾ(elm, ਖੇਤਰ)) {					\
		elm = RB_ਸੱਜਾ(elm, ਖੇਤਰ);				\
		ਜਦੋਂ (RB_ਖੱਬਾ(elm, ਖੇਤਰ))				\
			elm = RB_ਖੱਬਾ(elm, ਖੇਤਰ);			\
	} ਨਹੀਂਤਾਂ {							\
		ਜੇ (RB_ਮਾਪਾ(elm, ਖੇਤਰ) &&				\
		    (elm == RB_ਖੱਬਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ)))	\
			elm = RB_ਮਾਪਾ(elm, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ {							\
			ਜਦੋਂ (RB_ਮਾਪਾ(elm, ਖੇਤਰ) &&			\
			    (elm == RB_ਸੱਜਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ)))\
				elm = RB_ਮਾਪਾ(elm, ਖੇਤਰ);		\
			elm = RB_ਮਾਪਾ(elm, ਖੇਤਰ);			\
		}							\
	}								\
	ਵਾਪਸ (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ਬਣਤਰ type *							\
name##_RB_PREV(ਬਣਤਰ type *elm)					\
{									\
	ਜੇ (RB_ਖੱਬਾ(elm, ਖੇਤਰ)) {					\
		elm = RB_ਖੱਬਾ(elm, ਖੇਤਰ);				\
		ਜਦੋਂ (RB_ਸੱਜਾ(elm, ਖੇਤਰ))				\
			elm = RB_ਸੱਜਾ(elm, ਖੇਤਰ);			\
	} ਨਹੀਂਤਾਂ {							\
		ਜੇ (RB_ਮਾਪਾ(elm, ਖੇਤਰ) &&				\
		    (elm == RB_ਸੱਜਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ)))	\
			elm = RB_ਮਾਪਾ(elm, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ {							\
			ਜਦੋਂ (RB_ਮਾਪਾ(elm, ਖੇਤਰ) &&			\
			    (elm == RB_ਖੱਬਾ(RB_ਮਾਪਾ(elm, ਖੇਤਰ), ਖੇਤਰ)))\
				elm = RB_ਮਾਪਾ(elm, ਖੇਤਰ);		\
			elm = RB_ਮਾਪਾ(elm, ਖੇਤਰ);			\
		}							\
	}								\
	ਵਾਪਸ (elm);							\
}									\
									\
attr ਬਣਤਰ type *							\
name##_RB_MINMAX(ਬਣਤਰ name *ਸਿਰ, ਪੂਰਨ val)				\
{									\
	ਬਣਤਰ type *tmp = RB_ਜੜ੍ਹ(ਸਿਰ);				\
	ਬਣਤਰ type *ਮਾਪਾ = ਨਿਰਾ;					\
	ਜਦੋਂ (tmp) {							\
		ਮਾਪਾ = tmp;						\
		ਜੇ (val < 0)						\
			tmp = RB_ਖੱਬਾ(tmp, ਖੇਤਰ);			\
		ਨਹੀਂਤਾਂ							\
			tmp = RB_ਸੱਜਾ(tmp, ਖੇਤਰ);			\
	}								\
	ਵਾਪਸ (ਮਾਪਾ);						\
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_NEGINF	-1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_INF	1

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਪਾਓ(name, x, y)	name##_RB_INSERT(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਲੱਭੋ(name, x, y)	name##_RB_FIND(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_ਅਗਲਾ(name, x, y)	name##_RB_NEXT(y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_PREV(name, x, y)	name##_RB_PREV(y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_FOREACH(x, name, ਸਿਰ)					\
	ਲਈ ((x) = RB_MIN(name, ਸਿਰ);					\
	     (x) != ਨਿਰਾ;						\
	     (x) = name##_RB_NEXT(x))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_FOREACH_ਸੁਰੱਖਿਅਤ(x, name, ਸਿਰ, y)				\
	ਲਈ ((x) = RB_MIN(name, ਸਿਰ);					\
	    ((x) != ਨਿਰਾ) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_FOREACH_ਉਲਟ(x, name, ਸਿਰ)				\
	ਲਈ ((x) = RB_MAX(name, ਸਿਰ);					\
	     (x) != ਨਿਰਾ;						\
	     (x) = name##_RB_PREV(x))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RB_FOREACH_ਉਲਟ_ਸੁਰੱਖਿਅਤ(x, name, ਸਿਰ, y)			\
	ਲਈ ((x) = RB_MAX(name, ਸਿਰ);					\
	    ((x) != ਨਿਰਾ) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#ਜੇ_ਅੰਤ	/* _SYS_TREE_H_ */
