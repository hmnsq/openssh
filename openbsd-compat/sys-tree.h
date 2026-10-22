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

#அந்தர்பாவ "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_மரம்_H
#define	SYS_மரம்_H

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

#define SPLAY_HEAD(name, type)						\
கட்டமைப்பு name {								\
	கட்டமைப்பு type *sph_வேர்; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(வேர்)						\
	{ வெற்று }

#define SPLAY_INIT(வேர்) செய் {						\
	(வேர்)->sph_வேர் = வெற்று;					\
} போது (0)

#define SPLAY_ENTRY(type)						\
கட்டமைப்பு {								\
	கட்டமைப்பு type *spe_இடது; /* left element */			\
	கட்டமைப்பு type *spe_வலது; /* right element */			\
}

#define SPLAY_இடது(elm, field)		(elm)->field.spe_இடது
#define SPLAY_வலது(elm, field)		(elm)->field.spe_வலது
#define SPLAY_வேர்(head)		(head)->sph_வேர்
#define SPLAY_EMPTY(head)		(SPLAY_வேர்(head) == வெற்று)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_வலது(head, tmp, field) செய் {			\
	SPLAY_இடது((head)->sph_வேர், field) = SPLAY_வலது(tmp, field);	\
	SPLAY_வலது(tmp, field) = (head)->sph_வேர்;			\
	(head)->sph_வேர் = tmp;						\
} போது (0)
	
#define SPLAY_ROTATE_இடது(head, tmp, field) செய் {			\
	SPLAY_வலது((head)->sph_வேர், field) = SPLAY_இடது(tmp, field);	\
	SPLAY_இடது(tmp, field) = (head)->sph_வேர்;			\
	(head)->sph_வேர் = tmp;						\
} போது (0)

#define SPLAY_LINKLEFT(head, tmp, field) செய் {				\
	SPLAY_இடது(tmp, field) = (head)->sph_வேர்;			\
	tmp = (head)->sph_வேர்;						\
	(head)->sph_வேர் = SPLAY_இடது((head)->sph_வேர், field);		\
} போது (0)

#define SPLAY_LINKRIGHT(head, tmp, field) செய் {				\
	SPLAY_வலது(tmp, field) = (head)->sph_வேர்;			\
	tmp = (head)->sph_வேர்;						\
	(head)->sph_வேர் = SPLAY_வலது((head)->sph_வேர், field);	\
} போது (0)

#define SPLAY_ASSEMBLE(head, முனை, இடது, வலது, field) செய் {		\
	SPLAY_வலது(இடது, field) = SPLAY_இடது((head)->sph_வேர், field);	\
	SPLAY_இடது(வலது, field) = SPLAY_வலது((head)->sph_வேர், field);\
	SPLAY_இடது((head)->sph_வேர், field) = SPLAY_வலது(முனை, field);	\
	SPLAY_வலது((head)->sph_வேர், field) = SPLAY_இடது(முனை, field);	\
} போது (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
வெறுமை name##_SPLAY(கட்டமைப்பு name *, கட்டமைப்பு type *);			\
வெறுமை name##_SPLAY_MINMAX(கட்டமைப்பு name *, முழு);				\
கட்டமைப்பு type *name##_SPLAY_INSERT(கட்டமைப்பு name *, கட்டமைப்பு type *);		\
கட்டமைப்பு type *name##_SPLAY_REMOVE(கட்டமைப்பு name *, கட்டமைப்பு type *);		\
									\
/* Finds the node with the same key as elm */				\
நிலையான __inline கட்டமைப்பு type *						\
name##_SPLAY_FIND(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	எனில் (SPLAY_EMPTY(head))						\
		திரும்பு(வெற்று);						\
	name##_SPLAY(head, elm);					\
	எனில் ((cmp)(elm, (head)->sph_வேர்) == 0)				\
		திரும்பு (head->sph_வேர்);				\
	திரும்பு (வெற்று);							\
}									\
									\
நிலையான __inline கட்டமைப்பு type *						\
name##_SPLAY_NEXT(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	எனில் (SPLAY_வலது(elm, field) != வெற்று) {				\
		elm = SPLAY_வலது(elm, field);				\
		போது (SPLAY_இடது(elm, field) != வெற்று) {		\
			elm = SPLAY_இடது(elm, field);			\
		}							\
	} இல்லையெனில்								\
		elm = வெற்று;						\
	திரும்பு (elm);							\
}									\
									\
நிலையான __inline கட்டமைப்பு type *						\
name##_SPLAY_MIN_MAX(கட்டமைப்பு name *head, முழு val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        திரும்பு (SPLAY_வேர்(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
கட்டமைப்பு type *								\
name##_SPLAY_INSERT(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)		\
{									\
    எனில் (SPLAY_EMPTY(head)) {						\
	    SPLAY_இடது(elm, field) = SPLAY_வலது(elm, field) = வெற்று;	\
    } இல்லையெனில் {								\
	    முழு __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_வேர்);			\
	    எனில்(__comp < 0) {						\
		    SPLAY_இடது(elm, field) = SPLAY_இடது((head)->sph_வேர், field);\
		    SPLAY_வலது(elm, field) = (head)->sph_வேர்;		\
		    SPLAY_இடது((head)->sph_வேர், field) = வெற்று;		\
	    } இல்லையெனில் எனில் (__comp > 0) {					\
		    SPLAY_வலது(elm, field) = SPLAY_வலது((head)->sph_வேர், field);\
		    SPLAY_இடது(elm, field) = (head)->sph_வேர்;		\
		    SPLAY_வலது((head)->sph_வேர், field) = வெற்று;	\
	    } இல்லையெனில்							\
		    திரும்பு ((head)->sph_வேர்);				\
    }									\
    (head)->sph_வேர் = (elm);						\
    திரும்பு (வெற்று);							\
}									\
									\
கட்டமைப்பு type *								\
name##_SPLAY_REMOVE(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)		\
{									\
	கட்டமைப்பு type *__tmp;						\
	எனில் (SPLAY_EMPTY(head))						\
		திரும்பு (வெற்று);						\
	name##_SPLAY(head, elm);					\
	எனில் ((cmp)(elm, (head)->sph_வேர்) == 0) {			\
		எனில் (SPLAY_இடது((head)->sph_வேர், field) == வெற்று) {	\
			(head)->sph_வேர் = SPLAY_வலது((head)->sph_வேர், field);\
		} இல்லையெனில் {						\
			__tmp = SPLAY_வலது((head)->sph_வேர், field);	\
			(head)->sph_வேர் = SPLAY_இடது((head)->sph_வேர், field);\
			name##_SPLAY(head, elm);			\
			SPLAY_வலது((head)->sph_வேர், field) = __tmp;	\
		}							\
		திரும்பு (elm);						\
	}								\
	திரும்பு (வெற்று);							\
}									\
									\
வெறுமை									\
name##_SPLAY(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	கட்டமைப்பு type __node, *__left, *__right, *__tmp;			\
	முழு __comp;							\
\
	SPLAY_இடது(&__node, field) = SPLAY_வலது(&__node, field) = வெற்று;\
	__left = __right = &__node;					\
\
	போது ((__comp = (cmp)(elm, (head)->sph_வேர்))) {		\
		எனில் (__comp < 0) {					\
			__tmp = SPLAY_இடது((head)->sph_வேர், field);	\
			எனில் (__tmp == வெற்று)				\
				நிறுத்து;					\
			எனில் ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_வலது(head, __tmp, field);	\
				எனில் (SPLAY_இடது((head)->sph_வேர், field) == வெற்று)\
					நிறுத்து;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} இல்லையெனில் எனில் (__comp > 0) {				\
			__tmp = SPLAY_வலது((head)->sph_வேர், field);	\
			எனில் (__tmp == வெற்று)				\
				நிறுத்து;					\
			எனில் ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_இடது(head, __tmp, field);	\
				எனில் (SPLAY_வலது((head)->sph_வேர், field) == வெற்று)\
					நிறுத்து;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}									\
									\
/* Splay with either the minimum or the maximum element			\
 * Used to find minimum or maximum element in tree.			\
 */									\
வெறுமை name##_SPLAY_MINMAX(கட்டமைப்பு name *head, முழு __comp) \
{									\
	கட்டமைப்பு type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_இடது(&__node, field) = SPLAY_வலது(&__node, field) = வெற்று;\
	__left = __right = &__node;					\
\
	போது (1) {							\
		எனில் (__comp < 0) {					\
			__tmp = SPLAY_இடது((head)->sph_வேர், field);	\
			எனில் (__tmp == வெற்று)				\
				நிறுத்து;					\
			எனில் (__comp < 0){				\
				SPLAY_ROTATE_வலது(head, __tmp, field);	\
				எனில் (SPLAY_இடது((head)->sph_வேர், field) == வெற்று)\
					நிறுத்து;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} இல்லையெனில் எனில் (__comp > 0) {				\
			__tmp = SPLAY_வலது((head)->sph_வேர், field);	\
			எனில் (__tmp == வெற்று)				\
				நிறுத்து;					\
			எனில் (__comp > 0) {				\
				SPLAY_ROTATE_இடது(head, __tmp, field);	\
				எனில் (SPLAY_வலது((head)->sph_வேர், field) == வெற்று)\
					நிறுத்து;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_செருகு(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? வெற்று	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? வெற்று	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	க்கு ((x) = SPLAY_MIN(name, head);				\
	     (x) != வெற்று;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
கட்டமைப்பு name {								\
	கட்டமைப்பு type *rbh_வேர்; /* root of the tree */			\
}

#define RB_INITIALIZER(வேர்)						\
	{ வெற்று }

#define RB_INIT(வேர்) செய் {						\
	(வேர்)->rbh_வேர் = வெற்று;					\
} போது (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
கட்டமைப்பு {								\
	கட்டமைப்பு type *rbe_இடது;		/* left element */		\
	கட்டமைப்பு type *rbe_வலது;		/* right element */		\
	கட்டமைப்பு type *rbe_parent;	/* parent element */		\
	முழு rbe_color;			/* node color */		\
}

#define RB_இடது(elm, field)		(elm)->field.rbe_இடது
#define RB_வலது(elm, field)		(elm)->field.rbe_வலது
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_வேர்(head)			(head)->rbh_வேர்
#define RB_EMPTY(head)			(RB_வேர்(head) == வெற்று)

#define RB_SET(elm, parent, field) செய் {					\
	RB_PARENT(elm, field) = parent;					\
	RB_இடது(elm, field) = RB_வலது(elm, field) = வெற்று;		\
	RB_COLOR(elm, field) = RB_RED;					\
} போது (0)

#define RB_SET_BLACKRED(black, red, field) செய் {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} போது (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	செய் {} போது (0)
#endif

#define RB_ROTATE_இடது(head, elm, tmp, field) செய் {			\
	(tmp) = RB_வலது(elm, field);					\
	எனில் ((RB_வலது(elm, field) = RB_இடது(tmp, field))) {		\
		RB_PARENT(RB_இடது(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	எனில் ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		எனில் ((elm) == RB_இடது(RB_PARENT(elm, field), field))	\
			RB_இடது(RB_PARENT(elm, field), field) = (tmp);	\
		இல்லையெனில்							\
			RB_வலது(RB_PARENT(elm, field), field) = (tmp);	\
	} இல்லையெனில்								\
		(head)->rbh_வேர் = (tmp);				\
	RB_இடது(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	எனில் ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} போது (0)

#define RB_ROTATE_வலது(head, elm, tmp, field) செய் {			\
	(tmp) = RB_இடது(elm, field);					\
	எனில் ((RB_இடது(elm, field) = RB_வலது(tmp, field))) {		\
		RB_PARENT(RB_வலது(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	எனில் ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		எனில் ((elm) == RB_இடது(RB_PARENT(elm, field), field))	\
			RB_இடது(RB_PARENT(elm, field), field) = (tmp);	\
		இல்லையெனில்							\
			RB_வலது(RB_PARENT(elm, field), field) = (tmp);	\
	} இல்லையெனில்								\
		(head)->rbh_வேர் = (tmp);				\
	RB_வலது(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	எனில் ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} போது (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) நிலையான)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr வெறுமை name##_RB_INSERT_COLOR(கட்டமைப்பு name *, கட்டமைப்பு type *);		\
attr வெறுமை name##_RB_REMOVE_COLOR(கட்டமைப்பு name *, கட்டமைப்பு type *, கட்டமைப்பு type *);\
attr கட்டமைப்பு type *name##_RB_REMOVE(கட்டமைப்பு name *, கட்டமைப்பு type *);	\
attr கட்டமைப்பு type *name##_RB_INSERT(கட்டமைப்பு name *, கட்டமைப்பு type *);	\
attr கட்டமைப்பு type *name##_RB_FIND(கட்டமைப்பு name *, கட்டமைப்பு type *);		\
attr கட்டமைப்பு type *name##_RB_NFIND(கட்டமைப்பு name *, கட்டமைப்பு type *);	\
attr கட்டமைப்பு type *name##_RB_NEXT(கட்டமைப்பு type *);			\
attr கட்டமைப்பு type *name##_RB_PREV(கட்டமைப்பு type *);			\
attr கட்டமைப்பு type *name##_RB_MINMAX(கட்டமைப்பு name *, முழு);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) நிலையான)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr வெறுமை								\
name##_RB_INSERT_COLOR(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)		\
{									\
	கட்டமைப்பு type *parent, *gparent, *tmp;				\
	போது ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		எனில் (parent == RB_இடது(gparent, field)) {		\
			tmp = RB_வலது(gparent, field);			\
			எனில் (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				தொடர்;				\
			}						\
			எனில் (RB_வலது(parent, field) == elm) {		\
				RB_ROTATE_இடது(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_வலது(head, gparent, tmp, field);	\
		} இல்லையெனில் {						\
			tmp = RB_இடது(gparent, field);			\
			எனில் (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				தொடர்;				\
			}						\
			எனில் (RB_இடது(parent, field) == elm) {		\
				RB_ROTATE_வலது(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_இடது(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_வேர், field) = RB_BLACK;			\
}									\
									\
attr வெறுமை								\
name##_RB_REMOVE_COLOR(கட்டமைப்பு name *head, கட்டமைப்பு type *parent, கட்டமைப்பு type *elm) \
{									\
	கட்டமைப்பு type *tmp;						\
	போது ((elm == வெற்று || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_வேர்(head)) {					\
		எனில் (RB_இடது(parent, field) == elm) {			\
			tmp = RB_வலது(parent, field);			\
			எனில் (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_இடது(head, parent, tmp, field);\
				tmp = RB_வலது(parent, field);		\
			}						\
			எனில் ((RB_இடது(tmp, field) == வெற்று ||		\
			    RB_COLOR(RB_இடது(tmp, field), field) == RB_BLACK) &&\
			    (RB_வலது(tmp, field) == வெற்று ||		\
			    RB_COLOR(RB_வலது(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} இல்லையெனில் {					\
				எனில் (RB_வலது(tmp, field) == வெற்று ||	\
				    RB_COLOR(RB_வலது(tmp, field), field) == RB_BLACK) {\
					கட்டமைப்பு type *oleft;		\
					எனில் ((oleft = RB_இடது(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_வலது(head, tmp, oleft, field);\
					tmp = RB_வலது(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				எனில் (RB_வலது(tmp, field))		\
					RB_COLOR(RB_வலது(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_இடது(head, parent, tmp, field);\
				elm = RB_வேர்(head);			\
				நிறுத்து;					\
			}						\
		} இல்லையெனில் {						\
			tmp = RB_இடது(parent, field);			\
			எனில் (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_வலது(head, parent, tmp, field);\
				tmp = RB_இடது(parent, field);		\
			}						\
			எனில் ((RB_இடது(tmp, field) == வெற்று ||		\
			    RB_COLOR(RB_இடது(tmp, field), field) == RB_BLACK) &&\
			    (RB_வலது(tmp, field) == வெற்று ||		\
			    RB_COLOR(RB_வலது(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} இல்லையெனில் {					\
				எனில் (RB_இடது(tmp, field) == வெற்று ||	\
				    RB_COLOR(RB_இடது(tmp, field), field) == RB_BLACK) {\
					கட்டமைப்பு type *oright;		\
					எனில் ((oright = RB_வலது(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_இடது(head, tmp, oright, field);\
					tmp = RB_இடது(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				எனில் (RB_இடது(tmp, field))		\
					RB_COLOR(RB_இடது(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_வலது(head, parent, tmp, field);\
				elm = RB_வேர்(head);			\
				நிறுத்து;					\
			}						\
		}							\
	}								\
	எனில் (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr கட்டமைப்பு type *							\
name##_RB_REMOVE(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	கட்டமைப்பு type *child, *parent, *old = elm;			\
	முழு color;							\
	எனில் (RB_இடது(elm, field) == வெற்று)				\
		child = RB_வலது(elm, field);				\
	இல்லையெனில் எனில் (RB_வலது(elm, field) == வெற்று)				\
		child = RB_இடது(elm, field);				\
	இல்லையெனில் {								\
		கட்டமைப்பு type *இடது;					\
		elm = RB_வலது(elm, field);				\
		போது ((இடது = RB_இடது(elm, field)))			\
			elm = இடது;					\
		child = RB_வலது(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		எனில் (child)						\
			RB_PARENT(child, field) = parent;		\
		எனில் (parent) {						\
			எனில் (RB_இடது(parent, field) == elm)		\
				RB_இடது(parent, field) = child;		\
			இல்லையெனில்						\
				RB_வலது(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} இல்லையெனில்							\
			RB_வேர்(head) = child;				\
		எனில் (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		எனில் (RB_PARENT(old, field)) {				\
			எனில் (RB_இடது(RB_PARENT(old, field), field) == old)\
				RB_இடது(RB_PARENT(old, field), field) = elm;\
			இல்லையெனில்						\
				RB_வலது(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} இல்லையெனில்							\
			RB_வேர்(head) = elm;				\
		RB_PARENT(RB_இடது(old, field), field) = elm;		\
		எனில் (RB_வலது(old, field))				\
			RB_PARENT(RB_வலது(old, field), field) = elm;	\
		எனில் (parent) {						\
			இடது = parent;					\
			செய் {						\
				RB_AUGMENT(இடது);			\
			} போது ((இடது = RB_PARENT(இடது, field)));	\
		}							\
		செல் color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	எனில் (child)							\
		RB_PARENT(child, field) = parent;			\
	எனில் (parent) {							\
		எனில் (RB_இடது(parent, field) == elm)			\
			RB_இடது(parent, field) = child;			\
		இல்லையெனில்							\
			RB_வலது(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} இல்லையெனில்								\
		RB_வேர்(head) = child;					\
color:									\
	எனில் (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	திரும்பு (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr கட்டமைப்பு type *							\
name##_RB_INSERT(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	கட்டமைப்பு type *tmp;						\
	கட்டமைப்பு type *parent = வெற்று;					\
	முழு comp = 0;							\
	tmp = RB_வேர்(head);						\
	போது (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		எனில் (comp < 0)						\
			tmp = RB_இடது(tmp, field);			\
		இல்லையெனில் எனில் (comp > 0)					\
			tmp = RB_வலது(tmp, field);			\
		இல்லையெனில்							\
			திரும்பு (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	எனில் (parent != வெற்று) {						\
		எனில் (comp < 0)						\
			RB_இடது(parent, field) = elm;			\
		இல்லையெனில்							\
			RB_வலது(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} இல்லையெனில்								\
		RB_வேர்(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	திரும்பு (வெற்று);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr கட்டமைப்பு type *							\
name##_RB_FIND(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	கட்டமைப்பு type *tmp = RB_வேர்(head);				\
	முழு comp;							\
	போது (tmp) {							\
		comp = cmp(elm, tmp);					\
		எனில் (comp < 0)						\
			tmp = RB_இடது(tmp, field);			\
		இல்லையெனில் எனில் (comp > 0)					\
			tmp = RB_வலது(tmp, field);			\
		இல்லையெனில்							\
			திரும்பு (tmp);					\
	}								\
	திரும்பு (வெற்று);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr கட்டமைப்பு type *							\
name##_RB_NFIND(கட்டமைப்பு name *head, கட்டமைப்பு type *elm)			\
{									\
	கட்டமைப்பு type *tmp = RB_வேர்(head);				\
	கட்டமைப்பு type *res = வெற்று;					\
	முழு comp;							\
	போது (tmp) {							\
		comp = cmp(elm, tmp);					\
		எனில் (comp < 0) {						\
			res = tmp;					\
			tmp = RB_இடது(tmp, field);			\
		}							\
		இல்லையெனில் எனில் (comp > 0)					\
			tmp = RB_வலது(tmp, field);			\
		இல்லையெனில்							\
			திரும்பு (tmp);					\
	}								\
	திரும்பு (res);							\
}									\
									\
/* ARGSUSED */								\
attr கட்டமைப்பு type *							\
name##_RB_NEXT(கட்டமைப்பு type *elm)					\
{									\
	எனில் (RB_வலது(elm, field)) {					\
		elm = RB_வலது(elm, field);				\
		போது (RB_இடது(elm, field))				\
			elm = RB_இடது(elm, field);			\
	} இல்லையெனில் {							\
		எனில் (RB_PARENT(elm, field) &&				\
		    (elm == RB_இடது(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		இல்லையெனில் {							\
			போது (RB_PARENT(elm, field) &&			\
			    (elm == RB_வலது(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	திரும்பு (elm);							\
}									\
									\
/* ARGSUSED */								\
attr கட்டமைப்பு type *							\
name##_RB_PREV(கட்டமைப்பு type *elm)					\
{									\
	எனில் (RB_இடது(elm, field)) {					\
		elm = RB_இடது(elm, field);				\
		போது (RB_வலது(elm, field))				\
			elm = RB_வலது(elm, field);			\
	} இல்லையெனில் {							\
		எனில் (RB_PARENT(elm, field) &&				\
		    (elm == RB_வலது(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		இல்லையெனில் {							\
			போது (RB_PARENT(elm, field) &&			\
			    (elm == RB_இடது(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	திரும்பு (elm);							\
}									\
									\
attr கட்டமைப்பு type *							\
name##_RB_MINMAX(கட்டமைப்பு name *head, முழு val)				\
{									\
	கட்டமைப்பு type *tmp = RB_வேர்(head);				\
	கட்டமைப்பு type *parent = வெற்று;					\
	போது (tmp) {							\
		parent = tmp;						\
		எனில் (val < 0)						\
			tmp = RB_இடது(tmp, field);			\
		இல்லையெனில்							\
			tmp = RB_வலது(tmp, field);			\
	}								\
	திரும்பு (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_செருகு(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	க்கு ((x) = RB_MIN(name, head);					\
	     (x) != வெற்று;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	க்கு ((x) = RB_MIN(name, head);					\
	    ((x) != வெற்று) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	க்கு ((x) = RB_MAX(name, head);					\
	     (x) != வெற்று;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	க்கு ((x) = RB_MAX(name, head);					\
	    ((x) != வெற்று) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
