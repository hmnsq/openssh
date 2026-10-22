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

#അന്തര്ഭാവ "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_വൃക്ഷം_H
#define	SYS_വൃക്ഷം_H

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
ഘടന name {								\
	ഘടന type *sph_വേര്; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(വേര്)						\
	{ ശൂന്യ }

#define SPLAY_INIT(വേര്) ചെയ്യുക {						\
	(വേര്)->sph_വേര് = ശൂന്യ;					\
} ആകുമ്പോൾ (0)

#define SPLAY_ENTRY(type)						\
ഘടന {								\
	ഘടന type *spe_ഇടത്; /* left element */			\
	ഘടന type *spe_വലത്; /* right element */			\
}

#define SPLAY_ഇടത്(elm, field)		(elm)->field.spe_ഇടത്
#define SPLAY_വലത്(elm, field)		(elm)->field.spe_വലത്
#define SPLAY_വേര്(head)		(head)->sph_വേര്
#define SPLAY_EMPTY(head)		(SPLAY_വേര്(head) == ശൂന്യ)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_വലത്(head, tmp, field) ചെയ്യുക {			\
	SPLAY_ഇടത്((head)->sph_വേര്, field) = SPLAY_വലത്(tmp, field);	\
	SPLAY_വലത്(tmp, field) = (head)->sph_വേര്;			\
	(head)->sph_വേര് = tmp;						\
} ആകുമ്പോൾ (0)
	
#define SPLAY_ROTATE_ഇടത്(head, tmp, field) ചെയ്യുക {			\
	SPLAY_വലത്((head)->sph_വേര്, field) = SPLAY_ഇടത്(tmp, field);	\
	SPLAY_ഇടത്(tmp, field) = (head)->sph_വേര്;			\
	(head)->sph_വേര് = tmp;						\
} ആകുമ്പോൾ (0)

#define SPLAY_LINKLEFT(head, tmp, field) ചെയ്യുക {				\
	SPLAY_ഇടത്(tmp, field) = (head)->sph_വേര്;			\
	tmp = (head)->sph_വേര്;						\
	(head)->sph_വേര് = SPLAY_ഇടത്((head)->sph_വേര്, field);		\
} ആകുമ്പോൾ (0)

#define SPLAY_LINKRIGHT(head, tmp, field) ചെയ്യുക {				\
	SPLAY_വലത്(tmp, field) = (head)->sph_വേര്;			\
	tmp = (head)->sph_വേര്;						\
	(head)->sph_വേര് = SPLAY_വലത്((head)->sph_വേര്, field);	\
} ആകുമ്പോൾ (0)

#define SPLAY_ASSEMBLE(head, കണ്ണി, ഇടത്, വലത്, field) ചെയ്യുക {		\
	SPLAY_വലത്(ഇടത്, field) = SPLAY_ഇടത്((head)->sph_വേര്, field);	\
	SPLAY_ഇടത്(വലത്, field) = SPLAY_വലത്((head)->sph_വേര്, field);\
	SPLAY_ഇടത്((head)->sph_വേര്, field) = SPLAY_വലത്(കണ്ണി, field);	\
	SPLAY_വലത്((head)->sph_വേര്, field) = SPLAY_ഇടത്(കണ്ണി, field);	\
} ആകുമ്പോൾ (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
ശൂന്യം name##_SPLAY(ഘടന name *, ഘടന type *);			\
ശൂന്യം name##_SPLAY_MINMAX(ഘടന name *, പൂർണ്ണസംഖ്യ);				\
ഘടന type *name##_SPLAY_INSERT(ഘടന name *, ഘടന type *);		\
ഘടന type *name##_SPLAY_REMOVE(ഘടന name *, ഘടന type *);		\
									\
/* Finds the node with the same key as elm */				\
സ്ഥിതം __inline ഘടന type *						\
name##_SPLAY_FIND(ഘടന name *head, ഘടന type *elm)			\
{									\
	എങ്കിൽ (SPLAY_EMPTY(head))						\
		തിരികെ(ശൂന്യ);						\
	name##_SPLAY(head, elm);					\
	എങ്കിൽ ((cmp)(elm, (head)->sph_വേര്) == 0)				\
		തിരികെ (head->sph_വേര്);				\
	തിരികെ (ശൂന്യ);							\
}									\
									\
സ്ഥിതം __inline ഘടന type *						\
name##_SPLAY_NEXT(ഘടന name *head, ഘടന type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	എങ്കിൽ (SPLAY_വലത്(elm, field) != ശൂന്യ) {				\
		elm = SPLAY_വലത്(elm, field);				\
		ആകുമ്പോൾ (SPLAY_ഇടത്(elm, field) != ശൂന്യ) {		\
			elm = SPLAY_ഇടത്(elm, field);			\
		}							\
	} അല്ലെങ്കിൽ								\
		elm = ശൂന്യ;						\
	തിരികെ (elm);							\
}									\
									\
സ്ഥിതം __inline ഘടന type *						\
name##_SPLAY_MIN_MAX(ഘടന name *head, പൂർണ്ണസംഖ്യ val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        തിരികെ (SPLAY_വേര്(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
ഘടന type *								\
name##_SPLAY_INSERT(ഘടന name *head, ഘടന type *elm)		\
{									\
    എങ്കിൽ (SPLAY_EMPTY(head)) {						\
	    SPLAY_ഇടത്(elm, field) = SPLAY_വലത്(elm, field) = ശൂന്യ;	\
    } അല്ലെങ്കിൽ {								\
	    പൂർണ്ണസംഖ്യ __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_വേര്);			\
	    എങ്കിൽ(__comp < 0) {						\
		    SPLAY_ഇടത്(elm, field) = SPLAY_ഇടത്((head)->sph_വേര്, field);\
		    SPLAY_വലത്(elm, field) = (head)->sph_വേര്;		\
		    SPLAY_ഇടത്((head)->sph_വേര്, field) = ശൂന്യ;		\
	    } അല്ലെങ്കിൽ എങ്കിൽ (__comp > 0) {					\
		    SPLAY_വലത്(elm, field) = SPLAY_വലത്((head)->sph_വേര്, field);\
		    SPLAY_ഇടത്(elm, field) = (head)->sph_വേര്;		\
		    SPLAY_വലത്((head)->sph_വേര്, field) = ശൂന്യ;	\
	    } അല്ലെങ്കിൽ							\
		    തിരികെ ((head)->sph_വേര്);				\
    }									\
    (head)->sph_വേര് = (elm);						\
    തിരികെ (ശൂന്യ);							\
}									\
									\
ഘടന type *								\
name##_SPLAY_REMOVE(ഘടന name *head, ഘടന type *elm)		\
{									\
	ഘടന type *__tmp;						\
	എങ്കിൽ (SPLAY_EMPTY(head))						\
		തിരികെ (ശൂന്യ);						\
	name##_SPLAY(head, elm);					\
	എങ്കിൽ ((cmp)(elm, (head)->sph_വേര്) == 0) {			\
		എങ്കിൽ (SPLAY_ഇടത്((head)->sph_വേര്, field) == ശൂന്യ) {	\
			(head)->sph_വേര് = SPLAY_വലത്((head)->sph_വേര്, field);\
		} അല്ലെങ്കിൽ {						\
			__tmp = SPLAY_വലത്((head)->sph_വേര്, field);	\
			(head)->sph_വേര് = SPLAY_ഇടത്((head)->sph_വേര്, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_വലത്((head)->sph_വേര്, field) = __tmp;	\
		}							\
		തിരികെ (elm);						\
	}								\
	തിരികെ (ശൂന്യ);							\
}									\
									\
ശൂന്യം									\
name##_SPLAY(ഘടന name *head, ഘടന type *elm)			\
{									\
	ഘടന type __node, *__left, *__right, *__tmp;			\
	പൂർണ്ണസംഖ്യ __comp;							\
\
	SPLAY_ഇടത്(&__node, field) = SPLAY_വലത്(&__node, field) = ശൂന്യ;\
	__left = __right = &__node;					\
\
	ആകുമ്പോൾ ((__comp = (cmp)(elm, (head)->sph_വേര്))) {		\
		എങ്കിൽ (__comp < 0) {					\
			__tmp = SPLAY_ഇടത്((head)->sph_വേര്, field);	\
			എങ്കിൽ (__tmp == ശൂന്യ)				\
				നിർത്തുക;					\
			എങ്കിൽ ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_വലത്(head, __tmp, field);	\
				എങ്കിൽ (SPLAY_ഇടത്((head)->sph_വേര്, field) == ശൂന്യ)\
					നിർത്തുക;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} അല്ലെങ്കിൽ എങ്കിൽ (__comp > 0) {				\
			__tmp = SPLAY_വലത്((head)->sph_വേര്, field);	\
			എങ്കിൽ (__tmp == ശൂന്യ)				\
				നിർത്തുക;					\
			എങ്കിൽ ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_ഇടത്(head, __tmp, field);	\
				എങ്കിൽ (SPLAY_വലത്((head)->sph_വേര്, field) == ശൂന്യ)\
					നിർത്തുക;				\
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
ശൂന്യം name##_SPLAY_MINMAX(ഘടന name *head, പൂർണ്ണസംഖ്യ __comp) \
{									\
	ഘടന type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_ഇടത്(&__node, field) = SPLAY_വലത്(&__node, field) = ശൂന്യ;\
	__left = __right = &__node;					\
\
	ആകുമ്പോൾ (1) {							\
		എങ്കിൽ (__comp < 0) {					\
			__tmp = SPLAY_ഇടത്((head)->sph_വേര്, field);	\
			എങ്കിൽ (__tmp == ശൂന്യ)				\
				നിർത്തുക;					\
			എങ്കിൽ (__comp < 0){				\
				SPLAY_ROTATE_വലത്(head, __tmp, field);	\
				എങ്കിൽ (SPLAY_ഇടത്((head)->sph_വേര്, field) == ശൂന്യ)\
					നിർത്തുക;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} അല്ലെങ്കിൽ എങ്കിൽ (__comp > 0) {				\
			__tmp = SPLAY_വലത്((head)->sph_വേര്, field);	\
			എങ്കിൽ (__tmp == ശൂന്യ)				\
				നിർത്തുക;					\
			എങ്കിൽ (__comp > 0) {				\
				SPLAY_ROTATE_ഇടത്(head, __tmp, field);	\
				എങ്കിൽ (SPLAY_വലത്((head)->sph_വേര്, field) == ശൂന്യ)\
					നിർത്തുക;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_തിരുകുക(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? ശൂന്യ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? ശൂന്യ	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	വേണ്ടി ((x) = SPLAY_MIN(name, head);				\
	     (x) != ശൂന്യ;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
ഘടന name {								\
	ഘടന type *rbh_വേര്; /* root of the tree */			\
}

#define RB_INITIALIZER(വേര്)						\
	{ ശൂന്യ }

#define RB_INIT(വേര്) ചെയ്യുക {						\
	(വേര്)->rbh_വേര് = ശൂന്യ;					\
} ആകുമ്പോൾ (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
ഘടന {								\
	ഘടന type *rbe_ഇടത്;		/* left element */		\
	ഘടന type *rbe_വലത്;		/* right element */		\
	ഘടന type *rbe_parent;	/* parent element */		\
	പൂർണ്ണസംഖ്യ rbe_color;			/* node color */		\
}

#define RB_ഇടത്(elm, field)		(elm)->field.rbe_ഇടത്
#define RB_വലത്(elm, field)		(elm)->field.rbe_വലത്
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_വേര്(head)			(head)->rbh_വേര്
#define RB_EMPTY(head)			(RB_വേര്(head) == ശൂന്യ)

#define RB_SET(elm, parent, field) ചെയ്യുക {					\
	RB_PARENT(elm, field) = parent;					\
	RB_ഇടത്(elm, field) = RB_വലത്(elm, field) = ശൂന്യ;		\
	RB_COLOR(elm, field) = RB_RED;					\
} ആകുമ്പോൾ (0)

#define RB_SET_BLACKRED(black, red, field) ചെയ്യുക {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} ആകുമ്പോൾ (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	ചെയ്യുക {} ആകുമ്പോൾ (0)
#endif

#define RB_ROTATE_ഇടത്(head, elm, tmp, field) ചെയ്യുക {			\
	(tmp) = RB_വലത്(elm, field);					\
	എങ്കിൽ ((RB_വലത്(elm, field) = RB_ഇടത്(tmp, field))) {		\
		RB_PARENT(RB_ഇടത്(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	എങ്കിൽ ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		എങ്കിൽ ((elm) == RB_ഇടത്(RB_PARENT(elm, field), field))	\
			RB_ഇടത്(RB_PARENT(elm, field), field) = (tmp);	\
		അല്ലെങ്കിൽ							\
			RB_വലത്(RB_PARENT(elm, field), field) = (tmp);	\
	} അല്ലെങ്കിൽ								\
		(head)->rbh_വേര് = (tmp);				\
	RB_ഇടത്(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	എങ്കിൽ ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} ആകുമ്പോൾ (0)

#define RB_ROTATE_വലത്(head, elm, tmp, field) ചെയ്യുക {			\
	(tmp) = RB_ഇടത്(elm, field);					\
	എങ്കിൽ ((RB_ഇടത്(elm, field) = RB_വലത്(tmp, field))) {		\
		RB_PARENT(RB_വലത്(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	എങ്കിൽ ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		എങ്കിൽ ((elm) == RB_ഇടത്(RB_PARENT(elm, field), field))	\
			RB_ഇടത്(RB_PARENT(elm, field), field) = (tmp);	\
		അല്ലെങ്കിൽ							\
			RB_വലത്(RB_PARENT(elm, field), field) = (tmp);	\
	} അല്ലെങ്കിൽ								\
		(head)->rbh_വേര് = (tmp);				\
	RB_വലത്(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	എങ്കിൽ ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} ആകുമ്പോൾ (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) സ്ഥിതം)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr ശൂന്യം name##_RB_INSERT_COLOR(ഘടന name *, ഘടന type *);		\
attr ശൂന്യം name##_RB_REMOVE_COLOR(ഘടന name *, ഘടന type *, ഘടന type *);\
attr ഘടന type *name##_RB_REMOVE(ഘടന name *, ഘടന type *);	\
attr ഘടന type *name##_RB_INSERT(ഘടന name *, ഘടന type *);	\
attr ഘടന type *name##_RB_FIND(ഘടന name *, ഘടന type *);		\
attr ഘടന type *name##_RB_NFIND(ഘടന name *, ഘടന type *);	\
attr ഘടന type *name##_RB_NEXT(ഘടന type *);			\
attr ഘടന type *name##_RB_PREV(ഘടന type *);			\
attr ഘടന type *name##_RB_MINMAX(ഘടന name *, പൂർണ്ണസംഖ്യ);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) സ്ഥിതം)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr ശൂന്യം								\
name##_RB_INSERT_COLOR(ഘടന name *head, ഘടന type *elm)		\
{									\
	ഘടന type *parent, *gparent, *tmp;				\
	ആകുമ്പോൾ ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		എങ്കിൽ (parent == RB_ഇടത്(gparent, field)) {		\
			tmp = RB_വലത്(gparent, field);			\
			എങ്കിൽ (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				തുടരുക;				\
			}						\
			എങ്കിൽ (RB_വലത്(parent, field) == elm) {		\
				RB_ROTATE_ഇടത്(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_വലത്(head, gparent, tmp, field);	\
		} അല്ലെങ്കിൽ {						\
			tmp = RB_ഇടത്(gparent, field);			\
			എങ്കിൽ (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				തുടരുക;				\
			}						\
			എങ്കിൽ (RB_ഇടത്(parent, field) == elm) {		\
				RB_ROTATE_വലത്(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_ഇടത്(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_വേര്, field) = RB_BLACK;			\
}									\
									\
attr ശൂന്യം								\
name##_RB_REMOVE_COLOR(ഘടന name *head, ഘടന type *parent, ഘടന type *elm) \
{									\
	ഘടന type *tmp;						\
	ആകുമ്പോൾ ((elm == ശൂന്യ || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_വേര്(head)) {					\
		എങ്കിൽ (RB_ഇടത്(parent, field) == elm) {			\
			tmp = RB_വലത്(parent, field);			\
			എങ്കിൽ (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_ഇടത്(head, parent, tmp, field);\
				tmp = RB_വലത്(parent, field);		\
			}						\
			എങ്കിൽ ((RB_ഇടത്(tmp, field) == ശൂന്യ ||		\
			    RB_COLOR(RB_ഇടത്(tmp, field), field) == RB_BLACK) &&\
			    (RB_വലത്(tmp, field) == ശൂന്യ ||		\
			    RB_COLOR(RB_വലത്(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} അല്ലെങ്കിൽ {					\
				എങ്കിൽ (RB_വലത്(tmp, field) == ശൂന്യ ||	\
				    RB_COLOR(RB_വലത്(tmp, field), field) == RB_BLACK) {\
					ഘടന type *oleft;		\
					എങ്കിൽ ((oleft = RB_ഇടത്(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_വലത്(head, tmp, oleft, field);\
					tmp = RB_വലത്(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				എങ്കിൽ (RB_വലത്(tmp, field))		\
					RB_COLOR(RB_വലത്(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_ഇടത്(head, parent, tmp, field);\
				elm = RB_വേര്(head);			\
				നിർത്തുക;					\
			}						\
		} അല്ലെങ്കിൽ {						\
			tmp = RB_ഇടത്(parent, field);			\
			എങ്കിൽ (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_വലത്(head, parent, tmp, field);\
				tmp = RB_ഇടത്(parent, field);		\
			}						\
			എങ്കിൽ ((RB_ഇടത്(tmp, field) == ശൂന്യ ||		\
			    RB_COLOR(RB_ഇടത്(tmp, field), field) == RB_BLACK) &&\
			    (RB_വലത്(tmp, field) == ശൂന്യ ||		\
			    RB_COLOR(RB_വലത്(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} അല്ലെങ്കിൽ {					\
				എങ്കിൽ (RB_ഇടത്(tmp, field) == ശൂന്യ ||	\
				    RB_COLOR(RB_ഇടത്(tmp, field), field) == RB_BLACK) {\
					ഘടന type *oright;		\
					എങ്കിൽ ((oright = RB_വലത്(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_ഇടത്(head, tmp, oright, field);\
					tmp = RB_ഇടത്(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				എങ്കിൽ (RB_ഇടത്(tmp, field))		\
					RB_COLOR(RB_ഇടത്(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_വലത്(head, parent, tmp, field);\
				elm = RB_വേര്(head);			\
				നിർത്തുക;					\
			}						\
		}							\
	}								\
	എങ്കിൽ (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr ഘടന type *							\
name##_RB_REMOVE(ഘടന name *head, ഘടന type *elm)			\
{									\
	ഘടന type *child, *parent, *old = elm;			\
	പൂർണ്ണസംഖ്യ color;							\
	എങ്കിൽ (RB_ഇടത്(elm, field) == ശൂന്യ)				\
		child = RB_വലത്(elm, field);				\
	അല്ലെങ്കിൽ എങ്കിൽ (RB_വലത്(elm, field) == ശൂന്യ)				\
		child = RB_ഇടത്(elm, field);				\
	അല്ലെങ്കിൽ {								\
		ഘടന type *ഇടത്;					\
		elm = RB_വലത്(elm, field);				\
		ആകുമ്പോൾ ((ഇടത് = RB_ഇടത്(elm, field)))			\
			elm = ഇടത്;					\
		child = RB_വലത്(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		എങ്കിൽ (child)						\
			RB_PARENT(child, field) = parent;		\
		എങ്കിൽ (parent) {						\
			എങ്കിൽ (RB_ഇടത്(parent, field) == elm)		\
				RB_ഇടത്(parent, field) = child;		\
			അല്ലെങ്കിൽ						\
				RB_വലത്(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} അല്ലെങ്കിൽ							\
			RB_വേര്(head) = child;				\
		എങ്കിൽ (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		എങ്കിൽ (RB_PARENT(old, field)) {				\
			എങ്കിൽ (RB_ഇടത്(RB_PARENT(old, field), field) == old)\
				RB_ഇടത്(RB_PARENT(old, field), field) = elm;\
			അല്ലെങ്കിൽ						\
				RB_വലത്(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} അല്ലെങ്കിൽ							\
			RB_വേര്(head) = elm;				\
		RB_PARENT(RB_ഇടത്(old, field), field) = elm;		\
		എങ്കിൽ (RB_വലത്(old, field))				\
			RB_PARENT(RB_വലത്(old, field), field) = elm;	\
		എങ്കിൽ (parent) {						\
			ഇടത് = parent;					\
			ചെയ്യുക {						\
				RB_AUGMENT(ഇടത്);			\
			} ആകുമ്പോൾ ((ഇടത് = RB_PARENT(ഇടത്, field)));	\
		}							\
		പോകുക color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	എങ്കിൽ (child)							\
		RB_PARENT(child, field) = parent;			\
	എങ്കിൽ (parent) {							\
		എങ്കിൽ (RB_ഇടത്(parent, field) == elm)			\
			RB_ഇടത്(parent, field) = child;			\
		അല്ലെങ്കിൽ							\
			RB_വലത്(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} അല്ലെങ്കിൽ								\
		RB_വേര്(head) = child;					\
color:									\
	എങ്കിൽ (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	തിരികെ (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr ഘടന type *							\
name##_RB_INSERT(ഘടന name *head, ഘടന type *elm)			\
{									\
	ഘടന type *tmp;						\
	ഘടന type *parent = ശൂന്യ;					\
	പൂർണ്ണസംഖ്യ comp = 0;							\
	tmp = RB_വേര്(head);						\
	ആകുമ്പോൾ (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		എങ്കിൽ (comp < 0)						\
			tmp = RB_ഇടത്(tmp, field);			\
		അല്ലെങ്കിൽ എങ്കിൽ (comp > 0)					\
			tmp = RB_വലത്(tmp, field);			\
		അല്ലെങ്കിൽ							\
			തിരികെ (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	എങ്കിൽ (parent != ശൂന്യ) {						\
		എങ്കിൽ (comp < 0)						\
			RB_ഇടത്(parent, field) = elm;			\
		അല്ലെങ്കിൽ							\
			RB_വലത്(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} അല്ലെങ്കിൽ								\
		RB_വേര്(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	തിരികെ (ശൂന്യ);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr ഘടന type *							\
name##_RB_FIND(ഘടന name *head, ഘടന type *elm)			\
{									\
	ഘടന type *tmp = RB_വേര്(head);				\
	പൂർണ്ണസംഖ്യ comp;							\
	ആകുമ്പോൾ (tmp) {							\
		comp = cmp(elm, tmp);					\
		എങ്കിൽ (comp < 0)						\
			tmp = RB_ഇടത്(tmp, field);			\
		അല്ലെങ്കിൽ എങ്കിൽ (comp > 0)					\
			tmp = RB_വലത്(tmp, field);			\
		അല്ലെങ്കിൽ							\
			തിരികെ (tmp);					\
	}								\
	തിരികെ (ശൂന്യ);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr ഘടന type *							\
name##_RB_NFIND(ഘടന name *head, ഘടന type *elm)			\
{									\
	ഘടന type *tmp = RB_വേര്(head);				\
	ഘടന type *res = ശൂന്യ;					\
	പൂർണ്ണസംഖ്യ comp;							\
	ആകുമ്പോൾ (tmp) {							\
		comp = cmp(elm, tmp);					\
		എങ്കിൽ (comp < 0) {						\
			res = tmp;					\
			tmp = RB_ഇടത്(tmp, field);			\
		}							\
		അല്ലെങ്കിൽ എങ്കിൽ (comp > 0)					\
			tmp = RB_വലത്(tmp, field);			\
		അല്ലെങ്കിൽ							\
			തിരികെ (tmp);					\
	}								\
	തിരികെ (res);							\
}									\
									\
/* ARGSUSED */								\
attr ഘടന type *							\
name##_RB_NEXT(ഘടന type *elm)					\
{									\
	എങ്കിൽ (RB_വലത്(elm, field)) {					\
		elm = RB_വലത്(elm, field);				\
		ആകുമ്പോൾ (RB_ഇടത്(elm, field))				\
			elm = RB_ഇടത്(elm, field);			\
	} അല്ലെങ്കിൽ {							\
		എങ്കിൽ (RB_PARENT(elm, field) &&				\
		    (elm == RB_ഇടത്(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		അല്ലെങ്കിൽ {							\
			ആകുമ്പോൾ (RB_PARENT(elm, field) &&			\
			    (elm == RB_വലത്(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	തിരികെ (elm);							\
}									\
									\
/* ARGSUSED */								\
attr ഘടന type *							\
name##_RB_PREV(ഘടന type *elm)					\
{									\
	എങ്കിൽ (RB_ഇടത്(elm, field)) {					\
		elm = RB_ഇടത്(elm, field);				\
		ആകുമ്പോൾ (RB_വലത്(elm, field))				\
			elm = RB_വലത്(elm, field);			\
	} അല്ലെങ്കിൽ {							\
		എങ്കിൽ (RB_PARENT(elm, field) &&				\
		    (elm == RB_വലത്(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		അല്ലെങ്കിൽ {							\
			ആകുമ്പോൾ (RB_PARENT(elm, field) &&			\
			    (elm == RB_ഇടത്(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	തിരികെ (elm);							\
}									\
									\
attr ഘടന type *							\
name##_RB_MINMAX(ഘടന name *head, പൂർണ്ണസംഖ്യ val)				\
{									\
	ഘടന type *tmp = RB_വേര്(head);				\
	ഘടന type *parent = ശൂന്യ;					\
	ആകുമ്പോൾ (tmp) {							\
		parent = tmp;						\
		എങ്കിൽ (val < 0)						\
			tmp = RB_ഇടത്(tmp, field);			\
		അല്ലെങ്കിൽ							\
			tmp = RB_വലത്(tmp, field);			\
	}								\
	തിരികെ (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_തിരുകുക(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	വേണ്ടി ((x) = RB_MIN(name, head);					\
	     (x) != ശൂന്യ;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	വേണ്ടി ((x) = RB_MIN(name, head);					\
	    ((x) != ശൂന്യ) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	വേണ്ടി ((x) = RB_MAX(name, head);					\
	     (x) != ശൂന്യ;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	വേണ്ടി ((x) = RB_MAX(name, head);					\
	    ((x) != ശൂന്യ) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
