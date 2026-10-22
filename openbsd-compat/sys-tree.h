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

#अन्तर्भाव "config.h"
#ifdef NO_ATTRIBUTE_ON_RETURN_TYPE
# define __attribute__(x)
#endif

#ifndef	SYS_वृक्षः_H
#define	SYS_वृक्षः_H

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
संरचना name {								\
	संरचना type *sph_मूलम्; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(मूलम्)						\
	{ रिक्त }

#define SPLAY_INIT(मूलम्) करोहि {						\
	(मूलम्)->sph_मूलम् = रिक्त;					\
} याव (0)

#define SPLAY_ENTRY(type)						\
संरचना {								\
	संरचना type *spe_वामः; /* left element */			\
	संरचना type *spe_दक्षिणः; /* right element */			\
}

#define SPLAY_वामः(elm, field)		(elm)->field.spe_वामः
#define SPLAY_दक्षिणः(elm, field)		(elm)->field.spe_दक्षिणः
#define SPLAY_मूलम्(head)		(head)->sph_मूलम्
#define SPLAY_EMPTY(head)		(SPLAY_मूलम्(head) == रिक्त)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_दक्षिणः(head, tmp, field) करोहि {			\
	SPLAY_वामः((head)->sph_मूलम्, field) = SPLAY_दक्षिणः(tmp, field);	\
	SPLAY_दक्षिणः(tmp, field) = (head)->sph_मूलम्;			\
	(head)->sph_मूलम् = tmp;						\
} याव (0)
	
#define SPLAY_ROTATE_वामः(head, tmp, field) करोहि {			\
	SPLAY_दक्षिणः((head)->sph_मूलम्, field) = SPLAY_वामः(tmp, field);	\
	SPLAY_वामः(tmp, field) = (head)->sph_मूलम्;			\
	(head)->sph_मूलम् = tmp;						\
} याव (0)

#define SPLAY_LINKLEFT(head, tmp, field) करोहि {				\
	SPLAY_वामः(tmp, field) = (head)->sph_मूलम्;			\
	tmp = (head)->sph_मूलम्;						\
	(head)->sph_मूलम् = SPLAY_वामः((head)->sph_मूलम्, field);		\
} याव (0)

#define SPLAY_LINKRIGHT(head, tmp, field) करोहि {				\
	SPLAY_दक्षिणः(tmp, field) = (head)->sph_मूलम्;			\
	tmp = (head)->sph_मूलम्;						\
	(head)->sph_मूलम् = SPLAY_दक्षिणः((head)->sph_मूलम्, field);	\
} याव (0)

#define SPLAY_ASSEMBLE(head, ग्रन्थिः, वामः, दक्षिणः, field) करोहि {		\
	SPLAY_दक्षिणः(वामः, field) = SPLAY_वामः((head)->sph_मूलम्, field);	\
	SPLAY_वामः(दक्षिणः, field) = SPLAY_दक्षिणः((head)->sph_मूलम्, field);\
	SPLAY_वामः((head)->sph_मूलम्, field) = SPLAY_दक्षिणः(ग्रन्थिः, field);	\
	SPLAY_दक्षिणः((head)->sph_मूलम्, field) = SPLAY_वामः(ग्रन्थिः, field);	\
} याव (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)				\
शून्य name##_SPLAY(संरचना name *, संरचना type *);			\
शून्य name##_SPLAY_MINMAX(संरचना name *, पूर्णाङ्क);				\
संरचना type *name##_SPLAY_INSERT(संरचना name *, संरचना type *);		\
संरचना type *name##_SPLAY_REMOVE(संरचना name *, संरचना type *);		\
									\
/* Finds the node with the same key as elm */				\
स्थिर __inline संरचना type *						\
name##_SPLAY_FIND(संरचना name *head, संरचना type *elm)			\
{									\
	सचे (SPLAY_EMPTY(head))						\
		पटिनिवत्त(रिक्त);						\
	name##_SPLAY(head, elm);					\
	सचे ((cmp)(elm, (head)->sph_मूलम्) == 0)				\
		पटिनिवत्त (head->sph_मूलम्);				\
	पटिनिवत्त (रिक्त);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_NEXT(संरचना name *head, संरचना type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	सचे (SPLAY_दक्षिणः(elm, field) != रिक्त) {				\
		elm = SPLAY_दक्षिणः(elm, field);				\
		याव (SPLAY_वामः(elm, field) != रिक्त) {		\
			elm = SPLAY_वामः(elm, field);			\
		}							\
	} अञ्ञथा								\
		elm = रिक्त;						\
	पटिनिवत्त (elm);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_MIN_MAX(संरचना name *head, पूर्णाङ्क val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        पटिनिवत्त (SPLAY_मूलम्(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
संरचना type *								\
name##_SPLAY_INSERT(संरचना name *head, संरचना type *elm)		\
{									\
    सचे (SPLAY_EMPTY(head)) {						\
	    SPLAY_वामः(elm, field) = SPLAY_दक्षिणः(elm, field) = रिक्त;	\
    } अञ्ञथा {								\
	    पूर्णाङ्क __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_मूलम्);			\
	    सचे(__comp < 0) {						\
		    SPLAY_वामः(elm, field) = SPLAY_वामः((head)->sph_मूलम्, field);\
		    SPLAY_दक्षिणः(elm, field) = (head)->sph_मूलम्;		\
		    SPLAY_वामः((head)->sph_मूलम्, field) = रिक्त;		\
	    } अञ्ञथा सचे (__comp > 0) {					\
		    SPLAY_दक्षिणः(elm, field) = SPLAY_दक्षिणः((head)->sph_मूलम्, field);\
		    SPLAY_वामः(elm, field) = (head)->sph_मूलम्;		\
		    SPLAY_दक्षिणः((head)->sph_मूलम्, field) = रिक्त;	\
	    } अञ्ञथा							\
		    पटिनिवत्त ((head)->sph_मूलम्);				\
    }									\
    (head)->sph_मूलम् = (elm);						\
    पटिनिवत्त (रिक्त);							\
}									\
									\
संरचना type *								\
name##_SPLAY_REMOVE(संरचना name *head, संरचना type *elm)		\
{									\
	संरचना type *__tmp;						\
	सचे (SPLAY_EMPTY(head))						\
		पटिनिवत्त (रिक्त);						\
	name##_SPLAY(head, elm);					\
	सचे ((cmp)(elm, (head)->sph_मूलम्) == 0) {			\
		सचे (SPLAY_वामः((head)->sph_मूलम्, field) == रिक्त) {	\
			(head)->sph_मूलम् = SPLAY_दक्षिणः((head)->sph_मूलम्, field);\
		} अञ्ञथा {						\
			__tmp = SPLAY_दक्षिणः((head)->sph_मूलम्, field);	\
			(head)->sph_मूलम् = SPLAY_वामः((head)->sph_मूलम्, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_दक्षिणः((head)->sph_मूलम्, field) = __tmp;	\
		}							\
		पटिनिवत्त (elm);						\
	}								\
	पटिनिवत्त (रिक्त);							\
}									\
									\
शून्य									\
name##_SPLAY(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
	पूर्णाङ्क __comp;							\
\
	SPLAY_वामः(&__node, field) = SPLAY_दक्षिणः(&__node, field) = रिक्त;\
	__left = __right = &__node;					\
\
	याव ((__comp = (cmp)(elm, (head)->sph_मूलम्))) {		\
		सचे (__comp < 0) {					\
			__tmp = SPLAY_वामः((head)->sph_मूलम्, field);	\
			सचे (__tmp == रिक्त)				\
				भङ्ग;					\
			सचे ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_दक्षिणः(head, __tmp, field);	\
				सचे (SPLAY_वामः((head)->sph_मूलम्, field) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} अञ्ञथा सचे (__comp > 0) {				\
			__tmp = SPLAY_दक्षिणः((head)->sph_मूलम्, field);	\
			सचे (__tmp == रिक्त)				\
				भङ्ग;					\
			सचे ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_वामः(head, __tmp, field);	\
				सचे (SPLAY_दक्षिणः((head)->sph_मूलम्, field) == रिक्त)\
					भङ्ग;				\
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
शून्य name##_SPLAY_MINMAX(संरचना name *head, पूर्णाङ्क __comp) \
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
\
	SPLAY_वामः(&__node, field) = SPLAY_दक्षिणः(&__node, field) = रिक्त;\
	__left = __right = &__node;					\
\
	याव (1) {							\
		सचे (__comp < 0) {					\
			__tmp = SPLAY_वामः((head)->sph_मूलम्, field);	\
			सचे (__tmp == रिक्त)				\
				भङ्ग;					\
			सचे (__comp < 0){				\
				SPLAY_ROTATE_दक्षिणः(head, __tmp, field);	\
				सचे (SPLAY_वामः((head)->sph_मूलम्, field) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} अञ्ञथा सचे (__comp > 0) {				\
			__tmp = SPLAY_दक्षिणः((head)->sph_मूलम्, field);	\
			सचे (__tmp == रिक्त)				\
				भङ्ग;					\
			सचे (__comp > 0) {				\
				SPLAY_ROTATE_वामः(head, __tmp, field);	\
				सचे (SPLAY_दक्षिणः((head)->sph_मूलम्, field) == रिक्त)\
					भङ्ग;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_निवेशय(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	अत्थाय ((x) = SPLAY_MIN(name, head);				\
	     (x) != रिक्त;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
संरचना name {								\
	संरचना type *rbh_मूलम्; /* root of the tree */			\
}

#define RB_INITIALIZER(मूलम्)						\
	{ रिक्त }

#define RB_INIT(मूलम्) करोहि {						\
	(मूलम्)->rbh_मूलम् = रिक्त;					\
} याव (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
संरचना {								\
	संरचना type *rbe_वामः;		/* left element */		\
	संरचना type *rbe_दक्षिणः;		/* right element */		\
	संरचना type *rbe_parent;	/* parent element */		\
	पूर्णाङ्क rbe_color;			/* node color */		\
}

#define RB_वामः(elm, field)		(elm)->field.rbe_वामः
#define RB_दक्षिणः(elm, field)		(elm)->field.rbe_दक्षिणः
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_मूलम्(head)			(head)->rbh_मूलम्
#define RB_EMPTY(head)			(RB_मूलम्(head) == रिक्त)

#define RB_SET(elm, parent, field) करोहि {					\
	RB_PARENT(elm, field) = parent;					\
	RB_वामः(elm, field) = RB_दक्षिणः(elm, field) = रिक्त;		\
	RB_COLOR(elm, field) = RB_RED;					\
} याव (0)

#define RB_SET_BLACKRED(black, red, field) करोहि {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} याव (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	करोहि {} याव (0)
#endif

#define RB_ROTATE_वामः(head, elm, tmp, field) करोहि {			\
	(tmp) = RB_दक्षिणः(elm, field);					\
	सचे ((RB_दक्षिणः(elm, field) = RB_वामः(tmp, field))) {		\
		RB_PARENT(RB_वामः(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	सचे ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		सचे ((elm) == RB_वामः(RB_PARENT(elm, field), field))	\
			RB_वामः(RB_PARENT(elm, field), field) = (tmp);	\
		अञ्ञथा							\
			RB_दक्षिणः(RB_PARENT(elm, field), field) = (tmp);	\
	} अञ्ञथा								\
		(head)->rbh_मूलम् = (tmp);				\
	RB_वामः(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	सचे ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} याव (0)

#define RB_ROTATE_दक्षिणः(head, elm, tmp, field) करोहि {			\
	(tmp) = RB_वामः(elm, field);					\
	सचे ((RB_वामः(elm, field) = RB_दक्षिणः(tmp, field))) {		\
		RB_PARENT(RB_दक्षिणः(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	सचे ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		सचे ((elm) == RB_वामः(RB_PARENT(elm, field), field))	\
			RB_वामः(RB_PARENT(elm, field), field) = (tmp);	\
		अञ्ञथा							\
			RB_दक्षिणः(RB_PARENT(elm, field), field) = (tmp);	\
	} अञ्ञथा								\
		(head)->rbh_मूलम् = (tmp);				\
	RB_दक्षिणः(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	सचे ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} याव (0)

/* Generates prototypes and inline functions */
#define	RB_PROTOTYPE(name, type, field, cmp)				\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp,)
#define	RB_PROTOTYPE_STATIC(name, type, field, cmp)			\
	RB_PROTOTYPE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) स्थिर)
#define RB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)		\
attr शून्य name##_RB_INSERT_COLOR(संरचना name *, संरचना type *);		\
attr शून्य name##_RB_REMOVE_COLOR(संरचना name *, संरचना type *, संरचना type *);\
attr संरचना type *name##_RB_REMOVE(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_INSERT(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_FIND(संरचना name *, संरचना type *);		\
attr संरचना type *name##_RB_NFIND(संरचना name *, संरचना type *);	\
attr संरचना type *name##_RB_NEXT(संरचना type *);			\
attr संरचना type *name##_RB_PREV(संरचना type *);			\
attr संरचना type *name##_RB_MINMAX(संरचना name *, पूर्णाङ्क);			\
									\

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define	RB_GENERATE(name, type, field, cmp)				\
	RB_GENERATE_INTERNAL(name, type, field, cmp,)
#define	RB_GENERATE_STATIC(name, type, field, cmp)			\
	RB_GENERATE_INTERNAL(name, type, field, cmp, __attribute__((__unused__)) स्थिर)
#define RB_GENERATE_INTERNAL(name, type, field, cmp, attr)		\
attr शून्य								\
name##_RB_INSERT_COLOR(संरचना name *head, संरचना type *elm)		\
{									\
	संरचना type *parent, *gparent, *tmp;				\
	याव ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		सचे (parent == RB_वामः(gparent, field)) {		\
			tmp = RB_दक्षिणः(gparent, field);			\
			सचे (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				अनुवर्त;				\
			}						\
			सचे (RB_दक्षिणः(parent, field) == elm) {		\
				RB_ROTATE_वामः(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_दक्षिणः(head, gparent, tmp, field);	\
		} अञ्ञथा {						\
			tmp = RB_वामः(gparent, field);			\
			सचे (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				अनुवर्त;				\
			}						\
			सचे (RB_वामः(parent, field) == elm) {		\
				RB_ROTATE_दक्षिणः(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_वामः(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_मूलम्, field) = RB_BLACK;			\
}									\
									\
attr शून्य								\
name##_RB_REMOVE_COLOR(संरचना name *head, संरचना type *parent, संरचना type *elm) \
{									\
	संरचना type *tmp;						\
	याव ((elm == रिक्त || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_मूलम्(head)) {					\
		सचे (RB_वामः(parent, field) == elm) {			\
			tmp = RB_दक्षिणः(parent, field);			\
			सचे (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_वामः(head, parent, tmp, field);\
				tmp = RB_दक्षिणः(parent, field);		\
			}						\
			सचे ((RB_वामः(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_वामः(tmp, field), field) == RB_BLACK) &&\
			    (RB_दक्षिणः(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_दक्षिणः(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अञ्ञथा {					\
				सचे (RB_दक्षिणः(tmp, field) == रिक्त ||	\
				    RB_COLOR(RB_दक्षिणः(tmp, field), field) == RB_BLACK) {\
					संरचना type *oleft;		\
					सचे ((oleft = RB_वामः(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_दक्षिणः(head, tmp, oleft, field);\
					tmp = RB_दक्षिणः(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				सचे (RB_दक्षिणः(tmp, field))		\
					RB_COLOR(RB_दक्षिणः(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_वामः(head, parent, tmp, field);\
				elm = RB_मूलम्(head);			\
				भङ्ग;					\
			}						\
		} अञ्ञथा {						\
			tmp = RB_वामः(parent, field);			\
			सचे (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_दक्षिणः(head, parent, tmp, field);\
				tmp = RB_वामः(parent, field);		\
			}						\
			सचे ((RB_वामः(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_वामः(tmp, field), field) == RB_BLACK) &&\
			    (RB_दक्षिणः(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_दक्षिणः(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अञ्ञथा {					\
				सचे (RB_वामः(tmp, field) == रिक्त ||	\
				    RB_COLOR(RB_वामः(tmp, field), field) == RB_BLACK) {\
					संरचना type *oright;		\
					सचे ((oright = RB_दक्षिणः(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_वामः(head, tmp, oright, field);\
					tmp = RB_वामः(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				सचे (RB_वामः(tmp, field))		\
					RB_COLOR(RB_वामः(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_दक्षिणः(head, parent, tmp, field);\
				elm = RB_मूलम्(head);			\
				भङ्ग;					\
			}						\
		}							\
	}								\
	सचे (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr संरचना type *							\
name##_RB_REMOVE(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *child, *parent, *old = elm;			\
	पूर्णाङ्क color;							\
	सचे (RB_वामः(elm, field) == रिक्त)				\
		child = RB_दक्षिणः(elm, field);				\
	अञ्ञथा सचे (RB_दक्षिणः(elm, field) == रिक्त)				\
		child = RB_वामः(elm, field);				\
	अञ्ञथा {								\
		संरचना type *वामः;					\
		elm = RB_दक्षिणः(elm, field);				\
		याव ((वामः = RB_वामः(elm, field)))			\
			elm = वामः;					\
		child = RB_दक्षिणः(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		सचे (child)						\
			RB_PARENT(child, field) = parent;		\
		सचे (parent) {						\
			सचे (RB_वामः(parent, field) == elm)		\
				RB_वामः(parent, field) = child;		\
			अञ्ञथा						\
				RB_दक्षिणः(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} अञ्ञथा							\
			RB_मूलम्(head) = child;				\
		सचे (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		सचे (RB_PARENT(old, field)) {				\
			सचे (RB_वामः(RB_PARENT(old, field), field) == old)\
				RB_वामः(RB_PARENT(old, field), field) = elm;\
			अञ्ञथा						\
				RB_दक्षिणः(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} अञ्ञथा							\
			RB_मूलम्(head) = elm;				\
		RB_PARENT(RB_वामः(old, field), field) = elm;		\
		सचे (RB_दक्षिणः(old, field))				\
			RB_PARENT(RB_दक्षिणः(old, field), field) = elm;	\
		सचे (parent) {						\
			वामः = parent;					\
			करोहि {						\
				RB_AUGMENT(वामः);			\
			} याव ((वामः = RB_PARENT(वामः, field)));	\
		}							\
		गच्छ color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	सचे (child)							\
		RB_PARENT(child, field) = parent;			\
	सचे (parent) {							\
		सचे (RB_वामः(parent, field) == elm)			\
			RB_वामः(parent, field) = child;			\
		अञ्ञथा							\
			RB_दक्षिणः(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} अञ्ञथा								\
		RB_मूलम्(head) = child;					\
color:									\
	सचे (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	पटिनिवत्त (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr संरचना type *							\
name##_RB_INSERT(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp;						\
	संरचना type *parent = रिक्त;					\
	पूर्णाङ्क comp = 0;							\
	tmp = RB_मूलम्(head);						\
	याव (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		सचे (comp < 0)						\
			tmp = RB_वामः(tmp, field);			\
		अञ्ञथा सचे (comp > 0)					\
			tmp = RB_दक्षिणः(tmp, field);			\
		अञ्ञथा							\
			पटिनिवत्त (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	सचे (parent != रिक्त) {						\
		सचे (comp < 0)						\
			RB_वामः(parent, field) = elm;			\
		अञ्ञथा							\
			RB_दक्षिणः(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} अञ्ञथा								\
		RB_मूलम्(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	पटिनिवत्त (रिक्त);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr संरचना type *							\
name##_RB_FIND(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_मूलम्(head);				\
	पूर्णाङ्क comp;							\
	याव (tmp) {							\
		comp = cmp(elm, tmp);					\
		सचे (comp < 0)						\
			tmp = RB_वामः(tmp, field);			\
		अञ्ञथा सचे (comp > 0)					\
			tmp = RB_दक्षिणः(tmp, field);			\
		अञ्ञथा							\
			पटिनिवत्त (tmp);					\
	}								\
	पटिनिवत्त (रिक्त);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr संरचना type *							\
name##_RB_NFIND(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_मूलम्(head);				\
	संरचना type *res = रिक्त;					\
	पूर्णाङ्क comp;							\
	याव (tmp) {							\
		comp = cmp(elm, tmp);					\
		सचे (comp < 0) {						\
			res = tmp;					\
			tmp = RB_वामः(tmp, field);			\
		}							\
		अञ्ञथा सचे (comp > 0)					\
			tmp = RB_दक्षिणः(tmp, field);			\
		अञ्ञथा							\
			पटिनिवत्त (tmp);					\
	}								\
	पटिनिवत्त (res);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_NEXT(संरचना type *elm)					\
{									\
	सचे (RB_दक्षिणः(elm, field)) {					\
		elm = RB_दक्षिणः(elm, field);				\
		याव (RB_वामः(elm, field))				\
			elm = RB_वामः(elm, field);			\
	} अञ्ञथा {							\
		सचे (RB_PARENT(elm, field) &&				\
		    (elm == RB_वामः(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अञ्ञथा {							\
			याव (RB_PARENT(elm, field) &&			\
			    (elm == RB_दक्षिणः(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	पटिनिवत्त (elm);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_PREV(संरचना type *elm)					\
{									\
	सचे (RB_वामः(elm, field)) {					\
		elm = RB_वामः(elm, field);				\
		याव (RB_दक्षिणः(elm, field))				\
			elm = RB_दक्षिणः(elm, field);			\
	} अञ्ञथा {							\
		सचे (RB_PARENT(elm, field) &&				\
		    (elm == RB_दक्षिणः(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अञ्ञथा {							\
			याव (RB_PARENT(elm, field) &&			\
			    (elm == RB_वामः(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	पटिनिवत्त (elm);							\
}									\
									\
attr संरचना type *							\
name##_RB_MINMAX(संरचना name *head, पूर्णाङ्क val)				\
{									\
	संरचना type *tmp = RB_मूलम्(head);				\
	संरचना type *parent = रिक्त;					\
	याव (tmp) {							\
		parent = tmp;						\
		सचे (val < 0)						\
			tmp = RB_वामः(tmp, field);			\
		अञ्ञथा							\
			tmp = RB_दक्षिणः(tmp, field);			\
	}								\
	पटिनिवत्त (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_निवेशय(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	अत्थाय ((x) = RB_MIN(name, head);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	अत्थाय ((x) = RB_MIN(name, head);					\
	    ((x) != रिक्त) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	अत्थाय ((x) = RB_MAX(name, head);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	अत्थाय ((x) = RB_MAX(name, head);					\
	    ((x) != रिक्त) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
