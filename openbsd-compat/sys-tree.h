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

#ifndef	SYS_रूख_H
#define	SYS_रूख_H

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
	संरचना type *sph_जरा; /* root of the tree */			\
}

#define SPLAY_INITIALIZER(जरा)						\
	{ रिक्त }

#define SPLAY_INIT(जरा) गर {						\
	(जरा)->sph_जरा = रिक्त;					\
} जबसम्म (0)

#define SPLAY_ENTRY(type)						\
संरचना {								\
	संरचना type *spe_बायाँ; /* left element */			\
	संरचना type *spe_दायाँ; /* right element */			\
}

#define SPLAY_बायाँ(elm, field)		(elm)->field.spe_बायाँ
#define SPLAY_दायाँ(elm, field)		(elm)->field.spe_दायाँ
#define SPLAY_जरा(head)		(head)->sph_जरा
#define SPLAY_EMPTY(head)		(SPLAY_जरा(head) == रिक्त)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_दायाँ(head, tmp, field) गर {			\
	SPLAY_बायाँ((head)->sph_जरा, field) = SPLAY_दायाँ(tmp, field);	\
	SPLAY_दायाँ(tmp, field) = (head)->sph_जरा;			\
	(head)->sph_जरा = tmp;						\
} जबसम्म (0)
	
#define SPLAY_ROTATE_बायाँ(head, tmp, field) गर {			\
	SPLAY_दायाँ((head)->sph_जरा, field) = SPLAY_बायाँ(tmp, field);	\
	SPLAY_बायाँ(tmp, field) = (head)->sph_जरा;			\
	(head)->sph_जरा = tmp;						\
} जबसम्म (0)

#define SPLAY_LINKLEFT(head, tmp, field) गर {				\
	SPLAY_बायाँ(tmp, field) = (head)->sph_जरा;			\
	tmp = (head)->sph_जरा;						\
	(head)->sph_जरा = SPLAY_बायाँ((head)->sph_जरा, field);		\
} जबसम्म (0)

#define SPLAY_LINKRIGHT(head, tmp, field) गर {				\
	SPLAY_दायाँ(tmp, field) = (head)->sph_जरा;			\
	tmp = (head)->sph_जरा;						\
	(head)->sph_जरा = SPLAY_दायाँ((head)->sph_जरा, field);	\
} जबसम्म (0)

#define SPLAY_ASSEMBLE(head, गाँठो, बायाँ, दायाँ, field) गर {		\
	SPLAY_दायाँ(बायाँ, field) = SPLAY_बायाँ((head)->sph_जरा, field);	\
	SPLAY_बायाँ(दायाँ, field) = SPLAY_दायाँ((head)->sph_जरा, field);\
	SPLAY_बायाँ((head)->sph_जरा, field) = SPLAY_दायाँ(गाँठो, field);	\
	SPLAY_दायाँ((head)->sph_जरा, field) = SPLAY_बायाँ(गाँठो, field);	\
} जबसम्म (0)

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
	यदि (SPLAY_EMPTY(head))						\
		फर्काऊ(रिक्त);						\
	name##_SPLAY(head, elm);					\
	यदि ((cmp)(elm, (head)->sph_जरा) == 0)				\
		फर्काऊ (head->sph_जरा);				\
	फर्काऊ (रिक्त);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_NEXT(संरचना name *head, संरचना type *elm)			\
{									\
	name##_SPLAY(head, elm);					\
	यदि (SPLAY_दायाँ(elm, field) != रिक्त) {				\
		elm = SPLAY_दायाँ(elm, field);				\
		जबसम्म (SPLAY_बायाँ(elm, field) != रिक्त) {		\
			elm = SPLAY_बायाँ(elm, field);			\
		}							\
	} अन्यथा								\
		elm = रिक्त;						\
	फर्काऊ (elm);							\
}									\
									\
स्थिर __inline संरचना type *						\
name##_SPLAY_MIN_MAX(संरचना name *head, पूर्णाङ्क val)			\
{									\
	name##_SPLAY_MINMAX(head, val);					\
        फर्काऊ (SPLAY_जरा(head));					\
}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)				\
संरचना type *								\
name##_SPLAY_INSERT(संरचना name *head, संरचना type *elm)		\
{									\
    यदि (SPLAY_EMPTY(head)) {						\
	    SPLAY_बायाँ(elm, field) = SPLAY_दायाँ(elm, field) = रिक्त;	\
    } अन्यथा {								\
	    पूर्णाङ्क __comp;							\
	    name##_SPLAY(head, elm);					\
	    __comp = (cmp)(elm, (head)->sph_जरा);			\
	    यदि(__comp < 0) {						\
		    SPLAY_बायाँ(elm, field) = SPLAY_बायाँ((head)->sph_जरा, field);\
		    SPLAY_दायाँ(elm, field) = (head)->sph_जरा;		\
		    SPLAY_बायाँ((head)->sph_जरा, field) = रिक्त;		\
	    } अन्यथा यदि (__comp > 0) {					\
		    SPLAY_दायाँ(elm, field) = SPLAY_दायाँ((head)->sph_जरा, field);\
		    SPLAY_बायाँ(elm, field) = (head)->sph_जरा;		\
		    SPLAY_दायाँ((head)->sph_जरा, field) = रिक्त;	\
	    } अन्यथा							\
		    फर्काऊ ((head)->sph_जरा);				\
    }									\
    (head)->sph_जरा = (elm);						\
    फर्काऊ (रिक्त);							\
}									\
									\
संरचना type *								\
name##_SPLAY_REMOVE(संरचना name *head, संरचना type *elm)		\
{									\
	संरचना type *__tmp;						\
	यदि (SPLAY_EMPTY(head))						\
		फर्काऊ (रिक्त);						\
	name##_SPLAY(head, elm);					\
	यदि ((cmp)(elm, (head)->sph_जरा) == 0) {			\
		यदि (SPLAY_बायाँ((head)->sph_जरा, field) == रिक्त) {	\
			(head)->sph_जरा = SPLAY_दायाँ((head)->sph_जरा, field);\
		} अन्यथा {						\
			__tmp = SPLAY_दायाँ((head)->sph_जरा, field);	\
			(head)->sph_जरा = SPLAY_बायाँ((head)->sph_जरा, field);\
			name##_SPLAY(head, elm);			\
			SPLAY_दायाँ((head)->sph_जरा, field) = __tmp;	\
		}							\
		फर्काऊ (elm);						\
	}								\
	फर्काऊ (रिक्त);							\
}									\
									\
शून्य									\
name##_SPLAY(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type __node, *__left, *__right, *__tmp;			\
	पूर्णाङ्क __comp;							\
\
	SPLAY_बायाँ(&__node, field) = SPLAY_दायाँ(&__node, field) = रिक्त;\
	__left = __right = &__node;					\
\
	जबसम्म ((__comp = (cmp)(elm, (head)->sph_जरा))) {		\
		यदि (__comp < 0) {					\
			__tmp = SPLAY_बायाँ((head)->sph_जरा, field);	\
			यदि (__tmp == रिक्त)				\
				रोक;					\
			यदि ((cmp)(elm, __tmp) < 0){			\
				SPLAY_ROTATE_दायाँ(head, __tmp, field);	\
				यदि (SPLAY_बायाँ((head)->sph_जरा, field) == रिक्त)\
					रोक;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} अन्यथा यदि (__comp > 0) {				\
			__tmp = SPLAY_दायाँ((head)->sph_जरा, field);	\
			यदि (__tmp == रिक्त)				\
				रोक;					\
			यदि ((cmp)(elm, __tmp) > 0){			\
				SPLAY_ROTATE_बायाँ(head, __tmp, field);	\
				यदि (SPLAY_दायाँ((head)->sph_जरा, field) == रिक्त)\
					रोक;				\
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
	SPLAY_बायाँ(&__node, field) = SPLAY_दायाँ(&__node, field) = रिक्त;\
	__left = __right = &__node;					\
\
	जबसम्म (1) {							\
		यदि (__comp < 0) {					\
			__tmp = SPLAY_बायाँ((head)->sph_जरा, field);	\
			यदि (__tmp == रिक्त)				\
				रोक;					\
			यदि (__comp < 0){				\
				SPLAY_ROTATE_दायाँ(head, __tmp, field);	\
				यदि (SPLAY_बायाँ((head)->sph_जरा, field) == रिक्त)\
					रोक;				\
			}						\
			SPLAY_LINKLEFT(head, __right, field);		\
		} अन्यथा यदि (__comp > 0) {				\
			__tmp = SPLAY_दायाँ((head)->sph_जरा, field);	\
			यदि (__tmp == रिक्त)				\
				रोक;					\
			यदि (__comp > 0) {				\
				SPLAY_ROTATE_बायाँ(head, __tmp, field);	\
				यदि (SPLAY_दायाँ((head)->sph_जरा, field) == रिक्त)\
					रोक;				\
			}						\
			SPLAY_LINKRIGHT(head, __left, field);		\
		}							\
	}								\
	SPLAY_ASSEMBLE(head, &__node, __left, __right, field);		\
}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_घुसाउ(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)		(SPLAY_EMPTY(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)		(SPLAY_EMPTY(x) ? रिक्त	\
					: name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)					\
	लागि ((x) = SPLAY_MIN(name, head);				\
	     (x) != रिक्त;						\
	     (x) = SPLAY_NEXT(name, head, x))

/* Macros that define a red-black tree */
#define RB_HEAD(name, type)						\
संरचना name {								\
	संरचना type *rbh_जरा; /* root of the tree */			\
}

#define RB_INITIALIZER(जरा)						\
	{ रिक्त }

#define RB_INIT(जरा) गर {						\
	(जरा)->rbh_जरा = रिक्त;					\
} जबसम्म (0)

#define RB_BLACK	0
#define RB_RED		1
#define RB_ENTRY(type)							\
संरचना {								\
	संरचना type *rbe_बायाँ;		/* left element */		\
	संरचना type *rbe_दायाँ;		/* right element */		\
	संरचना type *rbe_parent;	/* parent element */		\
	पूर्णाङ्क rbe_color;			/* node color */		\
}

#define RB_बायाँ(elm, field)		(elm)->field.rbe_बायाँ
#define RB_दायाँ(elm, field)		(elm)->field.rbe_दायाँ
#define RB_PARENT(elm, field)		(elm)->field.rbe_parent
#define RB_COLOR(elm, field)		(elm)->field.rbe_color
#define RB_जरा(head)			(head)->rbh_जरा
#define RB_EMPTY(head)			(RB_जरा(head) == रिक्त)

#define RB_SET(elm, parent, field) गर {					\
	RB_PARENT(elm, field) = parent;					\
	RB_बायाँ(elm, field) = RB_दायाँ(elm, field) = रिक्त;		\
	RB_COLOR(elm, field) = RB_RED;					\
} जबसम्म (0)

#define RB_SET_BLACKRED(black, red, field) गर {				\
	RB_COLOR(black, field) = RB_BLACK;				\
	RB_COLOR(red, field) = RB_RED;					\
} जबसम्म (0)

#ifndef RB_AUGMENT
#define RB_AUGMENT(x)	गर {} जबसम्म (0)
#endif

#define RB_ROTATE_बायाँ(head, elm, tmp, field) गर {			\
	(tmp) = RB_दायाँ(elm, field);					\
	यदि ((RB_दायाँ(elm, field) = RB_बायाँ(tmp, field))) {		\
		RB_PARENT(RB_बायाँ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	यदि ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		यदि ((elm) == RB_बायाँ(RB_PARENT(elm, field), field))	\
			RB_बायाँ(RB_PARENT(elm, field), field) = (tmp);	\
		अन्यथा							\
			RB_दायाँ(RB_PARENT(elm, field), field) = (tmp);	\
	} अन्यथा								\
		(head)->rbh_जरा = (tmp);				\
	RB_बायाँ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	यदि ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} जबसम्म (0)

#define RB_ROTATE_दायाँ(head, elm, tmp, field) गर {			\
	(tmp) = RB_बायाँ(elm, field);					\
	यदि ((RB_बायाँ(elm, field) = RB_दायाँ(tmp, field))) {		\
		RB_PARENT(RB_दायाँ(tmp, field), field) = (elm);		\
	}								\
	RB_AUGMENT(elm);						\
	यदि ((RB_PARENT(tmp, field) = RB_PARENT(elm, field))) {		\
		यदि ((elm) == RB_बायाँ(RB_PARENT(elm, field), field))	\
			RB_बायाँ(RB_PARENT(elm, field), field) = (tmp);	\
		अन्यथा							\
			RB_दायाँ(RB_PARENT(elm, field), field) = (tmp);	\
	} अन्यथा								\
		(head)->rbh_जरा = (tmp);				\
	RB_दायाँ(tmp, field) = (elm);					\
	RB_PARENT(elm, field) = (tmp);					\
	RB_AUGMENT(tmp);						\
	यदि ((RB_PARENT(tmp, field)))					\
		RB_AUGMENT(RB_PARENT(tmp, field));			\
} जबसम्म (0)

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
	जबसम्म ((parent = RB_PARENT(elm, field)) &&			\
	    RB_COLOR(parent, field) == RB_RED) {			\
		gparent = RB_PARENT(parent, field);			\
		यदि (parent == RB_बायाँ(gparent, field)) {		\
			tmp = RB_दायाँ(gparent, field);			\
			यदि (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				जारी;				\
			}						\
			यदि (RB_दायाँ(parent, field) == elm) {		\
				RB_ROTATE_बायाँ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_दायाँ(head, gparent, tmp, field);	\
		} अन्यथा {						\
			tmp = RB_बायाँ(gparent, field);			\
			यदि (tmp && RB_COLOR(tmp, field) == RB_RED) {	\
				RB_COLOR(tmp, field) = RB_BLACK;	\
				RB_SET_BLACKRED(parent, gparent, field);\
				elm = gparent;				\
				जारी;				\
			}						\
			यदि (RB_बायाँ(parent, field) == elm) {		\
				RB_ROTATE_दायाँ(head, parent, tmp, field);\
				tmp = parent;				\
				parent = elm;				\
				elm = tmp;				\
			}						\
			RB_SET_BLACKRED(parent, gparent, field);	\
			RB_ROTATE_बायाँ(head, gparent, tmp, field);	\
		}							\
	}								\
	RB_COLOR(head->rbh_जरा, field) = RB_BLACK;			\
}									\
									\
attr शून्य								\
name##_RB_REMOVE_COLOR(संरचना name *head, संरचना type *parent, संरचना type *elm) \
{									\
	संरचना type *tmp;						\
	जबसम्म ((elm == रिक्त || RB_COLOR(elm, field) == RB_BLACK) &&	\
	    elm != RB_जरा(head)) {					\
		यदि (RB_बायाँ(parent, field) == elm) {			\
			tmp = RB_दायाँ(parent, field);			\
			यदि (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_बायाँ(head, parent, tmp, field);\
				tmp = RB_दायाँ(parent, field);		\
			}						\
			यदि ((RB_बायाँ(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_बायाँ(tmp, field), field) == RB_BLACK) &&\
			    (RB_दायाँ(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_दायाँ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अन्यथा {					\
				यदि (RB_दायाँ(tmp, field) == रिक्त ||	\
				    RB_COLOR(RB_दायाँ(tmp, field), field) == RB_BLACK) {\
					संरचना type *oleft;		\
					यदि ((oleft = RB_बायाँ(tmp, field)))\
						RB_COLOR(oleft, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_दायाँ(head, tmp, oleft, field);\
					tmp = RB_दायाँ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				यदि (RB_दायाँ(tmp, field))		\
					RB_COLOR(RB_दायाँ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_बायाँ(head, parent, tmp, field);\
				elm = RB_जरा(head);			\
				रोक;					\
			}						\
		} अन्यथा {						\
			tmp = RB_बायाँ(parent, field);			\
			यदि (RB_COLOR(tmp, field) == RB_RED) {		\
				RB_SET_BLACKRED(tmp, parent, field);	\
				RB_ROTATE_दायाँ(head, parent, tmp, field);\
				tmp = RB_बायाँ(parent, field);		\
			}						\
			यदि ((RB_बायाँ(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_बायाँ(tmp, field), field) == RB_BLACK) &&\
			    (RB_दायाँ(tmp, field) == रिक्त ||		\
			    RB_COLOR(RB_दायाँ(tmp, field), field) == RB_BLACK)) {\
				RB_COLOR(tmp, field) = RB_RED;		\
				elm = parent;				\
				parent = RB_PARENT(elm, field);		\
			} अन्यथा {					\
				यदि (RB_बायाँ(tmp, field) == रिक्त ||	\
				    RB_COLOR(RB_बायाँ(tmp, field), field) == RB_BLACK) {\
					संरचना type *oright;		\
					यदि ((oright = RB_दायाँ(tmp, field)))\
						RB_COLOR(oright, field) = RB_BLACK;\
					RB_COLOR(tmp, field) = RB_RED;	\
					RB_ROTATE_बायाँ(head, tmp, oright, field);\
					tmp = RB_बायाँ(parent, field);	\
				}					\
				RB_COLOR(tmp, field) = RB_COLOR(parent, field);\
				RB_COLOR(parent, field) = RB_BLACK;	\
				यदि (RB_बायाँ(tmp, field))		\
					RB_COLOR(RB_बायाँ(tmp, field), field) = RB_BLACK;\
				RB_ROTATE_दायाँ(head, parent, tmp, field);\
				elm = RB_जरा(head);			\
				रोक;					\
			}						\
		}							\
	}								\
	यदि (elm)							\
		RB_COLOR(elm, field) = RB_BLACK;			\
}									\
									\
attr संरचना type *							\
name##_RB_REMOVE(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *child, *parent, *old = elm;			\
	पूर्णाङ्क color;							\
	यदि (RB_बायाँ(elm, field) == रिक्त)				\
		child = RB_दायाँ(elm, field);				\
	अन्यथा यदि (RB_दायाँ(elm, field) == रिक्त)				\
		child = RB_बायाँ(elm, field);				\
	अन्यथा {								\
		संरचना type *बायाँ;					\
		elm = RB_दायाँ(elm, field);				\
		जबसम्म ((बायाँ = RB_बायाँ(elm, field)))			\
			elm = बायाँ;					\
		child = RB_दायाँ(elm, field);				\
		parent = RB_PARENT(elm, field);				\
		color = RB_COLOR(elm, field);				\
		यदि (child)						\
			RB_PARENT(child, field) = parent;		\
		यदि (parent) {						\
			यदि (RB_बायाँ(parent, field) == elm)		\
				RB_बायाँ(parent, field) = child;		\
			अन्यथा						\
				RB_दायाँ(parent, field) = child;	\
			RB_AUGMENT(parent);				\
		} अन्यथा							\
			RB_जरा(head) = child;				\
		यदि (RB_PARENT(elm, field) == old)			\
			parent = elm;					\
		(elm)->field = (old)->field;				\
		यदि (RB_PARENT(old, field)) {				\
			यदि (RB_बायाँ(RB_PARENT(old, field), field) == old)\
				RB_बायाँ(RB_PARENT(old, field), field) = elm;\
			अन्यथा						\
				RB_दायाँ(RB_PARENT(old, field), field) = elm;\
			RB_AUGMENT(RB_PARENT(old, field));		\
		} अन्यथा							\
			RB_जरा(head) = elm;				\
		RB_PARENT(RB_बायाँ(old, field), field) = elm;		\
		यदि (RB_दायाँ(old, field))				\
			RB_PARENT(RB_दायाँ(old, field), field) = elm;	\
		यदि (parent) {						\
			बायाँ = parent;					\
			गर {						\
				RB_AUGMENT(बायाँ);			\
			} जबसम्म ((बायाँ = RB_PARENT(बायाँ, field)));	\
		}							\
		गच्छ color;						\
	}								\
	parent = RB_PARENT(elm, field);					\
	color = RB_COLOR(elm, field);					\
	यदि (child)							\
		RB_PARENT(child, field) = parent;			\
	यदि (parent) {							\
		यदि (RB_बायाँ(parent, field) == elm)			\
			RB_बायाँ(parent, field) = child;			\
		अन्यथा							\
			RB_दायाँ(parent, field) = child;		\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_जरा(head) = child;					\
color:									\
	यदि (color == RB_BLACK)						\
		name##_RB_REMOVE_COLOR(head, parent, child);		\
	फर्काऊ (old);							\
}									\
									\
/* Inserts a node into the RB tree */					\
attr संरचना type *							\
name##_RB_INSERT(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp;						\
	संरचना type *parent = रिक्त;					\
	पूर्णाङ्क comp = 0;							\
	tmp = RB_जरा(head);						\
	जबसम्म (tmp) {							\
		parent = tmp;						\
		comp = (cmp)(elm, parent);				\
		यदि (comp < 0)						\
			tmp = RB_बायाँ(tmp, field);			\
		अन्यथा यदि (comp > 0)					\
			tmp = RB_दायाँ(tmp, field);			\
		अन्यथा							\
			फर्काऊ (tmp);					\
	}								\
	RB_SET(elm, parent, field);					\
	यदि (parent != रिक्त) {						\
		यदि (comp < 0)						\
			RB_बायाँ(parent, field) = elm;			\
		अन्यथा							\
			RB_दायाँ(parent, field) = elm;			\
		RB_AUGMENT(parent);					\
	} अन्यथा								\
		RB_जरा(head) = elm;					\
	name##_RB_INSERT_COLOR(head, elm);				\
	फर्काऊ (रिक्त);							\
}									\
									\
/* Finds the node with the same key as elm */				\
attr संरचना type *							\
name##_RB_FIND(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_जरा(head);				\
	पूर्णाङ्क comp;							\
	जबसम्म (tmp) {							\
		comp = cmp(elm, tmp);					\
		यदि (comp < 0)						\
			tmp = RB_बायाँ(tmp, field);			\
		अन्यथा यदि (comp > 0)					\
			tmp = RB_दायाँ(tmp, field);			\
		अन्यथा							\
			फर्काऊ (tmp);					\
	}								\
	फर्काऊ (रिक्त);							\
}									\
									\
/* Finds the first node greater than or equal to the search key */	\
attr संरचना type *							\
name##_RB_NFIND(संरचना name *head, संरचना type *elm)			\
{									\
	संरचना type *tmp = RB_जरा(head);				\
	संरचना type *res = रिक्त;					\
	पूर्णाङ्क comp;							\
	जबसम्म (tmp) {							\
		comp = cmp(elm, tmp);					\
		यदि (comp < 0) {						\
			res = tmp;					\
			tmp = RB_बायाँ(tmp, field);			\
		}							\
		अन्यथा यदि (comp > 0)					\
			tmp = RB_दायाँ(tmp, field);			\
		अन्यथा							\
			फर्काऊ (tmp);					\
	}								\
	फर्काऊ (res);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_NEXT(संरचना type *elm)					\
{									\
	यदि (RB_दायाँ(elm, field)) {					\
		elm = RB_दायाँ(elm, field);				\
		जबसम्म (RB_बायाँ(elm, field))				\
			elm = RB_बायाँ(elm, field);			\
	} अन्यथा {							\
		यदि (RB_PARENT(elm, field) &&				\
		    (elm == RB_बायाँ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अन्यथा {							\
			जबसम्म (RB_PARENT(elm, field) &&			\
			    (elm == RB_दायाँ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	फर्काऊ (elm);							\
}									\
									\
/* ARGSUSED */								\
attr संरचना type *							\
name##_RB_PREV(संरचना type *elm)					\
{									\
	यदि (RB_बायाँ(elm, field)) {					\
		elm = RB_बायाँ(elm, field);				\
		जबसम्म (RB_दायाँ(elm, field))				\
			elm = RB_दायाँ(elm, field);			\
	} अन्यथा {							\
		यदि (RB_PARENT(elm, field) &&				\
		    (elm == RB_दायाँ(RB_PARENT(elm, field), field)))	\
			elm = RB_PARENT(elm, field);			\
		अन्यथा {							\
			जबसम्म (RB_PARENT(elm, field) &&			\
			    (elm == RB_बायाँ(RB_PARENT(elm, field), field)))\
				elm = RB_PARENT(elm, field);		\
			elm = RB_PARENT(elm, field);			\
		}							\
	}								\
	फर्काऊ (elm);							\
}									\
									\
attr संरचना type *							\
name##_RB_MINMAX(संरचना name *head, पूर्णाङ्क val)				\
{									\
	संरचना type *tmp = RB_जरा(head);				\
	संरचना type *parent = रिक्त;					\
	जबसम्म (tmp) {							\
		parent = tmp;						\
		यदि (val < 0)						\
			tmp = RB_बायाँ(tmp, field);			\
		अन्यथा							\
			tmp = RB_दायाँ(tmp, field);			\
	}								\
	फर्काऊ (parent);						\
}

#define RB_NEGINF	-1
#define RB_INF	1

#define RB_घुसाउ(name, x, y)	name##_RB_INSERT(x, y)
#define RB_REMOVE(name, x, y)	name##_RB_REMOVE(x, y)
#define RB_FIND(name, x, y)	name##_RB_FIND(x, y)
#define RB_NFIND(name, x, y)	name##_RB_NFIND(x, y)
#define RB_NEXT(name, x, y)	name##_RB_NEXT(y)
#define RB_PREV(name, x, y)	name##_RB_PREV(y)
#define RB_MIN(name, x)		name##_RB_MINMAX(x, RB_NEGINF)
#define RB_MAX(name, x)		name##_RB_MINMAX(x, RB_INF)

#define RB_FOREACH(x, name, head)					\
	लागि ((x) = RB_MIN(name, head);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_NEXT(x))

#define RB_FOREACH_SAFE(x, name, head, y)				\
	लागि ((x) = RB_MIN(name, head);					\
	    ((x) != रिक्त) && ((y) = name##_RB_NEXT(x), 1);		\
	     (x) = (y))

#define RB_FOREACH_REVERSE(x, name, head)				\
	लागि ((x) = RB_MAX(name, head);					\
	     (x) != रिक्त;						\
	     (x) = name##_RB_PREV(x))

#define RB_FOREACH_REVERSE_SAFE(x, name, head, y)			\
	लागि ((x) = RB_MAX(name, head);					\
	    ((x) != रिक्त) && ((y) = name##_RB_PREV(x), 1);		\
	     (x) = (y))

#endif	/* _SYS_TREE_H_ */
