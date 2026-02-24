/*
--------------------------------------------------------------------
lookup2.c, by Bob Jenkins, December 1996, Public Domain.
hash(), hash2(), hash3, and mix() are externally useful functions.
Routines to test the hash are included if SELF_TEST is defined.
You can use this free for any purpose.  It has no warranty.

Obsolete.  Use lookup3.c instead, it is faster and more thorough.
--------------------------------------------------------------------
*/
/*
* source of the below macro and function defintion from the below link
* http://burtleburtle.net/bob/c/lookup2.c
*/
#ifndef BOBJENKINS_HASH_H
#define BOBJENKINS_HASH_H  1

/*
By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^32 is
acceptable.  Do NOT use for cryptographic purposes.
*/


#define mix(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c >> 13); \
	b -= c; b -= a; b ^= (a << 8); \
	c -= a; c -= b; c ^= (b >> 13); \
	a -= b; a -= c; a ^= (c >> 12);  \
	b -= c; b -= a; b ^= (a << 16); \
	c -= a; c -= b; c ^= (b >> 5); \
	a -= b; a -= c; a ^= (c >> 3);  \
	b -= c; b -= a; b ^= (a << 10); \
	c -= a; c -= b; c ^= (b >> 15); \
}

#define HASH_INITVAL	0x9e3779b9

static uint32_t compute_jenkins_hash(uint8_t *k, uint32_t length, uint32_t initval) __attribute__((unused));
static uint32_t compute_jenkins_hash(uint8_t *k, uint32_t length, uint32_t initval)
{
	uint32_t a, b, c, len;

	/* Set up the internal state */
	len = length;
	a = b = HASH_INITVAL;  /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/* handle most of the key */
	while (len >= 12)
	{
		a += (k[0] +((uint32_t)k[1] << 8) + ((uint32_t)k[2] << 16) + 
			((uint32_t)k[3] << 24));
		b += (k[4] +((uint32_t)k[5] << 8) + ((uint32_t)k[6] << 16) + 
			((uint32_t)k[7] << 24));
		c += (k[8] +((uint32_t)k[9] << 8) + ((uint32_t)k[10] << 16) + 
			((uint32_t)k[11] << 24));
		mix(a, b, c);
		k += 12; len -= 12;
	}

	/* handle the last few bytes */
	c += length;
	switch(len)              /* all the case statements fall through */
	{
		case 11: 
			c+=((uint32_t)k[10] <<24);
            /* fall through */
		case 10: 
			c+=((uint32_t)k[9] <<16);
            /* fall through */
		case 9 : 		
			c+=((uint32_t)k[8] <<8);
            /* fall through */
		/* the first byte of c is reserved for the length */
		case 8 : 
			b+=((uint32_t)k[7] <<24);
            /* fall through */
		case 7 : 
			b+=((uint32_t)k[6] <<16);
            /* fall through */
		case 6 : 
			b+=((uint32_t)k[5] <<8);
            /* fall through */
		case 5 : 
			b+=k[4];
            /* fall through */
		case 4 : 
			a+=((uint32_t)k[3] <<24);
            /* fall through */
		case 3 : 
			a+=((uint32_t)k[2] <<16);
            /* fall through */
		case 2 : 
			a+=((uint32_t)k[1] <<8);
            /* fall through */
		case 1 : 
			a+=k[0];
		/* case 0: nothing left to add */
	}
	mix(a, b, c);
	return c;
}

#endif

