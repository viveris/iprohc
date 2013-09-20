/*
This file is part of iprohc.

iprohc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.

iprohc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with iprohc.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Inline functions
 */

/**
 * @brief In-place change the byte order in a two-byte value.
 *
 * @param value The two-byte value to modify
 * @return      The same value with the byte order changed
 */
static inline uint16_t swab16(uint16_t value)
{
	return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}


#ifdef __i386__

/**
 * @brief This is a version of ip_compute_csum() optimized for IP headers,
 *        which always checksum on 4 octet boundaries.
 *
 * @author Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *         Arnt Gulbrandsen.
 *
 * @param iph The IPv4 header
 * @param ihl The length of the IPv4 header
 * @return    The IPv4 checksum
 */
static inline unsigned short ip_fast_csum(unsigned char *iph, unsigned int ihl)
{
	unsigned int sum;

	__asm__ __volatile__ (
	   " \n\
       movl (%1), %0      \n\
       subl $4, %2		\n\
       jbe 2f		\n\
       addl 4(%1), %0	\n\
       adcl 8(%1), %0	\n\
       adcl 12(%1), %0	\n\
1:     adcl 16(%1), %0	\n\
       lea 4(%1), %1	\n\
       decl %2		\n\
       jne 1b		\n\
       adcl $0, %0		\n\
       movl %0, %2		\n\
       shrl $16, %0	\n\
       addw %w2, %w0	\n\
       adcl $0, %0		\n\
       notl %0		\n\
2:     \n\
       "
	   /* Since the input registers which are loaded with iph and ipl
	      are modified, we must also specify them as outputs, or gcc
	      will assume they contain their original values. */
		: "=r" (sum), "=r" (iph), "=r" (ihl)
		: "1" (iph), "2" (ihl));

	return(sum);
}


#else

static inline unsigned short from32to16(unsigned long x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}


static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd, count;
	unsigned long result = 0;

	if(len <= 0)
	{
		goto out;
	}
	odd = 1 & (unsigned long) buff;
	if(odd)
	{
#ifdef __LITTLE_ENDIAN
		result = *buff;
#else
		result += (*buff << 8);
#endif
		len--;
		buff++;
	}
	count = len >> 1;        /* nr of 16-bit words.. */
	if(count)
	{
		if(2 & (unsigned long) buff)
		{
			result += *(unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;          /* nr of 32-bit words.. */
		if(count)
		{
			unsigned long carry = 0;
			do
			{
				unsigned long w = *(unsigned int *) buff;
				count--;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			}
			while(count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if(len & 2)
		{
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if(len & 1)
#ifdef __LITTLE_ENDIAN
	{ result += *buff; }
#else
	{ result += (*buff << 8); }
#endif
	result = from32to16(result);
	if(odd)
	{
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
out:
	return result;
}


/**
 *  This is a version of ip_compute_csum() optimized for IP headers,
 *  which always checksum on 4 octet boundaries.
 */
static inline uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (uint16_t) ~do_csum(iph, ihl * 4);
}


#endif

