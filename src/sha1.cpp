
#include <iostream>
#include <filesystem>
#include <fstream>

#include "sha1.h"

static inline u32 rl( u32 data, i32 rotates )
{
	return ( data << rotates ) | ( data >> ( 32 - rotates ) );
}

static inline u32 choice( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) | ( ~data0 & data2 );
}

static inline u32 parity( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 ^ data1 ) ^ data2;
}

static inline u32 majority( u32 data0, u32 data1, u32 data2 )
{
	return ( data0 & data1 ) ^ ( data0 & data2 ) ^ ( data1 & data2 );
}

struct Sha1Context
{
	const u8 *data;
	u32 a;
	u32 b;
	u32 c;
	u32 d;
	u32 e;
};

static Sha1Hash sha1_create_hash( Sha1Context *context )
{
	Sha1Hash hash;
	hash.value[  0 ] = ( context->a >> 24 ) & 0xFF;
	hash.value[  1 ] = ( context->a >> 16 ) & 0xFF;
	hash.value[  2 ] = ( context->a >>  8 ) & 0xFF;
	hash.value[  3 ] = ( context->a >>  0 ) & 0xFF;
	hash.value[  4 ] = ( context->b >> 24 ) & 0xFF;
	hash.value[  5 ] = ( context->b >> 16 ) & 0xFF;
	hash.value[  6 ] = ( context->b >>  8 ) & 0xFF;
	hash.value[  7 ] = ( context->b >>  0 ) & 0xFF;
	hash.value[  8 ] = ( context->c >> 24 ) & 0xFF;
	hash.value[  9 ] = ( context->c >> 16 ) & 0xFF;
	hash.value[ 10 ] = ( context->c >>  8 ) & 0xFF;
	hash.value[ 11 ] = ( context->c >>  0 ) & 0xFF;
	hash.value[ 12 ] = ( context->d >> 24 ) & 0xFF;
	hash.value[ 13 ] = ( context->d >> 16 ) & 0xFF;
	hash.value[ 14 ] = ( context->d >>  8 ) & 0xFF;
	hash.value[ 15 ] = ( context->d >>  0 ) & 0xFF;
	hash.value[ 16 ] = ( context->e >> 24 ) & 0xFF;
	hash.value[ 17 ] = ( context->e >> 16 ) & 0xFF;
	hash.value[ 18 ] = ( context->e >>  8 ) & 0xFF;
	hash.value[ 19 ] = ( context->e >>  0 ) & 0xFF;
	return hash;
}

static void sha1_process_block( Sha1Context *context )
{
	u32 words[ 80 ];

	const u8 *data = context->data;

	// -- message schedule ---
	for ( i32 w = 0; w < 16; ++w )
	{
		u32 d0 = *data++;
		u32 d1 = *data++;
		u32 d2 = *data++;
		u32 d3 = *data++;

		words[ w ] = ( d0 << 24 ) | ( d1 << 16 ) | ( d2 << 8 ) | d3;
	}

	for ( i32 w = 16; w < 80; ++w )
	{
		words[ w ] = rl( words[ w - 3 ] ^ words[ w - 8 ] ^ words[ w - 14 ] ^ words[ w - 16 ], 1 );
	}

	// -- compression --
	u32 a = context->a;
	u32 b = context->b;
	u32 c = context->c;
	u32 d = context->d;
	u32 e = context->e;

	for ( i32 w = 0; w < 20; ++w )
	{
		u32 t = rl( a, 5 ) + choice( b, c, d ) + e + 0x5a827999 + words[ w ];

		e = d;
		d = c;
		c = rl( b, 30 );
		b = a;
		a = t;
	}

	for ( i32 w = 20; w < 40; ++w )
	{
		u32 t = rl( a, 5 ) + parity( b, c, d ) + e + 0x6ed9eba1 + words[ w ];

		e = d;
		d = c;
		c = rl( b, 30 );
		b = a;
		a = t;
	}

	for ( i32 w = 40; w < 60; ++w )
	{
		u32 t = rl( a, 5 ) + majority( b, c, d ) + e + 0x8f1bbcdc + words[ w ];

		e = d;
		d = c;
		c = rl( b, 30 );
		b = a;
		a = t;
	}

	for ( i32 w = 60; w < 80; ++w )
	{
		u32 t = rl( a, 5 ) + parity( b, c, d ) + e + 0xca62c1d6 + words[ w ];

		e = d;
		d = c;
		c = rl( b, 30 );
		b = a;
		a = t;
	}

	context->a += a;
	context->b += b;
	context->c += c;
	context->d += d;
	context->e += e;
}

Sha1Hash sha1( const u8 *data, u64 size )
{
	Sha1Context context =
	{
		.a = 0x67452301,
		.b = 0xefcdab89,
		.c = 0x98badcfe,
		.d = 0x10325476,
		.e = 0xc3d2e1f0,
	};

	// -- full blocks --
	for ( u64 blockIdx = 0, blockCount = size / 64; blockIdx < blockCount; ++blockIdx )
	{
		context.data = data;
		sha1_process_block( &context );
		data += 64;
	}

	// -- final blocks --
	u8 finalBlocks[ 64 * 2 ];
	u64 finalBlockSize = size & 63;
	memcpy( finalBlocks, data, finalBlockSize );

	finalBlocks[ finalBlockSize++ ] = 0b10000000;

	// 1 byte of 0b10000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
	u64 padding = 64 - ( ( size + 1 + 8 ) & 63 );
	memset( &finalBlocks[ finalBlockSize ], 0, padding );
	finalBlockSize += padding;

	// -- length of message (big endian) --
	u64 bits = size * 8;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 56 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 48 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 40 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 32 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 24 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >> 16 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >>  8 ) & 0xFF;
	finalBlocks[ finalBlockSize++ ] = ( bits >>  0 ) & 0xFF;

	context.data = finalBlocks;
	sha1_process_block( &context );

	if ( finalBlockSize > 64 )
	{
		context.data = finalBlocks + 64;
		sha1_process_block( &context );
	}

	// -- output --
	return sha1_create_hash( &context );
}

Sha1Hash sha1( const char *filepath, i32 *errorCode )
{
	if ( errorCode )
		*errorCode = 0;

	if ( !std::filesystem::is_regular_file( filepath ) )
	{
		if ( errorCode )
			*errorCode = 2;
		return {};
	}

	std::ifstream file( filepath, std::ios::binary );
	if ( !file )
	{
		if ( errorCode )
			*errorCode = 3;
		return {};
	}

	u8 buffer[ 64 * 2 ];
	u64 totalBytes = 0;

	Sha1Context context =
	{
		.data = buffer,
		.a = 0x67452301,
		.b = 0xefcdab89,
		.c = 0x98badcfe,
		.d = 0x10325476,
		.e = 0xc3d2e1f0,
	};

	while ( file.read( (char *)buffer, 64 ) || file.gcount() >= 0 )
	{
		std::streamsize bytesRead = file.gcount();

		if ( bytesRead == 64 )
		{
			// -- full blocks --
			sha1_process_block( &context );
			totalBytes += bytesRead;
		}
		else
		{
			// -- final blocks --
			totalBytes += bytesRead;

			buffer[ bytesRead++ ] = 0b10000000;

			// 1 byte of 0b10000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
			u64 padding = 64 - ( ( totalBytes + 1 + 8 ) & 63 );
			memset( &buffer[ bytesRead ], 0, padding );
			bytesRead += padding;

			// -- length of message (big endian) --
			u64 bits = totalBytes * 8;
			buffer[ bytesRead++ ] = ( bits >> 56 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 48 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 40 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 32 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 24 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >> 16 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >>  8 ) & 0xFF;
			buffer[ bytesRead++ ] = ( bits >>  0 ) & 0xFF;

			sha1_process_block( &context );

			if ( bytesRead > 64 )
			{
				context.data = buffer + 64;
				sha1_process_block( &context );
			}

			break;
		}
	}

	// -- output --
	return sha1_create_hash( &context );
}

std::ostream & operator << ( std::ostream &out, const Sha1Hash &hash )
{
	constexpr char hex[] = "0123456789abcdef";
	for ( i32 i = 0; i < SHA1_HASH_BYTES; ++i )
	{
		u8 v = hash.value[ i ];
		out << hex[ ( v >> 4 ) & 15 ] << hex[ v & 15 ];
	}
	return out;
}