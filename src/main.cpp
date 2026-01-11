
// System Includes
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>

// Includes
#include "types.h"

static inline u32 sr( u32 data, i32 shift )
{
	return ( data >> shift );
}

static inline u32 sl( u32 data, i32 shift )
{
	return ( data << shift );
}

static inline u32 rr( u32 data, i32 rotates )
{
	return ( data >> rotates ) | ( data << ( 32 - rotates ) );
}

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

constexpr const u32 constants[ 4 ] =
{
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xca62c1d6,
};

enum RESULT_CODE
{
	RESULT_CODE_SUCCESS,
	RESULT_CODE_MISSING_ARGUMENTS,
	RESULT_CODE_NOT_A_FILE,
	RESULT_CODE_FAILED_TO_OPEN_FILE,
};

constexpr const u64 SHA1_HASH_BYTES = 20;

struct Sha1Hash
{
	char value[ SHA1_HASH_BYTES ];
};

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

Sha1Hash sha1( const char *dataIn, u64 size )
{
	// 1 byte of 0b10000000 + 8 bytes of the length, &63 = %64, which is 512 bit blocks
	u64 padding = 64 - ( ( size + 1 + 8 ) & 63 );

	std::vector<u8> data;
	data.reserve( size + 1 + 8 + padding );
	data.assign( dataIn, dataIn + size );

	// -- padding --
	data.push_back( 0b10000000 );
	data.resize( data.size() + padding );

	// -- length of message (big endian) --
	u64 bits = size * 8;
	data.push_back( ( bits >> 56 ) & 0xFF );
	data.push_back( ( bits >> 48 ) & 0xFF );
	data.push_back( ( bits >> 40 ) & 0xFF );
	data.push_back( ( bits >> 32 ) & 0xFF );
	data.push_back( ( bits >> 24 ) & 0xFF );
	data.push_back( ( bits >> 16 ) & 0xFF );
	data.push_back( ( bits >>  8 ) & 0xFF );
	data.push_back( ( bits >>  0 ) & 0xFF );

	u32 a = 0x67452301;
	u32 b = 0xefcdab89;
	u32 c = 0x98badcfe;
	u32 d = 0x10325476;
	u32 e = 0xc3d2e1f0;

	u8 *dataByte = data.data();
	u32 words[ 80 ];

	for ( u64 blockIdx = 0, blockCount = ( data.size() / 64 ); blockIdx < blockCount; ++blockIdx )
	{
		// -- message schedule ---
		for ( i32 w = 0; w < 16; ++w )
		{
			u32 d0 = *dataByte++;
			u32 d1 = *dataByte++;
			u32 d2 = *dataByte++;
			u32 d3 = *dataByte++;

			words[ w ] = ( d0 << 24 ) | ( d1 << 16 ) | ( d2 << 8 ) | d3;
		}

		for ( i32 w = 16; w < 80; ++w )
		{
			words[ w ] = rl( words[ w - 3 ] ^ words[ w - 8 ] ^ words[ w - 14 ] ^ words[ w - 16 ], 1 );
		}

		// -- compression --
		u32 h0 = a;
		u32 h1 = b;
		u32 h2 = c;
		u32 h3 = d;
		u32 h4 = e;

		for ( i32 w = 0; w < 80; ++w )
		{
			u32 f = 0;
			u32 k = 0;

			switch ( w / 20 )
			{
			case 0:
				f = choice( b, c, d );
				k = constants[ 0 ];
				break;

			case 1:
				f = parity( b, c, d );
				k = constants[ 1 ];
				break;

			case 2:
				f = majority( b, c, d );
				k = constants[ 2 ];
				break;

			case 3:
				f = parity( b, c, d );
				k = constants[ 3 ];
				break;
			}

			u32 t = rl( a, 5 ) + f + e + k + words[ w ];

			e = d;
			d = c;
			c = rl( b, 30 );
			b = a;
			a = t;
		}

		a += h0;
		b += h1;
		c += h2;
		d += h3;
		e += h4;
	}

	// -- output --
	Sha1Hash hash;
	hash.value[  0 ] = ( a >> 24 ) & 0xFF;
	hash.value[  1 ] = ( a >> 16 ) & 0xFF;
	hash.value[  2 ] = ( a >>  8 ) & 0xFF;
	hash.value[  3 ] = ( a >>  0 ) & 0xFF;
	hash.value[  4 ] = ( b >> 24 ) & 0xFF;
	hash.value[  5 ] = ( b >> 16 ) & 0xFF;
	hash.value[  6 ] = ( b >>  8 ) & 0xFF;
	hash.value[  7 ] = ( b >>  0 ) & 0xFF;
	hash.value[  8 ] = ( c >> 24 ) & 0xFF;
	hash.value[  9 ] = ( c >> 16 ) & 0xFF;
	hash.value[ 10 ] = ( c >>  8 ) & 0xFF;
	hash.value[ 11 ] = ( c >>  0 ) & 0xFF;
	hash.value[ 12 ] = ( d >> 24 ) & 0xFF;
	hash.value[ 13 ] = ( d >> 16 ) & 0xFF;
	hash.value[ 14 ] = ( d >>  8 ) & 0xFF;
	hash.value[ 15 ] = ( d >>  0 ) & 0xFF;
	hash.value[ 16 ] = ( e >> 24 ) & 0xFF;
	hash.value[ 17 ] = ( e >> 16 ) & 0xFF;
	hash.value[ 18 ] = ( e >>  8 ) & 0xFF;
	hash.value[ 19 ] = ( e >>  0 ) & 0xFF;

	return hash;
}

int main( int argc, char *argv[] )
{
	if ( argc <= 1 )
		return RESULT_CODE_MISSING_ARGUMENTS;

	const char *filepath = argv[ 1 ];

	if ( !std::filesystem::is_regular_file( filepath ) )
		return RESULT_CODE_NOT_A_FILE;

	std::ifstream file( filepath, std::ios::binary );
	if ( !file.is_open() )
		return RESULT_CODE_FAILED_TO_OPEN_FILE;

	std::stringstream buffer;
	buffer << file.rdbuf();
	std::string fileData = buffer.str();

	Sha1Hash sha1Result = sha1( fileData.data(), fileData.size() );

	std::cout << sha1Result;

	return RESULT_CODE_SUCCESS;
}