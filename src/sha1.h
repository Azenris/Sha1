
#pragma once

#include <iosfwd>

#include "types.h"

constexpr const u64 SHA1_HASH_BYTES = 20;

struct Sha1Hash
{
	char value[ SHA1_HASH_BYTES ];
};

Sha1Hash sha1( const u8 *data, u64 size );

inline Sha1Hash sha1( const char *data, u64 size )
{
	return sha1( reinterpret_cast<const u8*>( data ), size );
}

Sha1Hash sha1( const char *filepath, i32 *errorCode = nullptr );

std::ostream & operator << ( std::ostream &out, const Sha1Hash &hash );