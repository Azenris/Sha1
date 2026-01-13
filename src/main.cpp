
// System Includes
#include <iostream>

// Includes
#include "sha1.h"

int main( int argc, char *argv[] )
{
	if ( argc <= 1 )
		return 1;

	const char *filepath = argv[ 1 ];

	Sha1Hash sha1Result = sha1( filepath );

	std::cout << sha1Result;

	return 0;
}