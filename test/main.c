/**
 * GNU General Public License Version 3.0, 29 June 2007
 * Test for 128 bit AES.
 * Copyright (C) <2019>
 *      Authors: <amirkhaniansev>  <amirkhanyan.sevak@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Full notice : https://github.com/amirkhaniansev/aes/tree/master/LICENSE
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "../include/aes_128.h"

static inline char* s_random(size_t size)
{
	char* random = malloc(size);
	if (random == NULL)
		return NULL;

	srand((unsigned int)time(NULL));
	for (size_t i = 0; i < size; i++)
		* (random + i) = rand() % 0xFF;

	return random;
}

int main(int argc, char** argv)
{
    for (size_t i = 0; i < 10; i++)
	{
		char* nonce = s_random(NONCE_SIZE);
		char* key = s_random(KEY_SIZE);

		char plaintext[] = "Jeremy Thorpe (29 April 1929 – 4 December 2014) was a British politician\
						who served as Member of Parliament for North Devon from 1959 to 1979, and\
						as leader of the Liberal Party between 1967 and 1976. After graduating\
					    from Oxford University, he became one of the Liberals' brightest stars in\
						the 1950s. As party leader, Thorpe capitalised on the growing unpopularity\
						of the Conservative and Labour parties to lead the Liberals through a period \
						of electoral success. This culminated in the general election of February 1974.";

		size_t size = sizeof(plaintext) / sizeof(plaintext[0x0]);

        printf("ORIGINAL : %s\n", plaintext);

		char* cyphertext = aes_128_encrypt(key, nonce, plaintext, size);
        printf("CYPHERTEXT : %s\n", cyphertext);

		char* original = aes_128_decrypt(key, nonce, cyphertext, 576);
        printf("ORIGINAL : %s\n", original);

		free(nonce);
		free(key);
		free(cyphertext);
		free(original); 
	}

    return 0;
}