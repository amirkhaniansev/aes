/**
 * GNU General Public License Version 3.0, 29 June 2007
 * Implemenation of 128 bit AES.
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
#include <string.h>

#include "../include/aes_128.h"

static char c_x[4][4] =
{
	{ 0x2, 0x3, 0x1, 0x1 },
	{ 0x1, 0x2, 0x3, 0x1 },
	{ 0x1, 0x1, 0x2, 0x3 },
	{ 0x3, 0x1, 0x1, 0x2 }
};

static char sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static char rcon[11][4] = {
	{ 0x00, 0x00, 0x00, 0x00 },
	{ 0x01, 0x00, 0x00, 0x00 },
	{ 0x02, 0x00, 0x00, 0x00 },
	{ 0x04, 0x00, 0x00, 0x00 },
	{ 0x08, 0x00, 0x00, 0x00 },
	{ 0x10, 0x00, 0x00, 0x00 },
	{ 0x20, 0x00, 0x00, 0x00 },
	{ 0x40, 0x00, 0x00, 0x00 },
	{ 0x80, 0x00, 0x00, 0x00 },
	{ 0x1b, 0x00, 0x00, 0x00 },
	{ 0x36, 0x00, 0x00, 0x00 } 
};

static inline void rot_word(char* word)
{
	char temp = word[0];	
	for (size_t i = 0; i < WORD_SIZE - 1; i++)
		word[i] = word[i + 1];
	word[WORD_SIZE - 1] = temp;
}

static inline void sub_word(char* word)
{
	for (size_t i = 0; i < WORD_SIZE; i++)
		word[i] = sbox[word[i]];
}

static inline void assign_word(char* left, char* right)
{
	for (size_t i = 0; i < WORD_SIZE; i++)
		left[i] = right[i];
}

static inline void xor_word(char* result, char* left, char* right)
{
	for (size_t i = 0; i < WORD_SIZE; i++)
		result[i] = left[i] ^ right[i];
}

static inline char* word(char* arr, size_t index)
{
	return arr + WORD_SIZE * index;
}

static inline char* round_key(char* expansion, size_t round)
{
	return expansion + round * WORD_SIZE * K_NUMBER;
}

static inline void add_round_key(char* state, char* expansion, size_t round)
{
	char* r_key = round_key(expansion, round);
	for (size_t i = 0; i < K_NUMBER; i++)
		for (size_t j = 0; j < WORD_SIZE; j++)
			state[4 * i + j] ^= r_key[4 * j + i];
}

static inline void sub_bytes(char* state)
{
	for (size_t i = 0; i < K_NUMBER; i++)
		for (size_t j = 0; j < K_NUMBER; j++)
			state[4 * i + j] = sbox[state[4 * i + j]];
}

static inline void shift_rows(char* state)
{
	for (size_t i = 1; i < K_NUMBER; i++)
		for (size_t j = 0; j < i; j++)
			rot_word(state + 4 * i);
}

static inline char mul(char left, char right)
{
	char res = 0;
	for (size_t i = 0; i < BYTE_SIZE; i++) {
		if ((right & 1) != 0)
			res ^= left;

		left <<= 1;
		if ((left & 0x80) != 0)
			left ^= 0x11B;
		right >>= 1;
	}
	return res;
}

static inline void mix_columns(char* state)
{
	for (size_t i = 0; i < K_NUMBER; i++)
		for (size_t j = 0; j < K_NUMBER; j++)
			state[4 * j + i] ^= mul(c_x[i][j], state[4 * j + i]);
}

static inline char* expand_key(char* key)
{
	char* expansion = malloc(WORDS_COUNT * WORD_SIZE);
	if (expansion == NULL)
		return NULL;

	for (size_t i = 0; i < K_NUMBER; i++)
		assign_word(expansion + 4 * i, key + 4 * i);

	char temp[4];
	for (size_t i = K_NUMBER; i < WORDS_COUNT; i++) {
		assign_word(temp, word(expansion, i - 1));
		
		if (i % K_NUMBER == 0) {
			rot_word(temp);
			xor_word(temp, temp, rcon[i / K_NUMBER]);
			sub_word(temp);
		}

		xor_word(temp, word(expansion, i - K_NUMBER), temp);
		assign_word(word(expansion, i), temp);
	}

	return expansion;
}

static inline void block_cypher(char* cyphertext, char* expansion, char* nonce_counter, size_t counter)
{
	char* state = cyphertext + counter * KEY_SIZE;
	for (size_t i = 0; i < KEY_SIZE; i++)
		state[i] = nonce_counter[i];

	add_round_key(state, expansion, 0);

	for (size_t i = 0; i < ROUNDS_NUMBER; i++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, expansion, i);
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, expansion, ROUNDS_NUMBER);
 }

static inline void assign_counter(char* nonce_counter, size_t counter)
{
	size_t temp = counter;
	size_t size = sizeof(size_t);
	size_t i = KEY_SIZE - 1;
	while (temp != 0) {
		nonce_counter[i--] = (char)(temp & 0xFF);
		temp >>= BYTE_SIZE;
	}
}

static inline void xor_with_block(char* cypher,  char* data)
{
	for (size_t i = 0; i < KEY_SIZE; i++)
		cypher[i] ^= data[i];
}

static inline void block(char* nonc_counter, char* cyphertext, char* expansion, char* data, size_t counter)
{
	assign_counter(nonc_counter, counter);
	block_cypher(cyphertext, expansion, nonc_counter, counter);
	xor_with_block(cyphertext + KEY_SIZE * counter, data + KEY_SIZE * counter);
}

char* aes_128_encrypt(char* key, char* nonce, char* data, size_t data_size)
{
	if (key == NULL || data == NULL || nonce == NULL || data_size <= 0)
		return NULL;

	size_t cyphertext_size = data_size + 2 * KEY_SIZE - data_size % KEY_SIZE;
	char* cyphertext = malloc(cyphertext_size);
	if (cyphertext == NULL)
		return NULL;

	char* nonce_counter = malloc(KEY_SIZE);
	if (nonce_counter == NULL) {
		free(cyphertext);
		return NULL;
	}

	char* expansion = expand_key(key);
	if (expansion == NULL) {
		free(cyphertext);
		free(nonce_counter);
		return NULL;
	}

	for (size_t i = 0; i < NONCE_SIZE; i++)
		nonce_counter[i] = nonce[i];

	size_t block_count = cyphertext_size / KEY_SIZE;
	for (size_t i = 0; i < block_count - 1; i++)
		block(nonce_counter, cyphertext, expansion, data, i);

	free(nonce_counter);
	free(expansion);
	return cyphertext;
}

char* aes_128_decrypt(char* key, char* nonce, char* cyphertext, size_t cyphertext_size)
{
	if (key == NULL ||
		cyphertext == NULL ||
		nonce == NULL ||
		cyphertext_size <= 0 ||
		cyphertext_size % KEY_SIZE != 0)
		return NULL;

	char* expansion = expand_key(key);
	if (expansion == NULL)
		return NULL;

	char* nonce_counter = malloc(KEY_SIZE);
	if (nonce_counter == NULL) {
		free(expansion);
		return NULL;
	}

	char* original = malloc(cyphertext_size);
	if (original == NULL) {
		free(expansion);
		free(nonce_counter);
		return NULL;
	}
		
	for (size_t i = 0; i < cyphertext_size; i++)
		original[i] = cyphertext[i];

	size_t block_count = cyphertext_size / KEY_SIZE;
	for (size_t i = 0; i < block_count - 1; i++)
		block(nonce_counter, original, expansion, cyphertext, i);

	free(expansion);
	free(nonce_counter);
	return original;
}