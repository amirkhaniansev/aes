/**
 * GNU General Public License Version 3.0, 29 June 2007
 * 128 AES header file.
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

#ifndef __AES_128_H__
#define __AES_128_H__

#define ROUNDS_NUMBER	((size_t)0xA)
#define NONCE_SIZE		((size_t)0x8)
#define KEY_SIZE		((size_t)0x10)
#define WORD_SIZE		((size_t)0x4)
#define WORDS_COUNT		((size_t)0x44)
#define K_NUMBER		((size_t)0x4)
#define BYTE_SIZE		((size_t)0x8)

char* aes_128_encrypt(char* key, char* nonce, char* data, size_t data_size);

char* aes_128_decrypt(char* key, char* nonce, char* cyphertext, size_t cyphertext_size);

#endif