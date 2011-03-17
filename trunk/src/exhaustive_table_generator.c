/*
 * exhaustive_table_generator.c
 *
 *  Created on: Mar 12, 2011
 *      Author: a
 */

#include <stdio.h>
#include <stdlib.h>
#include "helpers.h"
#include "DEHT.h"

#define ELEMENTS_PER_NODE 10

#ifdef EXHAUSTIVE_TABLE_GENERATOR
int main(void)
{
	int i = 0, len = 0, datalen = 0, keylen = 0;
	DEHT* deht = create_empty_DEHT("deht", hashfun, validfun, "SHA1", 65536, ELEMENTS_PER_NODE, 8);
	char* keybuf = calloc(1, 20);
	char* databuf = calloc(1, 30);
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	add_DEHT(deht, keybuf, keylen, databuf, datalen);

	for (i=0; i<11; i++)
	{
		datalen = hexa2binary("65432100", databuf, 30);
		keylen = hexa2binary("dd5fef9c1c1da1394d6d34b248c51be2ad740840", keybuf, 20);
		add_DEHT(deht, keybuf, keylen, databuf, datalen);
	}
	write_DEHT_pointers_table(deht);
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	memset(databuf, 0, 30);
	len = query_DEHT(deht, keybuf, 20, databuf, 30);
	memset(keybuf, 0 , 20);
	binary2hexa(databuf, len, keybuf, 20);
	printf("data is %s\n", keybuf);
	return EXIT_SUCCESS;
}
#endif
