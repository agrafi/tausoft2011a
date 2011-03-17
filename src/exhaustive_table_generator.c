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
	int i = 0;
	DEHT* deht = create_empty_DEHT("deht", hashfun, validfun, "SHA1", 65536, ELEMENTS_PER_NODE, 8);
	char* keybuf = calloc(1, 20);
	char* databuf = calloc(1, 30);
	snprintf(databuf, sizeof(databuf), "%s", "123456");
	hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, sizeof(keybuf));
	add_DEHT(deht, keybuf, sizeof(keybuf), databuf, strlen(databuf));

	for (i=0; i<10; i++)
	{
		snprintf(databuf, sizeof(databuf), "%s", "6543210");
		hexa2binary("dd5fef9c1c1da1394d6d34b248c51be2ad740840", keybuf, sizeof(keybuf));
		add_DEHT(deht, keybuf, sizeof(keybuf), databuf, strlen(databuf));
	}
	write_DEHT_pointers_table(deht);
	return EXIT_SUCCESS;
}
#endif
