/*
 * exhaustive_table_generator.c
 *
 *  Created on: Mar 12, 2011
 *      Author: a
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "helpers.h"
#include "DEHT.h"
#include "rules.h"

#define ELEMENTS_PER_NODE 10

#define binaryHashMaker hashfun
#define cryptHashTo64bit validfun

#ifdef EXHAUSTIVE_TABLE_GENERATOR

int main(int argc, char** argv)
{
	lexicon* lex = NULL;
	DEHT* deht = NULL;
	passgencontext* passgenctx = NULL;
	char* prefix = argv[4];
	char* hashname = argv[3];
	char* lexname = argv[2];
	char* rule = argv[1];
	unsigned int passgensize = 0;
	unsigned long k = 0;
	unsigned long numOfPasswords = 0;
	char pass[MAX_FIELD] = { 0 };
	unsigned long i = 0;
	unsigned long idx = 0;

	enum Hashfunc hashfunc;
	BasicHashFunctionPtr hashptr;
	int hashed_password_len = 0;

	char hashbuf[2*SHA1_OUTPUT_LENGTH_IN_BYTES + 1];

	/* initialize random generator */
	srandom(time(NULL));

	if (argc != 6)
	{
		fprintf(stderr, "Error: Usage exhaustive_table_generator <rule> <lexicon file name> <hash name> <DEHT prefix> <N|all>\n");
		return 1;
	}

	if(strcmp("SHA1",hashname)==0)
	{
		hashfunc = SHA1;
		hashptr = SHA1BasicHash;
		hashed_password_len = SHA1_OUTPUT_LENGTH_IN_BYTES;
	}
	else if(strcmp("MD5",hashname)==0)
	{
		hashfunc = MD5;
		hashptr = MD5BasicHash;
		hashed_password_len = MD5_OUTPUT_LENGTH_IN_BYTES;
	}
	else
	{
		fprintf(stderr, "Error: Hash \"%s\" is not supported\n", hashname);
		return 1;
	}

	if (strcmp(argv[5], "all") != 0)
		k = atol(argv[5]);

	deht = create_empty_DEHT(prefix, hashfun, validfun, hashname, 65536, ELEMENTS_PER_NODE, 8);

	if (!deht)
		return 1;

	lex = preprocessLexicon(lexname);
	if(!lex)
	{
		lock_DEHT_files(deht);
		return 1;
	}
	passgenctx = createrule(rule, lex, &passgensize);
	if (!passgenctx)
	{
		freelex(lex);
		lock_DEHT_files(deht);
		return 1;
	}

	// all is specified
	if (k == 0)
		numOfPasswords = passgenctx->numOfPasswords - 1; // ignore the empty password
	else
		numOfPasswords = k;

	for(i = 0; i < numOfPasswords; i++)
	{
		idx = (k == 0 ? i + 1: random() % (passgenctx->numOfPasswords - 1) + 1);
		generatePassword(passgenctx, lex, idx, pass);
		hashptr((unsigned char*)pass, strlen(pass), (unsigned char*)hashbuf);
		// keylen = hexa2binary(hashbuf, keybuf, SHA1_OUTPUT_LENGTH_IN_BYTES);
#ifdef DEBUG
		printf("The %luth password (out of %lu) for %s is %s\n", idx, passgenctx->numOfPasswords, rule, pass);
#endif
		if (DEHT_STATUS_SUCCESS != add_DEHT(deht, (unsigned char*)hashbuf, hashed_password_len, (unsigned char*)pass, strlen(pass)))
		{
			break;
		}
	}

	lock_DEHT_files(deht);
	freerule(passgenctx);
	freelex(lex);
	return EXIT_SUCCESS;
}
#endif
