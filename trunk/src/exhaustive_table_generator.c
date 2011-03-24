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

#define binaryHashMaker hashfun
#define cryptHashTo64bit validfun

void test1(void) {
	int i = 0;
	DEHT *ht;
	if ((ht = create_empty_DEHT("yael10", binaryHashMaker, cryptHashTo64bit, "MD5", 10, 5, 8)) == NULL) {
		printf("failed create\n");
		return;
	}
	if (read_DEHT_pointers_table(ht) == DEHT_STATUS_FAIL) {
		printf("read_DEHT failed\n");
		return;
	}
	if (calc_DEHT_last_block_per_bucket(ht) == DEHT_STATUS_FAIL) {
		printf("calc_DEHT failed\n");
		return;
	}

	for (i = 0; i < 100; i++) {
		char mypassword[14];
		unsigned char hashed[16];
		sprintf(mypassword, "myPassword%d", i);
		MD5BasicHash((unsigned char *) mypassword, strlen(mypassword), hashed);
		if (DEHT_STATUS_SUCCESS != add_DEHT(ht, hashed, 16, (unsigned char *) mypassword, strlen(mypassword))){
			printf("add failed for %s\n", mypassword);
		}
	}

	for (i = 0; i < 100; i++) {
		char mypassword[14];
		unsigned char hashed[16];
		char hashedInHexa[33];
		int err;
		sprintf(mypassword, "myPassword%d", i);
		MD5BasicHash((unsigned char *) mypassword, strlen(mypassword), hashed);
		binary2hexa(hashed, 16, hashedInHexa, 33);
		err = query_DEHT(ht, hashed, 16, (unsigned char *) mypassword, 14);
		switch (err) {
		case DEHT_STATUS_FAIL: {
			printf("error!\n");
			break;
		}
		case DEHT_STATUS_NOT_NEEDED: {
			printf("key - %s - not found!\n", hashedInHexa);
			break;
		}
		default: {
			printf("password for %s: %s\n", hashedInHexa, mypassword);
			break;
		}
		}

	}
	if (write_DEHT_pointers_table(ht) == DEHT_STATUS_FAIL){
		printf("write_DEHT failed!");
	}
	lock_DEHT_files(ht);
	printf("done!");

	/*ht = load_DEHT_from_files("yael8", binaryHashMaker, cryptHashTo64bit);
	 read_DEHT_pointers_table(ht);
	 calc_DEHT_last_block_per_bucket(ht);*/

}

void test2() {
	DEHT *ht;
	int i = 0;
	int num_of_keys = 10000;
	int hash_size = SHA1_OUTPUT_LENGTH_IN_BYTES;
	if ((ht = create_empty_DEHT("golan8", binaryHashMaker, cryptHashTo64bit, "SHA1", 20, 20, 8)) == NULL) {
		printf("failed create\n");
		return;
	}
	read_DEHT_pointers_table(ht);
	calc_DEHT_last_block_per_bucket(ht);
	for (i = 0; i < num_of_keys; i++) {
		char mypassword[25];
		unsigned char hashed[SHA1_OUTPUT_LENGTH_IN_BYTES];
		switch (i % 5) {
		case 0:
			sprintf(mypassword, "myPassword%d", i);
			break;
		case 1:
			sprintf(mypassword, "%dPassword%d", i, i + 1);
			break;
		case 2:
			sprintf(mypassword, "%d", i);
			break;
		case 3:
			sprintf(mypassword, "my other password");
			break;
		case 4:
			sprintf(mypassword, "shnaboob_%d", i);
			break;
		}
		SHA1BasicHash((unsigned char *) mypassword, strlen(mypassword), hashed);
		add_DEHT(ht, hashed, hash_size, (unsigned char *) mypassword, strlen(mypassword));
	}

	for (i = 0; i < num_of_keys; i++) {
		char mypassword[25];
		unsigned char hashed[SHA1_OUTPUT_LENGTH_IN_BYTES];
		char hashedInHexa[33];
		int err;
		switch (i % 5) {
		case 0:
			sprintf(mypassword, "myPassword%d", i);
			break;
		case 1:
			sprintf(mypassword, "%dPassword%d", i, i + 1);
			break;
		case 2:
			sprintf(mypassword, "%d", i);
			break;
		case 3:
			sprintf(mypassword, "my other password");
			break;
		case 4:
			sprintf(mypassword, "shnaboob_%d", i);
			break;
		}

		SHA1BasicHash((unsigned char *) mypassword, strlen(mypassword), hashed);
		binary2hexa(hashed, 16, hashedInHexa, 33);
		err = query_DEHT(ht, hashed, hash_size, (unsigned char *) mypassword, 25);
		switch (err) {
		case DEHT_STATUS_FAIL: {
			printf("error!\n");
			break;
		}
		case DEHT_STATUS_NOT_NEEDED: {
			printf("not found!\n");
			break;
		}
		default: {
			printf("password for %s: %s\n", hashedInHexa, mypassword);
			break;
		}
		}

	}
	write_DEHT_pointers_table(ht);
	lock_DEHT_files(ht);
	printf("done!");

}

void test3() {
	DEHT *ht = load_DEHT_from_files("golan8", binaryHashMaker, cryptHashTo64bit);
	char *pass1 = "my other password";
	char *pass2 = "eran!!!";
	char *pass3 = "shnaboob_199";
	unsigned char hashed1[SHA1_OUTPUT_LENGTH_IN_BYTES];
	unsigned char hashed2[SHA1_OUTPUT_LENGTH_IN_BYTES];
	unsigned char hashed3[SHA1_OUTPUT_LENGTH_IN_BYTES];
	unsigned char data1[17 * 20];
	unsigned char data11[17 * 18];
	unsigned char data111[15 * 10];
	unsigned char *point1[21];
	unsigned char *point11[21];
	unsigned char *point111[6];
	unsigned char data2[8 * 2];
	unsigned char *point2[3];
	unsigned char data3[12 * 2];
	unsigned char *point3[2];

	SHA1BasicHash((unsigned char *) pass1, strlen(pass1), hashed1);
	SHA1BasicHash((unsigned char *) pass2, strlen(pass2), hashed2);
	SHA1BasicHash((unsigned char *) pass3, strlen(pass3), hashed3);

	read_DEHT_pointers_table(ht);
	calc_DEHT_last_block_per_bucket(ht);

	if (mult_query_DEHT(ht, hashed1, SHA1_OUTPUT_LENGTH_IN_BYTES, data1, 17 * 20, point1, 21) == DEHT_STATUS_FAIL)
		printf("error1!");
	else {
		int i;
		printf("my other password res1:\n");
		for (i = 0; i < 20 && point1[i] != 0 && point1[i+1] != 0 ; i++) {
			unsigned char brara[100] = { 0 };
			memcpy(brara, point1[i], point1[i + 1] - point1[i]);
			printf("%d: %s\n", i, brara);
		}
	}

	if (mult_query_DEHT(ht, hashed1, SHA1_OUTPUT_LENGTH_IN_BYTES, data11, 17 * 18, point11, 21) == DEHT_STATUS_FAIL)
		printf("error11!");
	else {
		int i;
		printf("my other password res11:\n");
		for (i = 0; i < 20 && point11[i] != 0 && point11[i+1] != 0; i++) {
			unsigned char brara[100] = { 0 };
			memcpy(brara, point11[i], point11[i + 1] - point11[i]);
			printf("%d: %s\n", i, brara);
		}
	}

	if (mult_query_DEHT(ht, hashed1, SHA1_OUTPUT_LENGTH_IN_BYTES, data111, 15 * 10, point111, 6) == DEHT_STATUS_FAIL)
		printf("error111!");
	else {
		int i;
		printf("my other password res111:\n");
		for (i = 0; i < 5 && point111[i] != 0 && point111[i+1] != 0; i++) {
			unsigned char brara[100] = { 0 };
			memcpy(brara, point111[i], point111[i + 1] - point111[i]);
			printf("%d: %s\n", i, brara);
		}
	}

	if (mult_query_DEHT(ht, hashed2, SHA1_OUTPUT_LENGTH_IN_BYTES, data2, 8 * 2, point2, 3) == DEHT_STATUS_FAIL)
		printf("error2!");
	else {
		int i;
		printf("eran!!!:\n");
		for (i = 0; i < 2 && point2[i] != 0 && point2[i+1] != 0; i++) {
			unsigned char brara[100] = { 0 };
			memcpy(brara, point2[i], point2[i + 1] - point2[i]);
			printf("%d: %s\n", i, brara);
		}
	}

	if (mult_query_DEHT(ht, hashed3, SHA1_OUTPUT_LENGTH_IN_BYTES, data3, 12 * 2, point3, 2) == DEHT_STATUS_FAIL)
		printf("error3!");
	else {
		int i;
		printf("shnabob_199:\n");
		for (i = 0; i < 1 && point3[i] != 0 && point3[i+1] != 0; i++) {
			unsigned char brara[100] = { 0 };
			memcpy(brara, point3[i], point3[i + 1] - point3[i]);
			printf("%d: %s\n", i, brara);
		}
	}

	printf("done!");
}


int main(void)
{
	/*
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
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	memset(databuf, 0, 30);
	len = query_DEHT(deht, keybuf, 20, databuf, 30);
	memset(keybuf, 0 , 20);
	binary2hexa(databuf, len, keybuf, 20);
	printf("data is %s\n", keybuf);
	lock_DEHT_files(deht);

	deht = load_DEHT_from_files("deht", hashfun, validfun);
	datalen = hexa2binary("123456", databuf, 30);
	keylen = hexa2binary("7c4a8d09ca3762af61e59520943dc26494f8941b", keybuf, 20);
	memset(databuf, 0, 30);
	len = query_DEHT(deht, keybuf, 20, databuf, 30);
	memset(keybuf, 0 , 20);
	binary2hexa(databuf, len, keybuf, 20);
	printf("data is %s\n", keybuf);
	*/
	test1();
	test2();
	test3(); /*needs file for test2*/

	return EXIT_SUCCESS;
}
#endif
