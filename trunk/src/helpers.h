#ifndef HELPERS_H
#define HELPERS_H

#define _GNU_SOURCE
#include "misc.h"
#include "stdio.h"
#include <stdlib.h>

 /* #define CREATE_AUTHENTICATION */
#define AUTHENTICATE
/* #define RULES_PREPROCESS
#define EXHAUSTIVE_TABLE_GENERATOR
#define EXHAUSTIVE_QUERY
#define CREATE_RAINBOW_TABLE
#define CRACK_USING_RAINBOW_TABLE
*/

#define MD5_OUTPUT_LENGTH_IN_BYTES    16
#define SHA1_OUTPUT_LENGTH_IN_BYTES   20

#define MAX_FIELD 255
#define MAX_INPUT (MAX_FIELD + MAX_FIELD + 2)

#define CMD_QUIT 0
#define CMD_CONTINUE 1
#define CMD_VALID 2

#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))

#define PARAM_INVALID 0
#define PARAM_LEXNAME 1
#define PARAM_CHAIN_LENGTH 2
#define PARAM_NUM_OF_HASH_ENTRIES 3
#define PARAM_ELEMS_IN_BUCKET 4
#define PARAM_RULE 5
#define PARAM_MAIN_RAND_SEED 6
#define PARAM_HASH_FUNCTION 7
#define PARAM_OUTPUT_FILE_PREFIX 8

typedef struct rainbow_settings_struct {
	char 			LexiconName[MAX_INPUT];
	unsigned int 	ChainLength;
	unsigned int 	NumOfHashEnries;
	unsigned int 	ElementsInBucket;
	char			Rule[MAX_INPUT];
	char			MainRandSeed[MAX_INPUT];
	char			HashFunction[MAX_INPUT];
	BasicHashFunctionPtr hashptr;
	unsigned int 	hashed_password_len;
	char 			OutputFilePrefix[MAX_INPUT];
} rainbow_settings;

enum Hashfunc {
	MD5,
	SHA1
};

typedef struct record_tag {
	enum Hashfunc hash;
	BasicHashFunctionPtr hashptr;
	char username[MAX_FIELD];
	char password[MAX_FIELD];
	union {
		unsigned char md5[MD5_OUTPUT_LENGTH_IN_BYTES];
		unsigned char sha1[SHA1_OUTPUT_LENGTH_IN_BYTES];
	} hashed_password;
	unsigned int hashed_password_len;
} record;

void printHash(record* r, FILE* file);
int fileexists(char* filename);
int numOfLines(char* filename);
int readLineFromUser(record* newuser);
int readHashFromUser(char* hashedpass);
int parseSettings(rainbow_settings* settings, char* inipath);
#endif
