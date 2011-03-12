#ifndef HELPERS_H
#define HELPERS_H

#include "misc.h"
#include "stdio.h"

// #define CREATE_AUTHENTICATION
// #define AUTHENTICATE
// #define RULES_PREPROCESS
#define EXHAUSTIVE_TABLE_GENERATOR

#define MD5_OUTPUT_LENGTH_IN_BYTES    16
#define SHA1_OUTPUT_LENGTH_IN_BYTES   20

#define MAX_FIELD 255
#define MAX_INPUT (MAX_FIELD + MAX_FIELD + 2)

#define CMD_QUIT 0
#define CMD_CONTINUE 1
#define CMD_VALID 2

#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))

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
#endif
