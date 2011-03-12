#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include "sha1.h"
#include "md5.h"
#include "misc.h"
#include "helpers.h"

void printHash(record* r, FILE* file)
{
	int i = 0;
	if (r->hash == SHA1)
	{
		for (i=0; i<20; i++)
			fprintf(file, "%02x", r->hashed_password.sha1[i]);
	}
	else if (r->hash == MD5)
	{
		for (i=0; i<16; i++)
			fprintf(file, "%02x", r->hashed_password.md5[i]);
	}
}

int fileexists(char* filename)
{
	FILE *fp = fopen(filename,"r");
	if (fp)
	{
		fclose(fp);
		return 1;
	}
	else
	{
		return 0;
	}
}

int numOfLines(char* filename)
{
	FILE *f;
	char c;
	int lines = 0;

	f = fopen(filename, "r");

	if(f == NULL)
		return 0;

	while((c = fgetc(f)) != EOF)
		if(c == '\n')
			lines++;

	fclose(f);

	if(c != '\n')
		lines++;

	return lines;
}
