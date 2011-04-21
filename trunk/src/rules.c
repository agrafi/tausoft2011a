/*
 * rules.c
 *
 *  Created on: Mar 2, 2011
 *      Author: a
 */

#include "rules.h"
#include "helpers.h"
#include <math.h>
#include <ctype.h>
#include <stdlib.h>

void freerule(passgencontext* ctx)
{
	int i = 0, j = 0;

	if (!ctx)
		return;

	for (i = 0; i < ctx->numOfTerms; i++)
	{
		for (j = 0; j < ctx->terms[i].numOfBlocks; j++)
		{
			if (ctx->terms[i].blocks[j].cells)
				free(ctx->terms[i].blocks[j].cells);
		}
		if (ctx->terms[i].blocks)
			free(ctx->terms[i].blocks);
	}
	if (ctx->terms)
		free(ctx->terms);
	free(ctx);
	return;
}

passgencontext* createrule(char* rule, lexicon* lex, unsigned int* passgensize)
{
	/* scan expression and determine passcell array size */
	int i = 0, counter = 0, j = 0, t = 0;
	unsigned long mul = 1;
	unsigned long mul_prev = 1;
	char* expression = NULL;
	char* current = NULL;

	passblock* passgen = NULL;
	passgencontext* retcontext = calloc(1, sizeof(passgencontext));
	if (!retcontext)
	{
		return NULL;
	}

	retcontext->numOfTerms = 1;
	memcpy(retcontext->rule, rule, strlen(rule) + 1);
	expression = retcontext->rule;
	current = expression;


	for (i=0; i<strlen(expression); i++)
	{
		if(expression[i] == '+')
		{
			retcontext->numOfTerms++;
		}
	}

	retcontext->terms = calloc(retcontext->numOfTerms, sizeof(passterm));
	if (!retcontext->terms)
	{
		freerule(retcontext);
		return NULL;
	}
	retcontext->terms[0].term = expression;
	for (i=0; i<strlen(expression) && counter < retcontext->numOfTerms - 1; i++)
	{
		if(expression[i] == '+')
		{
			expression[i] = '\0';
			counter++;
			retcontext->terms[counter].term = expression+i+1;
		}
	}

	for (t=0; t<retcontext->numOfTerms; t++)
	{
		counter = 0;
		current = retcontext->terms[t].term;
		while(*current != '\0')
		{
			switch (*current)
			{
			case '*':
			case '^':
			case '%':
				if (*(current + 1) == '\0')
				{
					fprintf(stderr, "malformed rule expression\n");
					freerule(retcontext);
					return NULL;
				}
				counter++;
				while (isdigit(*(current+1)))
					current++;

				break;
			case '?':
			case '@':
			case '#':
				counter++;
				break;

			default:
				fprintf(stderr, "malformed rule expression\n");
				freerule(retcontext);
				return NULL;
			}
			current++;
		}
		/* allocate and init passblock array */
		passgen = calloc(counter,sizeof(passblock));
		if (!passgen)
		{
			freerule(retcontext);
			return NULL;
		}
		/* configure every passblock item according to expression */
		current = retcontext->terms[t].term;
		i = 0;
		while(i < counter)
		{
			switch (*current)
			{
			case '*':
				passgen[i].type = LETTERS;
				passgen[i].numOfCells = atoi(current+1);
				if (passgen[i].numOfCells == 0)
				{
					fprintf(stderr, "malformed rule expression\n");
					freerule(retcontext);
					return NULL;
				}
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				if (!passgen[i].cells)
				{
					freerule(retcontext);
					return NULL;
				}
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = LETTERS;
					passgen[i].cells[j].range = 2*26;
				}
				i++;
				while (isdigit(*(current+1)))
					current++;
				break;
			case '^':
				passgen[i].type = NUMBERS;
				passgen[i].numOfCells = atoi(current+1);
				if (passgen[i].numOfCells == 0)
				{
					fprintf(stderr, "malformed rule expression\n");
					freerule(retcontext);
					return NULL;
				}
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				if (!passgen[i].cells)
				{
					freerule(retcontext);
					return NULL;
				}
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = NUMBERS;
					passgen[i].cells[j].range = 10;
				}
				i++;
				while (isdigit(*(current+1)))
					current++;
				break;
			case '%':
				passgen[i].type = ALPHANUMERIC;
				passgen[i].numOfCells = atoi(current+1);
				if (passgen[i].numOfCells == 0)
				{
					fprintf(stderr, "malformed rule expression\n");
					freerule(retcontext);
					return NULL;
				}
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				if (!passgen[i].cells)
				{
					freerule(retcontext);
					return NULL;
				}
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = ALPHANUMERIC;
					passgen[i].cells[j].range = 10 + 26 + 4;;
				}
				i++;
				while (isdigit(*(current+1)))
					current++;
				break;
			case '?':
				passgen[i].type = CHARACTER;
				passgen[i].numOfCells = 1;
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				if (!passgen[i].cells)
				{
					freerule(retcontext);
					return NULL;
				}
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = CHARACTER;
					passgen[i].cells[j].range = (126 - 32) + 1;
				}
				i++;
				break;
			case '@':
				passgen[i].type = LEXCS;
				passgen[i].numOfCells = 1;
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				if (!passgen[i].cells)
				{
					freerule(retcontext);
					return NULL;
				}
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = LEXCS;
					passgen[i].cells[j].range = lex->numOfWordsInLexicon + 1;
				}
				i++;
				break;
			case '#':
				passgen[i].type = LEX;
				passgen[i].numOfCells = 1;
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				if (!passgen[i].cells)
				{
					freerule(retcontext);
					return NULL;
				}
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = LEX;
					passgen[i].cells[j].range = lex->sumOfWordsPermutationsInLexicon + 1;
				}
				i++;
				break;
			default:
				printf("wrong rule code %c\n", *current);
				break;
			}
			current++;
		}
		*passgensize = counter;
		retcontext->terms[t].numOfBlocks = counter;
		retcontext->terms[t].blocks = passgen;

		/* calc each block range*/
		for(i=0; i< retcontext->terms[t].numOfBlocks; i++)
		{
			mul = 1;
			for (j=0; j<retcontext->terms[t].blocks[i].numOfCells; j++)
			{
				mul_prev = mul;
				mul *= retcontext->terms[t].blocks[i].cells[j].range;
				if (mul < mul_prev) /* detect overflow */
				{
					printf("Ahhhh. Rule overflow detected.\n");
					freerule(retcontext);
					return NULL;
				}
				retcontext->terms[t].blocks[i].range += mul;
			}
			if ((retcontext->terms[t].blocks[i].type != LEX) && (retcontext->terms[t].blocks[i].type != LEXCS))
			{
				/* add empty phrase case + 1 */
				retcontext->terms[t].blocks[i].range++;
			}
		}

		/* counts number of possible passwords for a term*/
		mul_prev = retcontext->terms[t].numOfPasswords = 1;
		for(i=0; i< retcontext->terms[t].numOfBlocks; i++)
		{
			mul_prev = retcontext->terms[t].numOfPasswords;
			retcontext->terms[t].numOfPasswords *= retcontext->terms[t].blocks[i].range;
			if (retcontext->terms[t].numOfPasswords < mul_prev) /* detect overflow */
			{
				printf("Ahhhh. Rule overflow detected.\n");
				freerule(retcontext);
				return NULL;
			}
		}
	}


	/* counts number of possible passwords for all terms*/
	retcontext->numOfPasswords = 0;
	for(i=0; i< retcontext->numOfTerms; i++)
	{
		retcontext->numOfPasswords += retcontext->terms[i].numOfPasswords;
	}

	return retcontext;
}

void freelex(lexicon* lex)
{
	int i = 0;

	if (!lex)
		return;
	if (lex->words)
	{
		for (i=0; i < lex->numOfWordsInLexicon; i++)
		{
			if (lex->words[i].wordlower)
				free(lex->words[i].wordlower);
			if (lex->words[i].playground)
				free(lex->words[i].playground);
			lex->words[i].wordlower = lex->words[i].playground = NULL;
		}
		free(lex->words);
	}

	if (lex->buffer)
		free(lex->buffer);
	free(lex);
	return;
}

lexicon* preprocessLexicon(char* filename)
{
	FILE* f = NULL;
	unsigned long buffersize = 0;
	int counter = 0;
	int i = 0, j = 0;
	lexicon* lex = calloc(1, sizeof(lexicon));
	if (!lex)
	{
		freelex(lex);
		return NULL;
	}
	if ((f = fopen(filename, "rt")) == NULL)
	{
		freelex(lex);
		return NULL;
	}
	if (0 != fseek(f, 0, SEEK_END))
	{
		perror("Could not seek lexicon file");
		freelex(lex);
		return NULL;
	}
	buffersize = ftell(f);
	if (buffersize == -1) /* which means error */
	{
		freelex(lex);
		return NULL;
	}
	lex->buffer = calloc(1, buffersize + 1);
	if (!lex->buffer)
	{
		freelex(lex);
		return NULL;
	}

	rewind(f); /* returns void */
	if (buffersize != fread(lex->buffer, 1, buffersize, f))
	{
		freelex(lex);
		return NULL;
	}

	for (i=0; i<buffersize; i++)
	{
		if(isalpha(lex->buffer[i]))
			lex->numOfLettersInLexicon++;
		if(lex->buffer[i] == '\n')
		{
			lex->numOfWordsInLexicon++;
		}
	}
	/* check last char */
	if (lex->buffer[i-1] != '\n')
	{
		lex->numOfWordsInLexicon++;
		lex->buffer[i] = '\n';
	}

	lex->words = calloc(lex->numOfWordsInLexicon, sizeof(lexword));
	if (!lex->words)
	{
		freelex(lex);
		return NULL;
	}
	lex->words[0].word = lex->buffer;
	for (i=0; i<buffersize && counter < lex->numOfWordsInLexicon; i++)
	{
		if(lex->buffer[i] == '\n')
		{
			lex->buffer[i] = '\0';
			lex->words[counter].len = strlen(lex->words[counter].word);
			lex->words[counter].wordlower = calloc(1, lex->words[counter].len);
			if (!lex->words[counter].wordlower)
			{
				freelex(lex);
				return NULL;
			}
			lex->words[counter].playground = calloc(1, lex->words[counter].len);
			if (!lex->words[counter].playground)
			{
				freelex(lex);
				return NULL;
			}
			for(j = 0; j < lex->words[counter].len; j++)
			{
				lex->words[counter].wordlower[j] = tolower(lex->words[counter].word[j]);
				lex->words[counter].numOfLettersPermutaionsInWord += (isalpha(lex->words[counter].word[j]) ? 1 : 0);
			}
			lex->words[counter].numOfLettersPermutaionsInWord = pow(2, lex->words[counter].numOfLettersPermutaionsInWord);
			lex->sumOfWordsPermutationsInLexicon += lex->words[counter].numOfLettersPermutaionsInWord;
			counter++;
			if (counter == lex->numOfWordsInLexicon)
				break;
			lex->words[counter].word = lex->buffer+i+1;
		}
	}

	return lex;
}

void advanceCell(passcell* cell, lexicon* lex, unsigned long k, char* pass)
{
	unsigned long counter = 0, j = 0, len = 0;
	char temp[MAX_FIELD + 1] = {0};
	char celldata[MAX_FIELD + 1] = {0};

	switch (cell->type)
	{
	case NUMBERS:
		celldata[0] = '0' + k;
		break;
	case LETTERS:
		celldata[0] = (k > 25 ? 'A' + k + 6 :  'A' + k);
		break;
	case ALPHANUMERIC:
		if (k < 26)
			celldata[0] = 'a' + k;
		else if (k < 36)
			celldata[0] = '0' + k - 26;
		else if (k == 36)
			celldata[0] = '!';
		else if (k == 37)
			celldata[0] = '?';
		else if (k == 38)
			celldata[0] = '~';
		else if (k == 39)
			celldata[0] = '.';
		break;
	case CHARACTER:
		celldata[0] = ' ' + k;
		break;
	case LEX:
		counter = 0;
		k++; /* convert to 1 based counting, as the other counters are 1 based */
		while (k > lex->words[counter].numOfLettersPermutaionsInWord)
		{
			k -= lex->words[counter].numOfLettersPermutaionsInWord;
			counter++;
		}
		/* apply the relevant transformation on the lower case form of the word */
		len = lex->words[counter].len;
		memset(lex->words[counter].playground, 0, len);
		k--; /* convert back to 0 based counting, for the bitwise comparison*/
		while (len > 0)
		{
			if (isalpha(lex->words[counter].wordlower[j]))
			{
				/* for every 1 bit apply to upper and copy to playground array */
				lex->words[counter].playground[j] = ((k & 0x1) ?
						toupper(lex->words[counter].wordlower[j]) :
								lex->words[counter].wordlower[j]);
				k >>= 1;
			}
			else
			{
				lex->words[counter].playground[j] = lex->words[counter].wordlower[j];
			}
			len--;
			j++;
		}
		strncpy(celldata, lex->words[counter].playground, MAX_FIELD);
		break;
	case LEXCS:
		strncpy(celldata, lex->words[k].word, MAX_FIELD);
		break;
	default:
		fprintf(stderr, "Unknown cell type %d\n", cell->type);
	}
	snprintf(temp, MAX_FIELD, "%s%s", celldata, pass);
	strncpy(pass, temp, MAX_FIELD);
	return;
}


char* advanceBlock(passblock* block, lexicon* lex, unsigned long k, char* pass)
{
	unsigned long currentCellIndex = block->numOfCells - 1;
	if (k == 0)
		return "";

	while (k != 0)
	{
		k--;
		advanceCell(block->cells + currentCellIndex, lex,
				k % block->cells[currentCellIndex].range, pass);
		k = k / block->cells[currentCellIndex].range;
		currentCellIndex--;
	}
	return pass;
}

char* generatePassword(passgencontext* passgenctx, lexicon* lex, unsigned long k, char* pass)
{
	unsigned long currentTermIndex = 0;
	unsigned long currentBlockIndex = 0;
	memset(pass, 0, MAX_FIELD); /* zero password */
	k %= passgenctx->numOfPasswords;

	/* Locate relevant term */
	while (k >= passgenctx->terms[currentTermIndex].numOfPasswords)
	{
		k -= passgenctx->terms[currentTermIndex].numOfPasswords;
		currentTermIndex++;
	}
	currentBlockIndex = passgenctx->terms[currentTermIndex].numOfBlocks - 1;

	/* if k = range1*range2*...*rangem, treat as k == 1 */
	if (k==0) k++;

	while (k != 0)
	{
		advanceBlock(passgenctx->terms[currentTermIndex].blocks + currentBlockIndex, lex,
				k % passgenctx->terms[currentTermIndex].blocks[currentBlockIndex].range, pass);
		k = k / passgenctx->terms[currentTermIndex].blocks[currentBlockIndex].range;
		if (currentBlockIndex == 0)
			break;
		currentBlockIndex--;
	}
	return pass;
}
#define RULE 		"^1^1^1"
#define CONST_K		12


#ifdef RULES_PREPROCESS
int main(int argc, char** argv) {
	unsigned long k = CONST_K;/*1221-1;//123321 + 3;//10 + 26 + 4 + 28; //pow(52,0) + pow(52,1) + pow(52,2); TODO: remove PREPROCESS Code*/
	unsigned int passgensize = 0;
	char pass[MAX_FIELD+1];
	pass[0] = NULL;
	lexicon* lex = preprocessLexicon("/home/a/workspace/Project/lexicon.txt");
	char* rule = calloc(1, strlen(RULE));
	memcpy(rule, RULE, strlen(RULE) + 1);
	passgencontext* passgenctx = createrule(rule, lex, &passgensize);
	generatePassword(passgenctx, lex, k, pass);
	printf("The %luth password (out of %lu) for %s is %s\n", CONST_K, passgenctx->numOfPasswords, RULE, pass);
	freerule(passgenctx);
	return 0;
}
#endif
