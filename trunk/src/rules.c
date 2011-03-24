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
	int i = 0, j = 0, k = 0;
	for (i = 0; i < ctx->numOfTerms; i++)
	{
		for (j = 0; j < ctx->terms[i].numOfBlocks; j++)
		{
			for (k = 0; k < ctx->terms[i].blocks[j].numOfCells; k++)
			{
				if (ctx->terms[i].blocks[j].cells[k].data)
					free(ctx->terms[i].blocks[j].cells[k].data);
			}
			free(ctx->terms[i].blocks[j].cells);
		}
		free(ctx->terms[i].blocks);
	}
	free(ctx->terms);
	free(ctx);
	return;
}

passgencontext* createrule(char* expression, lexicon* lex, unsigned int* passgensize)
{
	/* scan expression and determine passcell array size */
	int i = 0, counter = 0, j = 0, t = 0;
	passblock* passgen = NULL;
	char* current = expression;
	passgencontext* retcontext = calloc(1, sizeof(passgencontext));
	retcontext->numOfTerms = 1;

	for (i=0; i<strlen(expression); i++)
	{
		if(expression[i] == '+')
		{
			retcontext->numOfTerms++;
		}
	}

	retcontext->terms = calloc(retcontext->numOfTerms, sizeof(passterm));
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
		while(*current != NULL)
		{
			switch (*current)
			{
			case '*':
			case '^':
			case '%':
				if (*(current + 1) == NULL)
				{
					fprintf(stderr, "malformed expression\n");
					return 0;
				}
				counter++; //= atoi(current+1);
				current++;
				break;
			case '?':
			case '@':
			case '#':
				counter++;
				break;

			default:
				break;
			}
			current++;
		}
		/* allocate and init passblock array */
#if DEBUG
		printf("Allocating %d blocks\n", counter);
#endif
		passgen = calloc(counter,sizeof(passblock));
		/* configure every passblock item according to expression */
		current = retcontext->terms[t].term;
		i = 0;
		while(i < counter)
		{
			switch (*current)
			{
			case '*':
				passgen[i].type = LETTERS;
				passgen[i].data = NULL;
				passgen[i].numOfCells = atoi(current+1);
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = LETTERS;
					passgen[i].cells[j].range = 2*26;
					passgen[i].cells[j].data = calloc(2, sizeof(char));
				}
				i++;
				current++;
				break;
			case '^':
				passgen[i].type = NUMBERS;
				passgen[i].data = NULL;
				passgen[i].numOfCells = atoi(current+1);
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = NUMBERS;
					passgen[i].cells[j].range = 10;
					passgen[i].cells[j].data = calloc(2, sizeof(char));
				}
				i++;
				current++;
				break;
			case '%':
				passgen[i].type = ALPHANUMERIC;
				passgen[i].data = NULL;
				passgen[i].numOfCells = atoi(current+1);
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = ALPHANUMERIC;
					passgen[i].cells[j].range = 10 + 26 + 4;;
					passgen[i].cells[j].data = calloc(2, sizeof(char));
				}
				i++;
				current++;
				break;
			case '?':
				passgen[i].type = CHARACTER;
				passgen[i].data = NULL;
				passgen[i].numOfCells = 1;
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = CHARACTER;
					passgen[i].cells[j].range = (126 - 32) + 1;
					passgen[i].cells[j].data = calloc(2, sizeof(char));
				}
				i++;
				break;
			case '@':
				passgen[i].type = LEXCS;
				passgen[i].data = NULL;
				passgen[i].numOfCells = 1;
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = LEXCS;
					passgen[i].cells[j].range = lex->numOfWordsInLexicon + 1;
					passgen[i].cells[j].data = NULL;
				}
				i++;
				break;
			case '#':
				passgen[i].type = LEX;
				passgen[i].data = NULL;
				passgen[i].numOfCells = 1;
				passgen[i].cells = calloc(passgen[i].numOfCells, sizeof(passcell));
				for(j=0; j<passgen[i].numOfCells; j++)
				{
					passgen[i].cells[j].type = LEX;
					passgen[i].cells[j].range = lex->sumOfWordsPermutationsInLexicon + 1;
					passgen[i].cells[j].data = NULL;
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
		unsigned long mul = 1;
		for(i=0; i< retcontext->terms[t].numOfBlocks; i++)
		{
			mul = 1;
			for (j=0; j<retcontext->terms[t].blocks[i].numOfCells; j++)
			{
				mul *= retcontext->terms[t].blocks[i].cells[j].range;
				retcontext->terms[t].blocks[i].range += mul;
			}
			if ((retcontext->terms[t].blocks[i].type != LEX) && (retcontext->terms[t].blocks[i].type != LEXCS))
			{
				/* add empty phrase case + 1 */
				retcontext->terms[t].blocks[i].range++;
			}
		}

		/* counts number of possible passwords for a term*/
		retcontext->terms[t].numOfPasswords = 1;
		for(i=0; i< retcontext->terms[t].numOfBlocks; i++)
		{
			retcontext->terms[t].numOfPasswords *= retcontext->terms[t].blocks[i].range;
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

lexicon* preprocessLexicon(char* filename)
{
	FILE* f = NULL;
	char* buffer = NULL;
	unsigned long buffersize = 0;
	int counter = 0;
	int i = 0, j = 0;
	lexicon* lex = calloc(1, sizeof(lexicon));
	if ((f = fopen(filename, "rt")) == NULL)
	{
		perror(filename);
		return 1;
	}
	/* TODO check return values! */
	fseek(f, 0, SEEK_END);
	buffersize = ftell(f) + 1; /* room for additional \n */
	buffer = calloc(1, buffersize);
	rewind(f);
	fread(buffer, buffersize, 1, f);
	for (i=0; i<buffersize; i++)
	{
		if(isalpha(buffer[i]))
			lex->numOfLettersInLexicon++;
		if(buffer[i] == '\n')
		{
			lex->numOfWordsInLexicon++;
		}
	}
	/* check last char */
	if (buffer[i-2] != '\n')
	{
		lex->numOfWordsInLexicon++;
		buffer[i] = '\n';
	}

	lex->words = calloc(lex->numOfWordsInLexicon, sizeof(lexword));
	lex->words[0].word = buffer;
	for (i=0; i<buffersize && counter < lex->numOfWordsInLexicon; i++)
	{
		if(buffer[i] == '\n')
		{
			buffer[i] = '\0';
			lex->words[counter].len = strlen(lex->words[counter].word);
			lex->words[counter].wordlower = calloc(1, lex->words[counter].len);
			lex->words[counter].playground = calloc(1, lex->words[counter].len);

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
			lex->words[counter].word = buffer+i+1;
		}
	}

	return lex;
}

char* advanceCell(passcell* cell, lexicon* lex, unsigned long k)
{
	unsigned long counter = 0, j = 0, len = 0;

	switch (cell->type)
	{
	case NUMBERS:
		*cell->data = '0' + k;
		break;
	case LETTERS:
		*cell->data = (k > 25 ? 'A' + k + 6 :  'A' + k);
		break;
	case ALPHANUMERIC:
		if (k < 26)
			*cell->data = 'a' + k;
		else if (k < 36)
			*cell->data = '0' + k - 26;
		else if (k == 36)
			*cell->data = '!';
		else if (k == 37)
			*cell->data = '?';
		else if (k == 38)
			*cell->data = '~';
		else if (k == 39)
			*cell->data = '.';
		break;
	case CHARACTER:
		*cell->data = ' ' + k;
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
		cell->data = lex->words[counter].playground;
		break;
	case LEXCS:
		cell->data = lex->words[k].word;
		break;
	default:
		fprintf(stderr, "Unknown cell type %d\n", cell->type);
	}
	return cell->data;
}


char* advanceBlock(passblock* block, lexicon* lex, unsigned long k)
{
	unsigned int currentCellIndex = block->numOfCells - 1;
	unsigned int retpasssize, partialsize;
	char* retpass = NULL;
	char* retpasstemp = NULL;
	char* partialpass = NULL;
	retpass = malloc(sizeof(char));
	if (k == 0)
#ifdef DEBUG
		return "$";
#else
		return "";
#endif
	while (k != 0)
	{
		k--;
		partialpass = advanceCell(block->cells + currentCellIndex, lex,
				k % block->cells[currentCellIndex].range);
		partialsize = strlen(partialpass);
		retpasssize = strlen(retpass);
		retpasstemp = calloc(1, retpasssize + partialsize + 1);
		memcpy(retpasstemp, partialpass, strlen(partialpass) + 1);
		// TODO: check return values
		strcat(retpasstemp, retpass);
		free(retpass);
		retpass = retpasstemp;
		k = k / block->cells[currentCellIndex].range;
		currentCellIndex--;
	}
	return retpass;
}

char* generatePassword(passgencontext* passgenctx, lexicon* lex, unsigned long k)
{
	unsigned int currentTermIndex = 0;
	unsigned int currentBlockIndex = 0;
	unsigned int retpasssize, partialsize;
	char* retpass = NULL;
	char* retpasstemp = NULL;
	char* partialpass = NULL;
	retpass = malloc(sizeof(char));
	k %= passgenctx->numOfPasswords;

	/* Locate relevant term */
	while (k > passgenctx->terms[currentTermIndex].numOfPasswords)
	{
		k -= passgenctx->terms[currentTermIndex].numOfPasswords;
		currentTermIndex++;
	}
	currentBlockIndex = passgenctx->terms[currentTermIndex].numOfBlocks - 1;

	if (k==0) return "Empty Password!";

	while (k != 0)
	{
		// k--;
		partialpass = advanceBlock(passgenctx->terms[currentTermIndex].blocks + currentBlockIndex, lex,
				k % passgenctx->terms[currentTermIndex].blocks[currentBlockIndex].range);
		partialsize = strlen(partialpass);
		retpasssize = strlen(retpass);
		retpasstemp = calloc(1, retpasssize + partialsize + 1);
		memcpy(retpasstemp, partialpass, strlen(partialpass) + 1);
		// TODO: check return values
		strcat(retpasstemp, retpass);
		free(retpass);
		retpass = retpasstemp;
		k = k / passgenctx->terms[currentTermIndex].blocks[currentBlockIndex].range;
		currentBlockIndex--;
	}
	return retpass;
}
#define RULE 		"^1^1^1"
#define CONST_K		121


#ifdef RULES_PREPROCESS
int main(int argc, char** argv) {
	unsigned long k = CONST_K;//1221-1;//123321 + 3;//10 + 26 + 4 + 28; //pow(52,0) + pow(52,1) + pow(52,2);
	unsigned int passgensize = 0;
	char* pass = NULL;
	lexicon* lex = preprocessLexicon("/home/a/workspace/Project/lexicon.txt");
	char* rule = calloc(1, strlen(RULE));
	memcpy(rule, RULE, strlen(RULE) + 1);
	passgencontext* passgenctx = createrule(rule, lex, &passgensize);
	pass = generatePassword(passgenctx, lex, k);
	printf("The %luth password (out of %lu) for %s is %s\n", CONST_K, passgenctx->numOfPasswords, RULE, pass);
	freerule(passgenctx);
	return 0;
}
#endif
