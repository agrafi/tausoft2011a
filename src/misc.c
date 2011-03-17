#include "misc.h"
#include "md5.h"
#include "sha1.h"

#define MAX_SEED_USAGE 24

LONG_INDEX_PROJ pseudo_random_function(const unsigned char *x,int inputLength,LONG_INDEX_PROJ y)
/* You are allowed to change it or keep as is. Up to you*/
{
    LONG_INDEX_PROJ md5res[MD5_OUTPUT_LENGTH_IN_BYTES/sizeof(LONG_INDEX_PROJ)];
    unsigned char buffer4hashing[MAX_SEED_USAGE+sizeof(LONG_INDEX_PROJ)];

    if(inputLength>MAX_SEED_USAGE) inputLength = MAX_SEED_USAGE;
        /*for efficiency purpose*/
    memcpy(buffer4hashing,x,inputLength);/*copy y itself*/
    memcpy(buffer4hashing+inputLength,&y,sizeof(LONG_INDEX_PROJ));
        /*concatenate step to the y*/
    MD5BasicHash( buffer4hashing, inputLength+sizeof(LONG_INDEX_PROJ) , (unsigned char *)md5res );
       /*main step, hash both y and index as fusion process*/
    /*now just harvest 63 bit out of 128*/
    return ((md5res[0])&0x7fffffffffffffff);
}

int cryptHash ( BasicHashFunctionPtr cryptHashPtr, const char *passwd, unsigned char *outBuf )
{
	return cryptHashPtr ( passwd, strlen(passwd) , outBuf) ;
}

int MD5BasicHash ( const unsigned char *in,int len, unsigned char *outBuf)
{
  /* when you want to compute MD5, first, declere the next struct */
  MD5_CTX mdContext;
  /* then, init it before the first use */
  MD5Init (&mdContext);

  /* compute your string's hash using the next to calls */
  MD5Update (&mdContext, (unsigned char *)in, len);
  MD5Final (&mdContext);

  memcpy(outBuf,mdContext.digest,MD5_OUTPUT_LENGTH_IN_BYTES);
  return MD5_OUTPUT_LENGTH_IN_BYTES;
}

int SHA1BasicHash ( const unsigned char *in,int len, unsigned char *outBuf)
{
	int i =0;
  /* when you want to compute SHA1, first, declere the next struct */
  SHA1Context shaContext;
  /* then, init it before the first use */
  SHA1Reset (&shaContext);

  /* compute your string's hash using the next to calls */
  SHA1Input (&shaContext, (unsigned char *)in, len);
  SHA1Result (&shaContext);

  for (i=0; i< SHA1_OUTPUT_LENGTH_IN_BYTES/sizeof(int); i++)
  {
	  shaContext.Message_Digest[i] = htonl(shaContext.Message_Digest[i]);
  }
  memcpy(outBuf,shaContext.Message_Digest,SHA1_OUTPUT_LENGTH_IN_BYTES);
  return SHA1_OUTPUT_LENGTH_IN_BYTES;
}

unsigned char hex_to_nibble(unsigned char hex) {
        if (hex >= '0' && hex <= '9')
                return hex - '0';
        if (hex >= 'a' && hex <= 'f')
                return 10 + hex - 'a';
        return 'E';
}
int hexa2binary(const char *strIn, unsigned char *outBuf, int outMaxLen){
        int i;
        unsigned char *c = (unsigned char *)strIn;
        unsigned char *o = outBuf;
        for (i = 0; i < outMaxLen && c[2*i]; i++) {
                o[i] = (hex_to_nibble(c[2*i]) << 4) + hex_to_nibble(c[2*i+1]);
        }
        return i;
}

const unsigned char nibble_to_hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

int binary2hexa(const unsigned char *bufIn, int lengthIn, char *outStr, int outMaxLen){
        int i;
        unsigned char *c = bufIn;
        char *o = outStr;
        for (i = 0; i < lengthIn; i++) {
                if ((2*i+2) >= outMaxLen)
                        return 0;
                *(o + 2*i) = nibble_to_hex[c[i] / 0x10];
                *(o + 2*i + 1) = nibble_to_hex[c[i] % 0x10];
        }
        o[2*i] = '\0';
        return 2*lengthIn;
}
