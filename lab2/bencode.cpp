#include <sys/types.h>
#include <regex.h>
#include <stdio.h>

#define MAX_MATCHES 100 //The maximum number of matches allowed in a single string

void match(regex_t *pexp, char *sz) 
{
	regmatch_t matches[MAX_MATCHES]; //A list of the matches in the string (a list of 1)
	
	//regexec() returns 0 on match, otherwise REG_NOMATCH
	while(regexec(pexp, sz, MAX_MATCHES, matches, 0) == 0)
	{
		printf("\"%s\" matches characters %d - %d\n", sz, matches[0].rm_so, matches[0].rm_eo);								
		sz++;
	} 	
}
 
int main() {
	int rv;
	regex_t exp; //Our compiled expression	
	rv = regcomp(&exp, "([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED);
	if (rv != 0) 
	{
		printf("regcomp failed with %d\n", rv);
	}
	//2. Now run some tests on it
	char test[]="d8:annoiunce11:fritzi:6969e";
	match(&exp, test);
	//3. Free it
	regfree(&exp);
	return 0;
}
