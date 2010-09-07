#include <sol_compat.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <../sol_compat.h>

int yylineno;
int yymorfg;
int yyestate;
int yybgin;

hrtime_t gethrvtime(void)
{
	struct timespec sp;
	int ret;
	hrtime_t v;

	ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&sp);
	if(ret != 0) 
		return 0;

	v=1000000000LL; /* seconds->nanonseconds */
	v*=sp.tv_sec;
	v+=sp.tv_nsec;
	return v;
}

//void yyerror(const char *fmt, ...)
//{
//	va_list argptr;
//
//	va_start(argptr, fmt);
//	vprintf(fmt, argptr);
//	va_end(argptr);
//} 

char* econvert(double value, int  ndigit,  int  *decpt,  int
		     *sign, char *buf)
{
	char* tmp = ecvt(value, ndigit, decpt, sign);
	strncpy(buf, tmp, 512);
	return buf;
}

char *qeconvert(long double *value, int  ndigit,  int  *decpt,
		     int *sign, char *buf)
{
	char* tmp = ecvt(*value, ndigit, decpt, sign);
	strncpy(buf, tmp, 512);
	return buf;
}

/*ARGSUSED*/
int
proc_str2sig(const char *buf, int *ptr)
{
		return (-1);
}


/*ARGSUSED*/
int
proc_str2sys(const char *buf, int *ptr)
{
		return (-1);
}


/*ARGSUSED*/
int
proc_str2flt(const char *buf, int *ptr)
{
		return (-1);
}
