#include "errors.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void warn_perror(const char *fmt, ...) 
{
  va_list ap;
  char buf[4096];
  fprintf(stderr,"WARNING: ");
  va_start(ap,fmt);
  vsnprintf(buf,4096,fmt,ap);
  va_end(ap);
  perror(buf);
}

void die_perror(const char *fmt, ...) 
{
  va_list ap;
  char buf[4096];
  fprintf(stderr,"ERROR  : ");
  va_start(ap,fmt);
  vsnprintf(buf,4096,fmt,ap);
  va_end(ap);
  perror(buf);
  exit(-1);
}

void die(const char *fmt, ...)
{
  va_list ap;
  fprintf(stderr,"ERROR  : ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(-1);
  
}

void warn(const char *fmt, ...)
{
  va_list ap;
  fprintf(stderr,"WARNING: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}
