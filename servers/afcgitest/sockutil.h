#ifndef _FCGIEV_SOCKUTIL_H_
#define _FCGIEV_SOCKUTIL_H_

#include <sys/un.h>
#include <netinet/in.h>

typedef union {
  struct sockaddr_un un;
  struct sockaddr_in in;
} sau_t;

int sockutil_bind(const char *bindPath, int backlog, sau_t *sa);

#endif
