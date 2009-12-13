#include "sockutil.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>      /* for fcntl */
#include <math.h>
#include <memory.h>     /* for memchr() */
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>
#include <err.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef PATH_MAX
  #ifdef MAXPATHLEN
    #define PATH_MAX MAXPATHLEN
  #else
    #define PATH_MAX 1024
  #endif
#endif

inline static int _build_un(const char *bindPath, struct sockaddr_un *servAddrPtr, int *servAddrLen) {
  int bindPathLen = strlen(bindPath);
  if(bindPathLen > sizeof(servAddrPtr->sun_path))
    return -1;
  memset((char *) servAddrPtr, 0, sizeof(*servAddrPtr));
  servAddrPtr->sun_family = AF_UNIX;
  memcpy(servAddrPtr->sun_path, bindPath, bindPathLen);
  *servAddrLen = sizeof(servAddrPtr->sun_family) + bindPathLen;
  return 0;
}


int sockutil_bind(const char *bindPath, int backlog, sau_t *sa) {
  int fd, servLen;
  bool tcp = false;
  unsigned long tcp_ia = 0;
  char *tp;
  short port = 0;
  char host[PATH_MAX];
  
  strcpy(host, bindPath);
  
  if((tp = strchr(host, ':')) != 0) {
    *tp++ = 0;
    if((port = atoi(tp)) == 0)
      *--tp = ':';
    else
      tcp = true;
  }
  
  if(tcp) {
    if (!*host || !strcmp(host,"*")) {
      tcp_ia = htonl(INADDR_ANY);
    }
    else {
      tcp_ia = inet_addr(host);
      if (tcp_ia == INADDR_NONE) {
        struct hostent * hep;
        hep = gethostbyname(host);
        if ((!hep) || (hep->h_addrtype != AF_INET || !hep->h_addr_list[0])) {
          warn("fcgiev: cannot resolve host name %s", host);
          return -1;
        }
        if (hep->h_addr_list[1]) {
          warn("fcgiev: host %s has multiple addresses -- choose one explicitly", host);
          return -1;
        }
        tcp_ia = ((struct in_addr *) (hep->h_addr))->s_addr;
      }
    }
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if(fd >= 0) {
      int flag = 1;
      if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0) {
        warn("fcgiev: can't set SO_REUSEADDR.");
        return -1;
      }
    }
  }
  else { /* tcp == FALSE */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
  }
  
  if(fd < 0)
    return -1;
  
  // Bind the listening socket.
  if(tcp) {
    memset((char *)&sa->in, 0, sizeof(sa->in));
    sa->in.sin_family = AF_INET;
    sa->in.sin_addr.s_addr = tcp_ia;
    sa->in.sin_port = htons(port);
    servLen = sizeof(sa->in);
  }
  else {
    unlink(bindPath);
    if(_build_un(bindPath, &sa->un, &servLen)) {
      warn("fcgiev: listening socket's path name is too long.");
      return -1;
    }
  }
  
  if(bind(fd, (struct sockaddr *) &sa->un, servLen) < 0) {
    perror("fcgiev: bind");
    return -1;
  }
  
  if(listen(fd, backlog) < 0) {
    perror("fcgiev: listen");
    return -1;
  }
  
  return fd;
}
