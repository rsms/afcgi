#include "sockutil.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* for inet_ntop */

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <event.h>

#define DEBUG_RESPONSE_DELAY 5

#ifndef DEBUG_RESPONSE_DELAY
#define DEBUG_RESPONSE_DELAY 0
#endif

#define AZ(foo) assert((foo) == 0)
#define AN(foo) assert((foo) != 0)

#define FCGI_LISTENSOCK_FILENO 0
#define FLAG_KEEP_CONN 1
#define REQUESTS_MAX __SHRT_MAX__+__SHRT_MAX__

#define ROLE_RESPONDER	1
#define ROLE_AUTHORIZER 2
#define ROLE_FILTER		 3


typedef struct {
	struct event ev;
} server_t;


typedef struct {
	uint16_t id;
	uint16_t role;
	uint8_t keepconn;
	uint8_t stdin_eof;
	uint8_t terminate;
	uint8_t padding;
	struct bufferevent *bev;
} request_t;


request_t *_requests[REQUESTS_MAX];


enum {
	TYPE_BEGIN_REQUEST		 =	1,
	TYPE_ABORT_REQUEST		 =	2,
	TYPE_END_REQUEST			 =	3,
	TYPE_PARAMS						=	4,
	TYPE_STDIN						 =	5,
	TYPE_STDOUT						=	6,
	TYPE_STDERR						=	7,
	TYPE_DATA							=	8,
	TYPE_GET_VALUES				=	9,
	TYPE_GET_VALUES_RESULT = 10,
	TYPE_UNKNOWN					 = 11
};


enum {
	PROTOST_REQUEST_COMPLETE = 0,
	PROTOST_CANT_MPX_CONN		 = 1,
	PROTOST_OVERLOADED			 = 2,
	PROTOST_UNKNOWN_ROLE		 = 3
};


typedef struct {
	uint8_t version;
	uint8_t type;
	uint8_t requestIdB1;
	uint8_t requestIdB0;
	uint8_t contentLengthB1;
	uint8_t contentLengthB0;
	uint8_t paddingLength;
	uint8_t reserved;
} header_t; // 8


typedef struct {
	uint8_t roleB1;
	uint8_t roleB0;
	uint8_t flags;
	uint8_t reserved[5];
} begin_request_t; // 8


typedef struct {
	header_t header;
	uint8_t appStatusB3;
	uint8_t appStatusB2;
	uint8_t appStatusB1;
	uint8_t appStatusB0;
	uint8_t protocolStatus;
	uint8_t reserved[3];
} end_request_t; // 16


typedef struct {
	header_t header;
	uint8_t type;
	uint8_t reserved[7];
} unknown_type_t; // 16


inline static void header_init(header_t *self, uint8_t t, uint16_t id, uint16_t len) {
	self->version = '\1';
	self->type = t;
	self->requestIdB1 = id >> 8;
	self->requestIdB0 = id & 0xff;
	self->contentLengthB1 = len >> 8;
	self->contentLengthB0 = len & 0xff;
	self->paddingLength = '\0';
	self->reserved = '\0';
}


inline static void end_request_init(end_request_t *self, uint16_t id, uint32_t ast, uint8_t protostatus) {
	header_init((header_t *)self, TYPE_END_REQUEST, id, sizeof(end_request_t)-sizeof(header_t));
	self->appStatusB3 = (ast >> 24) & 0xff;
	self->appStatusB3 = (ast >> 16) & 0xff;
	self->appStatusB3 = (ast >> 8) & 0xff;
	self->appStatusB3 = ast & 0xff;
	self->protocolStatus = protostatus;
	memset(self->reserved, 0, sizeof(self->reserved));
}


inline static void unknown_type_init(unknown_type_t *self, uint8_t unknown_type) {
	header_init((header_t *)self, TYPE_UNKNOWN, 0, sizeof(unknown_type_t)-sizeof(header_t));
	self->type = unknown_type;
	memset(self->reserved, 0, sizeof(self->reserved));
}


/////////// bev


#define BEV_FD(p) ((p)->ev_read.ev_fd)
#define BEV_FD_SET(p, v) ((p)->ev_read.ev_fd = (v))


inline static void bev_disable(struct bufferevent *bev) {
	int events = 0;
	if (bev->readcb)
		events |= EV_READ;
	if (bev->writecb)
		events |= EV_WRITE;
	bufferevent_disable(bev, events);
}


inline static void bev_close(struct bufferevent *bev) {
	bev_disable(bev);
	close(BEV_FD(bev));
	BEV_FD_SET(bev, -1);
}


inline static void bev_drain(struct bufferevent *bev) {
	evbuffer_drain(bev->input, EVBUFFER_LENGTH(bev->input));
	evbuffer_drain(bev->output, EVBUFFER_LENGTH(bev->output));
}


void bev_abort(struct bufferevent *bev) {
	struct linger lingeropt;
	lingeropt.l_onoff = 1;
	lingeropt.l_linger = 0;
	AZ(setsockopt(BEV_FD(bev), SOL_SOCKET, SO_LINGER, (char *)&lingeropt, sizeof(lingeropt)));
	shutdown(BEV_FD(bev), SHUT_RDWR);
	bev_drain(bev);
	bev_close(bev);
}


inline static int bev_add(struct event *ev, int timeout) {
	struct timeval tv, *ptv = NULL;
	if (timeout) {
		evutil_timerclear(&tv);
		tv.tv_sec = timeout;
		ptv = &tv;
	}
	return event_add(ev, ptv);
}


/////////// request

void app_handle_beginrequest(request_t *r);
void app_handle_input(request_t *r, uint16_t length);
void app_handle_requestaborted(request_t *r);


// get a request by request id
inline static request_t *request_get(uint16_t id) {
	request_t *r;
	r = _requests[id];
	if (r == NULL) {
		r = (request_t *)calloc(1, sizeof(request_t));
		_requests[id] = r;
	}
	printf("** get req %p\n", r);
	return r;
}

// restore a request object
inline static void request_put(request_t *r) {
	printf("** put req %p\n", r);
	r->bev->cbarg = NULL;
	r->bev = NULL;
}

static inline bool request_is_active(request_t *r) {
	return ((r != NULL) && (r->bev != NULL));
}


void request_write(request_t *r, const char *buf, uint16_t len, uint8_t tostdout) {
	if (len == 0)
		return;
	
	if (!request_is_active(r)) {
		//warn("request_write(): request is not active");
		return;
	}
	
	header_t h;
	header_init(&h, tostdout ? TYPE_STDOUT : TYPE_STDERR, r->id, len);
	
	if (evbuffer_add(r->bev->output, (const void *)&h, sizeof(header_t)) != -1)
		evbuffer_add(r->bev->output, (const void *)buf, len);
	
	// schedule write
	if (r->bev->enabled & EV_WRITE)
		bev_add(&r->bev->ev_write, r->bev->timeout_write);
}


void request_end(request_t *r, uint32_t appstatus, uint8_t protostatus) {
	if (!request_is_active(r)) {
		//warn("request_end(): request is not active");
		return;
	}
	
	uint8_t buf[32]; // header + header + end_request_t
	uint8_t *p = buf;
	
	//assert(EVBUFFER_LENGTH(r->bev->output) == 0);
	
	// Terminate the stdout and stderr stream, and send the end-request message.
	header_init((header_t *)p, TYPE_STDOUT, r->id, 0);
	p += sizeof(header_t);
	header_init((header_t *)p, TYPE_STDERR, r->id, 0);
	p += sizeof(header_t);
	end_request_init((end_request_t *)p, r->id, appstatus, protostatus);
	p += sizeof(end_request_t);
	
	printf("sending END_REQUEST for id %d\n", r->id);
	
	bufferevent_write(r->bev, (const void *)buf, sizeof(buf));
	
	r->terminate = true;
}


inline static void process_abort_request(request_t *r) {
	assert(r->bev != NULL);
	printf("request %p aborted by client\n", r);
	
	app_handle_requestaborted(r);
	
	r->terminate = 1; // can we trust fcgiproto_writecb to be called?
}


void fcgiproto_errorcb(struct bufferevent *bev, short what, request_t *r) {
	if (what & EVBUFFER_EOF) {
		printf("request %p EOF\n", r);
		// we treat abrupt disconnect as abort
		process_abort_request(r);
	}
	else if (what & EVBUFFER_TIMEOUT)
		printf("request %p timeout\n", r);
	else
		printf("request %p error\n", r);
	
	bev_close(bev);
	if (r)
		request_put(r);
}


inline static void process_unknown(struct bufferevent *bev, uint8_t type, uint16_t len) {
	printf("process_unknown(%p, %d, %d)\n", bev, type, len);
	unknown_type_t msg;
	unknown_type_init(&msg, type);
	bufferevent_write(bev, (const void *)&msg, sizeof(unknown_type_t));
	evbuffer_drain(bev->input, sizeof(header_t) + len);
}


inline static void process_begin_request(struct bufferevent *bev, uint16_t id, const begin_request_t *br) {
	request_t *r;
	
	r = request_get(id);
	//assert(r->bev == NULL);
	if ((r->bev != NULL) && (EVBUFFER_LENGTH(r->bev->input) != 0)) {
		printf("warn: client sent already used req id %d -- skipping", id);
		// todo: respond with error
		bev_close(r->bev);
		return;
	}
	
	
	r->bev = bev;
	r->id = id;
	r->keepconn = (br->flags & FLAG_KEEP_CONN) == 1;
	r->role = (br->roleB1 << 8) + br->roleB0;
	r->stdin_eof = false;
	r->terminate = false;
	bev->cbarg = (void *)r;
	
	evbuffer_drain(bev->input, sizeof(header_t)+sizeof(begin_request_t));
}


inline static void process_params(struct bufferevent *bev, uint16_t id, const uint8_t *buf, uint16_t len) {
	request_t *r;
	
	r = request_get(id);
	//assert(r->bev != NULL); // this can actually happen and it's ok
	
	// Is this the last message to come? Then queue the request for the user.
	if (len == 0) {
		evbuffer_drain(bev->input, sizeof(header_t));
		app_handle_beginrequest(r);
		return;
	}
	
	// Process message.

	uint8_t const * const bufend = buf + len;
	uint32_t name_len;
	uint32_t data_len;
	
	while(buf != bufend) {
		
		if (*buf >> 7 == 0) {
			name_len = *(buf++);
		}
		else {
			name_len = ((buf[0] & 0x7F) << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
			buf += 4;
		}
		
		if (*buf >> 7 == 0) {
			data_len = *(buf++);
		}
		else {
			data_len = ((buf[0] & 0x7F) << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
			buf += 4;
		}
		
		assert(buf + name_len + data_len <= bufend);
		
		// todo replace with actual adding to req:
		char k[255], v[8192];
		strncpy(k, (const char *)buf, name_len); k[name_len] = '\0';
		buf += name_len;
		strncpy(v, (const char *)buf, data_len); v[data_len] = '\0';
		buf += data_len;
		printf("fcgiproto>> param>> '%s' => '%s'\n", k, v);
		// todo: req->second->params[name] = data;
	}
	
	evbuffer_drain(bev->input, sizeof(header_t) + len);
}


inline static void process_stdin(struct bufferevent *bev, uint16_t id, const uint8_t *buf, uint16_t len) {
	request_t *r;
	
	r = request_get(id);
	
	// left-over stdin on inactive request is drained and forgotten
	if (r->bev == NULL) {
		bev_drain(bev);
		return;
	}
	
	assert(r->bev != NULL);
	evbuffer_drain(bev->input, sizeof(header_t));
	
	// Is this the last message to come? Then set the eof flag.
	// Otherwise, add the data to the buffer in the request structure.	
	if (len == 0) {
		r->stdin_eof = true;
		return;
	}
	
	app_handle_input(r, len);
}


void fcgiproto_readcb(struct bufferevent *bev, request_t *r) {
	printf("fcgiproto_readcb(%p, %p)\n", bev, r);
	//bufferevent_write_buffer(bev, bev->input);
	
	while(EVBUFFER_LENGTH(bev->input) >= sizeof(header_t)) {
		const header_t *hp = (const header_t *)EVBUFFER_DATA(bev->input);
		
		// Check whether our peer speaks the correct protocol version.
		if (hp->version != 1) {
			warnx("fcgiev: cannot handle protocol version %u", hp->version);
			bev_abort(bev);
			break;
		}
		
		// Check whether we have the whole message that follows the
		// headers in our buffer already. If not, we can't process it
		// yet.
		uint16_t msg_len = (hp->contentLengthB1 << 8) + hp->contentLengthB0;
		uint16_t msg_id	= (hp->requestIdB1 << 8) + hp->requestIdB0;
		
		if (EVBUFFER_LENGTH(bev->input) < sizeof(header_t) + msg_len + hp->paddingLength)
			return;
		
		// Process the message.
		printf("fcgiproto>> received message: id: %d, bodylen: %d, padding: %d, type: %d\n",
			msg_id, msg_len, hp->paddingLength, (int)hp->type);
		
		switch (hp->type) {
			case TYPE_BEGIN_REQUEST:
				process_begin_request(bev, msg_id, 
					(const begin_request_t *)(EVBUFFER_DATA(bev->input) + sizeof(header_t)) );
				break;
			case TYPE_ABORT_REQUEST:
				process_abort_request(request_get(msg_id));
				break;
			case TYPE_PARAMS:
				process_params(bev, msg_id, (const uint8_t *)EVBUFFER_DATA(bev->input) + sizeof(header_t), msg_len);
				break;
			case TYPE_STDIN:
				process_stdin(bev, msg_id, (const uint8_t *)EVBUFFER_DATA(bev->input) + sizeof(header_t), msg_len);
				break;
			//case TYPE_END_REQUEST:
			//case TYPE_STDOUT:
			//case TYPE_STDERR:
			//case TYPE_DATA:
			//case TYPE_GET_VALUES:
			//case TYPE_GET_VALUES_RESULT:
			//case TYPE_UNKNOWN:
			default:
				process_unknown(bev, hp->type, msg_len);
		}/* switch(hp->type) */
		
		if (hp->paddingLength)
			evbuffer_drain(bev->input, hp->paddingLength);
	}
}


void fcgiproto_writecb(struct bufferevent *bev, request_t *r) {
	// Invoked if bev->output is drained or below the low watermark.
	printf("fcgiproto_writecb(%p, %p)\n", bev, r);
	
	if (r != NULL && r->terminate) {
		bev_disable(r->bev);
		bev_drain(r->bev);
		bev_close(r->bev);
		request_put(r);
		if (r->keepconn == false) {
			printf("PUT connection (r->keepconn == false, in fcgiproto_writecb)\n");
		}
	}
}


/*void conn_init(request_t *r, int fd) {
	r->ident = 0;
	r->bev.readcb = (evbuffercb)fcgiproto_readcb;
	r->bev.writecb = (evbuffercb)fcgiproto_writecb;
	r->bev.errorcb = (everrorcb)fcgiproto_errorcb;
	r->bev.cbarg = (void *)r;
	event_set(&r->bev.ev_read, fd, EV_READ, bufferevent_readcb, (void *)&r->bev);
	event_set(&r->bev.ev_write, fd, EV_WRITE, bufferevent_writecb, (void *)&r->bev);
	r->bev.enabled = EV_WRITE;
}*/


void server_init(server_t *server) {
	server->ev.ev_fd = FCGI_LISTENSOCK_FILENO;
}


const sau_t *server_bind(server_t *server, const char *addrorpath) {
	static sau_t sa;
	if ((server->ev.ev_fd = sockutil_bind(addrorpath, SOMAXCONN, &sa)) < 0)
		return NULL;
	return (const sau_t *)(&sa);
}


static const char *sockaddr_host(const sau_t *sa) {
  static char *buf[SOCK_MAXADDRLEN+1];
  buf[0] = '\0';
	struct sockaddr_in *sk = (struct sockaddr_in *)sa;
  return inet_ntop(AF_INET, &(sk->sin_addr), (char *)buf, SOCK_MAXADDRLEN);
}


void server_accept(int fd, short ev, server_t *server) {
	struct bufferevent *bev;
	socklen_t saz;
	int on = 1, events, connfd;
	struct timeval *timeout;
	sau_t sa;
	
	saz = sizeof(sa);
	connfd = accept(fd, (struct sockaddr *)&sa, &saz);
	timeout = NULL;
	
	if (connfd < 0) {
		warn("accept failed");
		return;
	}
	
	// Disable Nagle -- better response times at the cost of more packets being sent.
	setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
	// Set nonblocking
	AZ(ioctl(connfd, FIONBIO, (int *)&on));
	
	bev = bufferevent_new(connfd, (evbuffercb)fcgiproto_readcb,
		(evbuffercb)fcgiproto_writecb, (everrorcb)fcgiproto_errorcb, NULL);
	
	events = EV_READ;
	if (bev->writecb)
		events |= EV_WRITE;
	bufferevent_enable(bev, events);
	
	printf("GET connection\n");
	printf("fcgi client %s connected on fd %d\n", sockaddr_host(&sa), connfd);
}


void server_enable(server_t *server) {
	int on = 1;
	AZ(ioctl(server->ev.ev_fd, FIONBIO, (int *)&on));
	event_set(&server->ev, server->ev.ev_fd, EV_READ|EV_PERSIST,
		(void (*)(int,short,void*))server_accept, (void *)server);
	event_add(&server->ev, NULL/* no timeout */);
}


void fcgiev_init() {
	memset((void *)_requests, 0, sizeof(_requests));
}


static void app_test_delayed_finalize_request(int fd, short event, void *arg) {
	request_t *r = (request_t *)arg;
	if (request_is_active(r)) {
		printf("app_test_delayed_finalize_request %p\n", r);
		static const char hello[] = "Content-type: text/plain\r\n\r\nHello world\n";
		request_write(r, hello, sizeof(hello)-1, 1);
		request_end(r, 0, PROTOST_REQUEST_COMPLETE);
	}
}


void app_handle_beginrequest(request_t *r) {
	printf("app_handle_beginrequest %p\n", r);
	
	if (r->role != ROLE_RESPONDER) {
		request_write(r, "We can't handle any role but RESPONDER.", 39, 0);
		request_end(r, 1, PROTOST_UNKNOWN_ROLE);
		return;
	}
	
#if DEBUG_RESPONSE_DELAY
	// DELAYED
	struct event *timer_ev;
	struct timeval tv;
	timer_ev = calloc(1,sizeof(struct event));
	tv.tv_sec = DEBUG_RESPONSE_DELAY;
	tv.tv_usec = 0;
	evtimer_set(timer_ev, app_test_delayed_finalize_request, (void *)r);
	evtimer_add(timer_ev, &tv);
#else
	// DIRECT
	static const char hello[] = "Content-type: text/plain\r\n\r\nHello world\n";
	request_write(r, hello, sizeof(hello)-1, 1);
	request_end(r, 0, PROTOST_REQUEST_COMPLETE);
#endif
}


void app_handle_input(request_t *r, uint16_t length) {
	printf("app_handle_input %p -- %d bytes\n", r, length);
	// simply drain it for now
	evbuffer_drain(r->bev->input, length);
}


void app_handle_requestaborted(request_t *r) {
	printf("app_handle_requestaborted %p\n", r);
}


int main(int argc, const char * const *argv) {
	server_t *server;
	int i;
	
	// initialize libraries
	event_init();
	fcgiev_init();
	
	// no argmuents: bind to stdin
	if (argc <= 1) {
		server = calloc(1,sizeof(server_t));
		server_init(server);
		server_enable(server);
	}
	// bind with every argument
	else {
		for (i=1; i<argc; i++) {
			server = calloc(1,sizeof(server_t));
			server_init(server);
			if (server_bind(server, argv[i]) == NULL)
				err(1, "server_bind");
			printf("listening on %s\n", argv[i]);
			server_enable(server);
		}
	}
	
	// enter runloop
	event_dispatch();
	
	return 0;
}
/*
gcc -Wall -o test1 -L/opt/local/lib -I/opt/local/include -levent test1.c sockutil.c
 -O3 -finline-functions -ffast-math -funroll-all-loops -ftree -msse3
*/