# afcgi

Asynchronous FastCGI.

Primarily a modified version of the [Nginx FastCGI module](http://wiki.nginx.org/NginxHttpFcgiModule) which implements multiplexing of connections, allowing a single FastCGI server to handle many concurrent requests.

This paves the way for long-lived connections in web apps without wasting resources -- i.e. optimally you only need to run one server process per CPU (or one server with one thread per CPU) instead of one process per request.

## Files

- `nginx/` contains the modified `ngx_http_fastcgi_module.c` along with a "prefix" (conf, logs, etc) for running a test server.

- `servers/` contains a set of asynchronous FastCGI server implementations, most notably the original libevent-based server written with the purpose to test afcgi.

## Building

### Nginx module

The nginx module is built by *replacing* the original `ngx_http_fastcgi_module.c`:

	wget http://sysoev.ru/nginx/nginx-0.8.29.tar.gz
	tar xzf nginx-0.8.29.tar.gz
	cd nginx-0.8.29/src/http/modules
	mv ngx_http_fastcgi_module.c ngx_http_fastcgi_module.c.dist
	cp /path/to/afcgi/nginx/src/http/modules/ngx_http_fastcgi_module.c .
	cd ../../..
	./configure
	make

This module has been developed for and tested with nginx version 0.8.29 and is still in an experimental stage. No warranties, no guarantees -- use at own risk ;)

### Server reference implementation

The FCGI server reference implementation in `servers/afcgitest` is built by using regular make and linking against [libevent](http://monkey.org/~provos/libevent/):

	cd /path/to/afcgi/servers/afcgitest
	make
	./afcgitest 127.0.0.1:5000

> The last line assumes a FastCGI client (i.e. nginx) is connecting to port `5000` on `127.0.0.1`.

At the moment the `Makefile` is prepared for Mac OS X and contains a few lines which will not work in other environments. Simply remove or comment-out these lines when building on another platform:

	# If Mac OS X:
	CFLAGS += -arch i386
	LDFLAGS += -arch i386

becomes:

	# If Mac OS X:
	#CFLAGS += -arch i386
	#LDFLAGS += -arch i386

> **OS X users:** This assumes libevent is built for the i386 architecture. Your libevent library might use another architecture and then you should change the `-arch` argument value to match the architecture of libevent.

## License & redistribution

Most parts of this software is licensed under the MIT license (see the `LICENSE` file for details) while the nginx module is licensed under the nginx license (details in the file `nginx/LICENSE`).

In short; you are free to use this software for commercial and non-commercial applictions as long as the license(s) and copyright notice(s) are properly reproduced. Read the LICENSEs files for details.

## Authors

- Rasmus Andersson <http://hunch.se/>

- Igor Sysoev (author of the original, synchronous fastcgi module)
