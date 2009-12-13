# afcgi

Asynchronous FastCGI.

Primarily a modified version of the [Nginx FastCGI module](http://wiki.nginx.org/NginxHttpFcgiModule) which implements multiplexing of connections, allowing a single FastCGI server to handle many concurrent requests.

This paves the way for long-lived connections in web apps without wasting resources -- i.e. optimally you only need to run one server process per CPU (or one server with one thread per CPU) instead of one process per request.

## Files

- `nginx/` contains the modified `ngx_http_fastcgi_module.c` along with a "prefix" (conf, logs, etc) for running a test server.

- `servers/` contains a set of asynchronous FastCGI server implementations, most notably the original libevent-based server written with the purpose to test afcgi.

## License & redistribution

Most parts of this software is licensed under the MIT license (see the `LICENSE` file for details) while the nginx module is licensed under the nginx license (details in the file `nginx/LICENSE`).

In short; you are free to use this software for commercial and non-commercial applictions as long as the license(s) and copyright notice(s) are properly reproduced. Read the LICENSEs files for details.

## Authors

- Rasmus Andersson <http://hunch.se/>

- Igor Sysoev (author of the original, synchronous fastcgi module)
