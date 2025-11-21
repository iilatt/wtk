#include "ctk-0.40/mod.hpp"

#ifdef CBS_LINUX
#include <netdb.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "mod.hpp"

namespace wtk {
	#include "json/json.cpp"

#ifdef CBS_LINUX
	void make_socket_nonblocking(int socket_fd) {
		int flags = ::fcntl(socket_fd, F_GETFL, 0);
		if (flags == -1) {
			WTK_PANIC("::fcntl(F_GETFL) failed");
		}
		if (::fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			WTK_PANIC("::fcntl(F_SETFL) failed");
		}
	}

	#include "addr/addr.cpp"
	#include "socket/server/server.cpp"
	#include "socket/client/client.cpp"
	#include "http/http.cpp"
	#include "websocket/websocket.cpp"
	void init() {
		::SSL_library_init();
		::OpenSSL_add_all_algorithms();
		::SSL_load_error_strings();
	}
#endif
}