namespace wtk {
	void make_socket_nonblocking(int socket_fd);

	#include "addr/addr.hpp"
	#include "socket/server/server.hpp"
	#include "socket/client/client.hpp"
	#include "http/http.hpp"
	#include "websocket/websocket.hpp"
	#include "json/json.hpp"

	void init();
}