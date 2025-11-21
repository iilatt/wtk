struct SocketServer {
	struct TLS {
		ctk::ar<u8> cert;
		ctk::ar<u8> key;
	};

	struct Client {
		ctk::gar<u8> buffer;
		int socket_fd;
		SSL* ssl;

		void create(this auto& self) {
			self.buffer.create_auto();
		}

		void destroy(this auto& self) {
			self.buffer.destroy();
			::shutdown(self.socket_fd, SHUT_WR);
			::close(self.socket_fd);
			::SSL_free(self.ssl);
		}

		enum class Result {
			Fail,
			Ok,
		};

		Result read(this auto& self) {
			constexpr size_t temp_buffer_size = 4096;
			u8 temp_buffer[temp_buffer_size];
			ssize_t bytes_read;
			start:
			if (self.ssl == nullptr) {
				bytes_read = ::read(self.socket_fd, temp_buffer, temp_buffer_size);
			} else {
				bytes_read = ::SSL_read(self.ssl, temp_buffer, temp_buffer_size);
			}
			if (bytes_read == 0) {
				return Result::Fail;
			}
			if (bytes_read > 0) {
				self.buffer.push_many(temp_buffer, bytes_read);
				if (bytes_read == temp_buffer_size) {
					goto start;
				}
			}
			return Result::Ok;
		}

		Result send(this const auto& self, ctk::ar<const u8> data) {
			size_t total_sent = 0;
			while (total_sent < data.len) {
				int sent;
				if (self.ssl == nullptr) {
					sent = ::send(self.socket_fd, &data.buf[total_sent], data.len - total_sent, MSG_NOSIGNAL);
				} else {
					sent = ::SSL_write(self.ssl, &data.buf[total_sent], data.len - total_sent);
					if (sent <= 0) {
						int ssl_err = ::SSL_get_error(self.ssl, sent);
						if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
							struct pollfd pfd = {
								.fd = self.socket_fd,
								.events = POLLOUT,
							};
							if (::poll(&pfd, 1, 5000) <= 0) {
								return Result::Fail;
							}
							continue;
						}
					}
				}
				if (sent <= 0) {
					return Result::Fail;
				}
				total_sent += sent;
			}
			return Result::Ok;
		}
	};

	Addr addr;
	SSL_CTX* ssl_ctx;
	int socket_fd;
	void (*client_thread_func)(Client*);
	const ctk::ar<const u32>* disallowed_ips;
	ctk::Thread thread;

	static void thread_func(SocketServer* server) {
		struct sockaddr_in address;
		socklen_t addrlen = sizeof(address);
		bool use_tls = server->ssl_ctx != nullptr;
		while (server->thread.exists) {
			int client_socket_fd = ::accept(server->socket_fd, (struct sockaddr*)&address, &addrlen);
			if (client_socket_fd < 0) {
				WTK_LOG("accept failed (%x)", errno);
				continue;
			}
			u32 ip_address = address.sin_addr.s_addr;
			ctk::ar<const u32> disallowed_ips = *server->disallowed_ips;
			for (size_t a = 0; a < disallowed_ips.len; ++a) {
				if (disallowed_ips[a] == ip_address) {
					::close(client_socket_fd);
					continue;
				}
			}
			
			SSL* ssl = nullptr;
			if (use_tls) {
				ssl = ::SSL_new(server->ssl_ctx);
				::SSL_set_fd(ssl, client_socket_fd);
				if (::SSL_accept(ssl) <= 0) {
					::close(client_socket_fd);
					::SSL_free(ssl);
					continue;
				}
			}

			int flags = ::fcntl(client_socket_fd, F_GETFL, 0);
			::fcntl(client_socket_fd, F_SETFL, flags | O_NONBLOCK);

			Client client;
			client.create();
			client.socket_fd = client_socket_fd;
			client.ssl = ssl;
			ctk::Thread client_thread;
			Client* client_ptr = ctk::alloc<Client>(client);
			client_thread.create(server->client_thread_func, client_ptr);
			if (client_thread.exists == false) {
				client_ptr->destroy();
				std::free(client_ptr);
				continue;
			}
		}
		::close(server->socket_fd);
	}

	static SocketServer* make(bool is_async, Addr addr, TLS* tls, void (*client_thread_func)(Client*), const ctk::ar<const u32>* disallowed_ips) {
		SSL_CTX* ssl_ctx = nullptr;
		if (tls != nullptr) {
			BIO* cert_bio = ::BIO_new_mem_buf(tls->cert.buf, tls->cert.len);
			BIO* key_bio = ::BIO_new_mem_buf(tls->key.buf, tls->key.len);
			X509* cert = ::PEM_read_bio_X509(cert_bio, nullptr, 0, nullptr);
			EVP_PKEY* key = ::PEM_read_bio_PrivateKey(key_bio, nullptr, 0, nullptr);
			if (cert == nullptr || key == nullptr) {
				WTK_PANIC("::PEM_read_bio_X509 failed");
			}
			if (key == nullptr) {
				WTK_PANIC("::PEM_read_bio_PrivateKey failed");
			}
			ssl_ctx = ::SSL_CTX_new(TLS_server_method());
			if (ssl_ctx == nullptr) {
				WTK_PANIC("::SSL_CTX_new failed");
			}
			SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
			SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
			if (::SSL_CTX_use_certificate(ssl_ctx, cert) <= 0) {
				WTK_PANIC("::SSL_CTX_use_certificate failed");
			}
			if (::SSL_CTX_use_PrivateKey(ssl_ctx, key) <= 0) {
				WTK_PANIC("::SSL_CTX_use_PrivateKey failed");
			}
			if (::SSL_CTX_check_private_key(ssl_ctx) != 1) {
				WTK_PANIC("::SSL_CTX_check_private_key failed");
			}
			::X509_free(cert);
			::BIO_free(cert_bio);
			::EVP_PKEY_free(key);
			::BIO_free(key_bio);
		}

		int socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
		if (socket_fd == -1) {
			WTK_PANIC("::socket failed");
		}

		int opt = 1;
		if (::setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
			WTK_PANIC("::setsockopt(SO_REUSEADDR) failed");
		}

		struct linger linger_opt = {
			.l_onoff = 1,
			.l_linger = 10,
		};
		if (::setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)) == -1) {
			WTK_PANIC("::setsockopt(SO_LINGER) failed");
		}

		int bind_result;
		if (addr.type == Addr::Type::IPv4) {
			struct sockaddr_in server_addr = {};
			server_addr.sin_family = AF_INET;
			server_addr.sin_port = ::htons(addr.port);
			server_addr.sin_addr.s_addr = htonl(addr.ip.v4.s_addr);
			bind_result = ::bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
		} else {
			struct sockaddr_in6 server_addr = {};
			server_addr.sin6_family = AF_INET6;
			server_addr.sin6_port = ::htons(addr.port);
			server_addr.sin6_addr = addr.ip.v6;
			bind_result = ::bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
		}
		if (bind_result == -1) {
			WTK_PANIC("::bind failed");
		}

		if (::listen(socket_fd, 128) == -1) {
			WTK_PANIC("::listen failed");
		}

		SocketServer* server = ctk::alloc<SocketServer>(SocketServer());
		server->addr = addr;
		server->ssl_ctx = ssl_ctx;
		server->socket_fd = socket_fd;
		server->client_thread_func = client_thread_func;
		server->disallowed_ips = disallowed_ips;
		server->thread.create<SocketServer>(thread_func, server);
		if (server->thread.exists == false) {
			return nullptr;
		}
		return server;
	}
};