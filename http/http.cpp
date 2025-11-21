struct HTTP {
	struct Response {
		struct Status {
			ctk::gar<u8> data;
			
			void create(this auto& self) {
				self.data = ctk::gar<u8>::empty();
			}

			void destroy(this auto& self) {
				self.data.destroy();
			}
		};
		
		struct Headers {
			ctk::gar<u8> data;

			void create(this auto& self) {
				self.data = ctk::gar<u8>::empty();
			}

			void destroy(this auto& self) {
				self.data.destroy();
			}

			ctk::ar<const u8> get_header(this const auto& self, const char* name) {
				size_t name_len = std::strlen(name);
				size_t min_header_len = name_len + std::strlen(": *\n");
				size_t up_to;
				if (self.data.len < min_header_len) {
					goto end;
				}
				{
					up_to = self.data.len - min_header_len;
				}
				for (size_t a = 0; a < up_to; ++a) {
					if (ctk::astr_nocase_cmp(&self.data[a], name, name_len)) {
						a += name_len;
						if (self.data[a] == ':' && self.data[a + 1] == ' ') {
							a += 2;
							for (size_t b = a; b < up_to; ++b) {
								if (self.data[b] == '\n') {
									return ctk::ar<const u8>(&self.data[a], b - a);
								}
							}
						}
						goto end;
					}
				}
				end:
				return ctk::ar<const u8>(nullptr, 0);
			}
		};

		struct Body {
			ctk::gar<u8> data;

			void create(this auto& self) {
				self.data = ctk::gar<u8>::empty();
			}

			void destroy(this auto& self) {
				self.data.destroy();
			}
		};

		size_t id;
		Status status;
		Headers headers;
		Body body;

		void create(this auto& self) {
			self.status.create();
			self.headers.create();
			self.body.create();
		}

		void destroy(this auto& self) {
			self.status.destroy();
			self.headers.destroy();
			self.body.destroy();
		}
	};
	
	struct Request {
		enum class SSL_State {
			NoUse,
			Initial,
			Handshake,
			Ready,
		};

		enum class State {
			Status,
			Header,
			Body,
			ChunkedBodySize,
			ChunkedBodyData,
		};

		size_t id;
		const Addr* addr;
		ctk::ar<u8> data;
		size_t sent_bytes;
		int socket_fd;
		SSL_State ssl_state;
		SSL_CTX* ssl_ctx;
		SSL* ssl;
		State state;
		bool got_carriage_return;
		Response::Status status;
		Response::Headers headers;
		Response::Body body;

		void create(this auto& self, bool use_tls) {
			self.sent_bytes = 0;
			self.ssl_state = use_tls ? SSL_State::Initial : SSL_State::NoUse;
			self.ssl_ctx = nullptr;
			self.ssl = nullptr;
			self.state = State::Status;
			self.got_carriage_return = false;
			self.status.data.create_auto();
			self.headers.create();
			self.body.create();
		}

		void create_get(this auto& self, const Addr* addr, bool use_tls, const char* path) {
			self.addr = addr;
			self.data = ctk::alloc_format("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, addr->name);
			self.create(use_tls);
		}
		
		void create_post(this auto& self, const Addr* addr, bool use_tls, const char* path, ctk::ar<const u8> headers, ctk::ar<const u8> body) {
			self.addr = addr;
			self.data = ctk::alloc_format("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %zu\r\nConnection: close%.*s\r\n\r\n%.*s", path, addr->name, body.len, headers.len, headers.buf, body.len, body.buf);
			self.create(use_tls);
		}

		void destroy(this auto& self, int epoll_fd) {
			self.data.destroy();
			::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, self.socket_fd, nullptr);
			::close(self.socket_fd);
			if (self.ssl_state == SSL_State::Handshake || self.ssl_state == SSL_State::Ready) {
				::SSL_free(self.ssl);
				::SSL_CTX_free(self.ssl_ctx);
			}
		}

		enum class SSL_Result {
			Wait,
			None,
			Failed,
			Ready,
		};

		SSL_Result handle_ssl_err(this auto& self, int ret, int epoll_fd) {
			if (ret > 0) {
				return SSL_Result::None;
			}
			int err = ::SSL_get_error(self.ssl, ret);
			if (err == SSL_ERROR_WANT_READ) {
				struct epoll_event ev;
				ev.events = EPOLLIN | EPOLLET;
				ev.data.fd = self.socket_fd;
				epoll_ctl(epoll_fd, EPOLL_CTL_MOD, self.socket_fd, &ev);
				return SSL_Result::Wait;
			} else if (err == SSL_ERROR_WANT_WRITE) {
				struct epoll_event ev;
				ev.events = EPOLLOUT | EPOLLET;
				ev.data.fd = self.socket_fd;
				epoll_ctl(epoll_fd, EPOLL_CTL_MOD, self.socket_fd, &ev);
				return SSL_Result::Wait;
			} else {
				return SSL_Result::Failed;
			}
		}

		SSL_Result update_ssl(this auto& self, int epoll_fd) {
			if (self.ssl_state == SSL_State::Ready) {
				return SSL_Result::Ready;
			}
			if (self.ssl_state == SSL_State::Initial) {
				int err = 0;
				socklen_t len = sizeof(err);
				if (::getsockopt(self.socket_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
					return SSL_Result::Failed;
				}
				self.ssl_ctx = ::SSL_CTX_new(::TLS_client_method());
				if (self.ssl_ctx == nullptr) {
					WTK_PANIC("::SSL_CTX_new failed");
				}
				self.ssl = ::SSL_new(self.ssl_ctx);
				::SSL_set_fd(self.ssl, self.socket_fd);
				::SSL_set_connect_state(self.ssl);
				self.ssl_state = SSL_State::Handshake;
			}
			int ret = ::SSL_connect(self.ssl);
			if (ret == 1) {
				self.ssl_state = SSL_State::Ready;
				self.try_send(epoll_fd);
				return SSL_Result::Ready;
			} else {
				return self.handle_ssl_err(ret, epoll_fd);
			}
		}

		enum class SendResult {
			None,
			Close,
		};

		SendResult try_send(this auto& self, int epoll_fd) {
			while (self.sent_bytes < self.data.len) {
				ssize_t bytes_sent = 0;
				if (self.ssl_state == SSL_State::NoUse) {
					bytes_sent = ::send(self.socket_fd, &self.data[self.sent_bytes], self.data.len - self.sent_bytes, MSG_NOSIGNAL);
					if (bytes_sent == -1) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							return SendResult::None;
						}
						WTK_LOG("::send failed (%i)", errno);
						return SendResult::Close;
					}
				} else {
					SSL_Result ssl_result = self.update_ssl(epoll_fd);
					if (ssl_result == SSL_Result::Ready) {
						bytes_sent = ::SSL_write(self.ssl, &self.data[self.sent_bytes], self.data.len - self.sent_bytes);
						ssl_result = self.handle_ssl_err(bytes_sent, epoll_fd);
						if (ssl_result == SSL_Result::Failed) {
							return SendResult::Close;
						}
						if (ssl_result == SSL_Result::Wait) {
							return SendResult::None;
						}
					} else if (ssl_result == SSL_Result::Failed) {
						return SendResult::Close;
					} else {
						return SendResult::None;
					}
				}
				if (bytes_sent == 0) {
					return SendResult::None;
				}
				self.sent_bytes += bytes_sent;
			}
			return SendResult::None;
		}

		enum class RecvResult {
			None,
			Close,
			Finished,
		};

		RecvResult try_recv(this auto& self, int epoll_fd) {
			constexpr size_t temp_buffer_size = 256 * 256;
			u8 temp_buffer[temp_buffer_size];
			while (true) {
				ssize_t bytes_read = 0;
				if (self.ssl_state == SSL_State::NoUse) {
					bytes_read = ::recv(self.socket_fd, temp_buffer, temp_buffer_size, 0);
					if (bytes_read == -1) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							return RecvResult::None;
						}
						return RecvResult::Close;
					}
				} else {
					SSL_Result ssl_result = self.update_ssl(epoll_fd);
					if (ssl_result == SSL_Result::Ready) {
						bytes_read = ::SSL_read(self.ssl, temp_buffer, temp_buffer_size);
						ssl_result = self.handle_ssl_err(bytes_read, epoll_fd);
						if (ssl_result == SSL_Result::Failed) {
							return RecvResult::Close;
						}
						if (ssl_result == SSL_Result::Wait) {
							return RecvResult::None;
						}
					} else if (ssl_result == SSL_Result::Failed) {
						return RecvResult::Close;
					} else {
						return RecvResult::None;
					}
				}
				if (bytes_read == 0) {
					return RecvResult::None;
				}
				if (self.state == State::Body) {
					self.body.data.push_many(temp_buffer, bytes_read);
					continue;
				}
				int temp_buffer_offset = 0;
				int crlf_index = bytes_read;
				for (int a = 0; a < bytes_read; ++a) {
					if (self.got_carriage_return) {
						if (temp_buffer[a] != '\n') {
							return RecvResult::Close;
						}
						self.got_carriage_return = false;
						temp_buffer_offset = a + 1;
						continue;
					}
					if (temp_buffer[a] == '\r') {
						self.got_carriage_return = true;
						crlf_index = a;
					}
					bool double_crlf = crlf_index == temp_buffer_offset;
					if (self.got_carriage_return || a == bytes_read - 1) {
						switch (self.state) {
							case State::Status: {
								self.status.data.push_many(&temp_buffer[temp_buffer_offset], crlf_index - temp_buffer_offset);
								if (self.got_carriage_return) {
									self.state = State::Header;
									self.headers.data.create_auto();
								}
								break;
							}
							case State::Header: {
								if (self.got_carriage_return && double_crlf) {
									self.state = State::Body;
									self.body.data.create_auto();
									ctk::ar<const u8> transfer_encoding = self.headers.get_header("transfer-encoding");
									if (transfer_encoding.buf != nullptr) {
										const char* chunked_encoding = "chunked";
										if (ctk::astr_nocase_cmp(transfer_encoding.buf, chunked_encoding, std::strlen(chunked_encoding))) {
											self.state = State::ChunkedBodySize;
										}
									}
									if (self.state == State::Body) {
										self.body.data.push_many(&temp_buffer[temp_buffer_offset], bytes_read - temp_buffer_offset);
										goto main_loop_continue;
									}
									continue;
								}
								self.headers.data.push_many(&temp_buffer[temp_buffer_offset], crlf_index - temp_buffer_offset);
								if (self.got_carriage_return) {
									self.headers.data.push('\n');
								}
								break;
							}
							case State::ChunkedBodySize:
							case State::ChunkedBodyData: {
								if (self.got_carriage_return && double_crlf) {
									return RecvResult::Finished;
								}
								if (self.state == State::ChunkedBodyData) {
									self.body.data.push_many(&temp_buffer[temp_buffer_offset], crlf_index - temp_buffer_offset);
								}
								if (self.got_carriage_return) {
									self.state = (self.state == State::ChunkedBodySize) ? State::ChunkedBodyData : State::ChunkedBodySize;
								}
								break;
							}
							default: {
								WTK_PANIC("invalid State");
								break;
							}
						}
						temp_buffer_offset = crlf_index;
						crlf_index = bytes_read;
					}
				}
				main_loop_continue:
				continue;
			}
			if (self.state == State::Status || self.state == State::Header) {
				self.status.destroy();
				self.headers.destroy();
				return RecvResult::Close;
			}
		}
	};

	int epoll_fd;
	size_t next_id;
	ctk::gar<Request> requests;
	ctk::gar<Response> responses;

	void create(this auto& self) {
		self.epoll_fd = ::epoll_create1(0);
		if (self.epoll_fd == -1) {
			WTK_PANIC("::epoll_create1 failed");
		}
		self.next_id = 1;
		self.requests.create_auto();
		self.responses.create_auto();
	}

	void destroy(this auto& self) {
		::close(self.epoll_fd);
		for (size_t a = 0; a < self.requests.len; ++a) {
			self.requests[a].destroy(self.epoll_fd);
		}
		self.requests.destroy();
		for (size_t a = 0; a < self.responses.len; ++a) {
			self.responses[a].destroy();
		}
		self.responses.destroy();
	}

	void update(this auto& self) {
		constexpr size_t max_events = 4096;
		struct epoll_event events[max_events];
		int epoll_fd_count = ::epoll_wait(self.epoll_fd, events, max_events, 0);
		if (epoll_fd_count == -1) {
			if (errno != EINTR) {
				WTK_LOG("::epoll_wait failed (%i)", errno);
			}
			return;
		}
		for (int a = 0; a < epoll_fd_count; ++a) {
			int epoll_fd = events[a].data.fd;
			size_t request_index = self.get_request(epoll_fd);
			bool remove = (events[a].events & EPOLLERR) || (events[a].events & EPOLLHUP);
			if (remove == false && (events[a].events & EPOLLIN)) {
				Request::RecvResult recv_result = self.requests[request_index].try_recv(self.epoll_fd);
				if (recv_result == Request::RecvResult::Close) {
					remove = true;
				} else if (recv_result == Request::RecvResult::Finished) {
					remove = true;
				}
			}
			if (remove == false && (events[a].events & EPOLLOUT)) {
				if (self.requests[request_index].try_send(self.epoll_fd) == Request::SendResult::Close) {
					remove = true;
				}
			}
			if (remove) {
				if (self.requests[request_index].state == Request::State::Body) {
					Request request = self.requests[request_index];
					self.responses.push(Response(request.id, request.status, request.headers, request.body));
				}
				self.requests[request_index].destroy(self.epoll_fd);
				self.requests.remove(request_index);
				continue;
			}
		}
	}

	size_t get_request(this auto& self, int socket_fd) {
		for (size_t a = 0; a < self.requests.len; ++a) {
			if (self.requests[a].socket_fd == socket_fd) {
				return a;
			}
		}
		WTK_PANIC("HTTP::get_request failed");
		return 0;
	}

	size_t push_request(this auto& self, Request request) {
		int address_family = request.addr->type == Addr::Type::IPv4 ? AF_INET : AF_INET6;
		request.socket_fd = ::socket(address_family, SOCK_STREAM, 0);
		if (request.socket_fd < 0) {
			WTK_LOG("::socket failed (host:%s)", request.addr->name);
			return 0;
		}
		wtk::make_socket_nonblocking(request.socket_fd);
		int connect_result;
		if (request.addr->type == Addr::Type::IPv4) {
			struct sockaddr_in server_addr = {};
			server_addr.sin_family = AF_INET;
			server_addr.sin_port = ::htons(request.addr->port);
			server_addr.sin_addr = request.addr->ip.v4;
			connect_result = ::connect(request.socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
		} else {
			struct sockaddr_in6 server_addr = {};
			server_addr.sin6_family = AF_INET6;
			server_addr.sin6_port = ::htons(request.addr->port);
			server_addr.sin6_addr = request.addr->ip.v6;
			connect_result = ::connect(request.socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
		}
		if (connect_result == -1 && errno != EINPROGRESS) {
			WTK_LOG("::connect failed (host:%s)", request.addr->name);
			request.destroy(self.epoll_fd);
			return 0;
		}
		struct epoll_event ev = {};
		ev.events = EPOLLOUT | EPOLLET;
		ev.data.fd = request.socket_fd;
		if (::epoll_ctl(self.epoll_fd, EPOLL_CTL_ADD, request.socket_fd, &ev) == -1) {
			WTK_PANIC("::epoll_ctl failed");
		}
		request.id = self.next_id;
		self.next_id += 1;
		self.requests.push(request);
		return request.id;
	}

	bool try_pop_response(this auto& self, Response* out_response) {
		if (self.responses.len > 0) {
			*out_response = self.responses.pop();
			return true;
		}
		return false;
	}
};