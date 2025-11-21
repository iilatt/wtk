struct WebsocketClient {
	constexpr static size_t sec_websocket_key_len = 24;

	SocketServer::Client* client;
	ctk::gar<u8> payload_buffer;
	bool payload_ready;

	void create(this auto& self) {
		self.client = nullptr;
		self.payload_buffer.create_empty();
		self.payload_ready = false;
	}
	
	void destroy(this auto& self) {
		if (self.is_valid()) {
			self.client->destroy();
			std::free(self.client);
		}
		self.payload_buffer.destroy();
	}

	bool is_valid(this const auto& self) {
		return self.client != nullptr;
	}

	bool consume_payload(this auto& self) {
		if (self.payload_ready) {
			self.payload_ready = false;
			return true;
		}
		return false;
	}

	SocketServer::Client::Result http_upgrade(this auto& self, SocketServer::Client* new_client, size_t index) {
		constexpr const char* sec_websocket_key_header = "sec-websocket-key: ";
		constexpr size_t sec_websocket_key_header_len = std::strlen(sec_websocket_key_header);
		if (new_client->buffer.len < sec_websocket_key_header_len + sec_websocket_key_len) {
			return SocketServer::Client::Result::Ok;
		}
		ctk::ar<const u8> accept_key;
		size_t up_to = new_client->buffer.len - sec_websocket_key_header_len - sec_websocket_key_len;
		for (size_t a = index; a < up_to; ++a) {
			if (ctk::astr_nocase_cmp(&new_client->buffer[a], sec_websocket_key_header, sec_websocket_key_header_len)) {
				accept_key = self.get_header_sec_websocket_key(new_client, a + sec_websocket_key_header_len);
			}
		}
		if (accept_key.buf == nullptr) {
			return SocketServer::Client::Result::Fail;
		}

		constexpr size_t server_accept_key_len = 28; // base64(sha1())
		char server_accept_key[server_accept_key_len];
		websocket_generate_accept_key(accept_key, server_accept_key);

		constexpr const char* response_start = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
		constexpr size_t response_start_len = std::strlen(response_start);
		constexpr size_t terminator_len = 4;
		constexpr size_t resp_len = response_start_len + server_accept_key_len + terminator_len;
		u8 resp_buffer[resp_len];
		std::memcpy(resp_buffer, response_start, response_start_len);
		std::memcpy(resp_buffer + response_start_len, server_accept_key, server_accept_key_len);
		std::memcpy(resp_buffer + response_start_len + server_accept_key_len, "\r\n\r\n", terminator_len);
		self.client = new_client;
		self.payload_buffer.create_auto();
		return self.client->send(ctk::ar<const u8>(resp_buffer, resp_len));
	}

	static ctk::ar<const u8> get_header_sec_websocket_key(SocketServer::Client* new_client, size_t index) {
		for (size_t a = index; a < new_client->buffer.len; ++a) {
			if (a - index > sec_websocket_key_len) {
				break;
			}
			if (new_client->buffer[a] == '\r' && new_client->buffer[a + 1] == '\n') {
				return ctk::ar<const u8>(&new_client->buffer[index], a - index);
			}
		}
		return ctk::ar<const u8>(nullptr, 0);
	}

	static void base64_encode(const u8* input, size_t input_len, char* output) {
		BUF_MEM* bptr;
		BIO* b64 = ::BIO_new(::BIO_f_base64());
		BIO* bmem = ::BIO_new(::BIO_s_mem());
		b64 = ::BIO_push(b64, bmem);
		::BIO_write(b64, input, input_len);
		BIO_flush(b64);
		::BIO_get_mem_ptr(b64, &bptr);
		std::memcpy(output, bptr->data, bptr->length - 1);
		::BIO_free_all(b64);
	}

	static void websocket_generate_accept_key(ctk::ar<const u8> client_key, char* accept_key) {
		constexpr const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		constexpr size_t GUID_len = std::strlen(GUID);
		u8 buffer[sec_websocket_key_len + GUID_len];
		std::memcpy(buffer, client_key.buf, client_key.len);
		std::memcpy(&buffer[client_key.len], GUID, GUID_len);
		u8 hash[SHA_DIGEST_LENGTH];
		::SHA1(buffer, client_key.len + GUID_len, hash);
		base64_encode(hash, SHA_DIGEST_LENGTH, accept_key);
	}

	SocketServer::Client::Result handle_frame(this auto& self) {
		if (self.client->buffer.len < 2) {
			return SocketServer::Client::Result::Ok;
		}

		u8 byte1 = self.client->buffer[0];
		u8 byte2 = self.client->buffer[1];

		u8 fin = (byte1 & 0x80) >> 7;
		u8 opcode = byte1 & 0x0f;
		u8 mask = (byte2 & 0x80) >> 7;
		u64 payload_len = byte2 & 0x7f;
		
		if (opcode != 0x0 && opcode != 0x2) {
			return SocketServer::Client::Result::Fail;
		}

		size_t offset = 2;
		if (payload_len == 126) {
			if (self.client->buffer.len < offset + 2) {
				return SocketServer::Client::Result::Ok;
			}
			payload_len = (self.client->buffer[offset] << 8) | self.client->buffer[offset + 1];
			offset += 2;
		} else if (payload_len == 127) {
			if (self.client->buffer.len < offset + 8) {
				return SocketServer::Client::Result::Ok;
			}
			payload_len = 0;
			for (size_t a = 0; a < 8; ++a) {
				payload_len = (payload_len << 8) | self.client->buffer[offset + a];
			}
			offset += 8;
		}

		u8 masking_key[4];
		if (mask) {
			if (self.client->buffer.len < offset + 4) {
				return SocketServer::Client::Result::Ok;
			}
			std::memcpy(masking_key, &self.client->buffer[offset], 4);
			offset += 4;
		}

		if (self.client->buffer.len < offset + payload_len) {
			return SocketServer::Client::Result::Ok;
		}

		if (mask) {
			size_t mask_index = 0;
			for (uint64_t a = 0; a < payload_len; ++a) {
				self.client->buffer[offset + a] ^= masking_key[mask_index];
				mask_index += 1;
				if (mask_index >= 4) {
					mask_index = 0;
				}
			}
		}

		if (opcode == 0x9) {
			self.client->buffer[0] = 0x8a;
			SocketServer::Client::Result result = self.client->send(ctk::ar<const u8>(self.client->buffer.buf, 2 + payload_len));
			self.client->buffer.remove_many(0, offset + payload_len);
			return result;
		}
		
		if (payload_len > 0) {
			self.payload_buffer.push_many(&self.client->buffer[offset], payload_len);
		}
		self.client->buffer.remove_many(0, offset + payload_len);
		if (fin == 1) {
			self.payload_ready = true;
		}
		return SocketServer::Client::Result::Ok;
	}

	SocketServer::Client::Result send(this const auto& self, ctk::ar<const u8> data) {
		if (data.len > 65535) {
			WTK_PANIC("data.len is too big");
			return SocketServer::Client::Result::Fail;
		}
		if (data.len > 125) {
			u8 temp[2 + 2 + 65535];
			temp[0] = 0x82;
			temp[1] = 126;
			temp[2] = (data.len >> 8) & 0xFF;
			temp[3] = data.len & 0xFF;
			std::memcpy(temp + 4, data.buf, data.len);
			return self.client->send(ctk::ar<const u8>(temp, 4 + data.len));
		} else {
			u8 temp[2 + 125];
			temp[0] = 0x82;
			temp[1] = data.len;
			std::memcpy(temp + 2, data.buf, data.len);
			return self.client->send(ctk::ar<const u8>(temp, 2 + data.len));
		}
	}
};