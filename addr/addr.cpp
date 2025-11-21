struct Addr {
	enum Type {
		Error, IPv4, IPv6,
	};

	Type type = Type::Error;
	const char* name = nullptr;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
	u16 port;

	static Addr make_ipv4(in_addr_t ipv4, u16 port) {
		Addr addr;
		addr.type = Addr::Type::IPv4;
		addr.ip.v4.s_addr = ipv4;
		addr.port = port;
		return addr;
	}

	static Addr make_ipv6(struct in6_addr ipv6, u16 port) {
		Addr addr;
		addr.type = Addr::Type::IPv4;
		addr.ip.v6 = ipv6;
		addr.port = port;
		return addr;
	}

	static Addr resolve(const char* name, u16 port) {
		struct hostent* host_ent = ::gethostbyname(name); // TODO: deprecated, use ::getaddrinfo
		Addr addr;
		if (host_ent != nullptr && (host_ent->h_addrtype == AF_INET || host_ent->h_addrtype == AF_INET6)) {
			addr.name = name;
			bool ipv4 = host_ent->h_addrtype == AF_INET;
			addr.type = ipv4 ? Addr::Type::IPv4 : Addr::Type::IPv6;
			std::memcpy(&addr.ip, host_ent->h_addr, host_ent->h_length);
			addr.port = port;
		}
		return addr;
	}
};