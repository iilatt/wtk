struct JSON {
	struct Field;

	struct Value {
		enum class Type {
			Error, Object, Array, String, Number, Bool, Null,
		};
		
		union {
			ctk::gar<Field> fields = ctk::gar<Field>();
			ctk::gar<Value> array;
			ctk::gar<u8> string;
			double number;
			bool boolean;
		};
		Type type;

		static Value create_of_type(Type type);
		void destroy(this Value& self);
		Value get_value(this const Value& self, const char* name);
	};

	struct Field {
		ctk::gar<u8> name;
		Value value;

		void destroy(this Field& self);
	};

	static ctk::gar<u8> parse_string(ctk::ar<const u8> data, size_t* index);
	static Value parse_object(ctk::ar<const u8> data, size_t* index);
	static Value parse_array(ctk::ar<const u8> data, size_t* index);
	static Value parse_number(ctk::ar<const u8> data, size_t* index);
	static Value parse_value(ctk::ar<const u8> data, size_t* index);
	static Value parse(ctk::ar<const u8> data);
};