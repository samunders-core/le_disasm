#ifndef ERROR_H_
#define ERROR_H_

#include <sstream>
#include <stdexcept>
#include <string>

#include "stacktrace.h"

// http://marknelson.us/2007/11/13/no-exceptions/
// throw Error() <<"Game over, "
//                     <<mHealth
//                     <<" health points!";
struct Error : public std::exception {
	Error() {
		print_stacktrace();
	}

	Error(const Error &that) {
		mWhat += that.mStream.str();
	}

	virtual ~Error() throw() {};

	virtual const char *what() const throw () {
		if (mStream.str().size()) {
			mWhat += mStream.str();
			mStream.str("");
		}
		return mWhat.c_str();
	}

	template<typename T>
	Error& operator<<(const T& t) {
		mStream << t;
		return *this;
	}
private:
	mutable std::stringstream mStream;
	mutable std::string mWhat;
};

#endif /* ERROR_H_ */
