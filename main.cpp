#include <fstream>

#include "print.h"

int main(int argc, char **argv) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " [main.exe]\n";
		return 1;
	}
	try {
		std::ifstream is(argv[1]);
		LinearExecutable lx(is);
		Image image(is, lx);
		Analyzer analyzer(lx, image);

		analyzer.run(lx);
		print_code(lx, image, analyzer);
	} catch (const std::exception &e) {
		std::cerr << std::dec << e.what() << std::endl;
	}
}
