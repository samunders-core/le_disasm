#include <cstring>
#include <fstream>
#define PACKAGE

#include "print.h"
#include "symbol_map.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [main.exe]\n";
        std::cerr << "To dump flat linear executable image to a bin file: " << argv[0] << " [main.exe] [dump.bin]\n";
        return 1;
    }
    try {
        SymbolMap *map_ptr = 0;

        std::ifstream is(argv[1]);
        if (!is.is_open()) {
            std::cerr << "Error opening file: " << argv[1];
            return 1;
        }

        LinearExecutable lx(is);
        Image image(is, lx);

        if (argc >= 3) {
            std::cerr << "Dump flat linear executable image to " << argv[2] << "\n";
            image.outputFlatMemoryDump(argv[2]);
        }

        if (argc >= 4) {
            map_ptr = new SymbolMap(argv[3]);
        }

        Analyzer analyzer(lx, image);

        analyzer.run(lx, map_ptr);
        print_code(lx, image, analyzer);

        if (map_ptr) {
            delete map_ptr;
        }
    } catch (const std::exception &e) {
        std::cerr << std::dec << e.what() << std::endl;
    }
}
