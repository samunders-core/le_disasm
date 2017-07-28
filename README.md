# le_disasm
libopcodes-based (AT&amp;T syntax) linear executable (MZ/LE/LX DOS EXEs) disassembler modified from http://swars.vexillium.org/files/swdisasm-1.0.tar.bz2

g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"main.d" -MT"main.o" -o "main.o" "main.cpp"
g++  -o "le_disasm"  ./main.o   -lstdc++ -lopcodes -lbfd -rdynamic
success on 13.12.2016: './le_disasm FATAL_beta.LE > output.S 2> stderr.txt && gcc output.S' exited with 0

