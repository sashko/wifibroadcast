#!/bin/bash

# From https://stackoverflow.com/a/65988393

THIS_PATH="$(realpath "$0")"
THIS_DIR="$(dirname "$THIS_PATH")"

EXCLUDED_DIRECTORIES="external"

# Find all files in THIS_DIR which end in .ino, .cpp, etc., as specified
# in the regular expression just below
FILE_LIST="$(find "$THIS_DIR/src" -not -path "$THIS_DIR/src/external/*" | grep -E ".*(\.ino|\.cpp|\.c|\.h|\.hpp|\.hh)$")"

echo -e "Files found to format = \n\"\"\"\n$FILE_LIST\n\"\"\""

# Format each file.
# - NB: do NOT put quotes around `$FILE_LIST` below or else the `clang-format` command will
#   mistakenly see the entire blob of newline-separated file names as a SINGLE file name instead
#   of as a new-line separated list of *many* file names!
#clang-format --verbose -i --style=file $FILE_LIST

# Create a directory where we can build with ninja & generate the list of files for clang tidy
cmake -G Ninja -S . -B build_clang_format -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
#clang-tidy -format-style=file -p build_clang_format $FILE_LIST