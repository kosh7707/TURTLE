cmake_minimum_required(VERSION 3.20)
execute_process(
    COMMAND tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --exclude-vcs --dereference -cf - -C "${TREE}" .
    COMMAND sha256sum
    RESULTS_VARIABLE outcomes OUTPUT_VARIABLE digest OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT outcomes STREQUAL "0;0")
    message(FATAL_ERROR "Could not fingerprint ${TREE}: ${outcomes}")
endif()
string(REGEX MATCH "^[0-9a-f]+" digest "${digest}")
file(WRITE "${RECORD}" "${digest}\n")
