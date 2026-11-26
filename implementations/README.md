# Submit a TLS implementation

Put one TLS source tree here. [`build.sh`](build.sh) and [`implementation.cpp`](implementation.cpp) are editable templates; they do not run TLS as shipped.

1. Place the TLS source in a subdirectory. A custom build recipe can use any directory name.
2. Edit `build.sh` to follow the [build recipe contract](../docs/submission.md#build-recipe) and keep it executable. Implement the [seven bridge functions](../docs/submission.md#porting) in `implementation.cpp`. Alternatively, [select an example](../docs/examples/submissions/README.md). The selection tool will not overwrite an edited file or a symbolic link.
3. From the repository root, run `./bench.sh --build-only` to link the client and server. Use the printed build directory in place of `JOB` in `./bench.sh --run-from JOB --scenario S0`, then [read the results](../docs/submission.md#results). If either template is untouched, the command exits with status 2 before building or measuring anything.

Git tracks both templates. Other source files and keys in this directory are ignored by default; do not put secrets in the two tracked files.
