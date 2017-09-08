* Build the noop filter:
bazel build //src/envoy/noop:envoy
* Test the noop filter:
$ ./start_envoy -l debug
