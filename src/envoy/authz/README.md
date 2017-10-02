* Build the authz filter:
bazel build //src/envoy/authz:envoy
* Test the authz filter:
$ ./start_envoy -l debug
* To setup a test:
 1. start the microservice: cd tests && python echo.py
 1. start the authz_grpcserver: tbd
 1. make a curl call to envoy for the echo service: ./tests/curlwithssl
