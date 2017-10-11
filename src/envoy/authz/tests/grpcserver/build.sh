# This is just for notes...need to plug this into the bazel build system.
dep ensure
protoc -I ./authz_v1 authz.proto --go_out=plugins=grpc:authz_v1
go build authzserver.go
