load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")
load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_binary",
    "envoy_linkopts",
)

envoy_cc_library(
    name = "filter_lib",
    srcs = [
        "client_impl.h",
        "client_impl.cc"
    ],
    hdrs = ["client.h"],
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
	"//src/envoy/authz/protobuf/v1:authz_api_cc_proto"
    ],
)
