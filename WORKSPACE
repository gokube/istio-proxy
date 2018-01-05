# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#

load(
    "//src/envoy/mixer:repositories.bzl",
    "mixer_client_repositories",
)

mixer_client_repositories()

load(
    "@mixerclient_git//:repositories.bzl",
    "mixerapi_repositories",
)

mixerapi_repositories()

bind(
    name = "boringssl_crypto",
    actual = "//external:ssl",
)

ENVOY_SHA = "522ab0cc82458e6c4d114b120a421015f333b518"  # Oct 31, 2017

git_repository(
    name = "envoy",
    commit = ENVOY_SHA,
    remote = "https://github.com/colabsaumoh/envoy",
)

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies(skip_targets=["io_bazel_rules_go"])

load("@envoy//bazel:cc_configure.bzl", "cc_configure")

cc_configure()

load("@envoy_api//bazel:repositories.bzl", "api_dependencies")

api_dependencies()

git_repository(
    name = "io_bazel_rules_go",
    commit = "9cf23e2aab101f86e4f51d8c5e0f14c012c2161c",  # Oct 12, 2017 (Add `build_external` option to `go_repository`)
    remote = "https://github.com/bazelbuild/rules_go.git",
)

load("@com_lyft_protoc_gen_validate//bazel:go_proto_library.bzl", "go_proto_repositories")
go_proto_repositories(shared=0)


load("@mixerapi_git//:api_dependencies.bzl", "mixer_api_for_proxy_dependencies")
mixer_api_for_proxy_dependencies()

ISTIO_SHA = "cdbdb153fb673cf444649c520ba7ed1b0dc99972"

git_repository(
    name = "io_istio_istio",
    commit = ISTIO_SHA,
    remote = "https://github.com/istio/istio",
)

load("//src/envoy/mixer/integration_test:repositories.bzl", "mixer_test_repositories")
mixer_test_repositories()
