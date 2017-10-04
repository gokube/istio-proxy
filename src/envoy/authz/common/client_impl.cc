/* Copyright 2017 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "src/envoy/authz/common/client_impl.h"

using ::authz::v1::Request;
using ::authz::v1::Response;
using ::google::protobuf::util::Status;
using ::google::protobuf::util::error::Code;

namespace Envoy {
namespace Network {
namespace Authz_client {

AuthzClientImpl::AuthzClientImpl(const AuthzClientOptions &options)
    : options_(options) {

  if (options_.uuid_generate_func) {
    deduplication_id_base_ = options_.uuid_generate_func();
  }
}

AuthzClientImpl::~AuthzClientImpl() {}

CancelFunc AuthzClientImpl::Check(const Request &request,
                                 TransportCheckFunc transport,
                                 DoneFunc on_done) {

  Request *request_copy = new Request(request);

  // Need to make a copy for processing the response for check cache.
  auto response = new Response;
  return transport(
      request, response, [this, request_copy, response,
                          on_done](const Status &status, Response *resp) {
        // raw_check_result->SetResponse(status, *request_copy, *response);
        std::ignore = resp;
        if (on_done) {
          on_done(status, response);
        }
        // delete raw_check_result;
        delete request_copy;
        delete response;

      });
}

// Creates a AuthzClient object.
std::unique_ptr<AuthzClient> CreateAuthzClient(
    const AuthzClientOptions &options) {
  return std::unique_ptr<AuthzClient>(new AuthzClientImpl(options));
}

}  // namespace Authz_client
}  // namespace Network
}  // namespace Envoy
