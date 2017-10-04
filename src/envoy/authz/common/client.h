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

#ifndef AUTHZCLIENT_CLIENT_H
#define AUTHZCLIENT_CLIENT_H

#include "google/protobuf/stubs/status.h"
#include "src/envoy/authz/protobuf/v1/authz.pb.h"

namespace Envoy {
namespace Network {
namespace Authz_client {

using ::authz::v1::Request;

// Defines a function prototype used when an asynchronous transport call
// is completed.
// Uses UNAVAILABLE status code to indicate network failure.
//@SM TBD using DoneFunc = std::function<void(const ::google::protobuf::util::Status&)>;
using DoneFunc = std::function<void(const ::google::protobuf::util::Status&, ::authz::v1::Response*)>;

// Defines a function prototype used to cancel an asynchronous transport call.
using CancelFunc = std::function<void()>;

// Defines a function prototype to make an asynchronous Check call
using TransportCheckFunc = std::function<CancelFunc(
    const ::authz::v1::Request& request,
    ::authz::v1::Response* response, DoneFunc on_done)>;

// Defines a function prototype to generate an UUID
using UUIDGenerateFunc = std::function<std::string()>;

// Defines the options to create an instance of MixerClient interface.
struct AuthzClientOptions {
  // Default constructor with default values.
  AuthzClientOptions() {}

  // Constructor with specified option values.
  // AuthzClientOptions(const CheckOptions& check_options)
  //    : check_options(check_options) {}

  // Check options.
  // CheckOptions check_options;

  // UUID generating function
  UUIDGenerateFunc uuid_generate_func;
};

class AuthzClient {
 public:
  // Destructor
  virtual ~AuthzClient() {}

  // A check call.
  virtual CancelFunc Check(const Request& request,
                           TransportCheckFunc transport, DoneFunc on_done) = 0;

};

// Creates a AuthzClient object.
std::unique_ptr<AuthzClient> CreateAuthzClient(
    const AuthzClientOptions& options);

}  // namespace Authz_client
}  // namespace Network
}  // namespace Envoy

#endif  // AUTHZCLIENT_CLIENT_H
