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

#ifndef AUTHZCLIENT_CLIENT_IMPL_H
#define AUTHZCLIENT_CLIENT_IMPL_H

#include "src/envoy/authz/common/client.h"

#include <atomic>

namespace Envoy {
namespace Network {
namespace Authz_client {

class AuthzClientImpl : public AuthzClient {
 public:
  // Constructor
  AuthzClientImpl(const AuthzClientOptions& options);

  // Destructor
  virtual ~AuthzClientImpl();

  virtual CancelFunc Check(const Request& request,
                           TransportCheckFunc transport, DoneFunc on_done);

 private:
  // Store the options
  AuthzClientOptions options_;

  // for deduplication_id
  std::string deduplication_id_base_;
  std::atomic<std::uint64_t> deduplication_id_;

  GOOGLE_DISALLOW_EVIL_CONSTRUCTORS(AuthzClientImpl);
};

}  // namespace Authz_client
}  // namespace Network
}  // namespace Envoy

#endif  // AUTHZCLIENT_CLIENT_IMPL_H
