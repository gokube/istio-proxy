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

#pragma once

#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "common/common/logger.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"
#include "include/noop/client.h"
#include "src/envoy/noop/config.h"
#include "src/envoy/noop/grpc_transport.h"

namespace Envoy {
namespace Network {
namespace Noop {

struct NetworkRequestData {
     ::istio::mixer_client::Attributes attributes;
};
typedef std::shared_ptr<NetworkRequestData> NetworkRequestDataPtr;

struct AuthzRequestData {
     ::istio::v1::authz::Request request;
};
typedef std::shared_ptr<AuthzRequestData> AuthzRequestDataPtr;

// The tcp client class to control TCP requests.
// It has Check() to validate if a request can be processed.
// At the end of request, call Report().
class NoopControl final : public ThreadLocal::ThreadLocalObject,
                          public Logger::Loggable<Logger::Id::filter> {
 public:
  // The constructor.
  NoopControl(const NoopConfig& noop_config, Upstream::ClusterManager& cm,
              Event::Dispatcher& dispatcher, Runtime::RandomGenerator& random);

  // Build check request attributes for Network.
  void BuildNetworkCheck(NetworkRequestDataPtr request_data,
                     std::map<std::string, std::string> attrs,
                     Network::Connection& connection,
                     const std::string& source_user) const;

  void BuildAuthzCheck(AuthzRequestDataPtr request_data,
                       std::map<std::string, std::string> &labels,
                       Network::Connection& connection,
                       const std::string& source_user) const;
/*
  @SM TBD: may need this: Make remote report call.
  // Build report request attributs for Network.
  void BuildNetworkReport(
      HttpRequestDataPtr request_data, uint64_t received_bytes,
      uint64_t send_bytes, int check_status_code,
      std::chrono::nanoseconds duration,
      Upstream::HostDescriptionConstSharedPtr upstreamHost) const;

  // Make remote report call.
  // void SendReport(HttpRequestDataPtr request_data);
*/
  // Make remote check call.
  istio::noop_client::CancelFunc SendCheck(
      AuthzRequestDataPtr request_data, ::istio::noop_client::DoneFunc on_done);

  // See if check calls are disabled for Network proxy
  bool NoopCheckDisabled() const {
    return noop_config_.disable_attribute_check;
  }

 private:
  // Envoy cluster manager for making gRPC calls.
  Upstream::ClusterManager& cm_;
  // The dikastes client
  std::unique_ptr<::istio::noop_client::NoopClient> noop_client_;
  // The noop config
  const NoopConfig& noop_config_;
  // @SM TBD CheckTransport::AsyncClientPtr check_client_;
  // @SM TBD ReportTransport::AsyncClientPtr report_client_;
};

}  // namespace Noop 
}  // namespace Network 
}  // namespace Envoy
