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
#include "common/http/headers.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"
#include "src/envoy/authz/common/client.h"
#include "src/envoy/authz/config.h"
#include "src/envoy/authz/grpc_transport.h"
#include "openssl/obj.h"
#include "openssl/asn1.h"
#include "openssl/x509v3.h"
#include "openssl/bio.h"

namespace Envoy {
namespace Network {
namespace Authz {

struct AuthzRequestData {
     ::authz::v1::Request request;
};
typedef std::shared_ptr<AuthzRequestData> AuthzRequestDataPtr;

// The tcp client class to control TCP requests.
// It has Check() to validate if a request can be processed.
// At the end of request, call Report().
class AuthzControl final : public ThreadLocal::ThreadLocalObject,
                          public Logger::Loggable<Logger::Id::filter> {
 public:
  // The constructor.
  AuthzControl(const AuthzConfig& authz_config, Upstream::ClusterManager& cm,
              Event::Dispatcher& dispatcher, Runtime::RandomGenerator& random);

  // Build check request for Network layer
  void BuildAuthzCheck(AuthzRequestDataPtr request_data,
                       const std::map<std::string, std::string> &labels,
                       const Network::Connection& connection,
                       const std::string& source_user) const;

  void BuildAuthzHttpCheck(AuthzRequestDataPtr request_data, Envoy::Http::HeaderMap &headers,
			   const std::map<std::string, std::string> &labels,
                           const Network::Connection* connection,
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
  Envoy::Network::Authz_client::CancelFunc SendCheck(
      AuthzRequestDataPtr request_data, ::Envoy::Network::Authz_client::DoneFunc on_done);

  // See if check calls are disabled for Network proxy
  bool AuthzCheckDisabled() const {
    return authz_config_.disable_check;
  }

  std::map<std::string, std::string> getLabels(const bssl::UniquePtr<X509> &cert);

 private:
  // Envoy cluster manager for making gRPC calls.
  Upstream::ClusterManager& cm_;
  // The dikastes client
  std::unique_ptr<::Envoy::Network::Authz_client::AuthzClient> authz_client_;
  // The authz config
  const AuthzConfig& authz_config_;
  std::map<std::string, std::string> labels_;
  int nid_;
  // @SM TBD CheckTransport::AsyncClientPtr check_client_;
  // @SM TBD ReportTransport::AsyncClientPtr report_client_;
  void BuildCommonChecks(AuthzRequestDataPtr request_data,
			 const std::map<std::string, std::string> &labels,
                         const std::string& source_user) const;
};

class AuthzCmConfig : public Logger::Loggable<Logger::Id::filter> {
  public:
    static AuthzCmConfig& getInstance(const std::string &clusterName, const std::string &sock) {
      static AuthzCmConfig instance(clusterName, sock);
      return instance;
    }

    envoy::api::v2::Cluster getCluster() {
       return _cluster;
    }

  private:
    envoy::api::v2::Cluster _cluster;
    AuthzCmConfig(const std::string &clusterName, const std::string &sockName);

    ~AuthzCmConfig() = default;
};


}  // namespace Authz 
}  // namespace Network 
}  // namespace Envoy
