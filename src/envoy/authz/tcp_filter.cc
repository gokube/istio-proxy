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

#include "common/common/base64.h"
#include "common/common/enum_to_int.h"
#include "common/common/logger.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/instance.h"
#include "server/config/network/http_connection_manager.h"
#include "src/envoy/authz/config.h"
#include "src/envoy/authz/authz_control.h"
#include "common/ssl/connection_impl.h"

using ::google::protobuf::util::Status;
using StatusCode = ::google::protobuf::util::error::Code;
using ::istio::v1::authz::Response;
using ResponseCode = ::istio::v1::authz::Response_Status_Code;

namespace Envoy {
namespace Network {
namespace Authz {

class TcpConfig : public Logger::Loggable<Logger::Id::filter> {
 private:
  Upstream::ClusterManager& cm_;
  AuthzConfig authz_config_;
  ThreadLocal::SlotPtr tls_;

 public:
  TcpConfig(const Json::Object& config,
            Server::Configuration::FactoryContext& context)
      : cm_(context.clusterManager()),
        tls_(context.threadLocal().allocateSlot()) {
    authz_config_.Load(config);
    Runtime::RandomGenerator& random = context.random();
    tls_->set(
        [this, &random](Event::Dispatcher& dispatcher)
            -> ThreadLocal::ThreadLocalObjectSharedPtr {
              return ThreadLocal::ThreadLocalObjectSharedPtr(
                  new AuthzControl(authz_config_, cm_, dispatcher, random));
            });
  }

  AuthzControl& authz_control() { return tls_->getTyped<AuthzControl>(); }
};

typedef std::shared_ptr<TcpConfig> TcpConfigPtr;

class TcpInstance : public Network::Filter,
                    public Network::ConnectionCallbacks,
                    public Logger::Loggable<Logger::Id::filter> {
 private:
  enum class State { NotStarted, Calling, Completed, Closed };

  istio::authz_client::CancelFunc cancel_check_;
  AuthzControl& authz_control_;
  std::shared_ptr<AuthzRequestData> request_data_;
  Network::ReadFilterCallbacks* filter_callbacks_{};
  State state_{State::NotStarted};
  bool calling_check_{};

  void _logData(std::string s_ctx) {
    bool ssl_peer = false;
    // Reports are always enabled.. And TcpReport uses attributes
    // extracted by BuildTcpCheck
    request_data_ = std::make_shared<AuthzRequestData>();

    std::string origin_user;
    std::map<std::string, std::string> labels;
    Ssl::Connection* ssl = filter_callbacks_->connection().ssl();
    if (ssl != nullptr) {
      ssl_peer = ssl->peerCertificatePresented();
      if (ssl_peer) {
        labels = getLabels();
      }
      origin_user = ssl->uriSanPeerCertificate();
    }

    authz_control_.BuildAuthzCheck(request_data_, labels,
                                  filter_callbacks_->connection(), origin_user);
    // @SM: Log the content of Build TCP Check
    ENVOY_CONN_LOG(warn, "Called Authz TcpInstance(}), ssl {}",
                   filter_callbacks_->connection(), s_ctx, ssl_peer == true ? "yes":"no");
  }

  std::map<std::string, std::string> getLabels() {
    Ssl::ConnectionImpl *ssl_impl = dynamic_cast<Ssl::ConnectionImpl*>(filter_callbacks_->connection().ssl());
    bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl_impl->rawSslForTest()));
    return authz_control_.getLabels(cert);
  }

 public:
  TcpInstance(TcpConfigPtr config) : authz_control_(config->authz_control()) {
    ENVOY_LOG(debug, "Called TcpInstance: {}", __func__);
  }

  ~TcpInstance() {
    ENVOY_LOG(debug, "Called TcpInstance : {}", __func__);
  }

  void initializeReadFilterCallbacks(
      Network::ReadFilterCallbacks& callbacks) override {
    ENVOY_LOG(warn, "Called TcpInstance: {}", __func__);
    filter_callbacks_ = &callbacks;
    filter_callbacks_->connection().addConnectionCallbacks(*this);
  }

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data) override {
    ENVOY_CONN_LOG(warn, "Called TcpInstance onRead bytes: {}",
                   filter_callbacks_->connection(), data.length());
    return Network::FilterStatus::Continue;
  }

  Network::FilterStatus onWrite(Buffer::Instance& data) override {
    ENVOY_CONN_LOG(warn, "Called TcpInstance onWrite bytes: {}",
                   filter_callbacks_->connection(), data.length());
    return Network::FilterStatus::Continue;
  }

  void _check_authz(std::string ctx) {
    _logData(ctx);
    bool ssl_peer = false;
    // Reports are always enabled.. And TcpReport uses attributes
    // extracted by BuildTcpCheck
    request_data_ = std::make_shared<AuthzRequestData>();

    std::string origin_user;
    std::map<std::string, std::string> labels;
    Ssl::Connection* ssl = filter_callbacks_->connection().ssl();
    if (ssl != nullptr) {
      ssl_peer = ssl->peerCertificatePresented();
      if (ssl_peer) {
        labels = getLabels();
      }
      origin_user = ssl->uriSanPeerCertificate();
    }

    authz_control_.BuildAuthzCheck(request_data_, labels,
                                  filter_callbacks_->connection(), origin_user);
    ENVOY_CONN_LOG(warn, "Called {}, ssl {}",
                   filter_callbacks_->connection(), __func__, ssl_peer == true ? "yes":"no");

    if (authz_control_.AuthzCheckDisabled() || ssl_peer == false) {
      return;
    }

    state_ = State::Calling;
    filter_callbacks_->connection().readDisable(true);
    calling_check_ = true;
    cancel_check_ = authz_control_.SendCheck(request_data_, [this](const Status &status, Response *resp) { completeCheck(status, resp); });
    calling_check_ = false;
  }

  Network::FilterStatus onNewConnection() override {
    ENVOY_CONN_LOG(warn,
                   "Called TcpInstance onNewConnection: remote {}, local {}",
                   filter_callbacks_->connection(),
                   filter_callbacks_->connection().remoteAddress().asString(),
                   filter_callbacks_->connection().localAddress().asString());
    _check_authz("onNewConnection");
    return state_ == State::Calling ? Network::FilterStatus::StopIteration
                                    : Network::FilterStatus::Continue;
  }

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override {
      ENVOY_LOG(warn, "Called TcpInstance onEvent: {}", enumToInt(event));
      if (event != Network::ConnectionEvent::Connected) {
        state_ = State::Closed;
        return;
      }
      _check_authz("onConnectedEvent");
  }

  void completeCheck(const Status& status, Response *resp) {
    ENVOY_LOG(warn, "{}: {}", __func__, status.ToString());
    if (state_ == State::Closed) {
      return;
    } 
    state_ = State::Completed;
    filter_callbacks_->connection().readDisable(false);

    if (!status.ok() ||
        resp->status().code() != ResponseCode::Response_Status_Code_OK) {
      ENVOY_CONN_LOG(warn, "{}: Closing connection {}",
                     filter_callbacks_->connection(), __func__,
                     std::to_string(resp->status().code()));
      filter_callbacks_->connection().close(
          Network::ConnectionCloseType::NoFlush);
    } else {
      if (!calling_check_) {
        filter_callbacks_->continueReading();
      }
    }
  }

  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}
};

}  // namespace Authz
}  // namespace Network

namespace Server {
namespace Configuration {

class TcpAuthzFilterFactory : public NamedNetworkFilterConfigFactory {
 public:
  NetworkFilterFactoryCb createFilterFactory(const Json::Object& config,
                                             FactoryContext& context) override {
    Network::Authz::TcpConfigPtr tcp_config(
        new Network::Authz::TcpConfig(config, context));
    return [tcp_config](Network::FilterManager& filter_manager) -> void {
      std::shared_ptr<Network::Authz::TcpInstance> instance =
          std::make_shared<Network::Authz::TcpInstance>(tcp_config);
      filter_manager.addReadFilter(Network::ReadFilterSharedPtr(instance));
      filter_manager.addWriteFilter(Network::WriteFilterSharedPtr(instance));
    };
  }
  std::string name() override { return "authz"; }
  NetworkFilterType type() override { return NetworkFilterType::Both; }
};

static Registry::RegisterFactory<TcpAuthzFilterFactory,
                                 NamedNetworkFilterConfigFactory>
    register_;

}  // namespace Configuration
}  // namespace Server
}  // namespace Envoy
