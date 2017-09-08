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
#include "src/envoy/noop/config.h"
#include "src/envoy/noop/noop_control.h"

using ::google::protobuf::util::Status;
using StatusCode = ::google::protobuf::util::error::Code;

namespace Envoy {
namespace Network {
namespace Noop {

class TcpConfig : public Logger::Loggable<Logger::Id::filter> {
 private:
  Upstream::ClusterManager& cm_;
  NoopConfig noop_config_;
  ThreadLocal::SlotPtr tls_;

 public:
  TcpConfig(const Json::Object& config,
            Server::Configuration::FactoryContext& context)
      : cm_(context.clusterManager()),
        tls_(context.threadLocal().allocateSlot()) {
    noop_config_.Load(config);
    Runtime::RandomGenerator& random = context.random();
    tls_->set(
        [this, &random](Event::Dispatcher& dispatcher)
            -> ThreadLocal::ThreadLocalObjectSharedPtr {
              return ThreadLocal::ThreadLocalObjectSharedPtr(
                  new NoopControl(noop_config_, cm_, dispatcher));
            });
  }

  NoopControl& noop_control() { return tls_->getTyped<NoopControl>(); }
};

typedef std::shared_ptr<TcpConfig> TcpConfigPtr;

class TcpInstance : public Network::Filter,
                    public Network::ConnectionCallbacks,
                    public Logger::Loggable<Logger::Id::filter> {
 private:
  NoopControl& noop_control_;
  std::shared_ptr<NetworkRequestData> request_data_;
  Network::ReadFilterCallbacks* filter_callbacks_{};

  void _logData(std::string s_ctx) {
    // Reports are always enabled.. And TcpReport uses attributes
    // extracted by BuildTcpCheck
    request_data_ = std::make_shared<NetworkRequestData>();

    std::string origin_user;
    Ssl::Connection* ssl = filter_callbacks_->connection().ssl();
    if (ssl != nullptr) {
      origin_user = ssl->uriSanPeerCertificate();
    }

    std::map<std::string, std::string> attrs = { {"k1", "v1"}, {"k2", "v2"}};
   
    noop_control_.BuildNetworkCheck(request_data_, attrs,
                                    filter_callbacks_->connection(), origin_user);
    // @SM: Log the content of Build TCP Check
    ENVOY_CONN_LOG(debug, "Called Noop TcpInstance({}), ssl {}: {}",
                   filter_callbacks_->connection(), s_ctx, ssl != nullptr ? "yes":"no",
                   request_data_->attributes.DebugString());
  }

 public:
  TcpInstance(TcpConfigPtr config) : noop_control_(config->noop_control()) {
    ENVOY_LOG(debug, "Called TcpInstance: {}", __func__);
  }

  ~TcpInstance() {
    ENVOY_LOG(debug, "Called TcpInstance : {}", __func__);
  }

  void initializeReadFilterCallbacks(
      Network::ReadFilterCallbacks& callbacks) override {
    ENVOY_LOG(debug, "Called TcpInstance: {}", __func__);
    filter_callbacks_ = &callbacks;
    filter_callbacks_->connection().addConnectionCallbacks(*this);
  }

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data) override {
    ENVOY_CONN_LOG(debug, "Called TcpInstance onRead bytes: {}",
                   filter_callbacks_->connection(), data.length());
    return Network::FilterStatus::Continue;
  }

  Network::FilterStatus onWrite(Buffer::Instance& data) override {
    ENVOY_CONN_LOG(debug, "Called TcpInstance onWrite bytes: {}",
                   filter_callbacks_->connection(), data.length());
    return Network::FilterStatus::Continue;
  }

  Network::FilterStatus onNewConnection() override {
    ENVOY_CONN_LOG(debug,
                   "Called TcpInstance onNewConnection: remote {}, local {}",
                   filter_callbacks_->connection(),
                   filter_callbacks_->connection().remoteAddress().asString(),
                   filter_callbacks_->connection().localAddress().asString());

    _logData("NewConnection");
    // Reports are always enabled.. And TcpReport uses attributes
    // extracted by BuildTcpCheck
    request_data_ = std::make_shared<NetworkRequestData>();

    std::string origin_user;
    Ssl::Connection* ssl = filter_callbacks_->connection().ssl();
    if (ssl != nullptr) {
      origin_user = ssl->uriSanPeerCertificate();
    }

    std::map<std::string, std::string> attrs = { {"k1", "v1"}, {"k2", "v2"}};
   
    noop_control_.BuildNetworkCheck(request_data_, attrs,
                                    filter_callbacks_->connection(), origin_user);
    // @SM: Log the content of Build TCP Check
    ENVOY_CONN_LOG(debug, "Called Noop TcpInstance onNewConnection: {}",
                   filter_callbacks_->connection(),
                   request_data_->attributes.DebugString());

    return Network::FilterStatus::Continue;
  }

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override {
      ENVOY_LOG(debug, "Called TcpInstance onEvent: {}", enumToInt(event));
      if (event != Network::ConnectionEvent::Connected) {
        return;
      }
      _logData("OnEvent");
  }

  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}
};

}  // namespace Noop
}  // namespace Network

namespace Server {
namespace Configuration {

class TcpNoopFilterFactory : public NamedNetworkFilterConfigFactory {
 public:
  NetworkFilterFactoryCb createFilterFactory(const Json::Object& config,
                                             FactoryContext& context) override {
    Network::Noop::TcpConfigPtr tcp_config(
        new Network::Noop::TcpConfig(config, context));
    return [tcp_config](Network::FilterManager& filter_manager) -> void {
      std::shared_ptr<Network::Noop::TcpInstance> instance =
          std::make_shared<Network::Noop::TcpInstance>(tcp_config);
      filter_manager.addReadFilter(Network::ReadFilterSharedPtr(instance));
      filter_manager.addWriteFilter(Network::WriteFilterSharedPtr(instance));
    };
  }
  std::string name() override { return "noop"; }
  NetworkFilterType type() override { return NetworkFilterType::Both; }
};

static Registry::RegisterFactory<TcpNoopFilterFactory,
                                 NamedNetworkFilterConfigFactory>
    register_;

}  // namespace Configuration
}  // namespace Server
}  // namespace Envoy
