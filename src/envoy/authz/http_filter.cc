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
#include "common/common/logger.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "envoy/registry/registry.h"
#include "envoy/ssl/connection.h"
#include "envoy/thread_local/thread_local.h"
#include "server/config/network/http_connection_manager.h"
#include "src/envoy/authz/config.h"
#include "src/envoy/authz/authz_control.h"
#include "common/ssl/connection_impl.h"

#include <map>
#include <mutex>
#include <thread>

using ::google::protobuf::util::Status;
using StatusCode = ::google::protobuf::util::error::Code;
using ::authz::v1::Response;
using ResponseCode = ::authz::v1::Response_Status_Code;

namespace Envoy {
namespace Http {
namespace Authz {
namespace {

// Switch to turn on/off authz check only.
const std::string kJsonNameAuthzCheck("authz_check");

// The prefix in route opaque data to define
// a sub string map of authz attributes forwarded to upstream proxy.
//const std::string kPrefixForwardAttributes("authz_forward_attributes.");

// Convert Status::code to HTTP code
int HttpCode(int code) {
  // Map Canonical codes to HTTP status codes. This is based on the mapping
  // defined by the protobuf http error space.
  switch (code) {
    case StatusCode::OK:
      return 200;
    case StatusCode::CANCELLED:
      return 499;
    case StatusCode::UNKNOWN:
      return 500;
    case StatusCode::INVALID_ARGUMENT:
      return 400;
    case StatusCode::DEADLINE_EXCEEDED:
      return 504;
    case StatusCode::NOT_FOUND:
      return 404;
    case StatusCode::ALREADY_EXISTS:
      return 409;
    case StatusCode::PERMISSION_DENIED:
      return 403;
    case StatusCode::RESOURCE_EXHAUSTED:
      return 429;
    case StatusCode::FAILED_PRECONDITION:
      return 400;
    case StatusCode::ABORTED:
      return 409;
    case StatusCode::OUT_OF_RANGE:
      return 400;
    case StatusCode::UNIMPLEMENTED:
      return 501;
    case StatusCode::INTERNAL:
      return 500;
    case StatusCode::UNAVAILABLE:
      return 503;
    case StatusCode::DATA_LOSS:
      return 500;
    case StatusCode::UNAUTHENTICATED:
      return 401;
    default:
      return 500;
  }
}

}  // namespace

class Config {
 private:
  Upstream::ClusterManager& cm_;
  Network::Authz::AuthzConfig authz_config_;
  ThreadLocal::SlotPtr tls_;

 public:
  Config(const Json::Object& config,
         Server::Configuration::FactoryContext& context)
      : cm_(context.clusterManager()),
        tls_(context.threadLocal().allocateSlot()) {
    authz_config_.Load(config);
    Runtime::RandomGenerator& random = context.random();
    tls_->set(
        [this, &random](Event::Dispatcher& dispatcher)
            -> ThreadLocal::ThreadLocalObjectSharedPtr {
              return ThreadLocal::ThreadLocalObjectSharedPtr(
                  new Network::Authz::AuthzControl(authz_config_, cm_, dispatcher, random));
            });
  }

  Network::Authz::AuthzControl& authz_control() { return tls_->getTyped<Network::Authz::AuthzControl>(); }
};

typedef std::shared_ptr<Config> ConfigPtr;

class Instance : public Http::StreamDecoderFilter,
                 public Http::AccessLog::Instance,
                 public Logger::Loggable<Logger::Id::http> {
 private:
  Network::Authz::AuthzControl& authz_control_;
  std::shared_ptr<Network::Authz::AuthzRequestData> request_data_;
  Envoy::Network::Authz_client::CancelFunc cancel_check_;

  enum State { NotStarted, Calling, Complete, Responded };
  State state_;

  StreamDecoderFilterCallbacks* decoder_callbacks_;

  bool initiating_call_;
  int check_status_code_;

  bool authz_check_disabled_;

  // check authz on/off flags in route opaque data
  void check_authz_route_flags() {
    // Check is enabbled by default.
    authz_check_disabled_ = authz_control_.AuthzCheckDisabled();
    auto route = decoder_callbacks_->route();
    if (route != nullptr) {
      auto entry = route->routeEntry();
      if (entry != nullptr) {
        auto check_key = entry->opaqueConfig().find(kJsonNameAuthzCheck);
        if (check_key != entry->opaqueConfig().end() &&
            check_key->second == "off") {
          authz_check_disabled_ = true;
        }
      }
    }
  }

  // Extract a prefixed string map from route opaque config.
  // Route opaque config only supports flat name value pair, have to use
  // prefix to create a sub string map. such as:
  //    prefix.key1 = value1
/*
  Utils::StringMap GetRouteStringMap(const std::string& prefix) {
    Utils::StringMap attrs;
    auto route = decoder_callbacks_->route();
    if (route != nullptr) {
      auto entry = route->routeEntry();
      if (entry != nullptr) {
        for (const auto& it : entry->opaqueConfig()) {
          if (it.first.substr(0, prefix.size()) == prefix) {
            attrs[it.first.substr(prefix.size(), std::string::npos)] =
                it.second;
          }
        }
      }
    }
    return attrs;
  }
*/

  std::map<std::string, std::string> getLabels() {
    Ssl::Connection* ssl =
        const_cast<Ssl::Connection*>(decoder_callbacks_->connection()->ssl());
    Ssl::ConnectionImpl *ssl_impl = dynamic_cast<Ssl::ConnectionImpl*>(ssl);
    bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl_impl->rawSslForTest()));
    return authz_control_.getLabels(cert);
  }

 public:
  Instance(ConfigPtr config)
      : authz_control_(config->authz_control()),
        state_(NotStarted),
        initiating_call_(false),
        check_status_code_(HttpCode(StatusCode::UNKNOWN)) {
    ENVOY_LOG(debug, "Called Authz::Instance : {}", __func__);
  }

  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool) override {
    ENVOY_LOG(debug, "Called Authz::Instance : {}", __func__);

    check_authz_route_flags();
    if (authz_check_disabled_) {
      ENVOY_LOG(debug, "{} authz check disabled.", __func__);
      return FilterHeadersStatus::Continue;
    }

    request_data_ = std::make_shared<Network::Authz::AuthzRequestData>();

    bool ssl_peer = false;
    std::string origin_user;
    std::map<std::string, std::string> labels;
    Ssl::Connection* ssl =
        const_cast<Ssl::Connection*>(decoder_callbacks_->connection()->ssl());
    if (ssl != nullptr) {
      ssl_peer = ssl->peerCertificatePresented();
      if (ssl_peer) {
        labels = getLabels();
      }
      origin_user = ssl->uriSanPeerCertificate();
    }


    authz_control_.BuildAuthzHttpCheck(request_data_, headers, labels,
                                       decoder_callbacks_->connection(), origin_user);

    state_ = Calling;
    initiating_call_ = true;
    cancel_check_ = authz_control_.SendCheck(
        request_data_,
        [this](const Status& status, Response *resp) { completeCheck(status, resp); });
    initiating_call_ = false;

    if (state_ == Complete) {
      return FilterHeadersStatus::Continue;
    }
    ENVOY_LOG(debug, "Called Authz::Instance : {} Stop", __func__);
    return FilterHeadersStatus::StopIteration;
  }

  FilterDataStatus decodeData(Buffer::Instance& data,
                              bool end_stream) override {
    if (authz_check_disabled_) {
      return FilterDataStatus::Continue;
    }

    ENVOY_LOG(debug, "Called Authz::Instance : {} ({}, {})", __func__,
              data.length(), end_stream);
    if (state_ == Calling) {
      return FilterDataStatus::StopIterationAndBuffer;
    }
    return FilterDataStatus::Continue;
  }

  FilterTrailersStatus decodeTrailers(HeaderMap&) override {
    if (authz_check_disabled_) {
      return FilterTrailersStatus::Continue;
    }

    ENVOY_LOG(debug, "Called Authz::Instance : {}", __func__);
    if (state_ == Calling) {
      return FilterTrailersStatus::StopIteration;
    }
    return FilterTrailersStatus::Continue;
  }

  void setDecoderFilterCallbacks(
      StreamDecoderFilterCallbacks& callbacks) override {
    ENVOY_LOG(debug, "Called Authz::Instance : {}", __func__);
    decoder_callbacks_ = &callbacks;
  }

  void completeCheck(const Status& status, Response *resp) {
    ENVOY_LOG(debug, "{} check complete {}", __func__,
              status.ToString());
    // This stream has been reset, abort the callback.
    if (state_ == Responded) {
      return;
    }
    if ((!status.ok() ||
        resp->status().code() != ResponseCode::Response_Status_Code_OK) &&
        state_ != Responded) {
      state_ = Responded;
      check_status_code_ = HttpCode(StatusCode::PERMISSION_DENIED);
      Utility::sendLocalReply(*decoder_callbacks_, false,
                              Code(check_status_code_), status.ToString());
      return;
    }

    state_ = Complete;
    if (!initiating_call_) {
      decoder_callbacks_->continueDecoding();
    }
  }

  void onDestroy() override {
    ENVOY_LOG(debug, "Called Authz::Instance : {} state: {}", __func__, state_);
    if (state_ != Calling) {
      cancel_check_ = nullptr;
    }
    state_ = Responded;
    if (cancel_check_) {
      ENVOY_LOG(debug, "Cancelling check call");
      cancel_check_();
      cancel_check_ = nullptr;
    }
  }

  virtual void log(const HeaderMap*, const HeaderMap* response_headers,
                   const AccessLog::RequestInfo& request_info) override {
    ENVOY_LOG(debug, "Called Authz::Instance : {}", __func__);
    std::ignore = response_headers;
    std::ignore = request_info;
    // If decodeHaeders() is not called, not to call Authz report.
  }
};

}  // namespace Authz
}  // namespace Http 

namespace Server {
namespace Configuration {

class AuthzConfigFactory : public NamedHttpFilterConfigFactory {
 public:
  HttpFilterFactoryCb createFilterFactory(const Json::Object& config,
                                          const std::string&,
                                          FactoryContext& context) override {
    Http::Authz::ConfigPtr authz_config(
        new Http::Authz::Config(config, context));
    return
        [authz_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
          std::shared_ptr<Http::Authz::Instance> instance =
              std::make_shared<Http::Authz::Instance>(authz_config);
          callbacks.addStreamDecoderFilter(
              Http::StreamDecoderFilterSharedPtr(instance));
          callbacks.addAccessLogHandler(
              Http::AccessLog::InstanceSharedPtr(instance));
        };
  }
  std::string name() override { return "authz"; }
};

static Registry::RegisterFactory<AuthzConfigFactory,
                                 NamedHttpFilterConfigFactory>
    register_;

}  // namespace Configuration
}  // namespace Server
}  // namespace Envoy
