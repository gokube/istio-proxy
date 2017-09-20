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
#include "common/ssl/connection_impl.h"
#include "openssl/obj.h"
#include "openssl/asn1.h"
#include "openssl/x509v3.h"
#include "openssl/bio.h"

using ::google::protobuf::util::Status;
using StatusCode = ::google::protobuf::util::error::Code;

namespace Envoy {
namespace Network {
namespace Noop {

namespace {

#define TAGCLAIMLABEL 1
#define SIZETYLEN (sizeof(uint8_t) * 2)
int priv_nid = -1;
int getNid() {
    if (priv_nid == -1) {
      priv_nid = OBJ_create("1.3.6.1.4.1.94567.1.1.1", "kvAutz", "kvAutz");
    }
    return priv_nid;
}
}

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
                  new NoopControl(noop_config_, cm_, dispatcher, random));
            });
  }

  NoopControl& noop_control() { return tls_->getTyped<NoopControl>(); }
};

typedef std::shared_ptr<TcpConfig> TcpConfigPtr;

class TcpInstance : public Network::Filter,
                    public Network::ConnectionCallbacks,
                    public Logger::Loggable<Logger::Id::filter> {
 private:
  enum class State { NotStarted, Calling, Completed, Closed };

  istio::noop_client::CancelFunc cancel_check_;
  NoopControl& noop_control_;
  std::shared_ptr<AuthzRequestData> request_data_;
  Network::ReadFilterCallbacks* filter_callbacks_{};
  State state_{State::NotStarted};
  bool calling_check_{};
  int nid_;

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
      origin_user = ssl->subjectPeerCertificate();
      if (ssl_peer) {
        labels = getLabels();
      }
      // origin_user = ssl->uriSanPeerCertificate(); subjectPeerCertificate
    }

    noop_control_.BuildAuthzCheck(request_data_,
                                  filter_callbacks_->connection(), origin_user);
    // @SM: Log the content of Build TCP Check
    ENVOY_CONN_LOG(debug, "Called Noop TcpInstance(}), ssl {}",
                   filter_callbacks_->connection(), s_ctx, ssl_peer == true ? "yes":"no");
  }

  int parse_asn1_str_(const unsigned char *start, std::string &rval)
  {
    uint8_t t, l;

    t = static_cast<uint8_t>(*start);
    if (t != V_ASN1_PRINTABLESTRING) {
      ENVOY_LOG(debug, "{}: Not a string at {} ({})", __func__, start, t);
      return -1;
    }
    start++;
    l = static_cast<uint8_t>(*start);
    start++;
    for (long i = 0; i < l; i++) {
      rval += static_cast<char>(start[i]);
    }
    return SIZETYLEN + l;
  }

  int parse_context_spec_label(const unsigned char *start, long *omax, std::map<std::string, std::string> &result) {
    std::string key, val;
    long slen;
    int ptag, pclass, rval;
    int bcount = 0;

    rval = ASN1_get_object(&start, &slen, &ptag, &pclass, *omax);
    if (rval & 0x80) {
      ENVOY_LOG(debug, "{}: Bad object header", __func__);
      return -1;
    }
    if (ptag != V_ASN1_SEQUENCE) {
      ENVOY_LOG(debug, "{}: tag {} pclass: {} invalid!", __func__, ptag, pclass);
      return -1;
    }
    bcount += SIZETYLEN;
    // Start of the key
    int l = parse_asn1_str_(start, key);
    if (l <= 0) {
      return -1;
    }
    start += l;
    bcount += l;

    if (bcount >= *omax) {
      ENVOY_LOG(debug, "{}: bcount {} >= max {}", __func__, bcount, *omax);
      return -1;
    }

    // Must have the value now
    l = parse_asn1_str_(start, val);
    if (l <= 0) {
      return -1;
    }
    start += l;
    bcount += l;
    result.insert(std::map<std::string, std::string>::value_type(key, val));

    *omax -= bcount;
    ENVOY_LOG(debug, "{}: k,v is {}: {} (omax: {})", __func__, key, val, *omax);
    return bcount;
  }

  std::map<std::string, std::string> parse_claims(ASN1_OCTET_STRING *data) {
    const unsigned char *start;
    long slen;
    int ptag, pclass, rval;
    std::map<std::string, std::string> result;
    uint8_t classntag;

    start = data->data;
/*
    ENVOY_LOG(debug, "len: {}, type: {}, flags: {}, start: {}", data->length, data->type, data->flags, start);
    for (int i = 0; i < data->length; i++) {
       ENVOY_LOG(debug, "{}", data->data[i]);
    }
*/
    rval = ASN1_get_object(&start, &slen, &ptag, &pclass, data->length);
    if (rval & 0x80) {
      ENVOY_LOG(debug, "{}: Bad object header", __func__);
      return result;
    }
    if (ptag != V_ASN1_SEQUENCE) {
      ENVOY_LOG(debug, "{}: tag {} pclass: {} invalid!", __func__, ptag, pclass);
      return result;
    }

    long omax = slen;
    int l;
    for (classntag = static_cast<uint8_t>(*start);
         omax > 0  && classntag == (V_ASN1_CONTEXT_SPECIFIC|TAGCLAIMLABEL);
         start += l, classntag = static_cast<uint8_t>(*start)) {

      start += SIZETYLEN;
      omax -= SIZETYLEN;
      l = parse_context_spec_label(start, &omax, result);
      if (l <= 0) {
        return std::map<std::string, std::string>();
      }
    }

    return result;
  }

  std::map<std::string, std::string> getLabels() {
    Ssl::ConnectionImpl *ssl_impl = dynamic_cast<Ssl::ConnectionImpl*>(filter_callbacks_->connection().ssl());
    bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl_impl->rawSslForTest()));
    std::map<std::string, std::string> result;

    if (!cert) {
      ENVOY_LOG(debug, "No cert: {}", __func__);
      return result;
    }

    int azRef = X509_get_ext_by_NID(cert.get(), nid_, -1);
    if (azRef < 0) {
      ENVOY_LOG(debug, "{} no kvref, nid: {}, {}", __func__, nid_, azRef);
      return result;
    }

    X509_EXTENSION *ext = X509_get_ext(cert.get(), azRef);
    if (!ext) {
      ENVOY_LOG(debug, "no ext: {}", __func__);
      return result;
    }

    result = parse_claims(X509_EXTENSION_get_data(ext));
    return result;
  }

 public:
  TcpInstance(TcpConfigPtr config) : noop_control_(config->noop_control()) {
    nid_ = getNid();
    ENVOY_LOG(debug, "Called TcpInstance: {} {}", __func__, nid_);
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

    return Network::FilterStatus::Continue;
  }

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override {
      ENVOY_LOG(debug, "Called TcpInstance onEvent: {}", enumToInt(event));
      if (event != Network::ConnectionEvent::Connected) {
        return;
      }
      _logData("OnEvent");
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

      noop_control_.BuildAuthzCheck(request_data_,
                                    filter_callbacks_->connection(), origin_user);
      ENVOY_CONN_LOG(debug, "Called onEvent, ssl {}",
                     filter_callbacks_->connection(), ssl_peer == true ? "yes":"no");
      if (!noop_control_.NoopCheckDisabled()) {
        state_ = State::Calling;
        filter_callbacks_->connection().readDisable(true);
        calling_check_ = true;
        cancel_check_ = noop_control_.SendCheck(request_data_, [this](const Status& status) { completeCheck(status); });
        calling_check_ = false;
        //@SM find a good place to hook this response.
        // return state__ == State::Calling ? Network::FilterStatus::StopIteration : Network::FilterStatus::Continue;
      }
  }

  void completeCheck(const Status& status) {
    ENVOY_LOG(debug, "{}: {}", __func__, status.ToString());
    if (state_ == State::Closed) {
      return;
    } 
    state_ = State::Completed;
    filter_callbacks_->connection().readDisable(false);

    if (!status.ok()) {
      // check_status_code_ = status.errror_code();
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
