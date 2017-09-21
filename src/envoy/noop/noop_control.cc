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
#include <sstream>
#include <vector>

#include "src/envoy/noop/noop_control.h"

#include "common/common/base64.h"
#include "common/common/utility.h"

using ::google::protobuf::util::Status;
using ::google::protobuf::Map;
using StatusCode = ::google::protobuf::util::error::Code;
using ::istio::mixer_client::Attributes;
//using ::istio::mixer_client::noop::CheckOptions;
using ::istio::noop_client::DoneFunc;
using ::istio::noop_client::NoopClientOptions;
//using ::istio::mixer_client::noop::MixerClientOptions;
//using ::istio::mixer_client::ReportOptions;
//using ::istio::mixer_client::QuotaOptions;

namespace Envoy {
namespace Network {
namespace Noop {
namespace {

// Define attribute names
const std::string kSourceUser = "source.user";

const std::string kRequestLabels = "request.labels";
const std::string kNamespace = "namespace";
const std::string kAccount = "account";

// TCP attributes
// Downstream tcp connection: source ip/port.
const std::string kSourceIp = "source.ip";
const std::string kSourcePort = "source.port";
// Upstream tcp connection: destionation ip/port.
const std::string kTargetIp = "target.ip";
const std::string kTargetPort = "target.port";

// Context attributes
const std::string kContextProtocol = "context.protocol";
const std::string kContextTime = "context.time";

void SetStringAttribute(const std::string& name, const std::string& value,
                        Attributes* attr) {
  if (!value.empty()) {
    attr->attributes[name] = Attributes::StringValue(value);
  }
}

void SetInt64Attribute(const std::string& name, uint64_t value,
                       Attributes* attr) {
  attr->attributes[name] = Attributes::Int64Value(value);
}

void SetIPAttribute(const std::string& name, const Network::Address::Ip& ip,
                    Attributes* attr) {
  if (ip.ipv4()) {
    uint32_t ipv4 = ip.ipv4()->address();
    attr->attributes[name] = Attributes::BytesValue(
        std::string(reinterpret_cast<const char*>(&ipv4), sizeof(ipv4)));
  } else if (ip.ipv6()) {
    std::array<uint8_t, 16> ipv6 = ip.ipv6()->address();
    attr->attributes[name] = Attributes::BytesValue(
        std::string(reinterpret_cast<const char*>(ipv6.data()), 16));
  }
}

void extract_spiffy_attr(const std::string &source_user, std::map<std::string, std::string> &rmap) {
  std::stringstream ss(source_user);
  std::string item;
  std::vector<std::string> tokens;
  while (getline(ss, item, '/')) {
    tokens.push_back(std::move(item));
  }
  if (tokens.size() != 7) {
    return;
  }
  rmap[kNamespace] = tokens[4];
  rmap[kAccount] = tokens[6];
}

}  // namespace

NoopControl::NoopControl(const NoopConfig& noop_config,
                         Upstream::ClusterManager& cm,
                         Event::Dispatcher& dispatcher,
                         Runtime::RandomGenerator& random)
    : cm_(cm), noop_config_(noop_config) {
     std::ignore = dispatcher;

  NoopClientOptions options;

  options.uuid_generate_func = [&random]() -> std::string {
    return random.uuid();
  };

  noop_client_ = ::istio::noop_client::CreateNoopClient(options);
}

istio::noop_client::CancelFunc NoopControl::SendCheck(
    AuthzRequestDataPtr request_data, DoneFunc on_done) {
  if (!noop_client_) {
    on_done(
        Status(StatusCode::INVALID_ARGUMENT, "Missing mixer_server cluster"), nullptr);
    return nullptr;
  }
  ENVOY_LOG(debug, "Send Check:");
  return noop_client_->Check(request_data->request,
                             CheckTransport::GetFunc(cm_), on_done);
}

void NoopControl::BuildNetworkCheck(NetworkRequestDataPtr request_data,
				    std::map<std::string, std::string> attrs,
                                    Network::Connection& connection,
                                    const std::string& source_user) const {
  SetStringAttribute(kSourceUser, source_user, &request_data->attributes);

  const Network::Address::Ip* remote_ip = connection.remoteAddress().ip();
  if (remote_ip) {
    SetIPAttribute(kSourceIp, *remote_ip, &request_data->attributes);
    SetInt64Attribute(kSourcePort, remote_ip->port(),
                      &request_data->attributes);
  }

  request_data->attributes.attributes[kContextTime] =
      Attributes::TimeValue(std::chrono::system_clock::now());

  SetStringAttribute(kContextProtocol, "tcp", &request_data->attributes);
  request_data->attributes.attributes[kRequestLabels] = Attributes::StringMapValue(std::move(attrs));
}

void NoopControl::BuildAuthzCheck(AuthzRequestDataPtr request_data,
                                 Network::Connection& connection,
                                 const std::string& source_user) const {

  std::map<std::string, std::string> spiffy_attrs;

  extract_spiffy_attr(source_user, spiffy_attrs);
  ENVOY_LOG(debug, "Calling to setup the atts {}", source_user);
  ::istio::v1::authz::Request_Subject* subject = request_data->request.mutable_subject();

  if (spiffy_attrs.find(kAccount) != spiffy_attrs.end()) {
    subject->set_service_account(spiffy_attrs[kAccount]);
  }
  if (spiffy_attrs.find(kNamespace) != spiffy_attrs.end()) {
    subject->set_namespace_(spiffy_attrs[kNamespace]);
  }

  subject->set_ip_address(connection.remoteAddress().asString());
}
 
}  // namespace Noop
}  // namespace Network
}  // namespace Envoy
