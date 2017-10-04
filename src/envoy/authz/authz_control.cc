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

#include "src/envoy/authz/authz_control.h"
#include "envoy/http/header_map.h"

#include "common/common/base64.h"
#include "common/common/utility.h"

using ::google::protobuf::util::Status;
using ::google::protobuf::Map;
using StatusCode = ::google::protobuf::util::error::Code;
using ::Envoy::Network::Authz_client::DoneFunc;
using ::Envoy::Network::Authz_client::AuthzClientOptions;
using ::Envoy::Http::HeaderEntry;
using ::Envoy::Http::HeaderMap;

namespace Envoy {
namespace Network {
namespace Authz {
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

// @SM TBD Make it a template for map k,v types.
void SetPbuffMapStr2Str(::google::protobuf::Map< ::std::string, ::std::string>*dst,
                       const std::map<std::string, std::string>& src)
{
  if (dst != nullptr) {
    for (std::map<std::string, std::string>::const_iterator it = src.begin(); it != src.end(); it++) {
      (*dst)[it->first] = it->second;
    }
  }
}

#define TAGCLAIMLABEL 1
#define SIZETYLEN (sizeof(uint8_t) * 2)
int priv_nid = -1;
int getNid() {
    if (priv_nid == -1) {
      priv_nid = OBJ_create("1.3.6.1.4.1.94567.1.1.1", "kvAutz", "kvAutz");
    }
    return priv_nid;
}

int parse_asn1_str_(const unsigned char *start, std::string &rval)
{
  uint8_t t, l;

  t = static_cast<uint8_t>(*start);
  if (t != V_ASN1_PRINTABLESTRING) {
//    ENVOY_LOG(debug, "{}: Not a string at {} ({})", __func__, start, t);
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

int parse_context_spec_label(const unsigned char *start, long *omax,
                             std::map<std::string, std::string> &result) {
  std::string key, val;
  long slen;
  int ptag, pclass, rval;
  int bcount = 0;

  rval = ASN1_get_object(&start, &slen, &ptag, &pclass, *omax);
  if (rval & 0x80) {
//    ENVOY_LOG(debug, "{}: Bad object header", __func__);
    return -1;
  }
  if (ptag != V_ASN1_SEQUENCE) {
//    ENVOY_LOG(debug, "{}: tag {} pclass: {} invalid!", __func__, ptag, pclass);
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
//    ENVOY_LOG(debug, "{}: bcount {} >= max {}", __func__, bcount, *omax);
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
//  ENVOY_LOG(debug, "{}: k,v is {}: {} (omax: {})", __func__, key, val, *omax);
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
//    ENVOY_LOG(debug, "{}: Bad object header", __func__);
    return result;
  }
  if (ptag != V_ASN1_SEQUENCE) {
//    ENVOY_LOG(debug, "{}: tag {} pclass: {} invalid!", __func__, ptag, pclass);
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

}  // namespace


AuthzControl::AuthzControl(const AuthzConfig& authz_config,
                         Upstream::ClusterManager& cm,
                         Event::Dispatcher& dispatcher,
                         Runtime::RandomGenerator& random)
    : cm_(cm), authz_config_(authz_config) {
     std::ignore = dispatcher;

  AuthzClientOptions options;

  options.uuid_generate_func = [&random]() -> std::string {
    return random.uuid();
  };

  authz_client_ = ::Envoy::Network::Authz_client::CreateAuthzClient(options);
  nid_ = getNid();
}

Envoy::Network::Authz_client::CancelFunc AuthzControl::SendCheck(
    AuthzRequestDataPtr request_data, DoneFunc on_done) {
  if (!authz_client_) {
    on_done(
        Status(StatusCode::INVALID_ARGUMENT, "Missing authz_server cluster"), nullptr);
    return nullptr;
  }
  ENVOY_LOG(debug, "Send Check:");
  return authz_client_->Check(request_data->request,
                             CheckTransport::GetFunc(cm_), on_done);
}

void AuthzControl::BuildCommonChecks(AuthzRequestDataPtr request_data,
				     const std::map<std::string, std::string> &labels,
                                     const std::string& source_user) const {
  std::map<std::string, std::string> spiffy_attrs;

  extract_spiffy_attr(source_user, spiffy_attrs);
  ENVOY_LOG(debug, "Calling to setup the atts {}", source_user);
  ::authz::v1::Request_Subject* subject = request_data->request.mutable_subject();

  if (spiffy_attrs.find(kAccount) != spiffy_attrs.end()) {
    subject->set_service_account(spiffy_attrs[kAccount]);
  }
  if (spiffy_attrs.find(kNamespace) != spiffy_attrs.end()) {
    subject->set_namespace_(spiffy_attrs[kNamespace]);
  }

  SetPbuffMapStr2Str(subject->mutable_service_account_labels(), labels);
}

void AuthzControl::BuildAuthzCheck(AuthzRequestDataPtr request_data,
				   const std::map<std::string, std::string> &labels,
                                   const Network::Connection& connection,
                                   const std::string& source_user) const {
  BuildCommonChecks(request_data, labels, source_user);

  ::authz::v1::Request_Subject* subject = request_data->request.mutable_subject();
  subject->set_ip_address(connection.remoteAddress().ip()->addressAsString());
  subject->set_port(std::to_string(connection.remoteAddress().ip()->port()));
}

void AuthzControl::BuildAuthzHttpCheck(AuthzRequestDataPtr request_data, HeaderMap &headers,
				       const std::map<std::string, std::string> &labels,
                                       const Network::Connection* connection,
                                       const std::string& source_user) const {
  ENVOY_LOG(debug, "{}", __func__);
  BuildCommonChecks(request_data, labels, source_user);
  // Fill in the http header values.
  const HeaderEntry *entryPath = headers.Path();
  const HeaderEntry *entryMethod = headers.Method();

  ::authz::v1::Request_Action* action = request_data->request.mutable_action();
  ::authz::v1::HTTPRequest *httpreq = action->mutable_http();
  if (entryPath != nullptr) {
    std::string str(entryPath->value().c_str(), entryPath->value().size());
    httpreq->set_path(str);
  }
  if (entryMethod != nullptr) {
    std::string str(entryMethod->value().c_str(), entryMethod->value().size());
    httpreq->set_method(str);
  }

  ::authz::v1::Request_Subject* subject = request_data->request.mutable_subject();
  subject->set_ip_address(connection->remoteAddress().ip()->addressAsString());
  subject->set_port(std::to_string(connection->remoteAddress().ip()->port()));
}
 
std::map<std::string, std::string> AuthzControl::getLabels(const bssl::UniquePtr<X509> &cert) {
  std::map<std::string, std::string> result;

  if (!cert) {
    ENVOY_LOG(debug, "No cert: {}", __func__);
    return result;
  }
  if (labels_.size() > 0) {
    ENVOY_LOG(debug, "Labels: already extracted {}", __func__);
    return labels_;
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
  labels_ = result;
  return result;
}

}  // namespace Authz
}  // namespace Network
}  // namespace Envoy
