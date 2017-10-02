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
#include "src/envoy/authz/grpc_transport.h"

using ::google::protobuf::util::Status;
using StatusCode = ::google::protobuf::util::error::Code;

namespace Envoy {
namespace Network {
namespace Authz {
namespace {

// gRPC request timeout
const std::chrono::milliseconds kGrpcRequestTimeoutMs(5000);

/*
// HTTP trace headers that should pass to gRPC metadata from origin request.
// x-request-id is added for easy debugging.
const LowerCaseString kRequestId("x-request-id");
const LowerCaseString kB3TraceId("x-b3-traceid");
const LowerCaseString kB3SpanId("x-b3-spanid");
const LowerCaseString kB3ParentSpanId("x-b3-parentspanid");
const LowerCaseString kB3Sampled("x-b3-sampled");
const LowerCaseString kB3Flags("x-b3-flags");
const LowerCaseString kOtSpanContext("x-ot-span-context");

// The name for the mixer server cluster.
const char* kMixerServerClusterName = "authz_server";

inline void CopyHeaderEntry(const HeaderEntry* entry,
                            const LowerCaseString& key,
                            Http::HeaderMap& headers) {
  if (entry) {
    std::string val(entry->value().c_str(), entry->value().size());
    headers.addReferenceKey(key, val);
  }
}
*/

// The name for the authz server cluster.
const char* kAuthzServerClusterName = "authz_server";

}  // namespace

template <class RequestType, class ResponseType>
GrpcTransport<RequestType, ResponseType>::GrpcTransport(
    AsyncClientPtr async_client, const RequestType& request,
    ResponseType* response,
    istio::authz_client::DoneFunc on_done)
    : async_client_(std::move(async_client)),
      response_(response),
      on_done_(on_done),
      request_(async_client_->send(
          descriptor(), request, *this,
          Optional<std::chrono::milliseconds>(kGrpcRequestTimeoutMs))) {
  ENVOY_LOG(debug, "Sending {} request: {}", descriptor().name(),
            request.DebugString());
}

template <class RequestType, class ResponseType>
void GrpcTransport<RequestType, ResponseType>::onCreateInitialMetadata(Http::HeaderMap& metadata) {
  std::ignore = metadata;
  return;
}

template <class RequestType, class ResponseType>
void GrpcTransport<RequestType, ResponseType>::onSuccess(
    std::unique_ptr<ResponseType>&& response) {
  ENVOY_LOG(debug, "{} response: {}", descriptor().name(),
            response->DebugString());
  response->Swap(response_);
  on_done_(Status::OK, response_);
  delete this;
}

template <class RequestType, class ResponseType>
void GrpcTransport<RequestType, ResponseType>::onFailure(
    Grpc::Status::GrpcStatus status, const std::string& message) {
  ENVOY_LOG(debug, "{} failed with code: {}, {}", descriptor().name(), status,
            message);
  on_done_(Status(static_cast<StatusCode>(status), message), nullptr);
  delete this;
}

template <class RequestType, class ResponseType>
typename GrpcTransport<RequestType, ResponseType>::Func
GrpcTransport<RequestType, ResponseType>::GetFunc(Upstream::ClusterManager& cm) {
  return [&cm](const RequestType& request, ResponseType* response,
               istio::authz_client::DoneFunc
               on_done) -> istio::authz_client::CancelFunc {
    auto transport = new GrpcTransport<RequestType, ResponseType>(
        typename GrpcTransport<RequestType, ResponseType>::AsyncClientPtr(
            new Grpc::AsyncClientImpl<RequestType, ResponseType>(
                cm, kAuthzServerClusterName)),
        request, response, on_done);
    return [transport]() { transport->request_->cancel(); };
  };
}


template <>
const google::protobuf::MethodDescriptor& CheckTransport::descriptor() {
  static const google::protobuf::MethodDescriptor* check_descriptor =
      istio::v1::authz::Authorization::descriptor()->FindMethodByName("Check");
  ASSERT(check_descriptor);

  return *check_descriptor;
}
/*
template <>
const google::protobuf::MethodDescriptor& ReportTransport::descriptor() {
  static const google::protobuf::MethodDescriptor* report_descriptor =
      istio::v1::authz::descriptor()->FindMethodByName("Report");
  ASSERT(report_descriptor);

  return *report_descriptor;
}
*/

// explicitly instantiate CheckTransport and ReportTransport
template CheckTransport::Func CheckTransport::GetFunc(
    Upstream::ClusterManager& cm);
/*
template ReportTransport::Func ReportTransport::GetFunc(
    Upstream::ClusterManager& cm, const HeaderMap* headers);
*/

}  // namespace Authz 
}  // namespace Network 
}  // namespace Envoy
