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

#include <map>
#include <string>
#include <vector>

#include "envoy/json/json_object.h"
#include "include/attribute.h"

namespace Envoy {
namespace Network {
namespace Authz {

// A config for authz filter
struct AuthzConfig {
  // These static attributes will be matched from the cert. 
  std::map<std::string, std::string> authz_attributes;

  // if value is true then let un-matched traffic through
  bool disable_check;

  // Load the config from envoy config.
  void Load(const Json::Object& json);

};

}  // namespace Authz 
}  // namespace Network
}  // namespace Envoy
