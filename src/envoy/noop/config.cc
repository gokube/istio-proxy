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

#include "src/envoy/noop/config.h"

namespace Envoy {
namespace Network {
namespace Noop {
namespace {

// The Json object name for static attributes.
const std::string kNoopAttributes("noop_attributes");
const std::string kDisableAttrCheck("noop_disable_check");
/*
void ReadString(const Json::Object& json, const std::string& name,
                std::string* value) {
  if (json.hasObject(name)) {
    *value = json.getString(name);
  }
}
*/

void ReadStringMap(const Json::Object& json, const std::string& name,
                   std::map<std::string, std::string>* map) {
  if (json.hasObject(name)) {
    json.getObject(name)->iterate(
        [map](const std::string& key, const Json::Object& obj) -> bool {
          (*map)[key] = obj.asString();
          return true;
        });
  }
}

}  // namespace

void NoopConfig::Load(const Json::Object& json) {
  ReadStringMap(json, kNoopAttributes, &noop_attributes);

  disable_attribute_check = json.getBoolean(kDisableAttrCheck, false);
}

}  // namespace Noop 
}  // namespace Network 
}  // namespace Envoy