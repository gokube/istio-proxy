# Copyright 2016 Istio Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#

#MIXER_CLIENT = "63480a0c836fbeeb1daa2b24f5b749bd832a709c"
#@SM TBD: Make this a reference to a remote github branch rather than a local ref.
def dikastes_client_repositories(bind=True):
    native.local_repository(
        name = "dikastesclient_git",
        path = "/home/saurabh/go/src/github.com/tigera/istio-mixerclient",
    )

    if bind:
        native.bind(
            name = "mixer_client_lib",
            actual = "@dikastesclient_git//:mixer_client_lib",
        )
