#!/bin/bash
# Copyright 2020 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Extract host configuration info from testdata.yaml fixture
python $(dirname $0)/generate-host-envs.py

# The .dockerignore is for production, we'll need this
sed -i '/.circleci/d' $(dirname $0)/../../.dockerignore

# docker-compose rm -f
# docker-compose pull

# Parameter specifies --build-arg package_repo=... (testing or not prod packages)
docker-compose build --no-cache "$@"
