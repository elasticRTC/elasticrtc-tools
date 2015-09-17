#
# Cookbook Name:: kurento
# Recipe:: docker
#
# Copyright 2014, Kurento
#
# Licensed under the Lesser GPL, Version 2.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.gnu.org/licenses/lgpl-2.1.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# See https://github.com/docker/docker/issues/9592
execute "echo \"Acquire::HTTP::Proxy::apt.dockerproject.org \\\"DIRECT\\\";\" >> /etc/apt/apt.conf.d/01proxy"

# Install docker-engine
package 'curl'
execute 'curl -sSL https://get.docker.com/ | sh'

# Install docker-compose
execute 'curl -L https://github.com/docker/compose/releases/download/1.4.0/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose'
execute 'chmod +x /usr/local/bin/docker-compose'
execute "curl -L https://raw.githubusercontent.com/docker/compose/$(docker-compose --version | awk 'NR==1{print $NF}')/contrib/completion/bash/docker-compose > /etc/bash_completion.d/docker-compose"
