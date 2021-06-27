# "instances.invidio.us" (which is a status page)
# Copyright (C) 2019  Omar Roth
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require "http/client"
require "kemal"
require "uri"

require "./fetch.cr"
require "./helpers/helpers.cr"

CONFIG = load_config()

Kemal::CLI.new ARGV

macro rendered(filename)
  render "src/instances/views/#{{{filename}}}.ecr"
end

alias Owner = NamedTuple(name: String, url: String)
alias ClearNetInstance = NamedTuple(flag: String?, region: String?, country_name: String?, stats: JSON::Any?, type: String, uri: String, status_url: String?, privacy_policy: String?, ddos_protection: String?, owner: Owner, notes: String?, monitor: JSON::Any?)
alias OnionInstance = NamedTuple(flag: String?, region: String?, country_name: String?, stats: JSON::Any?, type: String, uri: String, clearnet_url: String?, privacy_policy: String?, owner: Owner, notes: String?, monitor: JSON::Any?)

INSTANCES = {} of String => ClearNetInstance | OnionInstance

spawn do
  loop do
    monitors = [] of JSON::Any
    page = 1
    loop do
      begin
        client = HTTP::Client.new(URI.parse("https://stats.uptimerobot.com/89VnzSKAn"))
        client.connect_timeout = 10.seconds
        client.read_timeout = 10.seconds
        response = JSON.parse(client.get("/api/getMonitorList/89VnzSKAn?page=#{page}").body)

        monitors += response["psp"]["monitors"].as_a
        page += 1

        break if response["psp"]["perPage"].as_i * (page - 1) + 1 > response["psp"]["totalMonitors"].as_i
      rescue ex
        error_message = response.try &.as?(String).try &.["errorStats"]?
        error_message ||= ex.message
        puts "Error pulling monitors: #{error_message}"
        break
      end
    end
    begin
      # Needs to be replaced once merged!
      body = HTTP::Client.get(URI.parse("https://raw.githubusercontent.com/TheFrenchGhosty/documentation/instances-list-rewrite/Public-Instances.md")).body
    rescue ex
      body = ""
    end

    instances = {} of String => ClearNetInstance | OnionInstance
    get_clearnet_instances(body, instances, monitors)
    get_onion_instances(body, instances)

    INSTANCES.clear
    INSTANCES.merge! instances

    sleep CONFIG["minutes_between_refresh"].as_i.minutes
  end
end

before_all do |env|
  env.response.headers["X-XSS-Protection"] = "1; mode=block"
  env.response.headers["X-Content-Type-Options"] = "nosniff"
  env.response.headers["Referrer-Policy"] = "same-origin"
  env.response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
end

get "/" do |env|
  sort_by = env.params.query["sort_by"]?
  sort_by ||= "type,users"

  instances = sort_instances(INSTANCES, sort_by)

  rendered "index"
end

get "/instances.json" do |env|
  env.response.headers["Access-Control-Allow-Origin"] = "*"
  env.response.content_type = "application/json; charset=utf-8"

  sort_by = env.params.query["sort_by"]?
  sort_by ||= "type,users"

  instances = sort_instances(INSTANCES, sort_by)

  if env.params.query["pretty"]?.try &.== "1"
    instances.to_pretty_json
  else
    instances.to_json
  end
end

error 404 do |env|
  env.redirect "/"
  halt env, status_code: 302, response: ""
end

static_headers do |response, filepath, filestat|
  response.headers.add("Cache-Control", "max-age=86400")
end

SORT_PROCS = {
  "health"   => ->(name : String, instance : ClearNetInstance | OnionInstance) { -(instance[:monitor]?.try &.["30dRatio"]["ratio"].as_s.to_f || 0.0) },
  "location" => ->(name : String, instance : ClearNetInstance | OnionInstance) { instance[:region]? || "ZZ" },
  "name"     => ->(name : String, instance : ClearNetInstance | OnionInstance) { name },
  "signup"   => ->(name : String, instance : ClearNetInstance | OnionInstance) { instance[:stats]?.try &.["openRegistrations"]?.try { |bool| bool.as_bool ? 0 : 1 } || 2 },
  "type"     => ->(name : String, instance : ClearNetInstance | OnionInstance) { instance[:type] },
  "users"    => ->(name : String, instance : ClearNetInstance | OnionInstance) { -(instance[:stats]?.try &.["usage"]?.try &.["users"]["total"].as_i || 0) },
  "version"  => ->(name : String, instance : ClearNetInstance | OnionInstance) { instance[:stats]?.try &.["software"]?.try &.["version"].as_s.try &.split("-", 2)[0].split(".").map { |a| -a.to_i } || [0, 0, 0] },
}

def sort_instances(instances, sort_by)
  instances = instances.to_a
  sorts = sort_by.downcase.split("-", 2)[0].split(",").map { |s| SORT_PROCS[s] }

  instances.sort! do |a, b|
    compare = 0
    sorts.each do |sort|
      first = sort.call(a[0], a[1])
      case first
      when Int32
        compare = first <=> sort.call(b[0], b[1]).as(Int32)
      when Array(Int32)
        compare = first <=> sort.call(b[0], b[1]).as(Array(Int32))
      when Float64
        compare = first <=> sort.call(b[0], b[1]).as(Float64)
      when String
        compare = first <=> sort.call(b[0], b[1]).as(String)
      else
        raise "Invalid proc"
      end
      break if compare != 0
    end
    compare
  end
  instances.reverse! if sort_by.ends_with?("-reverse")
  instances
end

gzip true
public_folder "assets"

Kemal.config.powered_by_header = false
Kemal.run
