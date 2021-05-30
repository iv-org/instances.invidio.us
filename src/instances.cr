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

require "./helpers/*"

CONFIG = load_config()

Kemal::CLI.new ARGV

macro rendered(filename)
  render "src/instances/views/#{{{filename}}}.ecr"
end

alias Instance = NamedTuple(flag: String?, region: String?, stats: JSON::Any?, type: String, uri: String, monitor: JSON::Any?)

INSTANCES = {} of String => Instance

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
      body = HTTP::Client.get(URI.parse("https://raw.githubusercontent.com/iv-org/documentation/master/Invidious-Instances.md")).body
    rescue ex
      body = ""
    end

    instances = {} of String => Instance

    body = body.split("### Blocked:")[0]
    body.scan(/\[(?<host>[^ \]]+)\]\((?<uri>[^\)]+)\)( .(?<region>[\x{1f100}-\x{1f1ff}]{2}))?/mx).each do |md|
      region = md["region"]?.try { |region| region.codepoints.map { |codepoint| (codepoint - 0x1f1a5).chr }.join("") }
      flag = md["region"]?

      uri = URI.parse(md["uri"])
      host = md["host"]

      case type = host.split(".")[-1]
      when "onion"
        type = "onion"

        if CONFIG["fetch_onion_instance_stats"]?
          begin
            args = Process.parse_arguments("--socks5-hostname '#{CONFIG["tor_sock_proxy_address"]}:#{CONFIG["tor_sock_proxy_port"]}' 'http://#{uri.host}/api/v1/stats'")
            response = nil
            Process.run("curl", args: args) do |result|
              data = result.output.read_line
              response = JSON.parse(data)
            end

            stats = response
          rescue ex
            stats = nil
          end
        end
      when "i2p"
      else
        type = uri.scheme.not_nil!
        client = HTTP::Client.new(uri)
        client.connect_timeout = 5.seconds
        client.read_timeout = 5.seconds
        begin
          stats = JSON.parse(client.get("/api/v1/stats").body)
        rescue ex
          stats = nil
        end
      end

      monitor = monitors.try &.select { |monitor| monitor["name"].try &.as_s == host }[0]?
      instances[host] = {flag: flag, region: region, stats: stats, type: type, uri: uri.to_s, monitor: monitor || instances[host]?.try &.[:monitor]?}
    end

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
  "health"   => ->(name : String, instance : Instance) { -(instance[:monitor]?.try &.["30dRatio"]["ratio"].as_s.to_f || 0.0) },
  "location" => ->(name : String, instance : Instance) { instance[:region]? || "ZZ" },
  "name"     => ->(name : String, instance : Instance) { name },
  "signup"   => ->(name : String, instance : Instance) { instance[:stats]?.try &.["openRegistrations"]?.try { |bool| bool.as_bool ? 0 : 1 } || 2 },
  "type"     => ->(name : String, instance : Instance) { instance[:type] },
  "users"    => ->(name : String, instance : Instance) { -(instance[:stats]?.try &.["usage"]?.try &.["users"]["total"].as_i || 0) },
  "version"  => ->(name : String, instance : Instance) { instance[:stats]?.try &.["software"]?.try &.["version"].as_s.try &.split("-", 2)[0].split(".").map { |a| -a.to_i } || [0, 0, 0] },
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
