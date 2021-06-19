private def fetch_country(instance_data)
  region = instance_data["country"]["flag"]?.try { |region| region.to_s.codepoints.map { |codepoint| (codepoint - 0x1f1a5).chr }.join("") }.to_s
  flag = instance_data["country"]["flag"].to_s
  country_name = instance_data["country"]["name"].to_s

  return {flag: flag, region: region, name: country_name}
end

def prepare_http_instance(instance_data, instances_storage, monitors)
  uri = URI.parse(instance_data["url"].to_s)
  host = uri.host

  country = fetch_country(instance_data)

  begin
    status_url = instance_data["status"].as_h["url"].to_s
  rescue TypeCastError
    status_url = nil
  end

  privacy_policy = instance_data["privacy_policy"].to_s
  ddos_mitm_protection = instance_data["ddos_mitm_protection"].to_s
  owner = {name: instance_data["owner"].to_s.split("/")[-1].to_s, url: instance_data["owner"].to_s}

  is_modified = instance_data["modified"]["is_modified"].as_bool
  source_url = instance_data["modified"]["source_url"]?.try &.to_s || nil

  client = HTTP::Client.new(uri)
  client.connect_timeout = 5.seconds
  client.read_timeout = 5.seconds

  begin
    stats = JSON.parse(client.get("/api/v1/stats").body)
  rescue ex
    stats = nil
  end

  monitor = monitors.try &.select { |monitor| monitor["name"].try &.as_s == host }[0]?
  return {country: country, stats: stats, type: "https", uri: uri.to_s, status_url: status_url,
          privacy_policy: privacy_policy, ddos_mitm_protection: ddos_mitm_protection,
          owner: owner, modified: {is_modified: is_modified, source_url: source_url},
          monitor: monitor || instances_storage[host]?.try &.[:monitor]?}
end

def prepare_onion_instance(instance_data, instances_storage)
  uri = URI.parse(instance_data["url"].to_s)
  host = uri.host

  country = fetch_country(instance_data)

  associated_clearnet_instance = instance_data["associated_clearnet_instance"]?.try &.to_s || nil
  privacy_policy = instance_data["privacy_policy"].to_s
  owner = {name: instance_data["owner"].to_s.split("/")[-1].to_s, url: instance_data["owner"].to_s}

  is_modified = instance_data["modified"]["is_modified"].as_bool
  source_url = instance_data["modified"]["source_url"]?.try &.to_s || nil

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
  else
    stats = nil
  end

  return {country: country, stats: stats, type: "https", uri: uri.to_s, associated_clearnet_instance: associated_clearnet_instance,
          privacy_policy: privacy_policy,
          owner: owner, modified: {is_modified: is_modified, source_url: source_url},
          monitor: nil}
end
