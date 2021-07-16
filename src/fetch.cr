private def fetch_country(instance_data)
  region = instance_data["country"].to_s

  # A flag is made out of two regional indicator symbols.
  # So in order to convert from an ISO 3166 alpha-2 code into unicode we'll have to
  # add a specific offset to each character to make them into the required regional
  # indicator symbols. This offset is exactly 0x1f1a5.
  # Reference implementation https://schinckel.net/2015/10/29/unicode-flags-in-python/
  flag = region.codepoints.map { |codepoint| (codepoint + 0x1f1a5).chr }.join("")

  return region, flag
end

def prepare_http_instance(instance_data, instances_storage, monitors)
  uri = URI.parse(instance_data["url"].to_s)
  host = uri.host

  region, flag = fetch_country(instance_data)

  begin
    status_url = instance_data["status"].as_h["url"].to_s
  rescue TypeCastError
    status_url = nil
  end

  privacy_policy = instance_data["privacy_policy"].to_s
  ddos_mitm_protection = instance_data["ddos_mitm_protection"].to_s
  owner = {name: instance_data["owner"].to_s.split("/")[-1].to_s, url: instance_data["owner"].to_s}

  is_modified = instance_data["is_modified"].try &.as_bool? || false
  source = try_convert_nil(instance_data["source"])
  source = source.nil? ? source : source.to_s

  notes = instance_data["notes"].as_a?

  client = HTTP::Client.new(uri)
  client.connect_timeout = 5.seconds
  client.read_timeout = 5.seconds

  begin
    stats = JSON.parse(client.get("/api/v1/stats").body)
  rescue ex
    stats = nil
  end

  monitor = monitors.try &.select { |monitor| monitor["name"].try &.as_s == host }[0]?
  return {region: region, flag: flag, stats: stats, type: "https", uri: uri.to_s, status_url: status_url,
          privacy_policy: privacy_policy, ddos_mitm_protection: ddos_mitm_protection,
          owner: owner, is_modified: is_modified, source: source, notes: notes,
          monitor: monitor || instances_storage[host]?.try &.[:monitor]?}
end

def prepare_onion_instance(instance_data, instances_storage)
  uri = URI.parse(instance_data["url"].to_s)
  host = uri.host

  region, flag = fetch_country(instance_data)

  associated_clearnet_instance = try_convert_nil(instance_data["associated_clearnet_instance"])
  associated_clearnet_instance = associated_clearnet_instance.nil? ? associated_clearnet_instance : associated_clearnet_instance.to_s

  privacy_policy = instance_data["privacy_policy"].to_s
  owner = {name: instance_data["owner"].to_s.split("/")[-1].to_s, url: instance_data["owner"].to_s}

  is_modified = instance_data["is_modified"].try &.as_bool? || false
  source = try_convert_nil(instance_data["source"])
  source = source.nil? ? source : source.to_s

  notes = instance_data["notes"].as_a?

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

  return {region: region, flag: flag, stats: stats, type: "onion", uri: uri.to_s,
          associated_clearnet_instance: associated_clearnet_instance, privacy_policy: privacy_policy,
          owner: owner, is_modified: is_modified, source: source, notes: notes,
          monitor: nil}
end
