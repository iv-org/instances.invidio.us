def fetch_country(md)
  region = md["flag"]?.try { |region| region.codepoints.map { |codepoint| (codepoint - 0x1f1a5).chr }.join("") }
  flag = md["flag"]?
  country_name = md["country_name"]?

  return flag, region, country_name
end

def fetch_notes(md)
  notes = md["notes"].strip("|")
  if notes.empty?
    notes = nil
  end

  return notes
end

def prepare_http_instance(md, instances, monitors)
  uri = URI.parse(md["uri"])
  host = md["host"]

  flag, region, country_name = fetch_country(md)

  status_url = md["status_url"]?

  privacy_policy = md["privacy_policy"]?

  ddos_protection = md["ddos_protection"].strip
  if ddos_protection == "None"
    ddos_protection = nil
  end

  owner = {name: md["owner"].strip("@"), url: md["owner_url"]}
  notes = fetch_notes(md)

  client = HTTP::Client.new(uri)
  client.connect_timeout = 5.seconds
  client.read_timeout = 5.seconds

  begin
    stats = JSON.parse(client.get("/api/v1/stats").body)
  rescue ex
    stats = nil
  end

  monitor = monitors.try &.select { |monitor| monitor["name"].try &.as_s == host }[0]?
  return {flag: flag, region: region, country_name: country_name, stats: stats, type: "https", uri: uri.to_s, status_url: status_url,
          privacy_policy: privacy_policy, ddos_protection: ddos_protection,
          owner: owner, notes: notes, monitor: monitor || instances[host]?.try &.[:monitor]?}
end

def prepare_onion_instance(md, instances)
  uri = URI.parse(md["uri"])
  host = md["host"]

  clearnet_url = md["clearnet_url"]
  flag, region, country_name = fetch_country(md)
  privacy_policy = md["privacy_policy"]?
  owner = {name: md["owner"].strip("@"), url: md["owner_url"]}
  notes = fetch_notes(md)

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

  return {flag: flag, region: region, country_name: country_name, stats: stats, type: "onion", uri: uri.to_s, clearnet_url: clearnet_url,
          privacy_policy: privacy_policy, owner: owner, notes: notes,
          monitor: nil}
end

def get_clearnet_instances(body, instances, monitors)
  # Crystal currently lacks a markdown parser that supports tables. So...
  clear_net_regexes = [
    /\[(?<host>[^ \]]+)\]\((?<uri>[^\)]+)\)/,                   # Address column
    /(?<flag>[\x{1f100}-\x{1f1ff}]{2}) (?<country_name>[^ ]+)/, # Country column
    /((\[[^\]]+\]\(.*\){1}\])\((?<status_url>.*)\)|(None))/,    # Status column
    /((\[[^ \]]+\]\((?<privacy_policy>[^\)]+)\))|(None))/,      # privacy policy column
    /(?<ddos_protection>.*)/,                                   # DDOS protection column
    /\[(?<owner>[^ \]]+)\]\((?<owner_url>[^\)]+)\)/,            # Owner column
    /(?<notes>.*)/,                                             # Note column
  ]

  body.scan(/#{clear_net_regexes.join(/ +\| +/)}/mx).each do |md|
    host = md["host"]
    instances[host] = prepare_http_instance(md, instances, monitors)
  end
end

def get_onion_instances(body, instances)
  # Crystal currently lacks a markdown parser that supports tables. So...
  clear_net_regexes = [
    /\[(?<host>[^ \]]+)\]\((?<uri>[^\)]+)\)/,                   # Address column
    /(?<flag>[\x{1f100}-\x{1f1ff}]{2}) (?<country_name>[^ ]+)/, # Country column
    /\[(?<clearnet_host>[^ \]]+)\]\((?<clearnet_url>[^\)]+)\)/, # Clearnet instance column
    /((\[[^ \]]+\]\((?<privacy_policy>[^\)]+)\))|(None))/,      # privacy policy column
    /\[(?<owner>[^ \]]+)\]\((?<owner_url>[^\)]+)\)/,            # Owner column
    /(?<notes>.*)/,                                             # Notes column
  ]

  body.scan(/#{clear_net_regexes.join(/ +\| +/)}/mx).each do |md|
    host = md["host"]
    instances[host] = prepare_onion_instance(md, instances)
  end
end
