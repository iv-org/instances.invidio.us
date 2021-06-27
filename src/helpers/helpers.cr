require "yaml"

def load_config
  config = YAML.parse(File.read("config.yml"))
  return config
end
