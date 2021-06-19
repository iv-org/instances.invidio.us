require "yaml"

def load_config
  return YAML.parse(File.read("config.yml"))
end

def load_instance_yaml(contents)
  return YAML.parse(contents)
end
