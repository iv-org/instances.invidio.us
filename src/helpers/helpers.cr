require "yaml"

def load_config
  return YAML.parse(File.read("config.yml"))
end

def load_instance_yaml(contents)
  return YAML.parse(contents)
end

def try_convert_nil(contents)
  begin
    return contents.as_nil
  rescue TypeCastError
    return contents
  end
end
