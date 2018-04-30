#!/usr/bin/ruby

require_relative "../lib/algorithms.rb"

def httpd_conf_location_block(path, config_options, indent = 2)
  contents = ["<Location #{path}>",
              "  AuthType None",
              "  Require all granted",
              "  ProxyPass http://testapp:4567"]
  contents += config_options.map { |option| "  #{option}" }
  contents += ["</Location>", ""]

  contents.map { |line| "#{' ' * indent}#{line}\n" }.join
end

def httpd_conf_contents
  contents = <<-EOL
ServerRoot "/etc/httpd"
Include conf.modules.d/*.conf

LoadModule proxy_jwt_auth_module /usr/lib64/httpd/modules/mod_proxy_jwt_auth.so

listen 80

User apache
Group apache

<Directory />
  AllowOverride none
  Require all denied
</Directory>

DocumentRoot "/var/www/html"

<Directory "/var/www/html">
  AllowOverride None
  Require all granted
</Directory>

ErrorLog "/dev/stderr"
LogLevel warn
LogFormat "%h %l %u %t \\"%r\\" %>s %b" common
CustomLog "/dev/stdout" common

AddDefaultCharset UTF-8

<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>

<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>



<VirtualHost *:80>
  LogLevel Debug

  SetEnv TEST_VAR_1 OneValue
  SetEnv TEST_VAR_2 TwoValue

  ProxyJwtAuthClaimMap TEST_VAR_1 testvar1

EOL

  contents += httpd_conf_location_block("/defaults", [])
  contents += httpd_conf_location_block("/enabled", ["ProxyJwtAuthEnabled On"])

  contents += "# Claim Mapping Tests\n"
  { "missing_enabled" => "On", "missing_disabled" => "Off" }.each_pair do |name, enabled|
    contents += httpd_conf_location_block("/claim_map/#{name}/without_testvar2", ["ProxyJwtAuthEnabled On", "ProxyJwtAuthAllowMissing #{enabled}"])
    contents += httpd_conf_location_block("/claim_map/#{name}/with_testvar2",    ["ProxyJwtAuthEnabled On", "ProxyJwtAuthAllowMissing #{enabled}", "ProxyJwtAuthClaimMap TEST_VAR_2 testvar2"])
    # Unknown var
    contents += httpd_conf_location_block("/claim_map/#{name}/with_testvar3", ["ProxyJwtAuthEnabled On", "ProxyJwtAuthAllowMissing #{enabled}", "ProxyJwtAuthClaimMap TEST_VAR_3 testvar3"])
  end

  contents += "# Algorithm Tests\n"
  ModuleTestSuite::ALGORITHMS.keys.each do |algorithm|
    options = ["ProxyJwtAuthEnabled On", "ProxyJwtAuthTokenAlgorithm #{algorithm}"]
    key_path = ModuleTestSuite::Keys.private_key_filename(algorithm)
    options.push("ProxyJwtAuthTokenAlgorithmKeyPath #{key_path}") unless key_path.nil?

    contents += httpd_conf_location_block("/algorithms/#{algorithm}", options)
  end

  contents += "# Duration Tests\n"
  contents += httpd_conf_location_block("/token_duration", ["ProxyJwtAuthEnabled On", "ProxyJwtAuthTokenDuration 90"])

  contents += "</VirtualHost>"

  contents
end

File.write("/test_files/httpd/httpd.conf", httpd_conf_contents)
puts "Wrote test httpd.conf"
ModuleTestSuite::Keys.save_keys
puts "Wrote test keys"
