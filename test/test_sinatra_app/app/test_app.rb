#!/usr/bin/ruby

require "sinatra"
require "json"

set :bind, "0.0.0.0"
set :port, 4567

get "/*" do
  status 200
  content_type :json
  body JSON.dump({}.tap do |resp|
                   request.instance_variables.each do |var|
                     resp[var] = request.instance_variable_get var
                   end
                 end)
end
