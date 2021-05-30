require "halite"

struct Token
  def initialize(@token : String)
  end

  def to_s
    "token #{@token}"
  end
end

GitHub = Halite::Client.new do
  endpoint("https://api.github.com/")
  logging(skip_request_body: true, skip_response_body: true)
end

private macro get_json_list(url, key = nil, params = Hash(String, String).new, max_items = 10000, **kwargs)
  %url : String? = {{url}}
  %max_items : Int32 = {{max_items}}
  %params = {{params}}
  %params["per_page"] = %max_items.to_s
  %n = 0
  while %url
    %resp = GitHub.get(%url, params: %params, {{**kwargs}})
    %resp.raise_for_status
    %result = JSON.parse(%resp.body)
    %url = %resp.links.try(&.["next"]?).try(&.target)
    %params = {"per_page" => %max_items.to_s}
    %result {% if key %}[{{key}}]{% end %}.as_a.each do |x|
      yield x
      %n += 1
      break if %n >= %max_items
    end
    break if %n >= %max_items
  end
end

def get_user(token : Token) : JSON::Any
  # https://docs.github.com/v3/users#get-the-authenticated-user
  resp = GitHub.get("user", headers: {Authorization: token})
  resp.raise_for_status
  JSON.parse(resp.body)
end

def get_repositories(token : Token, & : JSON::Any ->)
  # https://docs.github.com/en/rest/reference/repos#list-repositories-for-the-authenticated-user
  get_json_list("user/repos", headers: {Authorization: token})
end

def get_issues(repo : String, *, since : String?, state : String = "all", token : Token, & : JSON::Any ->)
  # https://docs.github.com/en/rest/reference/repos#list-repositories-for-the-authenticated-user
  params = {"state" => state, "sort" => "updated", "direction" => "asc"}
  params["since"] = since if since
  get_json_list("repos/#{repo}/issues", headers: {Authorization: token}, params: params)
end
