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

class GraphQLError < Exception
  getter errors : Array(JSON::Any)

  def initialize(@errors : Array(JSON::Any))
    super(@errors.to_s)
  end
end

def paginated_graphql(query : String, key : Tuple, vars : Hash? = nil, **kwargs) : Iterator(JSON::Any)
  my_vars = {} of String => String
  if vars
    my_vars = vars.merge(my_vars)
  end
  json = {"query" => query, "variables" => my_vars}

  iter = Iterator.of(Iterator.stop)
  has_next_page = true
  Iterator.of do
    item = iter.next
    if item.is_a?(Iterator::Stop) && has_next_page
      resp = GitHub.post("graphql", **kwargs, json: json)
      resp.raise_for_status
      result = JSON.parse(resp.body)
      if (errors = result["errors"]?)
        raise GraphQLError.new(errors.as_a)
      end
      data = result["data"].dig(*key)
      if (has_next_page = data["pageInfo"]["hasNextPage"].as_bool)
        my_vars["cursor"] = data["pageInfo"]["endCursor"].as_s
      end
      iter = data["nodes"].as_a.each
      item = iter.next
    end
    item
  end
end

def get_user(token : Token) : JSON::Any
  # https://docs.github.com/v3/users#get-the-authenticated-user
  resp = GitHub.get("user", headers: {Authorization: token})
  resp.raise_for_status
  JSON.parse(resp.body)
end

def get_repositories_for_user(token : Token) : Iterator(JSON::Any)
  paginated_graphql(%(
    query ($cursor: String) {
      viewer {
        repositories(privacy: PUBLIC,
                     first: 100,
                     affiliations: [OWNER, ORGANIZATION_MEMBER, COLLABORATOR],
                     ownerAffiliations: [OWNER, ORGANIZATION_MEMBER, COLLABORATOR],
                     after: $cursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            nameWithOwner
          }
        }
      }
    }
  ), {"viewer", "repositories"},
    headers: {Authorization: token})
end

{% for kind in ["issues", "pulls"] %}
  {% api_kind = {"issues" => "issues", "pulls" => "pullRequests"}[kind] %}

  def get_{{kind.id}}(repo : String, *, open_only : Bool = false, token : Token) : Iterator(JSON::Any)
    repo_owner, repo_name = repo.split("/", 2)
    paginated_graphql(%(
      query ($repo_owner: String!, $repo_name: String!, $cursor: String) {
        repository(owner: $repo_owner, name: $repo_name) {
          {{api_kind.id}}(first: 100,
                      #{open_only ? "states: [OPEN]," : ""}
                      orderBy: {field: UPDATED_AT, direction: DESC},
                      after: $cursor) {
            pageInfo { hasNextPage endCursor }
            nodes {
              number
              url
              title
              author { login }
              state
              updatedAt
              labels(last: 100) {
                nodes {
                  name
                  color
                }
              }
              {% if kind == "pulls" %}
              reviews(last: 100, states: [APPROVED, CHANGES_REQUESTED, DISMISSED]) {
                nodes {
                  author {
                    login
                  }
                  state
                  authorCanPushToRepository
                }
              }
              {% end %}
            }
          }
        }
      }
    ), {"repository", {{api_kind}}},
      {"repo_owner" => repo_owner, "repo_name" => repo_name},
      headers: {Authorization: token})
  end
{% end %}
