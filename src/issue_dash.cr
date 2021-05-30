require "http"
require "ecr"
require "log"

require "jwt"
require "halite"
require "retour/http"
require "sqlite3"
require "future"

require "./github_api"

GITHUB_CLIENT_ID     = ENV["GITHUB_CLIENT_ID"]
GITHUB_CLIENT_SECRET = ENV["GITHUB_CLIENT_SECRET"]
APP_SECRET           = ENV["APP_SECRET"]
PORT                 = ENV["PORT"]?.try(&.to_i)
URL                  = ENV["URL"]
DATABASE_FILE        = ENV["DATABASE_FILE"]? || "./db.sqlite"

Log.setup_from_env

def abs_url(path : String) : String
  Path.posix(URL).join(path).to_s
end

class IssueDash
  include Retour::HTTPRouter

  def initialize(@db : DB::Database = DB.open("sqlite3:#{DATABASE_FILE}"))
    db.exec(%(
      CREATE TABLE IF NOT EXISTS issues (
        id INTEGER NOT NULL UNIQUE GENERATED ALWAYS AS (json_extract(json, '$.id')),
        json TEXT NOT NULL,
        updated_at TEXT NOT NULL GENERATED ALWAYS AS (json_extract(json, '$.updated_at')),
        dismissed_at TEXT,
        repo TEXT NOT NULL GENERATED ALWAYS AS (substr(json_extract(json, '$.repository_url'), 30)),
        url TEXT NOT NULL GENERATED ALWAYS AS (json_extract(json, '$.html_url')),
        title TEXT NOT NULL GENERATED ALWAYS AS (json_extract(json, '$.title')),
        author TEXT GENERATED ALWAYS AS (json_extract(json, '$.user.login')),
        is_open BOOLEAN NOT NULL GENERATED ALWAYS AS (json_extract(json, '$.state') = 'open'),
        is_pull BOOLEAN NOT NULL GENERATED ALWAYS AS (json_extract(json, '$.pull_request') IS NOT NULL)
      )
    ))
    db.exec(%(
      CREATE INDEX IF NOT EXISTS index1 ON issues (repo, updated_at, is_pull, is_open)
    ))
  end

  def auth_url(destination : String? = nil)
    redirect_uri = IssueDash.gen_auth
    if destination
      redirect_uri += "?" + HTTP::Params.encode({destination: destination})
    end
    "https://github.com/login/oauth/authorize?" + HTTP::Params.encode({
      client_id: GITHUB_CLIENT_ID, scope: "read:org", redirect_uri: abs_url(redirect_uri),
    })
  end

  record Login, jwt : String, token : Token, repos : Hash(String, String)

  @@logins = Hash(String, Login).new # The key is username

  def check_auth?(ctx) : Login?
    return unless (jwt_cookie = ctx.request.cookies["ses"]?)
    begin
      jwt, _ = JWT.decode(jwt_cookie.value, APP_SECRET, JWT::Algorithm::HS256)
    rescue JWT::Error
      return
    end
    return unless (username = jwt["username"]?)
    return unless (login = @@logins[username]?)
    return if login.jwt != jwt_cookie.value
    login
  end

  def check_auth!(ctx) : Login
    check_auth?(ctx) || raise HTTPException.redirect(auth_url(ctx.request.path))
  end

  def check_repo?(repo : String, login : Login) : String?
    login.repos[repo.downcase]?
  end

  def check_repo!(repo : String, kind : String, login : Login) : String
    check_repo?(repo, login) ||
      raise HTTPException.new(:NotFound,
        "Repository '#{repo}' not found or the user doesn't have access.\n" +
        "Check on GitHub: <https://github.com/#{repo}/#{kind}>"
      )
  end

  @[Retour::Get("/auth")]
  def auth(ctx)
    code = ctx.request.query_params["code"]?
    destination = ctx.request.query_params["destination"]? || "/"
    if !code
      raise HTTPException.redirect(auth_url(destination))
    end

    resp = GitHub.post("https://github.com/login/oauth/access_token", form: {
      "client_id"     => GITHUB_CLIENT_ID,
      "client_secret" => GITHUB_CLIENT_SECRET,
      "code"          => code,
    }).tap(&.raise_for_status)
    resp = HTTP::Params.parse(resp.body)
    begin
      token = Token.new(resp["access_token"])
    rescue e
      if resp["error"]? == "bad_verification_code"
        raise HTTPException.redirect(IssueDash.gen_auth)
      end
      raise e
    end

    repos = future do
      pairs = [] of {String, String}
      get_repositories(token) do |repo|
        repo = repo["full_name"].as_s
        pairs << {repo.downcase, repo}
      end
      pairs.sort!.to_h
    end

    username = get_user(token)["login"].as_s
    jwt = JWT.encode({"username" => username, "iat" => Time.utc.to_unix}, APP_SECRET, JWT::Algorithm::HS256)

    @@logins[username] = Login.new(jwt: jwt, token: token, repos: repos.get)

    raise HTTPException.redirect(abs_url(destination), headers: HTTP::Headers{"Set-Cookie" => "ses=#{jwt}"})
  end

  @[Retour::Get("/")]
  def index(ctx)
    login = check_auth!(ctx)
    repos = login.repos

    ECR.embed("#{__DIR__}/../templates/head.html", ctx.response)
    ECR.embed("#{__DIR__}/../templates/repos.html", ctx.response)
  end

  @[Retour::Get("/{repo:[^/]+/[^/]+}/{kind:issues|pulls}")]
  def issue_list(ctx, repo : String, kind : String)
    login = check_auth!(ctx)
    repo = check_repo!(repo, kind, login)

    latest = nil
    @db.query(%(
      SELECT updated_at FROM issues WHERE repo = ? ORDER BY updated_at DESC LIMIT 1
    ), repo) do |rs|
      rs.each do
        latest = rs.read(String)
      end
    end

    get_issues(repo, state: (latest ? "all" : "open"), since: latest, token: login.token) do |iss|
      @db.exec(%(
        INSERT INTO issues (json) VALUES(?) ON CONFLICT DO UPDATE SET json = excluded.json
      ), iss.to_json)
    end

    issues = [] of {id: Int64, url: String, title: String, author: String, updated_at: Time, is_dismissed: Bool}
    @db.query(%(
      SELECT id, url, title, author, updated_at, (coalesce(dismissed_at, '') >= updated_at) AS is_dismissed FROM issues
      WHERE repo = ? AND is_pull = ? AND is_open = 1
      ORDER BY updated_at DESC
    ), repo, kind == "pulls") do |rs|
      rs.each do
        issues << {
          id: rs.read(Int64), url: rs.read(String), title: rs.read(String), author: rs.read(String),
          updated_at: Time.parse_rfc3339(rs.read(String)), is_dismissed: rs.read(Bool),
        }
      end
    end

    ECR.embed("#{__DIR__}/../templates/head.html", ctx.response)
    ECR.embed("#{__DIR__}/../templates/issues.html", ctx.response)
  end

  @[Retour::Get("/update_issue")]
  def update_issue(ctx)
    repo = ctx.request.query_params["repo"] rescue raise HTTPException.new(:BadRequest)
    id = ctx.request.query_params["id"].to_i64 rescue raise HTTPException.new(:BadRequest)
    dismiss = ctx.request.query_params["dismiss"].to_i rescue raise HTTPException.new(:BadRequest)

    login = check_auth?(ctx) || raise HTTPException.new(:Unauthorized)
    repo = check_repo?(repo, login) || raise HTTPException.new(:Unauthorized)

    @db.exec(%(
      UPDATE issues SET dismissed_at = #{dismiss > 0 ? "updated_at" : "NULL"} WHERE id = ? AND repo = ?
    ), id, repo)
  end

  {% for name, path in {style: "assets/style.css"} %}
    {% ext = path.split(".")[-1] %}
    {% headers = "#{ext.upcase.id}_HEADERS".id %}
    {{headers}} = HTTP::Headers{
      "Content-Type"  => MIME.from_extension({{"." + ext}}),
      "Cache-Control" => "max-age=#{100.days.total_seconds}",
    }

    @[Retour::Get({{"/#{path.id}"}})]
    def static_{{name}}(ctx)
      ctx.response.headers.merge!({{headers}})
      ctx.response << {{read_file("#{__DIR__}/../#{path.id}")}}
    end

    def self.gen_{{name}}
      {{"/#{path.id}?#{`sha1sum #{__DIR__}/../#{path.id}`[0...10]}"}}
    end
  {% end %}

  def serve_request(ctx, reraise = false)
    if call(ctx, ctx).is_a?(Retour::NotFound)
      raise HTTPException.new(:NotFound, ctx.request.path)
    end
  rescue exception
    if !exception.is_a?(HTTPException)
      raise exception if reraise
      Log.error(exception: exception) { }
      exception = HTTPException.new(:InternalServerError)
    end
    ctx.response.content_type = "text/html"
    ctx.response.status = status = exception.status
    ctx.response.headers.merge!(exception.headers)
    return if status.redirection?
    ECR.embed("#{__DIR__}/../templates/head.html", ctx.response)
    ECR.embed("#{__DIR__}/../templates/error.html", ctx.response)
  end
end

class HTTPException < Exception
  getter status : HTTP::Status
  property headers : HTTP::Headers

  def initialize(@status : HTTP::Status, message : String = "", @headers : HTTP::Headers = HTTP::Headers.new)
    super(message)
  end

  def self.redirect(location : String, status : HTTP::Status = :Found, headers : HTTP::Headers = HTTP::Headers.new)
    headers["Location"] = location
    HTTPException.new(status, headers: headers)
  end
end

if (port = PORT)
  app = IssueDash.new
  server = HTTP::Server.new([
    HTTP::LogHandler.new,
  ]) do |ctx|
    app.serve_request(ctx)
  end
  server.bind_tcp("127.0.0.1", port)
  server.listen
end
