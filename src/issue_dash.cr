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
        repo TEXT NOT NULL,
        number INTEGER NOT NULL,
        title TEXT NOT NULL,
        author TEXT,
        reviewers_html TEXT,
        labels_html TEXT,
        is_pull BOOLEAN NOT NULL,
        is_open BOOLEAN NOT NULL,
        updated_at TEXT,
        dismissed_at TEXT,
        UNIQUE(repo, number)
      )
    ))
    db.exec(%(
      CREATE INDEX IF NOT EXISTS index1 ON issues (is_pull, repo, updated_at, is_open)
    ))
  end

  def auth_url(destination : String? = nil)
    redirect_uri = IssueDash.gen_auth
    if destination
      redirect_uri += "?" + HTTP::Params.encode({destination: destination})
    end
    "https://github.com/login/oauth/authorize?" + HTTP::Params.encode({
      client_id: GITHUB_CLIENT_ID, scope: "", redirect_uri: abs_url(redirect_uri),
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
      get_repositories_for_user(token).map do |repo|
        repo = repo["nameWithOwner"].as_s
        {repo.downcase, repo}
      end.to_a.sort!.to_h
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

  {% for kind in ["issues", "pulls"] %}
  {% is_pull = kind == "pulls".id %}

  @[Retour::Get("/{repo:[^/]+/[^/]+}/{{kind.id}}")]
  def {{kind.id}}_list(ctx, repo : String)
    kind = {{kind}}
    login = check_auth!(ctx)
    repo = check_repo!(repo, kind, login)

    latest = nil
    @db.query(%(
      SELECT updated_at FROM issues WHERE repo = ? AND is_pull = ? ORDER BY updated_at DESC LIMIT 1
    ), repo, {{is_pull}}) do |rs|
      rs.each do
        latest = rs.read(String?)
      end
    end

    get_{{kind.id}}(repo, open_only: latest.nil?, token: login.token).each do |iss|
      if latest && iss["updatedAt"].as_s < latest
        break
      end
      number = iss["number"].as_i
      title = iss["title"].as_s
      author = iss.dig?("author", "login").try &.as_s
      updated_at = iss["updatedAt"].as_s
      is_open = iss["state"].as_s == "OPEN"

      if (reviews = iss["reviews"]?)
        reviewers = {} of String => Nil
        reviews["nodes"].as_a.each do |review|
          if (reviewer = review.dig?("author", "login").try &.as_s)
            if review["state"].as_s == "APPROVED" && review["authorCanPushToRepository"].as_bool
              reviewers[reviewer] = nil
            else
              reviewers.delete(reviewer)
            end
          end
        end
        reviewers_html = reviewers.keys.map { |r| %(<span class="reviewer">#{r}</span>) }.join(", ")
      end

      labels_html = iss["labels"]["nodes"].as_a.map do |label|
        %(<span class="label" style="background-color: ##{HTML.escape(label["color"].as_s)}">#{HTML.escape(label["name"].as_s)}</span>)
      end.join(" ")

      @db.exec(%(
        INSERT INTO issues (repo, number, title, author, reviewers_html, labels_html, is_pull, is_open, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO UPDATE SET title = excluded.title, reviewers_html = excluded.reviewers_html, labels_html = excluded.labels_html, is_open = excluded.is_open, updated_at = excluded.updated_at
      ), repo, number, title, author, reviewers_html, labels_html, {{is_pull}}, is_open, updated_at)
    end

    issues = [] of {number: Int64, title: String, author: String?, reviewers_html: String?, labels_html: String, updated_at: Time, is_dismissed: Bool}
    @db.query(%(
      SELECT number, title, author, reviewers_html, labels_html, updated_at, (coalesce(dismissed_at, '') >= updated_at) AS is_dismissed FROM issues
      WHERE repo = ? AND is_pull = ? AND is_open = 1
      ORDER BY updated_at DESC
    ), repo, {{is_pull}}) do |rs|
      rs.each do
        issues << {
          number: rs.read(Int64), title: rs.read(String), author: rs.read(String?),
          reviewers_html: rs.read(String?), labels_html: rs.read(String),
          updated_at: Time.parse_rfc3339(rs.read(String)), is_dismissed: rs.read(Bool),
        }
      end
    end

    ECR.embed("#{__DIR__}/../templates/head.html", ctx.response)
    ECR.embed("#{__DIR__}/../templates/issues.html", ctx.response)
  end
  {% end %}

  @[Retour::Get("/update_issue")]
  def update_issue(ctx)
    repo = ctx.request.query_params["repo"] rescue raise HTTPException.new(:BadRequest)
    number = ctx.request.query_params["number"].to_i64 rescue raise HTTPException.new(:BadRequest)
    dismiss = ctx.request.query_params["dismiss"].to_i rescue raise HTTPException.new(:BadRequest)

    login = check_auth?(ctx) || raise HTTPException.new(:Unauthorized)
    repo = check_repo?(repo, login) || raise HTTPException.new(:Unauthorized)

    @db.exec(%(
      UPDATE issues SET dismissed_at = #{dismiss > 0 ? "updated_at" : "NULL"} WHERE repo = ? AND number = ?
    ), repo, number)
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
