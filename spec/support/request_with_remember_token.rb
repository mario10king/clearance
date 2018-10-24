module RememberTokenHelpers
  def request_with_remember_token(remember_token)
    cookies = {
      'action_dispatch.cookies' => {
        Clearance.configuration.cookie_name => remember_token
      }
    }
    env = { clearance: Clearance::Session.new(cookies) }
    Rack::Request.new env
  end

  def request_without_remember_token
    request_with_remember_token nil
  end

  def remember_token_cookies
    response_cookies.select { |c| c =~ /^remember_token/ }
    # headers["Set-Cookie"].split("\n").select { |v| v =~ /^remember_token/ }
  end

  def response_cookies
    Hash[response['Set-Cookie'].lines.map {|line|
      cookie = Rack::Test::Cookie.new(line.chomp)
      [cookie.name, cookie]
    }]
  end
end

RSpec.configure do |config|
  config.include RememberTokenHelpers
end
