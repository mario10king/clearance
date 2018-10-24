require "spec_helper"

describe "token expiration" do
  describe "after sign-in" do
    before do
      get sign_in_path
      user = create(:user, password: "password")

      post session_path, params: {
        session: { email: user.email, password: "password" },
      }
      @remember_token_cookies = remember_token_cookies
    end

    it "should have a remember_token cookie with an expiration of <>" do
      expires = @remember_token_cookies["remember_token"].expires
      expect(expires).to be_between(
        1.years.from_now - 1.second,
        1.years.from_now,
      )
    end
  end

  describe "after sign-in and another request" do
    before do
      get sign_in_path
      user = create(:user, password: "password")

      post session_path, params: {
        session: { email: user.email, password: "password" },
      }
      @initial_cookies = remember_token_cookies

      Timecop.travel(30.seconds.from_now) do
        get root_path
        @followup_cookies = remember_token_cookies
      end
    end

    it "should set a new remember_token on every request with an updated expiration" do
      expect(@followup_cookies["remember_token"]).to be,
        "remember token wasn't set on second request"

      first_expiration = @initial_cookies["remember_token"].expires
      second_expiration = @followup_cookies["remember_token"].expires
      expect(second_expiration).to be > first_expiration
    end
  end
end
