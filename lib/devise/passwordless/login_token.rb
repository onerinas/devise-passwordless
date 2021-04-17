module Devise::Passwordless
  class LoginToken
    class InvalidOrExpiredTokenError < StandardError; end

    def self.encode(resource)
      resource.signed_id expires_in: Devise.passwordless_login_within, purpose: :password_reset
    end
  end
end
