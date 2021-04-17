# frozen_string_literal: true

require "devise"
require "devise/strategies/authenticatable"
require "devise/passwordless/login_token"

module Devise
  module Strategies
    class MagicLinkAuthenticatable < Authenticatable
      #undef :password
      #undef :password=
      attr_accessor :token

      def valid_for_http_auth?
        super && http_auth_hash[:token].present?
      end

      def valid_for_params_auth?
        super && params_auth_hash[:token].present?
      end

      def authenticate!
        begin
          resource = User.find_signed params[:user][:token], purpose: :magic_link_login
        rescue Devise::Passwordless::LoginToken::InvalidOrExpiredTokenError
          fail!(:magic_link_invalid)
          return
        end

        if resource
          remember_me(resource)
          resource.after_magic_link_authentication
          success!(resource)
        else
          fail!(:magic_link_invalid)
        end
      end
    end
  end
end

Warden::Strategies.add(:magic_link_authenticatable, Devise::Strategies::MagicLinkAuthenticatable)

Devise.add_module(:magic_link_authenticatable, {
  strategy: true,
  controller: :sessions,
  route: :session,
  model: "devise/models/magic_link_authenticatable",
})
