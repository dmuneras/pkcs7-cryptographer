# frozen_string_literal: true

require_relative "initializers"

module PKCS7
  class Cryptographer
    ###
    # Define an entity abel to decrypt or encrypt messages to send them to other
    # entities. It uses a Cryptographer to do the dirty work and just provide a
    # more human readable way to read an pass messages between trustable
    # entities.
    ###
    class Entity
      include PKCS7::Cryptographer::Initializers

      attr_reader :certificate

      # PUBLIC METHODS
      # ------------------------------------------------------------------------
      def initialize(
        certificate:,
        key: nil,
        ca_store: OpenSSL::X509::Store.new
      )
        @key = key ? rsa_key(key) : nil
        @certificate = x509_certificate(certificate)
        @cryptographer = PKCS7::Cryptographer.new
        @ca_store = ca_store
      end

      def trustable_entity?(entity)
        @ca_store.verify(entity.certificate)
      end

      def encrypt_data(data:, to:)
        perform_safely(to) do
          @cryptographer.sign_and_encrypt(
            data: data,
            key: @key,
            certificate: @certificate,
            public_certificate: to.certificate
          )
        end
      end

      def decrypt_data(data:, from:)
        perform_safely(from) do
          @cryptographer.decrypt_and_verify(
            data: data,
            key: @key,
            certificate: @certificate,
            public_certificate: from.certificate,
            ca_store: @ca_store
          )
        end
      end

      # PRIVATE METHODS
      # ------------------------------------------------------------------------
      private

      def perform_safely(entity)
        return false unless trustable_entity?(entity)
        return false unless @key.present?
        yield
      end
    end
  end
end
