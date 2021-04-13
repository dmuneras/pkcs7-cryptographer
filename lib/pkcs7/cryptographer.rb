# frozen_string_literal: true

require "openssl"
require_relative "cryptographer/version"
require_relative "cryptographer/initializers"

module PKCS7
  ###
  # Cryptographer is an small utility that allows to encrypt and decrypt
  # messages using PKCS7. PKCS7 is used to store signed and encrypted data.
  # It uses aes-256-cbc as chipher in the encryption process.
  # If you want to read more information about the involved data structures
  # and theory around this, please visit:
  # - https://ruby-doc.org/stdlib-3.0.0/libdoc/openssl/rdoc/OpenSSL.html
  # - https://tools.ietf.org/html/rfc5652
  ###
  class Cryptographer
    include PKCS7::Cryptographer::Initializers

    # PUBLIC METHODS
    # --------------------------------------------------------------------------

    ###
    # @description: Take some string data, this method encrypts and sign the
    # data using the information given.
    # @param [String] data
    # @param [String|OpenSSL::PKey::RSA] key
    # @param [String|OpenSSL::X509::Certificate] certificate
    # @param [String|OpenSSL::X509::Certificate] public_certificate
    # @return [String] encrypted data
    ###
    def sign_and_encrypt(
      data:,
      key:,
      certificate:,
      public_certificate:
    )
      key = rsa_key(key)
      certificate = x509_certificate(certificate)
      public_certificate = x509_certificate(public_certificate)
      signed_data = OpenSSL::PKCS7.sign(certificate, key, data)

      encrypted_data = OpenSSL::PKCS7.encrypt(
        [public_certificate],
        signed_data.to_pem,
        OpenSSL::Cipher.new("aes-256-cbc")
      )

      encrypted_data.to_pem
    end

    ###
    # @description: Take some PKCS7 encrypted data, this method decrypt the
    # data using the information given and verify the signature to ensure only
    # is read by the intented audience.
    # @param [String|OpenSSL::PKCS7] data
    # @param [String|OpenSSL::PKey::RSA] key
    # @param [String|OpenSSL::X509::Certificate] certificate
    # @param [String|OpenSSL::X509::Certificate] public_certificate
    # @param [OpenSSL::X509::Store] ca_store
    # @return [String] decrypted data
    ###
    def decrypt_and_verify(
      data:,
      key:,
      certificate:,
      public_certificate:,
      ca_store:
    )
      key = rsa_key(key)
      certificate = x509_certificate(certificate)
      public_certificate = x509_certificate(public_certificate)
      encrypted_data = pkcs7(data)
      decrypted_data = encrypted_data.decrypt(key, certificate)
      signed_data = OpenSSL::PKCS7.new(decrypted_data)
      verified = verified_signature?(signed_data, public_certificate, ca_store)

      return false unless verified

      signed_data.data
    end

    private

    def verified_signature?(signed_data, public_certificate, ca_store)
      signed_data.verify(
        [public_certificate],
        ca_store,
        nil,
        OpenSSL::PKCS7::NOINTERN | OpenSSL::PKCS7::NOCHAIN
      )
    end
  end
end
