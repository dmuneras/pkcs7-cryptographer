# frozen_string_literal: true

require "openssl"
require "active_support/all"
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

    # CONSTANS
    # --------------------------------------------------------------------------
    CYPHER_ALGORITHM = "aes-256-cbc"

    # PUBLIC METHODS
    # --------------------------------------------------------------------------

    ###
    # @description: Take some string data, this method only signs the data
    # using the information given.
    # @param [String] data
    # @param [String|OpenSSL::PKey::RSA] key
    # @param [String|OpenSSL::X509::Certificate] certificate
    # @param [Array<OpenSSL::X509::Certificate>] certs
    # @param [NilClass|Integer] OpenSSL signing flags
    # @return [String] signed data
    ###
    def sign(
      data:,
      key:,
      certificate:,
      certs: [],
      flags: nil
    )
      signed_data = raw_sign(data, certificate, key, certs, flags)

      signed_data.to_pem
    end

    ###
    # @description: Take some string data, this method encrypts and sign the
    # data using the information given.
    # @param [String] data
    # @param [String|OpenSSL::PKey::RSA] key
    # @param [String|OpenSSL::X509::Certificate] certificate
    # @param [String|OpenSSL::X509::Certificate] public_certificate
    # @param [Array<OpenSSL::X509::Certificate>] certs
    # @param [NilClass|Integer] OpenSSL signing flags
    # @return [String] encrypted data
    ###
    def sign_and_encrypt(
      data:,
      key:,
      certificate:,
      public_certificate:,
      certs: [],
      flags: nil
    )
      public_certificate = x509_certificate(public_certificate)
      signed_data = raw_sign(data, certificate, key, certs, flags)
      encrypted_data = encrypt(public_certificate, signed_data)

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

    def sign_certificate(
      csr:,
      key:,
      certificate:,
      valid_until: Time.current + 10.years
    )
      valid_until.to_time.utc
      check_csr(csr)

      sign_csr(csr, key, certificate, valid_until)
    end

    private

    def raw_sign(data, certificate, key, certs, flags)
      key = rsa_key(key)
      certificate = x509_certificate(certificate)
      OpenSSL::PKCS7.sign(certificate, key, data, certs, flags)
    end

    def encrypt(
      public_certificate, signed_data, cypher_algorithm = CYPHER_ALGORITHM
    )
      OpenSSL::PKCS7.encrypt(
        [public_certificate],
        signed_data.to_der,
        OpenSSL::Cipher.new(cypher_algorithm),
        OpenSSL::PKCS7::BINARY
      )
    end

    def verified_signature?(signed_data, public_certificate, ca_store)
      signed_data.verify(
        [public_certificate], ca_store, nil,
        OpenSSL::PKCS7::NOINTERN | OpenSSL::PKCS7::NOCHAIN
      )
    end

    def check_csr(signing_request)
      csr = OpenSSL::X509::Request.new signing_request
      raise "CSR can not be verified" unless csr.verify(csr.public_key)
    end

    def sign_csr(request, key, issuer_certificate, valid_until)
      request = certificate_signing_request(request)
      key = rsa_key(key)
      issuer_certificate = x509_certificate(issuer_certificate)

      csr_cert = build_certificate_from_csr(
        request, issuer_certificate, valid_until
      )
      csr_cert.sign(key, OpenSSL::Digest.new("SHA1")) # TODO: review this one
      x509_certificate(csr_cert.to_pem)
    end

    def build_certificate_from_csr(
      signing_request, issuer_certificate, valid_until
    )
      certificate = OpenSSL::X509::Certificate.new
      certificate.serial = Time.now.to_i
      certificate.version = 2 # TODO: Check what to put here
      certificate.not_before = Time.current
      certificate.not_after = valid_until
      certificate.subject = signing_request.subject
      certificate.public_key = signing_request.public_key
      certificate.issuer = issuer_certificate.subject

      certificate
    end
  end
end
