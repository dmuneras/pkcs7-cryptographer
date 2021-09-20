# frozen_string_literal: true

module PKCS7
  class Cryptographer
    ###
    # Provides a set of methods to initialize OpenSSL objects if necessary. It
    # allow consumers to pass either the OpenSSL ruby objects or the
    # certificate, key or encrypted message string.
    ###
    module Initializers
      # PRIVATE METHODS
      # ------------------------------------------------------------------------

      private

      def x509_certificate(certificate)
        wrap_in_class_or_return(certificate, OpenSSL::X509::Certificate)
      end

      def rsa_key(key)
        wrap_in_class_or_return(key, OpenSSL::PKey::RSA)
      end

      def certificate_signing_request(request)
        wrap_in_class_or_return(request, OpenSSL::X509::Request)
      end

      def pkcs7(pkcs7)
        wrap_in_class_or_return(pkcs7, OpenSSL::PKCS7)
      end

      def wrap_in_class_or_return(data, klass)
        data.instance_of?(klass) ? data : klass.new(data)
      end
    end
  end
end
