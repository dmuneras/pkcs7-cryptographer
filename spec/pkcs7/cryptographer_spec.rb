# frozen_string_literal: true

RSpec.describe PKCS7::Cryptographer do
  it "has a version number" do
    expect(PKCS7::Cryptographer::VERSION).not_to be nil
  end

  describe "#decrypt_and_verify" do
    context "when PKI info is correct" do
      let(:cryptographer) { described_class.new }
      let(:ca_certificate) { read_file("ca.crt") }
      let(:ca_key) { read_file("ca.key") }
      let(:client_certificate) { read_file("client.crt") }
      let(:client_key) { read_file("client.key") }
      let(:data) { read_file("encrypted_message_from_client.pem") }
      let(:ca_store) do
        ca_store = OpenSSL::X509::Store.new
        ca_certificate_obj = OpenSSL::X509::Certificate.new(ca_certificate)
        ca_store.add_cert(ca_certificate_obj)

        ca_store
      end
      let(:decrypt_and_verify) do
        lambda {
          cryptographer.decrypt_and_verify(
            data: data,
            key: ca_key,
            certificate: ca_certificate,
            public_certificate: client_certificate,
            ca_store: ca_store
          )
        }
      end

      it "decrypts the data" do
        expect(decrypt_and_verify.call).to eq("Totono Grisales")
      end
    end

    describe "#sign_and_encrypt" do
      context "when params are valid" do
        let(:cryptographer) { described_class.new }
        let(:ca_certificate) { read_file("ca.crt") }
        let(:ca_key) { read_file("ca.key") }
        let(:client_certificate) { read_file("client.crt") }
        let(:client_key) { read_file("client.key") }
        let(:data) { "Camilo Zuniga" }
        let(:sign_and_encrypt_data) do
          lambda {
            cryptographer.sign_and_encrypt(
              data: data,
              key: ca_key,
              certificate: ca_certificate,
              public_certificate: client_certificate
            )
          }
        end

        it "doesnt return the original undecrypted value" do
          encrypted_data = sign_and_encrypt_data.call

          expect(encrypted_data).not_to eq("Camilo Zuniga")
        end

        it "returns a String" do
          encrypted_data = sign_and_encrypt_data.call

          expect(encrypted_data).to be_an_instance_of(String)
        end

        it "returns valid String version of OpenSSL::PKCS7" do
          encrypted_data = sign_and_encrypt_data.call

          expect { OpenSSL::PKCS7.new(encrypted_data) }.not_to raise_error
        end
      end
    end
  end
end
