# frozen_string_literal: true

RSpec.describe PKCS7::Cryptographer do
  it "has a version number" do
    expect(PKCS7::Cryptographer::VERSION).not_to be nil
  end

  describe "#decrypt_and_verify" do
    let(:cryptographer) { PKCS7::Cryptographer.new }

    context "when params are valid" do
      context "and the owner of the public certificate can read the data" do
        let(:ca_certificate) { read_file("ca.crt") }
        let(:client_certificate) { read_file("client.crt") }
        let(:ca_key) { read_file("ca.key") }
        let(:client_key) { read_file("client.key") }
        let(:data) { read_file("encrypted_message_from_client.pem") }
        let(:ca_store) do
          ca_store = OpenSSL::X509::Store.new
          ca_certificate_obj = OpenSSL::X509::Certificate.new(ca_certificate)
          ca_store.add_cert(ca_certificate_obj)

          ca_store
        end

        it "decrypts the data" do
          decrypted_data = cryptographer.decrypt_and_verify(
            data: data,
            key: ca_key,
            certificate: ca_certificate,
            public_certificate: client_certificate,
            ca_store: ca_store
          )

          expect(decrypted_data).to eq("Totono Grisales")
        end
      end
    end

    describe "#sign_and_encrypt" do
      context "when params are valid" do
        let(:ca_certificate) { read_file("ca.crt") }
        let(:client_certificate) { read_file("client.crt") }
        let(:ca_key) { read_file("ca.key") }
        let(:client_key) { read_file("client.key") }
        let(:data) { "Camilo Zuniga" }

        it "returns a PKCS7 String as encrypted data" do
          encrypted_data = cryptographer.sign_and_encrypt(
            data: data,
            key: ca_key,
            certificate: ca_certificate,
            public_certificate: client_certificate
          )

          expect(encrypted_data).not_to eq("Camilo Zuniga")
          expect(encrypted_data).to be_an_instance_of(String)

          expect { OpenSSL::PKCS7.new(encrypted_data) }.not_to raise_error
        end
      end
    end
  end
end
