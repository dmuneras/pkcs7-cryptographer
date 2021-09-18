# frozen_string_literal: true

RSpec.describe PKCS7::Cryptographer do
  it "has a version number" do
    expect(PKCS7::Cryptographer::VERSION).not_to be nil
  end

  it "only responds to the public documented methods" do
    expect(
      described_class.new.public_methods(false)
    ).to contain_exactly(
      :decrypt_and_verify,
      :sign_and_encrypt,
      :sign_certificate
    )
  end

  describe "#decrypt_and_verify" do
    describe "when using self_signed certificates" do
      context "when PKI info is correct" do
        let(:cryptographer) { described_class.new }
        let(:ca_certificate) { read_file("self_signed/ca.crt") }
        let(:ca_key) { read_file("self_signed/ca.key") }
        let(:client_certificate) { read_file("self_signed/envigado.crt") }
        let(:client_key) { read_file("self_signed/envigado.key") }
        let(:data) { read_file("self_signed/messages/envigado_to_ca.pem") }
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
          cryptographer.decrypt_and_verify(
            data: data,
            key: ca_key,
            certificate: ca_certificate,
            public_certificate: client_certificate,
            ca_store: ca_store
          )

          expect(decrypt_and_verify.call).to eq("Totono Grisales")
        end
      end
    end

    context "when using certificates signed by a certificate authority" do
      context "when top entity reads message from trustable entity" do
        let(:cryptographer) { described_class.new }
        let(:ca_certificate) { read_file("ca_authority/ROOT_CERTIFICATE") }
        let(:ca_key) { read_file("ca_authority/ROOT_PRIVATE") }
        let(:entity_a_certificate) do
          read_file("ca_authority/ENTITY_A_CERTIFICATE")
        end
        let(:entity_a_key) { read_file("ca_authority/ENTITY_A_PRIVATE") }
        let(:entity_b_certificate) do
          read_file("ca_authority/ENTITY_B_CERTIFICATE")
        end
        let(:entity_b_key) { read_file("ca_authority/ENTITY_B_PRIVATE") }
        let(:inpay_certificate) do
          read_file("ca_authority/ENTITY_B_CERTIFICATE")
        end
        let(:inpay_key) { read_file("ca_authority/ENTITY_B_PRIVATE") }
        let(:ca_store) do
          ca_store = OpenSSL::X509::Store.new
          ca_certificate_obj = OpenSSL::X509::Certificate.new(ca_certificate)
          ca_store.add_cert(ca_certificate_obj)
          ca_store
        end

        let(:message) do
          read_file("ca_authority/messages/entity_b_to_inpay.pem")
        end

        let(:data) { "Sergio Ramos" }

        let(:decrypt_and_verify) do
          lambda do |data, entity_certificate|
            cryptographer.decrypt_and_verify(
              data: data,
              key: inpay_key,
              certificate: inpay_certificate,
              public_certificate: entity_certificate,
              ca_store: ca_store
            )
          end
        end

        context "with a message that is from the expected entity" do
          it "decryption works" do
            expect(
              decrypt_and_verify.call(message, entity_b_certificate)
            ).to eq(data)
          end
        end

        context "when msg is from trustrable but not the expected entity" do
          it "decryption fails because the signature verification fails" do
            expect(
              decrypt_and_verify.call(message, entity_a_certificate)
            ).to eq(false)
          end
        end

        context "when entities try to read each other messages" do
          let(:message_for_b) do
            cryptographer.sign_and_encrypt(
              data: data,
              key: inpay_key,
              certificate: inpay_certificate,
              public_certificate: entity_b_certificate
            )
          end

          let(:decrypt_and_verify) do
            lambda do |entity_reader_name, data|
              entity_key = send("#{entity_reader_name}_key")
              entity_certificate = send("#{entity_reader_name}_certificate")
              cryptographer.decrypt_and_verify(
                data: data,
                key: entity_key,
                certificate: entity_certificate,
                public_certificate: inpay_certificate,
                ca_store: ca_store
              )
            end
          end

          context "with a messages that is not for the entity" do
            it "decryption fails" do
              expect do
                decrypt_and_verify.call("entity_a", message_for_b)
              end.to raise_error(OpenSSL::PKCS7::PKCS7Error)
            end
          end

          context "with a message that is for the entity" do
            it "decrypts data" do
              expect do
                decrypt_and_verify.call("entity_b", message_for_b)
              end.not_to raise_error
            end
          end
        end
      end
    end
  end

  describe "#sign_and_encrypt" do
    context "when using self signed certificates" do
      context "when params are valid" do
        let(:cryptographer) { described_class.new }
        let(:ca_certificate) { read_file("self_signed/ca.crt") }
        let(:ca_key) { read_file("self_signed/ca.key") }
        let(:client_certificate) { read_file("self_signed/envigado.crt") }
        let(:client_key) { read_file("self_signed/envigado.key") }
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

    context "when using a certificate authority" do
      context "when params are valid" do
        let(:cryptographer) { described_class.new }
        let(:ca_certificate) { read_file("ca_authority/ROOT_CERTIFICATE") }
        let(:ca_key) { read_file("ca_authority/ROOT_PRIVATE") }
        let(:client_certificate) do
          read_file("ca_authority/ENTITY_A_CERTIFICATE")
        end
        let(:client_key) { read_file("ca_authority/ENTITY_A_PRIVATE") }
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

  describe "#sign_certificate" do
    context "with valid params" do
      let(:cryptographer) { described_class.new }
      let(:ca_certificate) { read_file("ca_authority/ROOT_CERTIFICATE") }
      let(:ca_key) { read_file("ca_authority/ROOT_PRIVATE") }
      let(:new_entity_key) { read_file("ca_authority/NEW_ENTITY") }
      let(:csr) { read_file("ca_authority/CERTIFICATE_SIGNING_REQUEST") }
      let(:ca_store) do
        ca_store = OpenSSL::X509::Store.new
        ca_certificate_obj = OpenSSL::X509::Certificate.new(ca_certificate)
        ca_store.add_cert(ca_certificate_obj)
        ca_store
      end

      let(:signed_certificate) do
        cryptographer.sign_certificate(
          csr: csr,
          certificate: ca_certificate,
          key: ca_key
        )
      end

      it "returns valid String version of OpenSSL::X509::Certificate" do
        expect {
          OpenSSL::X509::Certificate.new(signed_certificate)
        }.not_to raise_error
      end

      it "sets subject info in the cetificate" do
        expected_entries = {
          "C" => "DK",
          "ST" => "Copenhagen",
          "L" => "Sydhavn",
          "O" => "FSOCIETY"
        }

        signed_certificate.subject.to_a.each do |entry|
          name, data, _ = entry
          expect(expected_entries[name]).to eq(data)
        end
      end

      context "when passing 'valid_until'" do
        let(:valid_until) { Time.current + 5.years }
        let(:signed_certificate) do
          cryptographer.sign_certificate(
            csr: csr,
            certificate: ca_certificate,
            key: ca_key,
            valid_until: valid_until
          )
        end

        before(:each) { Timecop.freeze(Time.current) }
        after(:each) { Timecop.return }

        it "creates a certificate valid until the passed date" do
          expect(valid_until.utc.to_i).to eql(signed_certificate.not_after.to_i)
        end
      end

      context "when using signed certificate" do
        let(:data) { "Hello new Camilo Zuniga" }
        let(:entity_b_key) { read_file("ca_authority/ENTITY_B_PRIVATE") }
        let(:entity_b_certificate) do
          read_file("ca_authority/ENTITY_B_CERTIFICATE")
        end

        let(:sign_and_encrypt) do
          lambda do |new_entity_certificate|
            cryptographer.sign_and_encrypt(
              data: "Hello new Camilo Zuniga",
              key: entity_b_key,
              certificate: entity_b_certificate,
              public_certificate: new_entity_certificate
            )
          end
        end

        let(:decrypt_and_verify) do
          lambda do |encrypted_msg, new_entity_certificate|
            cryptographer.decrypt_and_verify(
              data: encrypted_msg,
              key: new_entity_key,
              certificate: new_entity_certificate,
              public_certificate: entity_b_certificate,
              ca_store: ca_store
            )
          end
        end

        it "certificate allows to read messages from trusted entities" do
          encrypted_msg = sign_and_encrypt.call(signed_certificate)
          decrypted_message = decrypt_and_verify.call(encrypted_msg, signed_certificate)

          expect(decrypted_message).to eq("Hello new Camilo Zuniga")
        end
      end
    end
  end
end
