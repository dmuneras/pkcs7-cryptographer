# frozen_string_literal: true

RSpec.describe PKCS7::Cryptographer::Entity do
  it "only responds to the public documented methods" do
    entity = described_class.new(certificate: read_file("self_signed/ca.crt"))

    expect(
      entity.public_methods(false)
    ).to contain_exactly(
      :encrypt_data,
      :decrypt_data,
      :trustable_entity?,
      :certificate
    )
  end

  describe "#decrypt_data" do
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

    let(:client_entity) do
      described_class.new(
        key: client_key,
        certificate: client_certificate,
        ca_store: ca_store
      )
    end

    let(:ca_entity) do
      described_class.new(
        key: ca_key,
        certificate: ca_certificate,
        ca_store: ca_store
      )
    end

    it "decrypts message" do
      expect(
        ca_entity.decrypt_data(data: data, sender: client_entity)
      ).to eq("Hello")
    end
  end

  describe "#encrypt_data" do
    let(:ca_certificate) { read_file("self_signed/ca.crt") }
    let(:ca_key) { read_file("self_signed/ca.key") }
    let(:client_certificate) { read_file("self_signed/envigado.crt") }
    let(:client_key) { read_file("self_signed/envigado.key") }
    let(:data) { "Camilo Zuniga" }
    let(:ca_store) do
      ca_store = OpenSSL::X509::Store.new
      ca_certificate_obj = OpenSSL::X509::Certificate.new(ca_certificate)
      ca_store.add_cert(ca_certificate_obj)

      ca_store
    end

    let(:client_entity) do
      described_class.new(
        key: client_key,
        certificate: client_certificate,
        ca_store: ca_store
      )
    end
    let(:ca_entity) do
      described_class.new(
        key: ca_key,
        certificate: ca_certificate,
        ca_store: ca_store
      )
    end

    it "sends encrypted mesage" do
      encrypted_data = ca_entity.encrypt_data(
        data: data,
        receiver: client_entity
      )

      expect(encrypted_data).not_to eq("Camilo Zuniga")
    end

    it "client can read it" do
      encrypted_data =
        ca_entity.encrypt_data(data: data, receiver: client_entity)

      expect(
        client_entity.decrypt_data(data: encrypted_data, sender: ca_entity)
      ).to eq("Camilo Zuniga")
    end
  end

  describe "#trustable?" do
    let(:ca_certificate) { read_file("self_signed/ca.crt") }
    let(:ca_key) { read_file("self_signed/ca.key") }
    let(:ca_store) do
      ca_store = OpenSSL::X509::Store.new
      ca_certificate_obj =
        OpenSSL::X509::Certificate.new(ca_certificate)
      ca_store.add_cert(ca_certificate_obj)

      ca_store
    end

    context "when entity is trustable" do
      let(:client_certificate) { read_file("self_signed/envigado.crt") }
      let(:client_entity) do
        described_class.new(
          certificate: client_certificate
        )
      end

      let(:ca_entity) do
        described_class.new(
          key: ca_key,
          certificate: ca_certificate,
          ca_store: ca_store
        )
      end

      it { expect(ca_entity.trustable_entity?(client_entity)).to eq(true) }
    end

    context "when entity is not trustable" do
      let(:pirate_certificate) { read_file("pirate.crt") }
      let(:pirate_entity) do
        described_class.new(
          certificate: pirate_certificate
        )
      end

      let(:ca_entity) do
        described_class.new(
          key: ca_key,
          certificate: ca_certificate,
          ca_store: ca_store
        )
      end

      it { expect(ca_entity.trustable_entity?(pirate_entity)).to eq(false) }
    end
  end
end
