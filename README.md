# PKCS7::Cryptographer

[![Gem Version](https://badge.fury.io/rb/pkcs7-cryptographer.svg)](https://badge.fury.io/rb/pkcs7-cryptographer)
![main workflow](https://github.com/dmuneras/pkcs7-cryptographer/actions/workflows/main.yml/badge.svg)


Cryptographer is an small utility to encrypt, sign and decrypt messages
using PKCS7.

PKCS7 is used to store signed and encrypted data.This specific implementation
uses `aes-256-cbc` as chipher in the encryption process. If you want to read
more information about the involved data structures and theory around this,
please visit:

- https://ruby-doc.org/stdlib-3.0.0/libdoc/openssl/rdoc/OpenSSL.html
- https://tools.ietf.org/html/rfc5652

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'pkcs7-cryptographer'
```

And then execute:

```sh
  $ bundle install
```

Or install it yourself as:

```sh
  $ gem install pkcs7-cryptographer
```
## Usage

### Using bare PKCS7::Cryptographer

After installing the gem you will have the `PKCS7::Cryptographer` available.

`PKCS7::Cryptographer` is a class that provides two public methods:

- `sign_and_encrypt`
- `decrypt_and_verify`

If you want to use the barebones cryptographer, you can. Please look at the
following example:



```ruby
  require 'pkcs7/cryptographer'

  # This script assumes you have a read_file method to read the certificates and
  # keys.

  # What we are going to do is signing an encrypting a message from the CA
  # Authority and read it from the Client:

  # Certificate Authority PKI data
  CA_KEY = read_file("ca.key")
  CA_CERTIFICATE = read_file("ca.crt")

  # Client PKI data
  CLIENT_CERTIFICATE = read_file("client.crt")
  CLIENT_KEY = read_file("client.key")

  # SEND MESSAGE TO THE CLIENT
  # ----------------------------------------------------------------------------
  # Encrypt a message in the CA Authority API to be sent to the Client.
  # Only the client can read the message since the required public
  # certificate to read it is the client certificate.

  # It could be read if the CA_STORE of the reader has the certificate of the
  # CA that signed the client certificate as trusted.

  cryptographer = PKCS7::Cryptographer.new

  # Client <------------------------- CA Authority API
  encrypted_data = cryptographer.sign_and_encrypt(
    data: "Atletico Nacional de Medellin",
    key: CA_KEY,
    certificate: CA_CERTIFICATE,
    public_certificate: CLIENT_CERTIFICATE
  )

  # encrypted_data is a PEM formatted string

  # READ MESSAGE IN CLIENT
  # ----------------------------------------------------------------------------
  # Store of trusted certificates
  CA_STORE = OpenSSL::X509::Store.new
  CA_STORE.add_cert(OpenSSL::X509::Certificate.new(CA_CERTIFICATE))

  decrypted_data = cryptographer.decrypt_and_verify(
    data: encrypted_data,
    key: CLIENT_KEY,
    certificate: CLIENT_CERTIFICATE,
    public_certificate: CA_CERTIFICATE,
    ca_store: CA_STORE
  )

  # decrypted_data returns: "Atletico Nacional de Medellin"
```

### Using PKCS7::Cryptographer::Entity

There is a possibility to use entities to communicate using encrypted data. In
order to use it you have to import the entities implementation.

Please look at the following example:

```ruby

  require 'pkcs7/cryptographer'
  require 'pkcs7/cryptographer/entity'

  # This script assumes you have a read_file method to read the certificates and
  # keys. If you have any question about how to generate the keys/certificates
  # check this post: https://mariadb.com/kb/en/certificate-creation-with-openssl/

  # What we are going to do is sending a message from the CA Authority and read
  # it from the Client:

  # Certificate Authority PKI data
  CA_KEY = read_file("ca.key")
  CA_CERTIFICATE = read_file("ca.crt")

  # Client PKI data
  CLIENT_CERTIFICATE = read_file("client.crt")

  CA_STORE = OpenSSL::X509::Store.new
  CA_STORE.add_cert(OpenSSL::X509::Certificate.new(CA_CERTIFICATE))

  ca_entity = PKCS7::Cryptographer::Entity.new(
    key: CA_KEY,
    certificate: CA_CERTIFICATE,
    ca_store: CA_STORE
  )

  client_entity = PKCS7::Cryptographer::Entity.new(
    certificate: CLIENT_CERTIFICATE
  )

  # SEND MESSAGE TO THE CLIENT
  # ----------------------------------------------------------------------------
  data = "Victor Ibarbo"
  encrypted_data = ca_entity.encrypt_data(data: data, receiver: client_entity)

  # READ MESSAGE IN CLIENT
  # ----------------------------------------------------------------------------
  decrypted_data = client_entity.decrypt_data(
    data: encrypted_data,
    sender: ca_entity
  )

  # decrypted_data returns: "Victor Ibarbo"
```

When using entities, all the complexity of knowing which PKI credentials to
send to the cryptographer dissapears. You only need to initialize the
entities and use the methods to indicate to whom the message will be sent.

If you want to verify if certain entity you defined "trust" another one, use the
`trustable_entity?(<the other entity>)`.

```ruby
  ca_entity = PKCS7::Cryptographer::Entity.new(
    key: CA_KEY,
    certificate: CA_CERTIFICATE,
    ca_store: CA_STORE
  )

  client_entity = PKCS7::Cryptographer::Entity.new(
    certificate: CLIENT_CERTIFICATE
  )

  ca_entity.trustable_entity?(client_entity)

  # Returns true because the client certificate was signed by the root
  # certificate of the ca_authority.
```

When sending data to an entity, you will most of the time initialize the entity
only with the `certificate` keyword arguments. So, initializing a receiver will
most of the time looks like this:

```ruby
  client_entity = PKCS7::Cryptographer::Entity.new(
    certificate: CLIENT_CERTIFICATE
  )
```

The entity above can't encrypt messages or decrypt them, if you want to decrypt
and encrypt the entity should have its the key (private key), certificate and
the list of trusted certificates of the entity (ca_store).

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`rake spec` to run the tests. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.
To release a new version, update the version number in `version.rb`, and then
run `bundle exec rake release`, which will create a git tag for the version,
push git commits and the created tag, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/dmuneras/pkcs7-cryptographer. This project is intended
to be a safe, welcoming space for collaboration, and contributors are expected
to adhere to the
[code of conduct](https://github.com/dmuneras/pkcs7-cryptographer/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the
[MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Pkcs7::Cryptographer project's codebases, issue
trackers, chat rooms and mailing lists is expected to follow the
[code of conduct](https://github.com/dmuneras/pkcs7-cryptographer/blob/master/CODE_OF_CONDUCT.md).
