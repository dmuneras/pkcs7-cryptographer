# frozen_string_literal: true

require "pkcs7/cryptographer"
require "pkcs7/cryptographer/entity"
require "pry"
require "timecop"

require "simplecov"
SimpleCov.start

# Load RSpec helpers
ROOT_FOLDER = Pathname.new(File.expand_path("..", __dir__))
support_files = File.join(ROOT_FOLDER, "spec", "helpers", "**", "*.rb")

Dir.glob(support_files).sort.each do |support_file_path|
  require support_file_path
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!
  config.include Helpers::FixtureReader

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
