# frozen_string_literal: true

module Helpers
  module FixtureReader
    def read_file(file_path)
      absolute_path = File.join(fixtures_dir, file_path)

      File.read(absolute_path)
    end

    def fixtures_dir
      return @fixtures_dir if @fixtures_dir

      specs_dir = Pathname.new(File.expand_path("..", __dir__))
      @fixtures_dir = File.join(specs_dir, "fixtures", "files")
    end
  end
end
