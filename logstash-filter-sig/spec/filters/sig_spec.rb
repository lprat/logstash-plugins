# encoding: utf-8
require 'spec_helper'
require "logstash/filters/sig"

describe LogStash::Filters::Sig do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        sig {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('Hello World')
    end
  end
end
