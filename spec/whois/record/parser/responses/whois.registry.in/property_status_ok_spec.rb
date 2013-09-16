# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.registry.in/property_status_ok.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.registry.in.rb'

describe Whois::Record::Parser::WhoisRegistryIn, "property_status_ok.expected" do

  subject do
    file = fixture("responses", "whois.registry.in/property_status_ok.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      subject.status.should == ["OK"]
    end
  end
end
