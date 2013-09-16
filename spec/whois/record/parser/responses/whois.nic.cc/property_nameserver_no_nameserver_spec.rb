# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.cc/property_nameserver_no_nameserver.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.cc.rb'

describe Whois::Record::Parser::WhoisNicCc, "property_nameserver_no_nameserver.expected" do

  subject do
    file = fixture("responses", "whois.nic.cc/property_nameserver_no_nameserver.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#nameservers" do
    it do
      subject.nameservers.should be_a(Array)
      subject.nameservers.should == []
    end
  end
end
