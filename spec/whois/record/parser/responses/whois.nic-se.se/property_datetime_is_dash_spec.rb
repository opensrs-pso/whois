# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic-se.se/property_datetime_is_dash.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic-se.se.rb'

describe Whois::Record::Parser::WhoisNicSeSe, "property_datetime_is_dash.expected" do

  subject do
    file = fixture("responses", "whois.nic-se.se/property_datetime_is_dash.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#created_on" do
    it do
      subject.created_on.should be_a(Time)
      subject.created_on.should == Time.parse("2010-08-05")
    end
  end
  describe "#updated_on" do
    it do
      subject.updated_on.should == nil
    end
  end
  describe "#expires_on" do
    it do
      subject.expires_on.should be_a(Time)
      subject.expires_on.should == Time.parse("2011-08-05")
    end
  end
end