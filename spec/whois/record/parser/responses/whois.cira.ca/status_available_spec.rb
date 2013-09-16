# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.cira.ca/status_available.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.cira.ca.rb'

describe Whois::Record::Parser::WhoisCiraCa, "status_available.expected" do

  subject do
    file = fixture("responses", "whois.cira.ca/status_available.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#disclaimer" do
    it do
      subject.disclaimer.should == "Use of CIRA's WHOIS service is governed by the Terms of Use in its Legal\nNotice, available at http://www.cira.ca/legal-notice/?lang=en\n\n(c) 2013 Canadian Internet Registration Authority, (http://www.cira.ca/)"
    end
  end
  describe "#domain" do
    it do
      subject.domain.should == "u34jedzcq.ca"
    end
  end
  describe "#domain_id" do
    it do
      lambda { subject.domain_id }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#status" do
    it do
      subject.status.should == :available
    end
  end
  describe "#available?" do
    it do
      subject.available?.should == true
    end
  end
  describe "#registered?" do
    it do
      subject.registered?.should == false
    end
  end
  describe "#created_on" do
    it do
      subject.created_on.should == nil
    end
  end
  describe "#updated_on" do
    it do
      subject.updated_on.should == nil
    end
  end
  describe "#expires_on" do
    it do
      subject.expires_on.should == nil
    end
  end
  describe "#registrar" do
    it do
      subject.registrar.should == nil
    end
  end
  describe "#registrant_contacts" do
    it do
      subject.registrant_contacts.should be_a(Array)
      subject.registrant_contacts.should == []
    end
  end
  describe "#admin_contacts" do
    it do
      subject.admin_contacts.should be_a(Array)
      subject.admin_contacts.should == []
    end
  end
  describe "#technical_contacts" do
    it do
      subject.technical_contacts.should be_a(Array)
      subject.technical_contacts.should == []
    end
  end
  describe "#nameservers" do
    it do
      subject.nameservers.should be_a(Array)
      subject.nameservers.should == []
    end
  end
  describe "#valid?" do
    it do
      subject.valid?.should == true
    end
  end
  describe "#invalid?" do
    it do
      subject.invalid?.should == false
    end
  end
end
