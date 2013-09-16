# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.dns.hr/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.dns.hr.rb'

describe Whois::Record::Parser::WhoisDnsHr, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.dns.hr/status_registered.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#disclaimer" do
    it do
      lambda { subject.disclaimer }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#domain" do
    it do
      subject.domain.should == "google.hr"
    end
  end
  describe "#domain_id" do
    it do
      lambda { subject.domain_id }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#status" do
    it do
      subject.status.should == :registered
    end
  end
  describe "#available?" do
    it do
      subject.available?.should == false
    end
  end
  describe "#registered?" do
    it do
      subject.registered?.should == true
    end
  end
  describe "#created_on" do
    it do
      lambda { subject.created_on }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#updated_on" do
    it do
      lambda { subject.updated_on }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#expires_on" do
    it do
      subject.expires_on.should be_a(Time)
      subject.expires_on.should == Time.parse("2012-09-21")
    end
  end
  describe "#registrar" do
    it do
      lambda { subject.registrar }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#registrant_contacts" do
    it do
      subject.registrant_contacts.should be_a(Array)
      subject.registrant_contacts.should have(1).items
      subject.registrant_contacts[0].should be_a(Whois::Record::Contact)
      subject.registrant_contacts[0].type.should          == Whois::Record::Contact::TYPE_REGISTRANT
      subject.registrant_contacts[0].id.should            == nil
      subject.registrant_contacts[0].name.should          == "Google Hrvatska d.o.o."
      subject.registrant_contacts[0].organization.should  == nil
      subject.registrant_contacts[0].address.should       == "Primorska 26"
      subject.registrant_contacts[0].city.should          == "Zagreb"
      subject.registrant_contacts[0].zip.should           == "10 000"
      subject.registrant_contacts[0].state.should         == nil
      subject.registrant_contacts[0].country.should       == nil
      subject.registrant_contacts[0].country_code.should  == nil
      subject.registrant_contacts[0].phone.should         == nil
      subject.registrant_contacts[0].fax.should           == nil
      subject.registrant_contacts[0].email.should         == nil
    end
  end
  describe "#admin_contacts" do
    it do
      lambda { subject.admin_contacts }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#technical_contacts" do
    it do
      lambda { subject.technical_contacts }.should raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#nameservers" do
    it do
      lambda { subject.nameservers }.should raise_error(Whois::AttributeNotSupported)
    end
  end
end