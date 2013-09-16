# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.it/property_contact_with_company_in_address.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.it.rb'

describe Whois::Record::Parser::WhoisNicIt, "property_contact_with_company_in_address.expected" do

  subject do
    file = fixture("responses", "whois.nic.it/property_contact_with_company_in_address.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#technical_contacts" do
    it do
      subject.technical_contacts.should be_a(Array)
      subject.technical_contacts.should have(1).items
      subject.technical_contacts[0].should be_a(Whois::Record::Contact)
      subject.technical_contacts[0].type.should         == Whois::Record::Contact::TYPE_TECHNICAL
      subject.technical_contacts[0].id.should           == "AARS1-ITNIC"
      subject.technical_contacts[0].name.should         == "Andrea Antonio Renato Stratta"
      subject.technical_contacts[0].organization.should == "UCI Italia Srl"
      subject.technical_contacts[0].address.should      == "Via E. Fermi, 161"
      subject.technical_contacts[0].city.should         == "Roma"
      subject.technical_contacts[0].zip.should          == "00146"
      subject.technical_contacts[0].state.should        == "RM"
      subject.technical_contacts[0].country_code.should == "IT"
      subject.technical_contacts[0].created_on.should   == Time.parse("2006-08-16 00:00:00")
      subject.technical_contacts[0].updated_on.should   == Time.parse("2007-03-01 07:48:42")
    end
  end
end