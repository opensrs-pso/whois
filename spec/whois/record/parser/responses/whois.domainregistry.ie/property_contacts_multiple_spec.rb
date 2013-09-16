# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.domainregistry.ie/property_contacts_multiple.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.domainregistry.ie.rb'

describe Whois::Record::Parser::WhoisDomainregistryIe, "property_contacts_multiple.expected" do

  subject do
    file = fixture("responses", "whois.domainregistry.ie/property_contacts_multiple.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#admin_contacts" do
    it do
      subject.admin_contacts.should be_a(Array)
      subject.admin_contacts.should have(2).items
      subject.admin_contacts[0].should be_a(Whois::Record::Contact)
      subject.admin_contacts[0].type.should          == Whois::Record::Contact::TYPE_ADMIN
      subject.admin_contacts[0].id.should            == "JL241-IEDR"
      subject.admin_contacts[0].name.should          == "Jonathan Lundberg"
      subject.admin_contacts[1].should be_a(Whois::Record::Contact)
      subject.admin_contacts[1].type.should          == Whois::Record::Contact::TYPE_ADMIN
      subject.admin_contacts[1].id.should            == "JM474-IEDR"
      subject.admin_contacts[1].name.should          == "John Moylan"
    end
  end
  describe "#technical_contacts" do
    it do
      subject.technical_contacts.should be_a(Array)
      subject.technical_contacts.should have(1).items
      subject.technical_contacts[0].should be_a(Whois::Record::Contact)
      subject.technical_contacts[0].type.should          == Whois::Record::Contact::TYPE_TECHNICAL
      subject.technical_contacts[0].id.should            == "JM474-IEDR"
      subject.technical_contacts[0].name.should          == "John Moylan"
    end
  end
end