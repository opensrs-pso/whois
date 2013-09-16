# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.dotpostregistry.net/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.dotpostregistry.net.rb'

describe Whois::Record::Parser::WhoisDotpostregistryNet, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.dotpostregistry.net/status_registered.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#disclaimer" do
    it do
      subject.disclaimer.should == "Access to .POST REGISTRY WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the .POST Registry registry database. The data in this record is provided by .POST Registry for informational purposes only, and .POST Registry does not guarantee its accuracy.  This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to: (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Afilias except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. .POST Registry reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy."
    end
  end
  describe "#domain" do
    it do
      subject.domain.should == "posteitaliane.post"
    end
  end
  describe "#domain_id" do
    it do
      subject.domain_id.should == "D19482-POST"
    end
  end
  describe "#status" do
    it do
      subject.status.should == ["TRANSFER PROHIBITED"]
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
      subject.created_on.should be_a(Time)
      subject.created_on.should == Time.parse("2012-09-21 12:03:07 UTC")
    end
  end
  describe "#updated_on" do
    it do
      subject.updated_on.should be_a(Time)
      subject.updated_on.should == Time.parse("2012-09-21 12:07:40 UTC")
    end
  end
  describe "#expires_on" do
    it do
      subject.expires_on.should be_a(Time)
      subject.expires_on.should == Time.parse("2014-09-21 12:03:07 UTC")
    end
  end
  describe "#registrar" do
    it do
      subject.registrar.should be_a(Whois::Record::Registrar)
      subject.registrar.id.should           == "R4947-POST"
      subject.registrar.name.should         == "Universal Postal Union"
      subject.registrar.organization.should == "Universal Postal Union"
    end
  end
  describe "#registrant_contacts" do
    it do
      subject.registrant_contacts.should be_a(Array)
      subject.registrant_contacts.should have(1).items
      subject.registrant_contacts[0].should be_a(Whois::Record::Contact)
      subject.registrant_contacts[0].type.should          == Whois::Record::Contact::TYPE_REGISTRANT
      subject.registrant_contacts[0].id.should            == "ITPI30001"
      subject.registrant_contacts[0].name.should          == "Poste Italiane"
      subject.registrant_contacts[0].organization.should  == "Poste Italiane"
      subject.registrant_contacts[0].address.should       == "Viale Europa 190"
      subject.registrant_contacts[0].city.should          == "Rome"
      subject.registrant_contacts[0].zip.should           == "00144"
      subject.registrant_contacts[0].state.should         == ""
      subject.registrant_contacts[0].country_code.should  == "IT"
      subject.registrant_contacts[0].phone.should         == "+39.0659581"
      subject.registrant_contacts[0].fax.should           == "+39.065942298"
      subject.registrant_contacts[0].email.should         == "info@poste.it"
    end
  end
  describe "#admin_contacts" do
    it do
      subject.admin_contacts.should be_a(Array)
      subject.admin_contacts.should have(1).items
      subject.admin_contacts[0].should be_a(Whois::Record::Contact)
      subject.admin_contacts[0].type.should          == Whois::Record::Contact::TYPE_ADMIN
      subject.admin_contacts[0].id.should            == "UPU_C1002"
      subject.admin_contacts[0].name.should          == "Giovanni Brardinoni"
      subject.admin_contacts[0].organization.should  == "Poste Italiane"
      subject.admin_contacts[0].address.should       == "Viale Europa 175"
      subject.admin_contacts[0].city.should          == "Rome"
      subject.admin_contacts[0].zip.should           == "00144"
      subject.admin_contacts[0].state.should         == ""
      subject.admin_contacts[0].country_code.should  == "IT"
      subject.admin_contacts[0].phone.should         == "+39.0659583671"
      subject.admin_contacts[0].fax.should           == "+39.0698688651"
      subject.admin_contacts[0].email.should         == "brardinonig@posteitaliane.it"
    end
  end
  describe "#technical_contacts" do
    it do
      subject.technical_contacts.should be_a(Array)
      subject.technical_contacts.should have(1).items
      subject.technical_contacts[0].should be_a(Whois::Record::Contact)
      subject.technical_contacts[0].type.should          == Whois::Record::Contact::TYPE_TECHNICAL
      subject.technical_contacts[0].id.should            == "UPU_C1001"
      subject.technical_contacts[0].name.should          == "Andrea Speranza"
      subject.technical_contacts[0].organization.should  == "Poste Italiane"
      subject.technical_contacts[0].address.should       == "Viale Europa 175"
      subject.technical_contacts[0].city.should          == "Rome"
      subject.technical_contacts[0].zip.should           == "00144"
      subject.technical_contacts[0].state.should         == ""
      subject.technical_contacts[0].country_code.should  == "IT"
      subject.technical_contacts[0].phone.should         == "+39.0659583086"
      subject.technical_contacts[0].fax.should           == "+39.0659582032"
      subject.technical_contacts[0].email.should         == "netsecurity@postecom.it"
    end
  end
  describe "#nameservers" do
    it do
      subject.nameservers.should be_a(Array)
      subject.nameservers.should have(2).items
      subject.nameservers[0].should be_a(Whois::Record::Nameserver)
      subject.nameservers[0].name.should == "dns.poste.it"
      subject.nameservers[1].should be_a(Whois::Record::Nameserver)
      subject.nameservers[1].name.should == "dns2.poste.it"
    end
  end
end
