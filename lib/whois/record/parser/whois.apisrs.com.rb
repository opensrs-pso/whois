#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2013 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'
require 'whois/record/scanners/base_shared2'

module Whois
  class Record
    class Parser

      # Parser for the whois.apisrs.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      class WhoisApisrsCom < Base

        include Scanners::Nodable

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          if content_for_scanner =~ /(?:Created on\.+|Creation Date): (.+)\n/
            Time.parse($1)
          end
        end

        property_not_supported :updated_on

        property_supported :expires_on do
          if content_for_scanner =~ /(?:Expires on\.+|Expiration Date): (.+)\n/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name         => 'TUONOME.IT SRL',
            :organization => 'TUONOME.IT SRL',
            :url          => 'http://www.apisrs.com/'
          )
        end

        property_supported :registrant_contacts do
          build_contact("Registrant", Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Admin", Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Tech", Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :billing_contacts do
          build_contact("Billing", Record::Contact::TYPE_BILLING)
        end



        property_supported :nameservers do
          content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |line|
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end

      def parse
          Scanners::BaseShared2.new(content_for_scanner).parse
      end

      private

        # Registrant Name: sagui zeno
        # Registrant Address: Via G. Giardino, 6
        # Registrant City: Conegliano
        # Registrant Postal Code: 31015
        # Registrant Country: IT
        # Registrant Phone Number: +39.0521247791
        # Registrant Fax Number: +39.05217431140
        # Registrant Email: curreli@netbuilder.it

        def build_contact(element, type)
            Record::Contact.new(
              :type         => type,
              :id           => node("#{element} ID"),
              :name         => node("#{element} Name"),
              :organization => node("#{element} Organization"),
              :address      => node("#{element} Address"),
              :city         => node("#{element} City"),
              :zip          => node("#{element} Postal Code"),
              :state        => node("#{element} State/Province"),
              :country_code => node("#{element} Country"),
              :phone        => node("#{element} Phone Number"),
              :fax          => node("#{element} Fax Number"),
              :email        => node("#{element} Email")
            )
        end


      end
    end
  end
end