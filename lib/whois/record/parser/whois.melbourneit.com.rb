#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2013 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'
require 'whois/record/scanners/whois.melbourneit.com'


module Whois
  class Record
    class Parser

      # Parser for the whois.apisrs.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      class WhoisMelbourneitCom < Base

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
          if content_for_scanner =~ /Creation Date\.+ (.+)\n/
            Time.parse($1)
          end
        end

        property_not_supported :updated_on

        property_supported :expires_on do
          if content_for_scanner =~ /Expiry Date\.+ (.+)\n/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name         => 'MELBOURNE IT, LTD. D/B/A INTERNET NAMES WORLDWIDE',
            :organization => 'MELBOURNE IT, LTD. D/B/A INTERNET NAMES WORLDWIDE',
            :url          => 'http://www.melbourneit.com'
          )
        end

        property_supported :registrant_contacts do
          build_contact("Organisation", Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("Admin", Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact("Tech", Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |line|
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end

      def parse
          Scanners::WhoisMelbourneitCom.new(content_for_scanner.chop.chop).parse
      end

      private

        # Domain Name.......... intrexdataservices.com
        #   Creation Date........ 2003-08-19
        #   Registration Date.... 2003-08-19
        #   Expiry Date.......... 2013-08-19
        #   Organisation Name.... Gordon Feir
        #   Organisation Address. 11423 Lakeside Place Drive
        #   Organisation Address. 
        #   Organisation Address. 
        #   Organisation Address. Houston
        #   Organisation Address. 77077
        #   Organisation Address. TX
        #   Organisation Address. UNITED STATES

        # Admin Name........... Gordon Feir
        #   Admin Address........ 11423 Lakeside Place Drive
        #   Admin Address........ 
        #   Admin Address........ 
        #   Admin Address. Houston
        #   Admin Address........ 77077
        #   Admin Address........ TX
        #   Admin Address........ UNITED STATES
        #   Admin Email.......... gdfeir@intrexdata.com
        #   Admin Phone.......... +1.2814972619
        #   Admin Fax............ 

        # Tech Name............ Earthlink Hostmaster
        #   Tech Address......... 1375 Peachtree St Level A
        #   Tech Address......... 
        #   Tech Address......... 
        #   Tech Address......... Atlanta
        #   Tech Address......... 30309
        #   Tech Address......... GA
        #   Tech Address......... UNITED STATES
        #   Tech Email........... hostmaster@earthlink.net
        #   Tech Phone........... +1.8889321997
        #   Tech Fax............. +1.4042871057
        #   Name Server.......... dns2.earthlink.net
        #   Name Server.......... dns3.earthlink.net


        def build_contact(element, type)
          # lines = match.split("\n")
          # p lines[0].to_s.scan(/^Organisation Name\.+\s+(.+)\n/)

          address = (1..3).
                map { |i| node("#{element} Address")[i] }.
                delete_if { |i| i.nil? || i.empty? }.
                join(", ")

          Record::Contact.new(
             :type     => type,
          #   :id       => node("#{element} ID"),
             :name     => node("#{element} Name"),
             :organization => node("#{element} Organization"),
             :address  => address, # node("#{element} Address")[0].to_s + ", " + node("#{element} Address")[1].to_s,
             :city     => node("#{element} Address")[3],
             :zip      => node("#{element} Address")[4],
             :state    => node("#{element} Address")[5],
             :country  => node("#{element} Address")[6],
             #   :country_code => node("#{element} Country"),
             :phone    => node("#{element} Phone"),
             :fax      => node("#{element} Fax"),
             :email    => node("#{element} Email")
          )
        end


      end
    end
  end
end