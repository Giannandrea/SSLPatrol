require 'xmlhasher'
require 'oga'
require "open-uri"
require 'time'
require './helper.rb'

TLS_CIPHER_CHEAT_SHEET = "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html"
COMMAND_SSLSCAN = "docker run --rm mini-sslscan sslscan --ssl3 --tlsall --xml=-"
SECURE_CHIPHERS = {
  "A"=>"Advanced", 
  "B"=>"Broad Compatibility",
  "C"=>"Widest Compatibility",
  "D"=>"Legacy"
}

XmlHasher.configure do |config|
  config.snakecase = true
  config.ignore_namespaces = true
  config.string_keys = false
end

class SslInfo
  def initialize(configure)
    @config = configure
  end
  
  def run
    report = {}
      @config["hosts"].each {|host|
        xml_doc = run_cmd("#{COMMAND_SSLSCAN} #{host}")
        doc = XmlHasher.parse(xml_doc)
        @hash = doc[:document][:ssltest]
        report[host] = run_report(host)
      }
      return report
  end
  
  private
  
  def run_report(host)
    intermediate_report = {}
    extract_ciphers()
    extract_ciphers_strength()
    if (@config["validityCheck"].to_s.to_boolean && !is_valid_cert())
      intermediate_report["valid_cert"] = false 
    end
    if (_pk_check = pk_check())
      intermediate_report["pk_check"] = _pk_check
    end
    if (_expiring = expire_in_x_days())
      intermediate_report["is_expiring"] = _expiring
    end
    if (_selfsigned = is_self_signed())
      intermediate_report["selfsigned"] = _selfsigned
    end
    if (_check_tls_versions = check_tls_versions())
      intermediate_report["versionsCheck"] = _check_tls_versions
    end
    if (_unsecure_ciphers = check_unsecure_ciphers())
      intermediate_report["ciphersCheck"] = _unsecure_ciphers
    end
    if (_renegotiation_support = is_renegotiation_supported())
      intermediate_report["renegotiation_support"] = _renegotiation_support
    end
    if (_compression_support = is_compression_supported())
      intermediate_report["compression_support"] = _compression_support
    end
    if (_heartbleed_vurnerable = is_heartbleed_vurnerable())
      intermediate_report["heartbleed_vurnerability"] = _heartbleed_vurnerable
    end
    return intermediate_report
  end
  
  def pk_check
    first_c = (@hash[:certificate][:pk][:error].to_s.to_boolean && @config["pk"]["error"].to_s.to_boolean)
    second_c = (@hash[:certificate][:pk][:error] == @config["pk"]["error"])
    return (first_c && second_c ? nil : @hash[:pk])
  end
  
  def expire_in_x_days
    diff = (Time.parse(@hash[:certificate][:not_valid_after]) - Time.now) / (24 * 60 * 60)
    if diff >= @hash[:expireAfterDays].to_i 
      diff = nil
    end 
    return diff
  end
  
  def is_self_signed
    return @hash[:selfsigned].to_s.to_boolean && @config["selfsigned"] ? nil : @hash[:selfsigned].to_s
  end
  
  def is_valid_cert
    return !(@hash[:expired].to_s.to_boolean && Time.now > Time.parse(@hash[:not_valid_before]))
  end
  
  def is_heartbleed_vurnerable
    vulnerable = []
    @hash[:heartbleed].each {|check|
      vulnerable << check[:sslversion] unless check[:vulnerable] == "0"
    }
    return (vulnerable.size > 0 ? vulnerable : nil)
  end
  
  def is_compression_supported
    return @config["mustSupportCompression"].to_s.to_boolean && @hash[:compression][:supported]
  end
  
  def is_renegotiation_supported
    renegotiation_b = (@hash[:renegotiation][:supported].to_i && @hash[:renegotiation][:secure].to_i)
    if @config["mustSupportSecureRenegotiation"].to_s.to_boolean && renegotiation_b
      return nil
    end
    return @hash[:renegotiation]
  end
  
  def check_tls_versions
    extract_ciphers()
    wrong_ciphers = []
    @cipher_hash.keys.each {|ssl_versions|
      wrong_ciphers << ssl_versions unless @config["tlsSecureVersions"].include? ssl_versions
    }
    return (wrong_ciphers.size > 0 ? wrong_ciphers : nil)
  end
  
  def check_unsecure_ciphers
    unsecure = {}
    @cipher_hash.keys.each {|key|
      unsecure_aux = []
      @cipher_hash[key].each {|cipher|
        unsecure_aux << cipher if is_unsecure_cipher cipher
      }
      unsecure[key] = unsecure_aux if unsecure_aux.size > 0
    }
    return unsecure
  end
  
  def is_unsecure_cipher(cipher)
    types = SECURE_CHIPHERS.values_at(*@config["cipherlevel"])
    types.each {|type|
      return false if @cipher_strength[type].include? cipher
    }
    return true
  end
  
  def extract_ciphers_strength
    return if !@cipher_strength.nil? && @cipher_strength.size > 0
    @cipher_strength = {}
    source = URI.parse(TLS_CIPHER_CHEAT_SHEET).read
    document = Oga.parse_html(source)
    doc = XmlHasher.parse(document.to_xml)
    table = doc[:html][:body][:div][:div][1][:div][:div][1][:div][:div][:div][0][:section][:table].last[:tbody][:tr]
    table.each {|item|
      key = item[:td].first
      values = item[:td].last[:code].split(":")
      @cipher_strength[key] = values
    }
    @cipher_strength
  end
  
  def extract_ciphers
    return if !@cipher_hash.nil? && @cipher_hash.size > 0
    @cipher_hash = Hash.new
    @hash[:cipher].each do |item|
      key = item[:sslversion]
      unless @cipher_hash.has_key?(key)
        @cipher_hash[item[:sslversion]] = []
      end
      @cipher_hash[item[:sslversion]] << item[:cipher]
    end
  end
  
  def run_cmd(command)
    io = `#{command}`
    return io
  end
end