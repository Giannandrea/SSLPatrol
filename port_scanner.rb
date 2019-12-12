
COMMAND_NMAP = "nmap -Pn -sV --version-intensity 3"

class PortScanner
  def initialize(configure)
    @config = configure
  end
  
  def run_report(host, output)
    output.each {|line|
      puts line
    }
  end
  
  def run
    report = {}
      @config["hosts"].each {|host|
        output = run_cmd("#{COMMAND_NMAP} #{host} | grep open ")
        report[host] = run_report(host, output)
      }
      return report
  end
  
  def run_cmd(command)
    io = `#{command}`
    return io
  end
  end