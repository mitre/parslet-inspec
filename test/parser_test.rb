require_relative '../lib/pdf2inspec/parser'
require 'rspec'

testStr = '2.13 Ensure operations on legacy registry (v1) are Disabled (Scored)
Profile Applicability:
Level 1 - Linux Host OS
Description:
All Docker containers and their data and metadata is stored under /var/lib/docker
directory. By default, /var/lib/docker would be mounted under / or /var partitions based
on availability.
Rationale:
Docker depends on /var/lib/docker as the default directory where all Docker related files,
including the images, are stored. This directory might fill up fast and soon Docker and the
host could become unusable. So, it is advisable to create a separate partition (logical
volume) for storing Docker files.
Audit:
At the Docker host execute the below command:
grep /var/lib/docker /etc/fstab
This should return the partition details for /var/lib/docker mount point.
Remediation:
For new installations, create a separate partition for /var/lib/docker mount point. For
systems that were previously installed, use the Logical Volume Manager (LVM) to create
partitions.
Impact:
None.
Default Value:
By default, /var/lib/docker would be mounted under / or /var partitions based on
availability.
References:
1. https://www.projectatomic.io/docs/docker-storage-recommendation/
CIS Controls:
14 Controlled Access Based on the Need to Know
Controlled Access Based on the Need to Know

1.2 Ensure the container host has been Hardened (Not Scored)
Profile Applicability:
Level 1 - Linux Host OS
Description:
Containers run on a Linux host. A container host can run one or more containers. It is of
utmost importance to harden the host to mitigate host security misconfiguration.
Rationale:
You should follow infrastructure security best practices and harden your host OS. Keeping
the host system hardened would ensure that the host vulnerabilities are mitigated. Not
hardening the host system could lead to security exposures and breaches.
Audit:
Ensure that the host specific security guidelines are followed. Ask the system
administrators which security benchmark does current host system comply with. Ensure
that the host systems actually comply with that host specific security benchmark.
Remediation:
You may consider various CIS Security Benchmarks for your container host. If you have
other security guidelines or regulatory requirements to adhere to, please follow them as
suitable in your environment.
Additionally, you can run a kernel with grsecurity and PaX. This would add many safety
checks, both at compile-time and run-time. It is also designed to defeat many exploits and
has powerful security features. These features do not require Docker-specific
configuration, since those security features apply system-wide, independent of containers.
Impact:
None.
Default Value:
By default, host has factory settings. It is not hardened.
References:
1. https://docs.docker.com/engine/security/security/
2.
3.
4.
5.
6.
7.
https://learn.cisecurity.org/benchmarks
https://docs.docker.com/engine/security/security/#other-kernel-security-features
https://grsecurity.net/
https://en.wikibooks.org/wiki/Grsecurity
https://pax.grsecurity.net/
http://en.wikipedia.org/wiki/PaX
CIS Controls:
3 Secure Configurations for Hardware and Software on Mobile Devices, Laptops,
Workstations, and Servers
Secure Configurations for Hardware and Software on Mobile Devices, Laptops,
Workstations, and Servers

'

RSpec.describe ControlParser do
  output_testStr = '[{:header=>{:section_num=>"2.13"@0, :title=>" Ensure operations on legacy registry (v1) are Disabled "@4, :score=>"(Scored)"@60}, :applicability=>"Level 1 - Linux Host OS"@92, :description=>[{:line=>"All Docker containers and their data and metadata is stored under /var/lib/docker\ndirectory. By default, /var/lib/docker would be mounted under / or /var partitions based\non availability.\n"@129}], :rationale=>[{:line=>"Docker depends on /var/lib/docker as the default directory where all Docker related files,\nincluding the images, are stored. This directory might fill up fast and soon Docker and the\nhost could become unusable. So, it is advisable to create a separate partition (logical\nvolume) for storing Docker files.\n"@328}], :audit=>[{:line=>"At the Docker host execute the below command:\ngrep /var/lib/docker /etc/fstab\nThis should return the partition details for /var/lib/docker mount point.\n"@640}], :remediation=>[{:line=>"For new installations, create a separate partition for /var/lib/docker mount point. For\nsystems that were previously installed, use the Logical Volume Manager (LVM) to create\npartitions.\n"@805}], :impact=>[{:line=>"None.\n"@1000}], :default_value=>[{:line=>"By default, /var/lib/docker would be mounted under / or /var partitions based on\navailability.\n"@1021}], :references=>[{:line=>"1. https://www.projectatomic.io/docs/docker-storage-recommendation/\n"@1128}], :cis_controls=>[{:line=>"14 Controlled Access Based on the Need to Know\n"@1210}, {:line=>"Controlled Access Based on the Need to Know\n"@1257}]}, {:header=>{:section_num=>"1.2"@1302, :title=>" Ensure the container host has been Hardened "@1305, :score=>"(Not Scored)"@1350}, :applicability=>"Level 1 - Linux Host OS"@1386, :description=>[{:line=>"Containers run on a Linux host. A container host can run one or more containers. It is of\nutmost importance to harden the host to mitigate host security misconfiguration.\n"@1423}], :rationale=>[{:line=>"You should follow infrastructure security best practices and harden your host OS. Keeping\nthe host system hardened would ensure that the host vulnerabilities are mitigated. Not\nhardening the host system could lead to security exposures and breaches.\n"@1605}], :audit=>[{:line=>"Ensure that the host specific security guidelines are followed. Ask the system\nadministrators which security benchmark does current host system comply with. Ensure\nthat the host systems actually comply with that host specific security benchmark.\n"@1862}], :remediation=>[{:line=>"You may consider various CIS Security Benchmarks for your container host. If you have\nother security guidelines or regulatory requirements to adhere to, please follow them as\nsuitable in your environment.\nAdditionally, you can run a kernel with grsecurity and PaX. This would add many safety\nchecks, both at compile-time and run-time. It is also designed to defeat many exploits and\nhas powerful security features. These features do not require Docker-specific\nconfiguration, since those security features apply system-wide, independent of containers.\n"@2121}], :impact=>[{:line=>"None.\n"@2681}], :default_value=>[{:line=>"By default, host has factory settings. It is not hardened.\n"@2702}], :references=>[{:line=>"1. https://docs.docker.com/engine/security/security/\n2.\n3.\n4.\n5.\n6.\n7.\nhttps://learn.cisecurity.org/benchmarks\nhttps://docs.docker.com/engine/security/security/#other-kernel-security-features\nhttps://grsecurity.net/\nhttps://en.wikibooks.org/wiki/Grsecurity\nhttps://pax.grsecurity.net/\nhttp://en.wikipedia.org/wiki/PaX\n"@2773}], :cis_controls=>[{:line=>"3 Secure Configurations for Hardware and Software on Mobile Devices, Laptops,\n"@3105}, {:line=>"Workstations, and Servers\n"@3183}, {:line=>"Secure Configurations for Hardware and Software on Mobile Devices, Laptops,\n"@3209}, {:line=>"Workstations, and Servers\n"@3285}]}]'

  parslet = ControlParser.new
  it "should be equal" do
    parslet.parse(testStr).to_s.should == output_testStr
  end

end

RSpec.describe Trans do
  output_trans = '[{:title=>"2.13 Ensure operations on legacy registry (v1) are Disabled (Scored)", :level=>"Level 1 - Linux Host OS", :descr=>"All Docker containers and their data and metadata is stored under /var/lib/docker\ndirectory. By default, /var/lib/docker would be mounted under / or /var partitions based\non availability.\nDocker depends on /var/lib/docker as the default directory where all Docker related files,\nincluding the images, are stored. This directory might fill up fast and soon Docker and the\nhost could become unusable. So, it is advisable to create a separate partition (logical\nvolume) for storing Docker files.\n", :check=>"At the Docker host execute the below command:\ngrep /var/lib/docker /etc/fstab\nThis should return the partition details for /var/lib/docker mount point.\n", :fix=>"For new installations, create a separate partition for /var/lib/docker mount point. For\nsystems that were previously installed, use the Logical Volume Manager (LVM) to create\npartitions.\n", :impact=>"None.\n", :default=>"By default, /var/lib/docker would be mounted under / or /var partitions based on\navailability.\n", :ref=>"1. https://www.projectatomic.io/docs/docker-storage-recommendation/\n", :cis=>"14 Controlled Access Based on the Need to Know\n"}, {:title=>"1.2 Ensure the container host has been Hardened (Not Scored)", :level=>"Level 1 - Linux Host OS", :descr=>"Containers run on a Linux host. A container host can run one or more containers. It is of\nutmost importance to harden the host to mitigate host security misconfiguration.\nYou should follow infrastructure security best practices and harden your host OS. Keeping\nthe host system hardened would ensure that the host vulnerabilities are mitigated. Not\nhardening the host system could lead to security exposures and breaches.\n", :check=>"Ensure that the host specific security guidelines are followed. Ask the system\nadministrators which security benchmark does current host system comply with. Ensure\nthat the host systems actually comply with that host specific security benchmark.\n", :fix=>"You may consider various CIS Security Benchmarks for your container host. If you have\nother security guidelines or regulatory requirements to adhere to, please follow them as\nsuitable in your environment.\nAdditionally, you can run a kernel with grsecurity and PaX. This would add many safety\nchecks, both at compile-time and run-time. It is also designed to defeat many exploits and\nhas powerful security features. These features do not require Docker-specific\nconfiguration, since those security features apply system-wide, independent of containers.\n", :impact=>"None.\n", :default=>"By default, host has factory settings. It is not hardened.\n", :ref=>"1. https://docs.docker.com/engine/security/security/\n2.\n3.\n4.\n5.\n6.\n7.\nhttps://learn.cisecurity.org/benchmarks\nhttps://docs.docker.com/engine/security/security/#other-kernel-security-features\nhttps://grsecurity.net/\nhttps://en.wikibooks.org/wiki/Grsecurity\nhttps://pax.grsecurity.net/\nhttp://en.wikipedia.org/wiki/PaX\n", :cis=>"3 Secure Configurations for Hardware and Software on Mobile Devices, Laptops,\n"}]'

  trans = Trans.new
  it "should be equal" do
    trans.apply(ControlParser.new.parse(testStr)).to_s.should == output_trans
  end
end
