#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import re
from datetime import datetime

def run_subfinder(domain):
    """Start subfinder to find domains and return results"""
    print(f"[+] Start subfinder for domain {domain}...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=True
        )
        subdomains = [subdomain.strip() for subdomain in result.stdout.strip().split('\n') if subdomain.strip()]
        print(f"[+] Found {len(subdomains)} subdomains using subfinder")
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"[!] Error to start subfinder: {e}")
        return []
    except FileNotFoundError:
        print("[!] Error: subfinder didnt install or problem with PATH")
        print("[!] Install subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []

def is_valid_ip(ip_str):
    """Check: Is it valide IPv4-address?"""
    # Regular expressinon to check format IPv4
    pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = pattern.match(ip_str)
    if not match:
        return False
    # Check every octet: 0-255
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet < 0 or octet > 255:
            return False
    return True

def run_theharvester(domain):
    """Start theHarvester to find information and return results"""
    print(f"[+] Start theHarvester for domain {domain}...")
    try:
        # Create temporary file for theHarvester results
        output_file_xml = f"harvester_output_{domain}.xml"
        output_file_json = f"harvester_output_{domain}.json"
        
        # Delete files if they have already been created
        for file_path in [output_file_xml, output_file_json]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"[!] Problem to delete existing file {file_path}: {e}")
        
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "all", "-f", output_file_xml],
            capture_output=True,
            text=True
        )
        
        # Check is XML exist?
        if not os.path.exists(output_file_xml):
            print("[!] theHarvester didnt create output XML file")
            
           # Check is JSON exist?
            if os.path.exists(output_file_json):
                print(f"[+] Found JSON file: {output_file_json}")
                with open(output_file_json, 'r') as f:
                    try:
                        json_data = json.load(f)
                        # Try to get data from JSON
                        hosts = []
                        emails = []
                        ips = []
                        
                        if 'hosts' in json_data:
                            for host_data in json_data.get('hosts', []):
                                if isinstance(host_data, dict) and 'host' in host_data:
                                    hosts.append(host_data['host'])
                        
                        if 'emails' in json_data:
                            emails = json_data.get('emails', [])
                        
                        if 'ips' in json_data:
                            for ip_data in json_data.get('ips', []):
                                if isinstance(ip_data, dict) and 'ip' in ip_data:
                                    ip = ip_data['ip']
                                    if is_valid_ip(ip):
                                        ips.append(ip)
                                    elif '.' in ip:  # It can be a domain
                                        hosts.append(ip)
                        
                        # Delete JSON file
                        try:
                            os.remove(output_file_json)
                            print(f"[+] Temporary file {output_file_json} deleted")
                        except Exception as e:
                            print(f"[!] Failed to delete temporary file {output_file_json}: {e}")
                            
                        # return processed data
                        return {
                            "hosts": list(set(hosts)),
                            "emails": list(set(emails)),
                            "ips": list(set(ips))
                        }
                    except json.JSONDecodeError:
                        print(f"[!] Failed to read json file {output_file_json}")
            
            return {
                "hosts": [],
                "emails": [],
                "ips": []
            }
        
        # Read results from XML file
        with open(output_file_xml, 'r') as f:
            content = f.read()
        
        # Create lists to store clean data
        pure_hosts = []
        emails = []
        pure_ips = []
        
        # Regular expressions for extracting IP and hostname from strings of the form <ip>X.X.X.X</ip><hostname>example.com</hostname>
        ip_hostname_pattern = re.compile(r'<ip>(.*?)</ip><hostname>(.*?)</hostname>')
        
        # Get clean hosts (without IP)
        host_pattern = re.compile(r'<host>(.*?)</host>')
        host_matches = host_pattern.findall(content)
        for host in host_matches:
            # Check if the host contains an IP address in angle brackets
            if not ('<ip>' in host and '</ip>' in host):
                pure_hosts.append(host.strip())
        
        # Get email-addresses
        email_pattern = re.compile(r'<email>(.*?)</email>')
        email_matches = email_pattern.findall(content)
        for email in email_matches:
            emails.append(email.strip())
        
        # Processing lines with IP and hostnames
        ip_hostname_matches = ip_hostname_pattern.findall(content)
        for ip, hostname in ip_hostname_matches:
            ip_stripped = ip.strip()
            hostname_stripped = hostname.strip()
            
            if is_valid_ip(ip_stripped):
                pure_ips.append(ip_stripped)
            else:
                # If it is not a valid IP, it may be a domain name
                if ip_stripped and '.' in ip_stripped:
                    pure_hosts.append(ip_stripped)
            
            if hostname_stripped:
                pure_hosts.append(hostname_stripped)
        
        # We process individual IPs
        ip_pattern = re.compile(r'<ip>(.*?)</ip>')
        ip_matches = ip_pattern.findall(content)
        for ip in ip_matches:
            # Check if the IP contains a hostname in the same line and if the IP is valid
            if '<hostname>' not in ip:
                ip_stripped = ip.strip()
                if is_valid_ip(ip_stripped):
                    pure_ips.append(ip_stripped)
                elif ip_stripped and '.' in ip_stripped:
                    # If it is not a valid IP but looks like a domain
                    pure_hosts.append(ip_stripped)
        
        # Delete temporary files
        for file_path in [output_file_xml, output_file_json]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"[+] Temporary file {file_path} deleted")
                except Exception as e:
                    print(f"[!] Failed to delete temporary file {file_path}: {e}")
        
        # Delete dublicaties
        pure_hosts = list(set(pure_hosts))
        emails = list(set(emails))
        pure_ips = list(set(pure_ips))
        
        print(f"[+] theHarvester found {len(pure_hosts)} unique hosts, {len(emails)} unique email-addresses и {len(pure_ips)} unique IP-addresses")
        return {
            "hosts": pure_hosts,
            "emails": emails,
            "ips": pure_ips
        }
    except subprocess.CalledProcessError as e:
        print(f"[!] Error while starting theHarvester: {e}")
        return {"hosts": [], "emails": [], "ips": []}
    except FileNotFoundError:
        print("[!] Error: theHarvester wasnt installed or not find in PATH")
        print("[!] Istall theHarvester: apt-get install theharvester or pip install theHarvester")
        return {"hosts": [], "emails": [], "ips": []}

def save_results_to_json(domain, subfinder_results, harvester_results):
    """Saves scan results to a JSON file with domain association."""
    # we combine unique domains from both sources
    all_domains = set(subfinder_results + harvester_results["hosts"])
    # We remove IP addresses from domains if they accidentally appear
    filtered_domains = [domain for domain in all_domains if not is_valid_ip(domain)]
    sorted_domains = sorted(list(filtered_domains))
    
    # Let's make sure that only IPs remain in IP
    filtered_ips = [ip for ip in harvester_results["ips"] if is_valid_ip(ip)]
    
    results = {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_domain": domain,
        "domains": sorted_domains,
        "emails": harvester_results["emails"],
        "ips": filtered_ips
    }
    
    output_filename = f"osint_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"[+] Results saved in this file: {output_filename}")
    print(f"[+] Total unique domains: {len(sorted_domains)}")
    print(f"[+] Total unique emails: {len(harvester_results['emails'])}")
    print(f"[+] Total unique IPs: {len(filtered_ips)}")
    return output_filename

def main():
    if len(sys.argv) < 2:
        print("Using: python script.py <domain>")
        print("Example: python script.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"[+] Start scanning domain: {domain}")
    
    # Starting tools and collecting results
    subfinder_results = run_subfinder(domain)
    harvester_results = run_theharvester(domain)
    
    # Check if there is a temporary file left and delete it
    temp_file_xml = f"harvester_output_{domain}.xml"
    temp_file_json = f"harvester_output_{domain}.json"
    
    for temp_file in [temp_file_xml, temp_file_json]:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                print(f"[+] Deleted last temporary file {temp_file}")
            except Exception as e:
                print(f"[!] Filed to delete temporary file {temp_file}: {e}")
    
    # Save results
    output_file = save_results_to_json(domain, subfinder_results, harvester_results)
    
    print(f"[+] Scanning was finished! Results was saved in: {output_file}")

if __name__ == "__main__":
    main()
