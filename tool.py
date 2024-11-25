import os
import requests
import socket
import json
import geocoder
import itertools
from subprocess import Popen, PIPE
from bs4 import BeautifulSoup
import logging
from shutil import copy2

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Helper Functions
def setup_directory_structure(base_dir, folders):
    """Create a structured directory for organizing output files."""
    paths = {}
    for folder in folders:
        path = os.path.join(base_dir, folder)
        os.makedirs(path, exist_ok=True)
        paths[folder] = path
    return paths


def run_command(command, *args):
    """Run a shell command and return its output."""
    try:
        process = Popen([command, *args], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        return stdout.decode(), stderr.decode()
    except Exception as e:
        logging.error(f"Error running command `{command}`: {e}")
        return None, None


def save_to_file(filepath, data):
    """Save data to a file."""
    with open(filepath, 'w') as f:
        f.write(data)
    logging.info(f"Data saved to {filepath}")


# Core Functions
def resolve_target_info(target):
    """Resolve target IP and location details."""
    try:
        target_ip = socket.gethostbyname(target)
        logging.info(f"Target IP: {target_ip}")
        
        geocode_info = geocoder.ipinfo(target_ip)
        location = geocode_info.latlng
        logging.info(f"Location: {location}")
        
        return target_ip, location, geocode_info.json
    except Exception as e:
        logging.error(f"Error resolving target info: {e}")
        return None, None, None


def perform_dns_recon(target, output_dir):
    """Perform DNS reconnaissance using dig, host, and whois."""
    commands = {
        'dig': ['dig', target],
        'host': ['host', target],
        'whois': ['whois', target],
    }

    for tool, cmd in commands.items():
        stdout, _ = run_command(*cmd)
        if stdout:
            save_to_file(os.path.join(output_dir, f"{tool}_output.txt"), stdout)


def perform_port_scan(target, output_dir):
    """Perform a port scan using Nmap."""
    nmap_command = ['nmap', '-sT', '-Pn', '-sV', '-T4', '-n', '-A', target]
    stdout, stderr = run_command(*nmap_command)
    
    if stdout:
        save_to_file(os.path.join(output_dir, "nmap_stdout.txt"), stdout)
    if stderr:
        save_to_file(os.path.join(output_dir, "nmap_stderr.txt"), stderr)


def search_exploits(query, output_dir):
    """Search for exploits using searchsploit."""
    stdout, _ = run_command('searchsploit', query)
    if stdout:
        save_to_file(os.path.join(output_dir, f"{query}_exploits.txt"), stdout)


def analyze_web_page(target, output_dir):
    """Fetch and analyze the webpage source of the target."""
    url = f"http://{target}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        save_to_file(os.path.join(output_dir, "webpage_source.html"), soup.prettify())
        
        links = [link.get('href') for link in soup.find_all('a')]
        save_to_file(os.path.join(output_dir, "links.txt"), "\n".join(filter(None, links)))
    except requests.RequestException as e:
        logging.error(f"Error fetching webpage: {e}")


# Main Script
def main():
    target = "www.dvwa.co.uk"
    base_dir = os.path.join(os.path.expanduser("~"), "penetration_tests", target)
    folders = ['dns_info', 'port_scans', 'exploits', 'web_analysis']
    paths = setup_directory_structure(base_dir, folders)

    # Target Info
    target_ip, location, geocode_info = resolve_target_info(target)
    if target_ip:
        logging.info(f"Target IP: {target_ip}")
        logging.info(f"Location: {location}")
        save_to_file(os.path.join(base_dir, "target_info.json"), json.dumps(geocode_info, indent=4))

    # DNS Recon
    logging.info("Starting DNS Reconnaissance...")
    perform_dns_recon(target, paths['dns_info'])

    # Port Scanning
    logging.info("Starting Port Scanning...")
    perform_port_scan(target, paths['port_scans'])

    # Exploit Search
    logging.info("Searching for Exploits...")
    search_exploits("nginx", paths['exploits'])

    # Web Analysis
    logging.info("Analyzing Web Page...")
    analyze_web_page(target, paths['web_analysis'])

    logging.info("Penetration Test Completed!")


if __name__ == "__main__":
    main()
