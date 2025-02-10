import subprocess
import sys
import os
import json
from datetime import datetime

class BugBountyScanner:
    def __init__(self):
        self.config = self.load_config()
        self.target_url = ""
        self.scan_results = {}
        self.history_file = "scan_history.json"

    def load_config(self):
        # Simplified config without YAML
        return {
            'scan_settings': {
                'fast': {'timeout': 5, 'threads': 50, 'ports': '80,443'},
                'deep': {'timeout': 10, 'threads': 100, 'ports': '80,443,8080,8443,3000'},
                'passive': {'timeout': 3, 'threads': 25, 'ports': '80,443'}
            },
            'tools': {
                'subfinder': True,
                'httpx': True,
                'nuclei': True,
                'gowitness': True
            }
        }

    def show_banner(self):
        print("="*50)
        print("Bug Bounty Scanner v2.0 by Neox")
        print("Automated Reconnaissance Suite")
        print("="*50 + "\n")

    def main_menu(self):
        while True:
            print("\nMain Menu:")
            print("1. Scan")
            print("2. Recon")
            print("3. History")
            print("4. Config")
            print("5. Quit")
            
            choice = input("\nSelect an option (1-5): ")
            
            if choice == "1":
                self.target_selection()
                self.run_scan_workflow()
            elif choice == "2":
                self.run_recon_workflow()
            elif choice == "3":
                self.show_scan_history()
            elif choice == "4":
                self.configure_settings()
            elif choice == "5":
                print("\nExiting...")
                sys.exit(0)

    def target_selection(self):
        self.target_url = input("\nEnter target URL: ")
        if not self.validate_target(self.target_url):
            print("Invalid target format!")
            sys.exit(1)

    def run_scan_workflow(self):
        print("\nSelect scan type:")
        print("1. Fast")
        print("2. Deep")
        print("3. Passive")
        
        choice = input("Choose scan type (1-3) [1]: ") or "1"
        scan_type = {"1": "fast", "2": "deep", "3": "passive"}[choice]
        
        try:
            print("\nScanning...")
            subdomains = self.find_subdomains(scan_type)
            live_hosts = self.check_live_hosts(subdomains)
            self.fingerprint_services(live_hosts)
            self.save_results()
            self.display_results(live_hosts)
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)

    def find_subdomains(self, scan_type):
        print("\nStarting subdomain enumeration...")
        try:
            cmd = ['subfinder', '-d', self.target_url, '-silent']
            if scan_type == "deep":
                cmd.extend(['-timeout', str(self.config['scan_settings']['deep']['timeout'])])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            
            # Save all discovered subdomains to a file
            all_subdomains_file = f"{self.target_url}_all_subdomains.txt"
            with open(all_subdomains_file, 'w') as f:
                f.write('\n'.join(subdomains))
            
            if subdomains:
                print(f"\nFound {len(subdomains)} subdomains:")
                for subdomain in subdomains:
                    print(f"  - {subdomain}")
                print(f"\nAll subdomains saved to: {all_subdomains_file}")
            else:
                print("No subdomains found.")
            
            return subdomains
        
        except subprocess.CalledProcessError as e:
            print(f"Error running subfinder: {e}")
            print(f"Error output: {e.stderr}")
            return []
        except Exception as e:
            print(f"Unexpected error during subdomain enumeration: {e}")
            return []

    def check_live_hosts(self, subdomains):
        if not subdomains:
            print("No subdomains to check.")
            return []
        
        print("\nChecking for live hosts...")
        live_hosts = []
        temp_file = f"temp_{self.target_url}_subdomains.txt"
        live_hosts_file = f"{self.target_url}_live_hosts.txt"
        
        try:
            # Add http:// prefix to subdomains if missing
            processed_subs = [f"http://{sub}" if not sub.startswith(('http://', 'https://')) else sub for sub in subdomains]
            
            with open(temp_file, 'w') as f:
                f.write('\n'.join(processed_subs))
            
            # Get current scan type configuration
            scan_config = self.config['scan_settings'].get('deep', {})  # Default to deep if not passed
            
            cmd = [
                'httpx',
                '-l', temp_file,
                '-status-code',
                '-title',
                '-tech-detect',
                '-follow-redirects',
                '-timeout', str(scan_config.get('timeout', 10)),  # Use config timeout
                '-ports', '80,443,8080,8443',  # Add common ports
                '-threads', str(scan_config.get('threads', 50)),  # Use config threads
                '-json'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            print("\nDiscovered live hosts:")
            print("-" * 80)
            
            # Open file to save live hosts
            with open(live_hosts_file, 'w') as f:
                f.write(f"Live Hosts for {self.target_url}\n")
                f.write("=" * 80 + "\n")
                
                for line in process.stdout:
                    try:
                        result = json.loads(line)
                        host_info = {
                            'subdomain': result['url'],
                            'status': result['status-code'],
                            'service': result.get('webserver', 'Unknown'),
                            'tech': result.get('technologies', ['Unknown'])[0],
                            'title': result.get('title', 'No title')
                        }
                        live_hosts.append(host_info)
                        
                        # Print to console
                        print(f"URL: {host_info['subdomain']}")
                        print(f"Status: {host_info['status']}")
                        print(f"Title: {host_info['title']}")
                        print(f"Technologies: {host_info['tech']}")
                        print("-" * 80)
                        
                        # Write to file
                        f.write(f"\nURL: {host_info['subdomain']}")
                        f.write(f"\nStatus: {host_info['status']}")
                        f.write(f"\nTitle: {host_info['title']}")
                        f.write(f"\nTechnologies: {host_info['tech']}")
                        f.write(f"\n{'-' * 80}")
                    
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"Error processing host: {e}")
                    
                process.wait()
                
                if not live_hosts:
                    print("No live hosts found.")
                    f.write("\nNo live hosts found.")
                else:
                    summary = f"\nTotal live hosts found: {len(live_hosts)}"
                    print(summary)
                    f.write(summary)
            
            print(f"\nLive hosts saved to: {live_hosts_file}")
            
        except Exception as e:
            print(f"Error checking live hosts: {e}")
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        return live_hosts

    def display_results(self, data):
        if not data:
            print("\nNo results found.")
            return
            
        print("\nScan Results Summary:")
        print("=" * 80)
        print(f"Target: {self.target_url}")
        print(f"Total hosts discovered: {len(data)}")
        print("=" * 80)
        
        print("\nDetailed Results:")
        print("-" * 80)
        print(f"{'Subdomain':<40} {'Status':<8} {'Service':<15} {'Technology'}")
        print("-" * 80)
        
        for item in data:
            print(f"{item['subdomain']:<40} {item['status']:<8} {item['service']:<15} {item['tech']}")
        print("-" * 80)

    def run_recon_workflow(self):
        while True:
            print("\nRecon Menu:")
            print("1. Port Scanning")
            print("2. Directory Bruteforce")
            print("3. Vulnerability Check")
            print("4. Take Screenshots")
            print("5. Back to Main Menu")
            
            choice = input("\nSelect option (1-5): ")
            
            if choice == "5":
                return
            elif choice == "1":
                self.run_port_scan()
            elif choice == "2":
                self.run_directory_scan()
            elif choice == "3":
                self.run_vuln_scan()
            elif choice == "4":
                self.capture_screenshots()

    def run_port_scan(self):
        print("\nStarting port scan...")
        try:
            subprocess.run(['naabu', '-host', self.target_url, '-silent'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Port scan error: {e}")

    def run_directory_scan(self):
        print("\nStarting directory bruteforce...")
        try:
            subprocess.run(['ffuf', '-u', f"{self.target_url}/FUZZ", '-w', 'wordlist.txt'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Directory scan error: {e}")

    def run_vuln_scan(self):
        print("\nRunning vulnerability scan...")
        try:
            subprocess.run(['nuclei', '-u', self.target_url, '-t', '~/nuclei-templates/'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Vulnerability scan error: {e}")

    def capture_screenshots(self):
        print("\nCapturing screenshots...")
        try:
            subprocess.run(['gowitness', 'scan', '-u', self.target_url, '--disable-db'], check=True)
            subprocess.run(['gowitness', 'report', 'serve'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Screenshot error: {e}")

    def save_results(self):
        if not self.scan_results:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"scan_results_{self.target_url}_{timestamp}.json"
        
        try:
            with open(results_file, 'w') as f:
                json.dump(self.scan_results, f, indent=4)
            print(f"\nResults saved to {results_file}")
            self.update_scan_history(results_file)
        except IOError as e:
            print(f"Error saving results: {e}")

    def validate_target(self, target):
        return '.' in target and len(target) > 3

    def show_scan_history(self):
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
            
            if not history:
                print("\nNo scan history found")
                return
            
            print("\nScan History:")
            print("-" * 80)
            print(f"{'Date':<25} {'Target':<30} {'Results File'}")
            print("-" * 80)
            
            for entry in history:
                print(f"{entry['date']:<25} {entry['target']:<30} {entry['results_file']}")
            print("-" * 80)
            
        except FileNotFoundError:
            print("\nNo scan history found")
        except json.JSONDecodeError:
            print("\nError reading scan history")

    def update_scan_history(self, results_file):
        history_entry = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': self.target_url,
            'results_file': results_file
        }
        
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            else:
                history = []
            
            history.append(history_entry)
            
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=4)
        except Exception as e:
            print(f"Error updating scan history: {e}")

    def configure_settings(self):
        print("\nConfiguration options:")
        print("(Feature coming soon)")

    def fingerprint_services(self, live_hosts):
        if not live_hosts:
            return
        
        print("\nFingerprinting services...")
        try:
            for host in live_hosts:
                # Store the results in scan_results
                if 'hosts' not in self.scan_results:
                    self.scan_results['hosts'] = []
                
                self.scan_results['hosts'].append({
                    'url': host['subdomain'],
                    'status': host['status'],
                    'service': host['service'],
                    'technology': host['tech']
                })
        except Exception as e:
            print(f"Error during service fingerprinting: {e}")

def main():
    scanner = BugBountyScanner()
    scanner.show_banner()
    scanner.main_menu()

if __name__ == "__main__":
    main()
