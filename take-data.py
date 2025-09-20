import re
import requests
import argparse
import json
import time
import random
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import tldextract
import html
from fake_useragent import UserAgent
import os
import xml.etree.ElementTree as ET
from datetime import datetime

class AdvancedDataExtractor:
    def __init__(self, target_url, max_threads=10, timeout=15, depth=2):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.max_threads = max_threads
        self.timeout = timeout
        self.max_depth = depth
        self.visited_urls = set()
        self.found_data = {
            'emails': set(),
            'phone_numbers': set(),
            'api_keys': {},
            'tokens': {},
            'passwords': set(),
            'endpoints': set(),
            'javascript_files': set(),
            'forms': [],
            'subdomains': set(),
            'sensitive_files': set(),
            'comments': [],
            'metadata': {}
        }
        
        # Initialize session with random user agents
        self.session = requests.Session()
        self.ua = UserAgent()
        self.update_user_agent()
        
        # DNS resolver for subdomain enumeration
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 5
        
    def update_user_agent(self):
        """Update session with random user agent"""
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def is_valid_url(self, url):
        """Check if URL is valid and belongs to target domain"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc or not parsed.scheme:
                return False
                
            # Allow same domain and subdomains
            if parsed.netloc == self.domain or parsed.netloc.endswith('.' + self.domain):
                return True
                
            return False
        except:
            return False
    
    def extract_emails(self, text):
        """Extract emails with advanced patterns"""
        email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            r'\b[\w\.-]+@[\w\.-]+\.\w+\b',
            r'mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})'
        ]
        
        emails = set()
        for pattern in email_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for email in matches:
                # Clean and validate email
                email = email.lower().strip()
                if re.match(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$', email):
                    emails.add(email)
        
        return emails
    
    def extract_phone_numbers(self, text):
        """Extract Indonesian phone numbers with various formats"""
        phone_patterns = [
            r'\b08[1-9][0-9]{7,10}\b',  # 08123456789
            r'\b\+62[0-9]{9,12}\b',     # +628123456789
            r'\b62[0-9]{9,12}\b',       # 628123456789
            r'\b021[0-9]{7,8}\b',       # 0211234567
            r'\b\(021\)[0-9]{7,8}\b',   # (021)1234567
            r'\b0[0-9]{3,4}-?[0-9]{6,7}\b',  # 021-1234567
            r'\b\+62\s[0-9]{2,4}\s[0-9]{3,4}\s[0-9]{3,4}\b'  # +62 21 1234 5678
        ]
        
        phones = set()
        for pattern in phone_patterns:
            matches = re.findall(pattern, text)
            for phone in matches:
                # Normalize phone number
                phone = re.sub(r'[\(\)\-\s]', '', phone)
                if phone.startswith('0'):
                    phone = '62' + phone[1:]
                elif phone.startswith('+'):
                    phone = phone[1:]
                phones.add(phone)
        
        return phones
    
    def extract_api_keys(self, text):
        """Extract various API keys with improved patterns"""
        api_key_patterns = {
            'google_api': r'AIza[0-9A-Za-z\-_]{35}',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'facebook_oauth': r'[fF][aA][cC][eE][bB][oO][oO][kK].*[\'\"][0-9a-f]{32}[\'\"]',
            'twitter_bearer_token': r'AAAAAAAAA[0-9A-Za-z]+',
            'twitter_oauth': r'[tT][wW][iI][tT][tT][eE][rR].*[\'\"][0-9a-zA-Z]{35,44}[\'\"]',
            'github_token': r'ghp_[0-9a-zA-Z]{36}',
            'github_oauth': r'github.*[\'\"][0-9a-zA-Z]{35,40}[\'\"]',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_pk': r'pk_live_[0-9a-zA-Z]{24}',
            'twilio_key': r'SK[0-9a-fA-F]{32}',
            'heroku_key': r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'mailgun_key': r'key-[0-9a-zA-Z]{32}',
            'mailchimp_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'paypal_key': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'linkedin_key': r'[lL][iI][nN][kK][eE][dD][iI][nN].*[\'\"][0-9a-zA-Z]{16}[\'\"]'
        }
        
        results = {}
        for key_type, pattern in api_key_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                results[key_type] = list(set(matches))
        
        return results
    
    def extract_tokens(self, text):
        """Extract various tokens with improved patterns"""
        token_patterns = {
            'jwt': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'basic_auth': r'Basic\s+[A-Za-z0-9+/=]+',
            'bearer_token': r'Bearer\s+[A-Za-z0-9._-]+',
            'session_token': r'session[id]?=[A-Za-z0-9%]+',
            'csrf_token': r'csrf[_-]?token[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            'oauth_token': r'oauth[_-]?token[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            'access_token': r'access[_-]?token[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            'refresh_token': r'refresh[_-]?token[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'
        }
        
        results = {}
        for token_type, pattern in token_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                results[token_type] = list(set(matches))
        
        return results
    
    def extract_passwords(self, text):
        """Extract password patterns"""
        password_patterns = [
            r'password[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            r'pass[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            r'pwd[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            r'login[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            r'secret[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            r'key[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
            r'credential[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'
        ]
        
        passwords = set()
        for pattern in password_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if len(match) >= 6:  # Minimum password length
                    passwords.add(match)
        
        return passwords
    
    def extract_endpoints(self, text, base_url):
        """Extract API endpoints and URLs"""
        endpoint_patterns = [
            r'["\'](/api/[^"\']+?)["\']',
            r'["\'](/v[0-9]+/[^"\']+?)["\']',
            r'["\'](/graphql[^"\']*?)["\']',
            r'["\'](/rest/[^"\']+?)["\']',
            r'["\'](/ajax/[^"\']+?)["\']',
            r'["\'](/admin/[^"\']+?)["\']',
            r'["\'](/internal/[^"\']+?)["\']',
            r'["\'](/private/[^"\']+?)["\']'
        ]
        
        endpoints = set()
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, text)
            for endpoint in matches:
                full_url = urljoin(base_url, endpoint)
                if self.is_valid_url(full_url):
                    endpoints.add(full_url)
        
        # Also extract all URLs
        url_pattern = r'https?://[^"\'\s<>]+'
        url_matches = re.findall(url_pattern, text)
        for url in url_matches:
            if self.is_valid_url(url):
                endpoints.add(url)
        
        return endpoints
    
    def extract_comments(self, html_content):
        """Extract comments from HTML, CSS, JS"""
        comments = []
        
        # HTML comments
        html_comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        for comment in html_comments:
            comments.append({
                'type': 'html',
                'content': comment.strip()
            })
        
        # JavaScript comments
        js_comments = re.findall(r'//(.*?)$|/\*(.*?)\*/', html_content, re.MULTILINE | re.DOTALL)
        for comment in js_comments:
            content = comment[0] or comment[1]
            comments.append({
                'type': 'javascript',
                'content': content.strip()
            })
        
        return comments
    
    def extract_metadata(self, html_content):
        """Extract metadata from HTML"""
        metadata = {}
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta tags
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
            content = meta.get('content')
            if name and content:
                meta_tags[name.lower()] = content
        
        if meta_tags:
            metadata['meta_tags'] = meta_tags
        
        # Title
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.get_text().strip()
        
        # Scripts and links
        scripts = []
        for script in soup.find_all('script', src=True):
            scripts.append(script['src'])
        
        if scripts:
            metadata['external_scripts'] = scripts
        
        links = []
        for link in soup.find_all('link', href=True):
            links.append({
                'rel': link.get('rel', [''])[0],
                'href': link['href']
            })
        
        if links:
            metadata['links'] = links
        
        return metadata
    
    def crawl_page(self, url, depth=0):
        """Crawl a page and extract data"""
        if depth > self.max_depth or url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        
        try:
            # Random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 2.0))
            
            # Update user agent occasionally
            if random.random() < 0.3:
                self.update_user_agent()
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return None
            
            html_content = response.text
            
            # Extract data from page
            self.extract_data_from_content(html_content, url)
            
            # Parse HTML for links to follow
            if depth < self.max_depth:
                soup = BeautifulSoup(html_content, 'html.parser')
                links = []
                
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    full_url = urljoin(url, href)
                    
                    if self.is_valid_url(full_url) and full_url not in self.visited_urls:
                        links.append(full_url)
                
                # Follow links with threading
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_to_url = {
                        executor.submit(self.crawl_page, link, depth + 1): link 
                        for link in links[:50]  # Limit to avoid too many requests
                    }
                    
                    for future in as_completed(future_to_url):
                        try:
                            future.result()
                        except Exception as e:
                            pass
            
            return html_content
            
        except requests.RequestException as e:
            return None
    
    def extract_data_from_content(self, html_content, url):
        """Extract all data from HTML content"""
        # Clean HTML content
        clean_html = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
        
        # Extract emails
        emails = self.extract_emails(clean_html)
        self.found_data['emails'].update(emails)
        
        # Extract phone numbers
        phones = self.extract_phone_numbers(clean_html)
        self.found_data['phone_numbers'].update(phones)
        
        # Extract API keys
        api_keys = self.extract_api_keys(clean_html)
        for key_type, keys in api_keys.items():
            if key_type not in self.found_data['api_keys']:
                self.found_data['api_keys'][key_type] = set()
            self.found_data['api_keys'][key_type].update(keys)
        
        # Extract tokens
        tokens = self.extract_tokens(clean_html)
        for token_type, token_list in tokens.items():
            if token_type not in self.found_data['tokens']:
                self.found_data['tokens'][token_type] = set()
            self.found_data['tokens'][token_type].update(token_list)
        
        # Extract passwords
        passwords = self.extract_passwords(clean_html)
        self.found_data['passwords'].update(passwords)
        
        # Extract endpoints
        endpoints = self.extract_endpoints(clean_html, url)
        self.found_data['endpoints'].update(endpoints)
        
        # Extract JavaScript files
        soup = BeautifulSoup(html_content, 'html.parser')
        for script in soup.find_all('script', src=True):
            js_url = urljoin(url, script['src'])
            if self.is_valid_url(js_url):
                self.found_data['javascript_files'].add(js_url)
        
        # Extract forms
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'page_url': url
            }
            
            for input_tag in form.find_all('input'):
                form_info['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', '')
                })
            
            self.found_data['forms'].append(form_info)
        
        # Extract comments
        comments = self.extract_comments(html_content)
        self.found_data['comments'].extend(comments)
        
        # Extract metadata
        metadata = self.extract_metadata(html_content)
        if metadata:
            self.found_data['metadata'][url] = metadata
    
    def enumerate_subdomains(self):
        """Enumerate subdomains using common patterns"""
        common_subdomains = [
            'www', 'api', 'admin', 'test', 'dev', 'development', 'staging',
            'secure', 'login', 'auth', 'account', 'mail', 'email', 'blog',
            'news', 'forum', 'support', 'help', 'download', 'upload', 'cdn',
            'static', 'assets', 'img', 'images', 'js', 'css', 'app', 'apps',
            'web', 'server', 'service', 'services', 'gateway', 'proxy'
        ]
        
        domain_parts = self.domain.split('.')
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 2 else self.domain
        
        for sub in common_subdomains:
            test_domain = f"{sub}.{base_domain}"
            try:
                answers = self.dns_resolver.resolve(test_domain, 'A')
                if answers:
                    self.found_data['subdomains'].add(test_domain)
            except:
                pass
    
    def check_sensitive_files(self):
        """Check for common sensitive files"""
        sensitive_files = [
            '.env', '.git/config', '.htaccess', '.htpasswd', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'phpinfo.php', 'admin.php',
            'config.php', 'database.yml', 'web.config', 'wp-config.php',
            'package.json', 'composer.json', 'yarn.lock', 'Gemfile',
            'README.md', 'CHANGELOG.md', 'LICENSE', 'docker-compose.yml',
            'jenkins.xml', 'travis.yml', '.DS_Store', 'thumbs.db'
        ]
        
        for file_path in sensitive_files:
            test_url = f"{self.target_url}/{file_path}"
            try:
                response = self.session.head(test_url, timeout=5)
                if response.status_code < 400:
                    self.found_data['sensitive_files'].add(test_url)
            except:
                pass
    
    def scan_js_files(self):
        """Scan JavaScript files for sensitive data"""
        js_urls = list(self.found_data['javascript_files'])
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {
                executor.submit(self.scan_single_js_file, js_url): js_url 
                for js_url in js_urls[:20]  # Limit to avoid too many requests
            }
            
            for future in as_completed(future_to_url):
                try:
                    future.result()
                except Exception as e:
                    pass
    
    def scan_single_js_file(self, js_url):
        """Scan a single JavaScript file for sensitive data"""
        try:
            response = self.session.get(js_url, timeout=10)
            if response.status_code == 200:
                js_content = response.text
                
                # Extract data from JS content
                emails = self.extract_emails(js_content)
                self.found_data['emails'].update(emails)
                
                api_keys = self.extract_api_keys(js_content)
                for key_type, keys in api_keys.items():
                    if key_type not in self.found_data['api_keys']:
                        self.found_data['api_keys'][key_type] = set()
                    self.found_data['api_keys'][key_type].update(keys)
                
                tokens = self.extract_tokens(js_content)
                for token_type, token_list in tokens.items():
                    if token_type not in self.found_data['tokens']:
                        self.found_data['tokens'][token_type] = set()
                    self.found_data['tokens'][token_type].update(token_list)
                
                endpoints = self.extract_endpoints(js_content, js_url)
                self.found_data['endpoints'].update(endpoints)
                
        except requests.RequestException:
            pass
    
    def run(self):
        """Run the complete scan"""
        print(f"[+] Starting advanced scan of: {self.target_url}")
        print(f"[+] Max depth: {self.max_depth}, Threads: {self.max_threads}")
        print("-" * 60)
        
        start_time = time.time()
        
        # Step 1: Enumerate subdomains
        print("[+] Enumerating subdomains...")
        self.enumerate_subdomains()
        
        # Step 2: Check for sensitive files
        print("[+] Checking for sensitive files...")
        self.check_sensitive_files()
        
        # Step 3: Crawl the main site
        print("[+] Crawling website...")
        self.crawl_page(self.target_url)
        
        # Step 4: Scan JavaScript files
        print("[+] Scanning JavaScript files...")
        self.scan_js_files()
        
        # Convert sets to lists for JSON serialization
        result = {
            'emails': list(self.found_data['emails']),
            'phone_numbers': list(self.found_data['phone_numbers']),
            'api_keys': {k: list(v) for k, v in self.found_data['api_keys'].items()},
            'tokens': {k: list(v) for k, v in self.found_data['tokens'].items()},
            'passwords': list(self.found_data['passwords']),
            'endpoints': list(self.found_data['endpoints']),
            'javascript_files': list(self.found_data['javascript_files']),
            'forms': self.found_data['forms'],
            'subdomains': list(self.found_data['subdomains']),
            'sensitive_files': list(self.found_data['sensitive_files']),
            'comments': self.found_data['comments'],
            'metadata': self.found_data['metadata'],
            'scan_info': {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'duration_seconds': round(time.time() - start_time, 2),
                'pages_crawled': len(self.visited_urls)
            }
        }
        
        return result

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Data Extractor for Bug Bounty')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-T', '--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        return
    
    try:
        extractor = AdvancedDataExtractor(
            args.url, 
            max_threads=args.threads, 
            timeout=args.timeout, 
            depth=args.depth
        )
        
        results = extractor.run()
        
        print("\n[+] Scan Results:")
        print("=" * 60)
        print(f"Emails found: {len(results['emails'])}")
        print(f"Phone numbers found: {len(results['phone_numbers'])}")
        print(f"API keys found: {sum(len(v) for v in results['api_keys'].values())}")
        print(f"Tokens found: {sum(len(v) for v in results['tokens'].values())}")
        print(f"Passwords found: {len(results['passwords'])}")
        print(f"Endpoints found: {len(results['endpoints'])}")
        print(f"JavaScript files: {len(results['javascript_files'])}")
        print(f"Forms found: {len(results['forms'])}")
        print(f"Subdomains found: {len(results['subdomains'])}")
        print(f"Sensitive files: {len(results['sensitive_files'])}")
        print(f"Comments found: {len(results['comments'])}")
        print(f"Pages crawled: {results['scan_info']['pages_crawled']}")
        print(f"Scan duration: {results['scan_info']['duration_seconds']} seconds")
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Results saved to {args.output}")
        
        # Print some samples if found
        if results['emails']:
            print(f"\nSample emails: {list(results['emails'])[:3]}")
        
        if results['api_keys']:
            print(f"\nAPI key types found: {list(results['api_keys'].keys())}")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")

if __name__ == "__main__":
    main()
