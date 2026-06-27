/**
 * CyberShield Database Seeder
 * ─────────────────────────────────────────────────────────────
 * Run this ONCE after starting MongoDB to seed the security_tools collection.
 * Command: node seed.js
 * ─────────────────────────────────────────────────────────────
 */

require('dotenv').config();
const mongoose = require('mongoose');
const SecurityTool = require('./models/SecurityTool');
const connectDB = require('./config/db');

const tools = [
  {
    name: 'AbuseIPDB',
    category: 'IP Intelligence',
    description: 'Check if an IP address has been reported for abusive behavior such as hacking, spam, or DDoS attacks across a global community database.',
    api_link: 'https://www.abuseipdb.com',
    tags: ['ip', 'malicious', 'abuse', 'reputation'],
  },
  {
    name: 'VirusTotal',
    category: 'Malware Analysis',
    description: 'Scan URLs, domains, IP addresses and files against 70+ antivirus engines and URL scanners to detect malware and other security threats.',
    api_link: 'https://www.virustotal.com',
    tags: ['virus', 'malware', 'scan', 'url', 'file'],
  },
  {
    name: 'Have I Been Pwned',
    category: 'Breach Detection',
    description: 'Check whether an email address or phone number has been compromised in known publicly disclosed data breaches.',
    api_link: 'https://haveibeenpwned.com',
    tags: ['breach', 'email', 'pwned', 'password', 'leak'],
  },
  {
    name: 'IPinfo',
    category: 'IP Intelligence',
    description: 'Comprehensive IP address data including geolocation, ASN, company, carrier, and abuse contact information with 99.99% uptime SLA.',
    api_link: 'https://ipinfo.io',
    tags: ['ip', 'geo', 'asn', 'company', 'info'],
  },
  {
    name: 'Shodan',
    category: 'Threat Detection',
    description: 'The search engine for Internet-connected devices. Find servers, routers, webcams, IoT devices, and analyze internet exposure.',
    api_link: 'https://www.shodan.io',
    tags: ['shodan', 'devices', 'iot', 'ports', 'services'],
  },
  {
    name: 'SecurityTrails',
    category: 'DNS Analysis',
    description: 'Historical DNS records, subdomain discovery, domain WHOIS history, and IP intelligence for comprehensive domain investigation.',
    api_link: 'https://securitytrails.com',
    tags: ['dns', 'domain', 'history', 'subdomain', 'whois'],
  },
  {
    name: 'WhoisXML API',
    category: 'WHOIS Lookup',
    description: 'Comprehensive WHOIS data lookup including registrar details, contact information, registration dates, and domain ownership history.',
    api_link: 'https://www.whoisxmlapi.com',
    tags: ['whois', 'domain', 'registrar', 'ownership'],
  },
  {
    name: 'GreyNoise',
    category: 'Threat Detection',
    description: 'Understand which IPs are scanning the internet, classify malicious vs benign scanners, and reduce alert fatigue in SOC operations.',
    api_link: 'https://www.greynoise.io',
    tags: ['threat', 'noise', 'scanning', 'soc', 'intelligence'],
  },
  {
    name: 'URLScan',
    category: 'URL Scanning',
    description: 'Scan and analyze websites. Takes a screenshot, records DOM content, JavaScript variables, and network requests for any URL.',
    api_link: 'https://urlscan.io',
    tags: ['url', 'scan', 'web', 'screenshot', 'network'],
  },
  {
    name: 'Hunter.io',
    category: 'Email Intelligence',
    description: 'Find professional email addresses behind any domain and verify email deliverability. Useful for OSINT and phishing investigations.',
    api_link: 'https://hunter.io',
    tags: ['email', 'hunter', 'domain', 'osint', 'verification'],
  },
  {
    name: 'BuiltWith',
    category: 'Threat Detection',
    description: 'Technology profiler that reveals which technologies, frameworks, analytics tools, and hosting providers any website is using.',
    api_link: 'https://builtwith.com',
    tags: ['tech', 'stack', 'framework', 'cms', 'hosting'],
  },
  {
    name: 'Censys',
    category: 'IP Intelligence',
    description: 'Internet-wide scanning platform for discovering exposed hosts, analyzing certificates, and mapping the attack surface of the internet.',
    api_link: 'https://censys.io',
    tags: ['censys', 'scan', 'host', 'certificate', 'exposure'],
  },
  {
    name: 'OpenPhish',
    category: 'URL Scanning',
    description: 'Real-time phishing intelligence feed. Detects phishing URLs by comparing against a continuously updated community-sourced blacklist.',
    api_link: 'https://openphish.com',
    tags: ['phishing', 'url', 'feed', 'blacklist', 'fraud'],
  },
  {
    name: 'AlienVault OTX',
    category: 'Threat Detection',
    description: 'Open threat exchange with millions of threat indicators. Access pulses, IoCs, and community-contributed threat intelligence data.',
    api_link: 'https://otx.alienvault.com',
    tags: ['threat', 'ioc', 'alienvault', 'intelligence', 'pulse'],
  },
  {
    name: 'NVD API',
    category: 'Vulnerability',
    description: 'National Vulnerability Database — search CVEs with CVSS scores, affected product versions, CWE classifications, and patch information.',
    api_link: 'https://nvd.nist.gov',
    tags: ['cve', 'nvd', 'vulnerability', 'cvss', 'nist'],
  },
  {
    name: 'IPAPI',
    category: 'Geolocation',
    description: 'Fast and reliable IP geolocation API providing country, region, city, postal code, latitude/longitude, timezone, and ISP information.',
    api_link: 'https://ipapi.co',
    tags: ['ip', 'geo', 'location', 'timezone', 'isp'],
  },
  {
    name: 'EmailRep',
    category: 'Email Intelligence',
    description: 'Email reputation scoring to identify suspicious, disposable, malicious, or spoofed email addresses using behavioral signals.',
    api_link: 'https://emailrep.io',
    tags: ['email', 'reputation', 'spam', 'disposable', 'phishing'],
  },
  {
    name: 'DNS Lookup',
    category: 'DNS Analysis',
    description: 'Query all DNS record types (A, MX, NS, TXT, CNAME, AAAA, SOA) for any domain using Google DNS-over-HTTPS — no key required.',
    api_link: 'https://dns.google',
    tags: ['dns', 'records', 'lookup', 'mx', 'nameserver'],
  },
  {
    name: 'Google Safe Browsing',
    category: 'URL Scanning',
    description: "Check URLs against Google's constantly updated threat lists detecting malware, phishing, and potentially harmful applications.",
    api_link: 'https://safebrowsing.google.com',
    tags: ['google', 'safe', 'browsing', 'phishing', 'malware'],
  },
  {
    name: 'CVE Details',
    category: 'Vulnerability',
    description: 'Detailed CVE vulnerability lookup with CVSS base scores, severity ratings, affected software versions, and reference links.',
    api_link: 'https://www.cvedetails.com',
    tags: ['cve', 'details', 'vulnerability', 'severity', 'cvss'],
  },
];

const seed = async () => {
  try {
    await connectDB();

    // Clear existing tools
    const deleted = await SecurityTool.deleteMany({});
    console.log(`\x1b[33m[SEED]\x1b[0m Cleared ${deleted.deletedCount} existing tools`);

    // Insert all 20 tools
    const inserted = await SecurityTool.insertMany(tools);
    console.log(`\x1b[32m[SEED]\x1b[0m Inserted ${inserted.length} security tools ✅`);

    // Print summary
    const categories = [...new Set(tools.map(t => t.category))];
    console.log(`\x1b[36m[SEED]\x1b[0m Categories seeded: ${categories.join(', ')}`);
    console.log('\x1b[32m[SEED]\x1b[0m Database seeding complete! ✅');
    console.log('\x1b[36m[NEXT]\x1b[0m Open MongoDB Compass → connect to mongodb://localhost:27017 → check "cybershield" database');

    process.exit(0);
  } catch (err) {
    console.error('\x1b[31m[SEED ERROR]\x1b[0m', err.message);
    process.exit(1);
  }
};

seed();
