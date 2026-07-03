const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const {
  checkAbuseIPDB, checkVirusTotal, checkHIBP, checkIPInfo,
  checkShodan, checkSecurityTrails, checkWhois, checkGreyNoise,
  checkURLScan, checkHunter, checkBuiltWith, checkCensys,
  checkOpenPhish, checkOTX, checkNVD, checkIPAPI,
  checkEmailRep, checkDNS, checkSafeBrowsing, checkCVEDetails,
} = require('../controllers/apiController');

// All API routes are protected — user must be authenticated
router.use(protect);

// ─── 20 Security API Endpoints ────────────────────────────────────────────────
router.get('/abuseipdb',      checkAbuseIPDB);      // Malicious IP detection
router.get('/virustotal',     checkVirusTotal);     // URL & file scanning
router.get('/hibp',           checkHIBP);           // Data breach detection
router.get('/ipinfo',         checkIPInfo);         // IP geolocation
router.get('/shodan',         checkShodan);         // Internet-connected device search
router.get('/securitytrails', checkSecurityTrails); // DNS & domain intelligence
router.get('/whois',          checkWhois);          // WHOIS lookup
router.get('/greynoise',      checkGreyNoise);      // Threat intelligence
router.get('/urlscan',        checkURLScan);        // Website scanning
router.get('/hunter',         checkHunter);         // Email intelligence
router.get('/builtwith',      checkBuiltWith);      // Technology detection
router.get('/censys',         checkCensys);         // Internet asset intelligence
router.get('/openphish',      checkOpenPhish);      // Phishing URL detection
router.get('/otx',            checkOTX);            // Threat intelligence platform
router.get('/nvd',            checkNVD);            // CVE vulnerability database
router.get('/ipapi',          checkIPAPI);          // IP location tracking
router.get('/emailrep',       checkEmailRep);       // Email reputation checking
router.get('/dns',            checkDNS);            // DNS record analysis
router.get('/safebrowsing',   checkSafeBrowsing);   // Unsafe website detection
router.get('/cvedetails',     checkCVEDetails);     // Vulnerability information

// ─── Tools Catalog (static list for frontend) ─────────────────────────────────
router.get('/tools', (req, res) => {
  const tools = [
    { id:1,  name:'AbuseIPDB',            category:'IP Intelligence',    endpoint:'/api/security/abuseipdb',      url:'https://www.abuseipdb.com',        tags:['ip','malicious','abuse'] },
    { id:2,  name:'VirusTotal',           category:'Malware Analysis',   endpoint:'/api/security/virustotal',     url:'https://www.virustotal.com',       tags:['virus','malware','scan'] },
    { id:3,  name:'Have I Been Pwned',    category:'Breach Detection',   endpoint:'/api/security/hibp',           url:'https://haveibeenpwned.com',       tags:['breach','email','pwned'] },
    { id:4,  name:'IPinfo',              category:'IP Intelligence',    endpoint:'/api/security/ipinfo',         url:'https://ipinfo.io',                tags:['ip','geo','info'] },
    { id:5,  name:'Shodan',              category:'Threat Detection',   endpoint:'/api/security/shodan',         url:'https://www.shodan.io',            tags:['shodan','devices','iot'] },
    { id:6,  name:'SecurityTrails',      category:'DNS Analysis',       endpoint:'/api/security/securitytrails', url:'https://securitytrails.com',       tags:['dns','domain','history'] },
    { id:7,  name:'WhoisXML API',        category:'WHOIS Lookup',       endpoint:'/api/security/whois',          url:'https://www.whoisxmlapi.com',      tags:['whois','domain','registrar'] },
    { id:8,  name:'GreyNoise',           category:'Threat Detection',   endpoint:'/api/security/greynoise',      url:'https://www.greynoise.io',         tags:['threat','noise','scanning'] },
    { id:9,  name:'URLScan',             category:'URL Scanning',       endpoint:'/api/security/urlscan',        url:'https://urlscan.io',               tags:['url','scan','web'] },
    { id:10, name:'Hunter.io',           category:'Email Intelligence', endpoint:'/api/security/hunter',         url:'https://hunter.io',                tags:['email','hunter','domain'] },
    { id:11, name:'BuiltWith',           category:'Threat Detection',   endpoint:'/api/security/builtwith',      url:'https://builtwith.com',            tags:['tech','stack','web'] },
    { id:12, name:'Censys',             category:'IP Intelligence',    endpoint:'/api/security/censys',         url:'https://censys.io',                tags:['censys','scan','host'] },
    { id:13, name:'OpenPhish',          category:'URL Scanning',       endpoint:'/api/security/openphish',      url:'https://openphish.com',            tags:['phishing','url','feed'] },
    { id:14, name:'AlienVault OTX',     category:'Threat Detection',   endpoint:'/api/security/otx',            url:'https://otx.alienvault.com',       tags:['threat','ioc','alienvault'] },
    { id:15, name:'NVD API',            category:'Vulnerability',      endpoint:'/api/security/nvd',            url:'https://nvd.nist.gov',             tags:['cve','nvd','vulnerability'] },
    { id:16, name:'IPAPI',              category:'Geolocation',        endpoint:'/api/security/ipapi',          url:'https://ipapi.co',                 tags:['ip','geo','location'] },
    { id:17, name:'EmailRep',           category:'Email Intelligence', endpoint:'/api/security/emailrep',       url:'https://emailrep.io',              tags:['email','reputation','spam'] },
    { id:18, name:'DNS Lookup',         category:'DNS Analysis',       endpoint:'/api/security/dns',            url:'https://toolbox.googleapps.com',   tags:['dns','records','lookup'] },
    { id:19, name:'Google Safe Browsing',category:'URL Scanning',      endpoint:'/api/security/safebrowsing',   url:'https://safebrowsing.google.com',  tags:['google','safe','browsing'] },
    { id:20, name:'CVE Details',        category:'Vulnerability',      endpoint:'/api/security/cvedetails',     url:'https://www.cvedetails.com',       tags:['cve','details','vuln'] },
  ];
  res.json({ success: true, count: tools.length, tools });
});

module.exports = router;
