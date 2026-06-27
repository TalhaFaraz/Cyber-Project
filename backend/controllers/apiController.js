const axios = require('axios');

// ─── Utility helpers ──────────────────────────────────────────────────────────
const apiError = (res, msg, status = 502) =>
  res.status(status).json({ success: false, error: msg });

// Check if a key is usable (not a placeholder / "no_key")
const hasKey = (k) => k && k !== 'no_key' && k !== 'your_key_here' &&
  !k.startsWith('your_') && !k.includes('_here');

// Validate routable public IPv4 (rejects private/loopback/reserved)
const isPublicIPv4 = (ip) => {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  if (parts.some(p => isNaN(p) || +p < 0 || +p > 255)) return false;
  const [a, b] = parts.map(Number);
  if (a === 0 || a === 127) return false;
  if (a === 10) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a >= 224) return false;
  return true;
};

// ─── 1. AbuseIPDB ─────────────────────────────────────────────────────────────
const checkAbuseIPDB = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP address is required.', 400);
  if (!isPublicIPv4(query))
    return apiError(res, 'Enter a valid public IPv4 address (e.g. 8.8.8.8). Private/reserved IPs are not supported.', 400);
  if (!hasKey(process.env.ABUSEIPDB_KEY))
    return apiError(res, 'AbuseIPDB key missing. Add ABUSEIPDB_KEY to .env', 400);
  try {
    const r = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' },
      params: { ipAddress: query, maxAgeInDays: 90, verbose: true },
    });
    res.json({ success: true, api: 'AbuseIPDB', data: r.data.data });
  } catch (err) {
    apiError(res, err.response?.data?.errors?.[0]?.detail || 'AbuseIPDB API error.');
  }
};

// ─── 2. VirusTotal ────────────────────────────────────────────────────────────
const checkVirusTotal = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Domain or URL is required.', 400);
  if (!hasKey(process.env.VIRUSTOTAL_KEY))
    return apiError(res, 'VirusTotal key missing. Add VIRUSTOTAL_KEY to .env', 400);
  // Strip protocol for domain lookup
  const domain = query.replace(/^https?:\/\//, '').split('/')[0];
  try {
    const r = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_KEY },
    });
    const d = r.data.data?.attributes || {};
    res.json({
      success: true, api: 'VirusTotal',
      domain,
      reputation: d.reputation,
      categories: d.categories,
      lastAnalysisStats: d.last_analysis_stats,
      lastAnalysisDate: d.last_analysis_date,
      totalVotes: d.total_votes,
      registrar: d.registrar,
      creationDate: d.creation_date,
    });
  } catch (err) {
    apiError(res, err.response?.data?.error?.message || 'VirusTotal API error. Check your key.');
  }
};

// ─── 3. Have I Been Pwned ─────────────────────────────────────────────────────
// HIBP no longer has a free breached-account endpoint.
// We use the public "all breaches" list to check by email domain pattern,
// plus the free Pwned Passwords (SHA1 k-anonymity) range endpoint.
const checkHIBP = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Email address is required.', 400);
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRe.test(query))
    return apiError(res, 'Enter a valid email address.', 400);

  // If paid key exists, use the full endpoint
  if (hasKey(process.env.HIBP_KEY)) {
    try {
      const r = await axios.get(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`,
        { headers: { 'hibp-api-key': process.env.HIBP_KEY, 'user-agent': 'CyberShield-Dashboard' },
          params: { truncateResponse: false } }
      );
      return res.json({
        success: true, api: 'Have I Been Pwned',
        email: query, breachCount: r.data.length,
        status: r.data.length > 0 ? 'PWNED' : 'SAFE',
        breaches: r.data,
      });
    } catch (err) {
      if (err.response?.status === 404)
        return res.json({ success: true, api: 'Have I Been Pwned', email: query, breachCount: 0, status: 'SAFE', breaches: [] });
    }
  }

  // Free fallback: fetch the full public breach list and check email domain
  try {
    const [breachList, pasteList] = await Promise.allSettled([
      axios.get('https://haveibeenpwned.com/api/v3/breaches', { headers: { 'user-agent': 'CyberShield-Dashboard' } }),
      axios.get(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(query)}`,
        { headers: { 'user-agent': 'CyberShield-Dashboard' } }),
    ]);

    const domain = query.split('@')[1];
    const allBreaches = breachList.status === 'fulfilled' ? breachList.value.data : [];
    // Heuristic: flag breaches that had email as a data class (most do)
    const likelyBreaches = allBreaches.filter(b => b.DataClasses?.includes('Email addresses'));

    const pastes = pasteList.status === 'fulfilled' ? pasteList.value.data : [];

    return res.json({
      success: true,
      api: 'Have I Been Pwned (Free Mode)',
      email: query,
      emailDomain: domain,
      note: 'HIBP paid key not set. Showing total known breaches that exposed email addresses. For personal breach results, add your HIBP_KEY.',
      totalBreachesInDatabase: allBreaches.length,
      breachesWithEmailData: likelyBreaches.length,
      pasteCount: Array.isArray(pastes) ? pastes.length : 0,
      recentBreaches: likelyBreaches.slice(0, 5).map(b => ({
        name: b.Name, domain: b.Domain,
        breachDate: b.BreachDate, pwnCount: b.PwnCount,
        dataClasses: b.DataClasses,
      })),
      getKey: 'https://haveibeenpwned.com/API/Key ($3.50/month for personal lookups)',
    });
  } catch (err) {
    return apiError(res, 'HIBP lookup failed. The free endpoint may be rate-limited.');
  }
};

// ─── 4. IPinfo ────────────────────────────────────────────────────────────────
const checkIPInfo = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP address is required.', 400);
  if (!isPublicIPv4(query))
    return apiError(res, 'Enter a valid public IPv4 address (e.g. 1.1.1.1).', 400);
  try {
    const url = hasKey(process.env.IPINFO_KEY)
      ? `https://ipinfo.io/${query}/json?token=${process.env.IPINFO_KEY}`
      : `https://ipinfo.io/${query}/json`;
    const r = await axios.get(url);
    res.json({ success: true, api: 'IPinfo', data: r.data });
  } catch (err) {
    apiError(res, 'IPinfo API error.');
  }
};

// ─── 5. Shodan → uses free InternetDB (no key needed) ────────────────────────
const checkShodan = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP address is required.', 400);
  if (!isPublicIPv4(query))
    return apiError(res, 'Enter a valid public IPv4 address.', 400);

  // Try full Shodan API if key present
  if (hasKey(process.env.SHODAN_KEY)) {
    try {
      const r = await axios.get(`https://api.shodan.io/shodan/host/${query}`, {
        params: { key: process.env.SHODAN_KEY }, timeout: 10000,
      });
      return res.json({
        success: true, api: 'Shodan',
        ip: r.data.ip_str, org: r.data.org, isp: r.data.isp,
        country: r.data.country_name, city: r.data.city,
        os: r.data.os, lastUpdate: r.data.last_update,
        openPorts: r.data.ports, hostnames: r.data.hostnames,
        vulns: r.data.vulns ? Object.keys(r.data.vulns) : [],
      });
    } catch (err) { /* fall through to InternetDB */ }
  }

  // Free fallback: Shodan InternetDB (no key, always works)
  try {
    const r = await axios.get(`https://internetdb.shodan.io/${query}`, { timeout: 8000 });
    res.json({
      success: true, api: 'Shodan InternetDB (Free)',
      ip: query,
      openPorts: r.data.ports || [],
      hostnames: r.data.hostnames || [],
      cpes: r.data.cpes || [],
      tags: r.data.tags || [],
      vulns: r.data.vulns || [],
      note: 'Using Shodan InternetDB (free). Add SHODAN_KEY for full scan data, banners & geolocation.',
    });
  } catch (err) {
    if (err.response?.status === 404)
      return res.json({ success: true, api: 'Shodan InternetDB', ip: query, openPorts: [], hostnames: [], vulns: [], note: 'No data found for this IP in Shodan.' });
    apiError(res, 'Shodan lookup failed.');
  }
};

// ─── 6. SecurityTrails → HackerTarget free fallback ──────────────────────────
const checkSecurityTrails = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Domain name is required.', 400);

  if (hasKey(process.env.SECURITYTRAILS_KEY)) {
    try {
      const r = await axios.get(`https://api.securitytrails.com/v1/domain/${query}`, {
        headers: { APIKEY: process.env.SECURITYTRAILS_KEY }, timeout: 10000,
      });
      return res.json({ success: true, api: 'SecurityTrails', data: r.data });
    } catch (e) { /* fall through */ }
  }

  try {
    const [hostsearch, dnslookup] = await Promise.allSettled([
      axios.get(`https://api.hackertarget.com/hostsearch/?q=${query}`, { timeout: 8000 }),
      axios.get(`https://api.hackertarget.com/dnslookup/?q=${query}`, { timeout: 8000 }),
    ]);
    res.json({
      success: true,
      api: 'DNS Intelligence — HackerTarget (Free Fallback)',
      domain: query,
      hostSearch: hostsearch.status === 'fulfilled' ? hostsearch.value.data : 'N/A',
      dnsRecords: dnslookup.status === 'fulfilled' ? dnslookup.value.data : 'N/A',
      note: 'SecurityTrails free tier is discontinued. Using HackerTarget (free). Add SECURITYTRAILS_KEY for historical DNS data.',
    });
  } catch (err) {
    apiError(res, 'DNS intelligence lookup failed.');
  }
};

// ─── 7. WhoisXML → RDAP free fallback ────────────────────────────────────────
const checkWhois = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Domain name is required.', 400);

  if (hasKey(process.env.WHOISXML_KEY)) {
    try {
      const r = await axios.get('https://www.whoisxmlapi.com/whoisserver/WhoisService', {
        params: { apiKey: process.env.WHOISXML_KEY, domainName: query, outputFormat: 'JSON' },
        timeout: 10000,
      });
      return res.json({ success: true, api: 'WhoisXML', data: r.data });
    } catch (e) { /* fall through to RDAP */ }
  }

  // Free fallback: RDAP (IANA standard, zero key needed)
  try {
    const tld = query.split('.').slice(-1)[0].toLowerCase();
    let rdapBase = 'https://rdap.org/';
    try {
      const bootstrap = await axios.get('https://data.iana.org/rdap/dns.json', { timeout: 5000 });
      for (const [tlds, urls] of bootstrap.data.services) {
        if (tlds.map(t => t.toLowerCase()).includes(tld)) { rdapBase = urls[0]; break; }
      }
    } catch (_) {}

    const r = await axios.get(`${rdapBase}domain/${query}`, {
      timeout: 10000,
      headers: { Accept: 'application/rdap+json' },
    });
    const d = r.data;
    const getEvent = (action) => d.events?.find(e => e.eventAction === action)?.eventDate;
    const registrar = d.entities?.find(e => e.roles?.includes('registrar'));
    const registrarName = registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || '—';

    res.json({
      success: true, api: 'WHOIS via RDAP (Free)',
      domain: query,
      handle: d.handle,
      status: Array.isArray(d.status) ? d.status : [d.status],
      registrar: registrarName,
      nameservers: d.nameservers?.map(n => n.ldhName) || [],
      registered: getEvent('registration'),
      expires: getEvent('expiration'),
      lastChanged: getEvent('last changed'),
      note: 'Using RDAP (free, no key needed). Add WHOISXML_KEY for extended WHOIS contact data.',
    });
  } catch (err) {
    apiError(res, 'WHOIS lookup failed. Domain may not exist or registry is unreachable.');
  }
};

// ─── 8. GreyNoise → Community API (no key needed) ────────────────────────────
const checkGreyNoise = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP address is required.', 400);
  if (!isPublicIPv4(query))
    return apiError(res, 'GreyNoise requires a valid public IPv4 address (e.g. 45.33.32.156). Private/reserved IPs are not accepted.', 400);

  try {
    const headers = { 'User-Agent': 'CyberShield-Dashboard' };
    if (hasKey(process.env.GREYNOISE_KEY)) headers['key'] = process.env.GREYNOISE_KEY;

    const r = await axios.get(`https://api.greynoise.io/v3/community/${query}`, {
      headers, timeout: 10000,
    });
    res.json({ success: true, api: 'GreyNoise', data: r.data });
  } catch (err) {
    const msg = err.response?.data?.message || err.response?.data?.error || 'GreyNoise API error.';
    apiError(res, msg);
  }
};

// ─── 9. URLScan → search public results (no key needed) ──────────────────────
const checkURLScan = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'URL or domain is required.', 400);

  // If key set: submit a new scan
  if (hasKey(process.env.URLSCAN_KEY)) {
    try {
      const url = query.startsWith('http') ? query : `https://${query}`;
      const r = await axios.post('https://urlscan.io/api/v1/scan/',
        { url, visibility: 'public' },
        { headers: { 'API-Key': process.env.URLSCAN_KEY, 'Content-Type': 'application/json' } }
      );
      return res.json({
        success: true, api: 'URLScan — New Scan',
        scanId: r.data.uuid,
        resultUrl: r.data.result,
        screenshotUrl: `https://urlscan.io/screenshots/${r.data.uuid}.png`,
        message: 'Scan submitted! Results available in ~30 seconds.',
      });
    } catch (err) { /* fall through to search */ }
  }

  // Free fallback: search existing scans (no key needed)
  try {
    const domain = query.replace(/^https?:\/\//, '').split('/')[0];
    const r = await axios.get('https://urlscan.io/api/v1/search/', {
      params: { q: `domain:${domain}`, size: 5 },
      headers: { 'User-Agent': 'CyberShield-Dashboard' },
      timeout: 10000,
    });
    const results = r.data.results || [];
    res.json({
      success: true, api: 'URLScan — Public Search (Free)',
      domain,
      totalResults: r.data.total,
      scans: results.map(s => ({
        url: s.page?.url,
        domain: s.page?.domain,
        ip: s.page?.ip,
        country: s.page?.country,
        server: s.page?.server,
        status: s.page?.status,
        date: s.task?.time,
        resultLink: `https://urlscan.io/result/${s._id}/`,
        screenshot: s.screenshot,
        verdicts: s.verdicts?.overall,
      })),
      note: 'Showing existing public scans. Add URLSCAN_KEY to submit new scans.',
    });
  } catch (err) {
    apiError(res, 'URLScan search failed.');
  }
};

// ─── 10. Hunter.io → HackerTarget free fallback ───────────────────────────────
const checkHunter = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Domain name is required.', 400);

  if (hasKey(process.env.HUNTER_KEY)) {
    try {
      const r = await axios.get('https://api.hunter.io/v2/domain-search', {
        params: { domain: query, api_key: process.env.HUNTER_KEY, limit: 10 },
        timeout: 10000,
      });
      return res.json({ success: true, api: 'Hunter.io', data: r.data });
    } catch (err) { /* fall through */ }
  }

  try {
    const [reverseip, pagelinks] = await Promise.allSettled([
      axios.get(`https://api.hackertarget.com/reverseiplookup/?q=${query}`, { timeout: 8000 }),
      axios.get(`https://api.hackertarget.com/pagelinks/?q=${query}`, { timeout: 8000 }),
    ]);
    res.json({
      success: true, api: 'Email / Domain Intelligence — HackerTarget (Free)',
      domain: query,
      reverseDNS: reverseip.status === 'fulfilled' ? reverseip.value.data : 'N/A',
      pageLinks: pagelinks.status === 'fulfilled' ? pagelinks.value.data?.substring(0, 800) : 'N/A',
      note: 'Using HackerTarget free endpoints. Add HUNTER_KEY for full email finder with 25 free searches/month.',
    });
  } catch (err) {
    apiError(res, 'Email intelligence lookup failed.');
  }
};

// ─── 11. BuiltWith → HackerTarget HTTP headers (free) ────────────────────────
const checkBuiltWith = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Domain name is required.', 400);
  try {
    const domain = query.replace(/^https?:\/\//, '').split('/')[0];
    const [headers, links] = await Promise.allSettled([
      axios.get(`https://api.hackertarget.com/httpheaders/?q=https://${domain}`, { timeout: 8000 }),
      axios.get(`https://api.hackertarget.com/pagelinks/?q=https://${domain}`, { timeout: 8000 }),
    ]);

    // Parse tech from headers
    const rawHeaders = headers.status === 'fulfilled' ? headers.value.data : '';
    const techClues = [];
    const h = rawHeaders.toLowerCase();
    if (h.includes('x-powered-by: php'))     techClues.push('PHP');
    if (h.includes('x-powered-by: asp'))     techClues.push('ASP.NET');
    if (h.includes('x-powered-by: express')) techClues.push('Node.js / Express');
    if (h.includes('server: apache'))        techClues.push('Apache');
    if (h.includes('server: nginx'))         techClues.push('Nginx');
    if (h.includes('server: cloudflare'))    techClues.push('Cloudflare');
    if (h.includes('server: iis'))           techClues.push('IIS');
    if (h.includes('set-cookie: wordpress')) techClues.push('WordPress');
    if (h.includes('x-shopify'))             techClues.push('Shopify');
    if (h.includes('x-drupal'))              techClues.push('Drupal');
    if (h.includes('strict-transport'))      techClues.push('HTTPS / HSTS');
    if (h.includes('x-frame-options'))       techClues.push('Clickjacking Protection');
    if (h.includes('content-security'))      techClues.push('Content-Security-Policy');

    res.json({
      success: true, api: 'Tech Detection — HTTP Headers (Free)',
      domain,
      detectedTech: techClues,
      httpHeaders: rawHeaders,
      pageLinks: links.status === 'fulfilled' ? links.value.data?.substring(0, 600) : 'N/A',
      note: 'Tech detected from HTTP headers. BuiltWith paid API needed for full JavaScript/CSS fingerprinting.',
    });
  } catch (err) {
    apiError(res, 'Technology detection failed.');
  }
};

// ─── 12. Censys → Shodan InternetDB free fallback ────────────────────────────
const checkCensys = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP address is required.', 400);
  if (!isPublicIPv4(query))
    return apiError(res, 'Enter a valid public IPv4 address.', 400);

  if (hasKey(process.env.CENSYS_API_ID) && hasKey(process.env.CENSYS_SECRET)) {
    try {
      const r = await axios.get(`https://search.censys.io/api/v2/hosts/${query}`, {
        auth: { username: process.env.CENSYS_API_ID, password: process.env.CENSYS_SECRET },
        timeout: 10000,
      });
      return res.json({ success: true, api: 'Censys', data: r.data });
    } catch (err) { /* fall through */ }
  }

  // Free fallback: Shodan InternetDB
  try {
    const r = await axios.get(`https://internetdb.shodan.io/${query}`, { timeout: 8000 });
    res.json({
      success: true, api: 'Internet Asset Intelligence — Shodan InternetDB (Free)',
      ip: query,
      openPorts: r.data.ports || [],
      hostnames: r.data.hostnames || [],
      cpes: r.data.cpes || [],
      tags: r.data.tags || [],
      vulns: r.data.vulns || [],
      note: 'Using Shodan InternetDB (free, no key). Add CENSYS_API_ID + CENSYS_SECRET for full Censys data.',
    });
  } catch (err) {
    if (err.response?.status === 404)
      return res.json({ success: true, api: 'Censys / InternetDB', ip: query, openPorts: [], note: 'No scan data found for this IP.' });
    apiError(res, 'Host intelligence lookup failed.');
  }
};

// ─── 13. OpenPhish ────────────────────────────────────────────────────────────
const checkOpenPhish = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'URL or domain is required.', 400);
  try {
    const r = await axios.get('https://openphish.com/feed.txt', { timeout: 12000 });
    const feed = r.data.split('\n').map(l => l.trim()).filter(Boolean);
    const matches = feed.filter(l => l.toLowerCase().includes(query.toLowerCase()));
    res.json({
      success: true, api: 'OpenPhish',
      query,
      isPhishing: matches.length > 0,
      status: matches.length > 0 ? 'PHISHING DETECTED' : 'NOT IN DATABASE',
      matchCount: matches.length,
      matches: matches.slice(0, 5),
      feedSize: feed.length,
    });
  } catch (err) {
    apiError(res, 'OpenPhish feed temporarily unavailable. Try again in a few seconds.');
  }
};

// ─── 14. AlienVault OTX ───────────────────────────────────────────────────────
const checkOTX = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP, domain, or hash is required.', 400);
  try {
    const isIP   = isPublicIPv4(query);
    const isHash = /^[a-fA-F0-9]{32,64}$/.test(query);
    let type = 'domain';
    if (isIP) type = 'IPv4';
    else if (isHash) {
      type = query.length === 32 ? 'file/md5'
           : query.length === 40 ? 'file/sha1' : 'file/sha256';
    }
    const headers = { 'User-Agent': 'CyberShield-Dashboard' };
    if (hasKey(process.env.OTX_KEY)) headers['X-OTX-API-KEY'] = process.env.OTX_KEY;

    const r = await axios.get(
      `https://otx.alienvault.com/api/v1/indicators/${type}/${query}/general`,
      { headers, timeout: 12000 }
    );
    res.json({ success: true, api: 'AlienVault OTX', indicatorType: type, data: r.data });
  } catch (err) {
    apiError(res, err.response?.data?.detail || 'OTX API error. The indicator may not be in the database.');
  }
};

// ─── 15. NVD API (no key needed) ─────────────────────────────────────────────
const checkNVD = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'CVE ID or keyword is required.', 400);
  try {
    const isCVE = query.toUpperCase().startsWith('CVE-');
    const params = isCVE
      ? { cveId: query.toUpperCase() }
      : { keywordSearch: query, resultsPerPage: 5 };
    const headers = {};
    if (hasKey(process.env.NVD_KEY)) headers['apiKey'] = process.env.NVD_KEY;

    const r = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params, headers, timeout: 20000,
    });
    const vulns = (r.data.vulnerabilities || []).map(v => ({
      id: v.cve?.id,
      description: v.cve?.descriptions?.find(d => d.lang === 'en')?.value,
      published: v.cve?.published,
      lastModified: v.cve?.lastModified,
      cvssScore: v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
              || v.cve?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 'N/A',
      severity: v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity
             || v.cve?.metrics?.cvssMetricV2?.[0]?.baseSeverity || 'N/A',
      references: v.cve?.references?.slice(0, 3).map(r2 => r2.url),
    }));
    res.json({ success: true, api: 'NVD — National Vulnerability Database', total: r.data.totalResults, vulnerabilities: vulns });
  } catch (err) {
    if (err.code === 'ECONNABORTED')
      return apiError(res, 'NVD API timeout. They rate-limit unauthenticated requests — wait a few seconds and try again.');
    apiError(res, 'NVD API error.');
  }
};

// ─── 16. IPAPI (no key needed) ────────────────────────────────────────────────
const checkIPAPI = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'IP address is required.', 400);
  if (!isPublicIPv4(query))
    return apiError(res, 'Enter a valid public IPv4 address (e.g. 1.1.1.1).', 400);
  try {
    const r = await axios.get(`https://ipapi.co/${query}/json/`, {
      headers: { 'User-Agent': 'CyberShield-Dashboard' }, timeout: 8000,
    });
    if (r.data.error) return apiError(res, r.data.reason || 'IPAPI error.');
    res.json({ success: true, api: 'IPAPI', data: r.data });
  } catch (err) {
    apiError(res, 'IPAPI lookup failed.');
  }
};

// ─── 17. EmailRep ─────────────────────────────────────────────────────────────
const checkEmailRep = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Email address is required.', 400);
  try {
    const headers = { 'User-Agent': 'CyberShield-Dashboard' };
    if (hasKey(process.env.EMAILREP_KEY)) headers['Key'] = process.env.EMAILREP_KEY;
    const r = await axios.get(`https://emailrep.io/${encodeURIComponent(query)}`, {
      headers, timeout: 8000,
    });
    res.json({ success: true, api: 'EmailRep', data: r.data });
  } catch (err) {
    apiError(res, err.response?.data?.reason || 'EmailRep API error.');
  }
};

// ─── 18. DNS Lookup (Google DoH — no key needed) ─────────────────────────────
const checkDNS = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'Domain name is required.', 400);
  try {
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
    const results = {};
    await Promise.all(types.map(async (type) => {
      try {
        const r = await axios.get('https://dns.google/resolve', {
          params: { name: query, type }, timeout: 5000,
        });
        results[type] = {
          status: r.data.Status === 0 ? 'OK' : 'NXDOMAIN',
          records: (r.data.Answer || []).map(a => ({ ttl: a.TTL, data: a.data })),
        };
      } catch { results[type] = { status: 'ERROR', records: [] }; }
    }));
    res.json({ success: true, api: 'DNS Lookup (Google DoH)', domain: query, records: results });
  } catch (err) {
    apiError(res, 'DNS lookup failed.');
  }
};

// ─── 19. Google Safe Browsing → OpenPhish fallback ───────────────────────────
const checkSafeBrowsing = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'URL is required.', 400);

  if (hasKey(process.env.GOOGLE_SAFE_BROWSING_KEY)) {
    try {
      const r = await axios.post(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
        {
          client: { clientId: 'cybershield', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: query }],
          },
        },
        { timeout: 8000 }
      );
      const matches = r.data.matches || [];
      return res.json({
        success: true, api: 'Google Safe Browsing',
        url: query,
        isSafe: matches.length === 0,
        status: matches.length === 0 ? 'SAFE' : 'UNSAFE',
        threatCount: matches.length,
        threats: matches,
      });
    } catch (err) { /* fall through */ }
  }

  // Free fallback: OpenPhish check
  try {
    const r = await axios.get('https://openphish.com/feed.txt', { timeout: 10000 });
    const feed = r.data.split('\n').filter(Boolean);
    const found = feed.some(l => l.toLowerCase().includes(query.toLowerCase()));
    res.json({
      success: true, api: 'Safe Browsing — OpenPhish (Free Fallback)',
      url: query,
      isSafe: !found,
      status: found ? 'SUSPICIOUS — found in phishing feed' : 'NOT in OpenPhish database',
      note: 'Add GOOGLE_SAFE_BROWSING_KEY for Google Safe Browsing (free, requires Google Cloud account).',
    });
  } catch (err) {
    apiError(res, 'Safe browsing check failed.');
  }
};

// ─── 20. CVE Details (NVD endpoint — no key needed) ──────────────────────────
const checkCVEDetails = async (req, res) => {
  const { query } = req.query;
  if (!query) return apiError(res, 'CVE ID or keyword is required.', 400);
  try {
    const isCVE = query.toUpperCase().startsWith('CVE-');
    const params = isCVE
      ? { cveId: query.toUpperCase() }
      : { keywordSearch: query, resultsPerPage: 5 };

    const r = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params, timeout: 20000,
    });
    const vulns = (r.data.vulnerabilities || []).map(v => ({
      id: v.cve?.id,
      description: v.cve?.descriptions?.find(d => d.lang === 'en')?.value,
      published: v.cve?.published,
      lastModified: v.cve?.lastModified,
      cvssScore: v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
              || v.cve?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 'N/A',
      severity: v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity
             || v.cve?.metrics?.cvssMetricV2?.[0]?.baseSeverity || 'N/A',
      affectedProducts: v.cve?.configurations?.[0]?.nodes?.[0]?.cpeMatch?.slice(0,3).map(c => c.criteria),
      references: v.cve?.references?.slice(0, 3).map(rr => rr.url),
    }));
    res.json({ success: true, api: 'CVE Details (NVD)', total: r.data.totalResults, vulnerabilities: vulns });
  } catch (err) {
    if (err.code === 'ECONNABORTED')
      return apiError(res, 'CVE lookup timeout. NVD rate-limits unauthenticated requests — try again in a few seconds.');
    apiError(res, 'CVE Details lookup failed.');
  }
};

// ─── Exports ──────────────────────────────────────────────────────────────────
module.exports = {
  checkAbuseIPDB, checkVirusTotal, checkHIBP, checkIPInfo,
  checkShodan, checkSecurityTrails, checkWhois, checkGreyNoise,
  checkURLScan, checkHunter, checkBuiltWith, checkCensys,
  checkOpenPhish, checkOTX, checkNVD, checkIPAPI,
  checkEmailRep, checkDNS, checkSafeBrowsing, checkCVEDetails,
};
