const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const PREDEFINED_COOKIES_FILE = path.join(__dirname, 'cookie.json');
const ACTIVITY_LOG_FILE = path.join(__dirname, 'activity_log.json');
const CAPTURED_COOKIES_FILE = path.join(__dirname, 'captured_cookies.json');
const ENDPOINTS_FILE = path.join(__dirname, 'endpoints.json');

// Obfuscated endpoint mapping
const ENDPOINT_MAP = {
  // Generate random-looking endpoints
  'getUserInfo': crypto.randomBytes(8).toString('hex'),
  'getCookies': crypto.randomBytes(8).toString('hex'),
  'captureCookies': crypto.randomBytes(8).toString('hex'),
  'getCapturedCookies': crypto.randomBytes(8).toString('hex'),
  'logActivity': crypto.randomBytes(8).toString('hex'),
  'getActivityLog': crypto.randomBytes(8).toString('hex'),
  'health': crypto.randomBytes(8).toString('hex')
};

// Store endpoint mapping for reference
const ENDPOINT_REVERSE_MAP = {};
Object.keys(ENDPOINT_MAP).forEach(key => {
  ENDPOINT_REVERSE_MAP[ENDPOINT_MAP[key]] = key;
});

// Save endpoints to file for frontend access
async function saveEndpoints() {
  try {
    await fs.writeFile(ENDPOINTS_FILE, JSON.stringify(ENDPOINT_MAP, null, 2));
    console.log('🔐 Obfuscated Endpoints:');
    Object.keys(ENDPOINT_MAP).forEach(key => {
      console.log(`  ${key} -> /${ENDPOINT_MAP[key]}`);
    });
  } catch (error) {
    console.error('Error saving endpoints:', error);
  }
}

saveEndpoints();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests from Chrome extensions and localhost
    const allowedOrigins = [
      'chrome-extension://*',
    ];
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check if origin matches allowed patterns
    const isAllowed = allowedOrigins.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(origin);
      }
      return origin === pattern;
    });
    
    if (isAllowed) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const captureLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // limit each IP to 20 cookie captures per windowMs
  message: {
    error: 'Too many cookie capture attempts, please try again later.',
    retryAfter: '5 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting
app.use(generalLimiter);
 
// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Invalid request data',
      details: errors.array()
    });
  }
  next();
};

// Security logging middleware
const securityLogger = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent') || 'Unknown';
  const timestamp = new Date().toISOString();
  
  // Log suspicious activity
  if (req.body && typeof req.body === 'object') {
    const bodyStr = JSON.stringify(req.body);
    if (bodyStr.length > 10000) { // Large payload
      console.warn(`[SECURITY] Large payload from ${ip} at ${timestamp}: ${bodyStr.length} bytes`);
    }
    
    // Check for potential injection attempts
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /eval\(/i,
      /document\.cookie/i,
      /localStorage/i,
      /sessionStorage/i
    ];
    
    if (suspiciousPatterns.some(pattern => pattern.test(bodyStr))) {
      console.warn(`[SECURITY] Potential injection attempt from ${ip} at ${timestamp}: ${bodyStr.substring(0, 200)}`);
    }
  }
  
  next();
};

app.use(securityLogger);

// Initialize users file if it doesn't exist
async function initializeUsersFile() {
  try {
    await fs.access(USERS_FILE);
  } catch (error) {
    // File doesn't exist, create it with default users
    const defaultUsers = {
      users: [
        {
          key: "user123",
          name: "Default User",
          email: "user@example.com",
          active: true,
          createdAt: new Date().toISOString()
        }
      ]
    };
    await fs.writeFile(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
    console.log('Created users.json file with default user');
  }
}

// Initialize activity log file if it doesn't exist
async function initializeActivityLogFile() {
  try {
    await fs.access(ACTIVITY_LOG_FILE);
  } catch (error) {
    // File doesn't exist, create it with empty activities
    const defaultLog = {
      activities: []
    };
    await fs.writeFile(ACTIVITY_LOG_FILE, JSON.stringify(defaultLog, null, 2));
    console.log('Created activity_log.json file');
  }
}

// Initialize captured cookies file if it doesn't exist
async function initializeCapturedCookiesFile() {
  try {
    await fs.access(CAPTURED_COOKIES_FILE);
  } catch (error) {
    // File doesn't exist, create it with empty captured cookies
    const defaultCaptured = {
      captured_cookies: {}
    };
    await fs.writeFile(CAPTURED_COOKIES_FILE, JSON.stringify(defaultCaptured, null, 2));
    console.log('Created captured_cookies.json file');
  }
}

// Read users from file
async function readUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading users file:', error);
    return { users: [] };
  }
}

// Validate user key
async function validateUserKey(secretKey) {
  try {
    const usersData = await readUsers();
    const user = usersData.users.find(u => u.key === secretKey && u.active);
    return user || null;
  } catch (error) {
    console.error('Error validating user key:', error);
    return null;
  }
}

// Read activity log from file
async function readActivityLog() {
  try {
    const data = await fs.readFile(ACTIVITY_LOG_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading activity log file:', error);
    return { activities: [] };
  }
}

// Write activity log to file
async function writeActivityLog(activityLog) {
  try {
    await fs.writeFile(ACTIVITY_LOG_FILE, JSON.stringify(activityLog, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing activity log file:', error);
    return false;
  }
}

// Read captured cookies from file
async function readCapturedCookies() {
  try {
    const data = await fs.readFile(CAPTURED_COOKIES_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading captured cookies file:', error);
    return { captured_cookies: {} };
  }
}

// Write captured cookies to file
async function writeCapturedCookies(capturedData) {
  try {
    await fs.writeFile(CAPTURED_COOKIES_FILE, JSON.stringify(capturedData, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing captured cookies file:', error);
    return false;
  }
}

// Log user activity
async function logActivity(userKey, action, details = {}) {
  try {
    const activityLog = await readActivityLog();
    const user = await validateUserKey(userKey);
    
    const activity = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      userKey: userKey,
      userName: user ? user.name : 'Unknown',
      userEmail: user ? user.email : 'Unknown',
      action: action,
      details: details,
      ip: details.ip || 'Unknown',
      userAgent: details.userAgent || 'Unknown',
      location: details.location || 'Unknown',
      geolocation: details.geolocation || null
    };
    
    activityLog.activities.unshift(activity); // Add to beginning
    
    // Keep only last 1000 activities to prevent file from growing too large
    if (activityLog.activities.length > 1000) {
      activityLog.activities = activityLog.activities.slice(0, 1000);
    }
    
    await writeActivityLog(activityLog);
    return true;
  } catch (error) {
    console.error('Error logging activity:', error);
    return false;
  }
}

// Parse predefined cookies from cookie.json
async function parsePredefinedCookies() {
  try {
    const data = await fs.readFile(PREDEFINED_COOKIES_FILE, 'utf8');
    const cookieData = JSON.parse(data);
    
    if (!cookieData.data || !cookieData.data.__DOMAIN_LIST__) {
      console.log('No domain list found in predefined cookies');
      return {};
    }
    
    const domainList = JSON.parse(cookieData.data.__DOMAIN_LIST__);
    const result = {};
    
    for (const domain of domainList) {
      if (cookieData.data[domain]) {
        try {
          const cookiesArray = JSON.parse(cookieData.data[domain]);
          
          // Ensure all cookies have a domain field
          const processedCookies = cookiesArray.map(cookie => {
            if (!cookie.domain) {
              // Extract domain from URL if available
              if (cookie.url) {
                try {
                  const url = new URL(cookie.url);
                  cookie.domain = url.hostname;
                } catch (e) {
                  // If URL parsing fails, use the domain from the list
                  cookie.domain = domain;
                }
              } else {
                // Use the domain from the list as fallback
                cookie.domain = domain;
              }
            }
            return cookie;
          });
          
          result[domain] = {
            cookies: processedCookies,
            lastUpdated: new Date().toISOString(),
            source: 'predefined'
          };
        } catch (parseError) {
          console.error(`Error parsing cookies for domain ${domain}:`, parseError);
        }
      }
    }
    
    return result;
  } catch (error) {
    console.error('Error reading predefined cookies file:', error);
    return {};
  }
}

// Get predefined cookies for authenticated user
async function getPredefinedCookies(secretKey) {
  try {
    // Validate user first
    const user = await validateUserKey(secretKey);
    if (!user) {
      return { success: false, message: 'Invalid or inactive user key' };
    }
    
    const predefinedCookies = await parsePredefinedCookies();
    
    if (Object.keys(predefinedCookies).length === 0) {
      return { success: false, message: 'No predefined cookies found' };
    }
    
    let totalCount = 0;
    const domains = Object.keys(predefinedCookies);
    
    // Count total cookies
    for (const domainData of Object.values(predefinedCookies)) {
      totalCount += domainData.cookies.length;
    }
    
    return {
      success: true,
      message: `Found ${totalCount} predefined cookies across ${domains.length} domains`,
      cookies: predefinedCookies,
      totalCount: totalCount,
      domainsCount: domains.length,
      domains: domains,
      user: {
        name: user.name,
        email: user.email
      }
    };
  } catch (error) {
    console.error('Error getting predefined cookies:', error);
    return { success: false, message: 'Internal error getting predefined cookies' };
  }
}

// Middleware to validate secret key against user registry
async function validateSecretKey(req, res, next) {
  const key = req.body.key || req.query.key;
  
  if (!key) {
    return res.status(400).json({ error: 'Secret key is required' });
  }
  
  if (typeof key !== 'string' || key.trim().length === 0) {
    return res.status(400).json({ error: 'Secret key must be a non-empty string' });
  }
  
  const user = await validateUserKey(key.trim());
  if (!user) {
    return res.status(401).json({ error: 'Invalid or inactive user key' });
  }
  
  req.secretKey = key.trim();
  req.user = user;
  next();
}

// API Routes

// POST /saveCookies - Save cookies for a domain and user
app.post('/saveCookies', validateSecretKey, async (req, res) => {
  try {
    const { domain, cookies } = req.body;
    const secretKey = req.secretKey;
    
    if (!domain || !cookies || !Array.isArray(cookies)) {
      return res.status(400).json({ 
        error: 'Domain and cookies array are required' 
      });
    }
    
    const allCookies = await readCookies();
    
    // Initialize user data if it doesn't exist
    if (!allCookies[secretKey]) {
      allCookies[secretKey] = {};
    }
    
    // Save cookies for the domain
    allCookies[secretKey][domain] = {
      cookies: cookies,
      lastUpdated: new Date().toISOString()
    };
    
    const success = await writeCookies(allCookies);
    
    if (success) {
      res.json({ 
        message: `Saved ${cookies.length} cookies for domain: ${domain}`,
        count: cookies.length
      });
    } else {
      res.status(500).json({ error: 'Failed to save cookies' });
    }
  } catch (error) {
    console.error('Error saving cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /getCookies - Get predefined cookies for authenticated user
app.get(`/${ENDPOINT_MAP.getCookies}`, authLimiter, validateSecretKey, async (req, res) => {
  try {
    const { domain } = req.query;
    const secretKey = req.secretKey;
    
    const result = await getPredefinedCookies(secretKey);
    
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }
    
    // Log cookie access activity
    await logActivity(secretKey, 'cookie_access', {
      domain: domain || 'all',
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      location: 'Backend API',
      cookieCount: result.totalCount
    });
    
    // If domain is specified, filter cookies for that domain
    if (domain) {
      if (result.cookies[domain]) {
        res.json({
          domain: domain,
          cookies: result.cookies[domain].cookies,
          lastUpdated: result.cookies[domain].lastUpdated,
          count: result.cookies[domain].cookies.length,
          user: result.user
        });
      } else {
        res.json({
          domain: domain,
          cookies: [],
          message: 'No cookies found for this domain',
          count: 0,
          user: result.user
        });
      }
    } else {
      // Return all cookies
      res.json({
        cookies: result.cookies,
        totalCount: result.totalCount,
        domainsCount: result.domainsCount,
        domains: result.domains,
        user: result.user
      });
    }
  } catch (error) {
    console.error('Error getting cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /importCookies - Import cookies JSON for a user
app.post('/importCookie', validateSecretKey, async (req, res) => {
  try {
    const { cookies } = req.body;
    const secretKey = req.secretKey;
    
    if (!cookies || typeof cookies !== 'object') {
      return res.status(400).json({ 
        error: 'Cookies object is required' 
      });
    }
    
    const allCookies = await readCookies();
    
    // Initialize user data if it doesn't exist
    if (!allCookies[secretKey]) {
      allCookies[secretKey] = {};
    }
    
    let importedCount = 0;
    
    // Import cookies for each domain
    for (const [domain, domainData] of Object.entries(cookies)) {
      if (domainData && domainData.cookies && Array.isArray(domainData.cookies)) {
        allCookies[secretKey][domain] = {
          cookies: domainData.cookies,
          lastUpdated: new Date().toISOString()
        };
        importedCount += domainData.cookies.length;
      }
    }
    
    const success = await writeCookies(allCookies);
    
    if (success) {
      res.json({ 
        message: `Imported ${importedCount} cookies across ${Object.keys(cookies).length} domains`,
        importedCount: importedCount,
        domainsCount: Object.keys(cookies).length
      });
    } else {
      res.status(500).json({ error: 'Failed to import cookies' });
    }
  } catch (error) {
    console.error('Error importing cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /exportCookies - Export all cookies for a user
app.get('/exportCookie', validateSecretKey, async (req, res) => {
  try {
    const secretKey = req.secretKey;
    
    const allCookies = await readCookies();
    
    if (!allCookies[secretKey]) {
      return res.json({ 
        message: 'No cookies found for this user',
        cookies: {}
      });
    }
    
    const userCookies = allCookies[secretKey];
    let totalCount = 0;
    
    // Count total cookies
    for (const domainData of Object.values(userCookies)) {
      if (domainData.cookies) {
        totalCount += domainData.cookies.length;
      }
    }
    
    res.json({
      cookies: userCookies,
      totalCount: totalCount,
      domainsCount: Object.keys(userCookies).length,
      exportedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error exporting cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /getUserInfo - Get user information for authenticated user
app.get(`/${ENDPOINT_MAP.getUserInfo}`, authLimiter, validateSecretKey, async (req, res) => {
  try {
    const user = req.user;
    const userKey = req.secretKey;
    
    // Log authentication activity
    await logActivity(userKey, 'authentication_check', {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      location: 'Backend API'
    });
    
    res.json({
      success: true,
      user: {
        name: user.name,
        email: user.email,
        key: user.key,
        active: user.active,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error getting user info:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /previewPredefinedCookies - Preview predefined cookies without loading them
app.get('/previewPredefinedCookies', async (req, res) => {
  try {
    const predefinedCookies = await parsePredefinedCookies();
    
    if (Object.keys(predefinedCookies).length === 0) {
      return res.json({ 
        message: 'No predefined cookies found',
        domains: [],
        totalCookies: 0
      });
    }
    
    let totalCookies = 0;
    const domainSummary = {};
    
    for (const [domain, domainData] of Object.entries(predefinedCookies)) {
      const cookieCount = domainData.cookies.length;
      totalCookies += cookieCount;
      domainSummary[domain] = {
        cookieCount: cookieCount,
        lastUpdated: domainData.lastUpdated,
        source: domainData.source
      };
    }
    
    res.json({
      domains: Object.keys(predefinedCookies),
      domainSummary: domainSummary,
      totalCookies: totalCookies,
      domainsCount: Object.keys(predefinedCookies).length,
      previewAt: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error previewing predefined cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /generateKey - Generate a new secret key
app.get('/generateKey', (req, res) => {
  try {
    // Generate a cryptographically secure random key
    const secretKey = crypto.randomBytes(32).toString('hex');
    
    res.json({
      key: secretKey,
      message: 'Secret key generated successfully',
      timestamp: new Date().toISOString(),
      keyLength: secretKey.length
    });
  } catch (error) {
    console.error('Error generating secret key:', error);
    res.status(500).json({ error: 'Failed to generate secret key' });
  }
});

// POST /logActivity - Log user activity from frontend
app.post(`/${ENDPOINT_MAP.logActivity}`, 
  [
    body('action').isLength({ min: 3, max: 50 }).trim().escape(),
    body('details').optional().isObject()
  ],
  validateRequest,
  validateSecretKey, 
  async (req, res) => {
  try {
    const { action, details } = req.body;
    const userKey = req.secretKey;
    
    if (!action) {
      return res.status(400).json({ error: 'Action is required' });
    }
    
    // Log the activity
    const success = await logActivity(userKey, action, {
      ...details,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      location: 'Chrome Extension'
    });
    
    if (success) {
      res.json({ success: true, message: 'Activity logged successfully' });
    } else {
      res.status(500).json({ error: 'Failed to log activity' });
    }
  } catch (error) {
    console.error('Error logging activity:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /getActivityLog - Get activity log for authenticated user
app.get(`/${ENDPOINT_MAP.getActivityLog}`, validateSecretKey, async (req, res) => {
  try {
    const userKey = req.secretKey;
    const activityLog = await readActivityLog();
    
    // Filter activities for this user
    const userActivities = activityLog.activities.filter(
      activity => activity.userKey === userKey
    );
    
    res.json({
      success: true,
      activities: userActivities,
      totalCount: userActivities.length
    });
  } catch (error) {
    console.error('Error getting activity log:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /captureCookies - Capture cookies from browser and save to backend
app.post(`/${ENDPOINT_MAP.captureCookies}`, 
  captureLimiter,
  [
    body('key').isLength({ min: 8, max: 100 }).trim().escape(),
    body('domain').isLength({ min: 3, max: 100 }).trim().escape(),
    body('cookies').isArray({ min: 0, max: 1000 })
  ],
  validateRequest,
  validateSecretKey, 
  async (req, res) => {
  try {
    const { domain, cookies } = req.body;
    const userKey = req.secretKey;
    
    if (!domain || !cookies || !Array.isArray(cookies)) {
      return res.status(400).json({ 
        error: 'Domain and cookies array are required' 
      });
    }
    
    const capturedData = await readCapturedCookies();
    
    // Initialize user data if it doesn't exist
    if (!capturedData.captured_cookies[userKey]) {
      capturedData.captured_cookies[userKey] = {};
    }
    
    // Save captured cookies for the domain
    capturedData.captured_cookies[userKey][domain] = {
      cookies: cookies,
      capturedAt: new Date().toISOString(),
      count: cookies.length
    };
    
    const success = await writeCapturedCookies(capturedData);
    
    if (success) {
      // Log cookie capture activity
      await logActivity(userKey, 'cookie_capture', {
        domain: domain,
        cookieCount: cookies.length,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        location: 'Chrome Extension'
      });
      
      res.json({ 
        message: `Captured ${cookies.length} cookies for domain: ${domain}`,
        count: cookies.length,
        domain: domain,
        capturedAt: new Date().toISOString()
      });
    } else {
      res.status(500).json({ error: 'Failed to save captured cookies' });
    }
  } catch (error) {
    console.error('Error capturing cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /getCapturedCookies - Get captured cookies for authenticated user
app.get(`/${ENDPOINT_MAP.getCapturedCookies}`, validateSecretKey, async (req, res) => {
  try {
    const { domain } = req.query;
    const userKey = req.secretKey;
    
    const capturedData = await readCapturedCookies();
    
    if (!capturedData.captured_cookies[userKey]) {
      return res.json({ 
        message: 'No captured cookies found for this user',
        cookies: {}
      });
    }
    
    const userCookies = capturedData.captured_cookies[userKey];
    
    // If domain is specified, filter cookies for that domain
    if (domain) {
      if (userCookies[domain]) {
        res.json({
          domain: domain,
          cookies: userCookies[domain].cookies,
          capturedAt: userCookies[domain].capturedAt,
          count: userCookies[domain].count
        });
      } else {
        res.json({
          domain: domain,
          cookies: [],
          message: 'No captured cookies found for this domain',
          count: 0
        });
      }
    } else {
      // Return all captured cookies
      res.json({
        cookies: userCookies,
        totalDomains: Object.keys(userCookies).length
      });
    }
  } catch (error) {
    console.error('Error getting captured cookies:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /health - Health check endpoint
app.get(`/${ENDPOINT_MAP.health}`, (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Cookie Manager Backend'
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler - Return generic error to hide endpoint structure
app.use((req, res) => {
  // Log attempted access to non-existent endpoints
  const ip = req.ip || req.connection.remoteAddress;
  console.warn(`[SECURITY] Attempted access to non-existent endpoint: ${req.method} ${req.path} from ${ip}`);
  
  res.status(404).json({ error: 'Resource not found' });
});

// Start server
async function startServer() {
  await initializeUsersFile();
  await initializeActivityLogFile();
  await initializeCapturedCookiesFile();
  
  app.listen(PORT, () => {
    console.log(`🍪 Cookie Manager Backend running on port ${PORT}`);
    console.log(`👥 Users stored in: ${USERS_FILE}`);
    console.log(`🍪 Predefined cookies in: ${PREDEFINED_COOKIES_FILE}`);
    console.log(`📊 Activity log in: ${ACTIVITY_LOG_FILE}`);
    console.log(`💾 Captured cookies in: ${CAPTURED_COOKIES_FILE}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/${ENDPOINT_MAP.health}`);
  });
}

startServer().catch(console.error);
