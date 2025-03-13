// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const app = express();

// Set secure HTTP headers
app.use(helmet());

// Rate limiting to mitigate brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Parse URL-encoded and JSON data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files (for CSS, JS, images)
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration – secure cookies in production!
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecretkey',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Enable CSRF protection
const csrfProtection = csrf();
app.use(csrfProtection);

// Configure Multer for file uploads (limit: 10MB)
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ---------------------------
// Routes
// ---------------------------

// GET / - Render login page
app.get('/', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});

// POST /login - Process login using Buzzheavier API token (accountId)
app.post('/login', (req, res) => {
  const { accountId } = req.body;
  req.session.accountId = accountId;
  res.redirect('/dashboard');
});

// GET /dashboard - Show account info and file system
app.get('/dashboard', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  try {
    const accountResponse = await axios.get('https://buzzheavier.com/api/account', {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    const fsResponse = await axios.get('https://buzzheavier.com/api/fs', {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.render('dashboard', {
      csrfToken: req.csrfToken(),
      account: accountResponse.data,
      files: fsResponse.data,
      accountId: req.session.accountId
    });
  } catch (error) {
    console.error("Error fetching dashboard data:", error.response ? error.response.data : error.message);
    res.send('Error fetching account or file system information. Please verify your account ID.');
  }
});

// POST /create-directory - Create a new directory
app.post('/create-directory', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { name, parentId } = req.body;
  try {
    const payload = { name };
    if (parentId && parentId.trim() !== "") payload.parentId = parentId;
    await axios.post('https://buzzheavier.com/api/fs', payload, {
        headers: { 
          Authorization: `Bearer ${req.session.accountId}`,
          'Content-Type': 'application/json'
        }
      });      
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error creating directory:", error.response ? error.response.data : error.message);
    res.send('Error creating directory. Check server logs for more details.');
  }
});

// POST /rename-directory - Rename an existing directory
app.post('/rename-directory', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { directoryId, newName } = req.body;
  try {
    await axios.patch(`https://buzzheavier.com/api/fs/${directoryId}`, { name: newName }, {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error renaming directory:", error.response ? error.response.data : error.message);
    res.send('Error renaming directory.');
  }
});

// POST /move-directory - Move a directory to a new parent
app.post('/move-directory', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { directoryId, newParentId } = req.body;
  try {
    await axios.put(`https://buzzheavier.com/api/fs/${directoryId}`, { parentId: newParentId }, {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error moving directory:", error.response ? error.response.data : error.message);
    res.send('Error moving directory.');
  }
});

// POST /rename-file - Rename a file
app.post('/rename-file', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { fileId, newName } = req.body;
  try {
    await axios.patch(`https://buzzheavier.com/api/fs/${fileId}`, { name: newName }, {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error renaming file:", error.response ? error.response.data : error.message);
    res.send('Error renaming file.');
  }
});

// POST /move-file - Move a file to a new directory
app.post('/move-file', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { fileId, newParentId } = req.body;
  try {
    await axios.put(`https://buzzheavier.com/api/fs/${fileId}`, { parentId: newParentId }, {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error moving file:", error.response ? error.response.data : error.message);
    res.send('Error moving file.');
  }
});

// POST /add-note - Add or update a note on a file
app.post('/add-note', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { fileId, note } = req.body;
  try {
    await axios.put(`https://buzzheavier.com/api/fs/${fileId}`, { note }, {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error adding note:", error.response ? error.response.data : error.message);
    res.send('Error adding note to file.');
  }
});

// POST /delete-directory - Delete a directory and its subdirectories
app.post('/delete-directory', async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { directoryId } = req.body;
  try {
    await axios.delete(`https://buzzheavier.com/api/fs/${directoryId}`, {
      headers: { Authorization: `Bearer ${req.session.accountId}` }
    });
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error deleting directory:", error.response ? error.response.data : error.message);
    res.send('Error deleting directory.');
  }
});

// POST /upload-file - Upload a file using Buzzheavier file upload endpoints
app.post('/upload-file', upload.single('uploadFile'), async (req, res) => {
  if (!req.session.accountId) return res.redirect('/');
  const { locationId, note } = req.body;
  const filePath = req.file.path;
  try {
    const fileData = fs.readFileSync(filePath);
    // Build endpoint based on provided parameters
    let endpoint = `https://w.buzzheavier.com/${req.file.originalname}`;
    if (locationId && locationId.trim() !== "") {
      endpoint += `?locationId=${locationId}`;
    } else if (note && note.trim() !== "") {
      // Encode note in base64 if provided (ensure to use Buffer)
      const base64Note = Buffer.from(note).toString('base64');
      endpoint += `?note=${base64Note}`;
    }
    await axios.put(endpoint, fileData, {
      headers: {
        Authorization: `Bearer ${req.session.accountId}`,
        'Content-Type': 'application/octet-stream'
      }
    });
    fs.unlinkSync(filePath); // Remove temporary file
    res.redirect('/dashboard');
  } catch (error) {
    console.error("Error uploading file:", error.response ? error.response.data : error.message);
    res.send('Error uploading file.');
  }
});

// GET /logout - End the user session
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});