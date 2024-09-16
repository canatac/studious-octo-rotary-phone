require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const dkim = require('nodemailer/lib/dkim');

const app = express();
app.use(express.json());

// Read private key from file
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

app.post('/generate-dkim', (req, res) => {
  const { from, to, subject, text } = req.body;

  const headers = {
    from,
    to,
    subject,
    'Content-Type': 'text/plain; charset=utf-8',
  };

  const body = text;

  try {
    const signature = dkim.sign({
      domainName: process.env.DOMAIN_NAME,
      keySelector: process.env.KEY_SELECTOR,
      privateKey: privateKey,
      headerFieldNames: 'from:to:subject:content-type',
      headers,
      body,
    });

    res.json({ dkimSignature: signature });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));