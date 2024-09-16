require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const dkimSign = require('nodemailer/lib/dkim');

const app = express();
app.use(express.json());

// Read private key from file
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');


console.log('Private key loaded from:', privateKeyPath);
console.log('Private key (first 50 chars):', privateKey.substring(0, 50) + '...');

app.post('/generate-dkim', async (req, res) => {
  const { from, to, subject, text } = req.body;

  const headers = {
    from,
    to,
    subject,
    'Content-Type': 'text/plain; charset=utf-8',
  };

  const body = text;

  console.log('Headers:', JSON.stringify(headers, null, 2));
  console.log('Body:', body);

  try {

    console.log('Attempting to generate DKIM signature...');
    console.log('Domain Name:', process.env.DOMAIN_NAME);
    console.log('Key Selector:', process.env.KEY_SELECTOR);

    const dkimSignature = dkimSign({
      domainName: process.env.DOMAIN_NAME,
      keySelector: process.env.KEY_SELECTOR,
      privateKey: privateKey,
      headerFieldNames: 'from:to:subject:content-type',
      headers,
      body,
    });

    console.log('DKIM Signature generated successfully');
    console.log('DKIM Signature:', dkimSignature);

    
    res.json({ dkimSignature });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));