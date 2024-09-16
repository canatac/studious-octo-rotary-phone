require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const DKIM = require('nodemailer/lib/dkim');

const app = express();
app.use(express.json());

// Read private key from file
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');


console.log('Private key loaded from:', privateKeyPath);
console.log('Private key (first 50 chars):', privateKey.substring(0, 50) + '...');

app.post('/generate-dkim', async (req, res) => {

    console.log('Received request:', JSON.stringify(req.body, null, 2));

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

    const dkim = new DKIM({
        domainName: process.env.DOMAIN_NAME,
        keySelector: process.env.KEY_SELECTOR,
        privateKey: privateKey,
        headerFieldNames: 'from:to:subject:content-type'
      });
      console.log('DKIM instance created');

      const rawEmail = Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join('\r\n') + '\r\n\r\n' + body;
      console.log('Raw email constructed:', rawEmail);

      console.log('Starting DKIM signing process...');
      const signedOutput = await new Promise((resolve, reject) => {
        let chunks = [];
        dkim.sign(rawEmail)
        .on('data', chunk => {
          console.log('Received chunk:', chunk.toString());
          chunks.push(chunk);
        })
        .on('end', () => {
          console.log('DKIM signing process completed');
          resolve(Buffer.concat(chunks).toString('utf8'));
        })
        .on('error', error => {
          console.error('Error during DKIM signing:', error);
          reject(error);
        });
      });

    console.log('DKIM Signature generated successfully');
    console.log('Signed output:', signedOutput);

    const dkimSignatureMatch = signedOutput.match(/dkim-signature:.+/i);
    if (dkimSignatureMatch) {
      const dkimSignature = dkimSignatureMatch[0];
      console.log('Extracted DKIM Signature:', dkimSignature);
      res.json({ dkimSignature });
    } else {
      console.error('DKIM Signature not found in signed output');
      res.status(500).json({ error: 'DKIM Signature not found in signed output' });
    }
    } catch (error) {
        console.error('Error generating DKIM signature:', error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));