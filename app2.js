require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// Read private key from file
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

console.log('Private key loaded from:', privateKeyPath);
console.log('Private key (first 50 chars):', privateKey.substring(0, 50) + '...');

// Create a transporter with DKIM configuration
var transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER, // Replace with your SMTP username
    pass: process.env.SMTP_PASS  // Replace with your SMTP password
  },
  tls: {
    // Do not fail on invalid certs
    rejectUnauthorized: false
  }
});

// Define the email options
let mailOptions = {
  from: 'jim@misfits.ai',
  to: 'can.atac@gmail.com',
  subject: 'Test Email from Nodemailer',
  text: 'This is a test email sent from Nodemailer to the Rust SMTP server.',
  dkim: {
    domainName: process.env.DOMAIN_NAME,
    keySelector: process.env.KEY_SELECTOR,
    privateKey: privateKey,
  }
};

// Send the email
transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.log('Error:', error);
  } else {
    console.log('Email sent:', info.response);
  }
});

app.post('/generate-dkim', async (req, res) => {
  console.log('Received request:', JSON.stringify(req.body, null, 2));

  const { from, to, subject, text } = req.body;

  try {
    console.log('Attempting to generate DKIM signature...');
    console.log('Domain Name:', process.env.DOMAIN_NAME);
    console.log('Key Selector:', process.env.KEY_SELECTOR);

    // Create a message object
    const message = {
      from,
      to,
      subject,
      text,
    };

    // Use nodemailer's built-in DKIM signing
    const info = await transporter.sendMail(message);

    console.log('Message sent:', info.messageId);
    console.log('Preview URL:', nodemailer.getTestMessageUrl(info));

    // Extract DKIM-Signature from the raw message
    const rawMessage = info.message.toString();
    const dkimSignatureMatch = rawMessage.match(/dkim-signature:[\s\S]+?(?=\r\n\S)/i);

    if (dkimSignatureMatch) {
      let dkimSignature = dkimSignatureMatch[0].trim();
      
      // Clean up the b= field
      dkimSignature = dkimSignature.replace(/b=([^;]+)/, (match, p1) => {
        return 'b=' + p1.replace(/\s+/g, '');
      });

      console.log('Cleaned DKIM Signature:', dkimSignature);
      res.json({ dkimSignature });
    } else {
      console.error('DKIM Signature not found in the message');
      res.status(500).json({ error: 'DKIM Signature not found in the message' });
    }
  } catch (error) {
    console.error('Error generating DKIM signature:', error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));