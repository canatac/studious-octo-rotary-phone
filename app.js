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

app.post('/generate-dkim', async (req, res) => {
  console.log('Received request:', JSON.stringify(req.body, null, 2));

  const { from, to, subject, text } = req.body;
    // Create a message object
    const message = {
      from,
      to,
      subject,
      text,
    };

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
  },
  dkim: {
    domainName: process.env.DOMAIN_NAME,
    keySelector: process.env.KEY_SELECTOR,
    privateKey : privateKey
  }
});

// Define the email options


let mailOptions = {
  from: `<${from}>`,
  to: `<${to}>`,
  subject: `${subject}`,
  text: `${text}`
};

// Send the email
transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.log('Error:', error);
  } else {
    console.log('Email sent:', info.response);
  }
});

    console.log('Message sent:', info.messageId);
    console.log('Preview URL:', nodemailer.getTestMessageUrl(info));

});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));