require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// Read private key from file
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

const transporter = nodemailer.createTransport({
  dkim: {
    domainName: process.env.DOMAIN_NAME,
    keySelector: process.env.KEY_SELECTOR,
    privateKey: privateKey
  }
});

app.post('/generate-dkim', (req, res) => {
  const { from, to, subject, text } = req.body;

  const mailOptions = {
    from,
    to,
    subject,
    text,
    dkim: {
      domainName: process.env.DOMAIN_NAME,
      keySelector: process.env.KEY_SELECTOR,
      privateKey: privateKey
    }
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else {
      const dkimSignature = info.dkim;
      res.json({ dkimSignature });
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));