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

// Create a transporter without any transport
const transporter = nodemailer.createTransport({
    streamTransport: true,
    newline: 'unix'
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

  try {
    const info = transporter.sendMail(mailOptions);
    const rawEmail = info.message.toString();
    const dkimSignature = rawEmail.match(/dkim-signature:.+/i)[0];
    res.json({ dkimSignature });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));