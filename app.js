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

app.post('/generate-dkim', async (req, res) => {
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
    const info = await transporter.sendMail(mailOptions);
    console.log('Info object:', JSON.stringify(info, null, 2));
    
    if (info.dkim) {
      res.json({ dkimSignature: info.dkim });
    } else {
      res.status(500).json({ error: 'DKIM signature not found in the generated email' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));