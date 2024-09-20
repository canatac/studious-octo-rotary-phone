/**
 * DKIM Signature Generator and Email Sender
 * 
 * This application provides an API endpoint to generate DKIM signatures
 * and send emails using the generated signatures. It uses Express.js for
 * the web server and Nodemailer for email functionality.
 * 
 * Key Features:
 * - Generates DKIM signatures for emails
 * - Sends emails with DKIM signatures
 * - Uses environment variables for configuration
 * - Provides a single POST endpoint for email sending
 * 
 * Setup:
 * 1. Ensure all required environment variables are set in a .env file
 * 2. Install dependencies using `npm install`
 * 3. Run the server using `node app.js`
 * 
 * Usage:
 * Send a POST request to /generate-dkim with the following JSON body:
 * {
 *   "from": "sender@example.com",
 *   "to": "recipient@example.com",
 *   "subject": "Email Subject",
 *   "text": "Email Body"
 * }
 * 
 * The server will generate a DKIM signature and send the email.
 * 
 * Note: Ensure that the SMTP server and DKIM private key are properly configured.
 */

// Import required modules
const dotenv = require('dotenv');
const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

// Load environment variables
dotenv.config();

/**
 * Express application setup
 * @type {import('express').Application}
 */
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

/**
 * Read private key from file
 * @type {string}
 */
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

/**
 * Route to generate DKIM signature and send email
 * @route POST /generate-dkim
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
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
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    tls: {
      rejectUnauthorized: false
    },
    dkim: {
      domainName: process.env.DOMAIN_NAME,
      keySelector: process.env.KEY_SELECTOR,
      privateKey: privateKey
    }
  });

  // Define the email options
  const mailOptions = {
    from: `<${from}>`,
    to: `<${to}>`,
    subject: `${subject}`,
    text: `${text}`
  };

  try {
    // Send mail with defined transport object
    const info = await transporter.sendMail(mailOptions);
    console.log('Message sent: %s', info.messageId);
    res.status(200).json({ message: 'Email sent successfully', messageId: info.messageId, status: 'success' });
    return;
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
