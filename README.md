# studious-octo-rotary-phone

## Simple DKIM Signature Service

This application provides an API endpoint to generate DKIM signatures and send emails using the generated signatures. It uses Express.js for the web server and Nodemailer for email functionality.

### Key Features

- Generates DKIM signatures for emails
- Sends emails with DKIM signatures
- Uses environment variables for configuration
- Provides a single POST endpoint for email sending

### Prerequisites

- Node.js and npm installed on your server
- Access to an SMTP server
- A DKIM private key file

### Creating a DKIM Private Key

To generate a DKIM private key, you can use OpenSSL. Follow these steps:

1.  **Generate a Private Key:**
    ```bash
    openssl genrsa -out private.key 2048
    ```
    This command generates a 2048-bit RSA private key and saves it to `private.key`.

2.  **Extract the Public Key:**
    ```bash
    openssl rsa -in private.key -pubout -out public.key
    ```
    This command extracts the public key from the private key and saves it to `public.key`. You will need to add this public key to your DNS records.

3.  **Add the Public Key to Your DNS Records:**

    You need to add the public key (contents of `public.key`) as a TXT record in your domain's DNS settings. The record typically looks like this:

    `selector._domainkey.yourdomain.com IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY_STRING"`

    -   Replace `selector` with your chosen DKIM selector (e.g., `default`, `mail`). This selector is also used in the email headers.
    -   Replace `yourdomain.com` with your actual domain name.
    -   Replace `YOUR_PUBLIC_KEY_STRING` with the actual content of your `public.key` file, removing any line breaks. It should be a single long string.

    **Example:**

    If your selector is `dkim` and your domain is `example.com`, and your `public.key` content is `MIIBIjANBgkqhkiG9...DAQAB`, the TXT record would be:

    `dkim._domainkey.example.com IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9...DAQAB"`

    The exact steps for adding a TXT record vary depending on your DNS provider (e.g., GoDaddy, Cloudflare, AWS Route 53). Consult your DNS provider's documentation for specific instructions.

**Note:** Keep your private key secure and ensure it is accessible by the application at the path specified in your `.env` file.

### Installation

1. **Update the System:**

   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Node.js and npm:**

   You can install Node.js and npm using the NodeSource repository:

   ```bash
   curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

3. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/studious-octo-rotary-phone.git
   cd studious-octo-rotary-phone
   ```

4. **Install Dependencies:**

   ```bash
   npm install
   ```

5. **Configure Environment Variables:**

   Create a `.env` file in the root directory of the project and configure it with your SMTP and DKIM settings. You can use the provided `.env` file as a template:

   ```bash
   cp .env.example .env
   ```

   Edit the `.env` file to include your SMTP credentials and DKIM settings.

6. **Place Your DKIM Private Key:**

   Ensure your DKIM private key file is placed in the path specified in the `.env` file (`PRIVATE_KEY_PATH`).

### Running the Application

Start the server using the following command:

```bash
node app.js
```

### Docker Container Installation

To run the application in a Docker container, follow these steps:

1. **Install Docker:**

   If Docker is not already installed, you can install it using the following commands:

   ```bash
   sudo apt update
   sudo apt install -y docker.io
   sudo systemctl start docker
   sudo systemctl enable docker
   ```

2. **Build the Docker Image:**

   Navigate to the project directory and build the Docker image:

   ```bash
   docker build -t dkim-service .
   ```

3. **Run the Docker Container:**

   Run the container with the necessary environment variables and volume for the DKIM private key:

   ```bash
   docker run -d -p 3000:3000 --env-file .env -v /path/to/private_key.pem:/app/private_key.pem dkim-service
   ```

   Replace `/path/to/private_key.pem` with the actual path to your DKIM private key file.

4. **Verify the Container is Running:**

   You can check if the container is running using:

   ```bash
   docker ps
   ```

### Testing the Application

To test the application, you can use a tool like `curl` or Postman to send a POST request to the `/generate-dkim` endpoint.

#### Using `curl`:

```bash
curl -X POST http://localhost:3000/generate-dkim \
-H "Content-Type: application/json" \
-d '{
  "from": "sender@example.com",
  "to": "recipient@example.com",
  "subject": "Email Subject",
  "text": "Email Body"
}'
```

#### Using Postman:

1. Open Postman and create a new POST request.
2. Set the URL to `http://localhost:3000/generate-dkim`.
3. In the "Body" tab, select "raw" and choose "JSON" from the dropdown.
4. Enter the following JSON:

   ```json
   {
     "from": "sender@example.com",
     "to": "recipient@example.com",
     "subject": "Email Subject",
     "text": "Email Body"
   }
   ```

5. Send the request and check the response for success or error messages.

### Note

Ensure that the SMTP server and DKIM private key are properly configured. The application will log messages to the console for debugging purposes.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.