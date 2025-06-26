# Telegram Anti-Phishing Bot

>Disclaimer: I got lazy and used Gemini to generate the README based on the code

A sophisticated, high-performance Telegram bot that scans URLs and domains found in messages to protect users from malicious links.

It provides a clear, standardized response format by assessing links against multiple threat intelligence sources, including **Google Threat Intelligence (Google Threat Intelligence verdicts + Vendor Scores)** and **Google Web Risk**. The bot is designed to handle multiple requests efficiently and can be extended with additional security checkers in the future.

## Key Features

-   **Multi-Source Analysis:** Integrates VirusTotal (using both classic vendor scores and Google Threat Intelligence verdicts) and Google Web Risk for a comprehensive risk assessment.
-   **Intelligent Conditional Polling:** Performs a long, deep scan on new, unknown URLs *only if* initial results from other sources are clean. This provides thoroughness without unnecessary waiting.
-   **Customizable Polling Schedule:** Uses a non-linear backoff schedule for deep scans (`60s`, `+45s`, `+30s`...) to efficiently wait for long-running analyses.
-   **Safe, Un-clickable Links:** Automatically "defangs" all URLs and domains in its responses (e.g., `example[.]com` and `http[:]//`) to prevent accidental clicks on potentially malicious links.
-   **Concurrent & Asynchronous:** Processes multiple links from a single message at the same time for incredibly fast response times.
-   **Efficient & Stable:** Manages network resources with an intelligent session manager that closes connections during idle periods. Handles large numbers of links by processing them in manageable chunks.

## Setup

Regardless of how you choose to run the bot, you will need to complete these initial setup steps.

### 1. Get Prerequisites

You will need three secret keys to run the bot.
-   **Telegram Bot Token:** Create a bot on Telegram by talking to the [BotFather](https://t.me/botfather).
-   **VirusTotal/Google Threat Intelligence API Key:** Get a API key from your [VirusTotal Account Settings](https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey).
-   **Google Web Risk API Key:** Set up a project in the [Google Cloud Console](https://cloud.google.com/web-risk/docs/setting-up) and get an API key.

### 2. Get the Code

Clone the project repository to your local machine or server.
```bash
git clone [https://github.com/repulsivityy/telegram_url_checker.git](https://github.com/repulsivityy/telegram_url_checker.git)
cd telegram_url_checker
```

## How to Run

You can run the bot in two ways. Using Docker is the recommended method as it's simpler and more portable.

---

### Option 1: Running Directly with Python

This method is suitable for local testing and development.

#### a. Install Dependencies
Create a file named `requirements.txt` with the following content:

```txt
# requirements.txt
python-telegram-bot
aiohttp
```
Then, install the packages:
```bash
pip install -r requirements.txt
```

#### b. Set Environment Variables
The bot reads your secret keys from environment variables.

**On Linux or macOS:**
```bash
export TELEGRAM_TOKEN="YOUR_TELEGRAM_TOKEN"
export VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
export WEBRISK_API_KEY="YOUR_WEBRISK_API_KEY"
```

**On Windows (Command Prompt):**
```bash
set TELEGRAM_TOKEN="YOUR_TELEGRAM_TOKEN"
set VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
set WEBRISK_API_KEY="YOUR_WEBRISK_API_KEY"
```

#### c. Run the Bot
Execute the script (assuming it's named `telegram_phishing_bot.py`):
```bash
python telegram_phishing_bot.py
```

---

### Option 2: Running with Docker (Recommended)

This is the best way to run the bot in production. It creates a self-contained, portable environment.

#### a. Create the Necessary Files
Ensure you have the `telegram_phishing_bot.py` script and the `requirements.txt` file from the previous option. Then, create the following three new files:

**`Dockerfile`** (The blueprint for the image)
```dockerfile
# Use an official lightweight Python image as a base
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies first to leverage caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your bot's source code into the container
COPY . .

# Define the command to run your bot when the container starts
CMD ["python", "telegram_phishing_bot.py"]
```

**`.dockerignore`** (Prevents copying unnecessary files)
```
__pycache__/
*.pyc
.env
.git
.gitignore
venv/
*.venv/
```

**`docker-compose.yml`** (The easiest way to run the container)
```yaml
version: '3.8'

services:
  telegram-bot:
    build: .
    container_name: phishing-bot
    env_file:
      - .env
    restart: unless-stopped
```

#### b. Create the `.env` File for Secrets
Create a file named `.env` in your project directory. This file will hold your secret keys. **Do not commit this file to Git.**

```
# .env file
# Environment variables for the Telegram bot
TELEGRAM_TOKEN="YOUR_TELEGRAM_TOKEN"
VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
WEBRISK_API_KEY="YOUR_WEBRISK_API_KEY"
```
Replace the placeholder values with your actual keys.

#### c. Build and Run the Container
With all the files in place, open a terminal in your project directory and run:
```bash
docker-compose up --build -d
```
Your bot is now running in the background inside a Docker container.

#### d. Managing the Container
-   **View logs:** `docker-compose logs -f`
-   **Stop the bot:** `docker-compose down`

## How to Use the Bot

Simply send any message containing one or more URLs or domains to your bot in Telegram. It will reply with a security analysis for each item found.

-   `/help`: Explains the bot's capabilities.

## How the Risk Logic Works

The bot uses a "safety-first" model to classify links:

1.  **Known Bad (DANGER):** A link is immediately flagged as `DANGER` if any of the following conditions are met:
    -   Its Google TI verdict is `MALICIOUS`.
    -   Its Google TI score is > 60.
    -   Its Google Web Risk confidence is `HIGH` or `EXTREMELY_HIGH`.
    -   Its VirusTotal vendor count meets the `MALICIOUS_THRESHOLD`.

2.  **Known Good (SAFE):** If not dangerous, a link is only flagged as `SAFE` if:
    -   Its Google TI verdict is `SAFE`.
    -   **OR** its classic VirusTotal score is 0 **AND** Google Web Risk finds nothing.

3.  **Everything Else (WARNING):** Any link that is not definitively dangerous or definitively safe is flagged as `WARNING` to encourage user caution.