# Squirrels-Email-Tool

> [!NOTE]
> This tool is in progress. I will be adding additional features in the future

## Overview
The script runs through a series of checks on the raw email, including a header analysis, domain analysis, IP analysis, URL analysis, and a spam word check. All of these are pass/fail checks. When a check is failed, points are added to the overall risk score. Not all failed checks are equal, point weight is determined by overall risk. After the analysis is completed the risk score is summed. A risk score greater than 100 is considered indicitive of a potentially suspicious/malicious/spam email.

A word on Naive Bayes:                                                                       
Naive Bayes for email spam checking uses Bayes Theorem to classify emails as spam or not based on the likelihood of certain words appearing in each category. It calculates the probability that an email belongs to the spam or non-spam class by analyzing the frequency of words in labeled training emails. By applying the "naive" assumption that words are independent, it predicts whether new emails are spam based on the words they contain and their probabilities from the training set.

More information on Naive Bayes for Email Spam:
[Naive Bayes Spam Filtering](https://en.wikipedia.org/wiki/Naive_Bayes_classifier#Spam_filtering)

## Analysis Methodology

### Header Analysis
The following checks are done in the email headers:
| Points | Check |
|--------|-------|
| 100    | **Date Sent:** Verifies the email was not sent in the future. |
| 100    | **DMARC:** Confirms this email authentication protocol returns a “PASS” value. |
| 100    | **DKIM:** Confirms this email authentication protocol returns a “PASS” value. |
| 100    | **Received SPF:** Confirms this email authentication protocol returns a “PASS” value. |
| 020    | **X Received Address:** Ensures the presence of an X-Received address. |
| 020    | **Return Address:** Ensures the presence of a return address. |
| 030    | **Sender Address and Return Address Match:** Confirms that the Sender Address and Return Address are matching. |
| 075    | **Sender Domain and Message ID Domain Match:** Confirms that the Sender Domain and Message ID Domain are matching. |

### Domain Analysis
| Points | Check |
|--------|-------|
| 100    | Sends the email’s domain to VirusTotal for analysis. If a domain has a greater number of suspicious or malicious findings than harmless findings, it is considered a failure. |
| 100    | Checks to confirm that the email domain wasn't created in the past 30 days. An email domain created in the last 30 days is suspicious. |

### IP Analysis
| Points | Check |
|--------|-------|
| 100    | Sends all external IP addresses associated with the email to VirusTotal for analysis. If an IP has a greater number of suspicious or malicious findings than harmless findings, it is considered a failure. |

### URL/Link Analysis
| Points | Check |
|--------|-------|
| 100    | Sends all URLs contained in the email to VirusTotal for analysis. If a URL has a greater number of suspicious or malicious findings than harmless findings, it is considered a failure. |

### Naive Bayes Body Analysis
| Points | Check |
|--------|-------|
| 075    | Runs a spam check on the body of the email using the Naive Bayes classifier. This is a pass/fail check indicating whether the words in the email body are indicative of spam. |

## Usage
The tool is designed to be used with the raw text of an email copied and pasted into an IDE or console. It requires a VirusTotal API key for usage, which can be stored as a configuration file in JSON format.

```
$ pip install -r requirements.txt
$ python3 email_analysis_script.py
```

### Step 1. Copy the Raw Email
Copy the raw email from any email client, ensuring the headers are included.

Example:
![Copy Raw Email](https://github.com/Thoimrn/Squirrels-Email-Tool/blob/main/images/421591842-8b57ee7c-56e0-4b13-a339-75dcd53ce3d8.png)

### Step 2. Paste the Raw Email and Run the Script
Run the script, and paste the raw email when prompted.

Example:
![Run Script](https://github.com/Thoimrn/Squirrels-Email-Tool/blob/main/images/421112897-864a2db1-2808-4c93-83c9-bc4e918a1a9c.png)

### Step 3. Observe Output
Press enter after pasting the raw email. The output should look something like this:

Example of a benign email:
![Output Benign Email](https://github.com/Thoimrn/Squirrels-Email-Tool/blob/main/images/421114467-0b776214-e101-46d4-9d55-88a00bcfa273.png)

Example of a known malicious email:
![Output Malicious Email](https://github.com/Thoimrn/Squirrels-Email-Tool/blob/main/images/421114522-eb9a1333-28b6-47f0-8177-38df86324d94.png)

## Contribution
To contribute to this project, please fork the repository and create a pull request with your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
