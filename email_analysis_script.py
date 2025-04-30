import re, base64, requests, json, joblib, pytz, ipaddress
from datetime import datetime
from email import policy
from email.parser import BytesParser


# Load the trained model and the fitted CountVectorizer for Naive Bayes as pickle files
model = joblib.load('naive_bayes_model-1.pkl')
count_vectorizer = joblib.load('count_vectorizer-1.pkl')

# Open json that contains API key for virustotal and assign API key
with open('config.json', 'r') as f:
    config = json.load(f)

api_key = config.get("VT_API_KEY")


def input_email():

    # Print spider
    def print_ascii_art():
        ascii_art = r'''
                  ||  ||  
                  \\\()// 
                 //(__)\\\\
                 ||    ||
       '''
        print(ascii_art)
        print("_________WELCOME TO EMAIL ANALYZER__________")
        print("\n" * 2)


    print_ascii_art()
    #Prompt user for raw email input
    print("Please paste the raw email content below: \n")

    email_raw_multi_line = ""
    while True:

        # read each line of input
        line = input()
        #exit when user presses enter twice
        if line.strip() == "" and email_raw_multi_line.endswith("\n\n"):
            break
        #build a multi-line string
        email_raw_multi_line += line + "\n"

    # Save the raw email content to a file, this is for the email body extraction
    with open('raw_email_2.txt', 'w') as file:
        file.write(email_raw_multi_line)

    # return the raw email that the user pasted
    email_raw = email_raw_multi_line
    return email_raw


def email_encoding(email_raw):

    #regex to capture base 64 encoding used in email
    encoding_pattern = r"Content-Transfer-Encoding:\s*base64"
    encoding_match = re.search(encoding_pattern, email_raw, re.MULTILINE)

    # regex to capture base64 encoded portion of the email
    base64_pattern = r"Content-Transfer-Encoding:\s*base64\s*((?:[A-Za-z0-9+/=]+\s*)+)"
    base_64_match = re.search(base64_pattern, email_raw, re.MULTILINE)


    #print(f"The string that you submitted is: {email_raw}")
    print("\n" * 2)
    print("Step 1. - ENCODING ANALYSIS")
    print("")
    print("Looking for encoding match... ")
    # Decode base 64 content in the email
    if encoding_match:
        print(f"Encoding type: {encoding_match.group(0)}")
        print(f"base 64 string is: {base_64_match}")
        base_64_characters = len(base_64_match.group(1))
        print(f"base 64 character count is:{base_64_characters}")
        if base_64_characters > 20:
            # Remove new lines from base 64 content
            base_64_string = base_64_match.group(1).replace("\n", "")
            print(f"Base64 encoded text (decoded): {base_64_string}")
            # Decode the base64 string
            decoded_base_64 = base64.b64decode(base_64_string)
            try:
                # Try to decode the UTF-8 text
                decoded_string = decoded_base_64.decode('utf-8')
                print(f"decoded string is {decoded_string}")
                print("\n" * 3)
                return(decoded_string)
            except UnicodeDecodeError:
                print("Decoded content is not valid UTF-8 text, it might be binary or encoded differently.")
                print("\n" * 3)
        else:
            print("No base64 content found.")
            print("\n" * 3)
    else:
        print("No encoding match found")
        print("\n" * 3)


def header_analysis(email_raw, decoded_string):

    Risk_Score = 0

    # Extract Date Sent using regex
    date_sent_pattern = r"Date:\s(\w{3}\S\s\d{2}\s\S{3}\s\d{4}\s\d{2}\:\d{2}\:\d{2}\s\S\d*)"
    date_sent = re.search(date_sent_pattern, email_raw, re.MULTILINE)

    print("\n" * 2)
    print("SEND DATE ANALYSIS")

    # Current time in UTC
    now = datetime.now(pytz.utc)

    if date_sent:
        # Extract and print the date sent (assuming it's in the format: "Sun, 16 Feb 2025 21:18:48 -0500")
        date_sent = date_sent.group(1)
        print(f"The date the email was sent is: {date_sent}")

        # Parse the date_sent string into a datetime object, including timezone offset
        try:
            # Strptime to make date sent into a datetime object
            date_sent_normalized = datetime.strptime(date_sent, "%a, %d %b %Y %H:%M:%S %z")

            if date_sent_normalized:

                # Convert to UTC
                date_sent_normalized = date_sent_normalized.astimezone(pytz.utc)

                print(f"The date the email was sent is: {date_sent_normalized} - UTC")

                # Now both date_sent_normalized and now are in UTC timezone and can be compared
                print(f"Current Time is: {now} - UTC")

                # check that email wasn't sent in the future
                if date_sent_normalized > now:
                    print("Email Sent in the Future, FAIL")
                    Risk_Score += 100
                else:
                    print("Email not sent in the Future, PASS")
            else:
                print("Unable to process date_sent.")

        except ValueError:
            print("Date sent format is incorrect.")
            # Handle the error case if date format doesn't match
            date_sent_normalized = None
    else:
        print("No date sent found")

    print("\n" * 3)



    # Extract email sender
    email_sender_pattern = r"^From\:.*@(?:[a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})>"
    email_sender_domain = re.search(email_sender_pattern, email_raw, re.MULTILINE)


    print("")
    print("EMAIL SENDER COMPARATIVE ANALYSIS")
    # Extract email sender
    if email_sender_domain:
        email_sender_domain = email_sender_domain.group(1)
        print(f"The email sender domain is: {email_sender_domain}")
    else:
        print("No email sender domain found")

    # Extract message ID sender
    message_id_sender_pattern = r"Message\SID.*@(?:[a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})"
    message_id_sender_domain = re.search(message_id_sender_pattern, email_raw, re.MULTILINE)

    if message_id_sender_domain and email_sender_domain:

        if message_id_sender_domain:
            message_id_sender_domain = message_id_sender_domain.group(1)
            print(f"The message ID domain is: {message_id_sender_domain}")
        else:
            print("No message ID sender domain found")

        # Compare email sender domain to the message ID domain
        if email_sender_domain != message_id_sender_domain:
            print("Sender Domain and Message ID Domain Mismatch, FAIL")
            Risk_Score += 75
        else:
            print("Sender domain matches Message ID domain, PASS")
        print("\n" * 3)

    print("HEADER SECURITY CHECKS, DMARC, DKIM & RECEIVED SPF")
    # Extract and analyze DMARC Values
    DMARC_pattern = r"dmarc=([a-z]*|[A-Z]*)"
    DMARC = re.search(DMARC_pattern, email_raw, re.MULTILINE)

    if DMARC:

        # Make a list of DMARC values
        DMARC_list = []

        DMARC = DMARC.group(1)
        DMARC_list.append(DMARC)

        # Check to make sure DMARC values are "pass"
        for w in DMARC_list:
            w.lower()
            if w != "pass":
                print(f"DMARC Failure, value is {DMARC}")
                Risk_Score += 100
            else:
                print("DMARC PASS")
    else:
        print("No DMARC was found")


    # Extract and analyze DKIM Values
    DKIM_pattern = r"dkim=([a-z]*|[A-Z]*)"
    DKIM = re.search(DKIM_pattern, email_raw, re.MULTILINE)

    if DKIM:

        # Make a list of DKIM values
        DKIM_list = []

        DKIM = DKIM.group(1)
        DKIM_list.append(DKIM)

        for w in DKIM_list:
            # check to make sure DKIM values are "pass"
            w.lower()
            if w != "pass":
                print(f"DKIM Failure, value is {DKIM}")
                Risk_Score += 100
            else:
                print("DKIM PASS")
    else:
        print("No DKIM was found")


    # Extract and analyze Received SPF Values
    recieved_SPF_pattern = r"spf=([a-z]*|[A-Z]*)"
    recieved_SPF = re.search(recieved_SPF_pattern, email_raw, re.MULTILINE)

    if recieved_SPF:

        # Make a list of received SPF values
        recieved_SPF_list = []

        recieved_SPF = recieved_SPF.group(1)
        recieved_SPF_list.append(recieved_SPF)

        # Check to make sure all received SPF values are "pass"
        for s in recieved_SPF_list:
            s.lower()
            if s != "pass":
                print(f"Recieved SPF Failure, value is {recieved_SPF}")
                Risk_Score += 100
            else:
                print("Recieved SPF PASS")
    else:
        print("No Recieved SPF was found")

    print("\n" * 3)

    print("RETURN AND SENDER ANALYSIS")

    # Extract and analyze X received address
    x_received_pattern = r"X\SSender\SIP\S\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    x_received_address = re.search(x_received_pattern, email_raw, re.MULTILINE)

    # Extract X received address
    if x_received_address:
        x_received_address = x_received_address.group(1)
        print(f"The X received IP address is: {x_received_address}")
    else:
        print("No X received address found")

    # Extract Return address
    return_address_pattern = r"return|Return.*<(.*)>"
    return_address = re.search(return_address_pattern, email_raw, re.MULTILINE)

    if return_address:
        return_address = return_address.group(1)
        print(f"The return address is: {return_address}")

    else:
        print("No return address found")



    # Extract From address
    sender_address_pattern = r"From.*<(.*)>"
    sender_address = re.search(sender_address_pattern, email_raw, re.MULTILINE)

    if sender_address:
        sender_address = sender_address.group(1)
        print(f"The sender address is: {sender_address}")

    else:
        print("No sender address found")


    # Check to see if the return address exists
    if return_address is None:
        print("No Return Address, FAIL")
        Risk_Score += 20
    else:
        print("Return Address exists, PASS")

    # Check to see if X received address exists
    if x_received_address is None:
        print("No X Received Address, FAIL")
        Risk_Score += 20
    else:
        print("X Received Address exists, PASS")



    # Check to see that sender address matches the return address
    if sender_address and return_address:
        if sender_address != return_address:
            print("Sender Address and Return Address mismatch, FAIL (this isn't critical)")
            Risk_Score += 30
        else:
            print("Sender Address and Return Address match, PASS")




    print("\n" * 3)
    return(Risk_Score)


def domain_analysis(email_raw, decoded_string):

    # Extract Email Domains
    email_domain_pattern = r"@([a-zA-Z0-9.-]+)"

    domain_match_list_raw = []
    domain_match_list_raw_deduplicated = []

    # Append any email domains found to a list of email domains
    while True:
        domain_email_raw = re.search(email_domain_pattern, email_raw, re.MULTILINE)
        if domain_email_raw:
            domain_match_list_raw.append(domain_email_raw.group(1))
            email_raw = email_raw[domain_email_raw.end():]
        else:
            break

    # Append any emails found in the decoded base 64 portion of the email to a list of email domains
    if decoded_string:
        domain_match_list_decoded_string = []
        domain_match_list_decoded_string_deduplicated = []
        while True:
            domain_decoded_string = re.search(email_domain_pattern, decoded_string, re.MULTILINE)
            if domain_decoded_string:
                domain_match_list_decoded_string.append(domain_decoded_string.group(1))
                decoded_string = decoded_string[domain_decoded_string.end():]
            else:
                break

        # Deduplicate list of matches from base 64 portion of email
        for i in domain_match_list_decoded_string:
            if i not in domain_match_list_decoded_string_deduplicated:
                domain_match_list_decoded_string_deduplicated.append(i)

        # Deduplicate list of matches from raw email
        for l in domain_match_list_decoded_string_deduplicated:
            if l not in domain_match_list_raw_deduplicated:
                domain_match_list_raw_deduplicated.append(l)

    # Combine both lists of domains
    for z in domain_match_list_raw:
        if z not in domain_match_list_raw_deduplicated:
            domain_match_list_raw_deduplicated.append(z)

    #print(f"Domain Match list: {domain_match_list_raw_deduplicated}")
    return domain_match_list_raw_deduplicated


def ip_analysis(email_raw, decoded_string):

    # Regex to extract IP addresses
    IP_pattern = r"[^\d|\.]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[^\d|\.]"

    ip_match_list_raw = []
    ip_match_list_raw_deduplicated = []
    while True:
        # Find IP addresses in raw unencoded email and append them to a list
        IP_email_raw = re.search(IP_pattern, email_raw, re.MULTILINE)
        if IP_email_raw:
            ip_match_list_raw.append(IP_email_raw.group(1))
            email_raw = email_raw[IP_email_raw.end():]
        else:
            break


    #print(f"The following IPs have been found: {ip_match_list_raw}")

    # If a decoded base 64 string exists, make lists for IPs to be added
    if decoded_string:
        ip_match_list_decoded_string = []
        ip_match_list_decoded_string_deduplicated = []
        while True:
            # Find IP addresses in decoded base 64 string and append them to a list
            IP_decoded_string = re.search(IP_pattern, decoded_string, re.MULTILINE)
            if IP_decoded_string:
                ip_match_list_decoded_string.append(IP_decoded_string.group(1))
                decoded_string = decoded_string[IP_decoded_string.end():]
            else:
                break

        # Deduplicate decoded base 64 IP list
        for i in ip_match_list_decoded_string:
            if i not in ip_match_list_decoded_string_deduplicated:
                ip_match_list_decoded_string_deduplicated.append(i)

        # Deduplicate unencoded IP list
        for l in ip_match_list_decoded_string_deduplicated:
            if l not in ip_match_list_raw_deduplicated:
                ip_match_list_raw_deduplicated.append(l)

    # Combine both the raw email IP list and the decoded base 64 IP list
    for z in ip_match_list_raw:
        if z not in ip_match_list_raw_deduplicated:
            ip_match_list_raw_deduplicated.append(z)


    # Removes internal IPs from IP list, to save on API calls to virustotal
    def remove_internal_ips(ip_match_list_raw_deduplicated):

        # Define Private IP ranges
        private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8')  # Localhost
        ]

        # Create a list of external only IPs, filtering out private IPs
        ip_match_list_raw_deduplicated = [ip for ip in ip_match_list_raw_deduplicated if not any(ipaddress.ip_address(ip) in network for network in private_networks)]

        return(ip_match_list_raw_deduplicated)

    ip_match_list_raw_deduplicated = remove_internal_ips(ip_match_list_raw_deduplicated)

    return ip_match_list_raw_deduplicated


def vt_api_ip(email_raw, decoded_string):

    Risk_Score = 0

    IPs_from_raw = ip_analysis(email_raw, decoded_string)
    #print(IPs_from_raw)
    if IPs_from_raw:
        for p in IPs_from_raw:
            ip_address = p
            #print(f"IPPP ADDREESSSS FFFRRROMMM RAWWWW: {ip_address}")

            #create URL for each IP in the list of found IPs
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

            # Set the headers, including the API key for authorization
            headers = {
                "accept": "application/json",
                "x-apikey": api_key  # Include the API key here
            }

            # Send the GET request to VirusTotal API
            response = requests.get(url, headers=headers)

            # Check the response status and print the result
            if response.status_code == 200:
                # The API returned a successful response
                data = response.json()
                #return(data)
                # Convert the string into a Python dictionary

                # Extract last_analysis_stats, for most recent analysis info from VT
                last_analysis_stats = data["data"]["attributes"]["last_analysis_stats"]

                ip_malicious = last_analysis_stats["malicious"]
                ip_suspicious = last_analysis_stats["suspicious"]
                ip_harmless = last_analysis_stats["harmless"]

                # Print the extracted values
                # print(f"Last Analysis Stats: {last_analysis_stats}")
                # print("Last Analysis Stats:")
                if (last_analysis_stats["malicious"] > last_analysis_stats["harmless"]) or (last_analysis_stats["suspicious"] > last_analysis_stats["harmless"]):
                    # print(f"IP analysis found the IP address {ip_address} to be Malicious")
                    print(f"Suspicious IP Address detected: {ip_address}")
                    print(f"Virustotal report indicates: {ip_harmless} reporters found the IP Address to be harmless")
                    print(f"Virustotal report indicates: {ip_suspicious} reporters found the IP Address to be suspicious")
                    print(f"Virustotal report indicates: {ip_malicious} reporters found the IP Address to be malicious")
                    Risk_Score += 100
                    print("\n" * 3)
                else:
                    print(f"IP Passed analysis: {ip_address}")
                    print(f"Virustotal report indicates: {ip_harmless} reporters found the IP Address to be harmless")
                    print(f"Virustotal report indicates: {ip_suspicious} reporters found the IP Address to be suspicious")
                    print(f"Virustotal report indicates: {ip_malicious} reporters found the IP Address to be malicious")
                    Risk_Score += 0
                    print("\n" * 3)
            else:
                response = "Failure on VirusTotal IP API Call"
                print(f"{response}")

    return(Risk_Score)


def url_extraction(email_raw, decoded_string):

    # Create lists for URLs
    url_match_list_raw = []
    url_match_list_decoded_string = []

    # Regex to extract URLs (Only works on http, https, www, and bit.ly)
    url_pattern = r"(https://|www.|http://)[a-zA-Z0-9-\.\/?=]*|bit.ly\/*[a-zA-Z0-9-\.\/?=]*"

    # Adds found URL in unencoded string to a list of URLs
    for match in re.finditer(url_pattern, email_raw):
        url_match_list_raw.append(match.group(0))

    if decoded_string:
        # Adds found URL in decoded string to a list of URLs
        for match in re.finditer(url_pattern, decoded_string):
            url_match_list_decoded_string.append(match.group(0))

    # Deduplicates lists of URLs, this time using "set()"
    url_match_list_raw_deduplicated = list(set(url_match_list_raw))
    url_match_list_decoded_string_deduplicated = list(set(url_match_list_decoded_string))

    # Creates finalized deduplicated list of URLs, from both decoded and unencoded
    combined_list = list(set(url_match_list_raw_deduplicated + url_match_list_decoded_string_deduplicated))


    return combined_list



def vt_api_url(email_raw, decoded_string):

    Risk_Score = 0

    # Gets list of URLs from url_extraction function
    URL_match_list_raw_deduplicated = url_extraction(email_raw, decoded_string)


    if URL_match_list_raw_deduplicated:
        for l in URL_match_list_raw_deduplicated:
            url = l

            # print(url)

            # Encode URL in base 64 and strip "=" padding for use with VT API
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

            headers = {
                "accept": "application/json",
                "x-apikey": api_key  # Include your API key here
            }

            # Send the GET request to the API
            response = requests.get(url, headers=headers)

            if response.status_code == 200:

                response = response.json()

                # Extract the last_analysis_stats
                stats = response["data"]["attributes"]["last_analysis_stats"]

                # Print the response from VirusTotal
                malicous_url = stats['malicious']
                suspicious_url = stats['suspicious']
                harmless_url = stats['harmless']

                # Determine if URL in the email was malicious or suspicious.
                if (stats["malicious"] > stats["harmless"]) or (stats["suspicious"] > stats["harmless"]):
                    print(f"Suspicious URL detected: {url}")
                    Risk_Score += 100
                else:
                    print(f"URL analysis found the link {l} to be Harmless")
                    print(f"Virustotal report indicates: {harmless_url} reporters found the email to be harmless")
                    print(f"Virustotal report indicates: {suspicious_url} reporters found the email to be suspicious")
                    print(f"Virustotal report indicates: {malicous_url} reporters found the email to be malicious")
                    print("\n" * 3)
                    Risk_Score += 0

            #else:
                #response = "Failure on VirusTotal URL API"
                #print(response)
                #print("\n" * 3)
    else:
        print("No Links found in email to be analyzed")
        print("\n" * 3)

    return(Risk_Score)


def vt_api_domain(email_raw, decoded_string):

    Risk_Score = 0

    # use domain_analysis() function to get domains from raw
    domains_from_raw = domain_analysis(email_raw, decoded_string)
    #print(IPs_from_raw)
    if domains_from_raw:
        for p in domains_from_raw:
            domain = p
            # Create URL for VT API with domain
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"

            # Set the headers, including the API key for authorization
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            # Send the GET request to VirusTotal API
            response = requests.get(url, headers=headers)
            # response = response.text

            if response.status_code == 200:

                response = response.json()
                last_analysis_stats = response["data"]["attributes"]["last_analysis_stats"]

                # get creation date from API reponse for domain, make it into a datetime object
                if "creation_date" in response["data"]["attributes"]:
                    creation_date = response["data"]["attributes"]["creation_date"]
                    creation_datetime_object = datetime.fromtimestamp(creation_date)
                    human_readable_time_creation = creation_datetime_object.strftime("%Y-%m-%d %H:%M:%S")

                else:
                    # error handling for datetime comparison if it doesn't exist
                    creation_date = 0
                    creation_datetime_object = datetime.fromtimestamp(creation_date)
                    human_readable_time_creation = creation_datetime_object.strftime("%Y-%m-%d %H:%M:%S")


                # create now time
                now = datetime.now()
                now = int(now.timestamp())



                malicous_domain = last_analysis_stats["malicious"]
                harmless_domain = last_analysis_stats["harmless"]
                suspicious_domain = last_analysis_stats["suspicious"]

    # Check if the domain is malicious or suspicious or if the domain has been created in the last 30 days.

                if (last_analysis_stats["malicious"] > last_analysis_stats["harmless"]) or (
                        last_analysis_stats["suspicious"] > last_analysis_stats["harmless"]) and (((now - creation_date) > 2592000)):
                    print(f"Domain analysis found the domain {domain} to be Malicious")
                    print(f"Virustotal report indicates: {harmless_domain} reporters found the domain to be harmless")
                    print(f"Virustotal report indicates: {suspicious_domain} reporters found the domain to be suspicious")
                    print(f"Virustotal report indicates: {malicous_domain} reporters found the domain to be malicious")
                    print("domain not created within the last 30 days")
                    print(f"Creation time: {human_readable_time_creation}")
                    print("\n" * 3)
                    Risk_Score += 100

                elif (last_analysis_stats["malicious"] > last_analysis_stats["harmless"]) or (
                        last_analysis_stats["suspicious"] > last_analysis_stats["harmless"]) and (((now - creation_date) < 2592000)):
                    print(f"Domain analysis found the domain {domain} to be Malicious")
                    print(f"Virustotal report indicates: {harmless_domain} reporters found the domain to be harmless")
                    print(f"Virustotal report indicates: {suspicious_domain} reporters found the domain to be suspicious")
                    print(f"Virustotal report indicates: {malicous_domain} reporters found the domain to be malicious")
                    print("Domain created within the last 30 days (suspicious)")
                    print(f"Creation time: {human_readable_time_creation}")
                    print("\n" * 3)
                    Risk_Score += 100

                elif (last_analysis_stats["malicious"] > last_analysis_stats["harmless"]) or (
                        last_analysis_stats["suspicious"] > last_analysis_stats["harmless"]) and (((now - creation_date) < 2592000)):
                    print(f"Domain analysis found the domain {domain} to be Suspicious, the domain has been created within the last 30 days")
                    print(f"Creation time: {human_readable_time_creation}")
                    print(f"Virustotal report indicates: {harmless_domain} reporters found the domain to be harmless")
                    print(f"Virustotal report indicates: {suspicious_domain} reporters found the domain to be suspicious")
                    print(f"Virustotal report indicates: {malicous_domain} reporters found the domain to be malicious")
                    print("\n" * 3)
                    Risk_Score += 100

                else:
                    print(f"Domain analysis found the domain {domain} to be Harmless")
                    print(f"Virustotal report indicates: {harmless_domain} reporters found the domain to be harmless")
                    print(f"Virustotal report indicates: {suspicious_domain} reporters found the domain to be suspicious")
                    print(f"Virustotal report indicates: {malicous_domain} reporters found the domain to be malicious")
                    print("domain not created within the last 30 days")
                    print(f"Creation time: {human_readable_time_creation}")
                    print("\n" * 3)
            else:
                # Error handling
                response = "Virustotal API failure on Domain"
                print(f"{response}")
                print("\n" * 3)

    return(Risk_Score)

def parse_email_body(raw_email: bytes):

    # Parse the raw email message
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    # Extract the email subject, sender, and recipient
    subject = msg['subject']
    sender = msg['from']
    recipient = msg['to']

    # Get the email body (either plain text or HTML)
    body = None

    if msg.is_multipart():
        # print("This is a multipart message.")

        # Iterate over each part of the email raw
        for i, part in enumerate(msg.iter_parts()):
            #print(f"\nPart {i + 1}:")
            #print(f"Content-Type: {part.get_content_type()}")
            #print(f"Charset: {part.get_content_charset()}")
            #print(f"Is Multipart: {part.is_multipart()}")
            #print(f"Payload (raw): {part.get_payload()}")

            # Check if the part is plaintext or html, if its html, make it regular text
            content_type = part.get_content_type()
            # Plaintext check
            if content_type == 'text/plain':
                charset = part.get_content_charset() or 'utf-8'
                try:
                    body = part.get_payload(decode=True).decode(charset, errors='ignore')
                    #print("Plain text body found.")
                    break
                # error handling
                except Exception as e:
                    print(f"Error decoding text/plain part: {e}")
            # HTML Check
            elif content_type == 'text/html':
                charset = part.get_content_charset() or 'utf-8'
                try:
                    body = part.get_payload(decode=True).decode(charset, errors='ignore')
                    print("HTML body found.")
                    break
                except Exception as e:
                    print(f"Error decoding text/html part: {e}")
    else:
        # If the message is not multipart, just decode the payload
        charset = msg.get_content_charset() or 'utf-8'
        try:
            body = msg.get_payload(decode=True).decode(charset, errors='ignore')
            #print("Non-multipart body found:")
            # print(body)
        except Exception as e:
            print(f"Error decoding non-multipart body: {e}")

    return subject, sender, recipient, body

def naive_bayes():

    Risk_Score = 0

    # Read the raw email content from the saved file
    with open('raw_email_2.txt', 'r') as file:
        email_raw_multi_line = file.read()

    # Convert the string into bytes using UTF-8 encoding
    raw_email = email_raw_multi_line.encode('utf-8')

    # Call the function to parse the email body for naive bayes analysis
    subject, sender, recipient, body = parse_email_body(raw_email)

    if body:
        print(f"\nEmail body length: {len(body)} characters")

    # Make the body into a list so it can be processed by vectorizer
    body = [body]

    # Append "the" to the body, so that the body list is never empty
    body.append("the")

    # Remove any instances of python object None
    body = [item for item in body if item is not None]


    if body:

       # Create matrix of words in the email, mapped to columns in training data with counts of word frequency in the email
        email_features = count_vectorizer.transform(body)

        # Use the pre-trained model to make a prediction on the email features/ body text
        prediction = model.predict(email_features)

        # Output the prediction results
        if prediction[0] == 1:
            print("The body text of this email is indicative of Spam.")
            Risk_Score += 75
            return(Risk_Score)
        else:
            print("The body text of this email is not indicative of Spam.")
            Risk_Score += 0
            return(Risk_Score)
    elif body is None:
        "No Email Body to run spam check"
        return(Risk_Score)
    else:
        "No Email Body to run spam check"
        return (Risk_Score)





def Main():

    Risk_Score = 0

    email_raw = input_email()

    decoded_string = email_encoding(email_raw)

    Risk_Score += (header_analysis(email_raw, decoded_string))

    Risk_Score += (vt_api_domain(email_raw, decoded_string))

    Risk_Score += (vt_api_ip(email_raw, decoded_string))

    url_extraction(email_raw, decoded_string)

    Risk_Score += (vt_api_url(email_raw, decoded_string))

    Risk_Score += (naive_bayes())

    # Print final risk score analysis
    print("\n" * 3)
    print("FINAL EMAIL ANALYSIS:")
    if Risk_Score >= 100:
        print(f"Email analysis determined that this email is likely Spam or Phishing, the overall risk score is: {Risk_Score}")
        print("A risk score >= 100 is considered a Failure, and is indicative of a potentially suspicious or malicious email")
    else:
        print(f"Email analysis determined that this email is not likely spam or phishing, the overall risk score is: {Risk_Score}")
        print("A risk score >= 100 is considered a Failure, and is indicative of a potentially suspicious or malicious email")
    print("\n" * 3)

Main()
