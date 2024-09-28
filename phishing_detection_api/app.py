from flask import Flask, request, jsonify
import joblib
import pandas as pd

app = Flask(__name__)

# Load the trained model from the .pkl file
model = joblib.load('phishing_model.pkl')

# Example: Function to extract features from URLs (placeholder, you should implement this based on your model's features)
import pandas as pd

def extract_features_from_links(links):
    features = {
        'qty_dot_url': [link.count('.') for link in links],
        'qty_hyphen_url': [link.count('-') for link in links],
        'qty_underline_url': [link.count('_') for link in links],
        'qty_slash_url': [link.count('/') for link in links],
        'qty_questionmark_url': [link.count('?') for link in links],
        'qty_equal_url': [link.count('=') for link in links],
        'qty_at_url': [link.count('@') for link in links],
        'qty_and_url': [link.count('&') for link in links],
        'qty_exclamation_url': [link.count('!') for link in links],
        'qty_space_url': [link.count(' ') for link in links],
        'qty_tilde_url': [link.count('~') for link in links],
        'qty_comma_url': [link.count(',') for link in links],
        'qty_plus_url': [link.count('+') for link in links],
        'qty_asterisk_url': [link.count('*') for link in links],
        'qty_hashtag_url': [link.count('#') for link in links],
        'qty_dollar_url': [link.count('$') for link in links],
        'qty_percent_url': [link.count('%') for link in links],
        'qty_tld_url': [sum(link.lower().count(tld) for tld in ['.com', '.net', '.org', '.edu']) for link in links],
        'length_url': [len(link) for link in links],

        # Domain-related features
        'qty_dot_domain': [link.split('/')[2].count('.') if '//' in link else 0 for link in links],
        'qty_hyphen_domain': [link.split('/')[2].count('-') if '//' in link else 0 for link in links],
        'qty_underline_domain': [link.split('/')[2].count('_') if '//' in link else 0 for link in links],
        'qty_slash_domain': [link.split('/')[2].count('/') if '//' in link else 0 for link in links],
        'qty_questionmark_domain': [link.split('/')[2].count('?') if '//' in link else 0 for link in links],
        'qty_equal_domain': [link.split('/')[2].count('=') if '//' in link else 0 for link in links],
        'qty_at_domain': [link.split('/')[2].count('@') if '//' in link else 0 for link in links],
        'qty_and_domain': [link.split('/')[2].count('&') if '//' in link else 0 for link in links],
        'qty_exclamation_domain': [link.split('/')[2].count('!') if '//' in link else 0 for link in links],
        'qty_space_domain': [link.split('/')[2].count(' ') if '//' in link else 0 for link in links],
        'qty_tilde_domain': [link.split('/')[2].count('~') if '//' in link else 0 for link in links],
        'qty_comma_domain': [link.split('/')[2].count(',') if '//' in link else 0 for link in links],
        'qty_plus_domain': [link.split('/')[2].count('+') if '//' in link else 0 for link in links],
        'qty_asterisk_domain': [link.split('/')[2].count('*') if '//' in link else 0 for link in links],
        'qty_hashtag_domain': [link.split('/')[2].count('#') if '//' in link else 0 for link in links],
        'qty_dollar_domain': [link.split('/')[2].count('$') if '//' in link else 0 for link in links],
        'qty_percent_domain': [link.split('/')[2].count('%') if '//' in link else 0 for link in links],
        'qty_vowels_domain': [sum(1 for char in link.split('/')[2] if char in 'aeiou') if '//' in link else 0 for link in links],
        'domain_length': [len(link.split('/')[2]) if '//' in link else 0 for link in links],
        'domain_in_ip': [1 if any(char.isdigit() for char in link.split('/')[2]) else 0 for link in links],
        'server_client_domain': [1 if any(server in link for server in ['client', 'server']) else 0 for link in links],

        # Directory-related features
        'qty_dot_directory': [link.count('.', link.find('/', 8)) for link in links],
        'qty_hyphen_directory': [link.count('-', link.find('/', 8)) for link in links],
        'qty_underline_directory': [link.count('_', link.find('/', 8)) for link in links],
        'qty_slash_directory': [link.count('/', link.find('/', 8)) for link in links],
        'qty_questionmark_directory': [link.count('?', link.find('/', 8)) for link in links],
        'qty_equal_directory': [link.count('=', link.find('/', 8)) for link in links],
        'qty_at_directory': [link.count('@', link.find('/', 8)) for link in links],
        'qty_and_directory': [link.count('&', link.find('/', 8)) for link in links],
        'qty_exclamation_directory': [link.count('!', link.find('/', 8)) for link in links],
        'qty_space_directory': [link.count(' ', link.find('/', 8)) for link in links],
        'qty_tilde_directory': [link.count('~', link.find('/', 8)) for link in links],
        'qty_comma_directory': [link.count(',', link.find('/', 8)) for link in links],
        'qty_plus_directory': [link.count('+', link.find('/', 8)) for link in links],
        'qty_asterisk_directory': [link.count('*', link.find('/', 8)) for link in links],
        'qty_hashtag_directory': [link.count('#', link.find('/', 8)) for link in links],
        'qty_dollar_directory': [link.count('$', link.find('/', 8)) for link in links],
        'qty_percent_directory': [link.count('%', link.find('/', 8)) for link in links],
        'directory_length': [len(link[link.find('/', 8):]) for link in links],

        # File-related features
        'qty_dot_file': [link[link.rfind('/'):].count('.') for link in links],
        'qty_hyphen_file': [link[link.rfind('/'):].count('-') for link in links],
        'qty_underline_file': [link[link.rfind('/'):].count('_') for link in links],
        'qty_slash_file': [link[link.rfind('/'):].count('/') for link in links],
        'qty_questionmark_file': [link[link.rfind('/'):].count('?') for link in links],
        'qty_equal_file': [link[link.rfind('/'):].count('=') for link in links],
        'qty_at_file': [link[link.rfind('/'):].count('@') for link in links],
        'qty_and_file': [link[link.rfind('/'):].count('&') for link in links],
        'qty_exclamation_file': [link[link.rfind('/'):].count('!') for link in links],
        'qty_space_file': [link[link.rfind('/'):].count(' ') for link in links],
        'qty_tilde_file': [link[link.rfind('/'):].count('~') for link in links],
        'qty_comma_file': [link[link.rfind('/'):].count(',') for link in links],
        'qty_plus_file': [link[link.rfind('/'):].count('+') for link in links],
        'qty_asterisk_file': [link[link.rfind('/'):].count('*') for link in links],
        'qty_hashtag_file': [link[link.rfind('/'):].count('#') for link in links],
        'qty_dollar_file': [link[link.rfind('/'):].count('$') for link in links],
        'qty_percent_file': [link[link.rfind('/'):].count('%') for link in links],
        'file_length': [len(link[link.rfind('/'):]) for link in links],

        # Parameter-related features
        'qty_dot_params': [link[link.find('?'):].count('.') if '?' in link else 0 for link in links],
        'qty_hyphen_params': [link[link.find('?'):].count('-') if '?' in link else 0 for link in links],
        'qty_underline_params': [link[link.find('?'):].count('_') if '?' in link else 0 for link in links],
        'qty_slash_params': [link[link.find('?'):].count('/') if '?' in link else 0 for link in links],
        'qty_questionmark_params': [link[link.find('?'):].count('?') if '?' in link else 0 for link in links],
        'qty_equal_params': [link[link.find('?'):].count('=') if '?' in link else 0 for link in links],
        'qty_at_params': [link[link.find('?'):].count('@') if '?' in link else 0 for link in links],
        'qty_and_params': [link[link.find('?'):].count('&') if '?' in link else 0 for link in links],
        'qty_exclamation_params': [link[link.find('?'):].count('!') if '?' in link else 0 for link in links],
        'qty_space_params': [link[link.find('?'):].count(' ') if '?' in link else 0 for link in links],
        'qty_tilde_params': [link[link.find('?'):].count('~') if '?' in link else 0 for link in links],
        'qty_comma_params': [link[link.find('?'):].count(',') if '?' in link else 0 for link in links],
        'qty_plus_params': [link[link.find('?'):].count('+') if '?' in link else 0 for link in links],
        'qty_asterisk_params': [link[link.find('?'):].count('*') if '?' in link else 0 for link in links],
        'qty_hashtag_params': [link[link.find('?'):].count('#') if '?' in link else 0 for link in links],
        'qty_dollar_params': [link[link.find('?'):].count('$') if '?' in link else 0 for link in links],
        'qty_percent_params': [link[link.find('?'):].count('%') if '?' in link else 0 for link in links],
        'params_length': [len(link[link.find('?'):]) if '?' in link else 0 for link in links],

        # Additional features
        'tld_present_params': [1 if any(tld in link for tld in ['.com', '.net', '.org', '.edu']) else 0 for link in links],
        'qty_params': [link.count('=') if '?' in link else 0 for link in links],
        'email_in_url': [1 if '@' in link else 0 for link in links],
        'time_response': [0 for link in links],  # Placeholder for time response if available
        'domain_spf': [0 for link in links],  # Placeholder for SPF-related feature if available
        'asn_ip': [0 for link in links],  # Placeholder for ASN-related feature if available
        'time_domain_activation': [0 for link in links],  # Placeholder for domain activation time
        'time_domain_expiration': [0 for link in links],  # Placeholder for domain expiration time
        'qty_ip_resolved': [0 for link in links],  # Placeholder for number of IPs resolved
        'qty_nameservers': [0 for link in links],  # Placeholder for number of nameservers
        'qty_mx_servers': [0 for link in links],  # Placeholder for number of MX servers
        'ttl_hostname': [0 for link in links],  # Placeholder for TTL hostname
        'tls_ssl_certificate': [0 for link in links],  # Placeholder for SSL/TLS certificate presence
        'qty_redirects': [0 for link in links],  # Placeholder for number of redirects
        'url_google_index': [0 for link in links],  # Placeholder for Google index status
        'domain_google_index': [0 for link in links],  # Placeholder for domain Google index status
        'url_shortened': [1 if any(shortener in link for shortener in ['bit.ly', 'goo.gl', 'tinyurl']) else 0 for link in links]
    }

    # Convert the features dictionary to a DataFrame
    features_df = pd.DataFrame(features)

    return features_df

@app.route('/analyze_links', methods=['POST'])
def analyze_links():
    # Get the list of URLs from the request
    data = request.json
    links = data['links']

    # Ensure links is a list of strings
    if not isinstance(links, list) or not all(isinstance(link, str) for link in links):
        return jsonify({'error': 'Invalid input format'}), 400

    # Extract features from the URLs
    features = extract_features_from_links(links)

    # Make sure the features DataFrame is not empty
    if features.empty:
        return jsonify({'error': 'No valid URLs for processing'}), 400

    # Use the loaded model to predict phishing status
    predictions = model.predict(features)

    # Return the predictions as a JSON response
    return jsonify(predictions.tolist())


if __name__ == '__main__':
    app.run(debug=True)
