browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.links) {
      // Call your Python API/Backend to analyze the links
      fetch('http://localhost:5000/analyze_links', { // Assuming a Flask backend
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ links: message.links })
      })
      .then(response => response.json())
      .then(data => {
        // Handle phishing classification results
        console.log(data);  // Process or notify user of phishing links
      })
      .catch(error => console.error('Error:', error));
    }
  });