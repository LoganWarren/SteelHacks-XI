document.addEventListener('DOMContentLoaded', function() {
    const emailLinks = Array.from(document.querySelectorAll('a')).map(a => a.href);
    browser.runtime.sendMessage({ links: emailLinks });
});

// This will collect all urls from the email content and then send the links to the bakground script.

