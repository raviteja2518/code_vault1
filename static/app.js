function getAnswer() {
  const selected = document.getElementById('faq').value;
  const responseBox = document.getElementById('response');

  const answers = {
    encryption: "Your files are encrypted using AES encryption before upload. Only users with the correct key can decrypt them.",
    security: "Yes. Files are encrypted, user authentication is enforced, and data is stored securely in the server.",
    key: "If you forget the encryption key, your file cannot be decrypted. Always keep your key secure.",
    login: "Currently, we don't support password reset. Please contact admin or create a new account.",
    upload: "Yes, you can upload any file type, but the maximum file size is limited to 10MB."
  };

  if (answers[selected]) {
    responseBox.textContent = answers[selected];
  } else {
    responseBox.textContent = "Please select a valid question to view the answer.";
  }
}
