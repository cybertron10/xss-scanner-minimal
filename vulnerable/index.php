<?php
// Vulnerable PHP file for XSS testing - /vulnerable/ endpoint
// This file intentionally contains reflected XSS vulnerabilities

// Get all parameters from GET request
$name = isset($_GET['name']) ? $_GET['name'] : '';
$search = isset($_GET['search']) ? $_GET['search'] : '';
$q = isset($_GET['q']) ? $_GET['q'] : '';
$id = isset($_GET['id']) ? $_GET['id'] : '';
$user = isset($_GET['user']) ? $_GET['user'] : '';
$email = isset($_GET['email']) ? $_GET['email'] : '';
$message = isset($_GET['message']) ? $_GET['message'] : '';

// Get current path to determine which endpoint we're on
$currentPath = $_SERVER['REQUEST_URI'];
$pathParts = explode('?', $currentPath);
$path = $pathParts[0];

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable XSS Test Page - Vulnerable Endpoint</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .vulnerable {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .parameter {
            background-color: #e7f3ff;
            border: 1px solid #b3d9ff;
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
        }
        h1 { color: #333; }
        h2 { color: #666; }
        .endpoint { color: #007bff; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 Vulnerable XSS Test Page - Vulnerable Endpoint</h1>
        <p><strong>Current Endpoint:</strong> <span class="endpoint"><?php echo htmlspecialchars($path); ?></span></p>
        
        <div class="vulnerable">
            <h2>⚠️ Vulnerable Parameters (Reflected XSS)</h2>
            <p><em>These parameters are intentionally vulnerable to reflected XSS for testing purposes.</em></p>
        </div>

        <?php if ($name): ?>
        <div class="parameter">
            <h3>Name Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $name; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <?php if ($search): ?>
        <div class="parameter">
            <h3>Search Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $search; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <?php if ($q): ?>
        <div class="parameter">
            <h3>Query Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $q; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <?php if ($id): ?>
        <div class="parameter">
            <h3>ID Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $id; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <?php if ($user): ?>
        <div class="parameter">
            <h3>User Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $user; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <?php if ($email): ?>
        <div class="parameter">
            <h3>Email Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $email; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <?php if ($message): ?>
        <div class="parameter">
            <h3>Message Parameter (Vulnerable)</h3>
            <p><strong>Value:</strong> <?php echo $message; ?></p>
            <p><em>This parameter is reflected without sanitization - vulnerable to XSS!</em></p>
        </div>
        <?php endif; ?>

        <div class="vulnerable">
            <h2>🔗 Test URLs for this endpoint</h2>
            <p>Use these URLs to test XSS vulnerabilities:</p>
            <ul>
                <li><code>https://16.170.226.104/vulnerable?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                <li><code>https://16.170.226.104/vulnerable?search=&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li><code>https://16.170.226.104/vulnerable?q=&lt;svg onload=alert('XSS')&gt;</code></li>
            </ul>
        </div>

        <div class="vulnerable">
            <h2>📋 All Parameters Received</h2>
            <p><strong>GET Parameters:</strong></p>
            <pre><?php print_r($_GET); ?></pre>
        </div>

        <div class="vulnerable">
            <h2>⚠️ Security Warning</h2>
            <p><strong>This page is intentionally vulnerable for testing purposes only!</strong></p>
            <p>Do not use this code in production environments. All user input is reflected without sanitization.</p>
        </div>
    </div>
</body>
</html>
