const express = require('express');
const xpath = require('xpath');
const dom = require('xmldom').DOMParser;
const app = express();
const fs = require('fs');

// Parse URL-encoded bodies and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Load an example XML document
const xmlString = fs.readFileSync('./users.xml', 'utf8');

/**
 * Vulnerable route that searches users by username
 * XPATH INJECTION VULNERABILITY: User input is directly concatenated into XPath expression
 */
app.get('/users/search', function(req, res) {
    try {
        // Get the username parameter from the request
        const username = req.query.username;
        
        // Parse the XML document
        const doc = new dom().parseFromString(xmlString);
        
        // VULNERABLE CODE: This line will trigger the Semgrep rule
        // Directly concatenating user input into XPath expression
        const nodes = xpath.parse("//user[username='" + req.query.username + "']").select({
            node: doc
        });
        
        // Convert the result to JSON
        const results = nodes.map(node => {
            return {
                id: node.getAttribute('id'),
                username: xpath.select('string(./username)', node),
                email: xpath.select('string(./email)', node),
                role: xpath.select('string(./role)', node)
            };
        });
        
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * Another vulnerable route using a different pattern
 * that will also trigger the Semgrep rule
 */
app.post('/users/role', function(req, res) {
    try {
        // Store user input in a variable
        const role = req.body.role;
        
        // Parse the XML document
        const doc = new dom().parseFromString(xmlString);
        
        // VULNERABLE CODE: Still a violation even with a variable
        const nodes = xpath.parse("//user[role='" + role + "']").select({
            node: doc
        });
        
        // Convert the result to JSON
        const results = nodes.map(node => {
            return {
                id: node.getAttribute('id'),
                username: xpath.select('string(./username)', node),
                role: xpath.select('string(./role)', node)
            };
        });
        
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * Yet another vulnerable route showing a different pattern
 * that will trigger the Semgrep rule
 */
app.get('/users/email', (req, res) => {
    try {
        // Parse the XML document
        const doc = new dom().parseFromString(xmlString);
        
        // VULNERABLE CODE: Using the parameter directly from req.params
        const emailParam = req.params.email;
        const xpathExpression = "//user[email='" + emailParam + "']";
        
        const nodes = xpath.parse(xpathExpression).select({
            node: doc
        });
        
        if (nodes.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const user = {
            id: nodes[0].getAttribute('id'),
            username: xpath.select('string(./username)', nodes[0]),
            email: xpath.select('string(./email)', nodes[0]),
            role: xpath.select('string(./role)', nodes[0])
        };
        
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

/*
Example users.xml file content:
<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user id="1">
        <username>admin</username>
        <email>admin@example.com</email>
        <role>administrator</role>
    </user>
    <user id="2">
        <username>john</username>
        <email>john@example.com</email>
        <role>user</role>
    </user>
    <user id="3">
        <username>jane</username>
        <email>jane@example.com</email>
        <role>user</role>
    </user>
</users>
*/
