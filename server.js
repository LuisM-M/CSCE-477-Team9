const express = require('express');
const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// In-memory storage for strings
const strings = [];

// Endpoint to store a string
app.post('/store', (req, res) => {
  const { text } = req.body;
  
  if (!text) {
    return res.status(400).json({ error: 'Text field is required' });
  }
  
  const id = strings.length;
  strings.push({ id, text, timestamp: new Date() });
  
  res.status(201).json({ 
    message: 'String stored successfully', 
    id,
    text 
  });
});

// Endpoint to retrieve all strings
app.get('/strings', (req, res) => {
  res.json({ count: strings.length, strings });
});

// Endpoint to retrieve a specific string by id
app.get('/strings/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const str = strings[id];
  
  if (!str) {
    return res.status(404).json({ error: 'String not found' });
  }
  
  res.json(str);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`POST to http://localhost:${port}/store to save strings`);
  console.log(`GET http://localhost:${port}/strings to view all strings`);
});