const express = require('express')
const router = express.Router()
const path = require('path')

router.get('^/$|/index(.html)?', (req, res) => {
    res.send('<h1>Redox API</h1><a href="/api-docs">Documentation</a>');
    // res.sendFile(path.join(__dirname, '..', 'views', 'index.html'))
})

module.exports = router