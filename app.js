require('dotenv').config();

const express = require('express');
const chalk = require('chalk');

// Security
const helmet = require('helmet');
const cors = require('cors');
const xss = require('xss-clean');

// Swagger UI
const swaggerUI = require("swagger-ui-express");
const YAML = require("yamljs");
const swaggerJsDocs = YAML.load("./api.yaml");

const app = express();
const http = require('http');
const path = require('path');
const { logger, logEvents } = require('./middleware/logger');
const errorHandler = require('./middleware/errorHandler');
const corsOptions = require('./config/corsOptions');
const bodyParser = require('body-parser');
const cookieParser = require("cookie-parser");

const server  = http.createServer(app);

const connectDB = require('./config/dbConn');

// Route Import
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes")

// Connecting to Database Environments
console.log(chalk.redBright(process.env.NODE_ENV));

connectDB()

// Middlewares
app.use(logger)


// Cross Origin Resource Sharing
app.use(cors(corsOptions));

app.use(express.json({ limit: "30mb", extended: true}))
app.use(helmet());
app.use(xss());
app.use(cookieParser())
app.use(express.urlencoded({ limit: "30mb", extended: false}))
app.use(bodyParser.json())


// Routes Middleware
app.use("/api/v1/api-docs", swaggerUI.serve, swaggerUI.setup(swaggerJsDocs));
app.use("/api/v1,", authRoutes);
app.use("/api/v1", userRoutes);


// Routes
app.use('/', express.static(path.join(__dirname, 'public')))
app.use('/', require('./routes/root'))
app.all('*', (req, res) => {
    res.status(404)
    if (req.accepts('html')) {
        res.sendFile(path.join(__dirname, 'views', '404.html'))
    } else if (req.accepts('json')) {
        res.json({ message: '404 Not Found' })
    } else {
        res.type('txt').send('404 Not Found')
    }
})
// Error Middleware
app.use(errorHandler)


module.exports = app;