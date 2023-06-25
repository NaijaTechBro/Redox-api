require('dotenv').config();

const express = require('express');
const chalk = require('chalk');

// Security
const helmet = require('helmet');
const morgan = require("morgan");
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');

const cors = require('cors');
const xss = require('xss-clean');
const app = express();

// Setting up socket.io config
const http = require('http');
const server  = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);

// Swagger UI
const swaggerUI = require("swagger-ui-express");
const YAML = require("yamljs");
const swaggerJsDocs = YAML.load("./api.yaml");

const path = require('path');
const { logger, logEvents } = require('./middleware/logger');
const errorHandler = require('./middleware/errorHandler');
const corsOptions = require('./config/corsOptions');
const bodyParser = require('body-parser');
const cookieParser = require("cookie-parser");



const connectDB = require('./config/dbConn');

// Route Import
const subscriberRoutes = require("./routes/subscriberRoutes");
const postRoutes = require("./routes/postRoutes");
const adminRoutes = require('./routes/admin/authRoutes');
const newsletterRoutes = require('./routes/newsletterRoutes');

// Connecting to Database Environments
console.log(chalk.redBright(process.env.NODE_ENV));

connectDB()

// Middlewares
app.use(logger)
app.use(errorHandler)
app.use(morgan('dev'));

// Cross Origin Resource Sharing
app.use(cors(corsOptions));

app.use((req, res, next,) => {
    res.set({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Origin, X-Requested-With, Content-Type, Accept",
        "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
        "Content-Security-Policy": "default-src *",
        "X-Content-Security-Policy": "default-src *",
        "X-WebKit-CSP": "default-src *"
    })
    next();
});

app.use(express.json({ limit: "30mb", extended: true}))
app.use(
    helmet.contentSecurityPolicy({
        useDefaults: true,
        directives: {
            "img-src": ["'self'", "https: data:"]
        }
    })
    );
app.use(xss());
app.use(cookieParser())
app.use(express.urlencoded({ limit: "30mb", extended: false}))
app.use(bodyParser.json({ limit: "5mb" }))

// Prevent SQL injection
app.use(mongoSanitize());

// limit queries per 15min
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})

app.use(limiter);

// HTTP Param Pollution
app.use(hpp());

// Routes Middleware
app.use("/api/v1/api-docs", swaggerUI.serve, swaggerUI.setup(swaggerJsDocs));
app.use("/api/v1/subscriber", subscriberRoutes);
app.use("/api/v1/post", postRoutes);
app.use("/api/v1/admin", adminRoutes);
app.use("/api/v1/newsletter", newsletterRoutes);


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


// Use Socket io
io.on('connection', (socket) => {
    socket.on('comment', (msg) => {
        io.emit("new-comment", msg);
    })
})

exports.io = io

module.exports = app;