const whiteList = require('./whiteList')

const corsOptions = {
    origin: (origin, callback) => {
        if (whiteList.indexOf(origin) !== -1 || !origin) {
            callback(null, true)
        } else {
            callback(new Error('Not allowed by CORS'))
        }
    },
    Credentials: true,
    OptionSuccessStatus: 200
}

module.exports = corsOptions