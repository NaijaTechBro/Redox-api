const cloudinary = require('cloudinary').v2;

cloudinary.config({
    cloud_name: process.env.REDOX_CLOUD_NAME,
    api_key: process.env.REDOX_CLOUD_KEY,
    api_secret: process.env.REDOX_CLOUD_KEY_SECRET
});

module.exports = cloudinary;