const express = require("express");
const { 
    subscribers,
    download,
    sendAllUser,
    sendSinglemail,
    getEmail,
    getEmails
 } = require("../controllers/subscriberController");
const {
    isAuthenticatedUser,
    adminOnly,

} = require("../middleware/authMiddleware");
const router = express.Router();

router.post("/subscriber", subscribers);

router.get("/download", download, isAuthenticatedUser, adminOnly);

router.post("/send-email", sendSinglemail, isAuthenticatedUser, adminOnly);

router.post("/send-emails", sendAllUser, isAuthenticatedUser, adminOnly);

router.get("/get-mail", getEmail, isAuthenticatedUser, adminOnly);

router.get("/get-mails", getEmails, isAuthenticatedUser, adminOnly);

module.exports = router;