const express = require("express");
const { 
    subscribers,
    download,
    sendAllUser,
    sendSinglemail
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

module.exports = router;