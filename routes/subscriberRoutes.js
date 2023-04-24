const express = require("express");
const { 
    subscribers,
    download,
    sendAllUser,
    sendSinglemail
 } = require("../controllers/subscriberController");
const router = express.Router();

router.post("/subscriber", subscribers);

router.get("/download", download);

router.post("/send-email", sendSinglemail);

router.post("/send-emails", sendAllUser);

module.exports = router;