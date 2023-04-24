const express = require("express");
const { Subscribers, DownloadSubscribers } = require("../controllers/subscriberController");
const router = express.Router();

router.post("/subscriber", Subscribers);

router.get("/download-subscribers", DownloadSubscribers);

module.exports = router;