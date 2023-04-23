const express = require("express");
const { Subscribers, downloadSubscribers } = require("../controllers/subscriberController");
const router = express.Router();

router.post("/subscriber", Subscribers);

router.get("/download-subscribers", downloadSubscribers);

module.exports = router;