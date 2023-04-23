const express = require("express");
const { WaitList } = require("../controllers/waitlistController");
const router = express.Router();

router.post("/waitlist", WaitList);

module.exports = router;