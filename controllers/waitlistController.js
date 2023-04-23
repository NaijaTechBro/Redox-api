const asyncHandler = require("express-async-handler");
const mongoose = require("mongoose");
const Waitlist = require("../model/waitlistModel");
const sendEmail = require("../utils/sendEmail");


const WaitList = asyncHandler(async (req, res) => {

    const { email } = req.body;

    // Validation
    if  (!email) {
        res.status(400);
        throw new Error("Please add your email");
    }

    // Check if email exist
    if (email) {
        let user = await Waitlist.findOne({ email })

    if (user) {
        res.status(400).json({
            message: 'You are already on our waitlist',
            success: false,
        })
    }   else {
        Waitlist.create({
            _id: new mongoose.Types.ObjectId(),
            email
        })


    }

}
    //send waitlist mail
    const subject = "Waitlist Confirmation";
    const send_to = email;
    const sent_from = "SeemeTracker App <hello@seemetracker.com>";
    const reply_to = "no-reply@seemetracker.com";
    const template = "waitlist";

    try {
        await sendEmail(
        subject,
        send_to,
        sent_from,
        reply_to,
        template,
    );
    res
        .status(200)
        .json({ success: true, message: "Waitlist Email Sent" });
    } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
    }

});

// Get all email
// Send email to a user
// send email to all users
module.exports = {
    WaitList,
};