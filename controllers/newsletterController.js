const mongoose = require('mongoose');
const asyncHandler = require('express-async-handler');
const sendEmail = require('../utils/sendEmail');
const Newsletter = require('../models/newsletterModel');



const newsletter = asyncHandler(async (req, res) => {

    const { email } = req.body;

      // validation
    if ( !email ) {
        res.status(400);
        throw new Error("Please enter your email");
    }

    // Check if email exist
    if (email) {
        let user = await Newsletter.findOne({ email })
    
        if (user) {
            res.status(400).json({
                message: 'You are already a subscriber',
                success: false,
            })
        }
            else {
                Newsletter.create({
                    _id: new mongoose.Types.ObjectId(),
                    email,
                })

            }
        }

            // send newsletter mail
            const subject = "Welcome to Redox Trading Newsletter";
            const send_to = email;
            const sent_from = "Redox Trading <hello@seemetracker.com>";
            const reply_to = "no-reply@redox.com.ng";
            const template = "newsletter";

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
                    .json({ success: true, message: "Newsletter Email Sent" });
                } catch (error) {
                    res.status(500);
                    throw new Error("Email not sent, please try again");
                }

        });




        module.exports = {
            newsletter,
        }