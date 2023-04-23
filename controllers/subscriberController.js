const asyncHandler = require("express-async-handler");
const mongoose = require("mongoose");
const Subscriber = require("../models/subscriberModel");
const Excel = require('exceljs');
const sendEmail = require("../utils/sendEmail");


const Subscribers = asyncHandler(async (req, res) => {

    const { email, name } = req.body;

    // Validation
    if  (!email || !name) {
        res.status(400);
        throw new Error("Please add your name and email");
    }

    // Check if email exist
    if (email) {
        let user = await Subscriber.findOne({ email })

    if (user) {
        res.status(400).json({
            message: 'You are already a subscriber',
            success: false,
        })
    }   else {
        Subscriber.create({
            _id: new mongoose.Types.ObjectId(),
            email,
            name
        })


    }

}
    //send waitlist mail
    const subject = " Welcome to Redox Trading Newsletter";
    const send_to = email;
    const sent_from = "Redox Trading <hello@redox.com.ng>";
    const reply_to = "no-reply@redox.com.ng";
    const template = "subscriber";

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
        .json({ success: true, message: "subscription Email Sent" });
    } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
    }

});



// Get all email via excel
const downloadSubscribers = asyncHandler (async (req, res) => {
  Waitlist.find({}, (err, subscribers) => {
    if (err) {
      console.log(err);
      return res.status(500).send(err);
    }
    const workbook = new Excel.Workbook();
    const worksheet = workbook.addWorksheet('Subscribers');
    worksheet.columns = [
      { header: 'Name', key: 'name', width: 20 },
      { header: 'Email', key: 'email', width: 40 }
    ];
    subscribers.forEach(subscriber => {
      worksheet.addRow({ name: subscriber.name, email: subscriber.email });
    });
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=subscribers.xlsx');
    workbook.xlsx.write(res)
      .then(() => {
        res.end();
      })
      .catch(err => {
        console.log(err);
        res.status(500).send(err);
      });
  });
});


// Send email to a user
// send email to all users
module.exports = {
    Subscribers,
    downloadSubscribers
};