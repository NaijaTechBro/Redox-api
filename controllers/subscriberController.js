const asyncHandler = require("express-async-handler");
const mongoose = require("mongoose");
const Subscriber = require("../models/subscriberModel");
const Excel = require('exceljs');
const sendEmail = require("../utils/sendEmail");


const subscribers = asyncHandler(async (req, res) => {

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
    const sent_from = "Redox Trading <insideredox@gmail.com>";
    // const reply_to = "no-reply@redox.com.ng";
    const template = "subscriber";

    try {
        await sendEmail(
        subject,
        send_to,
        sent_from,
        // reply_to,
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



const subers = asyncHandler(async (req, res) => {

  const { email } = req.body;

  // Validation
  if  (!email) {
      res.status(400);
      throw new Error("Please add your email");
  }

  // Check if email exist
  if (email) {
      let user = await Subscriber.findOne({ email })

  if (user) {
      res.status(400).json({
          message: 'You are already on our waitlist',
          success: false,
      })
  }   else {
      Subscriber.create({
          _id: new mongoose.Types.ObjectId(),
          email
      })


  }

}
  //send waitlist mail
  const subject = "Welcome Onboard! Idan";
  const send_to = email;
  const sent_from = "Redox Trading <insideredox@gmail.com>";
  // const reply_to = "no-reply@seemetracker.com";
  const template = "subscriber";

  try {
      await sendEmail(
      subject,
      send_to,
      sent_from,
      // reply_to,
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
const getEmails = async (req, res) => { 
  try {
      const allEmails = await Subscriber.find().sort({ _id: -1 });

      res.status(200).json(allEmails);
  } catch (error) {
      res.status(404).json({ message: error.message });
  }
}

    // Get an Email
    const getEmail = asyncHandler(async (req, res) => {
      const { id } = req.params;

      try {
          const mail = await Subscriber.findById(id);
          res.status(200).json(mail);
      } catch (error) {
          res.status(404).json({ message: "Subscriber id does not exist"})
      }
  })


// Download all email via excel
    const download = asyncHandler (async (req, res) => {

      Subscriber.find().then(async (objs) => {
        let subscribers = [];

        objs.forEach((obj) => {
          subscribers.push({
            id: obj.id,
            name: obj.name,
            email: obj.email,
          });
        });

        let workbook = new Excel.Workbook();
        let worksheet = workbook.addWorksheet("Subscribers");

        worksheet.columns = [
          { header: 'Id', key: 'id', width: 5 },
          { header: 'Name', key: 'name', width: 20 },
          { header: 'Email', key: 'email', width: 40},

        ];

        // Add Array Rows
        worksheet.addRows(subscribers);
        res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=subscribers.xlsx');

        await workbook.xlsx.write(res);
        res.status(200).end();
      });
    });


// Send email to a single user
const sendSinglemail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template } = req.body;

  // validation
  if (!subject || !send_to || !reply_to || !template) {
    res.status(400).send('Missing automated email parameter');
  }

  // Get user
  const user = await Subscriber.findOne({ email: send_to});

  if (!user) {
    res.status(404)
    .json({ message: 'Subscriber not found!'});
  }

          //send mail template
    const sent_from = "Redox Trading <insideredox@gmail.com>";

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
        .json({ success: true, message: "Email Sent Successfully" });
    } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
    }
});






// send email to all users
const sendAllUser = asyncHandler (async (req, res) => {
  const { subject, send_to, reply_to, template } = req.body;
  if (!subject || !send_to || !reply_to || !template) {
    res.status(400).send('Missing automated email parameter');
  }

  // Get Users
  const users = await Subscriber.find({ email});

  if (!users) {
    res.status(404)
    .json({ message: "user"});
  } 
    else {
      users.forEach(async function(user) {
 //send mail template
 const sent_from = "Redox Trading <hello@redox.com.ng>";

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
     .json({ success: true, message: "Emails Sent Successfully" });
 } catch (error) {
 res.status(500);
 throw new Error("Email not sent, please try again");
 }
      }
      
      )

           
    }

})


module.exports = {
    sendAllUser,
    subscribers,
    download,
    sendSinglemail,
    getEmail,
    getEmails,
    subers,
}; 