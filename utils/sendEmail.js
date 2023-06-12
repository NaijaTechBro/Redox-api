const nodemailer = require("nodemailer");
const hbs = require("nodemailer-express-handlebars");
const path = require("path");

const sendEmail = async (
    subject,
  // message,
    send_to,
    sent_from,
    reply_to,
    template,
    name,
    link
) => {
  // Create Email Transporter
    const transporter = nodemailer.createTransport({
    host: process.env.REDOX_EMAIL_HOST,
    port: process.env.REDOX_EMAIL_PORT,
    auth: {
        user: process.env.REDOX_EMAIL_USER,
        pass: process.env.REDOX_EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: false,
    },
    });

    const handlebarOptions = {
    viewEngine: {
        extName: ".handlebars",
        partialsDir: path.resolve("./email"),
        defaultLayout: false,
    },
    viewPath: path.resolve("./email"),
    extName: ".handlebars",
    };

    transporter.use("compile", hbs(handlebarOptions));

  // Option for sending email
    const options = {
    from: sent_from,
    to: send_to,
    replyTo: reply_to,
    subject: subject,
    // html: message,
    template, // String
    headers: {
      'X-Custom-Header' : 'Custom header'
    },
    context: {
        name,
        link,
    },
    };

  // send email
    transporter.sendMail(options, function (err, info) {
    if (err) {
        console.log(err);
    } else {
        console.log(info);
    }
    });
};

module.exports = sendEmail;