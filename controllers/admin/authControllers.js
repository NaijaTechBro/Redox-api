const asyncHandler = require("express-async-handler");
const Admin = require("../../models/adminModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const Token = require("../../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../../utils/sendEmail");
const { OAuth2Client } = require("google-auth-library");
const parser = require("ua-parser-js");
const { hashToken, decrypt, encrypt } = require("../../utils");
const Cryptr = require("cryptr");
const mongoose = require("mongoose")

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const cryptr = new Cryptr(process.env.CRYPTR_KEY);


// Generate Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.MY_SECRET, { expiresIn: "1d" });
}

// Register Admin
const registerAdmin = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all required fields");
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 characters");
  }

  // Check if user email already exists
  const userExists = await Admin.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email has already been registered");
  }

  // Get User Device Details
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // Create new user
  const user = await Admin.create({
    name,
    email,
    password,
    userAgent,
  });

  //   Generate JWT Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, photo } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }

  //send welcome mail
  const sent_from = "Redox Trading <hello@seemetracker.com>";
  const send_to = email;
  const reply_to = "<hello@seemetracker.com>";
  const subject = "Redox Trading Signup Successful! 🎉🙏";
  const template = "welcome";
  const first_name = name;

  try {
    await sendEmail(
      sent_from,
      send_to,
      reply_to,
      subject,
      template,
      first_name,
    );
    res
      .status(200)
      .json({ success: true, message: "Hello, Super Admin account created!." });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});


// Login User
const loginAdmin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validate Request
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add email and password");
  }

  // Check if user exists
  const user = await Admin.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("Admin not found, please signup");
  }

  // User exists, check if password is correct
  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("Invalid email or password");
  }

  // Trigger 2FA for unknown userAgent/device
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;
  console.log(thisUserAgent);
  const allowedDevice = user.userAgent.includes(thisUserAgent);

  if (!allowedDevice) {
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    // Hash token before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    // Delete token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    // Save Access Token to DB
    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes  1hr = 60 * (60 * 1000)
    }).save();

    res.status(400);
    throw new Error("Check your email for login code");
  }



  //   Generate Token
  const token = generateToken(user._id);
  if (user && passwordIsCorrect) {
    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, photo, phone, isVerified, role } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      isVerified,
      role,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Something went wrong, please try again");
  }
});

const sendLoginCode = asyncHandler(async (req, res) => {
  res.send("Login Token");
  const { email } = req.params;
  console.log(email);
  const user = await Admin.findOne({ email });

  // Check if user doesn't exists
  if (!user) {
    res.status(404);
    throw new Error("Admin User not found");
  }

  // Find Access Token in DB
  let userToken = await Token.findOne({ userId: user._id });

  if (!userToken) {
    res.status(500);
    throw new Error("Invalid or Expired token, Login again");
  }

  // get the login code
  const loginCode = userToken.loginToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);
  console.log(loginCode);

  const subject = "Login Access Code - Redox Trading";
  const send_to = email;
  const sent_from = "Redox Trading <hello@seemetracker.com>";
  const template = "accessToken";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      template,
      name,
      link
    );
    res
      .status(200)
      .json({ success: true, message: "Access Code Sent to your email." });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});



// Login with code
const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;
  console.log(email);
  console.log(loginCode);

  const user = await Admin.findOne({ email });

  // Check if user doesn't exists
  if (!user) {
    res.status(404);
    throw new Error("Admin User not found");
  }

  // Find Token in DB
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Code, please login again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);

  // Log user in
  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    // Register the userAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();
    //   Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, photo, phone, bio, isVerified, role } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      isVerified,
      role,
      token,
    });
  }
});



// Send Verification Email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await Admin.findById(req.user._id);

  // Check if user doesn't exists
  if (!user) {
    res.status(404);
    throw new Error("Admin User not found");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("Admin User already verified");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create Verification Token and save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user.id;

  // Hash token before saving to DB
  const hashedToken = hashToken(verificationToken);

  // Save Token to DB
  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
  }).save();

  // Construct Verification Url
  const verificationUrl = `${process.env.REDOX_FRONT_END_LIVE_URL}/admin/auth/email/verify/?verification_token=${verificationToken}`;

  // Verification Email
  const subject = "Verify Your Account 🙏 - Redox Trading";
  const send_to = user.email;
  const sent_from = "Redox <hello@seemetracker.com>";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      template,
      name,
      link
    );
    res.status(200).json({ success: true, message: "Verification Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});



// Verify User
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  // Hash Token
  const hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  // fIND tOKEN in DB
  const userToken = await Token.findOne({
    vToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token!!!");
  }
  // Find User
  const user = await Admin.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    res.status(400);
    throw new Error("Admin User is already verified!!!");
  }

  // Now Verify user
  user.isVerified = true;
  await user.save();

  res.status(200).json({
    message: "Account Verification Successful",
  });
});



// Login With Google
const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;
  // console.log(userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;
  // Get User Device Details
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // Check is the user exists
  const user = await Admin.findOne({ email });

  // User doesn't exist, register user
  if (!user) {
    // Create new use
    const newUser = await Admin.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      //   Generate Token
      const token = generateToken(newUser._id);

      // Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      });

      const { _id, name, email, photo, phone, bio, isVerified, role } = newUser;
      res.status(200).json({
        _id,
        name,
        email,
        photo,
        phone,
        bio,
        isVerified,
        role,
        token,
      });
    }
  }

  // user exists, Login
  if (user) {
    //   Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, photo, phone, bio, isVerified, role } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      isVerified,
      role,
      token,
    });
  }
});


// Logout User
const logout = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "Successfully Logged Out" });
});

// Get Login Status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  // Verify Token
  const verified = jwt.verify(token, process.env.MY_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

// Update User
const updateUser = asyncHandler(async (req, res) => {
  const user = await Admin.findById(req.user._id);

  if (user) {
    const { name, email, photo, phone, role, isVerified } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      photo: updatedUser.photo,
      phone: updatedUser.phone,
      role,
      isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const changePassword = asyncHandler(async (req, res) => {
  const user = await Admin.findById(req.user._id);
  const { oldPassword, password } = req.body;

  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }
  //Validate
  if (!oldPassword || !password) {
    res.status(400);
    throw new Error("Please add old and new password");
  }

  // check if old password matches password in DB
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // Save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res
      .status(200)
      .json({ message: "Password change successful, please re-login" });
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
  }

  // send Changepassword mail
  const subject = "Your Password was Changed";
  const send_to = user.email;
  const sent_from = "Redox Trading <hello@seemetracker.com>";
  const template = "changePassword";
  const name = user.name;


  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      template,
      name,
    );
    res
      .status(200)
      .json({ success: true, message: "Change Password mail Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});




// forgotPassword
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await Admin.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create Reset Token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // Hash token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Save Token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
  }).save();

  // Construct Reset Url
  const resetUrl = `${process.env.REDOX_FRONT_END_LIVE_URL}/resetPassword/${resetToken}`;
  // console.log(resetUrl);

  // Reset Email
  const sent_from = "Redox Trading <hello@seemetracker.com>";
  const send_to = email;
  const reply_to = "<hello@seemetracker.com>";
  const subject = "Password Reset Request - Redox Trading";
  const template = "forgotPassword";
  const first_name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      sent_from,
      send_to,
      reply_to,
      subject,
      template,
      first_name,
      link
    );
    res.status(200).json({ success: true, message: "Email Sent!!!" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  // Hash token, then compare to Token in DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Find Token in DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find user and reset password
  const user = await Admin.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();

  res.status(200).json({
    message: "Password Reset Successful, Please Login",
  });
});


// Send Automated Email
const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;
  // res.send(template);

  if (!subject || !send_to || !reply_to || !template) {
    res.status(400);
    throw new Error("Missing automated email parameter");
  }

  // Get user
  const user = await Admin.findOne({ email: send_to });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  const sent_from = process.env.REDOX_EMAIL_USER;
  const name = user.name;
  const link = `${process.env.REDOX_FRONT_END_LIVE_URL}/admin/resetPassword/${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ success: true, message: "Email Sent!!!" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});



module.exports = {
  registerAdmin,
  sendVerificationEmail,
  verifyUser,
  loginAdmin,
  logout,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
  sendAutomatedEmail,
  loginWithGoogle,
  sendLoginCode,
  loginWithCode,
};