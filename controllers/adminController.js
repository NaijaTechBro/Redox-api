const catchAsync = require("../utils/libs/catchAsync");
const path = require("path");
const Admin = require("../models/adminModel");
const AppError = require("../utils/libs/appError");
const crypto = require("crypto")
const jwt = require("jsonwebtoken")
const sendEmail = require("../utils/sendEmail")
const { successResMsg } = require("../utils/libs/response");

const {
  signAccessToken,
  verifyAccessToken,
} = require("../utils/libs/jwt-helper")

const URL = 
process.env.NODE_ENV == 'development'
    ? process.env.REDOX_FRONT_END_DEV_URL
    : process.env.REDOX_FRONT_END_LIVE_URL;

 const createSendToken = (user, statusCode, res) => {
  const token = signAccessToken({ id: user._id, adminRole: user.role, email: user.email });

  const cookieOptions = {
    expires: new Date(
      Date.now() +
        process.env.REDOX_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    secure: false,
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  user.password = undefined;

  res.cookie('jwt', token, cookieOptions);

  const dataInfo = { token, user }
  return successResMsg(res, 200, dataInfo);
};

// Logout User
  const logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  return successResMsg(res, 200, {});
};

// Login Admin user
  const login = catchAsync(async (req, res, next) => {
  let user;

  const { email, password } = req.body;
  // Check if email and password exists
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  // Check if the user exists and password correct
  user = await Admin.findOne({ email }).select('+password +isVerified +block');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Invalid email or password', 401));
  }

  if (!user.isVerified) {
    return next(new AppError('Your account is blocked', 403));
  }

  if (user.block) {
    return next(new AppError('Your account is blocked', 403));
  }

  // If all true, send token to user
  createSendToken(user, 200, res);
});
   

  const createSuperAdmin = async (req, res, next) => {

    try {
  
          const { name, email, password } = req.body;
  
          if (!name || !email || !password) {
            return next(new AppError('Please provide first name, last name, password, and email !', 400));
          }
  
          const user = await Admin.findOne({ email }).select('+password');
  
          if (user) {
            return next(new AppError('Email already exists!', 400));
          }
  
  
          const newUser = await Admin.create({
            name,
            email,
            password,
            isVerified: true,
            role: 'ROL-SUPERADMIN',
          });
  
          const subject = "Redox Trading Signup Successful! 🎉🙏";
          const send_to = email;
          const first_name = name;
          const sent_from = "Redox Trading <hello@seemetracker.com>";
          const reply_to = "no-reply@redox.com.ng";
          const template = "welcome";

          try {
            await sendEmail(
                subject,
                send_to,
                sent_from,
                first_name,
                reply_to,
                template,
            );
            res
                .status(200)
                .json({ success: true, message: "'Hello, Super Admin account created!." });
            } catch (error) {
                res.status(500);
                throw new Error("Email not sent, please try again");
            }

    } catch (error) {
      return next(new AppError(error, error.status));
    }
  
    };



    // verify Admin user email address after registration
  const verifyEmail = catchAsync(async (req, res, next) => {
  const { verification_token } = req.query;

  if (!verification_token) {
    return next(new AppError('Please provide verification token!', 400));
  }

  const decoded = await verifyAccessToken(verification_token);

  if (
    decoded &&
    decoded.name !== 'JsonWebTokenError' &&
    decoded.name !== 'TokenExpiredError'
  ) {
    const user = await Admin.findOne({email: decoded.email}).select('+isVerified');
    if (!user) return next(new AppError('Email has not been registered', 400));

    if (user.isVerified) {
      return next(new AppError('Email has already been verified!', 400));
    }

    user.isVerified = true;
    await user.save();
    
    const dataInfo = { message: 'Email verification successful' };
    return successResMsg(res, 200, dataInfo);

  } else if (decoded.name === 'TokenExpiredError')
    return next(new AppError('Verification email link has expired!', 400));
    else if (decoded.name === 'JsonWebTokenError')
    return next(new AppError(decoded.message, 400));
    else return next(new AppError('Something went wrong', 400));
})

  const resendEmailVerification = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new AppError('Please provide email!', 400));
  }

  const user = await Admin.findOne({ email }).select('+isVerified');

  if (!user) {
    return next(new AppError('Email has not been registered', 400));
  }

  if (user.isVerified) {
    return next(new AppError('Email has already been verified!', 400));
  }

  const data = {
    email,
  }

  const token = signAccessToken(data);
  const verificationUrl = `${URL}/admin/auth/email/verify/?verification_token=${token}`;

   
  const subject = "Verify your Email 🙏";
  const send_to = email;
  const link = verificationUrl;
  const first_name = name;
  const sent_from = "Redox Trading <hello@seemetracker.com>";
  const reply_to = "no-reply@redox.com.ng";
  const template = "verifyEmail";

  try {
    await sendEmail(
        subject,
        send_to,
        sent_from,
        link,
        first_name,
        reply_to,
        template,
    );
    res
        .status(200)
        .json({ success: true, message: "'Signup Successful!." });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }

  const dataInfo = { message: 'Verification email re-sent' };
  return successResMsg(res, 200, dataInfo);
})

  
// Protects Routes
  const protect = catchAsync(async (req, res, next) => {
  let token;
  // Get token and check if it exists
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1].toString();
  } else if (req.cookies) {
    console.log(req.cookies);
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(
      new AppError('You are not logged in!. Please login to gain access', 401)
    ); // 401 - Unauthorized
  }
  // Token verification
  const decoded = verifyAccessToken(token.toString());

  // Check if user still exists
  const currentUser = await Admin.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('This user no longer exist', 401));
  }

  // Check if user changed password after token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please login again.', 401)
    );
  }

    // Grant user access to route
  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});


// Only for rendered pages
  const isLoggedIn = async (req, res, next) => {
  // Get token and check if it exists
  if (req.cookies.jwt) {
    try {
      // Token verification
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.REDOX_ACCESS_TOKEN_SECRET
      );

      // Check if user still exists
      const currentUser = await Admin.findById(decoded.id);
      if (!currentUser) {
        return next();
      }

      // Check if user changed password after token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next();
      }

      // There is a logged in user
      res.locals.user = currentUser;
      return next();
    } catch (err) {
      return next;
    }
  }
  next();
};


// Forgot password
  const forgotPassword = catchAsync(async (req, res, next) => {
  // Get User based on password provided
  const user = await Admin.findOne({ email: req.body.email });

  if (!user) {
    return next(
      new AppError('There is no user with the provided email address', 404)
    );
  }
  // Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  try {
    // Send token via user's email
    const resetURL = `${URL}/auth/reset/resetPassword/?confirmationToken=${resetToken}`;

    ejs.renderFile(
      path.join(__dirname, '../../views/email-template.ejs'), {
        salutation: `Hello ${user.firstName}`,
        body: `<p>Forgot your password? \n </p>
        <p>Kindly Click the link to reset your password: \n <p> 
        <a href=${resetURL}>Reset my password</a>`,
      },
      async (err, data) => {
          //use the data here as the mail body
          const options = {
            email: req.body.email,
            subject: 'Password Reset!',
            message: data,
          };
          await sendEmail(options);
      }
    );
    
    const dataInfo = { message: 'Password reset token sent!' };
    return successResMsg(res, 200, dataInfo);

  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email', 500));
  }
});

// Reset Password
  const resetPassword = catchAsync(async (req, res, next) => {

  const { resettoken: confirmationToken } = req.params;
  // Get user based on token
  const hashedToken = crypto
    .createHash('sha256')
    .update(confirmationToken, 'utf8')
    .digest('hex');

    console.log(hashedToken);

  const user = await Admin.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // Check if token is still valid / not expired -- set new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save(); // No need to turn off validator as it's required

  // Update passwordChangedAt property in adminModel

  // send a mail
  ejs.renderFile(
    path.join(__dirname, '../../views/email-template.ejs'), {
      salutation: `Hello ${user.firstName}`,
      body: `<p> You've successfully changed your password \n </p>
      <p>If you didnt perfom this action, contact support immediately  \n <p> `,
    },
    async (err, data) => {
        //use the data here as the mail body
        const options = {
          email: user.email,
          subject: 'Password Reset Successfull!',
          message: data,
        };
        await sendEmail(options);
    }
  );

  // Log in user -- send JWT
  createSendToken(user, 200, res);
});

// Updating password of a logged in admin user
const updatePassword = catchAsync(async (req, res, next) => {
  // Get user from collection
  const user = await Admin.findById(req.user.id).select('+password');

  // Check if posted password is correct
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError('Password Incorrect. Try again!!', 401));
  }

  // Update Password
  user.password = req.body.newPassword;
  await user.save();

  // send a mail
  ejs.renderFile(
    path.join(__dirname, '../../views/email-template.ejs'), {
      salutation: `Hello ${user.firstName}`,
      body: `<p> You've successfully changed your password \n </p>
      <p>If you didnt perfom this action, contact support immediately  \n <p> `,
    },
    async (err, data) => {
        //use the data here as the mail body
        const options = {
          email: user.email,
          subject: 'Password Changed!',
          message: data,
        };
        await sendEmail(options);
    }
  );

  // Log user in -- send JWT
  createSendToken(user, 200, res);
});

// Get Admin user profile
  const getAdminProfile = catchAsync(async (req, res, next) => {
  const { id } = req.params;

  const user = await Admin.findById(id);

  if (!user) {
    return next(
      new AppError('Admin does not exist, do check the user id correctly', 404)
    )
    next();
  }
     const data = { user }
  return successResMsg(res, 200, data )
});

//Update Admin Profile
  const updateUserProfile = catchAsync(async (req, res, next) => {
  const { id } = req.params;

  const userExists = Admin.findById(id);

  if (!userExists)
    return next(new AppError('Admin does not exist, do check the user id correctly', 404));


  const { email, firstName, lastName } = req.body;

  const reqBody = {
    firstName,
    lastName,
    email,
  }

  const emailCheck = await Admin.exists({ email: email });

  if (emailCheck)
  return next(new AppError('Email Address already exist', 400));


  const updatedUser = await Admin.findByIdAndUpdate(id, reqBody, { 
    new: true,
    runValidators: true,
  });


  if (!updatedUser) {
    return next(new AppError('Update User failed', 404));
  }
  const data = { user: updatedUser };
  return successResMsg(res, 200, data);
});



    module.exports = {
        createSuperAdmin,
        login,
        logout,
        resendEmailVerification,
        verifyEmail,
        protect,
        isLoggedIn,
        forgotPassword,
        resetPassword,
        updatePassword,
        getAdminProfile,
        updateUserProfile,
        

    }