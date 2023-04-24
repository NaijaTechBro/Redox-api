const asyncHandler = requrie("express-async-handler");
const Admin = require("../models/adminModel");




    const createSuperAdmin = asyncHandler(async (req, res, next) => {

    try {
  
          const { firstName, lastName, email, password } = req.body;
  
          if (!firstName || !lastName || !email || !password) {
            return next(new AppError('Please provide first name, last name, password, and email !', 400));
          }
  
          const user = await Admin.findOne({ email }).select('+password');
  
          if (user) {
            return next(new AppError('Email already exists!', 400));
          }
  
  
          const newUser = await Admin.create({
            firstName,
            lastName,
            email,
            password,
            isVerified: true,
            role: 'ROL-SUPERADMIN',
          });
  
        const options = {
          email: req.body.email,
          subject: 'Signup Successful!',
          message: `Welcome, we're glad to have you 🎉🙏, 
                    Kindly Login`,
        };
  
        await sendEmail(options);
  
        const dataInfo = { 
          message: 'Hello, Super Admin account created!.' 
        }; 
         return successResMsg(res, 201, dataInfo);
    } catch (error) {
      return next(new AppError(error, error.status));
    }
  
    });

    module.exports = {
        createSuperAdmin
    }