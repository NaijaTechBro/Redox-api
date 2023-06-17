const express = require('express');

const router = express.Router();

const {
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

} = require('../controllers/adminController');


// admin auth routes
router.post('/create' , createSuperAdmin)
router.get('/email/verify/:verificationToken', verifyEmail);
router.put('/email/verify/resend', resendEmailVerification);
router.post('/login', login);
router.get('/logout', logout);
router.post('/forgotPassword', forgotPassword);
router.put('/resetPassword/:resettoken',  resetPassword);
router.get('/loggedIn', isLoggedIn);

// Protected routes

// Current User Routes
router.patch('/updatePassword', protect, updatePassword);
router.get('/profile',  getAdminProfile);
router.patch('/updateUser',  updateUserProfile);

module.exports = router;


