const express = require('express');

const router = express.Router();

const {
  loginLimiter,
} = require('../middleware/loginLimiter')

const {
  adminOnly,
  isAuthenticatedUser

} = require('../middleware/authMiddleware')
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
  getAdminProfile,
  updateUserProfile,
  updatePassword,

} = require('../controllers/admin/authController');

// admin auth routes
router.post('/create' , createSuperAdmin)
router.patch('/email/verify/:verificationToken', verifyEmail);
router.post('/email/verify/resend', resendEmailVerification);
router.post('/login', login);
router.get('/logout', logout);
router.post('/forgotPassword', forgotPassword);
router.patch('/resetPassword/:resettoken',  resetPassword);
router.get('/loggedin', isLoggedIn);

// Protected routes

// Current User Routes
router.patch('/updatePassword',protect, updatePassword);
router.get('/profile',protect,  getAdminProfile);
router.patch('/updateUser',protect, updateUserProfile);

module.exports = router;


