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
  changePassword,
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
router.get('/loggedIn', adminOnly, isLoggedIn);

// Protected routes

// Current User Routes
router.patch('/updatePassword', adminOnly, isAuthenticatedUser, updatePassword);
router.get('/profile', isAuthenticatedUser, adminOnly, getAdminProfile);
router.patch('/updateUser', isAuthenticatedUser, adminOnly,  updateUserProfile);

module.exports = router;


