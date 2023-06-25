const express = require("express");
const router = express.Router();
const {
    registerUser,
    loginUser,
    logout,
    loginStatus,
    updateUser,
    changePassword,
    forgotPassword,
    resetPassword,
    sendVerificationEmail,
    verifyUser,
    sendAutomatedEmail,
    loginWithGoogle,
    sendLoginCode,
    loginWithCode,
} = require("../controllers/authController");
const {
    isAuthenticatedUser,
} = require("../middleware/authMiddleware");
const loginLimiter = require("../middleware/loginLimiter");

router.post("/users/auth/register", registerUser);
router.post("/auth/sendVerificationEmail", isAuthenticatedUser, sendVerificationEmail);
router.patch("/auth/verifyUser/:verificationToken", verifyUser);
router.post("/users/auth/login", loginLimiter, loginUser);
router.get("/logout", logout);

router.post("/users/sendAutomatedEmail", isAuthenticatedUser, sendAutomatedEmail);
router.post("/users/sendLoginCode/:email", sendLoginCode);
router.post("/users/loginWithCode/:email", loginWithCode);

router.get("/users/auth/loginStatus", loginStatus);
router.patch("/users/updateUser", isAuthenticatedUser, updateUser);
router.patch("/users/changePassword", isAuthenticatedUser, changePassword);
router.post("/users/forgotPassword", forgotPassword);
router.patch("/users/resetPassword/:resetToken", resetPassword);

router.post("/users/auth/google/callback/:ID", loginLimiter, loginWithGoogle);


module.exports = router;