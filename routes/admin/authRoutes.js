const express = require("express");
const router = express.Router();
const {
    registerAdmin,
    loginAdmin,
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
} = require("../../controllers/adminControllers");
const {
    isAuthenticatedUser,
} = require("../../middleware/authMiddleware");
const loginLimiter = require("../../middleware/loginLimiter");

router.post("/auth/register", registerAdmin);
router.post("/auth/sendVerificationEmail", sendVerificationEmail);
router.patch("/auth/verifyUser/:verificationToken", verifyUser);
router.post("/auth/login", loginLimiter, loginAdmin);
router.get("/logout", logout);

router.post("/sendAutomatedEmail", sendAutomatedEmail);
router.post("/sendLoginCode/:email", sendLoginCode);
router.post("/loginWithCode/:email", loginWithCode);

router.get("/auth/loginStatus", loginStatus);
router.patch("/updateUser", updateUser);
router.patch("/changePassword", changePassword);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetPassword/:resetToken", resetPassword);

router.post("/auth/google/callback/:ID", loginLimiter, loginWithGoogle);


module.exports = router;