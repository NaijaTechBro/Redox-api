const express = require("express");
const router = express.Router();
const {
    registerAdmin,
    loginAdmin,
    logout,
    loginStatus,
    updateUser,
    forgotPassword,
    resetPassword,
    changePassword,
    sendVerificationEmail,
    verifyUser,
    sendAutomatedEmail,
    loginWithGoogle,
    sendLoginCode,
    loginWithCode,
} = require("../../controllers/admin/authControllers");


router.post("/auth/register", registerAdmin);
router.post("/auth/login", loginAdmin);
router.get("/logout", logout);
router.get("/auth/loginStatus", loginStatus);
router.patch("/updateUser", updateUser);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetPassword/:resetToken", resetPassword);
// router.post("/auth/sendVerificationEmail", sendVerificationEmail);
// router.patch("/auth/verifyUser/:verificationToken", verifyUser);
// router.post("/sendAutomatedEmail", sendAutomatedEmail);
// router.post("/sendLoginCode/:email", sendLoginCode);
// router.post("/loginWithCode/:email", loginWithCode);
// router.patch("/changePassword", changePassword);
// router.post("/auth/google/callback/:ID", loginWithGoogle);


module.exports = router;