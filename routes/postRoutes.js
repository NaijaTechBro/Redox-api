const express = require("express")
const router = express.Router();

const {
    createPost,
    getPost,
    getPosts,
    getPostsByUser,
    updatePost,
    deletePost
    

} = require("../controllers/postController")

const {
    isAuthenticatedUser,
    adminOnly,
} = require("../middleware/authMiddleware")



router.post ("/create-Post", createPost, adminOnly);
router.patch ("/update-Post/:id", updatePost, adminOnly);
router.get ("/getPost/:id", getPost, adminOnly);
router.get ("/getPosts", getPosts, adminOnly);
router.get ("/getPostByUser", getPostsByUser, adminOnly);
router.delete ("/delete-Post/:id", deletePost, adminOnly);

module.exports = router;