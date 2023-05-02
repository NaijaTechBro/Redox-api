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



router.post ("/create-post", createPost, adminOnly);
router.patch ("/update-post/:id", updatePost, adminOnly);
router.get ("/get-post/:id", getPost, adminOnly);
router.get ("/get-posts", getPosts, adminOnly);
router.get ("/getPostByUser", getPostsByUser, adminOnly);
router.delete ("/delete-post/:id", deletePost, adminOnly);

module.exports = router;