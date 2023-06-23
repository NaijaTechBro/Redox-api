const express = require("express")
const router = express.Router();

const {
    createPost,
    getPost,
    getPosts,
    getPostsByUser,
    updatePost,
    deletePost,
    showPost,
    addComment,
    addLike,
    unLike
    

} = require("../controllers/postController")

const {
    isAuthenticatedUser,
    adminOnly,
} = require("../middleware/authMiddleware")



router.post ("/create-post",isAuthenticatedUser, createPost, adminOnly);
router.get('/show', showPost);
router.patch ("/update-post/:id", updatePost, adminOnly);
router.get ("/get-post/:id", getPost );
router.get ("/get-posts", getPosts, adminOnly);
router.get ("/getPostByUser", getPostsByUser, adminOnly);
router.delete ("/delete-post/:id", isAuthenticatedUser, deletePost, adminOnly);
router.put('/comment/post/:id', isAuthenticatedUser, addComment);
router.put('/addlike/post/:id', isAuthenticatedUser, addLike);
router.put('/removelike/post/:id', isAuthenticatedUser, unLike);

module.exports = router;