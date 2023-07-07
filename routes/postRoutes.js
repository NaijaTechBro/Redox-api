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
    

} = require("../controllers/post/postController")

const {
    isAuthenticatedUser,
    adminOnly,
} = require("../middleware/authMiddleware")



router.post ("/create-post",createPost,);
router.get('/show', showPost);
router.patch ("/update-post/:id", updatePost,);
router.get ("/get-post/:id", getPost );
router.get ("/get-posts", getPosts, adminOnly);
router.get ("/getPostByUser", getPostsByUser, adminOnly);
router.delete ("/delete-post/:id", deletePost, adminOnly);
router.put('/comment/post/:id', addComment);
router.put('/addlike/post/:id', addLike);
router.put('/removelike/post/:id', unLike);

module.exports = router;