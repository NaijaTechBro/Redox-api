const express = require("express")
const router = express.Router();

const {
    createblog,
    updateBlog,
    getBlog,
    getBlogs,
    getBlogsByUser,
    deleteBlog

} = require("../controllers/blogController")

const {
    isAuthenticatedUser,
    adminOnly,
} = require("../middleware/authMiddleware")



router.post ("/create-blog", createblog, adminOnly);
router.put ("/update-blog/:id", updateBlog, adminOnly);
router.get ("/get-blog/:id", getBlog, adminOnly);
router.get ("/get-blogs", getBlogs, adminOnly);
router.get ("/getBlogByUser", getBlogsByUser, adminOnly);
router.delete ("/delete-blog/:id", deleteBlog, adminOnly);

module.exports = router;