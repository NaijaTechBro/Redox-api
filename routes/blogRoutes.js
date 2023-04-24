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


module.exports = router;