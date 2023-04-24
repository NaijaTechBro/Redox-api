const asyncHandler = require("express-async-handler");
const Blog = require("../models/blogModel");


// create blog
const createblog = asyncHandler (async (req, res) => {

    const { title, subtitle, image, body, link } = req.body;

    const newBlog = new Blog({ ...blogModel, createdAt: new Date().toISOString() })
    
    try {
        await newColor.save()
        res.status(201).json(newColor)
    } catch (error) {
        res.status(409).json(error.message)
    }})
    // Get a blog
    const getBlog = asyncHandler(async (req, res) => {
        const { id } = req.params;

        try {
            const blog = await Blog.findById(id);

            res.status(404)
        } catch (error) {
            
        }
    })
// update blog
// delete blog
// filter by category

module.exports = {
    createblog,
}