const asyncHandler = require("express-async-handler");
const Blog = require("../models/blogModel");


// create blog
const createblog = asyncHandler (async (req, res) => {

    const blog = { title, subtitle, image, body, link } = req.body;

    const newBlog = new Blog({ ...blog, createdAt: new Date().toISOString() })
    
    try {
        await newBlog.save()
        res.status(201).json(newBlog)
    } catch (error) {
        res.status(409).json(error.message)
    }})

    // Get a blog
    const getBlog = asyncHandler(async (req, res) => {
        const { id } = req.params;

        try {
            const blog = await Blog.findById(id);
            res.status(200).json(blog);
        } catch (error) {
            res.status(404).json({ message: "Blog id does not exist"})
        }
    })

    // Get All Blog
    const getBlogs = asyncHandler(async (req, res) => {
        const { page } = req.query;
        
        try {
            const LIMIT = 8;
            const startIndex = (Number(page) - 1) * LIMIT; // get the starting index of every page
        
            const total = await Blog.countDocuments({});
            const blogs = await Blog.find().sort({ _id: -1 }).limit(LIMIT).skip(startIndex);
    
            res.json({ data: blogs, currentPage: Number(page), numberOfPages: Math.ceil(total / LIMIT)});
        } catch (error) {    
            res.status(404).json({ message: error.message });
        }
    });

    
    // Update Blog
    const updateBlog = asyncHandler(async (req, res) => {
        const { id: _id } = req.params
        const blog = req.body
    
        if(!mongoose.Types.ObjectId.isValid(_id)) return res.status(404).send('No blog with that id')
    
        const updatedBlog = await Blog.findByIdAndUpdate(_id, {...blog, _id}, { new: true})
    
        res.json(updatedBlog)
    });
    
    
        // Delete Blog
        const deleteBlog = asyncHandler(async (req, res) => {
        const { id } = req.params
    
        if(!mongoose.Types.ObjectId.isValid(id)) return res.status(404).send('No Blog with that id')
    
        await Blog.findByIdAndRemove(id)
    
        res.json({message: 'Blog deleted successfully'})
    });
    
    
        // Get a Blog by a User
        const getBlogsByUser = asyncHandler(async (req, res) => {
        const { searchQuery } = req.query;
    
        try {
            const blogs = await Blog.find({ userId: searchQuery });
    
            res.json({ data: blogs });
        } catch (error) {    
            res.status(404).json({ message: error.message });
        }
    });


module.exports = {
    createblog,
    getBlog,
    getBlogs
}