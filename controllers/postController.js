const mongoose = require("mongoose")
const asyncHandler = require("express-async-handler");
const Post = require("../models/postModel");


// create Post
const createPost = asyncHandler (async (req, res) => {

    const post = { title, summary, image, content, category } = req.body;

    const newPost = new Post({ ...post, createdAt: new Date().toISOString() })
    
    try {
        await newPost.save()
        res.status(201).json(newPost)
    } catch (error) {
        res.status(409).json(error.message)
    }})

    // Get a Post
    const getPost = asyncHandler(async (req, res) => {
        const { id } = req.params;

        try {
            const post = await Post.findById(id);
            res.status(200).json(post);
        } catch (error) {
            res.status(404).json({ message: "Post id does not exist"})
        }
    })

    // Get All Post
    const getPosts = asyncHandler(async (req, res) => {
        const { page } = req.query;
        
        try {
            const LIMIT = 8;
            const startIndex = (Number(page) - 1) * LIMIT; // get the starting index of every page
        
            const total = await Post.countDocuments({});
            const posts = await Post.find().sort({ _id: -1 }).limit(LIMIT).skip(startIndex);
    
            res.json({ data: posts, currentPage: Number(page), numberOfPages: Math.ceil(total / LIMIT)});
        } catch (error) {    
            res.status(404).json({ message: error.message });
        }
    });

    
    // Update Post
    const updatePost = asyncHandler(async (req, res) => {
        const { id: _id } = req.params
        const post = req.body
    
        if(!mongoose.Types.ObjectId.isValid(_id)) return res.status(404).send('No post with that id')
    
        const updatedPost = await Post.findByIdAndUpdate(_id, {...post, _id}, { new: true})
    
        res.json(updatedPost)
    });
    
    
        // Delete Post
        const deletePost = asyncHandler(async (req, res) => {
        const { id } = req.params
    
        if(!mongoose.Types.ObjectId.isValid(id)) return res.status(404).send('No Post with that id')
    
        await Post.findByIdAndRemove(id)
    
        res.json({message: 'Post deleted successfully'})
    });
    
    
        // Get a Post by a User
        const getPostsByUser = asyncHandler(async (req, res) => {
        const { searchQuery } = req.query;
    
        try {
            const posts = await Post.find({ userId: searchQuery });
    
            res.json({ data: posts });
        } catch (error) {    
            res.status(404).json({ message: error.message });
        }
    });


module.exports = {
    createPost,
    updatePost,
    getPost,
    getPosts,
    getPostsByUser,
    deletePost,
}