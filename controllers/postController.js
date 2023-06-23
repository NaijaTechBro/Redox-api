const mongoose = require("mongoose")
const asyncHandler = require("express-async-handler");
const cloudinary = require("../utils/cloudinary");
const Post = require("../models/postModel");
const main = require("../app");


// create Post
const createPost = asyncHandler(async (req, res) => {

    const { title, summary, image, content, author, likes, comments, category } = req.body;
    
    try {
        // upload image in clodinary
        const result = await cloudinary.uploader.upload(image, {
            folder: "blogposts",
            width: 1200,
            crop: "scale"
        })
        const post = await Post.create({
            title,
            summary,
            content,
            category,
            author,
            image: {
                public_id: result.public_id,
                url: result.secure_url
            },
             createdAt: new Date().toISOString() })

        await Post.save()
        res.status(201).json({
            success: true,
            post
        })
    } catch (error) {
        res.status(409).json(error.message)
    }})


    // Get a Post
    const getPost = asyncHandler(async (req, res) => {
        const { id } = req.params;

        try {
            const post = await Post.findById(id).populate('comments.author', 'name');
            res.status(200).json({
                success: true,
                post
            });
        } catch (error) {
            res.status(404).json({ message: "Post id does not exist"})
        }
    })


    //  Show Post
    const showPost = asyncHandler(async (req, res) => {
        try {
            const posts = await Post.find().sort({ createdAt: -1 }).populate('postedBy', 'name');
            res.status(201).json({
                success: true,
                posts
            })
        } catch (error) {
            res.status(404).json({ message: error.message });
        }
    
    });


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
        try {
            const { title, content, category, summary, image } = req.body;
            const currentPost = await Post.findById(req.params.id);

            // build the object data
            const data = {
                title: title || currentPost.title,
                content: content || currentPost.content,
                category: category || currentPost.category,
                summary: summary || currentPost.summary,
                image: image || currentPost.image,
            }

            //  modify post image conditionally
            if ( req.body.image !== '') {

                const ImgId = currentPost.image.public_id;
                if (ImgId) {
                    await cloudinary.uploader.destroy(ImgId);
                }

                const newImage = await cloudinary.uploader.upload(req.body.image, {
                    folder: 'blogposts',
                    width: 1200,
                    crop: "scale"
                });

                data.image = {
                    public_id: newImage.public_id,
                    url: newImage.secure_url
                }
            }

            const postUpdate = await Post.findByIdAndUpdate(req.params.id, data, { new: true });

            res.status(200).json({
                success: true,
                postUpdate
            })
        } catch (error) {
            res.status(404).json({ message: error.message });
        }
    });
    
    
        // Delete Post
        const deletePost = asyncHandler(async (req, res) => {
            const currentPost = await Post.findById(req.params.id);

            // delete post image in clodinary
            const ImgId = currentPost.image.public_id;
            if (ImgId) {
                await cloudinary.uploader.destroy(ImgId);
            }

            try {
                if(!mongoose.Types.ObjectId.isValid(id)) return res.status(404).send('No Post with that id')
    
                await Post.findByIdAndRemove(id)
            
                res.json({message: 'Post deleted successfully'})
                
            } catch (error) {
                res.status(404).json({ message: error.message });
            }
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


    // Add comment
    const addComment = asyncHandler(async (req, res) => {
        const { comments } = req.body;

        try {
            const postComment = await Post.findByIdAndUpdate(req.params.id, {
                $push: { comments: { text: comments, postedBy: req.user._id } }
            },
            { new: true}
            );
            const post = await Post.findById(postComment._id).populate('comments.postedBy', 'name email');
            res.status(200).json({
                success: true,
                post
            })
        } catch (error) {
            res.status(404).json({ message: error.message });
        }
    })


    // Add like
    const addLike = asyncHandler(async (req, res) => {
        try {
            const post = await Post.findByIdAndUpdate(req.params.id, {
                $addToSet: { likes: req.user._id }
            },
                { new: true }
                );
            const posts = await Post.find().sort({ createdAt: -1 }).populate('postedBy', 'name');
            main.io.emit('add-like', posts);

            res.status(200).json({
                success: true,
                post,
                posts
            })
        } catch (error) {
            res.status(404).json({ message: error.message });
        }
    })


    //  remove Like
    const unLike = asyncHandler(async (req, res) => {

        try {
            const post = await Post.findByIdAndUpdate(req.params.id, {
                $pull: { likes: req.user._id }
            },
                { new: true }
                );

            const posts = await Post.find().sort({ createdAt: -1 }).populate('postedBy', 'name');
            main.io.emit('un-like', posts);

            res.status(200).json({
                success: true,
                post
            })
        } catch (error) {
            res.status(404).json({ message: error.message });
        }
    })





module.exports = {
    createPost,
    updatePost,
    getPost,
    getPosts,
    getPostsByUser,
    deletePost,
    addComment,
    addLike,
    unLike,
    showPost,
}