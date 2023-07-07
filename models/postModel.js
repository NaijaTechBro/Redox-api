const mongoose = require("mongoose")

const postSchema = mongoose.Schema({
    title: {
        type: String,
        required: [true, "Please add your title"]
    },
    summary: {
        type: String,
        trim: true,
        minLength: 50,
    },
    category: {
        type: String,
        // required: [true, "Please add a category"],
        default: "CryptoCurrency",
        enum: ["CryptoCurrency", "Economics", "Forex"]
        
    },
    postedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Admin"
    },
    image: {
        url: String,
        public_id: String,
    },
    content: {
        type: String,
        required: [true, "content is required"],
    },
    likes: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
    }],
    comments: [
        {
            text: String,
            created: { type: Date, default: Date.now },
            postedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
            },
        },
    ],
    readingTime: {
        type: String,
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    },
},
{
    timestamps: true,
});

module.exports = mongoose.model("Post", postSchema);