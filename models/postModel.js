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
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Subcriber"
    },
    image: {
        type: String,
    },
    content: {
        type: String,
        required: true
    },
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